"""Decide whether a shell command might change the sandbox.

Rewind snapshots the container before any command that might change it. The
check is deliberately conservative: anything it does not recognise as
read-only counts as a change, because a spare snapshot is cheap and a missing
one means the change cannot be undone.
"""
from __future__ import annotations

import hashlib
import re
import shlex
from typing import List, Optional
from urllib.parse import urlsplit

MODES = ("mutating", "always", "off")

READ_ONLY_COMMANDS = frozenset(
    {
        "[", "awk", "basename", "cat", "cd", "cmp", "column", "cut", "date", "df",
        "diff", "dirname", "du", "echo", "egrep", "env", "export", "false", "fgrep",
        "file", "find", "free", "grep", "head", "hostname", "id", "jq", "less", "ls",
        "md5sum", "more", "nl", "nproc", "od", "printenv", "printf", "ps", "pwd",
        "readlink", "realpath", "rg", "sed", "seq", "sha1sum", "sha256sum", "sleep",
        "sort", "stat", "tail", "test", "tr", "tree", "true", "type", "uname", "uniq",
        "uptime", "wc", "which", "whoami", "xxd",
    }
)
READ_ONLY_GIT = frozenset(
    {"blame", "describe", "diff", "grep", "log", "ls-files", "rev-parse", "show", "status"}
)
_FIND_WRITES = frozenset(
    {"-delete", "-exec", "-execdir", "-ok", "-okdir", "-fprint", "-fprint0", "-fprintf", "-fls"}
)
_WRAPPERS = frozenset({"time", "command", "builtin", "nohup"})
# env options that take a separate argument.
_ENV_ARG_OPTIONS = frozenset({"-u", "--unset", "-C", "--chdir"})
# Commands whose second positional argument is an output file (`uniq in out`).
_OUTPUT_FILE_ARG = frozenset({"uniq", "xxd"})
# sed commands that write files (w, W) or run shell commands (e), either on
# their own (`3w out`, `/x/e`) or as an s/// flag (`s/a/b/w out`, `s/a/b/ge`).
_SED_COMMAND = re.compile(r"(?:^|[;{}\n/0-9$!])\s*[wWe](?:\s|;|$)")
_SED_S_FLAG = re.compile(r"s(.)(?:\\.|(?!\1).)*\1(?:\\.|(?!\1).)*\1[gpiImM0-9]*[we]")

# ">", ">>", "2>", "&>" followed by a target. Targets "&N" (fd dup) and
# /dev/null do not touch the filesystem.
# ">|" (overwrite even with noclobber) is a redirect too.
_REDIRECT = re.compile(r"(?:\d|&)?>(?:>|\|)?\s*(&?[^\s;&|<>]+)")
_SEPARATORS = re.compile(r"\|\||&&|[;|&\n]")
_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
_FD_DUP = re.compile(r"&(?:\d+|-)")
# Read-only commands no environment variable can make run another program.
_NO_PROGRAM_HOOKS = frozenset({"env", "printenv", "echo", "printf", "true", "false", "pwd", "test", "[",
                               "export", "cd", "type", "which", "sleep", "date", "id", "whoami", "uname",
                               "hostname", "nproc", "uptime", "basename", "dirname", "seq"})
# git options that make even a read-only subcommand write a file or run a program.
_GIT_RISKY_OPTIONS = ("--output", "-c", "--config-env", "--exec-path", "--ext-diff", "--textconv",
                      "--open-files-in-pager")
# Programs a repository's own config can make run other programs (diff.external,
# core.fsmonitor, core.pager, filters...), so even a "read-only" use may write.
HOOKABLE_PROGRAMS = frozenset({"git"})


def _short_flags(args: list, letters: str) -> bool:
    """Whether any short-option group (-abc) contains one of ``letters``."""
    return any(a.startswith("-") and not a.startswith("--") and any(c in a[1:] for c in letters) for a in args)


def should_snapshot(command: str, mode: str = "mutating") -> bool:
    """Return True when Rewind should snapshot before running ``command``."""
    if mode == "always":
        return bool(command.strip())
    if mode == "off":
        return False
    return is_mutating(command)


def is_mutating(command: str) -> bool:
    command = command.strip()
    if not command:
        return False
    # Command or process substitution and backticks can run anything; don't try to parse it.
    if "$(" in command or "`" in command or "<(" in command or ">(" in command:
        return True
    for target in _REDIRECT.findall(command):
        # Only `>&N` / `>&-` duplicate a descriptor; bash's `>&word` writes the file `word`.
        if not (_FD_DUP.fullmatch(target) or target == "/dev/null"):
            return True
    stripped = _REDIRECT.sub(" ", command)
    for segment in _SEPARATORS.split(stripped):
        if _segment_mutates(segment):
            return True
    return False


def may_run_hooks(command: str) -> bool:
    """Whether ``command`` runs a program whose behaviour files in the sandbox can
    change (a repository's config can make `git status` run anything). Such a
    command is still read-only for deciding whether to snapshot *before* it, but
    a snapshot taken before it can't be trusted to hold the state after it."""
    stripped = _REDIRECT.sub(" ", command)
    for segment in _SEPARATORS.split(stripped):
        segment = segment.strip().lstrip("({!").rstrip(")}").strip()
        try:
            words = shlex.split(segment)
        except ValueError:
            words = segment.split()
        words, hidden = _strip_prefixes(words, 0)  # NAME=x, time, env -u X, sudo ...
        if hidden is not None or (words and words[0].rsplit("/", 1)[-1] in HOOKABLE_PROGRAMS):
            return True
    return False


def _segment_mutates(segment: str) -> bool:
    segment = segment.strip().lstrip("({!").rstrip(")}").strip()
    if not segment:
        return False
    try:
        words = shlex.split(segment)
    except ValueError:
        words = segment.split()
    return _words_mutate(words)


def _words_mutate(words: list) -> bool:
    assigned = False
    while words and (_ASSIGNMENT.match(words[0]) or words[0] in _WRAPPERS):
        assigned = assigned or bool(_ASSIGNMENT.match(words[0]))
        words = words[1:]
    if not words:
        return False
    program = words[0].rsplit("/", 1)[-1]
    if assigned and program not in _NO_PROGRAM_HOOKS:
        # `NAME=value cmd`: the variable can make a read-only program run something
        # (GIT_EXTERNAL_DIFF, PAGER, LESSOPEN, ...). Not worth guessing which.
        return True
    args = words[1:]
    if program == "env":
        return _env_mutates(args)
    if program == "git":
        if any(a == opt or a.startswith(opt + "=") for a in args for opt in _GIT_RISKY_OPTIONS):
            return True
        if any(a.startswith("-O") for a in args):  # git grep -O<cmd> runs a program
            return True
        sub = next((a for a in args if not a.startswith("-")), "")
        return sub not in READ_ONLY_GIT
    if program not in READ_ONLY_COMMANDS:
        return True
    if program == "sed":
        return _sed_mutates(args)
    if program == "awk":
        # awk can run commands with system(), gawk can edit files in place, and a
        # program file (-f) can do either without us seeing it.
        return any("system" in a or a in ("-i", "--include", "-f", "--file") or a.startswith(("-i", "-f", "--file="))
                   for a in args)
    if program == "find" and any(a in _FIND_WRITES for a in args):
        return True
    if program == "sort" and any(a == "-o" or a.startswith(("--output", "--compress-program")) for a in args):
        return True  # writes a file, or runs a (de)compression program
    if program == "rg" and any(a == "--pre" or a.startswith("--pre=") for a in args):
        return True  # runs a preprocessor program on every file
    if program == "tree" and _short_flags(args, "oR"):
        return True  # -o writes a file; -R (with -H) writes 00Tree.html into every folder
    if program == "file" and (_short_flags(args, "C") or "--compile" in args):
        return True  # compiles a magic file, writing <name>.mgc
    if program in ("less", "more") and (_short_flags(args, "oO") or any(
            a.startswith(("--log-file", "--LOG-FILE")) for a in args)):
        return True  # writes a log file
    if program in _OUTPUT_FILE_ARG and len([a for a in args if not a.startswith("-")]) >= 2:
        return True
    return False


# ------------------------------------------------------- irreversible commands
# Snapshots cover the sandbox's files. These reach outside it, so no restore
# can take them back. Matched per segment, on the program and its subcommand.
_GIT_REMOTE = frozenset({"push", "send-email", "request-pull"})
_PUBLISH = {
    "npm": {"publish", "unpublish", "deprecate"}, "pnpm": {"publish"}, "yarn": {"publish", "npm"},
    "cargo": {"publish", "yank"}, "gem": {"push", "yank"}, "twine": {"upload"},
    "poetry": {"publish"}, "uv": {"publish"}, "docker": {"push", "login"}, "podman": {"push"},
    "helm": {"install", "upgrade", "uninstall", "delete", "push"},
    "terraform": {"apply", "destroy", "import"}, "tofu": {"apply", "destroy", "import"},
    "pulumi": {"up", "destroy"}, "vercel": {"deploy", "--prod", "rm", "remove"},
    "netlify": {"deploy"}, "flyctl": {"deploy", "destroy"}, "fly": {"deploy", "destroy"},
    "heroku": set(), "aws": set(), "gcloud": set(), "az": set(), "doctl": set(),
}
_CLOUD_READ = ("describe", "get", "list", "ls", "show", "whoami", "help", "version", "info",
               "logs", "status", "configure", "config", "auth")
_KUBECTL_READ = frozenset({"get", "describe", "logs", "explain", "version", "config", "api-resources",
                           "top", "auth", "diff", "cluster-info"})
_GH_READ = frozenset({"view", "list", "status", "diff", "checks", "browse", "search", "download"})
_REMOTE_COPY = frozenset({"scp", "rsync", "sftp"})
_REMOTE_SHELL = frozenset({"ssh", "psql", "mysql", "mongosh", "mongo", "redis-cli", "sqlcmd"})
_MAIL = frozenset({"sendmail", "mail", "mailx", "mutt", "msmtp"})
_HTTP_WRITE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
_CURL_DATA = ("-d", "--data", "--data-raw", "--data-binary", "--data-urlencode", "--data-ascii", "-F", "--form",
              "--form-string", "-T", "--upload-file", "--json")
# Raw socket tools: whatever they send leaves the sandbox. `-z` only probes a port.
_SOCKET_TOOLS = frozenset({"nc", "ncat", "netcat", "socat", "telnet"})
# Package runners that run a tool by name: npx vercel deploy, uvx twine upload...
# (pipx run X, pnpm dlx X, ...: those need their verb first.)
_TOOL_RUNNERS = frozenset({"npx", "bunx", "uvx", "pipx", "pnpm", "yarn", "bun"})
_TOOL_RUNNER_VERBS = {"pipx": "run", "pnpm": "dlx", "yarn": "dlx", "bun": "x"}
# Scripts whose name says they publish or deploy; their contents can't be checked.
_RELEASE_SCRIPT = re.compile(r"(?:^|[/_.-])(?:deploy|publish|release|upload|push)(?:[_.-]|$)", re.IGNORECASE)
# Remote-sending git subcommands, for spotting aliases that hide them.
_GIT_ALIAS_SENDS = re.compile(r"(?:^|[\s!;&|])(?:git\s+)?(?:push|send-email|request-pull)\b|^!")


def irreversible_reason(command: str) -> Optional[str]:
    """Why ``command`` would change something outside the sandbox, or None.

    Best effort, aimed at the common cases (git push, publishing, deploys,
    HTTP writes, remote shells). A None here does not prove a command is safe.
    """
    return _irreversible(command, depth=0)


def _call_name(matched: str) -> str:
    """`requests.post(...` -> requests.post; `.request("POST"` -> request."""
    found = re.search(r"[A-Za-z_][\w.:]*", matched)
    return found.group(0) if found else "a network call"


def script_irreversible_reason(code: str) -> Optional[str]:
    """Like irreversible_reason, for source code (Python and similar) rather than a
    shell command: only network-sending calls and shelled-out commands are checked."""
    if not code or not code.strip():
        return None
    match = _SCRIPT_SENDS.search(code)
    if match:
        return f"a script calls `{_call_name(match.group(0))}`, which sends data outside the sandbox"
    # subprocess.run("git push") / os.system('npm publish') / subprocess.run(["git", "push"])
    for found in re.finditer(r"\b(?:os\.system|os\.popen|subprocess\.\w+)\(\s*(\[[^\]]*\]|'[^']*'|\"[^\"]*\")",
                             code):
        literal = found.group(1)
        if literal.startswith("["):
            words = re.findall(r"'([^']*)'|\"([^\"]*)\"", literal)
            command = " ".join(shlex.quote(a or b) for a, b in words)
        else:
            command = literal[1:-1]
        reason = _irreversible(command, depth=1)
        if reason:
            return reason
    return None


def _irreversible(command: str, depth: int) -> Optional[str]:
    if not command.strip() or depth > 3:
        return None
    # Inline scripts (python -c, heredocs, node -e) that send data somewhere.
    match = _SCRIPT_SENDS.search(command)
    if match:
        return f"a script calls `{_call_name(match.group(0))}`, which sends data outside the sandbox"
    # Command substitution runs its contents too: echo $(git push), `git push`.
    for inner in _SUBSTITUTION.findall(command):
        reason = _irreversible(next(part for part in inner if part), depth + 1)
        if reason:
            return reason
    for segment in _split_commands(_REDIRECT.sub(" ", command)):
        segment = segment.strip().lstrip("({!").rstrip(")}").strip()
        if not segment:
            continue
        try:
            words = shlex.split(segment)
        except ValueError:
            words = segment.split()
        reason = _words_irreversible(words, depth)
        if reason:
            return reason
    return None


def _split_commands(command: str) -> list:
    """Split on ; && || | & and newlines, but not inside quotes, so
    `sh -c "cd app && git push"` stays one command whose script is checked."""
    parts, current, quote, i = [], [], None, 0
    while i < len(command):
        ch = command[i]
        if quote:
            current.append(ch)
            if ch == "\\" and quote == '"' and i + 1 < len(command):
                current.append(command[i + 1])
                i += 1
            elif ch == quote:
                quote = None
        elif ch in "'\"":
            quote = ch
            current.append(ch)
        elif ch == "\\" and i + 1 < len(command):
            current += [ch, command[i + 1]]
            i += 1
        elif ch in ";|&\n":
            parts.append("".join(current))
            current = []
            if command[i:i + 2] in ("&&", "||"):
                i += 1
        else:
            current.append(ch)
        i += 1
    parts.append("".join(current))
    return parts


# Calls in inline Python/JS/Ruby that write to the network.
_SCRIPT_SENDS = re.compile(
    r"\b(?:requests|httpx|session|client)\.(?:post|put|patch|delete)\(|"
    r"\burllib\.request\.(?:urlopen|Request)\([^)]*data\s*=|"
    # urlopen(url, b"...") / Request(url, data): data passed positionally. The first
    # argument is one bounded run (with at most one call inside) and no separate
    # whitespace runs around it: overlapping ones made this a ReDoS.
    r"\b(?:urlopen|Request)\([^,()\n]{1,300}(?:\([^()\n]{0,300}\)[^,()\n]{0,300})?,[ \t]*"
    r"(?!timeout\b|context\b|headers\b|method\b|unverifiable\b|origin_req_host\b|cafile\b)[^\s)]|"
    r"\.request\(\s*['\"](?:POST|PUT|PATCH|DELETE)['\"]|"  # http.client / urllib3
    r"\bfetch\([^)]*method\s*:\s*['\"](?:POST|PUT|PATCH|DELETE)|"
    r"\baxios\.(?:post|put|patch|delete)\(|"
    r"\bsmtplib\.SMTP|\.sendmail\(|"
    r"\bNet::HTTP\.post|"
    r"\bparamiko\.SSHClient"
)
# Programs that run another command given as arguments: (program, options that take a value).
_RUNNERS = {
    "xargs": {"-I", "-n", "-P", "-L", "-d", "-a", "-E", "-s"}, "timeout": {"-s", "-k", "--signal", "--kill-after"},
    "nice": {"-n", "--adjustment"}, "exec": set(), "watch": {"-n", "--interval", "-d"},
    "stdbuf": {"-i", "-o", "-e"}, "unbuffer": set(), "doas": {"-u"}, "chroot": set(),
}
_SHELLS = frozenset({"sh", "bash", "zsh", "dash", "ksh", "ash", "fish"})
# `-c` alone or inside a cluster of short options: -c, -lc, -ec, -xec.
_SHELL_C = re.compile(r"-[A-Za-z]*c[A-Za-z]*")
_SUBSTITUTION = re.compile(r"\$\(([^()]*)\)|`([^`]*)`")
# Prefixes that run the rest of the line, and their options that take a value.
_PREFIX_VALUE_OPTS = {
    "sudo": {"-u", "-g", "-h", "-p", "-C", "-D", "-R", "-T", "-U", "--user", "--group", "--host", "--prompt"},
    "doas": {"-u", "-C"},
    "env": {"-u", "--unset", "-C", "--chdir", "-S", "--split-string"},
}
# curl short options that take a value, so the rest of a cluster is that value.
_CURL_VALUE_LETTERS = set("HoeuAbcxmwKErYyzCUQ")
# git options that come before the subcommand and take a value: git -C repo push.
_GIT_VALUE_OPTS = frozenset({"-C", "-c", "--git-dir", "--work-tree", "--namespace", "--exec-path"})


def _git_subcommand(args: list) -> str:
    i = 0
    while i < len(args):
        arg = args[i]
        if arg in _GIT_VALUE_OPTS:
            i += 2
        elif arg.startswith("-"):
            i += 1
        else:
            return arg
    return ""


def _strip_prefixes(words: list, depth: int):
    """Drop NAME=value, wrappers and sudo/doas/env with their options. Returns
    (words, reason): reason is set when `env -S 'cmd'` hides a command in a string."""
    while words:
        word = words[0]
        if _ASSIGNMENT.match(word) or word in _WRAPPERS:
            words = words[1:]
            continue
        if word in _PREFIX_VALUE_OPTS:
            takes_value, words = _PREFIX_VALUE_OPTS[word], words[1:]
            while words and words[0].startswith("-") and words[0] != "--":
                opt, words = words[0], words[1:]
                if opt in ("-S", "--split-string") and words:
                    return [], _irreversible(words[0], depth + 1)
                if opt in takes_value and words:
                    words = words[1:]
            if words and words[0] == "--":
                words = words[1:]
            continue
        break
    return words, None


def _words_irreversible(words: list, depth: int = 0) -> Optional[str]:
    words, hidden = _strip_prefixes(words, depth)
    if hidden or not words:
        return hidden
    program = words[0].rsplit("/", 1)[-1]
    args = words[1:]
    # A command hidden inside another: bash -c '...', bash -lc '...', eval ..., xargs git push, ...
    if program in _SHELLS:
        i = 0
        while i < len(args) - 1:
            arg = args[i]
            if _SHELL_C.fullmatch(arg):
                return _irreversible(args[i + 1], depth + 1)
            if arg in ("-o", "+o", "-O", "+O"):  # bash -o pipefail -c '...'
                i += 2
            elif arg.startswith(("-", "+")) and arg != "--":
                i += 1
            else:
                break  # a script file, not -c
        while i < len(args) and args[i].startswith(("-", "+")):
            i += 1
        return _release_script(args[i]) if i < len(args) else None
    if program in ("source", "."):
        return _release_script(args[0]) if args else None
    if program == "eval":
        return _irreversible(" ".join(args), depth + 1)
    if program in _RUNNERS:
        value_opts, i = _RUNNERS[program], 0
        while i < len(args) and args[i].startswith("-"):
            i += 2 if args[i] in value_opts else 1
        if program in ("timeout",) and i < len(args):
            i += 1  # the duration
        return _words_irreversible(args[i:], depth + 1) if i < len(args) else None
    # python -m twine upload: the module is the program.
    if re.fullmatch(r"python[0-9.]*|py|pypy[0-9.]*", program) and "-m" in args[:3]:
        module_at = args.index("-m") + 1
        if module_at < len(args):
            return _words_irreversible(args[module_at:], depth + 1)
    if program in _TOOL_RUNNERS:
        verb = _TOOL_RUNNER_VERBS.get(program)
        rest = None
        if not verb:
            rest = list(args)
        elif args[:1] == [verb]:
            rest = list(args[1:])
        if rest is not None:
            while rest and rest[0].startswith("-"):
                rest = rest[1:]
            if rest:
                rest[0] = re.sub(r"(?<=.)@[^/]*$", "", rest[0])  # vercel@latest -> vercel
                return _words_irreversible(rest, depth + 1)
    if "/" in words[0]:  # ./deploy.sh
        reason = _release_script(words[0])
        if reason:
            return reason
    positional = [a for a in args if not a.startswith("-")]
    sub = _git_subcommand(args) if program == "git" else (positional[0] if positional else "")
    if program == "git" and sub in _GIT_REMOTE:
        return f"`git {sub}` sends commits outside the sandbox"
    if program == "git":
        # An alias can hide a push: git config alias.p push, then `git p`;
        # or git -c alias.p=push p. Aliases starting with "!" run any shell command.
        for i, arg in enumerate(args):
            value = None
            if arg == "-c" and i + 1 < len(args) and args[i + 1].lower().startswith("alias."):
                value = args[i + 1].partition("=")[2]
            elif arg.lower().startswith("alias.") and sub == "config" and i + 1 < len(args):
                value = args[i + 1]
            if value is not None and _GIT_ALIAS_SENDS.search(value.strip()):
                return "`git alias` defines a git alias that can push or run commands outside the sandbox"
    if program in _PUBLISH:
        subs = _PUBLISH[program]
        if not subs:  # cloud CLIs: anything but an obvious read
            if not positional or any(p.startswith(_CLOUD_READ) for p in positional[1:] or positional):
                return None
            return f"`{program} {sub}` changes a cloud account outside the sandbox"
        if sub in subs or any(a in subs for a in args):
            what = f"{program} {sub}".strip()
            return f"`{what}` changes a remote service"
    if program == "kubectl" and sub and sub not in _KUBECTL_READ:
        return f"`kubectl {sub}` changes a cluster outside the sandbox"
    if program == "gh":
        action = positional[1] if len(positional) > 1 else ""
        if sub == "api" and any(a in ("-X", "--method", "-f", "-F", "--field", "--raw-field", "--input")
                                for a in args):
            return "`gh api` with a write changes GitHub"
        if sub not in ("api", "auth", "help", "") and action and action not in _GH_READ:
            return f"`gh {sub} {action}` changes GitHub"
    if program in ("curl", "wget", "http", "https", "xh"):
        method = _http_method(program, args)
        if method in _HTTP_WRITE_METHODS:
            # The host is part of the quoted action, so approving "always" for one
            # host's POSTs doesn't approve every curl write everywhere.
            return f"`{program} {method.lower()} {_http_host(args, program)}` sends an HTTP {method} request"
    # -z only probes a port; -l listens (inbound, which the guard blocks anyway).
    if program in _SOCKET_TOOLS and not _short_flags(args, "zl") and "--listen" not in args:
        return f"`{program}` sends raw network data outside the sandbox"
    if program in _REMOTE_COPY and any(":" in a and not a.startswith("-") for a in positional):
        return f"`{program}` copies files to or from another machine"
    if program in _REMOTE_SHELL:
        return f"`{program}` runs commands on another machine or database"
    if program in _MAIL:
        return f"`{program}` sends email"
    return None


def _release_script(path: str) -> Optional[str]:
    if _RELEASE_SCRIPT.search(path.rsplit("/", 1)[-1]):
        return f"`{path}` looks like a deploy or publish script, which Rewind can't check"
    return None


# Options whose next argument is a value, not a URL (so `-o resp.json` isn't a host).
_HTTP_VALUE_LONG = frozenset({
    "--output", "--header", "--data", "--data-raw", "--data-binary", "--data-urlencode", "--data-ascii",
    "--form", "--form-string", "--json", "--upload-file", "--user", "--user-agent", "--referer", "--cookie",
    "--cookie-jar", "--proxy", "--request", "--write-out", "--config", "--cacert", "--capath", "--cert",
    "--key", "--max-time", "--connect-timeout", "--range", "--continue-at", "--retry", "--resolve",
    "--connect-to", "--output-dir", "--method", "--post-data", "--post-file", "--body-data", "--body-file",
    "--output-document", "--append-output", "--execute", "--save-cookies", "--load-cookies", "--auth",
})
_HTTP_VALUE_SHORT = {"curl": set("HoeuAbcxmwKErYyzCUQdFTX"), "wget": set("OoaeUPTtwQiB"),
                     "http": set("aAo"), "https": set("aAo"), "xh": set("aAo")}
_BARE_HOST = re.compile(r"(?:localhost|\[[0-9A-Fa-f:.]+\]|[0-9]{1,3}(?:\.[0-9]{1,3}){3}|"
                        r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,})(?::[0-9]+)?(?:[/?#]|$)")


def _http_host(args: list, program: str = "curl") -> str:
    """The host(s) an HTTP command targets, for approval keys. Several hosts are
    all named ("a.example+b.example"). With none recognisable (a URL in a
    variable, say) the key is unique to this exact command, so approving it
    "always" doesn't approve other unknown targets."""
    hosts: List[str] = []
    short_values = _HTTP_VALUE_SHORT.get(program, set())
    skip = False
    for arg in args:
        if skip:
            skip = False
            continue
        if arg.startswith("--"):
            name, eq, value = arg.partition("=")
            if name == "--url":
                if not eq:
                    continue  # the next argument is the URL and is read as one
                arg = value
            else:
                skip = name in _HTTP_VALUE_LONG and not eq
                continue
        elif arg.startswith("-") and len(arg) > 1:
            for pos, letter in enumerate(arg[1:], 1):
                if letter in short_values:
                    skip = pos == len(arg) - 1  # value is the next argument, else attached
                    break
            continue
        candidate = arg if "://" in arg else ("http://" + arg if _BARE_HOST.match(arg) else "")
        if not candidate:
            continue
        try:
            host = (urlsplit(candidate).hostname or "").lower()
        except ValueError:
            continue
        if re.fullmatch(r"[a-z0-9.:-]+", host) and host not in hosts:
            hosts.append(host)
    if hosts:
        return "+".join(sorted(hosts))
    return "unknown-" + hashlib.sha1("\0".join(args).encode("utf-8", "replace")).hexdigest()[:8]


def _http_method(program: str, args: list) -> Optional[str]:
    for i, arg in enumerate(args):
        if arg in ("-X", "--request", "--method") and i + 1 < len(args):
            return args[i + 1].upper()
        if arg.startswith("--request=") or arg.startswith("--method="):
            return arg.partition("=")[2].upper()
        if arg.startswith("-X") and len(arg) > 2:
            return arg[2:].upper()
        if program == "curl" and arg.startswith("-") and not arg.startswith("--") and len(arg) > 2:
            # A cluster of short options: -sSXPOST, -sd x, -d@file, -sT file.
            for pos, letter in enumerate(arg[1:], 1):
                if letter == "X":
                    value = arg[pos + 1:] or (args[i + 1] if i + 1 < len(args) else "")
                    return value.upper()
                if letter in "dF":
                    return "POST"
                if letter == "T":
                    return "PUT"
                if letter in _CURL_VALUE_LETTERS:
                    break  # the rest of the cluster is this option's value
    if program == "curl" and any(a in ("-T", "--upload-file") or a.startswith("--upload-file=") for a in args):
        return "PUT"
    if program == "curl" and any(a in _CURL_DATA or a.startswith(tuple(f"{d}=" for d in _CURL_DATA))
                                 for a in args):
        return "POST"
    if program == "wget" and any(a.startswith(("--post-data", "--post-file", "--body-data")) for a in args):
        return "POST"
    if program in ("http", "https", "xh") and args and args[0].upper() in _HTTP_WRITE_METHODS:
        return args[0].upper()
    return None


def _env_mutates(args: list) -> bool:
    """`env` alone only prints; `env [options] [NAME=value...] cmd` runs cmd."""
    i = 0
    while i < len(args):
        arg = args[i]
        if arg in _ENV_ARG_OPTIONS:
            i += 2
        elif arg in ("-S", "--split-string") or arg.startswith(("-S", "--split-string")):
            return True  # the command is hidden inside a string; don't try to parse it
        elif arg.startswith("-") or _ASSIGNMENT.match(arg):
            i += 1
        else:
            return _words_mutate(args[i:])
    return False


def _sed_mutates(args: list) -> bool:
    for i, arg in enumerate(args):
        if arg == "-i" or arg.startswith(("-i", "--in-place")):
            return True
        if re.fullmatch(r"-[A-Za-z]*i\S*", arg):  # -i inside a cluster: -ni, -Ei, -nEi.bak
            return True
        if arg in ("-f", "--file") or arg.startswith("--file="):
            return True  # the script is in a file we can't inspect
        if arg.startswith("-") and arg not in ("-e", "--expression"):
            continue
        if _SED_COMMAND.search(arg) or _SED_S_FLAG.search(arg):
            return True
    return False
