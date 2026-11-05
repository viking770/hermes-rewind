"""Decide whether a shell command might change the sandbox.

Rewind snapshots the container before any command that might change it. The
check is deliberately conservative: anything it does not recognise as
read-only counts as a change, because a spare snapshot is cheap and a missing
one means the change cannot be undone.
"""
from __future__ import annotations

import re
import shlex
from typing import Optional

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
_REDIRECT = re.compile(r"(?:\d|&)?>>?\s*(&?[^\s;&|<>]+)")
_SEPARATORS = re.compile(r"\|\||&&|[;|&\n]")
_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")


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
    # Command substitution or backticks can run anything; don't try to parse it.
    if "$(" in command or "`" in command:
        return True
    for target in _REDIRECT.findall(command):
        if not (target.startswith("&") or target == "/dev/null"):
            return True
    stripped = _REDIRECT.sub(" ", command)
    for segment in _SEPARATORS.split(stripped):
        if _segment_mutates(segment):
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
    while words and (_ASSIGNMENT.match(words[0]) or words[0] in _WRAPPERS):
        words = words[1:]
    if not words:
        return False
    program = words[0].rsplit("/", 1)[-1]
    args = words[1:]
    if program == "env":
        return _env_mutates(args)
    if program == "git":
        sub = next((a for a in args if not a.startswith("-")), "")
        return sub not in READ_ONLY_GIT
    if program not in READ_ONLY_COMMANDS:
        return True
    if program == "sed":
        return _sed_mutates(args)
    if program == "awk":
        # awk can run commands with system(), and gawk can edit files in place.
        return any("system" in a or a in ("-i", "--include") or a.startswith("-i") for a in args)
    if program == "find" and any(a in _FIND_WRITES for a in args):
        return True
    if program == "sort" and any(a == "-o" or a.startswith("--output") for a in args):
        return True
    if program == "tree" and any(a == "-o" for a in args):
        return True
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
_CURL_DATA = ("-d", "--data", "--data-raw", "--data-binary", "--data-urlencode", "-F", "--form",
              "-T", "--upload-file", "--json")


def irreversible_reason(command: str) -> Optional[str]:
    """Why ``command`` would change something outside the sandbox, or None.

    Best effort, aimed at the common cases (git push, publishing, deploys,
    HTTP writes, remote shells). A None here does not prove a command is safe.
    """
    if not command.strip():
        return None
    for segment in _SEPARATORS.split(_REDIRECT.sub(" ", command)):
        segment = segment.strip().lstrip("({!").rstrip(")}").strip()
        if not segment:
            continue
        try:
            words = shlex.split(segment)
        except ValueError:
            words = segment.split()
        reason = _words_irreversible(words)
        if reason:
            return reason
    return None


def _words_irreversible(words: list) -> Optional[str]:
    while words and (_ASSIGNMENT.match(words[0]) or words[0] in _WRAPPERS or words[0] in ("sudo", "env")):
        words = words[1:]
    if not words:
        return None
    program = words[0].rsplit("/", 1)[-1]
    args = words[1:]
    positional = [a for a in args if not a.startswith("-")]
    sub = positional[0] if positional else ""
    if program == "git" and sub in _GIT_REMOTE:
        return f"`git {sub}` sends commits outside the sandbox"
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
            return f"`{program}` sends an HTTP {method} request"
    if program in _REMOTE_COPY and any(":" in a and not a.startswith("-") for a in positional):
        return f"`{program}` copies files to or from another machine"
    if program in _REMOTE_SHELL:
        return f"`{program}` runs commands on another machine or database"
    if program in _MAIL:
        return f"`{program}` sends email"
    return None


def _http_method(program: str, args: list) -> Optional[str]:
    for i, arg in enumerate(args):
        if arg in ("-X", "--request", "--method") and i + 1 < len(args):
            return args[i + 1].upper()
        if arg.startswith("--request=") or arg.startswith("--method="):
            return arg.partition("=")[2].upper()
        if arg.startswith("-X") and len(arg) > 2:
            return arg[2:].upper()
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
        if arg in ("-f", "--file") or arg.startswith("--file="):
            return True  # the script is in a file we can't inspect
        if arg.startswith("-") and arg not in ("-e", "--expression"):
            continue
        if _SED_COMMAND.search(arg) or _SED_S_FLAG.search(arg):
            return True
    return False
