"""Decide whether a shell command might change the sandbox.

Rewind snapshots the container before any command that might change it. The
check is deliberately conservative: anything it does not recognise as
read-only counts as a change, because a spare snapshot is cheap and a missing
one means the change cannot be undone.
"""
from __future__ import annotations

import re
import shlex

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
