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
_FIND_WRITES = frozenset({"-delete", "-exec", "-execdir", "-ok", "-okdir", "-fprint", "-fprintf", "-fls"})
_WRAPPERS = frozenset({"time", "command", "builtin", "nohup"})

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
    while words and (_ASSIGNMENT.match(words[0]) or words[0] in _WRAPPERS):
        words = words[1:]
    if not words:
        return False
    program = words[0].rsplit("/", 1)[-1]
    args = words[1:]
    if program == "git":
        sub = next((a for a in args if not a.startswith("-")), "")
        return sub not in READ_ONLY_GIT
    if program not in READ_ONLY_COMMANDS:
        return True
    if program == "sed" and any(a == "-i" or a.startswith(("-i", "--in-place")) for a in args):
        return True
    if program == "find" and any(a in _FIND_WRITES for a in args):
        return True
    if program == "sort" and any(a == "-o" or a.startswith("--output") for a in args):
        return True
    return False
