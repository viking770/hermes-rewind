"""An append-only record of what Rewind did, so a person can check afterwards.

One JSON object per line in ``<state dir>/audit.log``: when, what (restore,
undo, export, forget, purge, approval requested, sandbox resumed, network
guard fell back, ...), for which sandbox, and through what (the agent's tool,
/rewind, the CLI, or Rewind itself). Text is redacted like snapshot commands.
The file is owner-only on POSIX and rotates at 5 MB, keeping ``audit.log.1``
to ``audit.log.3``.
Set REWIND_AUDIT=0 to turn it off. Writing it never breaks the action itself.
"""
from __future__ import annotations

import json
import os
import re
import threading
import time
from pathlib import Path
from typing import Any, Iterator, Optional

from . import store as store_mod
from .redact import redact

MAX_BYTES = 5 * 1024 * 1024
KEEP_ROTATED = 3  # audit.log.1 (newest) to audit.log.3 (oldest)
_lock = threading.Lock()


def enabled() -> bool:
    return os.environ.get("REWIND_AUDIT", "1") != "0"


def path() -> Path:
    return store_mod.default_dir() / "audit.log"


def _clean(value: Any) -> Any:
    if isinstance(value, str):
        return redact(value)[:500]
    if isinstance(value, (list, tuple)):
        return [_clean(v) for v in list(value)[:50]]
    if isinstance(value, dict):
        return {str(k): _clean(v) for k, v in list(value.items())[:50]}
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return redact(str(value))[:500]


def log(event: str, *, task_id: Optional[str] = None, via: str = "rewind", **details: Any) -> None:
    """Append one event. Never raises."""
    if not enabled():
        return
    entry = {"ts": round(time.time(), 3), "time": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
             "event": event, "via": via, "task_id": task_id, "pid": os.getpid()}
    entry.update(_clean(details))
    # ASCII only: otherwise json leaves U+2028/U+2029/U+0085 raw, and agent text
    # holding them could break an entry apart for anything reading it line by line.
    line = json.dumps(entry, ensure_ascii=True) + "\n"
    try:
        with _lock:
            target = path()
            target.parent.mkdir(parents=True, exist_ok=True)
            try:
                if target.stat().st_size + len(line) > MAX_BYTES:
                    _rotate(target)
            except FileNotFoundError:
                pass
            fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            with os.fdopen(fd, "a", encoding="utf-8") as f:
                f.write(line)
    except OSError:
        pass


def _rotated(target: Path, n: int) -> Path:
    return target.with_name(f"{target.name}.{n}")


def _rotate(target: Path) -> None:
    """audit.log -> .1 -> .2 -> ... -> .KEEP_ROTATED, dropping the oldest. Several
    generations, so one burst of entries can't push older evidence out at once."""
    for n in range(KEEP_ROTATED - 1, 0, -1):
        try:
            os.replace(_rotated(target, n), _rotated(target, n + 1))
        except FileNotFoundError:
            pass
    os.replace(target, _rotated(target, 1))


def tail(count: int = 50) -> Iterator[dict]:
    """The last ``count`` events, oldest first (reads rotated files too if needed).
    Lines that aren't a JSON object are skipped."""
    if count <= 0:
        return
    target = path()
    entries: list = []
    for candidate in [target] + [_rotated(target, n) for n in range(1, KEEP_ROTATED + 1)]:
        try:
            text = candidate.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        found = []
        for line in text.split("\n"):  # only "\n" ends an entry, never U+2028 and friends
            try:
                value = json.loads(line)
            except ValueError:
                continue
            if isinstance(value, dict):
                found.append(value)
        entries = found + entries
        if len(entries) >= count:
            break
    yield from entries[-count:]


# C0/C1 controls, plus characters that hide or reorder text on screen: the soft
# hyphen, zero-width characters, Arabic/Mongolian/bidi marks, overrides and
# isolates (U+202E can make "evil.exe" read as "exe.live"), line and paragraph
# separators, and the BOM. Written as escapes so the source holds no invisible text.
_CONTROL = re.compile("[\x00-\x1f\x7f-\x9f\u00ad\u061c\u180e\u200b-\u200f\u2028-\u202e\u2060-\u2069\ufeff]")


def _printable(text: str) -> str:
    """Control characters as visible escapes (\\x1b, \\u202e...). Entries hold
    agent-written text, and `hermes rewind log` prints to a terminal that would
    act on them."""
    def escape(match) -> str:
        code = ord(match.group())
        return f"\\x{code:02x}" if code < 0x100 else f"\\u{code:04x}"
    return _CONTROL.sub(escape, str(text))


def describe(entry: dict) -> str:
    """One readable line for ``hermes rewind log``."""
    skip = {"ts", "time", "event", "via", "task_id", "pid"}
    details = ", ".join(f"{k}={v}" for k, v in entry.items() if k not in skip and v not in (None, "", []))
    task = entry.get("task_id") or "-"
    return _printable(f"{entry.get('time', '?')}  {entry.get('event', '?'):<18} via {entry.get('via', '?'):<8} {task}"
                      + (f"  {details}" if details else ""))
