"""An append-only record of what Rewind did, so a person can check afterwards.

One JSON object per line in ``<state dir>/audit.log``: when, what (restore,
undo, export, forget, purge, approval requested, sandbox resumed, network
guard fell back, ...), for which sandbox, and through what (the agent's tool,
/rewind, the CLI, or Rewind itself). Text is redacted like snapshot commands.
The file is owner-only on POSIX and rotates to ``audit.log.1`` at 5 MB.
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
    line = json.dumps(entry, ensure_ascii=False) + "\n"
    try:
        with _lock:
            target = path()
            target.parent.mkdir(parents=True, exist_ok=True)
            try:
                if target.stat().st_size + len(line) > MAX_BYTES:
                    os.replace(target, target.with_name(target.name + ".1"))
            except FileNotFoundError:
                pass
            fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            with os.fdopen(fd, "a", encoding="utf-8") as f:
                f.write(line)
    except OSError:
        pass


def tail(count: int = 50) -> Iterator[dict]:
    """The last ``count`` events, oldest first (reads the rotated file too if needed)."""
    lines = []
    for candidate in (path().with_name("audit.log.1"), path()):
        try:
            lines += candidate.read_text(encoding="utf-8").splitlines()
        except OSError:
            pass
    for line in lines[-count:]:
        try:
            yield json.loads(line)
        except ValueError:
            continue


_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f]")


def _printable(text: str) -> str:
    """Control characters as visible escapes (\\x1b...). Entries hold agent-written
    text, and `hermes rewind log` prints to a terminal that would act on them."""
    return _CONTROL.sub(lambda m: f"\\x{ord(m.group()):02x}", str(text))


def describe(entry: dict) -> str:
    """One readable line for ``hermes rewind log``."""
    skip = {"ts", "time", "event", "via", "task_id", "pid"}
    details = ", ".join(f"{k}={v}" for k, v in entry.items() if k not in skip and v not in (None, "", []))
    task = entry.get("task_id") or "-"
    return _printable(f"{entry.get('time', '?')}  {entry.get('event', '?'):<18} via {entry.get('via', '?'):<8} {task}"
                      + (f"  {details}" if details else ""))
