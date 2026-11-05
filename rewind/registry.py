"""Tracks live Rewind sandboxes so the rewind_* tools can find the right one."""
from __future__ import annotations

import threading
from typing import Any, Dict, Optional

_lock = threading.Lock()
_by_task: Dict[str, Any] = {}
_latest: Optional[Any] = None


def add(task_id: str, env: Any) -> None:
    global _latest
    with _lock:
        _by_task[task_id] = env
        _latest = env


def remove(env: Any) -> None:
    global _latest
    with _lock:
        for key in [k for k, v in _by_task.items() if v is env]:
            del _by_task[key]
        if _latest is env:
            _latest = next(reversed(list(_by_task.values())), None)


def get(task_id: Optional[str] = None) -> Optional[Any]:
    """Return the sandbox for ``task_id``, or the most recent one."""
    with _lock:
        if task_id and task_id in _by_task:
            return _by_task[task_id]
        return _latest


def clear() -> None:
    """Forget every sandbox (used by tests)."""
    global _latest
    with _lock:
        _by_task.clear()
        _latest = None
