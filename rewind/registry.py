"""Tracks live Rewind sandboxes so the rewind_* tools can find the right one."""
from __future__ import annotations

import threading
from typing import Any, Dict, Optional

_lock = threading.Lock()
_by_task: Dict[str, Any] = {}


def add(task_id: str, env: Any) -> None:
    with _lock:
        _by_task[task_id] = env


def remove(env: Any) -> None:
    with _lock:
        for key in [k for k, v in _by_task.items() if v is env]:
            del _by_task[key]


def get(task_id: Optional[str] = None) -> Optional[Any]:
    """Return the sandbox for ``task_id``, or the only one running.

    With several sandboxes and no match, return None rather than guess: acting
    on the most recent one could roll back another session's sandbox."""
    with _lock:
        if task_id and task_id in _by_task:
            return _by_task[task_id]
        live = {id(env): env for env in _by_task.values()}
        return next(iter(live.values())) if len(live) == 1 else None


def keys() -> list:
    with _lock:
        return list(_by_task)


def repositories() -> list:
    """Image repositories of the sandboxes in this process, which cleanup must not touch."""
    with _lock:
        return sorted({getattr(env, "repository", "") for env in _by_task.values()} - {""})


def count() -> int:
    with _lock:
        return len({id(env) for env in _by_task.values()})


def clear() -> None:
    """Forget every sandbox (used by tests)."""
    with _lock:
        _by_task.clear()
