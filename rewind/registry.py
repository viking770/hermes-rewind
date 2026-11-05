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
    """Return the sandbox registered under exactly ``task_id``, or None."""
    with _lock:
        return _by_task.get(task_id) if task_id else None


# Keys Hermes uses for a sandbox it shares on purpose (container_persistent:
# true): the default profile's "default", "profile:<name>", "shared:<key>".
_SHARED_PREFIXES = ("profile:", "shared:")
# Session ids are long random strings; a shorter id is not trusted for a suffix match.
_MIN_SUFFIX_LEN = 12


def is_shared_key(key: str) -> bool:
    return key == "default" or key.startswith(_SHARED_PREFIXES)


def find(*ids: Optional[str], allow_shared: bool = True) -> Optional[Any]:
    """The sandbox that belongs to the caller, or None. Never "whichever is running".

    Hermes keys a session's sandbox ``session:<session key>``, and the session
    key ends with the session id, while tool calls carry the session id as
    their task_id. So, in order:

    1. a sandbox registered under one of ``ids`` (or ``session:<id>``);
    2. one whose key ends with ``:<id>`` for a long id (the session id);
    3. with ``allow_shared``, the one sandbox Hermes shares on purpose, which
       is also the sandbox Hermes's own terminal tool uses for this caller.
    """
    ids = [i for i in ids if i]
    with _lock:
        for i in ids:
            for key in (i, f"session:{i}"):
                if key in _by_task:
                    return _by_task[key]
        for i in ids:
            if len(i) >= _MIN_SUFFIX_LEN:
                matches = {id(env): env for key, env in _by_task.items() if key.endswith(f":{i}")}
                if len(matches) == 1:
                    return next(iter(matches.values()))
        if allow_shared:
            shared = {id(env): env for key, env in _by_task.items() if is_shared_key(key)}
            if len(shared) == 1:
                return next(iter(shared.values()))
    return None


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
