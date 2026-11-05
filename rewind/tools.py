"""Agent-facing tools for listing, taking and restoring Rewind snapshots."""
from __future__ import annotations

import json
import shutil
import subprocess

from . import registry
from .environment import RewindEnvironment, RewindError

TOOLSET = "rewind"

SCHEMAS = {
    "rewind_list": {
        "name": "rewind_list",
        "description": (
            "List the snapshots of the Rewind sandbox. Rewind snapshots automatically before "
            "every command that can change files, so each entry is a point you can roll back to."
        ),
        "parameters": {"type": "object", "properties": {}, "required": []},
    },
    "rewind_snapshot": {
        "name": "rewind_snapshot",
        "description": "Save a named checkpoint of the sandbox now, e.g. before a risky refactor.",
        "parameters": {
            "type": "object",
            "properties": {"label": {"type": "string", "description": "Short name for the checkpoint."}},
            "required": ["label"],
        },
    },
    "rewind_restore": {
        "name": "rewind_restore",
        "description": (
            "Roll the sandbox back to a snapshot. Use 'last' to undo the most recent change. "
            "The current state is saved first, so a restore can itself be undone."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "snapshot_id": {"type": "string", "description": "Snapshot id such as 's4', or 'last'."}
            },
            "required": ["snapshot_id"],
        },
    },
    "rewind_changes": {
        "name": "rewind_changes",
        "description": (
            "Show files added (A), changed (C) or deleted (D) in the sandbox since it was "
            "created or last restored."
        ),
        "parameters": {"type": "object", "properties": {}, "required": []},
    },
}


def _ok(**data) -> str:
    return json.dumps({"ok": True, **data})


def _err(message: str) -> str:
    return json.dumps({"ok": False, "error": message})


def _hermes_env(task_id):
    """The sandbox Hermes's terminal tool uses for this task_id. Hermes keys
    sandboxes by its own scheme (one shared "default" sandbox unless
    container_persistent is false), so ask it rather than guess."""
    try:
        from tools.terminal_tool_lifecycle import get_active_env
        env = get_active_env(task_id or "default")
    except Exception:  # not running inside Hermes, or its internals changed
        return None
    return env if isinstance(env, RewindEnvironment) else None


def _env(kwargs):
    task_id = kwargs.get("task_id")
    env = _hermes_env(task_id) or registry.get(task_id)
    if env is None:
        if registry.count() > 1:
            raise RewindError(
                f"Several Rewind sandboxes are running and none belongs to task {task_id!r}, "
                "so Rewind won't guess which one to act on."
            )
        raise RewindError(
            "No Rewind sandbox is running. Set `hermes config set terminal.backend rewind` "
            "and run a terminal command first."
        )
    return env


def _guard(fn):
    def handler(args, **kwargs):
        try:
            return fn(args or {}, **kwargs)
        except (RewindError, subprocess.TimeoutExpired, OSError) as exc:
            return _err(str(exc))
    return handler


@_guard
def rewind_list(args, **kwargs):
    env = _env(kwargs)
    return _ok(snapshots=env.list_snapshots(), cwd=env.cwd)


@_guard
def rewind_snapshot(args, **kwargs):
    snap = _env(kwargs).snapshot(str(args.get("label", "manual"))[:80])
    return _ok(snapshot=snap.describe())


@_guard
def rewind_restore(args, **kwargs):
    target, safety = _env(kwargs).restore(str(args.get("snapshot_id", "last")))
    return _ok(
        restored=target.describe(),
        undo_with=safety.id,
        message=f"Sandbox rolled back to {target.id}. Restore {safety.id} to undo this rollback.",
    )


@_guard
def rewind_changes(args, **kwargs):
    return _ok(changes=_env(kwargs).changes())


HANDLERS = {
    "rewind_list": rewind_list,
    "rewind_snapshot": rewind_snapshot,
    "rewind_restore": rewind_restore,
    "rewind_changes": rewind_changes,
}


def docker_available() -> bool:
    return shutil.which("docker") is not None


def register(ctx) -> None:
    for name, schema in SCHEMAS.items():
        ctx.register_tool(name, TOOLSET, schema, HANDLERS[name], check_fn=docker_available)
