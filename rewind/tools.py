"""What Rewind adds to Hermes besides the terminal backend.

- Agent tools: rewind_list, rewind_snapshot, rewind_restore, rewind_undo,
  rewind_changes, rewind_export.
- ``/rewind`` in a chat, so a person can undo without going through the model.
- A pre_tool_call hook that asks the user before a command Rewind can't undo.
- A short system-prompt section that tells the model how undo works.
- ``hermes rewind status|gc`` on the command line.
"""
from __future__ import annotations

import json
import logging
import shlex
import shutil
import subprocess
import time

from . import policy, registry, settings, store as store_mod, version
from .environment import RewindError, Snapshot, describe_changes, subprocess_runner

TOOLSET = "rewind"

_STATE_HELP = (
    "A snapshot holds the state from BEFORE its command ran: the snapshot listed with `rm -rf x` "
    "still contains x."
)

SCHEMAS = {
    "rewind_undo": {
        "name": "rewind_undo",
        "description": (
            "Undo the most recent change in the sandbox (the terminal and file tools run there). "
            "Call it once per undo the user asks for; calling it again restores the same point, it "
            "does not go further back. Returns which files came back or went away."
        ),
        "parameters": {"type": "object", "properties": {}, "required": []},
    },
    "rewind_list": {
        "name": "rewind_list",
        "description": (
            "List the snapshots of the Rewind sandbox. Rewind snapshots automatically before every "
            f"command that can change files, so each entry is a point you can roll back to. {_STATE_HELP} "
            "Read each entry's `state` field."
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
            "Roll the sandbox back to a snapshot id from rewind_list ('last' = undo the most recent "
            "change; rewind_undo does the same). Call it once: 'last' again restores the same point. "
            "The current state is saved first; to undo a restore, pass the `undo_with` id it returned. "
            "Set preview to true to see which files would come back or go away without restoring."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "snapshot_id": {"type": "string", "description": "Snapshot id such as 's4', or 'last'."},
                "preview": {"type": "boolean", "description": "Only report what would change."},
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
    "rewind_export": {
        "name": "rewind_export",
        "description": (
            "Copy a file or folder out of the sandbox onto the user's computer, e.g. finished work "
            "the user wants to keep. Each export goes into a new folder, nothing is overwritten. "
            "Returns where the copy is."
        ),
        "parameters": {
            "type": "object",
            "properties": {"path": {"type": "string", "description": "Path in the sandbox, e.g. /workspace/app."}},
            "required": ["path"],
        },
    },
}

PROMPT_SECTION = (
    "Rewind sandbox: if the rewind_* tools are available (directly or through tool search), your "
    "terminal and file tools run in a Docker sandbox that is snapshotted before every command that "
    "changes files. To undo the latest change, call rewind_undo once. " + _STATE_HELP + " Never "
    "recreate lost files by hand when a snapshot has them. The restored files are what the next "
    "terminal command sees. Snapshots can't undo anything outside the sandbox (git push, deploys, "
    "HTTP requests, emails). Use rewind_export to hand finished files to the user."
)


def _ok(**data) -> str:
    return json.dumps({"ok": True, **data})


def _err(message: str) -> str:
    return json.dumps({"ok": False, "error": message})


def _env(kwargs):
    """The sandbox for this tool call. Hermes creates a sandbox with the
    session's task_id when sessions are isolated (container_persistent: false)
    and shares one otherwise, so an exact match or the only sandbox covers
    both; anything else is refused rather than guessed."""
    task_id = kwargs.get("task_id")
    env = registry.get(task_id)
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


def _with_status(data: dict) -> dict:
    """Add the plugin's version, and a warning when stale code is running."""
    status = version.status()
    data["plugin_version"] = status["version"]
    if status.get("warning"):
        data["warning"] = status["warning"]
    return data


def _restored(env, target, safety) -> dict:
    changes = env.last_restore_changes
    return {
        "restored": target.describe(),
        "undo_with": safety.id,
        "files": changes,
        "message": (
            f"Sandbox rolled back to {target.id} ({target.state()}). {describe_changes(changes)} "
            f"The terminal now sees this state. Do not restore again unless asked; to undo this "
            f"rollback, restore {safety.id}."
        ),
    }


@_guard
def rewind_list(args, **kwargs):
    env = _env(kwargs)
    snapshots = env.list_snapshots(sizes=True)
    sized = [s["size_mb"] for s in snapshots if s.get("size_mb") is not None]
    return _ok(**_with_status({"snapshots": snapshots, "cwd": env.cwd,
                               "total_mb": round(sum(sized), 1) if sized else None}))


@_guard
def rewind_snapshot(args, **kwargs):
    snap = _env(kwargs).snapshot(str(args.get("label", "manual"))[:80])
    return _ok(snapshot=snap.describe())


@_guard
def rewind_restore(args, **kwargs):
    env = _env(kwargs)
    snapshot_id = str(args.get("snapshot_id", "last"))
    if args.get("preview"):
        target, changes = env.preview(snapshot_id)
        return _ok(preview=target.describe(), files=changes,
                   message=f"Restoring {target.id} ({target.state()}) would change this: "
                           f"{describe_changes(changes)} Nothing was restored.")
    target, safety = env.restore(snapshot_id)
    return _ok(**_with_status(_restored(env, target, safety)))


@_guard
def rewind_undo(args, **kwargs):
    env = _env(kwargs)
    target, safety = env.undo()
    return _ok(**_with_status(_restored(env, target, safety)))


@_guard
def rewind_changes(args, **kwargs):
    return _ok(changes=_env(kwargs).changes())


@_guard
def rewind_export(args, **kwargs):
    path = str(args.get("path", "")).strip()
    if not path:
        raise RewindError("Pass the path of a file or folder in the sandbox.")
    copied = _env(kwargs).export(path, settings.export_dir())
    return _ok(host_path=str(copied), message=f"Copied {path} to {copied} on the user's computer.")


HANDLERS = {
    "rewind_undo": rewind_undo,
    "rewind_list": rewind_list,
    "rewind_snapshot": rewind_snapshot,
    "rewind_restore": rewind_restore,
    "rewind_changes": rewind_changes,
    "rewind_export": rewind_export,
}


def docker_available() -> bool:
    return shutil.which("docker") is not None


# --------------------------------------------------------------- /rewind
SLASH_HELP = (
    "/rewind              list snapshots\n"
    "/rewind undo         undo the most recent change\n"
    "/rewind restore ID   roll back to snapshot ID (e.g. s3)\n"
    "/rewind preview ID   show what restoring ID would change\n"
    "/rewind changes      files changed since the last restore\n"
    "/rewind export PATH  copy PATH out of the sandbox to this computer\n"
    "/rewind status       plugin version and sandbox state"
)


def _session_keys(session_key=None, session_id=None) -> list:
    return [k for k in (session_key and f"session:{session_key}", session_key, session_id,
                        session_id and f"session:{session_id}") if k]


def _session_env(session_key=None, session_id=None):
    keys = _session_keys(session_key, session_id)
    for key in keys:
        if key in registry.keys():
            return registry.get(key)
    env = registry.get(None)  # the only sandbox, if there is exactly one
    if env is None:
        if registry.count() > 1:
            raise RewindError("Several Rewind sandboxes are running and none is this chat's.")
        raise RewindError(_paused_text(keys) or "This chat has no Rewind sandbox yet: run a terminal command first.")
    return env


def _paused_text(keys) -> str:
    """When this chat's sandbox is parked (Hermes shut it down while idle), say so."""
    store = store_mod.Store(settings.state_dir())
    record = next((r for r in map(store.load, keys) if r and r.get("status") == "parked"), None)
    if record is None:
        return ""
    hours = max(0.0, (float(record.get("expires_at") or time.time()) - time.time()) / 3600)
    lines = [f"This chat's sandbox is paused (Hermes shuts idle sandboxes down). Its "
             f"{len(record.get('snapshots', []))} snapshot(s) are kept for {hours:.1f} h more:"]
    for snap in record.get("snapshots", []):
        lines.append(f"  {snap.get('id', '?'):>4}  {_recorded_state(snap)}")
    lines.append("Run any terminal command (or ask the agent to) and it resumes with this history; "
                 "then /rewind undo works as usual.")
    return "\n".join(lines)


def _recorded_state(snap: dict) -> str:
    """The `state` text for a snapshot read back from a parked record."""
    defaults = {"id": "", "image": "", "label": "", "command": "", "cwd": "/", "created_at": 0, "auto": False}
    return Snapshot.from_dict({**defaults, **snap}).state()


def _format_snapshots(env) -> str:
    snaps = env.list_snapshots(sizes=True)
    if not snaps:
        return "No snapshots yet. Rewind takes one before each command that changes files."
    lines = ["Snapshots (newest last). Each is the state BEFORE its command:"]
    for s in snaps:
        size = f", {s['size_mb']} MB" if s.get("size_mb") is not None else ""
        lines.append(f"  {s['id']:>4}  {s['state']}  ({int(s['age_seconds'])}s ago{size})")
    lines.append("Undo the latest change with /rewind undo, or roll back with /rewind restore ID.")
    return "\n".join(lines)


def slash_rewind(raw_args: str = "", session_key=None, session_id=None, **_ignored) -> str:
    """Handler for /rewind. Runs Rewind directly; the model is not involved."""
    try:
        words = shlex.split(raw_args or "")
    except ValueError:
        words = (raw_args or "").split()
    sub = words[0].lower() if words else "list"
    rest = words[1:]
    status = version.status()
    stale = f"\n\nWarning: {status['warning']}" if status.get("warning") else ""
    try:
        if sub in ("help", "-h", "--help"):
            return SLASH_HELP
        if sub == "status":
            return _status_text() + stale
        env = _session_env(session_key, session_id)
        if sub in ("list", "ls"):
            return _format_snapshots(env) + stale
        if sub in ("undo", "restore"):
            if sub == "restore" and not rest:
                return "Usage: /rewind restore ID (see /rewind for ids)."
            target, safety = env.undo() if sub == "undo" else env.restore(rest[0])
            return (f"Rolled back to {target.id} ({target.state()}).\n"
                    f"{describe_changes(env.last_restore_changes)}\n"
                    f"To undo this, run /rewind restore {safety.id}." + stale)
        if sub == "preview":
            target, changes = env.preview(rest[0] if rest else "last")
            return f"Restoring {target.id} ({target.state()}) would change:\n{describe_changes(changes)}"
        if sub == "changes":
            changes = env.changes()
            return "\n".join(changes) if changes else "No changes since the sandbox started or was restored."
        if sub == "export":
            if not rest:
                return "Usage: /rewind export PATH (a file or folder in the sandbox)."
            return f"Copied to {env.export(rest[0], settings.export_dir())}"
        return f"Unknown /rewind command {sub!r}.\n\n{SLASH_HELP}"
    except (RewindError, subprocess.TimeoutExpired, OSError) as exc:
        return f"Rewind: {exc}"


# ------------------------------------------------------------ status / gc
def _status_text() -> str:
    status = version.status()
    lines = [f"Rewind {status['version']}"]
    if status.get("warning"):
        lines.append(f"Warning: {status['warning']}")
    lines.append(f"Snapshots kept after a sandbox shuts down: {settings.keep_hours():g} h (REWIND_KEEP_HOURS)")
    lines.append(f"State folder: {settings.state_dir()}")
    store = store_mod.Store(settings.state_dir())
    records = list(store.records())
    if not records:
        lines.append("No sandboxes recorded.")
    for record in records:
        state = record.get("status")
        if state == "live":
            state = f"live (process {record.get('owner_pid')})"
        elif record.get("expires_at"):
            hours = max(0.0, (float(record["expires_at"]) - time.time()) / 3600)
            state = f"parked, kept {hours:.1f} h more"
        lines.append(f"  {record['task_id']}: {len(record.get('snapshots', []))} snapshot(s), {state}")
    return "\n".join(lines)


def run_gc() -> dict:
    """Delete expired snapshots and leftovers of dead processes now."""
    return store_mod.reap(store_mod.Store(settings.state_dir()), subprocess_runner,
                          keep_seconds=settings.keep_hours() * 3600,
                          live_repositories=registry.repositories())


def _cli_setup(parser) -> None:
    sub = parser.add_subparsers(dest="rewind_command")
    sub.add_parser("status", help="Show the plugin version and recorded sandboxes")
    sub.add_parser("gc", help="Delete expired snapshots and leftovers from crashed sessions")


def _cli_handler(args) -> int:
    if getattr(args, "rewind_command", None) == "gc":
        counts = run_gc()
        print("Rewind cleanup: " + ", ".join(f"{v} {k}" for k, v in counts.items()))
    else:
        print(_status_text())
    return 0


# --------------------------------------------------------------- hooks
def pre_tool_call(tool_name: str = "", args=None, task_id=None, **_ignored):
    """Ask the user before a terminal command whose effects Rewind can't undo."""
    if tool_name != "terminal" or not isinstance(args, dict):
        return None
    if not settings.confirm_irreversible() or not settings.network_enabled() or not settings.backend_active():
        return None
    command = args.get("command")
    if not isinstance(command, str):
        return None
    reason = policy.irreversible_reason(command)
    if not reason:
        return None
    program = reason.split("`")[1].split()[0] if "`" in reason else "command"
    return {
        "action": "approve",
        "message": f"Rewind can't undo this: {reason}. Snapshots only cover the sandbox's files. Run it?",
        "rule_key": f"rewind-irreversible-{program}",
    }


def register(ctx) -> None:
    for name, schema in SCHEMAS.items():
        ctx.register_tool(name, TOOLSET, schema, HANDLERS[name], check_fn=docker_available)
    # The rest is optional: older Hermes versions or test doubles may lack it.
    for method, call in (
        ("register_command", lambda: ctx.register_command(
            "rewind", slash_rewind, description="Undo or inspect the Rewind sandbox without the model",
            args_hint="[undo|restore ID|preview ID|changes|export PATH|status]")),
        ("register_hook", lambda: ctx.register_hook("pre_tool_call", pre_tool_call)),
        ("register_system_prompt_section", lambda: ctx.register_system_prompt_section(
            "rewind.undo", PROMPT_SECTION)),
        ("register_cli_command", lambda: ctx.register_cli_command(
            "rewind", "Rewind sandbox status and cleanup", _cli_setup, _cli_handler,
            description="Show Rewind's version and recorded sandboxes, or clean up old snapshots.")),
    ):
        if callable(getattr(ctx, method, None)):
            try:
                call()
            except Exception as exc:  # never let an optional surface break the backend
                logging.getLogger(__name__).warning("Rewind could not %s: %s", method, exc)
