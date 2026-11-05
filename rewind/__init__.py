"""Rewind: an undoable Docker sandbox terminal backend for Hermes Agent.

Enable with:
    hermes plugins enable rewind
    hermes config set terminal.backend rewind

Optional settings (environment variables):
    REWIND_IMAGE          base image (default python:3.12-slim)
    REWIND_SNAPSHOT_MODE  mutating | always | off (default mutating)
    REWIND_MAX_SNAPSHOTS  automatic snapshots to keep (default 25)
    REWIND_NETWORK        internet (default; this computer and the LAN are blocked), none, or full
    REWIND_CPUS / REWIND_MEMORY_MB / REWIND_PIDS_LIMIT  sandbox limits (default: Hermes's
                          terminal.container_cpu and container_memory, 2048 processes; 0 = no limit)
    REWIND_COMPACT_MB     compact snapshots once changes pass this size (default 256, 0 = never)
    REWIND_DOCKER_API     set to 0 to always use the docker CLI instead of the Engine API
    REWIND_BACKGROUND     set to 0 to snapshot right before each command instead of in the background
    REWIND_KEEP_HOURS     keep snapshots this long after the sandbox shuts down (default 24, 0 = delete)
    REWIND_STATE_DIR      where parked-sandbox records live (default <HERMES_HOME>/rewind)
    REWIND_EXPORT_DIR     where rewind_export copies files (default <state dir>/exports)
    REWIND_EXPORT_MAX_MB  largest single export allowed (default 500)
    REWIND_EXPORT_TOTAL_MB  cap on everything in the export folder (default 2000)
    REWIND_CONFIRM_EXPORT set to 0 to stop asking before the agent exports files
    REWIND_CONFIRM_IRREVERSIBLE  set to 0 to stop asking before commands Rewind can't undo
    REWIND_AUTO_GC        set to 0 to stop the automatic cleanup of expired snapshots and leftovers
    REWIND_MAX_PARKED_GB  disk cap for kept snapshots together; oldest go first (default 20, 0 = none)
    REWIND_AUDIT          set to 0 to stop writing <state dir>/audit.log
"""
from __future__ import annotations

import os
import shutil
import threading
import time

try:
    from agent.terminal_env_provider import TerminalEnvironmentProvider
except ImportError:  # imported outside Hermes, e.g. by the unit tests
    from ._compat import TerminalEnvironmentProvider

from . import settings, tools, version
from .store import Store
from .environment import (
    DEFAULT_COMPACT_MB,
    DEFAULT_CWD,
    DEFAULT_IMAGE,
    DEFAULT_MAX_SNAPSHOTS,
    RewindEnvironment,
)


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


class RewindProvider(TerminalEnvironmentProvider):
    name = "rewind"
    display_name = "Rewind"
    is_remote = False
    is_container = True
    # Rewind's sandboxes are thrown away when the session ends, so with
    # `terminal.container_persistent: false` each session gets its own.
    session_isolated_when_nonpersistent = True

    @property
    def description(self) -> str:
        return "Run commands in a Docker sandbox where every change can be rolled back."

    @property
    def env_description(self) -> str:
        return (
            "a Debian Linux Docker sandbox. Rewind snapshots it before every command that can "
            "change files; call rewind_restore with 'last' or a snapshot id to undo mistakes"
        )

    @property
    def default_cwd(self) -> str:
        return DEFAULT_CWD

    def is_available(self) -> bool:
        return shutil.which("docker") is not None

    def setup_instructions(self) -> list:
        return [
            "Install Docker Desktop (or Docker Engine) and make sure `docker ps` works.",
            "Run `hermes config set terminal.backend rewind`.",
        ]

    def doctor_checks(self) -> list:
        ok = self.is_available()
        status = version.status()
        return [
            (ok, "Rewind backend", "(docker found)" if ok else "(docker CLI not found on PATH)"),
            (not status["stale"], f"Rewind {status['version']} loaded",
             f"({status['warning']})" if status["stale"] else "(matches the files on disk)"),
        ]

    def create_environment(self, *, cwd, timeout, task_id="default", image=None, container_config=None, **kwargs):
        settings.mark_backend_used()
        keep = settings.keep_hours()
        env = RewindEnvironment(
            cwd=cwd if cwd and cwd != "~" else DEFAULT_CWD,
            timeout=timeout,
            task_id=task_id,
            image=image or os.environ.get("REWIND_IMAGE") or DEFAULT_IMAGE,
            snapshot_mode=os.environ.get("REWIND_SNAPSHOT_MODE", "mutating"),
            max_snapshots=_env_int("REWIND_MAX_SNAPSHOTS", DEFAULT_MAX_SNAPSHOTS),
            network=settings.network_mode(),
            # Hermes's own terminal.container_cpu / container_memory, as its Docker backend uses.
            **settings.limits(container_config or {}),
            compact_mb=_env_int("REWIND_COMPACT_MB", DEFAULT_COMPACT_MB),
            docker_api=os.environ.get("REWIND_DOCKER_API", "1") != "0",
            background=os.environ.get("REWIND_BACKGROUND", "1") != "0",
            keep_hours=keep,
            store=Store(settings.state_dir()) if keep > 0 else None,
            export_max_mb=settings.export_max_mb(),
            export_total_mb=settings.export_total_mb(),
        )
        _maybe_gc()
        return env


_GC_EVERY_SECONDS = 600
_last_gc = 0.0
_gc_lock = threading.Lock()


def _maybe_gc() -> None:
    """Clean up expired snapshots and crashed sessions' leftovers, at most every
    10 minutes, in the background so a new sandbox never waits for it."""
    global _last_gc
    if os.environ.get("REWIND_AUTO_GC", "1") == "0":
        return
    with _gc_lock:
        if time.time() - _last_gc < _GC_EVERY_SECONDS:
            return
        _last_gc = time.time()

    def work() -> None:
        try:
            tools.run_gc()
        except Exception:
            pass  # best effort; `hermes rewind gc` reports problems

    threading.Thread(target=work, name="rewind-gc", daemon=True).start()


def register(ctx) -> None:
    ctx.register_terminal_environment_provider(RewindProvider())
    tools.register(ctx)
