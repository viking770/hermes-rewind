"""Rewind: an undoable Docker sandbox terminal backend for Hermes Agent.

Enable with:
    hermes plugins enable rewind
    hermes config set terminal.backend rewind

Optional settings (environment variables):
    REWIND_IMAGE          base image (default python:3.12-slim)
    REWIND_SNAPSHOT_MODE  mutating | always | off (default mutating)
    REWIND_MAX_SNAPSHOTS  automatic snapshots to keep (default 25)
    REWIND_NETWORK        set to 0 to run the sandbox without network access
    REWIND_COMPACT_MB     compact snapshots once changes pass this size (default 256, 0 = never)
    REWIND_DOCKER_API     set to 0 to always use the docker CLI instead of the Engine API
    REWIND_BACKGROUND     set to 0 to snapshot right before each command instead of in the background
"""
from __future__ import annotations

import os
import shutil

try:
    from agent.terminal_env_provider import TerminalEnvironmentProvider
except ImportError:  # imported outside Hermes, e.g. by the unit tests
    from ._compat import TerminalEnvironmentProvider

from . import tools
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
        return [(ok, "Rewind backend", "(docker found)" if ok else "(docker CLI not found on PATH)")]

    def create_environment(self, *, cwd, timeout, task_id="default", image=None, container_config=None, **kwargs):
        return RewindEnvironment(
            cwd=cwd if cwd and cwd != "~" else DEFAULT_CWD,
            timeout=timeout,
            task_id=task_id,
            image=image or os.environ.get("REWIND_IMAGE") or DEFAULT_IMAGE,
            snapshot_mode=os.environ.get("REWIND_SNAPSHOT_MODE", "mutating"),
            max_snapshots=_env_int("REWIND_MAX_SNAPSHOTS", DEFAULT_MAX_SNAPSHOTS),
            network=os.environ.get("REWIND_NETWORK", "1") != "0",
            compact_mb=_env_int("REWIND_COMPACT_MB", DEFAULT_COMPACT_MB),
            docker_api=os.environ.get("REWIND_DOCKER_API", "1") != "0",
            background=os.environ.get("REWIND_BACKGROUND", "1") != "0",
        )


def register(ctx) -> None:
    ctx.register_terminal_environment_provider(RewindProvider())
    tools.register(ctx)
