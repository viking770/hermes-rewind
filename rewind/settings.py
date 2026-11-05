"""Rewind's settings, read from environment variables (see the README table)."""
from __future__ import annotations

import os
from pathlib import Path

from . import store as store_mod
from .environment import DEFAULT_EXPORT_MAX_MB, DEFAULT_KEEP_HOURS

# Set once this process has created a Rewind sandbox, i.e. Rewind is the
# terminal backend here. Hermes also exports TERMINAL_ENV in some setups.
_backend_used = False


def mark_backend_used() -> None:
    global _backend_used
    _backend_used = True


def backend_active() -> bool:
    return _backend_used or os.environ.get("TERMINAL_ENV", "").strip().lower() == "rewind"


def _float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, default))
    except ValueError:
        return default


def keep_hours() -> float:
    """How long snapshots outlive their sandbox (REWIND_KEEP_HOURS, 0 = delete at cleanup)."""
    return max(0.0, _float("REWIND_KEEP_HOURS", DEFAULT_KEEP_HOURS))


def state_dir() -> Path:
    return store_mod.default_dir()


def export_dir() -> Path:
    override = os.environ.get("REWIND_EXPORT_DIR")
    return Path(override) if override else state_dir() / "exports"


def export_max_mb() -> int:
    return int(max(0, _float("REWIND_EXPORT_MAX_MB", DEFAULT_EXPORT_MAX_MB)))


def confirm_irreversible() -> bool:
    """Ask the user before commands Rewind can't undo (REWIND_CONFIRM_IRREVERSIBLE, default on)."""
    return os.environ.get("REWIND_CONFIRM_IRREVERSIBLE", "1") != "0"


def network_enabled() -> bool:
    return os.environ.get("REWIND_NETWORK", "1") != "0"
