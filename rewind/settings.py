"""Rewind's settings, read from environment variables (see the README table)."""
from __future__ import annotations

import os
from pathlib import Path

from . import store as store_mod
from .environment import (
    DEFAULT_CPUS, DEFAULT_EXPORT_MAX_MB, DEFAULT_EXPORT_TOTAL_MB, DEFAULT_KEEP_HOURS, DEFAULT_MEMORY_MB, DEFAULT_PIDS_LIMIT,
    NETWORK_MODES,
)

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


def export_total_mb() -> int:
    """Cap on everything in the export folder (REWIND_EXPORT_TOTAL_MB, 0 = no cap)."""
    return int(max(0, _float("REWIND_EXPORT_TOTAL_MB", DEFAULT_EXPORT_TOTAL_MB)))


DEFAULT_MAX_PARKED_GB = 20


def max_parked_bytes() -> int:
    """Disk cap for parked snapshots together (REWIND_MAX_PARKED_GB, 0 = no cap)."""
    return int(max(0.0, _float("REWIND_MAX_PARKED_GB", DEFAULT_MAX_PARKED_GB)) * 1024 ** 3)


def confirm_export() -> bool:
    """Ask the user before the agent copies files onto this computer (REWIND_CONFIRM_EXPORT)."""
    return os.environ.get("REWIND_CONFIRM_EXPORT", "1") != "0"


def confirm_irreversible() -> bool:
    """Ask the user before commands Rewind can't undo (REWIND_CONFIRM_IRREVERSIBLE, default on)."""
    return os.environ.get("REWIND_CONFIRM_IRREVERSIBLE", "1") != "0"


def network_mode() -> str:
    """REWIND_NETWORK: internet (default: internet, but not this computer or the
    LAN), none, or full (unrestricted). The old 1/0 mean internet/none."""
    raw = os.environ.get("REWIND_NETWORK", "internet").strip().lower()
    return {"1": "internet", "true": "internet", "on": "internet", "0": "none", "false": "none",
            "off": "none"}.get(raw, raw if raw in NETWORK_MODES else "internet")


def network_enabled() -> bool:
    return network_mode() != "none"


def _limit(env_name: str, config: dict, key: str, default):
    """A resource limit: REWIND_* env var, else Hermes's terminal.<key>, else the default."""
    for raw in (os.environ.get(env_name), (config or {}).get(key)):
        if raw in (None, ""):
            continue
        try:
            value = float(raw)
        except (TypeError, ValueError):
            continue
        return None if value <= 0 else value
    return default


def limits(container_config: dict) -> dict:
    """cpus / memory_mb / pids_limit for a sandbox. 0 turns a limit off."""
    cpus = _limit("REWIND_CPUS", container_config, "container_cpu", DEFAULT_CPUS)
    memory = _limit("REWIND_MEMORY_MB", container_config, "container_memory", DEFAULT_MEMORY_MB)
    pids = _limit("REWIND_PIDS_LIMIT", {}, "", DEFAULT_PIDS_LIMIT)
    return {"cpus": cpus, "memory_mb": int(memory) if memory else None, "pids_limit": int(pids) if pids else None}
