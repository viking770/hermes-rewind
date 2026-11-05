"""Which Rewind version is running, and whether the files on disk have changed since.

Hermes imports a plugin once per process. The gateway is a long-running
process, so after the plugin files are updated it keeps running the old code
until it restarts, with nothing to show for it. This module fingerprints the
plugin's files at import and compares later, so Rewind can say so.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, List, Optional

VERSION = "0.2.3"

_DIR = Path(__file__).resolve().parent
_VERSION_LINE = re.compile(r"^version:\s*[\"']?([^\"'\s#]+)", re.MULTILINE)


def _fingerprint() -> Dict[str, int]:
    files = sorted(_DIR.glob("*.py")) + [_DIR / "plugin.yaml"]
    prints = {}
    for path in files:
        try:
            prints[path.name] = path.stat().st_mtime_ns
        except OSError:
            pass
    return prints


_LOADED = _fingerprint()


def changed_files() -> List[str]:
    """Plugin files added, removed or modified since this process loaded Rewind."""
    now = _fingerprint()
    return sorted(name for name in set(now) | set(_LOADED) if now.get(name) != _LOADED.get(name))


def disk_version() -> Optional[str]:
    try:
        match = _VERSION_LINE.search((_DIR / "plugin.yaml").read_text(encoding="utf-8"))
    except OSError:
        return None
    return match.group(1) if match else None


RESTART_HINT = "Run `hermes gateway restart` (and restart any open `hermes` CLI) to load it."


def status() -> dict:
    """``{"version", "stale", ...}``; when stale, also what changed and how to fix it."""
    changed = changed_files()
    info = {"version": VERSION, "stale": bool(changed)}
    if changed:
        on_disk = disk_version()
        info["changed_files"] = changed
        info["warning"] = (
            f"Rewind {VERSION} is running, but the plugin files on disk changed since it loaded"
            + (f" (now version {on_disk})" if on_disk and on_disk != VERSION else "")
            + f". {RESTART_HINT}"
        )
    return info
