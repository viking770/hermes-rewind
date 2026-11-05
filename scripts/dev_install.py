"""Install this checkout's plugin into Hermes and make sure the new code is the code running.

    python scripts/dev_install.py            # copy, restart the gateway, check
    python scripts/dev_install.py --no-restart

Hermes loads plugins once per process, and the gateway runs for a long time,
so copying files alone leaves the old code running. This copies rewind/ into
<HERMES_HOME>/plugins/rewind, restarts the gateway if one is running, and
prints what `hermes doctor` reports for Rewind.
"""
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SRC = REPO / "rewind"


def hermes_home() -> Path:
    if os.environ.get("HERMES_HOME") and Path(os.environ["HERMES_HOME"]).is_dir():
        return Path(os.environ["HERMES_HOME"])
    candidates = [Path.home() / ".hermes"]
    if os.name == "nt" and os.environ.get("LOCALAPPDATA"):
        candidates.insert(0, Path(os.environ["LOCALAPPDATA"]) / "hermes")
    for path in candidates:
        if (path / "config.yaml").is_file():
            return path
    sys.exit("Couldn't find the Hermes home folder. Set HERMES_HOME.")


def hermes(*args: str, env: dict) -> subprocess.CompletedProcess:
    exe = shutil.which("hermes")
    if not exe:
        sys.exit("`hermes` is not on PATH.")
    return subprocess.run([exe, *args], env=env, capture_output=True, text=True,
                          encoding="utf-8", errors="replace", timeout=300)


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):  # Hermes prints ✓; Windows consoles may not be UTF-8
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--no-restart", action="store_true", help="copy only; don't restart the gateway")
    args = parser.parse_args()

    home = hermes_home()
    env = {**os.environ, "HERMES_HOME": str(home)}
    dest = home / "plugins" / "rewind"
    if dest.exists():
        shutil.rmtree(dest)
    shutil.copytree(SRC, dest, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    print(f"Copied {SRC} -> {dest}")

    if args.no_restart:
        print("Not restarting. Run `hermes gateway restart` before testing.")
        return 0
    status = hermes("gateway", "status", env=env)
    if "running" in (status.stdout + status.stderr).lower() and "not running" not in status.stdout.lower():
        restart = hermes("gateway", "restart", env=env)
        print("Gateway restarted." if restart.returncode == 0 else f"Gateway restart failed:\n{restart.stdout}{restart.stderr}")
    else:
        print("No gateway running; the next `hermes` will load the new code.")

    doctor = hermes("doctor", env=env)
    lines = [line.strip() for line in doctor.stdout.splitlines() if "Rewind" in line]
    print("\n".join(lines) or "hermes doctor printed no Rewind lines (is the backend set to rewind?)")
    print("In a chat, `/rewind status` shows the version that chat's process is running.\n"
          "Close any open `hermes` chat and start a new one to use the new code there too.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
