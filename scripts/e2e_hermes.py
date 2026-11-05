"""End-to-end check of Rewind inside a real Hermes chat, with a real model.

    python scripts/e2e_hermes.py [--model MODEL] [--keep]

Runs one scripted chat through `hermes chat --oneshot --format stream-json`
and checks the *tool results* (not the model's summary): the snapshot list
says what each snapshot holds, undo brings the file back, undoing twice is
harmless, a restore can be undone, preview changes nothing, export copies the
file out, and the plugin version Hermes loaded is this checkout's.

The chat runs with --yolo so Hermes doesn't stop for approvals; every command
runs inside the Rewind sandbox. Close your own Hermes chats first: with
Hermes's default shared sandbox the test would act on theirs. The sandbox and
snapshots it creates are deleted at the end unless you pass --keep.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))
from rewind.version import VERSION  # noqa: E402

PROMPT = """You are testing the Rewind terminal backend. Do these steps in order, exactly as
written, one tool call per step. Do not skip, repeat or add steps. If a tool is not
listed, find it with tool search. Reply at the end with one line per step.

1. terminal: mkdir -p /workspace/demo && echo hi > /workspace/demo/hello.txt
2. terminal: rm -rf /workspace/demo
3. rewind_list
4. rewind_restore with snapshot_id "last" and preview true
5. rewind_undo
6. rewind_undo
7. terminal: cat /workspace/demo/hello.txt
8. rewind_export with path "/workspace/demo"
9. rewind_restore with the undo_with id that step 5 returned
10. terminal: ls /workspace
"""


def hermes_home() -> str:
    home = os.environ.get("HERMES_HOME")
    if home and Path(home).is_dir():
        return home
    for path in ([Path(os.environ["LOCALAPPDATA"]) / "hermes"] if os.name == "nt" and "LOCALAPPDATA" in os.environ
                 else []) + [Path.home() / ".hermes"]:
        if (path / "config.yaml").is_file():
            return str(path)
    sys.exit("Couldn't find the Hermes home folder. Set HERMES_HOME.")


def docker_lines(*args: str) -> set:
    out = subprocess.run(["docker", *args], capture_output=True, text=True).stdout
    return {line.strip() for line in out.splitlines() if line.strip()}


def run_chat(env: dict, model: str | None, log: Path) -> list:
    exe = shutil.which("hermes") or sys.exit("`hermes` is not on PATH.")
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False, encoding="utf-8") as f:
        f.write(PROMPT)
        query = f.name
    argv = [exe, "chat", "--query-file", query, "--oneshot", "--format", "stream-json", "--yolo",
            "--max-turns", "40"] + (["-m", model] if model else [])
    proc = subprocess.run(argv, env=env, capture_output=True, text=True, encoding="utf-8",
                          errors="replace", timeout=1200)
    log.write_text(proc.stdout + "\n--- stderr ---\n" + proc.stderr, encoding="utf-8")
    events = []
    for line in proc.stdout.splitlines():
        line = line.strip().lstrip("﻿")
        if line.startswith("{"):
            try:
                events.append(json.loads(line))
            except ValueError:
                pass
    return events


def tool_results(events: list) -> list:
    """[(tool name, input, parsed output)] in call order."""
    inputs = {e.get("tool_call_id"): e.get("input") for e in events if e.get("type") == "tool_use"}
    results = []
    for e in events:
        if e.get("type") != "tool_result":
            continue
        try:
            output = json.loads(e.get("output") or "{}")
        except ValueError:
            output = {"raw": e.get("output")}
        results.append((e.get("name"), inputs.get(e.get("tool_call_id")) or {}, output))
    return results


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):  # Windows consoles may not be UTF-8
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--model", help="model to use instead of your configured default")
    parser.add_argument("--keep", action="store_true", help="leave the test sandbox and snapshots")
    args = parser.parse_args()

    env = {**os.environ, "HERMES_HOME": hermes_home()}
    containers_before = docker_lines("ps", "-a", "--filter", "label=hermes.rewind=1", "--format", "{{.Names}}")
    log = Path(tempfile.gettempdir()) / "rewind-e2e.jsonl"
    print(f"Running the scripted chat (log: {log}) ...")
    results = tool_results(run_chat(env, args.model, log))

    checks = []

    def check(name, ok, detail=""):
        checks.append(ok)
        print(f"  {'PASS' if ok else 'FAIL'}  {name}" + (f"  ({detail})" if detail and not ok else ""))

    by_name = lambda n: [r for r in results if r[0] == n]  # noqa: E731
    terminal = lambda pattern: [r for r in results if r[0] == "terminal"  # noqa: E731
                                and re.search(pattern, str(r[1].get("command", "")))]

    lists = by_name("rewind_list")
    states = [s.get("state", "") for s in (lists[0][2].get("snapshots", []) if lists else [])]
    check("rewind_list explains each snapshot", any("state before running: rm -rf /workspace/demo" in s
                                                     for s in states), states)
    loaded = lists[0][2].get("plugin_version") if lists else None
    check(f"Hermes loaded this checkout's version ({VERSION})", loaded == VERSION and "warning" not in lists[0][2],
          f"loaded {loaded}, {lists[0][2].get('warning', '') if lists else 'no rewind_list call'}")

    previews = [r for r in by_name("rewind_restore") if r[1].get("preview")]
    check("preview lists the file that would come back",
          bool(previews) and "demo/hello.txt" in previews[0][2].get("files", {}).get("appear", []),
          previews[0][2] if previews else "no preview call")

    undos = by_name("rewind_undo")
    ids = [u[2].get("restored", {}).get("id") for u in undos[:2]]
    check("undo restores the snapshot from before the delete", bool(undos)
          and "demo/hello.txt" in (undos[0][2].get("files") or {}).get("appear", []), undos[:1])
    check("a second undo is harmless (same snapshot)", len(ids) == 2 and ids[0] == ids[1], ids)

    cats = terminal(r"cat /workspace/demo/hello\.txt")
    check("the file is back", bool(cats) and cats[-1][2].get("output", "").strip() == "hi", cats[-1:] or "no cat")

    exports = by_name("rewind_export")
    host = Path(exports[0][2].get("host_path", "")) if exports and exports[0][2].get("ok") else None
    check("export copied the folder to this computer",
          bool(host) and (host / "hello.txt").is_file() and (host / "hello.txt").read_text().strip() == "hi",
          exports[:1] or "no export call")

    undo_id = undos[0][2].get("undo_with") if undos else None
    redo = [r for r in by_name("rewind_restore") if not r[1].get("preview") and r[1].get("snapshot_id") == undo_id]
    listing = terminal(r"^ls /workspace")
    check("a restore can itself be undone", bool(redo) and bool(listing)
          and "demo" not in listing[-1][2].get("output", ""), f"undo_with={undo_id}, ls={listing[-1:]}")

    if not args.keep:
        new = docker_lines("ps", "-a", "--filter", "label=hermes.rewind=1", "--format", "{{.Names}}") - containers_before
        for name in new:
            repo = name.replace("hermes-rewind-", "hermes-rewind/", 1)
            images = docker_lines("images", repo, "--format", "{{.Repository}}:{{.Tag}}")
            subprocess.run(["docker", "rm", "-f", name], capture_output=True)
            if images:
                subprocess.run(["docker", "rmi", "-f", *images], capture_output=True)
            state = Path(os.environ.get("REWIND_STATE_DIR") or Path(env["HERMES_HOME"]) / "rewind") / "sandboxes"
            for record in state.glob("*.json"):  # its record, so nothing tries to resume it
                try:
                    if json.loads(record.read_text(encoding="utf-8")).get("repository") == repo:
                        record.unlink()
                except (OSError, ValueError):
                    pass
        if host:
            shutil.rmtree(host.parent, ignore_errors=True)
        print(f"Removed {len(new)} test sandbox(es).")

    passed = sum(checks)
    print(f"{passed}/{len(checks)} checks passed.")
    return 0 if passed == len(checks) else 1


if __name__ == "__main__":
    sys.exit(main())
