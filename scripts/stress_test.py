"""Stress test: attack every protection Rewind claims, against real Docker.

    python scripts/stress_test.py            # everything (about 3 to 6 minutes)
    python scripts/stress_test.py network undo export   # only some sections
    python scripts/stress_test.py --list     # section names

Each check runs real commands in real sandboxes and prints PASS or FAIL with
what it saw. State, exports and the audit log go to a temporary folder (your
Hermes data is never touched), and every container and image the run creates
is removed at the end. Exit code 0 means every check passed.

Needs Docker running. The first run builds Rewind's images (about a minute).
"""
from __future__ import annotations

import contextlib
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import traceback
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# Isolate everything before Rewind reads its settings.
WORK = Path(tempfile.mkdtemp(prefix="rewind-stress-"))
os.environ["REWIND_STATE_DIR"] = str(WORK / "state")
os.environ["REWIND_EXPORT_DIR"] = str(WORK / "exports")
os.environ.pop("TERMINAL_ENV", None)

from rewind import audit, registry, settings, tools  # noqa: E402
from rewind.environment import RewindEnvironment, RewindError, host_addresses  # noqa: E402
from rewind.redact import MASK  # noqa: E402
from rewind.store import Store  # noqa: E402

GREEN, RED, DIM, BOLD, RESET = ("\033[32m", "\033[31m", "\033[2m", "\033[1m", "\033[0m") \
    if sys.stdout.isatty() else ("", "", "", "", "")
RESULTS: list = []
ENVS: list = []


# ------------------------------------------------------------------ helpers
def check(name: str, ok: bool, saw: str = "") -> bool:
    RESULTS.append((CURRENT[0], name, bool(ok), saw))
    mark = f"{GREEN}PASS{RESET}" if ok else f"{RED}FAIL{RESET}"
    detail = f"  {DIM}{saw.strip()[:160]}{RESET}" if saw and (not ok or VERBOSE) else ""
    print(f"  {mark}  {name}{detail}")
    return bool(ok)


CURRENT = ["setup"]
VERBOSE = "-v" in sys.argv


def sandbox(task: str, **kw) -> RewindEnvironment:
    kw.setdefault("background", False)
    kw.setdefault("network", "none")
    env = RewindEnvironment(task_id=f"stress-{task}", timeout=120, **kw)
    ENVS.append(env)
    return env


def run(env: RewindEnvironment, command: str, **kw) -> dict:
    return env.execute(command, **kw)


def out(env: RewindEnvironment, command: str, **kw) -> str:
    return run(env, command, **kw)["output"].strip()


def py(code: str) -> str:
    """A python -c command for the sandbox, quoted for sh."""
    return "python3 -c " + "'" + code.replace("'", "'\"'\"'") + "'"


def connect(host: str, port: int, timeout: float = 3) -> str:
    family = "socket.AF_INET6" if ":" in host else "socket.AF_INET"
    return py(f"import socket;s=socket.socket({family});s.settimeout({timeout});"
              f"print('rc', s.connect_ex(('{host}', {port})))")


def blocked(text: str) -> bool:
    # Refused (111), unreachable (113/101/99) or timed out: anything but a connection.
    return "rc 0" not in text and "rc " in text


def docker(*args: str, timeout: float = 120) -> str:
    proc = subprocess.run(["docker", *args], capture_output=True, text=True, timeout=timeout)
    return (proc.stdout + proc.stderr).strip()


# ----------------------------------------------------------------- sections
def section_hardening():
    """Container hardening: capabilities, privileges, limits, nothing from the host."""
    env = sandbox("hardening")
    status = out(env, "grep -E '^(CapEff|NoNewPrivs)' /proc/self/status")
    cap = int(next((l.split()[1] for l in status.splitlines() if l.startswith("CapEff")), "0"), 16)
    # CHOWN(0) DAC_OVERRIDE(1) FOWNER(3) SETGID(6) SETUID(7) and nothing else.
    check("only the 5 package-manager capabilities", cap == 0b11001011, f"CapEff={cap:#x}")
    check("no NET_ADMIN or NET_RAW (firewall can't be changed from inside)", not cap & (1 << 12 | 1 << 13))
    check("no SYS_ADMIN", not cap & (1 << 21))
    check("no-new-privileges is set", "NoNewPrivs:\t1" in status, status)
    check("can't mount filesystems", "MOUNT_FAILED" in out(env, "mount -t tmpfs none /mnt 2>&1 || echo MOUNT_FAILED"))
    check("raw sockets refused", "Operation not permitted" in out(
        env, py("import socket;socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)") + " 2>&1"))
    check("Docker socket not mounted", "absent" in out(env, "test -e /var/run/docker.sock && echo present || echo absent"))
    check("no host environment passed in", "HERMES" not in out(env, "env") and "USERPROFILE" not in out(env, "env"))
    check("process limit is 2048", out(env, "cat /sys/fs/cgroup/pids.max") == "2048")
    check("memory limit is 5 GB", out(env, "cat /sys/fs/cgroup/memory.max") == str(5120 * 1024 * 1024))
    check("CPU limit is 1 CPU", out(env, "cat /sys/fs/cgroup/cpu.max").startswith("100000 100000"))

    small = sandbox("limits", pids_limit=64, memory_mb=128)
    forks = out(small, py(
        "import os,time\nn=0\ntry:\n  for _ in range(500):\n    if os.fork()==0:\n      time.sleep(3); os._exit(0)\n"
        "    n+=1\nexcept OSError: pass\nprint('forked', n)"), timeout=60)
    n = int(forks.split()[-1]) if forks.split() and forks.split()[-1].isdigit() else -1
    check("fork bomb stops at the process limit", 0 < n < 64, forks)
    time.sleep(4)
    # The marker is built at run time: bash echoes a killed command's text, and it must not match.
    hog = run(small, py("b=bytearray(400*1024*1024); print('ALLOC'+'ATED')"), timeout=60)
    check("memory hog is killed at the memory limit", hog["returncode"] == 137 and "ALLOCATED" not in hog["output"],
          f"exit {hog['returncode']}: {hog['output'][-80:]}")
    check("sandbox survives both", out(small, "echo alive") == "alive")


def section_network():
    """Network guard: internet yes, this computer / LAN / metadata no."""
    env = sandbox("network", network="internet")
    first = out(env, "echo up")
    check("guard installed (no fallback warning)", "couldn't firewall" not in first, first)
    check("internet reachable (HTTPS)", "200" in out(env, py(
        "import urllib.request;print(urllib.request.urlopen('https://example.com',timeout=15).status)"), timeout=60))
    check("DNS works", "ok" in out(env, py("import socket;socket.getaddrinfo('example.com',443);print('ok')")))
    gateway = out(env, "awk '$2==\"00000000\"{print $3}' /proc/net/route | head -1")
    if gateway:
        gw = ".".join(str(int(gateway[i:i + 2], 16)) for i in (6, 4, 2, 0))
        check(f"sandbox gateway {gw} blocked", blocked(out(env, connect(gw, 80))))
    targets = [("cloud metadata 169.254.169.254", "169.254.169.254", 80), ("LAN 10.0.0.1", "10.0.0.1", 22),
               ("LAN 192.168.0.1", "192.168.0.1", 80), ("LAN 172.16.0.1", "172.16.0.1", 80),
               ("carrier NAT 100.64.0.1", "100.64.0.1", 80)]
    for addr in host_addresses():
        if ":" not in addr:
            targets.append((f"this computer {addr}", addr, 445))
    for label, host, port in targets:
        check(f"{label} blocked", blocked(out(env, connect(host, port))))
    hdi = out(env, py("import socket\ntry:\n  print(socket.gethostbyname('host.docker.internal'))\nexcept OSError:\n  print('none')"))
    if hdi and hdi != "none":
        check(f"host.docker.internal ({hdi}) blocked", blocked(out(env, connect(hdi, 80))))
    loop = out(env, "python3 -m http.server 8765 --bind 127.0.0.1 >/dev/null 2>&1 & sleep 1; "
                    + connect("127.0.0.1", 8765) + "; kill %1")
    check("the sandbox's own loopback still works", "rc 0" in loop, loop)
    v6 = out(env, "grep -cv ' lo$' /proc/net/if_inet6 2>/dev/null || echo 0")
    if v6.strip() not in ("", "0"):
        for label, host in (("NAT64 to 10.0.0.1", "64:ff9b::a00:1"), ("IPv6 ULA fd00::1", "fd00::1")):
            check(f"{label} blocked", blocked(out(env, connect(host, 80))))
    else:
        check("IPv6 is off in the sandbox, so nothing to filter", True)
    offline = sandbox("offline", network="none")
    check("network=none has no internet", blocked(out(offline, connect("1.1.1.1", 443))))


def section_undo():
    """Snapshots, undo, restore, undo of undo, preview, history limits."""
    env = sandbox("undo", max_snapshots=6)
    run(env, "mkdir -p /workspace/app && cd /workspace/app && for i in 1 2 3; do echo v$i > f$i.txt; done")
    run(env, "rm -rf /workspace/app")  # deletes the directory the command runs in
    after = out(env, "test -d /workspace/app || echo gone")
    check("rm -rf of the working directory took effect (not recreated)", "gone" in after, after)
    check("says the working directory is gone and runs in /workspace", "no longer exists" in after
          and out(env, "pwd") == "/workspace", after)
    target, safety = env.undo()
    check("undo brings the folder back", out(env, "cat /workspace/app/f2.txt") == "v2", target.state())
    env.restore(safety.id)
    check("undo of the undo removes it again", "gone" in out(env, "test -d /workspace/app || echo gone"))
    env.undo()
    check("undo again is repeat-safe (same state)", out(env, "ls /workspace/app | wc -l") == "3")

    count = len(env.snapshots)
    for command in ("ls -la", "cat /workspace/app/f1.txt", "grep v /workspace/app/f1.txt", "git status 2>/dev/null; true",
                    "pwd", "echo hello"):
        run(env, command)
    check("read-only commands take no snapshot", len(env.snapshots) == count, f"{count} -> {len(env.snapshots)}")

    run(env, "echo outside > /etc/rewind-outside")
    run(env, "rm /etc/rewind-outside")
    env.undo()
    check("changes outside /workspace are restored too", out(env, "cat /etc/rewind-outside") == "outside")

    run(env, "echo before > /workspace/app/p.txt")
    run(env, "echo after > /workspace/app/p.txt")
    last = env.find("last")
    _, changes = env.preview(last.id)
    check("preview changes nothing", out(env, "cat /workspace/app/p.txt") == "after", json.dumps(changes)[:120])

    for i in range(10):
        run(env, f"echo {i} > /workspace/churn{i}")
    autos = [s for s in env.snapshots if s.auto]
    check("history is capped at max_snapshots", len(autos) <= 6, f"{len(autos)} automatic snapshots")
    images = docker("images", env.repository, "--format", "{{.Tag}}").split()
    check("pruned snapshots' images are deleted", len(images) <= len(env.snapshots) + 2, f"{len(images)} images")

    run(env, "mkdir -p /workspace/deep/dir && cd /workspace/deep/dir")
    check("cd carries over between commands", out(env, "pwd") == "/workspace/deep/dir")
    run(env, "cd /workspace && touch marker")
    env.undo()
    check("restore brings back the working directory", out(env, "pwd") == "/workspace/deep/dir")

    secret = "ghp_" + "Z" * 36
    run(env, f"GITHUB_TOKEN={secret} touch /workspace/tok")
    labels = " ".join(s.command for s in env.snapshots)
    check("secrets typed in commands are masked in snapshot history", secret not in labels and MASK in labels)


def section_stdin():
    """Hermes's file tools send contents on stdin: must arrive byte-exact."""
    env = sandbox("stdin")
    payload = "".join(chr(32 + (i * 7) % 90) for i in range(300_000)) + "\nünïcødé ✓\n'quotes' \"and\" $dollars `ticks`\n"
    got = out(env, "cat > /workspace/big.txt && sha256sum /workspace/big.txt | cut -d' ' -f1", stdin_data=payload)
    check("300 KB payload arrives byte-exact", got == hashlib.sha256(payload.encode()).hexdigest(), got)


def section_timeout():
    """A command that times out is stopped, with everything it started."""
    env = sandbox("timeout")
    started = time.time()
    result = run(env, "(sleep 301 &); setsid sleep 302 & nohup sleep 303 >/dev/null 2>&1 & sleep 304", timeout=4)
    took = time.time() - started
    check("returns soon after the limit", result["returncode"] == 124 and took < 30, f"{took:.1f}s")
    check("reports that it was stopped", "was stopped" in result["output"], result["output"][-120:])
    left = out(env, "for p in /proc/[0-9]*; do read -r s < $p/stat 2>/dev/null; case \"$s\" in *'(sleep)'*) "
                    "set -- $s; [ \"$4\" != 1 ] && echo ${p#/proc/};; esac; done | wc -l")
    check("detached, setsid and nohup children are all killed", left == "0", f"{left} left")
    run(env, "echo work > /workspace/w")
    env.undo()
    check("sandbox still works and can undo after a timeout", "missing" in out(env, "test -e /workspace/w || echo missing"))


def section_compaction():
    """Big changes don't make every later snapshot store them again."""
    env = sandbox("compact", compact_mb=1)
    for i in range(4):
        run(env, f"head -c 3000000 /dev/urandom > /workspace/blob{i}")
    layers = docker("image", "inspect", "-f", "{{len .RootFS.Layers}}", env.snapshots[-1].image)
    check("compaction keeps the layer count bounded", layers.isdigit() and int(layers) < 20, f"{layers} layers")
    env.restore(env.snapshots[1].id)
    present = out(env, "ls /workspace | grep -c blob")
    check("a snapshot from before compaction still restores", present in ("0", "1"), f"{present} blobs")


def section_export():
    """Exports bring only plain files onto this computer."""
    env = sandbox("export", export_max_mb=2)
    run(env, "mkdir -p /workspace/out && cd /workspace/out && echo hello > ok.txt && "
             "ln -s /etc/passwd link-to-passwd && ln -s /c/Users link-to-host && ln ok.txt hardlink.txt && "
             "mkfifo pipe && cp /bin/ls suid && chmod 4755 suid && chmod 755 ok.txt")
    dest = WORK / "exports"
    copied = env.export("/workspace/out", dest)
    files = sorted(p.name for p in copied.rglob("*"))
    check("plain file exported", (copied / "ok.txt").read_text().strip() == "hello", str(files))
    check("symlinks are not created on this computer", not any((copied / n).is_symlink() for n in files)
          and "link-to-passwd" not in files and "link-to-host" not in files, str(env.last_export_removed))
    check("both names of a hard-linked file arrive as plain files",
          (copied / "hardlink.txt").read_text().strip() == "hello" and (copied / "ok.txt").exists())
    check("FIFOs are not created", "pipe" not in files)
    suid = copied / "suid"
    check("setuid bit dropped", suid.exists() and not suid.stat().st_mode & stat.S_ISUID)
    check("nothing lands outside the export folder", all(str(p.resolve()).startswith(str(dest.resolve()))
                                                         for p in dest.rglob("*")))
    second = env.export("/workspace/out", dest)
    check("a second export never overwrites the first", second != copied and copied.exists())
    run(env, "head -c 3500000 /dev/urandom > /workspace/huge")
    try:
        env.export("/workspace/huge", dest)
        check("export over the size cap is refused", False, "it was exported")
    except RewindError as exc:
        check("export over the size cap is refused", "limit" in str(exc), str(exc))
    try:
        env.export("/workspace/does-not-exist", dest)
        check("export of a missing path is refused", False)
    except RewindError as exc:
        check("export of a missing path is refused", "does not exist" in str(exc))


@contextlib.contextmanager
def surface(name: str):
    class Ctx:
        def session_surface(self):
            return name
    saved, tools._CTX = tools._CTX, Ctx()
    try:
        yield
    finally:
        tools._CTX = saved


def call(tool: str, args=None, **kw) -> dict:
    return json.loads(tools.HANDLERS[tool](args or {}, **kw))


def section_isolation():
    """Each chat reaches only its own sandbox."""
    alice = sandbox("alice")
    bob = sandbox("bob")
    run(alice, "echo a > /workspace/a")
    run(bob, "echo b > /workspace/b")
    mine = call("rewind_list", task_id=alice.task_id)
    check("a chat's tools see its own snapshots", mine.get("ok") and len(mine["snapshots"]) == len(alice.snapshots))
    stranger = call("rewind_list", task_id="stress-carol")
    check("an unknown chat gets no sandbox, not someone else's", not stranger.get("ok"), stranger.get("error", ""))
    shared = sandbox("default")
    shared.task_id = "default"
    registry.add("default", shared)
    run(shared, "echo local-user-work > /workspace/precious")
    with surface("telegram"):
        for tool in ("rewind_list", "rewind_changes", "rewind_undo"):
            result = call(tool, task_id="tg-chat-1")
            check(f"Telegram chat can't reach the shared sandbox ({tool})", not result.get("ok"))
        result = call("rewind_export", {"path": "/workspace/precious"}, task_id="default")
        check("rewind_export refused from a messaging platform", not result.get("ok"), result.get("error", ""))
    reply = tools.slash_rewind("undo", session_key="tg-chat-2", platform="telegram")
    check("/rewind undo from Telegram can't touch the shared sandbox", "no Rewind sandbox" in reply
          or "paused" in reply, reply[:120])
    check("shared sandbox untouched", out(shared, "cat /workspace/precious") == "local-user-work")
    reply = tools.slash_rewind("export /workspace/precious", session_key="tg", platform="discord")
    check("/rewind export refused from Discord", "only works from a local chat" in reply)
    local = call("rewind_list", task_id="session-from-cli")
    check("the shared sandbox is reachable from a local chat", local.get("ok"))
    registry.remove(shared)


def section_approval():
    """Commands Rewind can't undo need the user's approval first."""
    saved = settings._backend_used
    settings._backend_used = True
    try:
        risky = ["git push origin main", "npm publish", "docker push me/img", "curl -X POST https://x.io/hook -d @f",
                 "bash -c 'git push'", "eval \"git push\"", "git -C repo push", "kubectl apply -f k.yaml",
                 "ssh prod 'rm -rf /srv'", py("import requests; requests.post('https://x.io', data='a')")]
        for command in risky:
            result = tools.pre_tool_call(tool_name="terminal", args={"command": command}, task_id="stress")
            check(f"asks before: {command[:48]}", bool(result) and result.get("action") == "approve")
        for command in ("ls -la", "cat README.md", "git status", "pip install requests", "python3 app.py"):
            check(f"no prompt for: {command}", tools.pre_tool_call(tool_name="terminal", args={"command": command}) is None)
        bridged = tools.pre_tool_call(tool_name="tool_call", args={"name": "terminal", "arguments": {"command": "git push"}})
        check("asks through the tool-search bridge too", bool(bridged))
        check("asks before an export", bool(tools.pre_tool_call(tool_name="rewind_export", args={"path": "/workspace"})))
        os.environ["REWIND_NETWORK"] = "none"
        check("no prompt when the sandbox has no network",
              tools.pre_tool_call(tool_name="terminal", args={"command": "git push"}) is None)
    finally:
        os.environ.pop("REWIND_NETWORK", None)
        settings._backend_used = saved


def section_parking():
    """Undo history survives Hermes shutting an idle sandbox down."""
    store = Store(WORK / "state" / "sandboxes")
    first = sandbox("park", keep_hours=1, store=store)
    run(first, "echo kept > /workspace/kept.txt")
    run(first, "rm /workspace/kept.txt")
    first.cleanup()
    record = store.load("stress-park")
    check("idle shutdown parks the snapshots", bool(record) and record.get("status") == "parked")
    check("no container left running while parked", not docker("ps", "-q", "--filter", f"name={first.container}"))
    second = sandbox("park", keep_hours=1, store=store)
    note = out(second, "ls /workspace")
    check("next sandbox resumes the history", "Resumed" in note and len(second.snapshots) == len(first.snapshots), note[:100])
    second.undo()
    check("undo works across the shutdown", out(second, "cat /workspace/kept.txt") == "kept")
    second.keep_seconds = 0
    second.cleanup()

    # A tampered record must not steer Docker.
    third = sandbox("tamper", keep_hours=1, store=store)
    run(third, "echo x > /workspace/x")
    third.cleanup()
    path = store.path("stress-tamper")
    data = json.loads(path.read_text())
    data["base_image"] = "--privileged"
    path.write_text(json.dumps(data))
    fourth = sandbox("tamper", keep_hours=1, store=store)
    note = out(fourth, "echo hi")
    check("a tampered record is ignored (starts fresh)", "Resumed" not in note and not fourth.snapshots, note[:100])
    check("tampered image name never reaches docker", "--privileged" not in fourth.base_image)
    fourth.keep_seconds = 0
    fourth.cleanup()
    with contextlib.suppress(Exception):
        docker("rmi", "-f", *[f"{data['repository']}:{s['id']}" for s in data.get("snapshots", [])])


def section_audit():
    """The audit log records what happened, with secrets masked."""
    entries = list(audit.tail(1000))
    events = {e.get("event") for e in entries}
    for event in ("undo", "approval_requested", "command_timeout"):
        if event == "undo":
            env = sandbox("audit")
            run(env, "touch /workspace/z")
            target, safety = env.undo()
            tools._audit_restore(env, target, safety, via="stress", event="undo")
            events = {e.get("event") for e in audit.tail(1000)}
        check(f"audit log has '{event}' events", event in events, ", ".join(sorted(e for e in events if e)))
    saved, settings._backend_used = settings._backend_used, True
    try:
        logged = tools.pre_tool_call(tool_name="terminal", args={"command": "TOKEN=ghp_" + "Q" * 36 + " git push"})
    finally:
        settings._backend_used = saved
    check("the approval request itself is logged", bool(logged))
    text = audit.path().read_text(encoding="utf-8")
    check("secrets are masked in the audit log", "ghp_" + "Q" * 36 not in text and MASK in text)
    if os.name != "nt":
        check("audit log is owner-only", stat.S_IMODE(audit.path().stat().st_mode) == 0o600)


SECTIONS = {
    "hardening": section_hardening, "network": section_network, "undo": section_undo,
    "stdin": section_stdin, "timeout": section_timeout, "compaction": section_compaction,
    "export": section_export, "isolation": section_isolation, "approval": section_approval,
    "parking": section_parking, "audit": section_audit,
}


def cleanup() -> None:
    for env in ENVS:
        with contextlib.suppress(Exception):
            env.keep_seconds = 0
            env.cleanup()
    registry.clear()
    left = docker("ps", "-aq", "--filter", "label=hermes.rewind=1")
    ours = [c for c in docker("ps", "-a", "--filter", "label=hermes.rewind=1", "--format", "{{.Names}}").split()
            if "stress-" in c]
    if ours:
        docker("rm", "-f", *ours)
    images = [i for i in docker("images", "--format", "{{.Repository}}:{{.Tag}}").split() if i.startswith("hermes-rewind/stress-")]
    if images:
        docker("rmi", "-f", *images)
    shutil.rmtree(WORK, ignore_errors=True)
    del left


def main() -> int:
    if "--list" in sys.argv:
        for name, fn in SECTIONS.items():
            print(f"{name:12} {fn.__doc__}")
        return 0
    wanted = [a for a in sys.argv[1:] if not a.startswith("-")] or list(SECTIONS)
    unknown = [w for w in wanted if w not in SECTIONS]
    if unknown:
        print(f"Unknown section(s): {', '.join(unknown)}. Use --list.")
        return 2
    if "Server Version" not in docker("info"):
        print("Docker isn't running.")
        return 2
    print(f"{BOLD}Rewind stress test{RESET}  (state in {WORK})")
    started = time.time()
    try:
        for name in wanted:
            CURRENT[0] = name
            print(f"\n{BOLD}{name}{RESET}  {DIM}{SECTIONS[name].__doc__}{RESET}")
            t = time.time()
            try:
                SECTIONS[name]()
            except Exception as exc:  # a crash is a failure of that section, not the run
                check(f"section ran to the end", False, f"{type(exc).__name__}: {exc}")
                if VERBOSE:
                    traceback.print_exc()
            print(f"  {DIM}{time.time() - t:.0f}s{RESET}")
    finally:
        CURRENT[0] = "cleanup"
        cleanup()
        leftover = [c for c in docker("ps", "-a", "--filter", "label=hermes.rewind=1", "--format", "{{.Names}}").split()
                    if "stress-" in c]
        check("no stress-test containers left behind", not leftover, " ".join(leftover))
    failed = [r for r in RESULTS if not r[2]]
    print(f"\n{BOLD}{len(RESULTS) - len(failed)}/{len(RESULTS)} checks passed{RESET} in {time.time() - started:.0f}s")
    for sec, name, _, saw in failed:
        print(f"  {RED}FAIL{RESET} [{sec}] {name}  {DIM}{saw[:200]}{RESET}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
