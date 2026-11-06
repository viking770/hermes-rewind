"""Stress test: attack every protection Rewind claims, against real Docker.

    python scripts/stress_test.py                      # everything (about 3 to 6 minutes)
    python scripts/stress_test.py network undo export  # only some sections
    python scripts/stress_test.py --list               # section names
    python scripts/stress_test.py -v                   # also print the evidence of passing checks
    python scripts/stress_test.py --report docs/stress-report   # where the report goes

Each check runs real commands in real sandboxes and records PASS or FAIL with
the evidence: what was tried and what the sandbox actually did. Every run
writes the results to stress-report.md and stress-report.json (or the
--report path), and in GitHub Actions also to the run's summary page.

State, exports and the audit log go to a temporary folder (your Hermes data
is never touched), and every container and image the run creates is removed
at the end. Exit code 0 means every check passed.

Needs Docker running. The first run builds Rewind's images (about a minute).
"""
from __future__ import annotations

import contextlib
import hashlib
import json
import os
import platform
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import traceback
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# Isolate everything before Rewind reads its settings.
WORK = Path(tempfile.mkdtemp(prefix="rewind-stress-"))
os.environ["REWIND_STATE_DIR"] = str(WORK / "state")
os.environ["REWIND_EXPORT_DIR"] = str(WORK / "exports")
os.environ.pop("TERMINAL_ENV", None)

from rewind import audit, registry, settings, tools, version  # noqa: E402
from rewind.environment import RewindEnvironment, RewindError, host_addresses  # noqa: E402
from rewind.redact import MASK  # noqa: E402
from rewind.store import Store  # noqa: E402

GREEN, RED, DIM, BOLD, RESET = ("\033[32m", "\033[31m", "\033[2m", "\033[1m", "\033[0m") \
    if sys.stdout.isatty() else ("", "", "", "", "")
RESULTS: list = []  # {"section", "check", "ok", "evidence"}
TIMES: dict = {}
ENVS: list = []
CURRENT = ["setup"]
VERBOSE = "-v" in sys.argv


# ------------------------------------------------------------------ helpers
_MASKS: dict = {}


def own_address(addr: str) -> str:
    """How this machine's own IP address appears in results: "own address #N"."""
    if not _MASKS:
        _MASKS.update({a: f"own address #{n}" for n, a in enumerate(host_addresses(), 1)})
    return _MASKS.get(addr, addr)


def private(text: str) -> str:
    """Mask what identifies this machine in recorded results (reports get shared):
    its own IP addresses, and the home and temp folders."""
    text = str(text).replace(str(WORK), "<temp>").replace(str(Path.home()), "~")
    own_address("")  # fill the table
    for addr in sorted(_MASKS, key=len, reverse=True):  # longest first: no partial replacements
        text = text.replace(addr, _MASKS[addr])
    return text


def check(name: str, ok: bool, evidence: str = "") -> bool:
    name, evidence = private(name), private(" ".join(str(evidence).split())[:300])
    RESULTS.append({"section": CURRENT[0], "check": name, "ok": bool(ok), "evidence": evidence})
    mark = f"{GREEN}PASS{RESET}" if ok else f"{RED}FAIL{RESET}"
    detail = f"  {DIM}{evidence[:160]}{RESET}" if evidence and (not ok or VERBOSE) else ""
    print(f"  {mark}  {name}{detail}")
    return bool(ok)


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


_ERRNO = {"0": "connected", "111": "connection refused", "113": "no route to host", "101": "network unreachable",
          "11": "timed out", "110": "timed out", "99": "address not available", "97": "address family not supported"}


def connection(text: str, host: str, port: int) -> str:
    rc = text.split("rc ")[-1].split()[0] if "rc " in text else "?"
    return f"connect {host}:{port} -> {_ERRNO.get(rc, 'error ' + rc)}"


def blocked(text: str) -> bool:
    # Refused, unreachable or timed out: anything but a connection.
    return "rc 0" not in text and "rc " in text


def try_connect(env, host: str, port: int) -> tuple:
    text = out(env, connect(host, port))
    return blocked(text), connection(text, host, port)


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
    check("only the 5 package-manager capabilities", cap == 0b11001011,
          f"CapEff={cap:#x} (expected 0xcb: CHOWN, DAC_OVERRIDE, FOWNER, SETGID, SETUID)")
    check("no NET_ADMIN or NET_RAW (firewall can't be changed from inside)", not cap & (1 << 12 | 1 << 13),
          f"bits 12 and 13 of CapEff={cap:#x} are clear")
    check("no SYS_ADMIN", not cap & (1 << 21), f"bit 21 of CapEff={cap:#x} is clear")
    check("no-new-privileges is set", "NoNewPrivs:\t1" in status, status.replace("\t", " ").splitlines()[-1])
    mount = out(env, "mount -t tmpfs none /mnt 2>&1 || echo MOUNT_FAILED")
    check("can't mount filesystems", "MOUNT_FAILED" in mount, f"mount -t tmpfs: {mount.splitlines()[0]}")
    raw = out(env, py("import socket;socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)") + " 2>&1")
    check("raw sockets refused", "Operation not permitted" in raw, f"SOCK_RAW: {raw.splitlines()[-1]}")
    sock = out(env, "test -e /var/run/docker.sock && echo present || echo absent")
    check("Docker socket not mounted", sock == "absent", f"/var/run/docker.sock: {sock}")
    names = out(env, "env | cut -d= -f1 | sort | tr '\\n' ' '")
    check("no host environment passed in", "HERMES" not in names and "USERPROFILE" not in names,
          f"variables in the sandbox: {names}")
    pids = out(env, "cat /sys/fs/cgroup/pids.max")
    check("process limit is 2048", pids == "2048", f"pids.max={pids}")
    mem = out(env, "cat /sys/fs/cgroup/memory.max")
    check("memory limit is 5 GB", mem == str(5120 * 1024 * 1024), f"memory.max={mem}")
    cpu = out(env, "cat /sys/fs/cgroup/cpu.max")
    check("CPU limit is 1 CPU", cpu.startswith("100000 100000"), f"cpu.max={cpu}")

    small = sandbox("limits", pids_limit=64, memory_mb=128)
    forks = out(small, py(
        "import os,time\nn=0\ntry:\n  for _ in range(500):\n    if os.fork()==0:\n      time.sleep(3); os._exit(0)\n"
        "    n+=1\nexcept OSError as e:\n  print('stopped:', e.strerror)\nprint('forked', n)"), timeout=60)
    n = int(forks.split()[-1]) if forks.split() and forks.split()[-1].isdigit() else -1
    check("fork bomb stops at the process limit", 0 < n < 64,
          f"tried 500 forks with a 64-process limit: {forks.replace(chr(10), ', ')}")
    time.sleep(4)
    # The marker is built at run time: bash echoes a killed command's text, and it must not match.
    hog = run(small, py("b=bytearray(400*1024*1024); print('ALLOC'+'ATED')"), timeout=60)
    check("memory hog is killed at the memory limit", hog["returncode"] == 137 and "ALLOCATED" not in hog["output"],
          f"allocating 400 MB with a 128 MB limit: exit {hog['returncode']} ({hog['output'].strip()[-60:]})")
    alive = out(small, "echo alive")
    check("sandbox survives both", alive == "alive", f"next command printed: {alive}")


def section_network():
    """Network guard: internet yes, this computer / LAN / metadata no."""
    env = sandbox("network", network="internet")
    first = out(env, "echo up")
    check("guard installed (no fallback warning)", "couldn't firewall" not in first, f"first command printed: {first[:80]}")
    status = out(env, py("import urllib.request;print(urllib.request.urlopen('https://example.com',timeout=15).status)"),
                 timeout=60)
    check("internet reachable (HTTPS)", "200" in status, f"GET https://example.com -> {status[-40:]}")
    dns = out(env, py("import socket;print(socket.getaddrinfo('example.com',443)[0][4][0])"))
    check("DNS works", bool(dns) and "Error" not in dns, f"example.com resolves to {dns[-40:]}")
    gateway = out(env, "awk '$2==\"00000000\"{print $3}' /proc/net/route | head -1")
    if gateway:
        gw = ".".join(str(int(gateway[i:i + 2], 16)) for i in (6, 4, 2, 0))
        check(f"sandbox gateway {gw} blocked", *try_connect(env, gw, 80))
    targets = [("cloud metadata 169.254.169.254", "169.254.169.254", 80), ("LAN 10.0.0.1", "10.0.0.1", 22),
               ("LAN 192.168.0.1", "192.168.0.1", 80), ("LAN 172.16.0.1", "172.16.0.1", 80),
               ("carrier NAT 100.64.0.1", "100.64.0.1", 80)]
    for addr in host_addresses():
        if ":" not in addr:
            targets.append((f"this computer ({own_address(addr)})", addr, 445))
    for label, host, port in targets:
        check(f"{label} blocked", *try_connect(env, host, port))
    hdi = out(env, py("import socket\ntry:\n  print(socket.gethostbyname('host.docker.internal'))\nexcept OSError:\n  print('none')"))
    if hdi and hdi != "none":
        check(f"host.docker.internal ({hdi}) blocked", *try_connect(env, hdi, 80))
    loop = out(env, "python3 -m http.server 8765 --bind 127.0.0.1 >/dev/null 2>&1 & sleep 1; "
                    + connect("127.0.0.1", 8765) + "; kill %1")
    check("the sandbox's own loopback still works", "rc 0" in loop,
          connection(loop, "127.0.0.1", 8765) + " (a server inside the sandbox)")
    v6 = out(env, "grep -cv ' lo$' /proc/net/if_inet6 2>/dev/null || echo 0")
    if v6.strip() not in ("", "0"):
        for label, host in (("NAT64 to 10.0.0.1", "64:ff9b::a00:1"), ("IPv6 ULA fd00::1", "fd00::1")):
            check(f"{label} blocked", *try_connect(env, host, 80))
    else:
        check("IPv6 is off in the sandbox, so nothing to filter", True, "no IPv6 address on any interface but lo")
    offline = sandbox("offline", network="none")
    check("network=none has no internet", *try_connect(offline, "1.1.1.1", 443))


_RESOLVE_AND_CONNECT = r'''
import json, socket, sys
results = {}
for label, (host, proto) in json.loads(sys.argv[1]).items():
    try:
        kind = socket.SOCK_DGRAM if proto == "udp" else socket.SOCK_STREAM
        family, _, _, _, addr = socket.getaddrinfo(host, 80 if proto == "tcp" else 53, type=kind)[0]
        s = socket.socket(family, kind)
        s.settimeout(3)
        if proto == "udp":
            s.connect(addr)
            s.send(b"x")
            s.recv(16)
            results[label] = [addr[0], "got a reply"]
        else:
            rc = s.connect_ex(addr)
            results[label] = [addr[0], "connected" if rc == 0 else f"refused or unreachable (errno {rc})"]
    except socket.gaierror as exc:
        results[label] = ["", f"name did not resolve ({exc.args[-1]})"]
    except OSError as exc:
        results[label] = ["", f"blocked: {exc.strerror or exc}"]
print(json.dumps(results))
'''


def section_evasion():
    """Firewall evasion: disguised addresses, DNS tricks, IPv6 mapping, UDP, tampering."""
    env = sandbox("evasion", network="internet")
    run(env, "true")
    lan = next((a for a in host_addresses() if ":" not in a and not a.startswith("127.")), "192.168.1.1")
    a, b, c, d = map(int, lan.split("."))
    # The disguised forms of this computer's address are never written to the report.
    probes = {
        "this computer as one decimal number": (str((a << 24) + (b << 16) + (c << 8) + d), "tcp"),
        "this computer in hex": ("0x%02x%02x%02x%02x" % (a, b, c, d), "tcp"),
        "this computer in octal": (".".join("0%o" % x for x in (a, b, c, d)), "tcp"),
        "this computer in short form (a.b.cd)": (f"{a}.{b}.{(c << 8) + d}", "tcp"),
        "cloud metadata as decimal (2852039166)": ("2852039166", "tcp"),
        "cloud metadata in hex (0xa9fea9fe)": ("0xa9fea9fe", "tcp"),
        "this computer as IPv4-mapped IPv6": (f"::ffff:{lan}", "tcp"),
        "cloud metadata as IPv4-mapped IPv6": ("::ffff:169.254.169.254", "tcp"),
        "DNS name resolving to cloud metadata (nip.io)": ("169.254.169.254.nip.io", "tcp"),
        "DNS name resolving to this computer (nip.io)": (f"{lan}.nip.io", "tcp"),
        "0.0.0.0": ("0.0.0.0", "tcp"),
        "UDP to this computer": (lan, "udp"),
    }
    raw = out(env, "python3 - '" + json.dumps(probes) + "'", stdin_data=_RESOLVE_AND_CONNECT)
    try:
        results = json.loads(raw.splitlines()[-1])
    except (ValueError, IndexError):
        check("evasion probes ran", False, raw[-200:])
        return
    for label, (addr, what) in results.items():
        reached = what in ("connected", "got a reply")
        shown = f"resolved to {addr}: {what}" if addr else what
        check(f"{label} blocked", not reached, shown)
    ns = out(env, "awk '/^nameserver/{print $2; exit}' /etc/resolv.conf")
    if ns:
        check(f"DNS resolver reachable only on port 53", *try_connect(env, ns, 80))
    unshare = out(env, "unshare -n true 2>&1 && echo ALLOWED || echo REFUSED")
    check("can't create a private network namespace to escape the rules", "ALLOWED" not in unshare,
          unshare.splitlines()[0][:100])
    tools_present = out(env, "command -v iptables nft ip6tables 2>/dev/null | tr '\\n' ' '")
    check("no firewall tools inside the sandbox", not tools_present, tools_present or "iptables/nft/ip6tables absent")
    packet = out(env, py("import socket\ntry:\n  socket.socket(socket.AF_PACKET, socket.SOCK_RAW)\n  print('ALLOWED')\n"
                         "except OSError as x:\n  print('refused:', x.strerror)"))
    check("can't open raw packet sockets (no hand-built packets)", "ALLOWED" not in packet, packet)


def section_undo():
    """Snapshots, undo, restore, undo of undo, preview, history limits."""
    env = sandbox("undo", max_snapshots=6)
    run(env, "mkdir -p /workspace/app && cd /workspace/app && for i in 1 2 3; do echo v$i > f$i.txt; done")
    run(env, "rm -rf /workspace/app")  # deletes the directory the command runs in
    after = out(env, "test -d /workspace/app || echo gone")
    check("rm -rf of the working directory took effect (not recreated)", "gone" in after,
          "after rm -rf /workspace/app (the working directory): " + after.splitlines()[-1])
    pwd = out(env, "pwd")
    check("says the working directory is gone and runs in /workspace", "no longer exists" in after and pwd == "/workspace",
          f"{after.splitlines()[0][:90]} / pwd={pwd}")
    target, safety = env.undo()
    f2 = out(env, "cat /workspace/app/f2.txt")
    check("undo brings the folder back", f2 == "v2", f"restored {target.id} ({target.state()[:60]}); f2.txt={f2}")
    env.restore(safety.id)
    gone = out(env, "test -d /workspace/app || echo gone")
    check("undo of the undo removes it again", "gone" in gone, f"restored {safety.id}; /workspace/app: {gone[-20:]}")
    env.undo()
    count3 = out(env, "ls /workspace/app | wc -l")
    check("undo again is repeat-safe (same state)", count3 == "3", f"/workspace/app has {count3} files")

    count = len(env.snapshots)
    readonly = ("ls -la", "cat /workspace/app/f1.txt", "grep v /workspace/app/f1.txt", "git status 2>/dev/null; true",
                "pwd", "echo hello")
    for command in readonly:
        run(env, command)
    check("read-only commands take no snapshot", len(env.snapshots) == count,
          f"{len(readonly)} read-only commands: snapshots {count} -> {len(env.snapshots)}")

    run(env, "echo outside > /etc/rewind-outside")
    run(env, "rm /etc/rewind-outside")
    env.undo()
    outside = out(env, "cat /etc/rewind-outside")
    check("changes outside /workspace are restored too", outside == "outside", f"/etc/rewind-outside={outside}")

    run(env, "echo before > /workspace/app/p.txt")
    run(env, "echo after > /workspace/app/p.txt")
    last = env.find("last")
    _, changes = env.preview(last.id)
    current = out(env, "cat /workspace/app/p.txt")
    check("preview changes nothing", current == "after",
          f"preview of {last.id} listed {sum(len(v) for v in (changes or {}).values() if isinstance(v, list))} "
          f"change(s); p.txt still={current}")

    for i in range(10):
        run(env, f"echo {i} > /workspace/churn{i}")
    autos = [s for s in env.snapshots if s.auto]
    check("history is capped at max_snapshots", len(autos) <= 6,
          f"after 10 more changes: {len(autos)} automatic snapshots kept (max_snapshots=6)")
    images = docker("images", env.repository, "--format", "{{.Tag}}").split()
    check("pruned snapshots' images are deleted", len(images) <= len(env.snapshots) + 2,
          f"{len(images)} images for {len(env.snapshots)} snapshots")

    run(env, "mkdir -p /workspace/deep/dir && cd /workspace/deep/dir")
    pwd = out(env, "pwd")
    check("cd carries over between commands", pwd == "/workspace/deep/dir", f"next command's pwd={pwd}")
    run(env, "cd /workspace && touch marker")
    env.undo()
    pwd = out(env, "pwd")
    check("restore brings back the working directory", pwd == "/workspace/deep/dir", f"pwd after undo={pwd}")

    secret = "ghp_" + "Z" * 36
    run(env, f"GITHUB_TOKEN={secret} touch /workspace/tok")
    label = env.snapshots[-1].command
    check("secrets typed in commands are masked in snapshot history", secret not in label and MASK in label,
          f"recorded as: {label}")


def section_stdin():
    """Hermes's file tools send contents on stdin: must arrive byte-exact."""
    env = sandbox("stdin")
    payload = "".join(chr(32 + (i * 7) % 90) for i in range(300_000)) + "\nünïcødé ✓\n'quotes' \"and\" $dollars `ticks`\n"
    want = hashlib.sha256(payload.encode()).hexdigest()
    got = out(env, "cat > /workspace/big.txt && sha256sum /workspace/big.txt | cut -d' ' -f1", stdin_data=payload)
    check("300 KB payload arrives byte-exact", got == want,
          f"sent {len(payload.encode()):,} bytes (Unicode, quotes, $, backticks); sha256 {got[:16]}… vs {want[:16]}…")


def section_timeout():
    """A command that times out is stopped, with everything it started."""
    env = sandbox("timeout")
    command = "(sleep 301 &); setsid sleep 302 & nohup sleep 303 >/dev/null 2>&1 & sleep 304"
    started = time.time()
    result = run(env, command, timeout=4)
    took = time.time() - started
    check("returns soon after the limit", result["returncode"] == 124 and took < 30,
          f"4 s limit: returned after {took:.1f}s with exit {result['returncode']}")
    check("reports that it was stopped", "was stopped" in result["output"], result["output"].strip()[-90:])
    left = out(env, "for p in /proc/[0-9]*; do read -r s < $p/stat 2>/dev/null; case \"$s\" in *'(sleep)'*) "
                    "set -- $s; [ \"$4\" != 1 ] && echo ${p#/proc/};; esac; done | wc -l")
    check("detached, setsid and nohup children are all killed", left == "0",
          f"`{command}`: {left} of its sleep processes left running")
    run(env, "echo work > /workspace/w")
    env.undo()
    state = out(env, "test -e /workspace/w || echo missing")
    check("sandbox still works and can undo after a timeout", "missing" in state, f"after undo, /workspace/w: {state}")


def section_compaction():
    """Big changes don't make every later snapshot store them again."""
    env = sandbox("compact", compact_mb=1)
    for i in range(4):
        run(env, f"head -c 3000000 /dev/urandom > /workspace/blob{i}")
    layers = docker("image", "inspect", "-f", "{{len .RootFS.Layers}}", env.snapshots[-1].image)
    check("compaction keeps the layer count bounded", layers.isdigit() and int(layers) < 20,
          f"4 x 3 MB changes with compact_mb=1: newest snapshot has {layers} layers")
    env.restore(env.snapshots[1].id)
    present = out(env, "ls /workspace | grep -c blob")
    check("a snapshot from before compaction still restores", present in ("0", "1"),
          f"restored {env.snapshots[1].id}: {present} blob(s) present, as at that point")


def section_export():
    """Exports bring only plain files onto this computer."""
    env = sandbox("export", export_max_mb=2)
    run(env, "mkdir -p /workspace/out && cd /workspace/out && echo hello > ok.txt && "
             "ln -s /etc/passwd link-to-passwd && ln -s /c/Users link-to-host && ln ok.txt hardlink.txt && "
             "mkfifo pipe && cp /bin/ls suid && chmod 4755 suid && chmod 755 ok.txt")
    dest = WORK / "exports"
    copied = env.export("/workspace/out", dest)
    files = sorted(p.name for p in copied.rglob("*"))
    skipped = env.last_export_removed
    check("plain file exported", (copied / "ok.txt").read_text().strip() == "hello", f"arrived: {', '.join(files)}")
    check("symlinks are not created on this computer", not any((copied / n).is_symlink() for n in files)
          and "link-to-passwd" not in files and "link-to-host" not in files, f"skipped: {', '.join(skipped)}")
    check("both names of a hard-linked file arrive as plain files",
          (copied / "hardlink.txt").read_text().strip() == "hello" and (copied / "ok.txt").exists(),
          "ok.txt and hardlink.txt both contain 'hello'")
    check("FIFOs are not created", "pipe" not in files, "pipe is in the skipped list" if "out/pipe" in skipped else "")
    suid = copied / "suid"
    mode = suid.stat().st_mode if suid.exists() else 0
    check("setuid bit dropped", suid.exists() and not mode & stat.S_ISUID,
          f"sandbox mode 4755 -> exported mode {stat.S_IMODE(mode):o}")
    check("nothing lands outside the export folder",
          all(str(p.resolve()).startswith(str(dest.resolve())) for p in dest.rglob("*")),
          f"every exported path is under the export folder")
    second = env.export("/workspace/out", dest)
    check("a second export never overwrites the first", second != copied and copied.exists(),
          f"first: …/{copied.parent.name}, second: …/{second.parent.name}")
    run(env, "head -c 3500000 /dev/urandom > /workspace/huge")
    try:
        env.export("/workspace/huge", dest)
        check("export over the size cap is refused", False, "a 3.5 MB file was exported with a 2 MB cap")
    except RewindError as exc:
        check("export over the size cap is refused", "limit" in str(exc), str(exc))
    try:
        env.export("/workspace/does-not-exist", dest)
        check("export of a missing path is refused", False, "it was exported")
    except RewindError as exc:
        check("export of a missing path is refused", "does not exist" in str(exc), str(exc))


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
    check("a chat's tools see its own snapshots", mine.get("ok") and len(mine["snapshots"]) == len(alice.snapshots),
          f"rewind_list for alice: {len(mine.get('snapshots', []))} snapshot(s), all alice's")
    stranger = call("rewind_list", task_id="stress-carol")
    check("an unknown chat gets no sandbox, not someone else's", not stranger.get("ok"), stranger.get("error", ""))
    shared = sandbox("default")
    shared.task_id = "default"
    registry.add("default", shared)
    run(shared, "echo local-user-work > /workspace/precious")
    with surface("telegram"):
        for tool in ("rewind_list", "rewind_changes", "rewind_undo"):
            result = call(tool, task_id="tg-chat-1")
            check(f"Telegram chat can't reach the shared sandbox ({tool})", not result.get("ok"),
                  result.get("error", "it was allowed")[:120])
        result = call("rewind_export", {"path": "/workspace/precious"}, task_id="default")
        check("rewind_export refused from a messaging platform", not result.get("ok"), result.get("error", "")[:120])
    reply = tools.slash_rewind("undo", session_key="tg-chat-2", platform="telegram")
    check("/rewind undo from Telegram can't touch the shared sandbox", "no Rewind sandbox" in reply
          or "paused" in reply, reply[:120])
    precious = out(shared, "cat /workspace/precious")
    check("shared sandbox untouched", precious == "local-user-work", f"/workspace/precious={precious}")
    reply = tools.slash_rewind("export /workspace/precious", session_key="tg", platform="discord")
    check("/rewind export refused from Discord", "only works from a local chat" in reply, reply[:120])
    local = call("rewind_list", task_id="session-from-cli")
    check("the shared sandbox is reachable from a local chat", local.get("ok"),
          f"rewind_list from the CLI: ok={local.get('ok')}")
    registry.remove(shared)


def section_approval():
    """Commands Rewind can't undo need the user's approval first."""
    saved = settings._backend_used
    settings._backend_used = True
    try:
        risky = ["git push origin main", "npm publish", "docker push me/img", "curl -X POST https://x.io/hook -d @f",
                 "bash -c 'git push'", "bash -lc 'git push origin main'", "echo $(git push)", "sudo -u bob git push",
                 "env -i git push", "curl -sSXPOST https://x.io/hook", "eval \"git push\"", "git -C repo push",
                 "kubectl apply -f k.yaml",
                 "ssh prod 'rm -rf /srv'", py("import requests; requests.post('https://x.io', data='a')")]
        for command in risky:
            result = tools.pre_tool_call(tool_name="terminal", args={"command": command}, task_id="stress")
            check(f"asks before: {command[:48]}", bool(result) and result.get("action") == "approve",
                  (result or {}).get("message", "no prompt")[:140])
        for command in ("ls -la", "cat README.md", "git status", "pip install requests", "python3 app.py"):
            result = tools.pre_tool_call(tool_name="terminal", args={"command": command})
            check(f"no prompt for: {command}", result is None, "no prompt" if result is None else result.get("message", ""))
        bridged = tools.pre_tool_call(tool_name="tool_call", args={"name": "terminal", "arguments": {"command": "git push"}})
        check("asks through the tool-search bridge too", bool(bridged), (bridged or {}).get("message", "no prompt")[:120])
        export = tools.pre_tool_call(tool_name="rewind_export", args={"path": "/workspace"})
        check("asks before an export", bool(export), (export or {}).get("message", "no prompt")[:120])
        os.environ["REWIND_NETWORK"] = "none"
        result = tools.pre_tool_call(tool_name="terminal", args={"command": "git push"})
        check("no prompt when the sandbox has no network", result is None,
              "git push with REWIND_NETWORK=none: no prompt (it can't reach anything)")
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
    check("idle shutdown parks the snapshots", bool(record) and record.get("status") == "parked",
          f"record status={(record or {}).get('status')}, {len((record or {}).get('snapshots', []))} snapshot(s)")
    running = docker("ps", "-q", "--filter", f"name={first.container}")
    check("no container left running while parked", not running, "docker ps finds none" if not running else running)
    second = sandbox("park", keep_hours=1, store=store)
    note = out(second, "ls /workspace")
    check("next sandbox resumes the history", "Resumed" in note and len(second.snapshots) == len(first.snapshots),
          note.splitlines()[0][:120])
    second.undo()
    kept = out(second, "cat /workspace/kept.txt")
    check("undo works across the shutdown", kept == "kept", f"kept.txt after undo={kept}")
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
    check("a tampered record is ignored (starts fresh)", "Resumed" not in note and not fourth.snapshots,
          "record edited to base_image='--privileged': started fresh with 0 snapshots")
    check("tampered image name never reaches docker", "--privileged" not in fourth.base_image,
          f"started from {fourth.base_image}")
    fourth.keep_seconds = 0
    fourth.cleanup()
    with contextlib.suppress(Exception):
        docker("rmi", "-f", *[f"{data['repository']}:{s['id']}" for s in data.get("snapshots", [])])


def section_audit():
    """The audit log records what happened, with secrets masked."""
    env = sandbox("audit")
    run(env, "touch /workspace/z")
    target, safety = env.undo()
    tools._audit_restore(env, target, safety, via="stress", event="undo")
    run(env, "sleep 60", timeout=2)  # so the section also works when run on its own
    saved, settings._backend_used = settings._backend_used, True
    try:
        logged = tools.pre_tool_call(tool_name="terminal", args={"command": "TOKEN=ghp_" + "Q" * 36 + " git push"})
    finally:
        settings._backend_used = saved
    entries = list(audit.tail(1000))
    events = sorted({e.get("event") for e in entries if e.get("event")})
    for event in ("undo", "approval_requested", "command_timeout"):
        check(f"audit log has '{event}' events", event in events,
              f"{sum(e.get('event') == event for e in entries)} of {len(entries)} entries")
    check("the approval request itself is logged", bool(logged), "approval_requested written for the git push")
    text = audit.path().read_text(encoding="utf-8")
    line = next((l for l in text.splitlines() if "git push" in l and "TOKEN" in l), "")
    check("secrets are masked in the audit log", "ghp_" + "Q" * 36 not in text and MASK in text,
          "logged command: " + (json.loads(line).get("command", "") if line else "(not found)"))
    if os.name != "nt":
        mode = stat.S_IMODE(audit.path().stat().st_mode)
        check("audit log is owner-only", mode == 0o600, f"mode {mode:o}")


SECTIONS = {
    "hardening": section_hardening, "network": section_network, "evasion": section_evasion, "undo": section_undo,
    "stdin": section_stdin, "timeout": section_timeout, "compaction": section_compaction,
    "export": section_export, "isolation": section_isolation, "approval": section_approval,
    "parking": section_parking, "audit": section_audit,
}


# ------------------------------------------------------------------- report
def _md(text: str) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ").replace("<", "&lt;")


def run_info() -> dict:
    commit = ""
    with contextlib.suppress(Exception):
        commit = subprocess.run(["git", "-C", str(ROOT), "rev-parse", "--short", "HEAD"],
                                capture_output=True, text=True, timeout=10).stdout.strip()
    return {
        "date": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "rewind": version.VERSION, "commit": commit,
        "docker": docker("version", "--format", "{{.Server.Version}} ({{.Server.Os}}/{{.Server.Arch}})"),
        "host": f"{platform.system()} {platform.release()}", "python": platform.python_version(),
    }


def report_markdown(info: dict, seconds: float) -> str:
    passed = sum(r["ok"] for r in RESULTS)
    verdict = "All checks passed" if passed == len(RESULTS) else f"{len(RESULTS) - passed} check(s) FAILED"
    lines = [
        "# Rewind stress test report", "",
        f"**{passed}/{len(RESULTS)} checks passed** in {seconds:.0f}s. {verdict}.", "",
        f"Rewind {info['rewind']} (commit `{info['commit'] or '?'}`) · Docker {info['docker']} · "
        f"{info['host']} · Python {info['python']} · {info['date']}", "",
        "Every check runs real commands in real Docker sandboxes and records what the sandbox actually did. "
        "Produced by [`scripts/stress_test.py`](../scripts/stress_test.py).", "",
        "| Section | What it attacks | Passed | Time |", "|---|---|---|---|",
    ]
    order = list(dict.fromkeys(r["section"] for r in RESULTS))
    for section in order:
        rows = [r for r in RESULTS if r["section"] == section]
        doc = (SECTIONS[section].__doc__ or "").strip() if section in SECTIONS else \
            "Every container and image the run created is removed."
        mark = "✅" if all(r["ok"] for r in rows) else "❌"
        lines.append(f"| {mark} [{section}](#{section}) | {_md(doc)} | {sum(r['ok'] for r in rows)}/{len(rows)} | "
                     f"{TIMES.get(section, 0):.0f}s |")
    for section in order:
        rows = [r for r in RESULTS if r["section"] == section]
        lines += ["", f"## {section}", "", "| | Check | What happened |", "|---|---|---|"]
        lines += [f"| {'✅' if r['ok'] else '❌'} | {_md(r['check'])} | {_md(r['evidence'])} |" for r in rows]
    return "\n".join(lines) + "\n"


def write_reports(base: Path, seconds: float) -> None:
    info = run_info()
    markdown = report_markdown(info, seconds)
    base.parent.mkdir(parents=True, exist_ok=True)
    md_path, json_path = base.with_suffix(".md"), base.with_suffix(".json")
    md_path.write_text(markdown, encoding="utf-8")
    json_path.write_text(json.dumps({**info, "seconds": round(seconds, 1),
                                     "passed": sum(r["ok"] for r in RESULTS), "total": len(RESULTS),
                                     "section_seconds": {k: round(v, 1) for k, v in TIMES.items()},
                                     "results": RESULTS}, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\nReport: {md_path}  (and {json_path.name})")
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as fh:
            fh.write(markdown.replace("](../scripts/", "](scripts/"))


# --------------------------------------------------------------------- main
def cleanup() -> None:
    for env in ENVS:
        with contextlib.suppress(Exception):
            env.keep_seconds = 0
            env.cleanup()
    registry.clear()
    ours = [c for c in docker("ps", "-a", "--filter", "label=hermes.rewind=1", "--format", "{{.Names}}").split()
            if "stress-" in c]
    if ours:
        docker("rm", "-f", *ours)
    images = [i for i in docker("images", "--format", "{{.Repository}}:{{.Tag}}").split()
              if i.startswith("hermes-rewind/stress-")]
    if images:
        docker("rmi", "-f", *images)
    shutil.rmtree(WORK, ignore_errors=True)


def main() -> int:
    args = sys.argv[1:]
    if "--list" in args:
        for name, fn in SECTIONS.items():
            print(f"{name:12} {fn.__doc__}")
        return 0
    report = Path("stress-report")
    if "--report" in args:
        i = args.index("--report")
        report = Path(args[i + 1]) if i + 1 < len(args) else report
        del args[i:i + 2]
    report = report.with_suffix("") if report.suffix in (".md", ".json") else report
    wanted = [a for a in args if not a.startswith("-")] or list(SECTIONS)
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
                check("section ran to the end", False, f"{type(exc).__name__}: {exc}")
                if VERBOSE:
                    traceback.print_exc()
            TIMES[name] = time.time() - t
            print(f"  {DIM}{TIMES[name]:.0f}s{RESET}")
    finally:
        CURRENT[0] = "cleanup"
        t = time.time()
        cleanup()
        leftover = [c for c in docker("ps", "-a", "--filter", "label=hermes.rewind=1", "--format", "{{.Names}}").split()
                    if "stress-" in c]
        check("no stress-test containers left behind", not leftover,
              "docker ps finds no stress-test containers" if not leftover else " ".join(leftover))
        TIMES["cleanup"] = time.time() - t
    seconds = time.time() - started
    failed = [r for r in RESULTS if not r["ok"]]
    print(f"\n{BOLD}{len(RESULTS) - len(failed)}/{len(RESULTS)} checks passed{RESET} in {seconds:.0f}s")
    for r in failed:
        print(f"  {RED}FAIL{RESET} [{r['section']}] {r['check']}  {DIM}{r['evidence'][:200]}{RESET}")
    write_reports(report, seconds)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
