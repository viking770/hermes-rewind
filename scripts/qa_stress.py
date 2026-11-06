"""Independent QA probes against real Docker (focused, ~5-10 minutes).

Each probe prints PASS / FAIL / BUG(<id>) with a one-line detail. BUG means the
probe reproduced a defect listed in the QA report; the script still exits 0 for
those, and non-zero only for unexpected FAILs.

Every sandbox uses a "qa-" task id, so its images are hermes-rewind/qa-*; the
script removes all of them at the end and checks nothing is left.

Run:  python scripts/qa_stress.py            (REWIND_DOCKER_API=0 to force the CLI path)
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
_TMP = tempfile.mkdtemp(prefix="rewind-qa-")
os.environ.setdefault("REWIND_STATE_DIR", str(Path(_TMP) / "state"))
os.environ.setdefault("REWIND_EXPORT_DIR", str(Path(_TMP) / "exports"))
os.environ["MSYS_NO_PATHCONV"] = "1"

from rewind import registry, tools  # noqa: E402
from rewind.environment import RewindEnvironment  # noqa: E402
from rewind.store import Store  # noqa: E402

API = os.environ.get("REWIND_DOCKER_API", "1") != "0"
RESULTS = []
ENVS = []


def report(name, status, detail=""):
    RESULTS.append((name, status, detail))
    print(f"[{status:>9}] {name}: {detail}", flush=True)


def make(name, **kw):
    kw.setdefault("network", "none")
    kw.setdefault("background", True)
    kw.setdefault("docker_api", API)
    kw.setdefault("timeout", 60)
    env = RewindEnvironment(task_id=f"qa-{name}", **kw)
    ENVS.append(env)
    return env


def sh(env, cmd, **kw):
    return env.execute(cmd, **kw)


def probe(fn):
    def run():
        try:
            fn()
        except Exception as exc:  # noqa
            report(fn.__name__, "FAIL", f"{type(exc).__name__}: {exc}"[:300])
    run.__name__ = fn.__name__
    return run


# --------------------------------------------------------------- probes
@probe
def misclassified_write_lost_on_undo():
    """QA-01: a write the classifier calls read-only is missing from the restore's safety snapshot."""
    env = make("lost")
    sh(env, "echo one > a.txt")
    time.sleep(2)  # let the background commit finish
    sh(env, "echo important >&b.txt")  # bash writes b.txt; classified read-only
    has_b = sh(env, "cat b.txt")["output"].strip()
    target, safety = env.undo()
    env.restore(safety.id)  # "undo the undo" should bring back exactly the state before the undo
    after = sh(env, "cat b.txt 2>&1; ls")["output"]
    if has_b == "important" and "important" not in after:
        report("misclassified_write_lost_on_undo", "BUG(QA-01)",
               f"b.txt existed before undo; after restoring the undo point ({safety.id}) it is gone")
    else:
        report("misclassified_write_lost_on_undo", "PASS", after.strip()[:100])


@probe
def heredoc_poisons_cwd():
    """QA-03 on real Docker: an unterminated heredoc swallows the wrapper and sets a garbage cwd."""
    env = make("heredoc", background=False)
    sh(env, "mkdir -p sub && cd sub")
    r = sh(env, "cat <<EOF\nhello")
    if not env.cwd.startswith("/"):
        report("heredoc_poisons_cwd", "BUG(QA-03)", f"cwd is now {env.cwd!r}; output tail {r['output'][-80:]!r}")
    else:
        report("heredoc_poisons_cwd", "PASS", env.cwd)


@probe
def fake_marker_sets_cwd():
    env = make("marker", background=False)
    sh(env, "printf '__REWIND_CWD__/etc\\n'; exit 0")
    status = "BUG(QA-03)" if env.cwd == "/etc" else "PASS"
    report("fake_marker_sets_cwd", status, f"cwd after printing a marker and exiting: {env.cwd}")


@probe
def exit_leaves_temp_files():
    env = make("exit", background=False)
    sh(env, "exit 3", stdin_data="x")
    # The checking command has a tracking file of its own while it runs (it holds
    # this shell's PID, $$); only files left by the earlier command count.
    left = sh(env, 'n=0; for f in /tmp/.rewind-*; do [ -e "$f" ] || continue; '
                   '[ "$(cat "$f" 2>/dev/null)" = "$$" ] && continue; n=$((n+1)); done; echo $n')["output"].strip()
    status = "BUG(QA-11)" if left not in ("", "0") else "PASS"
    report("exit_leaves_temp_files", status, f"{left} /tmp/.rewind-* file(s) left behind (they get committed into snapshots)")


@probe
def timeout_after_pid_file_removed():
    """QA-12: a timed-out command that removed /tmp's dotfiles is reported stopped but keeps running."""
    env = make("pidfile", background=False)
    r = sh(env, "find /tmp -mindepth 1 -delete; sleep 300", timeout=3)
    alive = sh(env, "for d in /proc/[0-9]*; do cat $d/cmdline 2>/dev/null | tr '\\0' ' '; echo; done | grep -c '^sleep 300' || true")
    n = alive["output"].strip().splitlines()[-1] if alive["output"].strip() else "0"
    if "was stopped" in r["output"] and n not in ("0", ""):
        report("timeout_after_pid_file_removed", "BUG(QA-12)", f"said 'was stopped' but {n} 'sleep 300' still running")
    else:
        report("timeout_after_pid_file_removed", "PASS", f"running={n}")
    sh(env, "pkill sleep 2>/dev/null; kill $(pidof sleep) 2>/dev/null; true")


@probe
def timeout_detached_child():
    env = make("detach", background=False)
    r = sh(env, "(setsid sh -c 'sleep 301' >/dev/null 2>&1 &) ; sleep 300", timeout=3)
    alive = sh(env, "for d in /proc/[0-9]*; do cat $d/cmdline 2>/dev/null | tr '\\0' ' '; echo; done | grep -c '^sleep 301' || true")
    n = alive["output"].strip().splitlines()[-1] if alive["output"].strip() else "0"
    if "was stopped" in r["output"] and n not in ("0", ""):
        report("timeout_detached_child", "BUG(QA-13)", f"said 'was stopped' but the setsid'd child is still running")
    else:
        report("timeout_detached_child", "PASS", f"stopped={'was stopped' in r['output']} running={n}")


@probe
def closed_stdout_returns_early():
    """A command that closes its output keeps running after execute() returns."""
    env = make("closed", background=False)
    t = time.time()
    r = sh(env, "exec >/dev/null 2>&1; sleep 4; touch /workspace/late", timeout=30)
    took = time.time() - t
    time.sleep(5)
    late = sh(env, "test -e /workspace/late && echo yes || echo no")["output"].strip()
    if took < 3:
        report("closed_stdout_returns_early", "BUG(QA-14)",
               f"returned after {took:.1f}s with code {r['returncode']}; command kept running (late file: {late})")
    else:
        report("closed_stdout_returns_early", "PASS", f"took {took:.1f}s")


@probe
def large_output():
    env = make("bigout", background=False)
    t = time.time()
    r = sh(env, "head -c 50000000 /dev/zero | tr '\\0' a")
    n = len(r["output"])
    report("large_output", "BUG(QA-15)" if n >= 50_000_000 else "PASS",
           f"{n:,} chars returned in {time.time() - t:.1f}s with no cap (host memory grows with output)")


@probe
def binary_output():
    env = make("binout", background=False)
    r = sh(env, "head -c 4096 /dev/urandom")
    report("binary_output", "PASS" if r["returncode"] == 0 else "FAIL", f"{len(r['output'])} chars, code {r['returncode']}")


@probe
def big_stdin():
    env = make("stdin", background=False)
    data = ("x" * 1023 + "\n") * 5 * 1024  # 5 MB
    t = time.time()
    r = sh(env, "wc -c", stdin_data=data)
    ok = r["output"].strip().endswith(str(len(data)))
    if not ok and "206" in r["output"]:  # QA-17: Windows command-line limit on the CLI path
        report("big_stdin", "BUG(QA-17)", f"5 MB stdin via the docker CLI: {r['output'].strip()[-70:]}")
        return
    report("big_stdin", "PASS" if ok else "FAIL", f"5 MB in {time.time() - t:.1f}s -> {r['output'].strip()[-30:]}")


@probe
def odd_filenames_roundtrip():
    env = make("names", background=False)
    names = ["with space", "-leading-dash", "quote'single", 'quote"double', "uni-\u00e9\u4e2d\U0001F600",
             "a" * 200, "new\nline"]
    script = "mkdir -p odd && cd odd && " + " && ".join(
        "printf x > " + "'" + n.replace("'", "'\\''") + "'" for n in names)
    sh(env, script)
    sh(env, "rm -rf /workspace/odd")
    env.undo()
    count = sh(env, "python3 -c \"import os; print(len(os.listdir('/workspace/odd')))\"")["output"].strip()
    changes = env.last_restore_changes or {}
    dest = env.export("/workspace/odd", Path(os.environ["REWIND_EXPORT_DIR"]))
    exported = sorted(p.name for p in dest.iterdir()) if dest.exists() else []
    skipped = [r[:40] for r in env.last_export_removed]
    report("odd_filenames_roundtrip", "PASS" if count.endswith("7") and len(exported) + len(skipped) == 7 else "FAIL",
           f"restored {count}/7; appear_count={changes.get('appear_count')}; exported {len(exported)}, "
           f"skipped+reported {len(skipped)} (names this host can't store): {skipped}")


@probe
def deep_and_many_files():
    env = make("many", background=False)
    sh(env, "cd /workspace && mkdir -p deep && cd deep && for i in $(seq 1 60); do mkdir d && cd d; done && echo bottom > f")
    sh(env, "cd /workspace && mkdir -p many && cd many && seq 1 5000 | xargs touch")
    sh(env, "cd /workspace && rm -rf deep many")
    t = time.time()
    env.undo()
    n = sh(env, "cd /workspace; ls many | wc -l; find deep -name f | wc -l")["output"].split()
    report("deep_and_many_files", "PASS" if n[:2] == ["5000", "1"] else "FAIL",
           f"restore {time.time() - t:.1f}s, many={n[0] if n else '?'} deep_f={n[1] if len(n) > 1 else '?'}")


@probe
def concurrent_tools_during_command():
    env = make("concur")
    sh(env, "echo a > a")
    errors, out = [], {}

    def long_cmd():
        out["cmd"] = sh(env, "sleep 3; echo done > b")

    def tool_calls():
        try:
            for _ in range(5):
                json.loads(tools.rewind_list({}, task_id="qa-concur"))
            out["undo"] = json.loads(tools.rewind_undo({}, task_id="qa-concur"))
        except Exception as exc:  # noqa
            errors.append(exc)
    a = threading.Thread(target=long_cmd)
    b = threading.Thread(target=tool_calls)
    a.start(); time.sleep(0.5); b.start(); a.join(); b.join()
    ok = not errors and out["cmd"]["returncode"] == 0 and out["undo"].get("ok")
    state = sh(env, "ls")["output"].split()
    report("concurrent_tools_during_command", "PASS" if ok else "FAIL",
           f"undo waited for the command; files after undo: {state}; errors={errors}")


@probe
def rapid_mutations_and_pruning():
    env = make("rapid", max_snapshots=5)
    t = time.time()
    for i in range(30):
        sh(env, f"echo {i} > f{i}")
    took = time.time() - t
    autos = [s for s in env.snapshots if s.auto]
    env.restore(autos[0].id)
    n = sh(env, "ls | wc -l")["output"].strip()
    report("rapid_mutations_and_pruning", "PASS" if len(autos) == 5 else "FAIL",
           f"30 writes in {took:.1f}s, {len(autos)} auto snapshots kept, oldest kept has {n} files")


@probe
def compaction_then_restore():
    env = make("compact", compact_mb=20)
    sh(env, "head -c 30000000 /dev/urandom > big.bin && echo v1 > v")
    time.sleep(3)
    sh(env, "echo v2 > v")
    time.sleep(3)
    sh(env, "rm -f big.bin v")
    env.undo()
    r = sh(env, "cat v; ls -la big.bin | awk '{print $5}'")["output"].split()
    report("compaction_then_restore", "PASS" if r[:2] == ["v2", "30000000"] else "FAIL", f"after undo: {r}")


@probe
def resource_limits_hold():
    env = make("limits", memory_mb=256, background=False)
    mem = sh(env, "python3 -c 'b=bytearray(600*1024*1024)'; echo rc=$?", timeout=60)
    caps = sh(env, "grep CapEff /proc/self/status")["output"].strip()
    nnp = sh(env, "grep NoNewPrivs /proc/self/status")["output"].strip()
    ok = "rc=137" in mem["output"] and "00000000000000cb" in caps.lower() or "rc=137" in mem["output"]
    report("resource_limits_hold", "PASS" if ok else "FAIL",
           f"600MB alloc in 256MB box -> {mem['output'].strip()[-8:]}; {caps}; {nnp}")


@probe
def pids_exhaustion_recovery():
    """QA-16: with the process limit used up by long-lived processes, Rewind cannot stop the
    command (its own kill exec can't start), and every later command fails until an undo."""
    env = make("pids", pids_limit=64, background=False)
    sh(env, "echo before > marker")
    r = sh(env, "for i in $(seq 1 100); do sleep 1000 & done; wait", timeout=5)
    after = sh(env, "echo alive")
    stuck = "alive" not in after["output"]
    undo_ok = ""
    if stuck:
        try:
            env.undo()
            undo_ok = sh(env, "cat marker")["output"].strip()
        except Exception as exc:  # noqa
            undo_ok = f"undo failed: {exc}"[:120]
    status = "BUG(QA-16)" if stuck else "PASS"
    report("pids_exhaustion_recovery", status,
           f"timeout msg: {r['output'].strip()[-60:]!r}; next command: {after['output'].strip()[:70]!r}; "
           f"after undo: {undo_ok!r}")


@probe
def firewall_basic():
    """Single short connects only: the sandbox's own host, metadata, and one public site."""
    env = make("net", network="internet", background=False)
    targets = {
        "host.docker.internal:80": "('host.docker.internal', 80)",
        "metadata 169.254.169.254": "('169.254.169.254', 80)",
        "metadata as decimal": "('2852039166', 80)",
        "LAN 192.168.1.1": "('192.168.1.1', 80)",
        "example.com:80 (should work)": "('example.com', 80)",
    }
    lines = []
    blocked_all = True
    for label, addr in targets.items():
        code = ("import socket\ns=socket.socket(); s.settimeout(3)\n"
                f"try:\n  s.connect({addr}); print('OPEN')\nexcept Exception as e:\n  print('BLOCKED', type(e).__name__)")
        res = sh(env, f"python3 -c \"{code}\"", timeout=20)["output"].strip().splitlines()[-1:]
        res = res[0] if res else "?"
        lines.append(f"{label}={res}")
        if "should work" not in label and res.startswith("OPEN"):
            blocked_all = False
    report("firewall_basic", "PASS" if blocked_all else "FAIL", "; ".join(lines))


@probe
def parking_roundtrip():
    store = Store(Path(os.environ["REWIND_STATE_DIR"]))
    env = make("park", store=store, keep_hours=1)
    sh(env, "echo keep > k && cd /tmp")
    env.cleanup()
    registry.clear()
    again = make("park", store=store, keep_hours=1)
    r = sh(again, "cat /workspace/k; pwd")
    ok = "keep" in r["output"] and "/tmp" in r["output"] and again.snapshots
    report("parking_roundtrip", "PASS" if ok else "FAIL", r["output"].strip()[-120:])


def cleanup():
    for env in ENVS:
        try:
            env.keep_seconds = 0
            env.cleanup()
        except Exception:
            pass
    run = lambda *a: subprocess.run(["docker", *a], capture_output=True, text=True).stdout  # noqa: E731
    leftovers_c = [line for line in run("ps", "-a", "--filter", "label=hermes.rewind=1", "--format",
                                        "{{.ID}} {{.Names}}").splitlines() if " hermes-rewind-qa-" in line]
    for line in leftovers_c:
        run("rm", "-f", line.split()[0])
    imgs = [i for i in run("images", "--format", "{{.Repository}}:{{.Tag}}").splitlines()
            if i.startswith("hermes-rewind/qa-")]
    if imgs:
        run("rmi", "-f", *imgs)
    left = [i for i in run("images", "--format", "{{.Repository}}:{{.Tag}}").splitlines()
            if i.startswith("hermes-rewind/qa-")]
    left_c = [line for line in run("ps", "-a", "--format", "{{.Names}}").splitlines()
              if line.startswith("hermes-rewind-qa-")]
    print(f"cleanup: removed {len(leftovers_c)} stray container(s), {len(imgs)} stray image(s); "
          f"left: {left + left_c or 'nothing'}")


PROBES = [misclassified_write_lost_on_undo, heredoc_poisons_cwd, fake_marker_sets_cwd, exit_leaves_temp_files,
          timeout_after_pid_file_removed, timeout_detached_child, closed_stdout_returns_early, large_output,
          binary_output, big_stdin, odd_filenames_roundtrip, deep_and_many_files, concurrent_tools_during_command,
          rapid_mutations_and_pruning, compaction_then_restore, resource_limits_hold, pids_exhaustion_recovery, firewall_basic,
          parking_roundtrip]

if __name__ == "__main__":
    only = set(sys.argv[1:])
    started = time.time()
    try:
        for p in PROBES:
            if not only or p.__name__ in only:
                p()
    finally:
        cleanup()
    fails = [r for r in RESULTS if r[1] == "FAIL"]
    bugs = [r for r in RESULTS if r[1].startswith("BUG")]
    print(f"\n{len(RESULTS)} probes in {time.time() - started:.0f}s (API={API}): "
          f"{len(RESULTS) - len(fails) - len(bugs)} pass, {len(bugs)} reproduced bugs, {len(fails)} unexpected fail")
    sys.exit(1 if fails else 0)
