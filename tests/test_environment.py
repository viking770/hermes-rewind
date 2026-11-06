import json
import re
import subprocess
import time
import unittest

from rewind import RewindProvider, registry, tools
from rewind.environment import (
    DEFAULT_IMAGE, GUARD_IMAGE, SLIM_IMAGE, TOOLS_IMAGE, RewindEnvironment, RewindError, _CWD_MARKER,
)


class FakeDocker:
    """Records docker CLI calls and returns canned results."""

    def __init__(self):
        self.calls = []
        self.exec_output = "hello\n"
        self.exec_code = 0
        self.exec_cwd = "/workspace"
        self.fail = set()
        self.fail_images = set()  # `docker run` fails for these images
        self.timeout_exec = False
        self.diff_output = "C /workspace\nA /workspace/new.txt\n"
        self.image_info = {}  # image -> "size layers" for `docker image inspect`
        self.guard_fails = False
        self.guard_image_present = True
        self.tools_image_present = True
        self.kill_fails = False
        self.kill_scripts = []

    def __call__(self, argv, timeout=None):
        assert argv[0] == "docker"
        self.calls.append(list(argv))
        verb = argv[1]
        if verb in self.fail:
            return 1, f"{verb} exploded"
        if verb == "run" and self.fail_images.intersection(argv):
            return 1, "image is broken"
        if verb == "run" and GUARD_IMAGE in argv:
            return (1, "iptables: not supported") if self.guard_fails else (0, "REWIND_GUARD_OK\n")
        if verb == "image" and argv[2] == "inspect" and argv[-1] == GUARD_IMAGE and self.guard_image_present:
            return 0, "100 3\n"
        if verb == "image" and argv[2] == "inspect" and argv[-1] == TOOLS_IMAGE and self.tools_image_present:
            return 0, "200 4\n"
        if verb == "build" and TOOLS_IMAGE in argv:
            self.tools_image_present = True
            return 0, ""
        if verb == "exec":
            if argv[-1] == "command -v bash":
                return 0, "/bin/bash\n"
            if "REWIND_KILL_OK" in argv[-1]:
                self.kill_scripts.append(argv[-1])
                return (1, "") if self.kill_fails else (0, "REWIND_KILL_OK\n")
            if self.timeout_exec:
                raise subprocess.TimeoutExpired(argv, timeout, output=b"partial")
            return self.exec_code, f"{self.exec_output}\n{_CWD_MARKER}{self.exec_cwd}\n"
        if verb == "diff":
            return 0, self.diff_output
        if verb == "image" and argv[2] == "inspect":
            info = self.image_info.get(argv[-1])
            return (0, info + "\n") if info else (1, "No such image")
        return 0, ""

    def verbs(self):
        return [c[1] for c in self.calls]


# Session ids the way Hermes makes them: long and random.
ALICE = "local-" + "a" * 64
BOB = "local-" + "b" * 64


def make_env(fake, **kw):
    # Snapshot before each command, so call order is deterministic. Background
    # snapshots have their own tests below. The network guard adds docker calls
    # of its own, so it is off here and tested in test_security.py.
    kw.setdefault("background", False)
    kw.setdefault("network", "none")
    # Call-order tests count docker calls; the default image's build check has its own tests.
    kw.setdefault("image", SLIM_IMAGE)
    return RewindEnvironment(task_id="Demo Task", runner=fake, **kw)


class EnvironmentTests(unittest.TestCase):
    def setUp(self):
        registry.clear()
        self.fake = FakeDocker()

    def test_lazy_start_and_read_only_command_skips_snapshot(self):
        env = make_env(self.fake)
        self.assertEqual(self.fake.calls, [])
        result = env.execute("ls")
        self.assertEqual(result, {"output": "hello\n", "returncode": 0, "exit_code": 0,
                                  "cwd": "/workspace", "cwd_observed": True})
        self.assertEqual(self.fake.verbs(), ["run", "exec", "exec"])
        self.assertNotIn("commit", self.fake.verbs())
        # Uses bash once detected, and names are docker-safe.
        self.assertEqual(self.fake.calls[-1][3], "bash")
        self.assertTrue(env.container.startswith("hermes-rewind-demo-task-"))

    def test_mutating_command_snapshots_first(self):
        env = make_env(self.fake)
        env.execute("rm -rf build")
        verbs = self.fake.verbs()
        self.assertLess(verbs.index("commit"), len(verbs) - 1)
        self.assertEqual(verbs[-1], "exec")
        self.assertEqual(len(env.snapshots), 1)
        self.assertEqual(env.snapshots[0].command, "rm -rf build")
        self.assertTrue(env.snapshots[0].image.endswith(":s1"))

    def test_cwd_persists_between_commands(self):
        env = make_env(self.fake)
        self.fake.exec_cwd = "/workspace/src"
        env.execute("cd src")
        self.assertEqual(env.cwd, "/workspace/src")
        env.execute("ls")
        self.assertIn("cd /workspace/src", self.fake.calls[-1][-1])

    def test_hermes_result_contract(self):
        # Hermes reads result["returncode"] (defaulting to 0!) and result["cwd"],
        # and passes its tracked cwd back as the second positional argument.
        env = make_env(self.fake)
        self.fake.exec_code = 2
        self.fake.exec_cwd = "/workspace/src"
        result = env.execute("cd src && false", "/workspace")
        self.assertEqual(result["returncode"], 2)
        self.assertEqual(result["cwd"], "/workspace/src")
        env.execute("ls", "/workspace/src", timeout=5, bounded_capture=True, rewrite_compound_background=False)
        self.assertIn("cd /workspace/src", self.fake.calls[-1][-1])

    def test_stdin_data_reaches_the_command_byte_exact(self):
        import base64
        env = make_env(self.fake)
        data = "line one\nno trailing newline ✓"
        env.execute("cat > /workspace/f.txt", stdin_data=data)
        staged = [c[-1] for c in self.fake.calls if c[1] == "exec" and ".rewind-stdin-" in c[-1]]
        chunk = staged[0].split("'")[3]
        self.assertEqual(base64.b64decode(chunk).decode(), data)
        self.assertTrue(any("base64 -d" in s for s in staged))
        command = self.fake.calls[-1][-1]
        self.assertRegex(command, r"\}\s*< /tmp/\.rewind-stdin-\w+")
        self.assertIn("rm -f /tmp/.rewind-stdin-", command)

    def test_large_stdin_is_chunked_under_the_argument_limit(self):
        from rewind.environment import _STDIN_CHUNK
        env = make_env(self.fake)
        env.execute("cat > big", stdin_data="x" * 300_000)
        appends = [c[-1] for c in self.fake.calls if c[1] == "exec" and ".b64" in c[-1] and ">>" in c[-1]]
        self.assertGreater(len(appends), 1)
        self.assertTrue(all(len(a) < _STDIN_CHUNK + 200 for a in appends))

    def test_exit_code_and_timeout(self):
        env = make_env(self.fake)
        self.fake.exec_code = 3
        self.assertEqual(env.execute("ls")["exit_code"], 3)
        self.fake.timeout_exec = True
        result = env.execute("ls", timeout=5)
        self.assertEqual(result["exit_code"], 124)
        self.assertIn("partial", result["output"])
        self.assertIn("timed out after 5s", result["output"])

    def test_timed_out_command_is_stopped_in_the_container(self):
        env = make_env(self.fake)
        self.fake.timeout_exec = True
        result = env.execute("sleep 999", timeout=5)
        self.assertIn("was stopped", result["output"])
        # The kill targets the PID file this very command's wrapper wrote.
        run = [c for c in self.fake.calls if c[1] == "exec" and "sleep 999" in c[-1]][-1][-1]
        pid_file = re.search(r"echo \$\$ > (\S+)", run).group(1)
        self.assertIn(f"f={pid_file}", self.fake.kill_scripts[-1])
        self.assertIn("kill -KILL", self.fake.kill_scripts[-1])

    def test_no_background_snapshot_while_a_timed_out_command_may_still_run(self):
        env = make_env(self.fake, background=True)
        self.fake.timeout_exec = True
        self.fake.kill_fails = True
        commits = self.fake.verbs().count("commit")
        result = env.execute("sleep 999", timeout=5)
        env._finish_background()
        self.assertIn("could not be stopped", result["output"])
        self.assertEqual(self.fake.verbs().count("commit"), commits)
        self.assertIsNone(env._pending)
        # Once the command is confirmed stopped, the next state is captured again.
        self.fake.kill_fails = False
        env.execute("sleep 999", timeout=5)
        env._finish_background()
        self.assertGreater(self.fake.verbs().count("commit"), commits)

    def test_snapshot_failure_warns_but_still_runs(self):
        env = make_env(self.fake)
        self.fake.fail.add("commit")
        result = env.execute("rm x")
        self.assertIn("cannot be undone", result["output"])
        self.assertEqual(self.fake.verbs()[-1], "exec")

    def test_start_failure_is_reported(self):
        env = make_env(self.fake)
        self.fake.fail.add("run")
        result = env.execute("ls")
        self.assertEqual(result["exit_code"], 1)
        self.assertIn("could not start", result["output"])
        # The half-created container is removed so a retry can reuse the name.
        self.assertEqual(self.fake.calls[-1], ["docker", "rm", "-f", env.container])
        self.fake.fail.clear()
        self.assertEqual(env.execute("ls")["exit_code"], 0)

    def test_failed_restore_falls_back_to_safety_snapshot(self):
        env = make_env(self.fake)
        env.execute("rm a")  # s1
        self.fake.fail_images.add(env.snapshots[0].image)
        with self.assertRaises(RewindError) as ctx:
            env.restore("s1")
        self.assertIn("s2", str(ctx.exception))
        run_calls = [c for c in self.fake.calls if c[1] == "run"]
        self.assertIn(f"{env.repository}:s2", run_calls[-1])
        self.assertTrue(env._started)

    def test_failed_restore_and_fallback_retries_from_safety_not_base(self):
        env = make_env(self.fake)
        env.execute("rm a")  # s1
        self.fake.fail_images.update({env.snapshots[0].image, f"{env.repository}:s2"})
        with self.assertRaises(RewindError):
            env.restore("s1")
        self.assertFalse(env._started)
        self.fake.fail_images.clear()
        env.execute("ls")
        run_calls = [c for c in self.fake.calls if c[1] == "run"]
        self.assertIn(f"{env.repository}:s2", run_calls[-1])
        self.assertNotIn(env.base_image, run_calls[-1])

    def test_restore_recreates_container_from_snapshot(self):
        env = make_env(self.fake)
        self.fake.exec_cwd = "/workspace/app"
        env.execute("cd app")
        env.execute("rm -rf data")  # snapshot s1 taken in /workspace/app
        self.fake.exec_cwd = "/tmp"
        env.execute("cd /tmp")
        target, safety = env.restore("s1")
        self.assertEqual(target.id, "s1")
        self.assertEqual(safety.id, "s2")
        self.assertFalse(safety.auto)
        run_calls = [c for c in self.fake.calls if c[1] == "run"]
        self.assertEqual(len(run_calls), 2)
        self.assertIn(target.image, run_calls[-1])
        self.assertEqual(env.cwd, "/workspace/app")
        # Hermes passes back the cwd it tracked before the restore; the
        # restored directory wins for the next command and is reported.
        self.fake.exec_cwd = "/workspace/app"
        result = env.execute("ls", "/tmp")
        self.assertIn("cd /workspace/app", self.fake.calls[-1][-1])
        self.assertEqual(result["cwd"], "/workspace/app")
        env.execute("ls", "/tmp")
        self.assertIn("cd /tmp", self.fake.calls[-1][-1])  # only once
        # The restore is itself undoable.
        env.restore(safety.id)

    def test_restore_last_and_unknown(self):
        env = make_env(self.fake)
        with self.assertRaises(RewindError):
            env.restore("last")
        env.execute("rm a")
        env.execute("rm b")
        target, _ = env.restore("last")
        self.assertEqual(target.id, "s2")
        with self.assertRaises(RewindError):
            env.restore("s99")

    def test_repeated_restore_last_does_not_undo_itself(self):
        # The demo that went wrong: create, delete, then "undo" twice.
        env = make_env(self.fake)
        env.execute("mkdir demo")             # s1: before mkdir
        env.execute("rm -rf demo")            # s2: before rm, still has demo
        first, safety1 = env.restore("last")
        self.assertEqual(first.id, "s2")
        self.assertTrue(safety1.restore_point)
        second, safety2 = env.restore("last")
        self.assertEqual(second.id, "s2")     # not safety1, which has demo deleted
        self.assertTrue(safety2.restore_point)
        # Undoing a restore still works with its explicit id.
        undone, _ = env.restore(safety1.id)
        self.assertEqual(undone.id, safety1.id)
        # A new change after a restore becomes "last".
        env.execute("rm -rf demo")
        self.assertFalse(env.find("last").restore_point)
        self.assertEqual(env.find("last").command, "rm -rf demo")

    def test_restore_last_with_only_restore_points_asks_for_an_id(self):
        env = make_env(self.fake)
        env.execute("rm a")
        env.restore("s1")
        env.snapshots = [s for s in env.snapshots if s.restore_point]
        with self.assertRaises(RewindError) as ctx:
            env.find("last")
        self.assertIn("snapshot id", str(ctx.exception))

    def test_describe_says_state_before_command(self):
        env = make_env(self.fake)
        env.execute("rm -rf demo")
        env.snapshot("before refactor")
        _, safety = env.restore("s1")
        states = {s["id"]: s["state"] for s in env.list_snapshots()}
        self.assertEqual(states["s1"], "state before running: rm -rf demo")
        self.assertEqual(states["s2"], "checkpoint: before refactor")
        self.assertIn("before restoring s1", states[safety.id])
        self.assertIn("undo that restore", states[safety.id])

    def test_prune_keeps_manual_snapshots(self):
        env = make_env(self.fake, max_snapshots=2)
        env.snapshot("keep me")
        for i in range(4):
            env.execute(f"rm f{i}")
        ids = [s.id for s in env.snapshots]
        self.assertEqual(ids, ["s1", "s4", "s5"])
        self.assertEqual(sum(1 for c in self.fake.calls if c[1] == "rmi"), 2)

    def test_cleanup_removes_container_and_images(self):
        env = make_env(self.fake)
        env.execute("rm a")
        env.cleanup()
        self.assertIn(["docker", "rm", "-f", env.container], self.fake.calls)
        rmi = [c for c in self.fake.calls if c[1] == "rmi"][-1]
        self.assertIn(f"{env.repository}:s1", rmi)
        self.assertIsNone(registry.get())

    def runs(self):
        return [c for c in self.fake.calls if c[1] == "run"]

    def test_big_snapshot_compacts_container(self):
        env = make_env(self.fake, compact_mb=1)
        self.fake.image_info = {
            env.base_image: "1000 4",
            f"{env.repository}:s1": f"{3 * 1024 * 1024} 5",
            f"{env.repository}:s2": f"{3 * 1024 * 1024 + 10} 6",
        }
        result = env.execute("pip install big")
        self.assertEqual(result["exit_code"], 0)
        self.assertIn(f"{env.repository}:s1", self.runs()[-1])
        self.assertEqual(self.fake.verbs()[-1], "exec")  # the command still runs
        # The next snapshot is small relative to s1, so no further restart.
        env.execute("rm x")
        self.assertEqual(len(self.runs()), 2)

    def test_small_snapshot_does_not_compact(self):
        env = make_env(self.fake, compact_mb=1)
        self.fake.image_info = {env.base_image: "1000 4", f"{env.repository}:s1": "5000 5"}
        env.execute("rm x")
        self.assertEqual(len(self.runs()), 1)

    def test_compaction_stops_near_layer_limit(self):
        env = make_env(self.fake, compact_mb=1)
        self.fake.image_info = {env.base_image: "1000 4", f"{env.repository}:s1": f"{10 ** 9} 100"}
        env.execute("rm x")
        self.assertEqual(len(self.runs()), 1)

    def test_compaction_off(self):
        env = make_env(self.fake, compact_mb=0)
        env.execute("rm x")
        self.assertNotIn("image", self.fake.verbs())

    def test_changes_survive_compaction_and_reset_on_restore(self):
        env = make_env(self.fake, compact_mb=1)
        self.fake.image_info = {env.base_image: "1000 4", f"{env.repository}:s1": f"{10 ** 9} 5"}
        self.fake.diff_output = "A /workspace/a.txt\nA /workspace/gone.txt\nD /workspace/old.txt\n"
        env.execute("pip install big")  # compacts, carrying these changes
        self.fake.diff_output = "D /workspace/gone.txt\nA /workspace/old.txt\nC /workspace/a.txt\n"
        self.assertEqual(env.changes(), ["A /workspace/a.txt", "C /workspace/old.txt"])
        env.restore("s1")
        self.assertEqual(env.changes(), sorted(self.fake.diff_output.splitlines(), key=lambda l: l[2:]))

    def test_failed_compaction_restart_is_retried_from_snapshot(self):
        env = make_env(self.fake, compact_mb=1)
        s1 = f"{env.repository}:s1"
        self.fake.image_info = {env.base_image: "1000 4", s1: f"{10 ** 9} 5"}
        self.fake.fail_images.add(s1)
        result = env.execute("pip install big")
        self.assertEqual(result["exit_code"], 1)
        self.assertIn("could not start", result["output"])
        self.fake.fail_images.clear()
        self.assertEqual(env.execute("ls")["exit_code"], 0)
        self.assertIn(s1, self.runs()[-1])

    def test_network_off(self):
        env = make_env(self.fake, network=False)
        env.execute("ls")
        self.assertIn("none", self.fake.calls[0])

    def test_split_cwd_keeps_late_output(self):
        from rewind.environment import _split_cwd
        out, cwd = _split_cwd(f"a\n\n{_CWD_MARKER}/x\nlate stderr\n")
        self.assertEqual((out, cwd), ("a\nlate stderr\n", "/x"))
        self.assertEqual(_split_cwd("no marker"), ("no marker", None))

    def test_bad_mode(self):
        with self.assertRaises(ValueError):
            make_env(self.fake, snapshot_mode="sometimes")


class BackgroundSnapshotTests(unittest.TestCase):
    def setUp(self):
        registry.clear()
        self.fake = FakeDocker()
        self.env = make_env(self.fake, background=True)

    def calls_during(self, fn):
        """Run fn, wait for any background commit, return the docker verbs fn
        caused, leaving out compaction's `image inspect` size checks."""
        self.env._finish_background()
        start = len(self.fake.calls)
        fn()
        before_join = [v for v in self.fake.verbs()[start:] if v != "image"]
        self.env._finish_background()
        return before_join, [v for v in self.fake.verbs()[start:] if v != "image"]

    def test_changing_command_claims_ready_snapshot_instead_of_waiting(self):
        env = self.env
        env.execute("ls")  # leaves a snapshot of the current state committing in the background
        _, verbs = self.calls_during(lambda: env.execute("rm -rf build"))
        self.assertEqual(verbs[0], "exec")  # ran straight away, no commit first
        self.assertEqual(verbs[1:], ["commit"])  # next state committed after it
        self.assertEqual([(s.id, s.command) for s in env.snapshots], [("s1", "rm -rf build")])
        self.assertIsNotNone(env._pending)
        self.assertEqual(env._pending.id, "s2")

    def test_read_only_commands_keep_the_pending_snapshot(self):
        env = self.env
        env.execute("ls")
        _, verbs = self.calls_during(lambda: env.execute("cat README.md"))
        self.assertEqual(verbs, ["exec"])
        env.execute("rm x")
        self.assertEqual(env.snapshots[-1].id, "s1")

    def test_first_change_without_a_ready_snapshot_commits_first(self):
        env = self.env
        _, verbs = self.calls_during(lambda: env.execute("rm x"))
        self.assertLess(verbs.index("commit"), verbs.index("exec", 2))
        self.assertEqual(env.snapshots[0].command, "rm x")

    def test_failed_background_commit_falls_back_to_committing_first(self):
        env = self.env
        self.fake.fail.add("commit")
        env.execute("ls")
        env._finish_background()
        self.assertIsNone(env._pending)
        self.fake.fail.clear()
        start = len(self.fake.calls)
        env.execute("rm x")
        self.assertEqual(self.fake.verbs()[start], "commit")
        self.assertEqual(env.snapshots[0].command, "rm x")

    def test_next_command_waits_for_a_slow_commit(self):
        env = self.env
        order = []
        real = self.fake.__call__

        def slow(argv, timeout=None):
            if argv[1] == "commit":
                time.sleep(0.3)
                order.append("commit done")
            elif argv[1] == "exec" and "rm y" in argv[-1]:
                order.append("rm y runs")
            return real(argv, timeout)

        env._run = slow
        started = time.time()
        env.execute("rm x")  # commits first (nothing ready), then starts a background commit
        returned = time.time() - started
        self.assertLess(returned, 0.55)  # one commit, not two
        env.execute("rm y")
        self.assertEqual(order[-2:], ["commit done", "rm y runs"])

    def test_restore_uses_ready_snapshot_as_safety_and_prepares_another(self):
        env = self.env
        env.execute("rm a")   # s1 (committed first), s2 pending
        env._finish_background()
        _, verbs = self.calls_during(lambda: env.restore("s1"))
        target, safety = env.find("s1"), env.snapshots[-1]
        self.assertEqual(safety.id, "s2")
        self.assertEqual(safety.label, "before restoring s1")
        self.assertNotIn("commit", verbs[:verbs.index("run")])  # safety was already committed
        self.assertEqual(verbs[-1], "commit")  # prepared for the next change
        self.assertEqual(env._pending.id, "s3")
        self.assertIn(target.image, [c for c in self.fake.calls if c[1] == "run"][-1])

    def test_manual_snapshot_claims_pending_and_prepares_another(self):
        env = self.env
        env.execute("ls")
        env._finish_background()
        snap = env.snapshot("checkpoint")
        self.assertEqual((snap.id, snap.label, snap.auto), ("s1", "checkpoint", False))
        env._finish_background()
        self.assertEqual(env._pending.id, "s2")

    def test_cleanup_removes_unclaimed_pending_image(self):
        env = self.env
        env.execute("ls")
        env.cleanup()
        rmi = [c for c in self.fake.calls if c[1] == "rmi"][-1]
        self.assertIn(f"{env.repository}:s1", rmi)
        self.assertIsNone(env._pending)

    def test_off_mode_never_commits(self):
        env = make_env(self.fake, background=True, snapshot_mode="off")
        env.execute("rm x")
        env._finish_background()
        self.assertNotIn("commit", self.fake.verbs())


class ToolTests(unittest.TestCase):
    def setUp(self):
        registry.clear()
        self.fake = FakeDocker()

    def call(self, name, args=None, **kw):
        return json.loads(tools.HANDLERS[name](args or {}, **kw))

    def test_tools_never_act_on_another_sessions_sandbox(self):
        # Even when it is the only sandbox running (the old fallback).
        RewindEnvironment(task_id=f"session:agent:main:telegram:dm:{ALICE}", runner=self.fake, background=False)
        result = self.call("rewind_list", task_id=BOB, session_id=BOB)
        self.assertFalse(result["ok"])
        self.assertIn("no Rewind sandbox", result["error"])
        self.assertTrue(self.call("rewind_list", task_id=ALICE, session_id=ALICE)["ok"])

    def test_tools_find_hermes_session_keyed_sandbox(self):
        # What Hermes really does: sandbox "session:<session key>", whose key
        # ends with the session id that tool calls carry as task_id.
        mine = RewindEnvironment(task_id=f"session:agent:main:local:dm:{ALICE}", runner=self.fake, background=False)
        RewindEnvironment(task_id=f"session:agent:main:local:dm:{BOB}", runner=self.fake, background=False)
        mine.execute("rm a")
        listed = self.call("rewind_list", task_id=ALICE, session_id=ALICE)
        self.assertEqual([s["id"] for s in listed["snapshots"]], ["s1"])

    def test_short_ids_are_not_suffix_matched(self):
        RewindEnvironment(task_id="session:agent:main:local:dm:x-1", runner=self.fake, background=False)
        self.assertFalse(self.call("rewind_list", task_id="1")["ok"])

    def test_shared_sandbox_serves_any_task_id(self):
        # Hermes's default: one sandbox created as "default", tool calls with
        # each session's own task_id. Hermes's own terminal tool uses it too.
        RewindEnvironment(task_id="default", runner=self.fake, background=False)
        self.assertTrue(self.call("rewind_list", task_id="session-123")["ok"])

    def test_shared_sandbox_is_not_reachable_from_messaging_platforms(self):
        # A Telegram chat with no sandbox of its own (none yet, or parked) must
        # not fall through to the local user's shared sandbox.
        class Ctx:
            def session_surface(self):
                return "telegram"

        shared = RewindEnvironment(task_id="default", runner=self.fake, background=False)
        shared.execute("rm a")
        old, tools._CTX = tools._CTX, Ctx()
        try:
            for name, args in (("rewind_list", {}), ("rewind_changes", {}),
                               ("rewind_restore", {"snapshot_id": "s1"}), ("rewind_undo", {})):
                result = self.call(name, args, task_id="telegram-chat", session_id="telegram-chat")
                self.assertFalse(result["ok"], name)
                self.assertIn("no Rewind sandbox", result["error"])
            # The chat's own sandbox still works.
            RewindEnvironment(task_id="telegram-chat", runner=self.fake, background=False)
            self.assertTrue(self.call("rewind_list", task_id="telegram-chat")["ok"])
        finally:
            tools._CTX = old

    def test_tools_without_sandbox_return_error(self):
        result = self.call("rewind_list")
        self.assertFalse(result["ok"])
        self.assertIn("terminal.backend", result["error"])

    def test_tool_flow(self):
        env = make_env(self.fake)
        env.execute("rm -rf src")
        mine = {"task_id": "Demo Task"}
        listed = self.call("rewind_list", **mine)
        self.assertTrue(listed["ok"])
        self.assertEqual(listed["snapshots"][0]["id"], "s1")
        snap = self.call("rewind_snapshot", {"label": "before refactor"}, **mine)
        self.assertEqual(snap["snapshot"]["label"], "before refactor")
        restored = self.call("rewind_restore", {"snapshot_id": "s1"}, **mine)
        self.assertTrue(restored["ok"])
        self.assertEqual(restored["undo_with"], "s3")
        changes = self.call("rewind_changes", **mine)
        self.assertIn("A /workspace/new.txt", changes["changes"])
        bad = self.call("rewind_restore", {"snapshot_id": "nope"}, **mine)
        self.assertFalse(bad["ok"])

    def test_register_with_fake_ctx(self):
        registered = {}

        class Ctx:
            def register_terminal_environment_provider(self, provider):
                registered["provider"] = provider

            def register_tool(self, name, toolset, schema, handler, check_fn=None, override=False):
                registered[name] = (toolset, schema["name"], handler, check_fn)

        import rewind
        rewind.register(Ctx())
        self.assertIsInstance(registered["provider"], RewindProvider)
        self.assertEqual(registered["provider"].name, "rewind")
        for name in tools.SCHEMAS:
            self.assertEqual(registered[name][1], name)

    def test_provider_creates_environment(self):
        env = RewindProvider().create_environment(cwd="~", timeout=30, task_id="t1", image="")
        self.assertEqual(env.cwd, "/workspace")
        self.assertEqual(env.base_image, DEFAULT_IMAGE)
        self.assertEqual(DEFAULT_IMAGE, TOOLS_IMAGE)
        self.assertIn("@sha256:", SLIM_IMAGE)  # what it's built from is pinned
        self.assertIs(registry.get("t1"), env)


class DefaultImageTests(unittest.TestCase):
    """The default sandbox has git and curl, so a fresh one can clone a repo."""

    def setUp(self):
        registry.clear()
        self.fake = FakeDocker()

    def sandbox_image(self):
        run = [c for c in self.fake.calls if c[1] == "run" and "-d" in c][-1]
        return run[run.index("--entrypoint") + 2]

    def test_default_image_is_built_once_from_the_pinned_slim_image(self):
        from rewind.environment import _TOOLS_DOCKERFILE
        self.assertTrue(_TOOLS_DOCKERFILE.startswith(f"FROM {SLIM_IMAGE}\n"))
        for package in ("git", "curl", "ca-certificates"):
            self.assertIn(f" {package}", _TOOLS_DOCKERFILE)
        self.fake.tools_image_present = False
        env = make_env(self.fake, image=DEFAULT_IMAGE)
        result = env.execute("git --version")
        self.assertEqual(self.sandbox_image(), TOOLS_IMAGE)
        self.assertIn("First run on this machine", result["output"])
        self.assertEqual(self.fake.verbs().count("build"), 1)
        # A second sandbox finds it and doesn't build again.
        make_env(self.fake, image=DEFAULT_IMAGE).execute("ls")
        self.assertEqual(self.fake.verbs().count("build"), 1)

    def test_falls_back_to_the_slim_image_when_the_build_fails(self):
        self.fake.tools_image_present = False
        self.fake.fail.add("build")
        env = make_env(self.fake, image=DEFAULT_IMAGE)
        result = env.execute("ls")
        self.assertEqual(result["exit_code"], 0)
        self.assertEqual(self.sandbox_image(), SLIM_IMAGE)
        self.assertEqual(env.base_image, SLIM_IMAGE)
        self.assertIn("couldn't build the sandbox image", result["output"])

    def test_custom_image_is_used_as_is(self):
        self.fake.tools_image_present = False
        make_env(self.fake, image="node:22-slim").execute("ls")
        self.assertEqual(self.sandbox_image(), "node:22-slim")
        self.assertNotIn("build", self.fake.verbs())


if __name__ == "__main__":
    unittest.main()
