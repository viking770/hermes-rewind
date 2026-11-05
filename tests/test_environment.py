import json
import subprocess
import unittest

from rewind import RewindProvider, registry, tools
from rewind.environment import RewindEnvironment, RewindError, _CWD_MARKER


class FakeDocker:
    """Records docker CLI calls and returns canned results."""

    def __init__(self):
        self.calls = []
        self.exec_output = "hello\n"
        self.exec_code = 0
        self.exec_cwd = "/workspace"
        self.fail = set()
        self.timeout_exec = False

    def __call__(self, argv, timeout=None):
        assert argv[0] == "docker"
        self.calls.append(list(argv))
        verb = argv[1]
        if verb in self.fail:
            return 1, f"{verb} exploded"
        if verb == "exec":
            if argv[-1] == "command -v bash":
                return 0, "/bin/bash\n"
            if self.timeout_exec:
                raise subprocess.TimeoutExpired(argv, timeout, output=b"partial")
            return self.exec_code, f"{self.exec_output}\n{_CWD_MARKER}{self.exec_cwd}\n"
        if verb == "diff":
            return 0, "C /workspace\nA /workspace/new.txt\n"
        return 0, ""

    def verbs(self):
        return [c[1] for c in self.calls]


def make_env(fake, **kw):
    return RewindEnvironment(task_id="Demo Task", runner=fake, **kw)


class EnvironmentTests(unittest.TestCase):
    def setUp(self):
        registry.clear()
        self.fake = FakeDocker()

    def test_lazy_start_and_read_only_command_skips_snapshot(self):
        env = make_env(self.fake)
        self.assertEqual(self.fake.calls, [])
        result = env.execute("ls")
        self.assertEqual(result, {"output": "hello\n", "exit_code": 0})
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

    def test_exit_code_and_timeout(self):
        env = make_env(self.fake)
        self.fake.exec_code = 3
        self.assertEqual(env.execute("ls")["exit_code"], 3)
        self.fake.timeout_exec = True
        result = env.execute("ls", timeout=5)
        self.assertEqual(result["exit_code"], 124)
        self.assertIn("partial", result["output"])
        self.assertIn("timed out after 5s", result["output"])

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


class ToolTests(unittest.TestCase):
    def setUp(self):
        registry.clear()
        self.fake = FakeDocker()

    def call(self, name, args=None, **kw):
        return json.loads(tools.HANDLERS[name](args or {}, **kw))

    def test_tools_without_sandbox_return_error(self):
        result = self.call("rewind_list")
        self.assertFalse(result["ok"])
        self.assertIn("terminal.backend rewind", result["error"])

    def test_tool_flow(self):
        env = make_env(self.fake)
        env.execute("rm -rf src")
        listed = self.call("rewind_list")
        self.assertTrue(listed["ok"])
        self.assertEqual(listed["snapshots"][0]["id"], "s1")
        snap = self.call("rewind_snapshot", {"label": "before refactor"})
        self.assertEqual(snap["snapshot"]["label"], "before refactor")
        restored = self.call("rewind_restore", {"snapshot_id": "s1"}, task_id="Demo Task")
        self.assertTrue(restored["ok"])
        self.assertEqual(restored["undo_with"], "s3")
        changes = self.call("rewind_changes")
        self.assertIn("A /workspace/new.txt", changes["changes"])
        bad = self.call("rewind_restore", {"snapshot_id": "nope"})
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
        self.assertEqual(env.base_image, "python:3.12-slim")
        self.assertIs(registry.get("t1"), env)


if __name__ == "__main__":
    unittest.main()
