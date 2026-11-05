"""Tests for the 0.2.1 security fixes: container hardening (H1) and the
network guard (H2). Session isolation (H3) is tested with the tools."""
import unittest

from rewind import registry
from rewind.docker_api import ApiRunner, _bytes
from rewind.environment import (
    GUARD_IMAGE, RewindEnvironment, RewindError, _BLOCKED_V4, _guard_script,
)

from .test_environment import FakeDocker


def env_for(fake, **kw):
    kw.setdefault("background", False)
    return RewindEnvironment(task_id="sec", runner=fake, **kw)


def sandbox_run(fake):
    """The `docker run -d` that started the sandbox (not the guard helper)."""
    return [c for c in fake.calls if c[1] == "run" and "-d" in c][-1]


class HardeningTests(unittest.TestCase):
    def setUp(self):
        registry.clear()
        self.fake = FakeDocker()

    def test_sandbox_runs_with_capabilities_dropped_and_limits(self):
        env_for(self.fake).execute("ls")
        run = sandbox_run(self.fake)
        self.assertEqual(run[run.index("--cap-drop") + 1], "ALL")
        added = {run[i + 1] for i, a in enumerate(run) if a == "--cap-add"}
        self.assertEqual(added, {"CHOWN", "DAC_OVERRIDE", "FOWNER", "SETUID", "SETGID"})
        self.assertNotIn("NET_RAW", added)
        self.assertNotIn("NET_ADMIN", added)
        self.assertIn("no-new-privileges", run)
        self.assertEqual(run[run.index("--pids-limit") + 1], "2048")
        self.assertEqual(run[run.index("--cpus") + 1], "1")
        self.assertEqual(run[run.index("--memory") + 1], "5120m")
        self.assertNotIn("--privileged", run)

    def test_limits_follow_settings(self):
        env_for(self.fake, cpus=2.5, memory_mb=1024, pids_limit=None).execute("ls")
        run = sandbox_run(self.fake)
        self.assertEqual(run[run.index("--cpus") + 1], "2.5")
        self.assertEqual(run[run.index("--memory") + 1], "1024m")
        self.assertNotIn("--pids-limit", run)

    def test_docker_without_cgroup_limits_still_starts(self):
        class NoCgroups(FakeDocker):
            def __call__(self, argv, timeout=None):
                if argv[1] == "run" and "--memory" in argv:
                    self.calls.append(list(argv))
                    return 125, "Error: NanoCPUs can not be set, as your kernel does not support CPU CFS"
                return super().__call__(argv, timeout)

        fake = NoCgroups()
        result = env_for(fake, network="none").execute("ls")
        self.assertIn("can't apply CPU/memory/process limits", result["output"])
        run = sandbox_run(fake)
        self.assertNotIn("--memory", run)
        self.assertEqual(run[run.index("--cap-drop") + 1], "ALL")  # hardening kept

    def test_image_that_looks_like_an_option_is_refused(self):
        env = env_for(self.fake, network="none")
        env._image = "--privileged"
        with self.assertRaises(RewindError):
            env._ensure_started()
        self.assertFalse([c for c in self.fake.calls if c[1] == "run"])

    def test_api_runner_translates_hardening_flags(self):
        api = ApiRunner("docker", lambda a, t: (0, ""), endpoint="npipe:////./pipe/x")
        captured = {}
        api._run = lambda name, config, t: captured.update(config) or (0, "id\n")
        argv = ["run", "-d", "--name", "c", "--label", "a=1", "--cap-drop", "ALL", "--cap-add", "CHOWN",
                "--security-opt", "no-new-privileges", "--pids-limit", "2048", "--cpus", "1.5",
                "--memory", "512m", "--entrypoint", "/bin/sh", "img", "-c", "x"]
        api._parse_run(argv[1:])(10)
        host = captured["HostConfig"]
        self.assertEqual(host["CapDrop"], ["ALL"])
        self.assertEqual(host["CapAdd"], ["CHOWN"])
        self.assertEqual(host["SecurityOpt"], ["no-new-privileges"])
        self.assertEqual(host["PidsLimit"], 2048)
        self.assertEqual(host["NanoCpus"], 1_500_000_000)
        self.assertEqual(host["Memory"], 512 * 1024 ** 2)
        self.assertEqual(_bytes("4g"), 4 * 1024 ** 3)
        self.assertIsNone(_bytes("lots"))


class NetworkGuardTests(unittest.TestCase):
    def setUp(self):
        registry.clear()
        self.fake = FakeDocker()

    def test_internet_mode_installs_the_guard_before_any_command(self):
        env_for(self.fake).execute("ls")
        verbs = [(c[1], c[2] if len(c) > 2 else "") for c in self.fake.calls]
        guard = next(i for i, c in enumerate(self.fake.calls) if c[1] == "run" and GUARD_IMAGE in c)
        first_command = next(i for i, c in enumerate(self.fake.calls) if c[1] == "exec" and "cd " in c[-1])
        self.assertLess(guard, first_command, verbs)
        helper = self.fake.calls[guard]
        sandbox = sandbox_run(self.fake)
        self.assertIn("container:" + sandbox[sandbox.index("--name") + 1], helper)
        self.assertEqual(helper[helper.index("--cap-add") + 1], "NET_ADMIN")
        self.assertNotIn("--network", sandbox_run(self.fake))  # bridge, but guarded

    def test_guard_failure_falls_back_to_no_network(self):
        self.fake.guard_fails = True
        result = env_for(self.fake).execute("ls")
        self.assertIn("couldn't firewall", result["output"])
        run = sandbox_run(self.fake)
        self.assertEqual(run[run.index("--network") + 1], "none")

    def test_guard_image_is_built_once_when_missing(self):
        self.fake.guard_image_present = False
        env_for(self.fake).execute("ls")
        builds = [c for c in self.fake.calls if c[1] == "build"]
        self.assertEqual(len(builds), 1)
        self.assertIn(GUARD_IMAGE, builds[0])

    def test_guard_runs_after_every_restart(self):
        env = env_for(self.fake)
        env.execute("rm a")
        env.restore("last")
        self.assertEqual(len([c for c in self.fake.calls if GUARD_IMAGE in c and c[1] == "run"]), 2)

    def test_none_and_full_modes_skip_the_guard(self):
        env_for(self.fake, network="none").execute("ls")
        self.assertEqual(sandbox_run(self.fake)[sandbox_run(self.fake).index("--network") + 1], "none")
        registry.clear()
        full = FakeDocker()
        env_for(full, network="full").execute("ls")
        self.assertFalse([c for c in self.fake.calls + full.calls if GUARD_IMAGE in c and c[1] == "run"])
        self.assertNotIn("--network", sandbox_run(full))

    def test_old_boolean_setting_still_works(self):
        self.assertEqual(env_for(self.fake, network=True).network_mode, "internet")
        registry.clear()
        self.assertEqual(env_for(FakeDocker(), network=False).network_mode, "none")
        with self.assertRaises(ValueError):
            env_for(FakeDocker(), network="sometimes")

    def test_guard_script_blocks_host_lan_and_metadata_but_allows_dns(self):
        script = _guard_script(["192.168.65.7", "fd00::1"])
        for net in ("192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12", "169.254.0.0/16", "127.0.0.0/8"):
            self.assertIn(f"-d {net} -j REJECT", script)
        self.assertEqual(len([n for n in _BLOCKED_V4 if f"-d {n} -j REJECT" in script]), len(_BLOCKED_V4))
        # DNS to the sandbox's own resolver is allowed, and only on port 53, before the rejects.
        allow = script.index("-d 192.168.65.7 -p udp --dport 53 -j ACCEPT")
        self.assertLess(allow, script.index("-d 192.168.0.0/16 -j REJECT"))
        self.assertIn("ip6tables -A OUTPUT -d fc00::/7 -j REJECT", script)
        self.assertIn("REWIND_GUARD_OK", script)


if __name__ == "__main__":
    unittest.main()
