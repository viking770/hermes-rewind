"""Tests for the 0.2.1 security fixes: container hardening (H1) and the
network guard (H2). Session isolation (H3) is tested with the tools."""
import contextlib
import io
import json
import os
import stat
import tarfile
import tempfile
import time
import unittest
from pathlib import Path

from rewind import audit, policy, registry, store as store_mod, tools
from rewind.docker_api import ApiRunner, _bytes
from rewind.redact import MASK, redact
from rewind.store import Store
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

    def test_guard_script_blocks_this_computers_own_addresses(self):
        # A VPS's public address isn't in any private range.
        script = _guard_script(["8.8.8.8"], ["203.0.113.7", "2001:db8::7", "127.0.0.1", "not-an-ip; rm -rf /"])
        self.assertIn("iptables -A OUTPUT -d 203.0.113.7/32 -j REJECT", script)
        self.assertIn("ip6tables -A OUTPUT -d 2001:db8::7/128 -j REJECT", script)
        self.assertNotIn("127.0.0.1/32", script)
        self.assertNotIn("rm -rf", script)
        # DNS still comes first, even when the resolver is one of the host's addresses.
        self.assertLess(script.index("-d 8.8.8.8 -p udp --dport 53 -j ACCEPT"),
                        script.index("-d 203.0.113.7/32 -j REJECT"))

    def test_guard_script_blocks_nat64_and_6to4(self):
        script = _guard_script([])
        for net in ("64:ff9b::/96", "64:ff9b:1::/48", "2002::/16"):
            self.assertIn(f"ip6tables -A OUTPUT -d {net} -j REJECT", script)

    def test_guard_script_fails_closed_when_ipv6_is_on_but_unfilterable(self):
        script = _guard_script([])
        self.assertIn("/proc/net/if_inet6", script)
        fail = script.index("cannot filter it'; exit 1")
        self.assertLess(fail, script.index("echo REWIND_GUARD_OK"))
        # Each IPv6 rule is its own line, so `set -e` catches any that fails.
        self.assertNotIn("&& ip6tables", script)

    def test_host_addresses_never_stall_a_sandbox_start(self):
        # macOS can take ~30 s to resolve its own hostname; the guard runs on every start.
        from unittest import mock
        from rewind import environment
        saved = environment._host_cache
        environment._host_cache = (0.0, [])
        calls = []

        def slow_lookup(*args, **kwargs):
            calls.append(1)
            time.sleep(5)
            return [(None, None, None, None, ("203.0.113.50", 0))]

        try:
            with mock.patch.object(environment, "_HOSTNAME_LOOKUP_SECONDS", 0.2), \
                    mock.patch.object(environment.socket, "getaddrinfo", slow_lookup):
                started = time.monotonic()
                first = environment.host_addresses()
                self.assertLess(time.monotonic() - started, 2)
                self.assertNotIn("203.0.113.50", first)  # gave up on the slow lookup
                started = time.monotonic()
                self.assertEqual(environment.host_addresses(), first)  # cached
                self.assertLess(time.monotonic() - started, 0.1)
                self.assertEqual(len(calls), 1)
        finally:
            environment._host_cache = saved

    def test_default_gateway_is_read_from_the_route_table(self):
        from rewind.environment import _default_gateways
        table = ("Iface\tDestination\tGateway \tFlags\n"
                 "eth0\t00000000\t010011AC\t0003\n"     # default via 172.17.0.1
                 "eth0\t000011AC\t00000000\t0001\n")    # on-link route
        self.assertEqual(_default_gateways(table), ["172.17.0.1"])

    def test_guard_receives_gateway_and_host_addresses(self):
        env = env_for(self.fake, network="internet")
        env._host_addresses = lambda: ["198.51.100.9"]
        env.execute("ls")
        guard = [c for c in self.fake.calls if c[1] == "run" and GUARD_IMAGE in c][-1]
        self.assertIn("-d 198.51.100.9/32 -j REJECT", guard[-1])


class ExportSafetyTests(unittest.TestCase):
    """M1: the agent can't quietly write to this computer."""

    def setUp(self):
        registry.clear()
        self.fake = FakeDocker()

    def test_hook_asks_before_the_agent_exports(self):
        result = tools.pre_tool_call(tool_name="rewind_export", args={"path": "/workspace/app"})
        self.assertEqual(result["action"], "approve")
        self.assertIn("/workspace/app", result["message"])
        self.assertIn("this computer", result["message"])
        self.assertEqual(result["rule_key"], "rewind-export")
        # Also when the call comes through Hermes's tool-search bridge.
        bridged = tools.pre_tool_call(tool_name="tool_call",
                                      args={"name": "rewind_export", "arguments": {"path": "x"}})
        self.assertEqual(bridged["action"], "approve")
        os.environ["REWIND_CONFIRM_EXPORT"] = "0"
        try:
            self.assertIsNone(tools.pre_tool_call(tool_name="rewind_export", args={"path": "x"}))
        finally:
            del os.environ["REWIND_CONFIRM_EXPORT"]

    def test_export_tool_refused_on_messaging_platforms(self):
        env_for(self.fake, network="none")

        class Ctx:
            def session_surface(self):
                return "telegram"

        saved, tools._CTX = tools._CTX, Ctx()
        try:
            result = json.loads(tools.HANDLERS["rewind_export"]({"path": "app"}, task_id="sec"))
        finally:
            tools._CTX = saved
        self.assertFalse(result["ok"])
        self.assertIn("only available in local chats", result["error"])
        self.assertNotIn("cp", self.fake.verbs())

    def test_export_total_cap(self):
        dest = Path(tempfile.mkdtemp())
        (dest / "old.bin").write_bytes(b"x" * 3 * 1024 * 1024)  # 3 MB already exported
        env = env_for(self.fake, network="none", export_total_mb=4)

        class Du(FakeDocker):
            def __call__(self, argv, timeout=None):
                if argv[1] == "exec" and "du -sk" in argv[-1]:
                    self.calls.append(list(argv))
                    return 0, "2048\n"  # 2 MB more would pass the 4 MB cap
                return super().__call__(argv, timeout)

        env._run = Du()
        with self.assertRaisesRegex(RewindError, "REWIND_EXPORT_TOTAL_MB"):
            env.export("big", dest)

    def test_only_plain_files_come_out_of_a_hostile_archive(self):
        from rewind.environment import _extract_plain
        archive = hostile_tar()
        dest = Path(tempfile.mkdtemp())
        outside = dest.parent / f"{dest.name}-outside"
        removed = _extract_plain(archive, dest)
        self.assertEqual((dest / "app" / "ok.txt").read_text(), "fine")
        self.assertEqual((dest / "app" / ".env").read_text(), "dotfile kept")  # leading dot survives
        self.assertTrue((dest / "app" / "sub").is_dir())
        for name in ("app/trap", "app/hard", "app/fifo", "app/dev", "../escape.txt", "abs/evil.txt"):
            self.assertIn(name, removed)
        self.assertFalse((dest / "app" / "trap").exists())
        self.assertFalse((dest.parent / "escape.txt").exists())
        self.assertFalse(outside.exists())
        mode = stat.S_IMODE(os.stat(dest / "app" / "setuid").st_mode)
        self.assertFalse(mode & (stat.S_ISUID | stat.S_ISGID))

    def test_extraction_never_overwrites_and_respects_the_cap(self):
        from rewind.environment import _extract_plain
        dest = Path(tempfile.mkdtemp())
        _extract_plain(hostile_tar(), dest)
        self.assertIn("app/ok.txt", _extract_plain(hostile_tar(), dest))  # exists already: skipped
        with self.assertRaisesRegex(RewindError, "limit"):
            _extract_plain(hostile_tar(big=2 * 1024 * 1024), Path(tempfile.mkdtemp()), max_mb=1)

    def test_export_streams_through_the_safe_extractor(self):
        env = env_for(self.fake, network="none")
        seen = []
        env._tar_reader = fake_tar_reader(seen)
        dest_root = Path(tempfile.mkdtemp())
        copied = env.export("app", dest_root)
        self.assertEqual(seen[0][1:], ["cp", f"{env.container}:/workspace/app", "-"])
        self.assertEqual((copied / "ok.txt").read_text(), "fine")
        self.assertIn("app/trap", env.last_export_removed)


def hostile_tar(big: int = 0) -> io.BytesIO:
    """A tar with plain files plus everything an export must not create."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        def add(name, kind=tarfile.REGTYPE, data=b"", **kw):
            info = tarfile.TarInfo(name)
            info.type = kind
            info.size = len(data)
            for key, value in kw.items():
                setattr(info, key, value)
            tar.addfile(info, io.BytesIO(data) if data else None)

        add("app", tarfile.DIRTYPE)
        add("app/ok.txt", data=b"fine")
        add("app/.env", data=b"dotfile kept")
        add("app/sub", tarfile.DIRTYPE)
        add("app/setuid", data=b"x", mode=0o4755)
        add("app/trap", tarfile.SYMTYPE, linkname="/etc/passwd")
        add("app/hard", tarfile.LNKTYPE, linkname="app/ok.txt")
        add("app/fifo", tarfile.FIFOTYPE)
        add("app/dev", tarfile.CHRTYPE)
        add("../escape.txt", data=b"escaped")
        add("/abs/evil.txt", data=b"absolute")
        if big:
            add("app/big.bin", data=b"x" * big)
    buf.seek(0)
    return buf


def fake_tar_reader(seen):
    @contextlib.contextmanager
    def reader(argv):
        seen.append(list(argv))
        yield hostile_tar()
    return reader


class SecretRetentionTests(unittest.TestCase):
    """M2: secrets in commands don't end up in records, and history can be deleted."""

    def test_redaction(self):
        cases = {
            'curl -H "Authorization: Bearer abc.def.ghi" https://x': "abc.def.ghi",
            "git clone https://alice:hunter2@github.com/a/b": "hunter2",
            "curl -u bob:s3cret https://x": "s3cret",
            "GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz0123 gh pr list": "ghp_abcdefghijklmnopqrstuvwxyz0123",
            "export OPENAI_API_KEY='sk-proj-abcdefghijklmnopqrstuvwx'": "sk-proj-abcdefghijklmnopqrstuvwx",
            "aws configure set aws_secret_access_key x AKIAABCDEFGHIJKLMNOP": "AKIAABCDEFGHIJKLMNOP",
            "psql --password hunter2 db": "hunter2",
            "mysql -u root -pHunter2 db": "Hunter2",
            "npm config set //registry/:_authToken=npm_abcdefghijklmnopqrstuvwxyz0123456789": "npm_abcdefghij",
        }
        for command, secret in cases.items():
            cleaned = redact(command)
            self.assertNotIn(secret, cleaned, command)
            self.assertIn(MASK, cleaned, command)
        for safe in ("ls -la", "git push origin main", "pip install requests", "echo password reset done"):
            self.assertEqual(redact(safe), safe)

    def test_snapshot_records_keep_the_redacted_command(self):
        registry.clear()
        store = Store(Path(tempfile.mkdtemp()))
        env = env_for(FakeDocker(), network="none", keep_hours=1, store=store)
        env.execute("git clone https://alice:hunter2@github.com/a/b")
        self.assertNotIn("hunter2", env.snapshots[0].command)
        self.assertNotIn("hunter2", json.dumps(env.list_snapshots()))
        self.assertNotIn("hunter2", store.path("sec").read_text(encoding="utf-8"))

    @unittest.skipIf(os.name == "nt", "POSIX permissions")
    def test_records_are_owner_only(self):
        store = Store(Path(tempfile.mkdtemp()))
        store.save({"task_id": "t", "status": "parked"})
        self.assertEqual(stat.S_IMODE(os.stat(store.path("t")).st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(os.stat(store.dir).st_mode), 0o700)

    def test_forget_deletes_this_chats_snapshots(self):
        registry.clear()
        fake = FakeDocker()
        env = RewindEnvironment(task_id="session:chat-f", runner=fake, background=False, network="none")
        env.execute("rm a")
        env.execute("rm b")
        images = [s.image for s in env.snapshots]
        ask = tools.slash_rewind("forget", session_key="chat-f")
        self.assertIn("Run /rewind forget yes", ask)
        self.assertEqual(len(env.snapshots), 2)  # nothing deleted without "yes"
        done = tools.slash_rewind("forget yes", session_key="chat-f")
        self.assertIn("Deleted 2 snapshot(s)", done)
        self.assertEqual(env.snapshots, [])
        rmi = [c for c in fake.calls if c[1] == "rmi"][-1]
        self.assertEqual(sorted(rmi[3:]), sorted(images))
        env.execute("rm c")  # snapshots continue
        self.assertEqual(len(env.snapshots), 1)

    def test_purge_deletes_parked_but_not_live(self):
        store = Store(Path(tempfile.mkdtemp()))
        store.save({"task_id": "parked", "status": "parked", "repository": "hermes-rewind/p-1",
                    "image": "hermes-rewind/p-1:s2", "snapshots": [{"image": "hermes-rewind/p-1:s1"}]})
        store.save({"task_id": "live", "status": "live", "repository": "hermes-rewind/l-1",
                    "owner_pid": os.getpid(), "host": store_mod.hostname(), "container": "hermes-rewind-l-1"})
        fake = FakeDocker()
        counts = store_mod.purge(store, fake)
        self.assertEqual(counts, {"purged": 1, "skipped_live": 1})
        self.assertIsNone(store.load("parked"))
        self.assertIsNotNone(store.load("live"))
        rmi = next(c for c in fake.calls if c[1] == "rmi")
        self.assertIn("hermes-rewind/p-1:s1", rmi)
        self.assertNotIn("rm", [c[1] for c in fake.calls if "hermes-rewind-l-1" in c])


class RecordValidationTests(unittest.TestCase):
    """L1: a tampered record can't steer docker at anything that isn't Rewind's."""

    GOOD = {"task_id": "t", "status": "parked", "repository": "hermes-rewind/t-1",
            "container": "hermes-rewind-t-1", "base_image": "python:3.12-slim",
            "image": "hermes-rewind/t-1:s3", "snapshots": [{"id": "s1", "image": "hermes-rewind/t-1:s1"}],
            "dropped_images": ["hermes-rewind/t-1:s2"], "owner_pid": None, "seq": 3, "cwd": "/workspace",
            "expires_at": 1.0}

    def test_rewinds_own_records_pass(self):
        self.assertTrue(store_mod.is_valid_record(dict(self.GOOD)))

    def test_tampered_records_are_rejected(self):
        bad = {
            "foreign container": {"container": "my-database"},
            "foreign image": {"image": "evil/backdoor:latest"},
            "option as image": {"image": "--privileged"},
            "other repository's snapshot": {"snapshots": [{"image": "hermes-rewind/other-1:s1"}]},
            "foreign dropped image": {"dropped_images": ["postgres:16"]},
            "foreign repository": {"repository": "library/python"},
            "option as base image": {"base_image": "--privileged"},
            "pid not a number": {"owner_pid": "1; rm -rf /"},
            "relative cwd": {"cwd": "workspace"},
            "unknown status": {"status": "owned"},
            "snapshots not a list": {"snapshots": "hermes-rewind/t-1:s1"},
        }
        for name, change in bad.items():
            self.assertFalse(store_mod.is_valid_record({**self.GOOD, **change}), name)

    def test_store_ignores_invalid_records_entirely(self):
        store = Store(Path(tempfile.mkdtemp()))
        store.save({**self.GOOD, "container": "my-database", "status": "live", "owner_pid": 99999999})
        self.assertIsNone(store.load("t"))
        self.assertEqual(list(store.records()), [])
        fake = FakeDocker()
        store_mod.reap(store, fake, keep_seconds=3600)
        store_mod.purge(store, fake)
        self.assertFalse([c for c in fake.calls if "my-database" in c])


class SizeCapTests(unittest.TestCase):
    """L4: parked snapshots can't grow without bound."""

    def test_oldest_parked_sandboxes_go_first_until_under_the_cap(self):
        store = Store(Path(tempfile.mkdtemp()))
        base = "python:3.12-slim"
        for i, age in enumerate((300, 200, 100)):  # parked 300 s, 200 s, 100 s ago
            store.save({"task_id": f"t{i}", "status": "parked", "repository": f"hermes-rewind/t-{i}",
                        "base_image": base, "image": f"hermes-rewind/t-{i}:s2",
                        "snapshots": [{"id": "s1", "image": f"hermes-rewind/t-{i}:s1", "parent": base}],
                        "parked_at": time.time() - age, "expires_at": time.time() + 3600})
        store.save({"task_id": "busy", "status": "live", "repository": "hermes-rewind/busy-1",
                    "owner_pid": os.getpid(), "host": store_mod.hostname(), "base_image": base})

        class Sizes(FakeDocker):
            # Every snapshot and parked state adds 1 GB on top of a 0.1 GB base.
            def __call__(self, argv, timeout=None):
                if argv[1:4] == ["image", "inspect", "-f"] and argv[4] == "{{.Size}}":
                    self.calls.append(list(argv))
                    return 0, "".join(("100000000" if a == base else str(1024 ** 3 + 100000000)) + "\n"
                                      for a in argv[5:])
                return super().__call__(argv, timeout)

        fake = Sizes()
        counts = store_mod.reap(store, fake, keep_seconds=3600, max_parked_bytes=int(2.5 * 1024 ** 3))
        # Each parked sandbox uses ~2 GB (two images); 6 GB > 2.5 GB, so the two oldest go.
        self.assertEqual(counts["over_size_cap"], 2)
        self.assertIsNone(store.load("t0"))
        self.assertIsNone(store.load("t1"))
        self.assertIsNotNone(store.load("t2"))
        self.assertIsNotNone(store.load("busy"))  # live: never evicted

    def test_no_cap_means_nothing_is_evicted(self):
        store = Store(Path(tempfile.mkdtemp()))
        store.save({"task_id": "t", "status": "parked", "repository": "hermes-rewind/t-1",
                    "image": "hermes-rewind/t-1:s1", "expires_at": time.time() + 3600})
        self.assertEqual(store_mod.reap(store, FakeDocker(), keep_seconds=3600)["over_size_cap"], 0)
        self.assertIsNotNone(store.load("t"))


class AuditLogTests(unittest.TestCase):
    """L3: a person can see afterwards what happened."""

    def setUp(self):
        registry.clear()
        self.log = audit.path()
        for f in (self.log, self.log.with_name("audit.log.1")):
            if f.exists():
                f.unlink()

    def events(self):
        return list(audit.tail(200))

    def test_restores_exports_forget_and_approvals_are_logged(self):
        fake = FakeDocker()
        env = RewindEnvironment(task_id="session:chat-a", runner=fake, background=False, network="none")
        env.execute("rm a")
        tools.slash_rewind("undo", session_key="chat-a", platform="local")
        json.loads(tools.HANDLERS["rewind_undo"]({}, task_id="chat-a"))
        env._tar_reader = fake_tar_reader([])
        os.environ["REWIND_EXPORT_DIR"] = tempfile.mkdtemp()
        try:
            tools.HANDLERS["rewind_export"]({"path": "app"}, task_id="chat-a")
        finally:
            del os.environ["REWIND_EXPORT_DIR"]
        tools.slash_rewind("forget yes", session_key="chat-a")
        tools.pre_tool_call(tool_name="terminal", args={"command": "TOKEN=ghp_abcdefghijklmnopqrstuvwxyz0123 git push"})
        events = self.events()
        kinds = [(e["event"], e["via"]) for e in events]
        for expected in [("undo", "/rewind"), ("undo", "agent"), ("export", "agent"), ("forget", "/rewind"),
                         ("approval_requested", "agent")]:
            self.assertIn(expected, kinds)
        undo = next(e for e in events if e["event"] == "undo")
        self.assertEqual(undo["task_id"], "session:chat-a")
        self.assertEqual(undo["snapshot"], "s1")
        export = next(e for e in events if e["event"] == "export")
        self.assertIn("app/trap", export["skipped_paths"])
        self.assertNotIn("ghp_abcdef", self.log.read_text(encoding="utf-8"))  # redacted

    def test_refused_export_is_logged(self):
        tools.slash_rewind("export x", session_key="k", platform="telegram")
        self.assertEqual(self.events()[-1]["event"], "export_refused")

    def test_rotation_and_off_switch(self):
        saved = audit.MAX_BYTES
        audit.MAX_BYTES = 400
        try:
            for i in range(20):
                audit.log("test", n=i)
        finally:
            audit.MAX_BYTES = saved
        self.assertTrue(self.log.with_name("audit.log.1").exists())
        self.assertLessEqual(self.log.stat().st_size, 400)
        self.assertEqual(self.events()[-1]["n"], 19)
        os.environ["REWIND_AUDIT"] = "0"
        try:
            audit.log("hidden")
        finally:
            del os.environ["REWIND_AUDIT"]
        self.assertNotEqual(self.events()[-1]["event"], "hidden")

    def test_describe_is_one_readable_line(self):
        line = audit.describe({"time": "2026-11-06T01:00:00", "event": "undo", "via": "/rewind",
                               "task_id": "session:x", "snapshot": "s2"})
        self.assertIn("undo", line)
        self.assertIn("snapshot=s2", line)
        self.assertNotIn("\n", line)


class WrappedCommandTests(unittest.TestCase):
    """M3: the obvious ways around the "can't undo" prompt are caught."""

    def test_wrapped_and_scripted_writes_are_caught(self):
        for command in [
            "bash -c 'git push origin main'", "sh -c \"cd app && git push\"", "eval git push",
            "git -C repo push", "git -c user.name=x push", "timeout 30 git push", "xargs -n1 git push",
            "nice -n 5 npm publish", "python3 -c \"import requests; requests.post('https://x', data=d)\"",
            "node -e \"fetch('https://x', {method: 'POST', body: b})\"",
            "python3 - <<'EOF'\nimport httpx\nhttpx.put('https://x')\nEOF",
            "python3 -c 'import smtplib; smtplib.SMTP(\"mail\")'",
        ]:
            self.assertIsNotNone(policy.irreversible_reason(command), command)

    def test_reads_stay_unflagged(self):
        for command in [
            "bash -c 'ls -la'", "git -C repo status", "timeout 5 curl https://x",
            "python3 -c \"import requests; print(requests.get('https://x').status_code)\"",
            "xargs -n1 echo", "eval echo hi",
        ]:
            self.assertIsNone(policy.irreversible_reason(command), command)

    def test_approval_is_per_action_not_per_program(self):
        from rewind.tools import _rule_key
        self.assertEqual(_rule_key(policy.irreversible_reason("git push")), "rewind-irreversible-git-push")
        self.assertEqual(_rule_key(policy.irreversible_reason("git send-email x")),
                         "rewind-irreversible-git-send-email")
        self.assertEqual(_rule_key(policy.irreversible_reason("npm publish")), "rewind-irreversible-npm-publish")
        self.assertNotEqual(_rule_key(policy.irreversible_reason("docker push a")),
                            _rule_key(policy.irreversible_reason("docker login")))


if __name__ == "__main__":
    unittest.main()
