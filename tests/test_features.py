"""Tests for 0.2.0: parking, cleanup, restore summaries, export, sizes,
irreversible commands, version checks and the /rewind command."""
import json
import os
import re
import tempfile
import time
import unittest
from pathlib import Path

from rewind import policy, registry, store as store_mod, tools, version
from rewind.environment import _LIST_FILES, SLIM_IMAGE, RewindEnvironment, RewindError
from rewind.store import Store

from .test_environment import FakeDocker

DEAD_PID = 999_999_99  # no such process


class FilesDocker(FakeDocker):
    """FakeDocker whose container and images report file listings.

    ``files[image]`` is the listing an image starts with; the container's
    listing is whatever image it was last started from (or ``live`` once set).
    """

    def __init__(self):
        super().__init__()
        self.files = {}
        self.live = None
        self.started_from = None
        self.du_kb = "4"
        self.ps_output = ""
        self.images_output = ""
        self.repo_tags = {}  # repository -> tags, for `docker images <repo>`

    @staticmethod
    def listing(names):
        return "".join(f"{n}\t1\t1700000000.0\n" for n in names)

    def __call__(self, argv, timeout=None):
        verb = argv[1]
        if verb == "run" and "--rm" not in argv:
            self.started_from = next(a for a in argv if a.startswith(("python:", "hermes-rewind/", "hermes-rewind-base:")))
            self.live = None
        if verb == "exec" and argv[-1] == _LIST_FILES:
            self.calls.append(list(argv))
            names = self.live if self.live is not None else self.files.get(self.started_from, [])
            return 0, self.listing(names)
        if verb == "run" and "--rm" in argv and argv[-1] == _LIST_FILES:
            self.calls.append(list(argv))
            image = argv[argv.index("sh") + 1]
            return 0, self.listing(self.files.get(image, []))
        if verb == "exec" and "du -sk" in argv[-1]:
            self.calls.append(list(argv))
            return (0, self.du_kb + "\n") if self.du_kb is not None else (1, "")
        if verb == "ps":
            self.calls.append(list(argv))
            return 0, self.ps_output
        if verb == "images" and len(argv) > 2 and argv[2].startswith("hermes-rewind/"):
            self.calls.append(list(argv))
            return 0, "".join(f"{argv[2]}:{tag}\n" for tag in self.repo_tags.get(argv[2], []))
        if verb == "images":
            self.calls.append(list(argv))
            return 0, "".join(line.split("\t")[-1] + "\n" for line in self.images_output.splitlines())
        if verb == "image" and argv[2] == "inspect" and "index .Config.Labels" in argv[4]:
            self.calls.append(list(argv))
            by_tag = {line.split("\t")[-1]: line.split("\t") for line in self.images_output.splitlines()}
            return 0, "".join(f"{by_tag[t][1]}\t{by_tag[t][2]}\t{t}\n" for t in argv[5:])
        return super().__call__(argv, timeout)


def make_env(fake, **kw):
    kw.setdefault("background", False)
    kw.setdefault("network", "none")
    kw.setdefault("task_id", "session:demo")
    kw.setdefault("image", SLIM_IMAGE)  # the default image's build step has tests of its own
    return RewindEnvironment(runner=fake, **kw)


class ParkingTests(unittest.TestCase):
    def setUp(self):
        registry.clear()
        self.fake = FilesDocker()
        self.dir = Path(tempfile.mkdtemp())
        self.store = Store(self.dir)

    def parked_env(self):
        env = make_env(self.fake, keep_hours=1, store=self.store)
        env.execute("mkdir demo")
        env.execute("rm -rf demo")
        return env

    def test_cleanup_parks_snapshots_instead_of_deleting(self):
        env = self.parked_env()
        snap_images = [s.image for s in env.snapshots]
        env.cleanup()
        rmi = [c for c in self.fake.calls if c[1] == "rmi"]
        self.assertFalse(any(img in call for call in rmi for img in snap_images))
        self.assertIn(["docker", "rm", "-f", env.container], self.fake.calls)
        record = self.store.load("session:demo")
        self.assertEqual(record["status"], "parked")
        self.assertEqual([s["id"] for s in record["snapshots"]], ["s1", "s2"])
        self.assertGreater(record["expires_at"], time.time() + 3000)
        self.assertIsNone(registry.get("session:demo"))

    def test_next_sandbox_resumes_parked_snapshots(self):
        env = self.parked_env()
        env.cleanup()
        record = self.store.load("session:demo")
        self.fake.image_info[record["image"]] = "100 3"
        again = make_env(self.fake, keep_hours=1, store=self.store)
        self.assertEqual(again.repository, env.repository)
        self.assertEqual([s.id for s in again.snapshots], ["s1", "s2"])
        result = again.execute("ls")
        self.assertIn("Resumed this session's sandbox", result["output"])
        self.assertEqual(self.fake.started_from, record["image"])
        self.assertEqual(again.find("last").id, "s2")
        self.assertNotIn("Resumed", again.execute("ls")["output"])  # said once
        # New snapshots continue the numbering instead of clashing.
        again.execute("rm x")
        self.assertEqual(again.snapshots[-1].id, "s4")

    def test_resume_skipped_when_images_are_gone(self):
        self.parked_env().cleanup()
        again = make_env(self.fake, keep_hours=1, store=self.store)  # image inspect fails
        self.assertEqual(again.snapshots, [])

    def test_keep_zero_deletes_everything(self):
        env = make_env(self.fake, keep_hours=0, store=self.store)
        env.execute("rm a")
        image = env.snapshots[0].image
        env.cleanup()
        self.assertIn(["docker", "rmi", "-f", image], self.fake.calls)
        self.assertEqual(env.snapshots, [])
        self.assertIsNone(self.store.load("session:demo"))

    def test_live_record_is_kept_current(self):
        env = self.parked_env()
        record = self.store.load("session:demo")
        self.assertEqual(record["status"], "live")
        self.assertEqual(record["owner_pid"], os.getpid())
        self.assertEqual(len(record["snapshots"]), 2)
        self.assertEqual(record["container"], env.container)

    def test_live_record_owned_by_another_process_is_not_adopted(self):
        self.parked_env()
        record = self.store.load("session:demo")
        record["owner_pid"] = os.getppid() or 1  # alive
        self.store.save(record)
        registry.clear()
        again = make_env(self.fake, keep_hours=1, store=self.store)
        self.assertEqual(again.snapshots, [])
        self.assertNotEqual(again.repository, record["repository"])

    def test_crashed_owner_is_recovered(self):
        env = self.parked_env()
        record = self.store.load("session:demo")
        record["owner_pid"] = DEAD_PID
        self.store.save(record)
        registry.clear()
        self.fake.image_info[f"{env.repository}:recovered"] = "100 3"
        again = make_env(self.fake, keep_hours=1, store=self.store)
        commit = [c for c in self.fake.calls if c[1] == "commit" and c[-1].endswith(":recovered")]
        self.assertEqual(commit[0][-2], env.container)
        self.assertEqual(again._image, f"{env.repository}:recovered")
        self.assertEqual(len(again.snapshots), 2)

    def test_parked_container_labels_name_owner(self):
        self.parked_env()
        run = next(c for c in self.fake.calls if c[1] == "run")
        self.assertIn(f"{store_mod.PID_LABEL}={os.getpid()}", run)
        self.assertIn(f"{store_mod.HOST_LABEL}={store_mod.hostname()}", run)


class ReapTests(unittest.TestCase):
    def setUp(self):
        registry.clear()
        self.fake = FilesDocker()
        self.store = Store(Path(tempfile.mkdtemp()))

    def reap(self, **kw):
        return store_mod.reap(self.store, self.fake, keep_seconds=3600, **kw)

    def test_expired_parked_record_is_deleted(self):
        self.store.save({"task_id": "t", "status": "parked", "repository": "hermes-rewind/t-1",
                         "image": "hermes-rewind/t-1:s3", "base_image": "python:3.12-slim",
                         "snapshots": [{"image": "hermes-rewind/t-1:s1"}], "expires_at": time.time() - 1})
        self.fake.repo_tags["hermes-rewind/t-1"] = ["s1", "s3", "s9"]  # s9: not in the record
        counts = self.reap()
        self.assertEqual(counts["expired"], 1)
        rmi = next(c for c in self.fake.calls if c[1] == "rmi")
        self.assertEqual(rmi[3:], ["hermes-rewind/t-1:s1", "hermes-rewind/t-1:s3", "hermes-rewind/t-1:s9"])
        self.assertIsNone(self.store.load("t"))

    def test_unexpired_record_is_kept(self):
        self.store.save({"task_id": "t", "status": "parked", "repository": "hermes-rewind/t-1",
                         "image": "hermes-rewind/t-1:s3", "expires_at": time.time() + 100})
        self.assertEqual(self.reap()["expired"], 0)
        self.assertIsNotNone(self.store.load("t"))

    def test_live_record_with_dead_owner_becomes_parked(self):
        self.store.save({"task_id": "t", "status": "live", "repository": "hermes-rewind/t-1",
                         "container": "hermes-rewind-t-1", "owner_pid": DEAD_PID, "host": store_mod.hostname(),
                         "image": "python:3.12-slim", "base_image": "python:3.12-slim"})
        self.assertEqual(self.reap()["recovered"], 1)
        record = self.store.load("t")
        self.assertEqual(record["status"], "parked")
        self.assertEqual(record["image"], "hermes-rewind/t-1:recovered")
        self.assertIn(["docker", "rm", "-f", "hermes-rewind-t-1"], self.fake.calls)

    def test_live_record_with_live_owner_is_left_alone(self):
        self.store.save({"task_id": "t", "status": "live", "repository": "hermes-rewind/t-1",
                         "container": "hermes-rewind-t-1", "owner_pid": os.getpid(), "host": store_mod.hostname()})
        self.assertFalse(any(self.reap().values()))

    def test_unrecorded_leftovers_of_dead_processes_are_deleted(self):
        host = store_mod.hostname()
        self.fake.ps_output = (
            f"dead1\t{DEAD_PID}\t{host}\thermes-rewind/x-1:s1\n"
            f"mine\t{os.getpid()}\t{host}\thermes-rewind/x-2:s1\n"
            f"other\t{DEAD_PID}\tsome-other-host\thermes-rewind/x-3:s1\n"
            f"legacy\t\t\thermes-rewind/x-4:s1\n"
        )
        self.fake.images_output = (
            f"i1\t{DEAD_PID}\t{host}\thermes-rewind/x-1:s1\n"
            f"i2\t{os.getpid()}\t{host}\thermes-rewind/x-2:s1\n"
            f"i3\t{DEAD_PID}\t{host}\thermes-rewind/live-1:s1\n"
        )
        counts = self.reap(live_repositories=["hermes-rewind/live-1"])
        self.assertEqual((counts["containers"], counts["images"]), (1, 1))
        self.assertIn(["docker", "rm", "-f", "dead1"], self.fake.calls)
        self.assertIn(["docker", "rmi", "-f", "hermes-rewind/x-1:s1"], self.fake.calls)

    def test_pid_alive(self):
        self.assertTrue(store_mod.pid_alive(os.getpid()))
        self.assertFalse(store_mod.pid_alive(DEAD_PID))
        self.assertTrue(store_mod.pid_alive(None))


class RestoreSummaryTests(unittest.TestCase):
    def setUp(self):
        registry.clear()
        self.fake = FilesDocker()

    def test_restore_reports_files_that_come_back(self):
        env = make_env(self.fake)
        env.execute("rm -rf demo")  # s1
        self.fake.files[f"{env.repository}:s1"] = ["demo/hello.txt", "keep.txt"]
        self.fake.live = ["keep.txt", "new.txt"]
        env.restore("last")
        changes = env.last_restore_changes
        self.assertEqual(changes["appear"], ["demo/hello.txt"])
        self.assertEqual(changes["disappear"], ["new.txt"])

    def test_preview_changes_nothing(self):
        env = make_env(self.fake)
        env.execute("rm -rf demo")
        self.fake.files[f"{env.repository}:s1"] = ["demo/hello.txt"]
        self.fake.live = []
        runs_before = len([c for c in self.fake.calls if c[1] == "run" and "--rm" not in c])
        target, changes = env.preview("last")
        self.assertEqual(target.id, "s1")
        self.assertEqual(changes["appear"], ["demo/hello.txt"])
        runs_after = len([c for c in self.fake.calls if c[1] == "run" and "--rm" not in c])
        self.assertEqual(runs_before, runs_after)
        self.assertNotIn("commit", [c[1] for c in self.fake.calls[-3:]])

    def test_summary_text(self):
        from rewind.environment import describe_changes
        text = describe_changes({"root": "/workspace", "appear": ["a"], "appear_count": 1,
                                 "disappear": [], "disappear_count": 0, "change": [], "change_count": 0})
        self.assertEqual(text, "Under /workspace: 1 file(s) come back (a).")
        self.assertIn("No files", describe_changes({"appear_count": 0}))
        self.assertIn("Couldn't", describe_changes(None))


class ExportAndSizeTests(unittest.TestCase):
    def setUp(self):
        registry.clear()
        self.fake = FilesDocker()

    def test_export_copies_into_a_new_folder(self):
        from .test_security import fake_tar_reader
        env = make_env(self.fake)
        seen = []
        env._tar_reader = fake_tar_reader(seen)
        dest_root = Path(tempfile.mkdtemp())
        first = env.export("app", dest_root)
        second = env.export("/workspace/app", dest_root)
        self.assertNotEqual(first.parent, second.parent)
        self.assertEqual(first.name, "app")
        self.assertEqual(seen[0][2], f"{env.container}:/workspace/app")
        self.assertTrue((first / "ok.txt").is_file())

    def test_export_refuses_missing_and_too_big(self):
        env = make_env(self.fake, export_max_mb=1)
        self.fake.du_kb = None
        with self.assertRaises(RewindError):
            env.export("nope", Path(tempfile.mkdtemp()))
        self.fake.du_kb = "4096"
        with self.assertRaisesRegex(RewindError, "export limit"):
            env.export("big", Path(tempfile.mkdtemp()))

    def test_snapshot_sizes(self):
        env = make_env(self.fake)
        env.execute("rm a")
        snap = env.snapshots[0]
        self.fake.image_info[snap.image] = "150000000 4"
        self.fake.image_info[snap.parent] = "100000000 3"
        listed = env.list_snapshots(sizes=True)
        self.assertEqual(listed[0]["size_mb"], 50.0)
        self.assertEqual(snap.parent, env.base_image)


class IrreversibleTests(unittest.TestCase):
    def test_flags_commands_that_leave_the_sandbox(self):
        for command in [
            "git push origin main", "cd app && git push", "npm publish", "docker push me/img",
            "curl -X POST https://x", "curl -d a=1 https://x", "curl --json '{}' https://x",
            "wget --post-data=a https://x", "gh pr create --fill", "gh api -X DELETE repos/a/b",
            "kubectl apply -f k.yaml", "terraform apply", "scp f host:/tmp", "ssh host ls",
            "aws s3 rm s3://b/k", "twine upload dist/*", "sudo git push",
        ]:
            self.assertIsNotNone(policy.irreversible_reason(command), command)

    def test_ignores_local_and_read_only_commands(self):
        for command in [
            "git status", "git commit -m x", "ls", "rm -rf build", "curl https://x",
            "curl -o out https://x", "gh pr view 3", "gh pr list", "kubectl get pods",
            "aws s3 ls", "scp a b", "npm install", "docker build .", "echo git push",
        ]:
            self.assertIsNone(policy.irreversible_reason(command), command)

    def test_execute_adds_a_note(self):
        registry.clear()
        env = make_env(FilesDocker(), network="internet")
        self.assertIn("rewind_restore cannot take that back", env.execute("git push")["output"])
        self.assertNotIn("[rewind] note", env.execute("ls")["output"])
        offline = make_env(FilesDocker(), network=False, task_id="offline")
        self.assertNotIn("[rewind] note", offline.execute("git push")["output"])

    def test_hook_asks_before_irreversible_commands(self):
        from rewind import settings
        settings.mark_backend_used()
        hook = tools.pre_tool_call
        result = hook(tool_name="terminal", args={"command": "git push origin main"}, task_id="t")
        self.assertEqual(result["action"], "approve")
        self.assertIn("can't undo", result["message"])
        self.assertEqual(result["rule_key"], "rewind-irreversible-git-push")
        self.assertIsNone(hook(tool_name="terminal", args={"command": "ls"}))
        self.assertIsNone(hook(tool_name="read_file", args={"command": "git push"}))
        os.environ["REWIND_CONFIRM_IRREVERSIBLE"] = "0"
        try:
            self.assertIsNone(hook(tool_name="terminal", args={"command": "git push"}))
        finally:
            del os.environ["REWIND_CONFIRM_IRREVERSIBLE"]


class VersionTests(unittest.TestCase):
    def test_manifest_matches_code(self):
        manifest = (Path(version.__file__).parent / "plugin.yaml").read_text(encoding="utf-8")
        self.assertEqual(version.disk_version(), version.VERSION)
        declared = re.findall(r"^  - (rewind_\w+)$", manifest, re.MULTILINE)
        self.assertEqual(sorted(declared), sorted(tools.SCHEMAS))

    def test_status_reports_stale_code(self):
        self.assertFalse(version.status()["stale"])
        saved = dict(version._LOADED)
        try:
            version._LOADED["tools.py"] = 1
            status = version.status()
            self.assertTrue(status["stale"])
            self.assertEqual(status["changed_files"], ["tools.py"])
            self.assertIn("hermes gateway restart", status["warning"])
        finally:
            version._LOADED.clear()
            version._LOADED.update(saved)

    def test_tool_results_carry_version_and_warning(self):
        registry.clear()
        make_env(FilesDocker()).execute("rm a")
        listed = json.loads(tools.HANDLERS["rewind_list"]({}, task_id="demo"))
        self.assertEqual(listed["plugin_version"], version.VERSION)
        self.assertNotIn("warning", listed)
        saved = dict(version._LOADED)
        try:
            version._LOADED["environment.py"] = 1
            listed = json.loads(tools.HANDLERS["rewind_list"]({}, task_id="demo"))
            self.assertIn("warning", listed)
        finally:
            version._LOADED.clear()
            version._LOADED.update(saved)


class UndoToolAndSlashTests(unittest.TestCase):
    def setUp(self):
        registry.clear()
        self.fake = FilesDocker()

    def test_rewind_undo_tool_is_repeat_safe(self):
        env = make_env(self.fake)
        env.execute("mkdir demo")
        env.execute("rm -rf demo")
        first = json.loads(tools.HANDLERS["rewind_undo"]({}, task_id="demo"))
        second = json.loads(tools.HANDLERS["rewind_undo"]({}, task_id="demo"))
        self.assertEqual(first["restored"]["id"], "s2")
        self.assertEqual(second["restored"]["id"], "s2")
        self.assertIn("files", first)

    def test_restore_preview_flag(self):
        env = make_env(self.fake)
        env.execute("rm -rf demo")
        self.fake.files[f"{env.repository}:s1"] = ["demo/hello.txt"]
        result = json.loads(tools.HANDLERS["rewind_restore"]({"snapshot_id": "last", "preview": True}, task_id="demo"))
        self.assertTrue(result["ok"])
        self.assertIn("Nothing was restored", result["message"])
        self.assertEqual(result["files"]["appear"], ["demo/hello.txt"])

    def test_export_tool(self):
        from .test_security import fake_tar_reader
        make_env(self.fake)._tar_reader = fake_tar_reader([])
        os.environ["REWIND_EXPORT_DIR"] = tempfile.mkdtemp()
        try:
            result = json.loads(tools.HANDLERS["rewind_export"]({"path": "app"}, task_id="demo"))
        finally:
            del os.environ["REWIND_EXPORT_DIR"]
        self.assertTrue(result["ok"], result)
        self.assertTrue(result["host_path"].endswith("app"))
        self.assertIn("app/trap", result["removed"])
        self.assertIn("symlink", result["message"])
        self.assertFalse(json.loads(tools.HANDLERS["rewind_export"]({}, task_id="demo"))["ok"])

    def test_slash_command(self):
        env = RewindEnvironment(task_id="session:chat-1", runner=self.fake, background=False)
        RewindEnvironment(task_id="session:chat-2", runner=FilesDocker(), background=False)
        self.assertIn("No snapshots yet", tools.slash_rewind("", session_key="chat-1"))
        env.execute("mkdir demo")
        env.execute("rm -rf demo")
        listing = tools.slash_rewind("list", session_key="chat-1")
        self.assertIn("state before running: rm -rf demo", listing)
        undo = tools.slash_rewind("undo", session_key="chat-1")
        self.assertIn("Rolled back to s2", undo)
        self.assertIn("/rewind restore s3", undo)
        self.assertIn("Rolled back to s2", tools.slash_rewind("undo", session_key="chat-1"))
        self.assertIn("Rolled back to s3", tools.slash_rewind("restore s3", session_key="chat-1"))
        self.assertIn("Usage", tools.slash_rewind("restore", session_key="chat-1"))
        self.assertIn("Unknown /rewind command", tools.slash_rewind("dance", session_key="chat-1"))
        self.assertIn("/rewind undo", tools.slash_rewind("help"))
        self.assertIn("Rewind 0.", tools.slash_rewind("status"))
        # No match: refuse rather than guess.
        self.assertIn("no Rewind sandbox", tools.slash_rewind("undo", session_key="chat-9"))

    def test_slash_command_from_a_messaging_platform(self):
        """Another person in a Telegram chat must not reach someone else's sandbox."""
        alice = RewindEnvironment(task_id="session:agent:main:telegram:dm:alice-chat-0001",
                                  runner=self.fake, background=False)
        alice.execute("rm -rf work")
        # Bob's chat: the only sandbox running is Alice's. Before 0.2.1 this undid her work.
        bob = dict(session_key="agent:main:telegram:dm:bob-chat-0002", session_id="bob-chat-0002",
                   platform="telegram")
        self.assertIn("no Rewind sandbox", tools.slash_rewind("undo", **bob))
        self.assertIn("no Rewind sandbox", tools.slash_rewind("list", **bob))
        self.assertEqual(len(alice.snapshots), 1)  # untouched
        # Alice in her own chat still can, but export (host disk) is local-only.
        mine = dict(session_key="agent:main:telegram:dm:alice-chat-0001", platform="telegram")
        self.assertIn("Rolled back", tools.slash_rewind("undo", **mine))
        self.assertIn("only works from a local chat", tools.slash_rewind("export work", **mine))
        self.assertNotIn("cp", self.fake.verbs())
        # status from a platform shows no other chats.
        Store(Path(os.environ["REWIND_STATE_DIR"])).save({"task_id": "someone-else", "status": "parked", "repository": "hermes-rewind/someone-1"})
        try:
            self.assertNotIn("someone-else", tools.slash_rewind("status", platform="telegram"))
            self.assertIn("someone-else", tools.slash_rewind("status", platform="local"))
        finally:
            Store(Path(os.environ["REWIND_STATE_DIR"])).delete("someone-else")

    def test_shared_sandbox_only_for_local_slash_commands(self):
        RewindEnvironment(task_id="default", runner=self.fake, background=False).execute("rm a")
        local = tools.slash_rewind("list", session_key="agent:main:local:dm:x", platform="local")
        self.assertIn("rm a", local)
        remote = tools.slash_rewind("list", session_key="agent:main:discord:dm:x", platform="discord")
        self.assertIn("no Rewind sandbox", remote)

    def test_slash_command_explains_a_paused_sandbox(self):
        store = Store(Path(os.environ["REWIND_STATE_DIR"]))
        env = RewindEnvironment(task_id="session:chat-p", runner=self.fake, background=False,
                                keep_hours=1, store=store)
        env.execute("rm -rf demo")
        env.cleanup()  # Hermes's idle shutdown
        text = tools.slash_rewind("undo", session_key="chat-p")
        self.assertIn("paused", text)
        self.assertIn("state before running: rm -rf demo", text)
        self.assertIn("Run any terminal command", text)
        store.delete("session:chat-p")

    def test_register_wires_optional_surfaces(self):
        got = {}

        class Ctx:
            def register_terminal_environment_provider(self, provider):
                got["provider"] = provider

            def register_tool(self, name, *a, **k):
                got.setdefault("tools", []).append(name)

            def register_command(self, name, handler, description="", args_hint=""):
                got["command"] = (name, handler)

            def register_hook(self, name, callback):
                got["hook"] = (name, callback)

            def register_system_prompt_section(self, id, content):
                got["prompt"] = (id, content)

            def register_cli_command(self, name, help, setup_fn, handler_fn=None, description=""):
                got["cli"] = name

        import rewind
        rewind.register(Ctx())
        self.assertEqual(sorted(got["tools"]), sorted(tools.SCHEMAS))
        self.assertEqual(got["command"][0], "rewind")
        self.assertEqual(got["hook"], ("pre_tool_call", tools.pre_tool_call))
        self.assertIn("rewind_undo", got["prompt"][1])
        self.assertEqual(got["cli"], "rewind")


if __name__ == "__main__":
    unittest.main()
