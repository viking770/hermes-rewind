"""End-to-end test against a real Docker daemon.

Skipped unless Docker is installed and REWIND_INTEGRATION=1:
    REWIND_INTEGRATION=1 python3 -m unittest tests.test_docker_integration -v
"""
import os
import shutil
import tempfile
import unittest
from pathlib import Path

from rewind import registry
from rewind.environment import RewindEnvironment
from rewind.store import Store


@unittest.skipUnless(
    shutil.which("docker") and os.environ.get("REWIND_INTEGRATION") == "1",
    "needs Docker and REWIND_INTEGRATION=1",
)
class DockerIntegrationTest(unittest.TestCase):
    def setUp(self):
        registry.clear()
        self.env = RewindEnvironment(task_id="integration", timeout=120,
                                     image=os.environ.get("REWIND_IMAGE", "python:3.12-slim"))
        self.addCleanup(self.env.cleanup)

    def test_undo_a_destructive_command(self):
        env = self.env
        r = env.execute("mkdir -p app && cd app && echo important > data.txt")
        self.assertEqual(r["exit_code"], 0, r["output"])
        self.assertEqual(env.cwd, "/workspace/app")

        r = env.execute("rm -rf /workspace/app/data.txt")
        self.assertEqual(r["exit_code"], 0, r["output"])
        self.assertNotEqual(env.execute("cat data.txt")["exit_code"], 0)

        before_rm = env.snapshots[-1]
        self.assertEqual(before_rm.command, "rm -rf /workspace/app/data.txt")
        target, changes = env.preview(before_rm.id)
        self.assertEqual(changes["appear"], ["app/data.txt"])
        env.restore(before_rm.id)
        self.assertEqual(env.last_restore_changes["appear"], ["app/data.txt"])
        r = env.execute("cat data.txt")
        self.assertEqual(r["output"].strip(), "important")
        self.assertIsInstance(env.changes(), list)
        self.assertIsNotNone(env.list_snapshots(sizes=True)[0]["size_mb"])

        exported = env.export("/workspace/app", Path(tempfile.mkdtemp()))
        self.assertEqual((exported / "data.txt").read_text().strip(), "important")

    def test_snapshots_survive_cleanup_and_resume(self):
        store = Store(Path(tempfile.mkdtemp()))
        image = os.environ.get("REWIND_IMAGE", "python:3.12-slim")
        first = RewindEnvironment(task_id="integration-park", timeout=120, image=image,
                                  keep_hours=1, store=store)
        try:
            first.execute("echo kept > /workspace/kept.txt")
            first.execute("rm /workspace/kept.txt")
            first.cleanup()  # what Hermes's idle reaper does
            self.assertEqual(store.load("integration-park")["status"], "parked")

            second = RewindEnvironment(task_id="integration-park", timeout=120, image=image,
                                       keep_hours=1, store=store)
            self.addCleanup(second._delete_everything)
            r = second.execute("ls /workspace")
            self.assertIn("Resumed", r["output"])
            self.assertNotIn("kept.txt", r["output"])  # resumed the state it was parked in
            second.undo()
            self.assertEqual(second.execute("cat /workspace/kept.txt")["output"].strip(), "kept")
        finally:
            first._delete_everything()


if __name__ == "__main__":
    unittest.main()
