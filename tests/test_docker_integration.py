"""End-to-end test against a real Docker daemon.

Skipped unless Docker is installed and REWIND_INTEGRATION=1:
    REWIND_INTEGRATION=1 python3 -m unittest tests.test_docker_integration -v
"""
import os
import shutil
import unittest

from rewind import registry
from rewind.environment import RewindEnvironment


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
        env.restore(before_rm.id)
        r = env.execute("cat data.txt")
        self.assertEqual(r["output"].strip(), "important")
        self.assertIsInstance(env.changes(), list)


if __name__ == "__main__":
    unittest.main()
