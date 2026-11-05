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

    def test_hardened_and_firewalled(self):
        """H1 and H2 on a real daemon: no host or LAN access, internet and
        package installs still work, capabilities dropped, limits applied."""
        env = self.env
        probe = (
            "python3 - <<'EOF'\n"
            "import socket\n"
            "def tcp(host, port):\n"
            "    try:\n"
            "        s = socket.create_connection((host, port), timeout=4); s.close(); return 'open'\n"
            "    except OSError as e:\n"
            "        return 'blocked:' + type(e).__name__\n"
            "try:\n"
            "    host_ip = socket.gethostbyname('host.docker.internal')\n"
            "except OSError:\n"
            "    host_ip = None\n"
            "print('host', tcp(host_ip, 445) if host_ip else 'blocked:no-name')\n"
            "print('metadata', tcp('169.254.169.254', 80))\n"
            "print('lan', tcp('192.168.1.1', 80))\n"
            "print('internet', tcp('example.com', 443))\n"
            "EOF"
        )
        out = env.execute(probe)["output"]
        lines = dict(line.split(" ", 1) for line in out.strip().splitlines() if " " in line)
        self.assertTrue(lines.get("host", "").startswith("blocked"), out)
        self.assertTrue(lines.get("metadata", "").startswith("blocked"), out)
        self.assertTrue(lines.get("lan", "").startswith("blocked"), out)
        self.assertEqual(lines.get("internet"), "open", out)

        # The sandbox can't remove the rules: it has no NET_ADMIN (or any extra capability).
        caps = env.execute("grep CapEff /proc/self/status")["output"].split()[-1]
        self.assertEqual(int(caps, 16) & (1 << 12), 0, caps)  # CAP_NET_ADMIN
        self.assertEqual(int(caps, 16) & (1 << 13), 0, caps)  # CAP_NET_RAW
        r = env.execute("pip install --quiet --no-cache-dir six && python3 -c 'import six; print(six.__name__)'")
        self.assertIn("six", r["output"], r["output"])
        r = env.execute("apt-get update -qq >/dev/null && apt-get install -y -qq tree >/dev/null && tree --version")
        self.assertIn("tree v", r["output"], r["output"])
        self.assertEqual(env.execute("cat /sys/fs/cgroup/pids.max")["output"].strip(), "2048")

        # The rules come back after a restore (a new container).
        env.restore("last")
        out = env.execute(probe)["output"]
        self.assertIn("host blocked", out)
        self.assertIn("internet open", out)

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
