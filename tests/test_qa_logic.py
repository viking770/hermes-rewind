"""Independent QA: unit-level adversarial tests (no Docker needed).

Tests marked @unittest.expectedFailure demonstrate a real bug; each names it
(QA-xx, matching the QA report). They "pass" while the bug exists, and turn
into "unexpected success" once it is fixed, so the marker can then be removed.

Run: python -m unittest tests.test_qa_logic -v
"""
import io
import json
import os
import tarfile
import tempfile
import time
import unittest
from pathlib import Path

from rewind import audit, policy, registry, tools
from rewind.environment import RewindEnvironment, RewindError, _extract_plain, _split_cwd, _CWD_MARKER
from rewind.redact import redact
from rewind.store import Store, is_valid_record
from tests.test_environment import FakeDocker, make_env, ALICE, BOB


def _tar(entries):
    """entries: list of (name, kind, data/linkname)."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        for name, kind, payload in entries:
            info = tarfile.TarInfo(name)
            if kind == "file":
                data = payload or b""
                info.size = len(data)
                tf.addfile(info, io.BytesIO(data))
            elif kind == "dir":
                info.type = tarfile.DIRTYPE
                tf.addfile(info)
            elif kind == "sym":
                info.type = tarfile.SYMTYPE
                info.linkname = payload
                tf.addfile(info)
            elif kind == "lnk":
                info.type = tarfile.LNKTYPE
                info.linkname = payload
                tf.addfile(info)
    buf.seek(0)
    return buf


# ----------------------------------------------------------------- classifier
class ReadOnlyClassifierTests(unittest.TestCase):
    """Commands that change files but are classified read-only get no snapshot,
    and (worse) leave a stale background snapshot in place: see QA-01."""

    def test_plain_cases_still_right(self):
        for cmd in ("ls -la", "cat a | grep b", "git status", "find . -name x"):
            self.assertFalse(policy.is_mutating(cmd), cmd)
        for cmd in ("rm x", "echo a > f", "sed -i s/a/b/ f", "find . -delete", "echo hi >| f",
                    "echo $(rm x)", "cat <<EOF\nrm x\nEOF"):
            self.assertTrue(policy.is_mutating(cmd), cmd)

    # Was QA-02 (fixed): combined short flags hide sed's -i
    def test_sed_combined_in_place_flag(self):
        self.assertTrue(policy.is_mutating("sed -ni 's/a/b/p' f.txt"))

    # Was QA-02 (fixed): combined short flags hide sed's -i
    def test_sed_E_i(self):
        self.assertTrue(policy.is_mutating("sed -Ei 's/a/b/' f.txt"))

    # Was QA-02 (fixed): bash `>&word` writes stdout+stderr to the file `word`
    def test_redirect_to_file_with_ampersand(self):
        self.assertTrue(policy.is_mutating("echo hi >&out.txt"))

    # Was QA-02 (fixed): git diff/log/show --output=FILE writes a file
    def test_git_output_option(self):
        self.assertTrue(policy.is_mutating("git diff --output=patch.txt"))

    # Was QA-02 (fixed): awk -f runs a script file that can write anything
    def test_awk_program_file(self):
        self.assertTrue(policy.is_mutating("awk -f prog.awk in.txt"))

    # Was QA-02 (fixed): process substitution runs arbitrary commands
    def test_process_substitution(self):
        self.assertTrue(policy.is_mutating("diff <(touch made) x"))

    # Was QA-02 (fixed): env assignment makes a read-only program run a command
    def test_env_prefix_runs_command(self):
        self.assertTrue(policy.is_mutating("GIT_EXTERNAL_DIFF=./x.sh git diff"))


class IrreversibleClassifierTests(unittest.TestCase):
    """The README calls the prompt best effort; these are common agent spellings it misses (QA-05)."""

    def test_documented_cases(self):
        for cmd in ("git push", "bash -c 'git push'", "timeout 5 curl -X POST https://e.x",
                    "git -C repo push", "xargs git push"):
            self.assertIsNotNone(policy.irreversible_reason(cmd), cmd)

    # Was QA-05 (fixed): bash -lc / -ec (combined flags) is how many agents call bash
    def test_bash_lc(self):
        self.assertIsNotNone(policy.irreversible_reason("bash -lc 'git push origin main'"))

    # Was QA-05 (fixed): command substitution
    def test_command_substitution(self):
        self.assertIsNotNone(policy.irreversible_reason("echo $(git push)"))

    # Was QA-05 (fixed): env with options
    def test_env_with_option(self):
        self.assertIsNotNone(policy.irreversible_reason("env -i git push"))

    # Was QA-05 (fixed): curl attached short options (-d@file, -sd, -sSXPOST)
    def test_curl_attached_data(self):
        self.assertIsNotNone(policy.irreversible_reason("curl -d@data.json https://example.com"))

    # Was QA-05 (fixed): curl combined flags
    def test_curl_combined_flags(self):
        self.assertIsNotNone(policy.irreversible_reason("curl -sSXPOST https://example.com"))


# ------------------------------------------------------------------ redaction
class RedactionTests(unittest.TestCase):
    def test_documented_cases(self):
        self.assertNotIn("hunter2", redact("curl -u admin:hunter2 https://x"))
        self.assertNotIn("abc123", redact("export GH_TOKEN=abc123"))
        self.assertNotIn("s3cret", redact("git clone https://u:s3cret@host/r"))

    # Was QA-06 (fixed): curl -uUSER:PASS (no space) is valid curl syntax
    def test_curl_attached_user(self):
        self.assertNotIn("hunter2", redact("curl -uadmin:hunter2 https://x"))

    # Was QA-06 (fixed): JSON bodies with a password key
    def test_json_password(self):
        self.assertNotIn("hunter2", redact("curl -d '{\"password\":\"hunter2\"}' https://x"))

    # Was QA-06 (fixed): Stripe secret keys use sk_live_ (underscore)
    def test_stripe_key(self):
        # Built at run time so the source holds no key-shaped literal (secret scanners flag those).
        fake_key = "sk_" + "live_" + "abcdefghijklmnopqrstuvwx1234"
        self.assertNotIn("abcdefghijklmnopqrstuvwx1234", redact(f"run {fake_key}"))

    # Was QA-06 (fixed): a password containing @ leaks its tail
    def test_url_password_with_at(self):
        self.assertNotIn("ss@", redact("git clone https://u:p@ss@host/r"))


# ----------------------------------------------------------- cwd and records
class CwdMarkerTests(unittest.TestCase):
    def setUp(self):
        registry.clear()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def test_split_cwd_uses_last_marker(self):
        out = f"x\n{_CWD_MARKER}/fake\nmore\n{_CWD_MARKER}/real\n"
        self.assertEqual(_split_cwd(out)[1], "/real")

    # Was QA-03 (fixed): the reported cwd is trusted without checking it is absolute
    def test_non_absolute_cwd_rejected(self):
        fake = FakeDocker()
        fake.exec_cwd = "%s\\n' \"/workspace\""  # what an unterminated heredoc makes the wrapper print
        env = make_env(fake)
        env.execute("cat <<EOF")
        self.assertTrue(env.cwd.startswith("/"), env.cwd)

    # Was QA-03 (fixed): ...and a poisoned cwd makes the parked record invalid, losing undo history
    def test_poisoned_cwd_survives_parking(self):
        store = Store(Path(self.tmp.name))
        fake = FakeDocker()
        fake.image_info = {}
        env = make_env(fake, store=store, keep_hours=1)
        env.execute("touch a")  # one snapshot
        fake.exec_cwd = "not-absolute"
        env.execute("cat <<EOF")
        env.cleanup()  # parks
        for snap in env.snapshots:
            fake.image_info[snap.image] = "100 3"
        fake.image_info[env._image] = "100 3"
        registry.clear()
        again = make_env(fake, store=store, keep_hours=1)
        self.assertEqual(len(again.snapshots), 1, "parked snapshots were not resumed")


class RecordTamperingTests(unittest.TestCase):
    """README: an edited record can't make Rewind remove someone else's container
    or start an arbitrary image."""

    def setUp(self):
        registry.clear()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = Store(Path(self.tmp.name))

    def _write(self, record):
        self.store.dir.mkdir(parents=True, exist_ok=True)
        record = {"format": 1, **record}
        self.store.path(record["task_id"]).write_text(json.dumps(record), encoding="utf-8")

    def test_foreign_repository_rejected(self):
        self.assertFalse(is_valid_record({"task_id": "t", "status": "parked", "repository": "evil/x"}))

    # Was QA-04 (fixed): base_image == image lets a record pick any local image
    def test_record_cannot_choose_arbitrary_image(self):
        self._write({"task_id": "Demo Task", "status": "parked", "repository": "hermes-rewind/demo-task-abc123",
                     "base_image": "attacker/evil:1", "image": "attacker/evil:1", "snapshots": [
                         {"id": "s1", "image": "hermes-rewind/demo-task-abc123:s1", "label": "auto", "command": "x",
                          "cwd": "/workspace", "created_at": time.time(), "auto": True}],
                     "expires_at": time.time() + 3600})
        fake = FakeDocker()
        fake.image_info = {"attacker/evil:1": "100 3"}
        env = make_env(fake, store=self.store, keep_hours=1)
        env.execute("ls")
        runs = [c for c in fake.calls if c[1] == "run"]
        self.assertFalse(any("attacker/evil:1" in c for c in runs), runs)

    # Was QA-04 (fixed): a record's container is not tied to its own repository
    def test_record_cannot_remove_another_sandboxes_container(self):
        other = "hermes-rewind-bob-zzz999"
        self._write({"task_id": "Demo Task", "status": "live", "repository": "hermes-rewind/demo-task-abc123",
                     "container": other, "owner_pid": 999999999, "host": __import__("socket").gethostname(),
                     "image": "hermes-rewind/demo-task-abc123:s1", "snapshots": []})
        fake = FakeDocker()
        make_env(fake, store=self.store, keep_hours=1)
        touched = [c for c in fake.calls if other in c]
        self.assertEqual(touched, [], touched)


# ---------------------------------------------------------------- snapshots
class SnapshotEdgeTests(unittest.TestCase):
    def setUp(self):
        registry.clear()
        self.fake = FakeDocker()

    def test_undo_with_nothing(self):
        env = make_env(self.fake)
        env.execute("ls")
        with self.assertRaises(RewindError):
            env.undo()

    def test_invalid_ids(self):
        env = make_env(self.fake)
        env.execute("touch a")
        for bad in ("s999", "-f", "../s1", "s1\n", "S1", " s1"):
            with self.assertRaises(RewindError, msg=bad):
                env.restore(bad)

    def test_auto_snapshot_cap(self):
        env = make_env(self.fake, max_snapshots=3)
        for i in range(10):
            env.execute(f"touch f{i}")
        self.assertEqual(len([s for s in env.snapshots if s.auto]), 3)

    # Was QA-07 (fixed): restore points are never pruned, so repeated undos grow without bound
    def test_restore_points_are_bounded(self):
        env = make_env(self.fake, max_snapshots=3)
        env.execute("touch a")
        for _ in range(30):
            env.undo()
        self.assertLessEqual(len(env.snapshots), 3 * 2 + 5, len(env.snapshots))

    def test_concurrent_execute_and_restore(self):
        import threading
        env = make_env(self.fake)
        env.execute("touch a")
        errors = []

        def worker(fn):
            try:
                for _ in range(20):
                    fn()
            except Exception as exc:  # noqa
                errors.append(exc)
        ts = [threading.Thread(target=worker, args=(lambda: env.execute("touch b"),)),
              threading.Thread(target=worker, args=(lambda: env.undo(),)),
              threading.Thread(target=worker, args=(lambda: env.list_snapshots(sizes=True),))]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
        self.assertEqual(errors, [])
        ids = [s.id for s in env.snapshots]
        self.assertEqual(len(ids), len(set(ids)))

    # Was QA-08 (fixed): a lone surrogate in stdin escapes execute() as UnicodeEncodeError
    def test_bad_stdin_does_not_raise(self):
        env = make_env(self.fake)
        result = env.execute("cat", stdin_data="\ud800")
        self.assertNotEqual(result["returncode"], 0)


# ---------------------------------------------------------- chat isolation
class IsolationTests(unittest.TestCase):
    def setUp(self):
        registry.clear()
        self.fake = FakeDocker()

    def test_messaging_cannot_reach_shared(self):
        shared = RewindEnvironment(task_id="default", runner=self.fake, network="none", background=False)
        self.assertIsNone(registry.find("telegram-" + "x" * 40, None, allow_shared=False))
        self.assertIs(registry.find(None, None, allow_shared=True), shared)

    def test_odd_ids_do_not_cross(self):
        a = RewindEnvironment(task_id=f"session:{ALICE}", runner=self.fake, network="none", background=False)
        RewindEnvironment(task_id=f"session:{BOB}", runner=self.fake, network="none", background=False)
        for probe in ("", "session:", ":", "*", ALICE[:11], "a" * 64, f"{ALICE}\n", f"session:{ALICE}:x"):
            env = registry.find(probe, None, allow_shared=False)
            self.assertIn(env, (None,), probe)
        self.assertIs(registry.find(ALICE, None, allow_shared=False), a)

    def test_tool_args_cannot_pick_sandbox(self):
        RewindEnvironment(task_id=f"session:{BOB}", runner=self.fake, network="none", background=False)
        out = json.loads(tools.HANDLERS["rewind_list"]({"task_id": BOB, "session_id": BOB},
                                                       task_id="someone-else-" + "c" * 30))
        self.assertFalse(out["ok"])


# ------------------------------------------------------------------- export
class ExtractTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dest = Path(self.tmp.name) / "out"
        self.dest.mkdir()

    def test_traversal_and_links(self):
        removed = _extract_plain(_tar([
            ("w/a.txt", "file", b"ok"), ("../escape.txt", "file", b"x"), ("/abs.txt", "file", b"x"),
            ("w/link", "sym", "/etc/passwd"), ("w/hard", "lnk", "/etc/passwd"),
            ("w/hard2", "lnk", "w/a.txt"), ("w/C:x", "file", b"x"), ("C:/y", "file", b"x"),
        ]), self.dest)
        self.assertTrue((self.dest / "w" / "a.txt").exists())
        self.assertEqual((self.dest / "w" / "hard2").read_bytes(), b"ok")
        self.assertFalse((Path(self.tmp.name) / "escape.txt").exists())
        for name in ("escape.txt", "abs.txt", "w/link", "w/hard"):
            self.assertTrue(any(name in r for r in removed), (name, removed))
        for p in Path(self.tmp.name).rglob("*"):
            self.assertTrue(str(p.resolve()).startswith(str(self.dest.resolve())), p)

    def test_size_cap_enforced(self):
        with self.assertRaises(RewindError):
            _extract_plain(_tar([("a", "file", b"x" * (2 * 1024 * 1024))]), self.dest, max_mb=1)

    def test_hardlink_chain_counts_toward_cap(self):
        entries = [("a", "file", b"x" * (600 * 1024))] + [(f"h{i}", "lnk", "a") for i in range(5)]
        with self.assertRaises(RewindError):
            _extract_plain(_tar(entries), self.dest, max_mb=1)

    # Was QA-09 (fixed): no cap on the number of files: empty files cost nothing against the MB caps.
    # The cap is REWIND_EXPORT_MAX_FILES (20,000 by default); past it the export is refused.
    def test_file_count_is_capped(self):
        entries = [(f"d/f{i}", "file", b"") for i in range(5000)]
        with self.assertRaises(RewindError) as ctx:
            _extract_plain(_tar(entries), self.dest, max_mb=1, max_files=1000)
        self.assertIn("REWIND_EXPORT_MAX_FILES", str(ctx.exception))
        self.assertLess(sum(1 for _ in self.dest.rglob("*")), 5000)

    def test_skipped_entries_say_why(self):
        from rewind.environment import SKIP_REASONS, describe_skipped
        reasons = {}
        removed = _extract_plain(_tar([("app/ok.txt", "file", b"ok"), ("app/link", "sym", "/etc/passwd")]),
                                 self.dest, reasons=reasons)
        self.assertEqual(removed, ["app/link"])
        self.assertEqual(reasons, {"app/link": "symlink"})
        message = describe_skipped(removed, reasons)
        self.assertIn("app/link (" + SKIP_REASONS["symlink"] + ")", message)
        self.assertEqual(describe_skipped([], {}), "")

    def test_exported_files_are_owner_only_and_marked_downloaded(self):
        _extract_plain(_tar([("app/run.sh", "file", b"#!/bin/sh\n")]), self.dest)
        target = self.dest / "app" / "run.sh"
        if os.name == "nt":
            zone = Path(f"{target}:Zone.Identifier").read_text(encoding="ascii")
            self.assertIn("ZoneId=3", zone)
        else:
            import stat
            self.assertEqual(stat.S_IMODE(target.stat().st_mode) & 0o077, 0)  # nothing for group/other
            self.assertEqual(stat.S_IMODE((self.dest / "app").stat().st_mode) & 0o077, 0)

    @unittest.skipUnless(os.name == "nt", "Windows device names")
    def test_windows_device_names_not_written_silently(self):
        removed = _extract_plain(_tar([("d/nul", "file", b"data"), ("d/con.txt", "file", b"data")]), self.dest)
        for name in ("d/nul", "d/con.txt"):
            if not (self.dest / name).is_file():
                self.assertIn(name, removed, f"{name} was neither written nor reported: {removed}")


# -------------------------------------------------------------------- audit
class AuditTests(unittest.TestCase):
    # Was QA-10 (fixed): control characters from agent text reach the terminal via `hermes rewind log`
    def test_describe_strips_control_characters(self):
        line = audit.describe({"time": "t", "event": "approval_requested", "via": "agent",
                               "command": "ls \x1b[2K\x1b[1A hidden"})
        self.assertNotIn("\x1b", line)

    def test_audit_redacts(self):
        with tempfile.TemporaryDirectory() as d:
            old = os.environ.get("REWIND_STATE_DIR")
            os.environ["REWIND_STATE_DIR"] = d
            try:
                audit.log("approval_requested", command="curl -H 'Authorization: Bearer abcdef123456' x")
                text = (Path(d) / "audit.log").read_text(encoding="utf-8")
            finally:
                if old is None:
                    os.environ.pop("REWIND_STATE_DIR")
                else:
                    os.environ["REWIND_STATE_DIR"] = old
        self.assertNotIn("abcdef123456", text)


if __name__ == "__main__":
    unittest.main()
