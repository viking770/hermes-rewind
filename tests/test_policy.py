import unittest

from rewind.policy import is_mutating, should_snapshot


class PolicyTests(unittest.TestCase):
    def test_read_only_commands(self):
        for cmd in [
            "ls -la",
            "cat README.md | grep foo",
            "pwd && cd src",
            "git status",
            "git log --oneline -5",
            "find . -name '*.py'",
            "sed -n '1,20p' app.py",
            "grep -r TODO . 2>/dev/null",
            "ls > /dev/null",
            "FOO=1 env",
            "echo hello 2>&1",
            "",
        ]:
            with self.subTest(cmd=cmd):
                self.assertFalse(is_mutating(cmd))

    def test_mutating_commands(self):
        for cmd in [
            "rm -rf build",
            "echo hi > notes.txt",
            "echo hi >> notes.txt",
            "ls 2> err.log",
            "pip install requests",
            "git commit -m wip",
            "git checkout -- .",
            "sed -i 's/a/b/' app.py",
            "find . -name '*.pyc' -delete",
            "ls && rm x",
            "cat x | tee y",
            "python3 script.py",
            "ls $(rm -rf /)",
            "sort -o out.txt in.txt",
            "unknowncommand",
        ]:
            with self.subTest(cmd=cmd):
                self.assertTrue(is_mutating(cmd))

    def test_modes(self):
        self.assertTrue(should_snapshot("ls", "always"))
        self.assertFalse(should_snapshot("rm -rf /", "off"))
        self.assertFalse(should_snapshot("ls", "mutating"))
        self.assertTrue(should_snapshot("rm x", "mutating"))


if __name__ == "__main__":
    unittest.main()
