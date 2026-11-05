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
            "env -u HOME FOO=1",
            "env ls -la",
            "awk -F, '{print $1}' data.csv",
            "sed 's/hello/world/g' app.py",
            "sed -e 's/a/b/' -e '1,5p' styles.css",
            "uniq data.txt",
            "xxd image.png",
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
            "env rm -rf src",
            "env -i PATH=/bin rm x",
            "env -u HOME python3 x.py",
            "env -S 'rm -rf src'",
            "awk 'BEGIN{system(\"rm -rf src\")}'",
            "awk -i inplace '{print}' app.py",
            "sed 's/a/b/w out.txt' app.py",
            "sed 's/a/b/gw out.txt' app.py",
            "sed -n '3w out.txt' app.py",
            "sed '/foo/e' app.py",
            "sed -f script.sed app.py",
            "find . -fprint0 list.txt",
            "uniq in.txt out.txt",
            "xxd -r dump.hex out.bin",
            "tree -o tree.txt",
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
