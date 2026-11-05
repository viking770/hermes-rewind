import json
import struct
import subprocess
import unittest

from rewind.docker_api import ApiRunner, _NotConnected, demux, resolve_endpoint


def frame(stream, text):
    data = text.encode()
    return struct.pack(">BxxxI", stream, len(data)) + data


class FakeApi(ApiRunner):
    """ApiRunner with the daemon replaced by canned responses."""

    def __init__(self, responses=None):
        self.cli_calls = []
        super().__init__("docker", self._cli, endpoint="npipe:////./pipe/test")
        self.requests = []
        self.responses = responses or {}
        self.unreachable = False

    def _cli(self, argv, timeout=None):
        self.cli_calls.append(list(argv))
        return 0, "from cli\n"

    def _request(self, method, path, body=None, timeout=None):
        if self.unreachable:
            raise _NotConnected("no daemon")
        self.requests.append((method, path, body))
        for (m, prefix), response in self.responses.items():
            if m == method and path.startswith(prefix):
                if isinstance(response, Exception):
                    raise response
                status, payload = response
                return status, payload if isinstance(payload, bytes) else json.dumps(payload).encode()
        return 204, b""


class ApiRunnerTests(unittest.TestCase):
    def test_exec_demuxes_output_and_returns_exit_code(self):
        api = FakeApi({
            ("POST", "/containers/box/exec"): (201, {"Id": "e1"}),
            ("POST", "/exec/e1/start"): (200, frame(1, "out\n") + frame(2, "err\n")),
            ("GET", "/exec/e1/json"): (200, {"ExitCode": 3}),
        })
        self.assertEqual(api(["docker", "exec", "box", "bash", "-c", "ls"], 10), (3, "out\nerr\n"))
        self.assertEqual(api.requests[0][2]["Cmd"], ["bash", "-c", "ls"])
        self.assertEqual(api.cli_calls, [])

    def test_exec_timeout_keeps_partial_output(self):
        api = FakeApi({
            ("POST", "/containers/box/exec"): (201, {"Id": "e1"}),
            ("POST", "/exec/e1/start"): subprocess.TimeoutExpired("x", 5, output=frame(1, "partial")),
        })
        with self.assertRaises(subprocess.TimeoutExpired) as ctx:
            api(["docker", "exec", "box", "sh", "-c", "sleep 99"], 5)
        self.assertEqual(ctx.exception.output, "partial")

    def test_run_creates_and_starts(self):
        api = FakeApi({("POST", "/containers/create"): (201, {"Id": "abc"})})
        code, out = api(["docker", "run", "-d", "--name", "box", "--label", "hermes.rewind=1",
                         "--network", "none", "--entrypoint", "/bin/sh", "img:1", "-c", "sleep"], 10)
        self.assertEqual((code, out), (0, "abc\n"))
        method, path, body = api.requests[0]
        self.assertEqual(path, "/containers/create?name=box")
        self.assertEqual(body["Image"], "img:1")
        self.assertEqual(body["Cmd"], ["-c", "sleep"])
        self.assertEqual(body["Entrypoint"], ["/bin/sh"])
        self.assertEqual(body["Labels"], {"hermes.rewind": "1"})
        self.assertEqual(body["HostConfig"], {"NetworkMode": "none"})
        self.assertEqual(api.requests[1][:2], ("POST", "/containers/abc/start"))

    def test_run_with_missing_image_lets_cli_pull_it(self):
        api = FakeApi({("POST", "/containers/create"): (404, {"message": "No such image: img"})})
        argv = ["docker", "run", "-d", "--name", "box", "img", "true"]
        self.assertEqual(api(argv, 10), (0, "from cli\n"))
        self.assertEqual(api.cli_calls, [argv])

    def test_commit_splits_repository_and_tag(self):
        api = FakeApi({("POST", "/commit"): (201, {"Id": "sha256:1"})})
        api(["docker", "commit", "--message", "rewind s1: auto", "box", "hermes-rewind/demo-ab12:s1"], 10)
        path = api.requests[0][1]
        self.assertIn("repo=hermes-rewind%2Fdemo-ab12", path)
        self.assertIn("tag=s1", path)
        self.assertIn("comment=rewind+s1%3A+auto", path)

    def test_rm_rmi_diff_and_inspect(self):
        api = FakeApi({
            ("DELETE", "/images/repo/x:s2"): (404, {"message": "No such image"}),
            ("GET", "/containers/box/changes"): (200, [{"Path": "/a", "Kind": 1}, {"Path": "/b", "Kind": 2}]),
            ("GET", "/images/repo/x:s1/json"): (200, {"Size": 1234, "RootFS": {"Layers": ["l1", "l2"]}}),
        })
        self.assertEqual(api(["docker", "rm", "-f", "box"], 10), (0, ""))
        self.assertEqual(api.requests[-1][:2], ("DELETE", "/containers/box?force=1"))
        code, out = api(["docker", "rmi", "-f", "repo/x:s1", "repo/x:s2"], 10)
        self.assertEqual(code, 1)  # one failed, like the CLI
        self.assertIn("No such image", out)
        self.assertEqual(api(["docker", "diff", "box"], 10), (0, "A /a\nD /b\n"))
        inspect = ["docker", "image", "inspect", "-f", "{{.Size}} {{len .RootFS.Layers}}", "repo/x:s1"]
        self.assertEqual(api(inspect, 10), (0, "1234 2\n"))

    def test_daemon_errors_look_like_cli_errors(self):
        api = FakeApi({("POST", "/containers/box/exec"): (409, {"message": "container is not running"})})
        code, out = api(["docker", "exec", "box", "sh", "-c", "ls"], 10)
        self.assertEqual(code, 1)
        self.assertIn("container is not running", out)

    def test_unknown_commands_go_to_cli(self):
        api = FakeApi()
        api(["docker", "ps", "-a"], 10)
        api(["docker", "image", "inspect", "-f", "{{.Id}}", "img"], 10)
        self.assertEqual(len(api.cli_calls), 2)
        self.assertEqual(api.requests, [])

    def test_unreachable_daemon_switches_to_cli_for_good(self):
        api = FakeApi()
        api.unreachable = True
        self.assertEqual(api(["docker", "rm", "-f", "box"], 10), (0, "from cli\n"))
        self.assertTrue(api.disabled)
        api.unreachable = False
        api(["docker", "diff", "box"], 10)
        self.assertEqual(len(api.cli_calls), 2)


class HelperTests(unittest.TestCase):
    def test_demux_ignores_a_cut_off_frame(self):
        raw = frame(1, "a") + frame(2, "b") + b"\x01\x00\x00"
        self.assertEqual(demux(raw), "ab")

    def test_resolve_endpoint_prefers_cli_context(self):
        calls = []

        def cli(argv, timeout=None):
            calls.append(argv)
            return 0, "unix:///home/me/.docker/run/docker.sock\n"

        import os
        from unittest import mock
        with mock.patch.dict(os.environ, {"DOCKER_HOST": ""}), mock.patch("sys.platform", "linux"):
            if hasattr(__import__("socket"), "AF_UNIX"):
                self.assertEqual(resolve_endpoint("docker", cli), "unix:///home/me/.docker/run/docker.sock")
        with mock.patch.dict(os.environ, {"DOCKER_HOST": "tcp://remote:2375"}):
            self.assertIsNone(resolve_endpoint("docker", cli))


if __name__ == "__main__":
    unittest.main()
