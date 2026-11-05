"""Talk to the Docker Engine API directly instead of starting the docker CLI.

On Docker Desktop every ``docker`` CLI call costs 0.6 to 1.2 seconds, most of
it starting the client. The same request over the daemon's socket (a named
pipe on Windows) takes milliseconds. ``ApiRunner`` has the same
``(argv, timeout) -> (exit_code, output)`` interface as the CLI runner and
translates the handful of docker commands Rewind uses into API calls.
Anything it does not translate goes to the CLI, and so does everything once
the API turns out to be unreachable. Only the standard library is used.
"""
from __future__ import annotations

import http.client
import io
import json
import os
import socket
import struct
import subprocess
import sys
import threading
import time
from typing import Callable, List, Optional, Sequence, Tuple
from urllib.parse import quote, urlencode

Runner = Callable[[Sequence[str], Optional[float]], Tuple[int, str]]

_CHANGE_KINDS = {0: "C", 1: "A", 2: "D"}
_INSPECT_FORMAT = "{{.Size}} {{len .RootFS.Layers}}"
_PIPE_BUSY = 231  # ERROR_PIPE_BUSY: every instance of the named pipe is in use


class _NotConnected(Exception):
    """The daemon could not be reached; nothing was sent, so the CLI may retry."""


class _UseCli(Exception):
    """Something the CLI handles better, e.g. `docker run` pulling a missing image."""


# --------------------------------------------------------------- transport
class _PipeSocket:
    """Just enough of a socket for http.client, over a Windows named pipe."""

    def __init__(self, path: str) -> None:
        for attempt in range(20):
            try:
                self.file = open(path, "r+b", buffering=0)
                return
            except OSError as exc:
                if getattr(exc, "winerror", None) != _PIPE_BUSY or attempt == 19:
                    raise
                time.sleep(0.05)

    def sendall(self, data: bytes) -> None:
        self.file.write(data)

    def makefile(self, mode: str):
        return io.BufferedReader(self.file)

    def close(self) -> None:
        # http.client closes the "socket" while the response is still being
        # read; the pipe is closed explicitly once the response is done.
        pass


class _Connection(http.client.HTTPConnection):
    def __init__(self, endpoint: str) -> None:
        super().__init__("localhost")
        self.endpoint = endpoint
        self.pipe: Optional[_PipeSocket] = None

    def connect(self) -> None:
        try:
            if self.endpoint.startswith("npipe://"):
                path = self.endpoint[len("npipe://"):].replace("/", "\\")
                self.pipe = _PipeSocket(path)
                self.sock = self.pipe
            else:
                sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                sock.connect(self.endpoint[len("unix://"):])
                self.sock = sock
        except OSError as exc:
            raise _NotConnected(str(exc)) from exc

    def release(self) -> None:
        """Close everything once the response has been read. (close() alone is
        not enough: http.client calls it early, before streamed bodies end.)"""
        self.close()
        if self.pipe is not None:
            self.pipe.file.close()
            self.pipe = None


def resolve_endpoint(docker_bin: str, cli: Runner) -> Optional[str]:
    """Find the daemon the CLI would talk to, as a unix:// or npipe:// URL."""
    host = os.environ.get("DOCKER_HOST", "")
    if not host:
        try:
            code, out = cli([docker_bin, "context", "inspect", "--format", "{{.Endpoints.docker.Host}}"], 30)
            host = out.strip() if code == 0 else ""
        except (OSError, subprocess.TimeoutExpired):
            host = ""
    if not host:
        host = "npipe:////./pipe/docker_engine" if sys.platform == "win32" else "unix:///var/run/docker.sock"
    if host.startswith("npipe://") and sys.platform == "win32":
        return host
    if host.startswith("unix://") and hasattr(socket, "AF_UNIX"):
        return host
    return None  # tcp://, ssh:// and the like stay with the CLI


def demux(raw: bytes) -> str:
    """Join Docker's multiplexed stdout/stderr frames in the order they arrived."""
    out = bytearray()
    pos = 0
    while pos + 8 <= len(raw):
        (size,) = struct.unpack(">I", raw[pos + 4:pos + 8])
        out += raw[pos + 8:pos + 8 + size]
        pos += 8 + size
    return out.decode("utf-8", errors="replace")


# ------------------------------------------------------------------ runner
class ApiRunner:
    def __init__(self, docker_bin: str, cli: Runner, endpoint: Optional[str] = None) -> None:
        self.docker_bin = docker_bin
        self.cli = cli
        self.endpoint = endpoint
        self._resolved = endpoint is not None
        self.disabled = False

    def __call__(self, argv: Sequence[str], timeout: Optional[float] = None) -> Tuple[int, str]:
        if not self._resolved:
            self.endpoint = resolve_endpoint(self.docker_bin, self.cli)
            self._resolved = True
            self.disabled = self.endpoint is None
        handler = None if self.disabled else self._translate(list(argv[1:]))
        if handler is None:
            return self.cli(argv, timeout)
        try:
            return handler(timeout)
        except _NotConnected:
            self.disabled = True
            return self.cli(argv, timeout)
        except _UseCli:
            return self.cli(argv, timeout)

    # The request, response and any streamed body happen on a worker thread so
    # a timeout works the same way on sockets and on Windows named pipes, which
    # have no read timeout.
    def _request(self, method: str, path: str, body=None, timeout: Optional[float] = None) -> Tuple[int, bytes]:
        result: dict = {}
        received = bytearray()

        def work() -> None:
            conn = _Connection(self.endpoint)
            try:
                data = json.dumps(body).encode() if body is not None else None
                headers = {"Content-Type": "application/json"} if data is not None else {}
                conn.request(method, path, body=data, headers=headers)
                resp = conn.getresponse()
                result["status"] = resp.status
                while True:
                    chunk = resp.read(65536)
                    if not chunk:
                        break
                    received.extend(chunk)
            except BaseException as exc:  # handed to the calling thread
                result["error"] = exc
            finally:
                conn.release()

        worker = threading.Thread(target=work, daemon=True)
        worker.start()
        worker.join(timeout)
        if worker.is_alive():
            raise subprocess.TimeoutExpired([method, path], timeout, output=bytes(received))
        if "error" in result:
            exc = result["error"]
            if isinstance(exc, _NotConnected):
                raise exc
            # Something was sent, so retrying with the CLI could run it twice.
            return 599, f"Docker API error: {exc}".encode()
        return result["status"], bytes(received)

    @staticmethod
    def _error(status: int, body: bytes) -> Tuple[int, str]:
        try:
            message = json.loads(body).get("message", "")
        except (ValueError, AttributeError):
            message = body.decode("utf-8", errors="replace")
        return 1, f"Error response from daemon: {message or f'HTTP {status}'}\n"

    def _translate(self, args: List[str]):
        """Return a handler for ``docker <args>``, or None to leave it to the CLI."""
        if not args:
            return None
        verb, rest = args[0], args[1:]
        if verb == "exec" and len(rest) >= 2 and not rest[0].startswith("-"):
            return lambda t: self._exec(rest[0], rest[1:], t)
        if verb == "run":
            return self._parse_run(rest)
        if verb == "commit" and len(rest) == 4 and rest[0] == "--message":
            return lambda t: self._commit(rest[2], rest[3], rest[1], t)
        if verb == "rm" and rest[:1] == ["-f"] and len(rest) == 2:
            return lambda t: self._simple("DELETE", f"/containers/{quote(rest[1])}?force=1", t)
        if verb == "rmi" and rest:
            force = rest[0] == "-f"
            images = rest[1:] if force else rest
            if images and not any(i.startswith("-") for i in images):
                return lambda t: self._rmi(images, force, t)
        if verb == "diff" and len(rest) == 1:
            return lambda t: self._diff(rest[0], t)
        if verb == "image" and rest[:3] == ["inspect", "-f", _INSPECT_FORMAT] and len(rest) == 4:
            return lambda t: self._inspect(rest[3], t)
        return None

    # ---------------------------------------------------------- commands
    def _simple(self, method: str, path: str, timeout) -> Tuple[int, str]:
        status, body = self._request(method, path, timeout=timeout)
        return (0, "") if status < 300 else self._error(status, body)

    def _exec(self, container: str, cmd: List[str], timeout) -> Tuple[int, str]:
        status, body = self._request(
            "POST", f"/containers/{quote(container)}/exec",
            {"AttachStdout": True, "AttachStderr": True, "Cmd": cmd}, timeout,
        )
        if status >= 300:
            return self._error(status, body)
        exec_id = json.loads(body)["Id"]
        try:
            status, raw = self._request("POST", f"/exec/{exec_id}/start", {"Detach": False, "Tty": False}, timeout)
        except subprocess.TimeoutExpired as exc:
            raise subprocess.TimeoutExpired(cmd, timeout, output=demux(exc.output or b""))
        if status >= 300:
            return self._error(status, raw)
        status, body = self._request("GET", f"/exec/{exec_id}/json", timeout=30)
        if status >= 300:
            return self._error(status, body)
        exit_code = json.loads(body).get("ExitCode")
        return (exit_code if exit_code is not None else 1), demux(raw)

    def _parse_run(self, rest: List[str]):
        if rest[:1] != ["-d"]:
            return None
        name, labels, network, entrypoint = None, {}, None, None
        i = 1
        while i < len(rest) and rest[i].startswith("-"):
            if i + 1 >= len(rest):
                return None
            opt, value = rest[i], rest[i + 1]
            if opt == "--name":
                name = value
            elif opt == "--label":
                key, _, val = value.partition("=")
                labels[key] = val
            elif opt == "--network":
                network = value
            elif opt == "--entrypoint":
                entrypoint = value
            else:
                return None
            i += 2
        if not name or i >= len(rest):
            return None
        config = {"Image": rest[i], "Cmd": rest[i + 1:], "Labels": labels}
        if entrypoint:
            config["Entrypoint"] = [entrypoint]
        if network:
            config["HostConfig"] = {"NetworkMode": network}
        return lambda t: self._run(name, config, t)

    def _run(self, name: str, config: dict, timeout) -> Tuple[int, str]:
        status, body = self._request("POST", f"/containers/create?{urlencode({'name': name})}", config, timeout)
        if status == 404:
            raise _UseCli()  # image not pulled yet; `docker run` pulls it
        if status >= 300:
            return self._error(status, body)
        container_id = json.loads(body)["Id"]
        status, body = self._request("POST", f"/containers/{container_id}/start", timeout=timeout)
        if status >= 300:
            return self._error(status, body)
        return 0, container_id + "\n"

    def _commit(self, container: str, image: str, message: str, timeout) -> Tuple[int, str]:
        repo, tag = image, "latest"
        if ":" in image.rsplit("/", 1)[-1]:
            repo, _, tag = image.rpartition(":")
        query = urlencode({"container": container, "repo": repo, "tag": tag, "comment": message})
        status, body = self._request("POST", f"/commit?{query}", timeout=timeout)
        if status >= 300:
            return self._error(status, body)
        return 0, json.loads(body).get("Id", "") + "\n"

    def _rmi(self, images: List[str], force: bool, timeout) -> Tuple[int, str]:
        code, errors = 0, []
        suffix = "?force=1" if force else ""
        for image in images:
            status, body = self._request("DELETE", f"/images/{quote(image, safe='/:@')}{suffix}", timeout=timeout)
            if status >= 300:
                code = 1
                errors.append(self._error(status, body)[1])
        return code, "".join(errors)

    def _diff(self, container: str, timeout) -> Tuple[int, str]:
        status, body = self._request("GET", f"/containers/{quote(container)}/changes", timeout=timeout)
        if status >= 300:
            return self._error(status, body)
        changes = json.loads(body) or []
        return 0, "".join(f"{_CHANGE_KINDS.get(c.get('Kind'), 'C')} {c.get('Path')}\n" for c in changes)

    def _inspect(self, image: str, timeout) -> Tuple[int, str]:
        status, body = self._request("GET", f"/images/{quote(image, safe='/:@')}/json", timeout=timeout)
        if status >= 300:
            return self._error(status, body)
        info = json.loads(body)
        layers = (info.get("RootFS") or {}).get("Layers") or []
        return 0, f"{info.get('Size', 0)} {len(layers)}\n"
