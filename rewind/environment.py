"""The Rewind sandbox: a Docker container whose filesystem can be rolled back.

Snapshots are ``docker commit`` images tagged ``hermes-rewind/<task>:<id>``.
Restoring replaces the container with a fresh one started from a snapshot
image. Everything goes through the ``docker`` CLI, so the plugin has no Python
dependencies.
"""
from __future__ import annotations

import re
import shlex
import subprocess
import threading
import time
import uuid
from dataclasses import asdict, dataclass
from typing import Callable, List, Optional, Sequence, Tuple

from . import policy, registry

DEFAULT_IMAGE = "python:3.12-slim"
DEFAULT_CWD = "/workspace"
DEFAULT_MAX_SNAPSHOTS = 25
_CWD_MARKER = "__REWIND_CWD__"
_SLUG = re.compile(r"[^a-z0-9]+")

# A runner takes (argv, timeout_seconds) and returns (exit_code, combined_output).
# It raises subprocess.TimeoutExpired on timeout, like subprocess.run.
Runner = Callable[[Sequence[str], Optional[float]], Tuple[int, str]]


class RewindError(RuntimeError):
    pass


def subprocess_runner(argv: Sequence[str], timeout: Optional[float] = None) -> Tuple[int, str]:
    proc = subprocess.run(
        list(argv),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
    )
    return proc.returncode, proc.stdout or ""


@dataclass
class Snapshot:
    id: str
    image: str
    label: str
    command: str
    cwd: str
    created_at: float
    auto: bool

    def describe(self) -> dict:
        info = asdict(self)
        info["age_seconds"] = round(time.time() - self.created_at, 1)
        return info


class RewindEnvironment:
    """Satisfies Hermes's duck-typed environment contract: execute() and cleanup()."""

    def __init__(
        self,
        *,
        cwd: str = DEFAULT_CWD,
        timeout: int = 180,
        task_id: str = "default",
        image: str = DEFAULT_IMAGE,
        snapshot_mode: str = "mutating",
        max_snapshots: int = DEFAULT_MAX_SNAPSHOTS,
        network: bool = True,
        runner: Optional[Runner] = None,
        docker_bin: str = "docker",
    ) -> None:
        if snapshot_mode not in policy.MODES:
            raise ValueError(f"snapshot_mode must be one of {policy.MODES}, got {snapshot_mode!r}")
        self.task_id = task_id
        self.cwd = cwd if cwd and cwd.startswith("/") else DEFAULT_CWD
        self.timeout = timeout
        self.base_image = image or DEFAULT_IMAGE
        self.snapshot_mode = snapshot_mode
        self.max_snapshots = max(1, int(max_snapshots))
        self.network = network
        self.docker_bin = docker_bin
        self._run = runner or subprocess_runner

        slug = _SLUG.sub("-", task_id.lower()).strip("-")[:40] or "task"
        suffix = uuid.uuid4().hex[:6]
        self.container = f"hermes-rewind-{slug}-{suffix}"
        self.repository = f"hermes-rewind/{slug}-{suffix}"

        self.snapshots: List[Snapshot] = []
        self._dropped_images: List[str] = []
        self._seq = 0
        self._shell = "sh"
        self._started = False
        self._lock = threading.RLock()
        registry.add(task_id, self)

    # ------------------------------------------------------------------ docker
    def _docker(self, *args: str, timeout: float = 120.0, check: bool = True) -> Tuple[int, str]:
        code, out = self._run([self.docker_bin, *args], timeout)
        if check and code != 0:
            raise RewindError(f"docker {args[0]} failed (exit {code}): {out.strip()[-500:]}")
        return code, out

    def _start_container(self, image: str) -> None:
        argv = [
            "run", "-d",
            "--name", self.container,
            "--label", "hermes.rewind=1",
            "--label", f"hermes.rewind.task={self.task_id}",
        ]
        if not self.network:
            argv += ["--network", "none"]
        keepalive = f"mkdir -p {shlex.quote(self.cwd)}; while :; do sleep 3600; done"
        argv += ["--entrypoint", "/bin/sh", image, "-c", keepalive]
        # The first run may pull the image, which can take a while.
        self._docker(*argv, timeout=900)

    def _ensure_started(self) -> None:
        if self._started:
            return
        self._start_container(self.base_image)
        code, _ = self._docker("exec", self.container, "sh", "-c", "command -v bash", check=False)
        self._shell = "bash" if code == 0 else "sh"
        self._started = True

    # ----------------------------------------------------------- environment
    def execute(self, command: str, timeout: Optional[int] = None, **kwargs) -> dict:
        with self._lock:
            cwd = kwargs.get("cwd") or self.cwd
            try:
                self._ensure_started()
            except (RewindError, subprocess.TimeoutExpired, OSError) as exc:
                return {"output": f"[rewind] could not start the sandbox: {exc}", "exit_code": 1}

            note = ""
            if policy.should_snapshot(command, self.snapshot_mode):
                try:
                    self._take_snapshot(label="auto", command=command, auto=True)
                except (RewindError, subprocess.TimeoutExpired, OSError) as exc:
                    note = f"[rewind] warning: snapshot failed, so this command cannot be undone ({exc})\n"

            limit = timeout or self.timeout
            argv = [self.docker_bin, "exec", self.container, self._shell, "-c", _wrap(command, cwd)]
            try:
                code, out = self._run(argv, limit)
            except subprocess.TimeoutExpired as exc:
                code, out = 124, _decode(exc.output) + f"\n[rewind] command timed out after {limit}s"

            output, new_cwd = _split_cwd(out)
            if new_cwd:
                self.cwd = new_cwd
            return {"output": note + output, "exit_code": code}

    def cleanup(self) -> None:
        with self._lock:
            if self._started:
                self._docker("rm", "-f", self.container, timeout=60, check=False)
                self._started = False
            images = [s.image for s in self.snapshots] + self._dropped_images
            if images:
                self._docker("rmi", "-f", *images, timeout=120, check=False)
            self.snapshots.clear()
            self._dropped_images.clear()
            registry.remove(self)

    # -------------------------------------------------------------- snapshots
    def snapshot(self, label: str = "manual") -> Snapshot:
        with self._lock:
            self._ensure_started()
            return self._take_snapshot(label=label or "manual", command="", auto=False)

    def _take_snapshot(self, *, label: str, command: str, auto: bool) -> Snapshot:
        self._seq += 1
        sid = f"s{self._seq}"
        image = f"{self.repository}:{sid}"
        self._docker("commit", "--message", f"rewind {sid}: {label}", self.container, image, timeout=300)
        snap = Snapshot(sid, image, label, command, self.cwd, time.time(), auto)
        self.snapshots.append(snap)
        self._prune()
        return snap

    def _prune(self) -> None:
        """Drop the oldest automatic snapshots beyond max_snapshots. Manual ones are kept."""
        autos = [s for s in self.snapshots if s.auto]
        excess = len(autos) - self.max_snapshots
        for snap in autos[:max(0, excess)]:
            self.snapshots.remove(snap)
            code, _ = self._docker("rmi", snap.image, timeout=60, check=False)
            if code != 0:  # e.g. the running container still uses it
                self._dropped_images.append(snap.image)

    def find(self, snapshot_id: str) -> Snapshot:
        if snapshot_id in ("last", "latest", ""):
            if not self.snapshots:
                raise RewindError("There are no snapshots yet.")
            return self.snapshots[-1]
        for snap in self.snapshots:
            if snap.id == snapshot_id:
                return snap
        known = ", ".join(s.id for s in self.snapshots) or "none"
        raise RewindError(f"Unknown snapshot {snapshot_id!r}. Known snapshots: {known}.")

    def restore(self, snapshot_id: str) -> Tuple[Snapshot, Snapshot]:
        """Roll the sandbox back. Returns (target, safety) where safety captures the
        state just before the restore, so the restore itself can be undone."""
        with self._lock:
            self._ensure_started()
            target = self.find(snapshot_id)
            safety = self._take_snapshot(label=f"before restoring {target.id}", command="", auto=False)
            self._docker("rm", "-f", self.container, timeout=60)
            self._started = False
            self._start_container(target.image)
            self._started = True
            self.cwd = target.cwd
            return target, safety

    def changes(self, limit: int = 200) -> List[str]:
        """Filesystem changes since the container was last (re)created."""
        with self._lock:
            self._ensure_started()
            _, out = self._docker("diff", self.container, timeout=60)
            lines = [line for line in out.splitlines() if line.strip()]
            return lines[:limit]

    def list_snapshots(self) -> List[dict]:
        with self._lock:
            return [s.describe() for s in self.snapshots]


def _wrap(command: str, cwd: str) -> str:
    """Run ``command`` in ``cwd`` and report the final directory so cd persists."""
    q = shlex.quote(cwd)
    return (
        f"cd {q} 2>/dev/null || {{ mkdir -p {q} && cd {q}; }}\n"
        f"{command}\n"
        "__rewind_rc=$?\n"
        f"printf '\\n{_CWD_MARKER}%s\\n' \"$(pwd)\"\n"
        "exit $__rewind_rc\n"
    )


def _split_cwd(out: str) -> Tuple[str, Optional[str]]:
    idx = out.rfind(_CWD_MARKER)
    if idx == -1:
        return out, None
    cwd, _, trailing = out[idx + len(_CWD_MARKER):].partition("\n")
    body = out[:idx]
    if body.endswith("\n"):  # the newline _wrap printed before the marker
        body = body[:-1]
    return body + trailing, cwd.strip() or None


def _decode(data) -> str:
    if data is None:
        return ""
    if isinstance(data, bytes):
        return data.decode("utf-8", errors="replace")
    return str(data)
