"""The Rewind sandbox: a Docker container whose filesystem can be rolled back.

Snapshots are ``docker commit`` images tagged ``hermes-rewind/<task>:<id>``.
Restoring replaces the container with a fresh one started from a snapshot
image. Docker commands go to the Engine API over the daemon socket when it can
be reached (see docker_api.py) and to the ``docker`` CLI otherwise, so the
plugin has no Python dependencies.
"""
from __future__ import annotations

import re
import shlex
import subprocess
import threading
import time
import uuid
from dataclasses import asdict, dataclass
from typing import Callable, Dict, List, Optional, Sequence, Tuple

from . import policy, registry
from .docker_api import ApiRunner

DEFAULT_IMAGE = "python:3.12-slim"
DEFAULT_CWD = "/workspace"
DEFAULT_MAX_SNAPSHOTS = 25
DEFAULT_COMPACT_MB = 256
# overlay2 refuses images deeper than ~125 layers. Each compaction adds one,
# so stop compacting well before that and let snapshots grow instead.
MAX_LAYERS = 100
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


@dataclass
class _Pending:
    """A snapshot committed in the background that nothing has claimed yet."""
    id: str
    image: str
    cwd: str
    created_at: float


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
        compact_mb: int = DEFAULT_COMPACT_MB,
        docker_api: bool = True,
        background: bool = True,
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
        self.compact_bytes = max(0, int(compact_mb)) * 1024 * 1024
        self.background = background
        self.docker_bin = docker_bin
        if runner is None:
            runner = ApiRunner(docker_bin, subprocess_runner) if docker_api else subprocess_runner
        self._run = runner

        slug = _SLUG.sub("-", task_id.lower()).strip("-")[:40] or "task"
        suffix = uuid.uuid4().hex[:6]
        self.container = f"hermes-rewind-{slug}-{suffix}"
        self.repository = f"hermes-rewind/{slug}-{suffix}"

        self.snapshots: List[Snapshot] = []
        self._dropped_images: List[str] = []
        self._seq = 0
        self._shell = "sh"
        self._started = False
        # The image the container is (re)started from: the base image at first,
        # then whichever snapshot was last restored.
        self._image = self.base_image
        # `docker diff` only sees changes since the container was created, so
        # changes from before a compaction are carried here. Path -> A/C/D.
        self._carried_changes: Dict[str, str] = {}
        self._image_info: Dict[str, Tuple[int, int]] = {}
        # Background snapshots: right after a command, the current state is
        # committed while the agent decides what to do next, and the next
        # command that needs a snapshot claims it instead of waiting for one.
        # Every entry point joins the worker before touching the container,
        # so the worker never runs alongside anything else.
        self._pending: Optional[_Pending] = None
        self._worker: Optional[threading.Thread] = None
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
        try:
            self._docker(*argv, timeout=900)
        except (RewindError, subprocess.TimeoutExpired, OSError):
            # A failed or timed-out run can leave a container behind under our
            # name, which would make every retry fail with a name conflict.
            self._docker("rm", "-f", self.container, timeout=60, check=False)
            raise
        self._image = image

    def _ensure_started(self) -> None:
        if self._started:
            return
        self._start_container(self._image)
        code, _ = self._docker("exec", self.container, "sh", "-c", "command -v bash", check=False)
        self._shell = "bash" if code == 0 else "sh"
        self._started = True

    # ----------------------------------------------------------- environment
    def execute(self, command: str, timeout: Optional[int] = None, **kwargs) -> dict:
        with self._lock:
            self._finish_background()
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
            try:
                self._ensure_started()  # in case a compaction could not restart it
            except (RewindError, subprocess.TimeoutExpired, OSError) as exc:
                return {"output": f"[rewind] could not start the sandbox: {exc}", "exit_code": 1}

            limit = timeout or self.timeout
            argv = [self.docker_bin, "exec", self.container, self._shell, "-c", _wrap(command, cwd)]
            try:
                code, out = self._run(argv, limit)
            except subprocess.TimeoutExpired as exc:
                code, out = 124, _decode(exc.output) + f"\n[rewind] command timed out after {limit}s"

            output, new_cwd = _split_cwd(out)
            if new_cwd:
                self.cwd = new_cwd
            # The state after this command is the state before the next one,
            # so capture it now, while the agent reads this output and decides
            # what to do. A read-only command leaves the pending snapshot valid.
            if self._pending is None:
                self._start_background()
            return {"output": note + output, "exit_code": code}

    def cleanup(self) -> None:
        with self._lock:
            self._finish_background()
            if self._started:
                self._docker("rm", "-f", self.container, timeout=60, check=False)
                self._started = False
            images = [s.image for s in self.snapshots] + self._dropped_images
            if self._pending is not None:
                images.append(self._pending.image)
                self._pending = None
            if images:
                self._docker("rmi", "-f", *images, timeout=120, check=False)
            self.snapshots.clear()
            self._dropped_images.clear()
            registry.remove(self)

    # -------------------------------------------------------------- snapshots
    def snapshot(self, label: str = "manual") -> Snapshot:
        with self._lock:
            self._finish_background()
            self._ensure_started()
            snap = self._take_snapshot(label=label or "manual", command="", auto=False)
            # The state is unchanged, so the next command can have a snapshot ready too.
            self._start_background()
            return snap

    def _take_snapshot(self, *, label: str, command: str, auto: bool, compact: bool = True) -> Snapshot:
        """Record the current state as a snapshot: the pending background one if
        there is one (it already holds this state), otherwise a fresh commit."""
        if self._pending is not None:
            pending, self._pending = self._pending, None
            snap = Snapshot(pending.id, pending.image, label, command, pending.cwd, pending.created_at, auto)
        else:
            pending = self._commit()
            snap = Snapshot(pending.id, pending.image, label, command, pending.cwd, pending.created_at, auto)
            if compact:
                self._maybe_compact(snap.image)
        self.snapshots.append(snap)
        self._prune()
        return snap

    def _commit(self) -> _Pending:
        self._seq += 1
        sid = f"s{self._seq}"
        image = f"{self.repository}:{sid}"
        self._docker("commit", "--message", f"rewind {sid}", self.container, image, timeout=300)
        return _Pending(sid, image, self.cwd, time.time())

    # ------------------------------------------------- background snapshots
    def _start_background(self) -> None:
        if not self.background or self.snapshot_mode == "off" or not self._started:
            return
        self._worker = threading.Thread(target=self._background_commit, name=f"rewind-{self.container}", daemon=True)
        self._worker.start()

    def _background_commit(self) -> None:
        try:
            pending = self._commit()
            self._maybe_compact(pending.image)
            self._pending = pending
        except (RewindError, subprocess.TimeoutExpired, OSError):
            self._pending = None  # the next command that needs a snapshot commits it itself

    def _finish_background(self) -> None:
        """Wait for a background commit. Called before anything uses the container."""
        worker, self._worker = self._worker, None
        if worker is not None:
            worker.join()

    def _maybe_compact(self, image: str) -> None:
        """Restart the container from ``image`` (a snapshot just taken) once its
        writable layer is big.

        ``docker commit`` saves everything changed since the container was
        created, so without this every snapshot after a 500 MB install would
        store those 500 MB again. Restarting from the snapshot just taken makes
        later snapshots hold only what changed since. It costs a restart, which
        stops background processes, so it only happens past ``compact_bytes``.
        """
        if not self.compact_bytes:
            return
        size, layers = self._inspect_image(image)
        base_size, _ = self._inspect_image(self._image)
        if not size or size - base_size < self.compact_bytes or layers >= MAX_LAYERS:
            return
        _, diff = self._docker("diff", self.container, timeout=120, check=False)
        self._docker("rm", "-f", self.container, timeout=60)
        self._started = False
        _merge_diff(self._carried_changes, diff)
        self._image = image  # a failed restart is retried from here, not the base image
        try:
            self._ensure_started()
        except (RewindError, subprocess.TimeoutExpired, OSError):
            pass  # execute() retries the start before running the command

    def _inspect_image(self, image: str) -> Tuple[int, int]:
        """Return (total size in bytes, layer count), or (0, 0) if unknown."""
        if image in self._image_info:
            return self._image_info[image]
        code, out = self._docker(
            "image", "inspect", "-f", "{{.Size}} {{len .RootFS.Layers}}", image, timeout=60, check=False
        )
        try:
            size, layers = (int(v) for v in out.split())
        except ValueError:
            return 0, 0
        if code == 0:
            self._image_info[image] = (size, layers)
        return size, layers

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
            self._finish_background()
            self._ensure_started()
            target = self.find(snapshot_id)
            # No compaction: the container is replaced right after anyway.
            safety = self._take_snapshot(
                label=f"before restoring {target.id}", command="", auto=False, compact=False
            )
            self._docker("rm", "-f", self.container, timeout=60)
            self._started = False
            # From here on, if anything fails the sandbox comes back as the
            # safety snapshot (the state just before this restore), never as
            # the empty base image.
            self._image = safety.image
            try:
                self._start_container(target.image)
            except (RewindError, subprocess.TimeoutExpired, OSError) as exc:
                try:
                    self._start_container(safety.image)
                    self._started = True
                except (RewindError, subprocess.TimeoutExpired, OSError):
                    pass  # the next command retries from the safety snapshot
                raise RewindError(
                    f"Could not restore {target.id} ({exc}). The sandbox is unchanged: "
                    f"it is in the state saved as {safety.id}."
                ) from exc
            self._started = True
            self._carried_changes.clear()
            self.cwd = target.cwd
            self._start_background()  # ready for the first change after the restore
            return target, safety

    def changes(self, limit: int = 200) -> List[str]:
        """Filesystem changes since the sandbox was created or last restored."""
        with self._lock:
            self._finish_background()
            self._ensure_started()
            _, out = self._docker("diff", self.container, timeout=60)
            merged = dict(self._carried_changes)
            _merge_diff(merged, out)
            return [f"{kind} {path}" for path, kind in sorted(merged.items())][:limit]

    def list_snapshots(self) -> List[dict]:
        with self._lock:
            return [s.describe() for s in self.snapshots]


def _merge_diff(changes: Dict[str, str], diff: str) -> None:
    """Fold newer ``docker diff`` output (lines like ``A /path``) into ``changes``."""
    for line in diff.splitlines():
        kind, _, path = line.strip().partition(" ")
        if kind not in ("A", "C", "D") or not path:
            continue
        before = changes.get(path)
        if before == "A" and kind == "D":
            del changes[path]  # created, then deleted again: no net change
        elif before == "A":
            pass  # still a new file
        elif before == "D" and kind == "A":
            changes[path] = "C"  # deleted, then recreated
        else:
            changes[path] = kind


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
