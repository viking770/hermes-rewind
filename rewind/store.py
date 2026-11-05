"""Snapshots that outlive the sandbox object, and cleanup of what nothing owns.

Hermes calls ``cleanup()`` both when a session ends and when its idle reaper
shuts a sandbox down after ``terminal.lifetime_seconds`` (5 minutes by
default). Rewind can't tell the two apart, so instead of deleting the
snapshots it *parks* them: the container is removed, the images stay, and a
small JSON file records them. The next sandbox Hermes creates for the same
task picks them up again, so undo history survives a coffee break or a
gateway restart. Parked snapshots expire after ``REWIND_KEEP_HOURS``.

Each record also names the process that owns a live sandbox. If that process
dies without cleaning up (crash, killed terminal, reboot), the next Rewind to
start finds the record, parks what it can and deletes the rest when it
expires. Containers and images that carry Rewind's label but have no record
and a dead owner are deleted outright.
"""
from __future__ import annotations

import hashlib
import json
import os
import socket
import time
from pathlib import Path
from typing import Callable, Dict, Iterator, List, Optional, Sequence, Tuple

FORMAT = 1
LABEL = "hermes.rewind"
PID_LABEL = "hermes.rewind.pid"
HOST_LABEL = "hermes.rewind.host"

Runner = Callable[[Sequence[str], Optional[float]], Tuple[int, str]]


def default_dir() -> Path:
    override = os.environ.get("REWIND_STATE_DIR")
    if override:
        return Path(override)
    home = os.environ.get("HERMES_HOME")
    return (Path(home) if home else Path.home() / ".hermes") / "rewind"


def hostname() -> str:
    return socket.gethostname()


def _key(task_id: str) -> str:
    return hashlib.sha1(task_id.encode("utf-8")).hexdigest()[:16]


class Store:
    """One JSON record per task under ``<dir>/sandboxes/``."""

    def __init__(self, root: Path) -> None:
        self.root = Path(root)
        self.dir = self.root / "sandboxes"

    def path(self, task_id: str) -> Path:
        return self.dir / f"{_key(task_id)}.json"

    def load(self, task_id: str) -> Optional[dict]:
        record = _read(self.path(task_id))
        return record if record and record.get("task_id") == task_id else None

    def save(self, record: dict) -> None:
        self.dir.mkdir(parents=True, exist_ok=True)
        _owner_only(self.root, 0o700)
        _owner_only(self.dir, 0o700)
        record = {**record, "format": FORMAT, "updated_at": time.time()}
        path = self.path(record["task_id"])
        tmp = path.with_suffix(f".{os.getpid()}.tmp")
        # Created owner-only from the start, so it is never readable by others, even briefly.
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(json.dumps(record, indent=1))
        os.replace(tmp, path)
        _owner_only(path, 0o600)

    def delete(self, task_id: str) -> None:
        try:
            self.path(task_id).unlink()
        except FileNotFoundError:
            pass

    def records(self) -> Iterator[dict]:
        if not self.dir.is_dir():
            return
        for path in sorted(self.dir.glob("*.json")):
            record = _read(path)
            if record and record.get("task_id"):
                yield record


def _owner_only(path: Path, mode: int) -> None:
    """chmod on POSIX. On Windows the folder under the user profile is already
    private to the user, and chmod can't express ACLs anyway."""
    if os.name != "nt":
        try:
            os.chmod(path, mode)
        except OSError:
            pass


def _read(path: Path) -> Optional[dict]:
    try:
        record = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return record if isinstance(record, dict) and record.get("format") == FORMAT else None


def record_images(record: dict) -> List[str]:
    """Every image a record keeps alive: snapshots, the parked state, pruned leftovers."""
    images = [s.get("image") for s in record.get("snapshots", [])]
    images += [record.get("image"), *record.get("dropped_images", [])]
    base = record.get("base_image")
    return sorted({i for i in images if i and i != base and i.startswith("hermes-rewind/")})


def is_expired(record: dict, now: Optional[float] = None) -> bool:
    expires = record.get("expires_at")
    return expires is not None and (now or time.time()) >= float(expires)


def pid_alive(pid: Optional[int]) -> bool:
    """Whether a process with this id is running on this machine. Unknown counts as alive."""
    if not pid:
        return True
    pid = int(pid)
    if pid == os.getpid():
        return True
    if os.name == "nt":
        return _pid_alive_windows(pid)
    try:
        os.kill(pid, 0)  # signal 0 only checks; on Windows os.kill would terminate instead
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return True
    return True


def _pid_alive_windows(pid: int) -> bool:
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.restype = wintypes.HANDLE
    process_query_limited_information, still_active, access_denied = 0x1000, 259, 5
    handle = kernel32.OpenProcess(process_query_limited_information, False, pid)
    if not handle:
        return ctypes.get_last_error() == access_denied  # exists, just not ours to open
    try:
        code = wintypes.DWORD()
        if not kernel32.GetExitCodeProcess(handle, ctypes.byref(code)):
            return True
        return code.value == still_active
    finally:
        kernel32.CloseHandle(handle)


# ------------------------------------------------------------------ purging
def purge(store: Store, run: Runner, *, docker_bin: str = "docker") -> Dict[str, int]:
    """Delete every parked sandbox's snapshots and record now, without waiting for
    them to expire. Sandboxes a live process is using are left alone."""
    counts = {"purged": 0, "skipped_live": 0}
    for record in list(store.records()):
        if record.get("status") == "live" and record.get("host") in (None, hostname()) \
                and pid_alive(record.get("owner_pid")):
            counts["skipped_live"] += 1
            continue
        repo = record.get("repository", "")
        images = set(record_images(record))
        if repo.startswith("hermes-rewind/"):
            try:
                code, out = run([docker_bin, "images", repo, "--format", "{{.Repository}}:{{.Tag}}"], 60)
            except Exception:
                code, out = 1, ""
            if code == 0:
                images |= {i.strip() for i in out.splitlines() if i.strip().startswith(repo + ":")}
        container = record.get("container") or ""
        try:
            if container.startswith("hermes-rewind-"):
                run([docker_bin, "rm", "-f", container], 60)
            if images:
                run([docker_bin, "rmi", "-f", *sorted(images)], 300)
        except Exception:
            pass
        store.delete(record["task_id"])
        counts["purged"] += 1
    return counts


# ------------------------------------------------------------------ reaping
def reap(store: Store, run: Runner, *, keep_seconds: float, live_repositories: Sequence[str] = (),
         docker_bin: str = "docker", now: Optional[float] = None) -> Dict[str, int]:
    """Delete expired snapshots and leftovers whose owner is gone. Returns counts.

    ``live_repositories`` are image repositories this process is using right now;
    they are never touched. Records owned by another live process are skipped.
    """
    now = now or time.time()
    host = hostname()
    live = set(live_repositories)
    counts = {"expired": 0, "recovered": 0, "containers": 0, "images": 0}

    def docker(*args: str, timeout: float = 120.0) -> Tuple[int, str]:
        try:
            return run([docker_bin, *args], timeout)
        except Exception as exc:  # a missing daemon must never break the caller
            return 1, str(exc)

    known_repositories = set()
    for record in list(store.records()):
        repo = record.get("repository", "")
        known_repositories.add(repo)
        if repo in live:
            continue
        if record.get("status") == "live":
            if record.get("host") not in (None, host) or pid_alive(record.get("owner_pid")):
                continue
            # The owner died without cleaning up: keep what it had, as if it had parked.
            container = record.get("container")
            if container:
                image = f"{repo}:recovered"
                code, _ = docker("commit", "--message", "rewind recovered", container, image, timeout=300)
                if code == 0:
                    record["image"] = image
                docker("rm", "-f", container, timeout=60)
            record.update(status="parked", parked_at=now, expires_at=record.get("updated_at", now) + keep_seconds,
                          owner_pid=None, container=None)
            store.save(record)
            counts["recovered"] += 1
        if record.get("status") == "parked" and is_expired(record, now):
            images = set(record_images(record))
            if repo.startswith("hermes-rewind/"):  # plus any the record missed (e.g. after a crash)
                code, out = docker("images", repo, "--format", "{{.Repository}}:{{.Tag}}", timeout=60)
                if code == 0:
                    images |= {i.strip() for i in out.splitlines() if i.strip().startswith(repo + ":")}
            images = sorted(images)
            if images:
                docker("rmi", "-f", *images, timeout=300)
            store.delete(record["task_id"])
            counts["expired"] += 1

    # Labelled leftovers no record knows about, from a dead process on this machine.
    fmt = '{{.ID}}\t{{.Label "%s"}}\t{{.Label "%s"}}\t%s'
    code, out = docker("ps", "-a", "--filter", f"label={LABEL}=1", "--format",
                       fmt % (PID_LABEL, HOST_LABEL, "{{.Image}}"), timeout=60)
    if code == 0:
        for line in out.splitlines():
            cid, pid, chost, image = (line.split("\t") + ["", "", "", ""])[:4]
            repo = image.rpartition(":")[0] if image.startswith("hermes-rewind/") else ""
            if not cid or not pid or chost != host or repo in live or repo in known_repositories:
                continue
            if not pid_alive(int(pid) if pid.isdigit() else None):
                docker("rm", "-f", cid, timeout=60)
                counts["containers"] += 1
    # `docker images` can filter by label but not print one, so list, then inspect.
    code, out = docker("images", "--filter", f"label={LABEL}=1", "--format", "{{.Repository}}:{{.Tag}}",
                       timeout=60)
    tagged = [line.strip() for line in out.splitlines()
              if line.strip().startswith("hermes-rewind/") and not line.strip().endswith(":<none>")]
    if code == 0 and tagged:
        inspect_fmt = ('{{index .Config.Labels "%s"}}\t{{index .Config.Labels "%s"}}\t'
                       '{{join .RepoTags ","}}' % (PID_LABEL, HOST_LABEL))
        code, out = docker("image", "inspect", "-f", inspect_fmt, *tagged, timeout=120)
    if code == 0 and tagged:
        orphans = []
        for line in out.splitlines():
            pid, ihost, tags = (line.split("\t") + ["", "", ""])[:3]
            image = next((t for t in tags.split(",") if t.startswith("hermes-rewind/")), "")
            repo = image.rpartition(":")[0]
            if not image.startswith("hermes-rewind/") or not pid or ihost != host:
                continue
            if repo in live or repo in known_repositories:
                continue
            if not pid_alive(int(pid) if pid.isdigit() else None):
                orphans.append(image)
        if orphans:
            docker("rmi", "-f", *orphans, timeout=300)
            counts["images"] += len(orphans)
    return counts
