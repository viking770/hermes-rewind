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
import re
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
    if not isinstance(record, dict) or record.get("format") != FORMAT:
        return None
    return record if is_valid_record(record) else None


# What Rewind itself writes. Anything else in a record (edited by hand, or by
# something that shouldn't) is rejected, so no record field can become an
# arbitrary container name, image or docker option.
REPOSITORY_RE = re.compile(r"hermes-rewind/[a-z0-9][a-z0-9-]{0,100}")
CONTAINER_RE = re.compile(r"hermes-rewind-[a-z0-9][a-z0-9-]{0,100}")
_TAG_RE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}")
_IMAGE_REF_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/:@+-]{0,255}")


def is_valid_record(record: dict) -> bool:
    try:
        repo = record.get("repository")
        if not isinstance(record.get("task_id"), str) or not record["task_id"]:
            return False
        if not isinstance(repo, str) or not REPOSITORY_RE.fullmatch(repo):
            return False

        def own_image(image) -> bool:
            if not isinstance(image, str):
                return False
            name, _, tag = image.rpartition(":")
            return name == repo and bool(_TAG_RE.fullmatch(tag))

        base = record.get("base_image")
        if base is not None and not (isinstance(base, str) and _IMAGE_REF_RE.fullmatch(base)):
            return False
        image = record.get("image")
        if image not in (None, "") and not (own_image(image) or image == base):
            return False
        container = record.get("container")
        # A sandbox's container is named after its own repository
        # (hermes-rewind/<name> -> hermes-rewind-<name>), so a record can't name
        # another chat's container for Rewind to commit or remove.
        if container is not None and not (isinstance(container, str) and CONTAINER_RE.fullmatch(container)
                                          and container == "hermes-rewind-" + repo.split("/", 1)[1]):
            return False
        snapshots = record.get("snapshots", [])
        if not isinstance(snapshots, list) or not all(
                isinstance(s, dict) and own_image(s.get("image")) for s in snapshots):
            return False
        for snap in snapshots:  # field types, so describing a snapshot can't fail later
            if "created_at" in snap and (not isinstance(snap["created_at"], (int, float))
                                         or isinstance(snap["created_at"], bool)):
                return False
            if "id" in snap and not (isinstance(snap["id"], str) and _TAG_RE.fullmatch(snap["id"])):
                return False
            for key in ("label", "command", "cwd", "parent"):
                if key in snap and not isinstance(snap[key], str):
                    return False
        dropped = record.get("dropped_images", [])
        if not isinstance(dropped, list) or not all(own_image(i) for i in dropped):
            return False
        for key in ("owner_pid", "seq"):
            value = record.get(key)
            if value is not None and (not isinstance(value, int) or isinstance(value, bool) or value < 0):
                return False
        for key in ("expires_at", "parked_at", "updated_at"):
            value = record.get(key)
            if value is not None and not isinstance(value, (int, float)):
                return False
        cwd = record.get("cwd")
        if cwd is not None and not (isinstance(cwd, str) and cwd.startswith("/") and "\n" not in cwd):
            return False
        return record.get("status") in ("live", "parked")
    except (TypeError, AttributeError):
        return False


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
        def docker(*args, timeout=120.0):
            try:
                return run([docker_bin, *args], timeout)
            except Exception as exc:
                return 1, str(exc)

        container = record.get("container") or ""
        if container:  # a dead owner's container (validated as Rewind's own when read)
            docker("rm", "-f", container, timeout=60)
            docker("rm", "-f", f"{container}-net", timeout=60)  # its network holder, if any
        _delete_record(store, record, docker)
        counts["purged"] += 1
    return counts


# ------------------------------------------------------------------ reaping
def _delete_record(store: Store, record: dict, docker) -> None:
    """Delete a parked sandbox: every image in its repository, then its record."""
    repo = record.get("repository", "")
    images = set(record_images(record))
    if repo.startswith("hermes-rewind/"):  # plus any the record missed (e.g. after a crash)
        code, out = docker("images", repo, "--format", "{{.Repository}}:{{.Tag}}", timeout=60)
        if code == 0:
            images |= {i.strip() for i in out.splitlines() if i.strip().startswith(repo + ":")}
    if images:
        docker("rmi", "-f", *sorted(images), timeout=300)
    store.delete(record["task_id"])


def record_bytes(record: dict, docker) -> int:
    """Roughly how much disk a parked sandbox's own images use: each image's size
    minus the image it was committed on top of (shared base layers aren't counted)."""
    images = record_images(record)
    parents = {s.get("image"): s.get("parent") for s in record.get("snapshots", [])}
    base = record.get("base_image") or ""
    wanted = sorted(set(images) | {p for p in parents.values() if p} | ({base} if base else set()))
    if not wanted:
        return 0
    code, out = docker("image", "inspect", "-f", "{{.Size}}", *wanted, timeout=120)
    sizes = {}
    if code == 0:
        for name, line in zip(wanted, out.splitlines()):
            sizes[name] = int(line.strip()) if line.strip().isdigit() else 0
    total = 0
    for image in images:
        parent = parents.get(image) or base
        total += max(0, sizes.get(image, 0) - sizes.get(parent, 0))
    return total


def reap(store: Store, run: Runner, *, keep_seconds: float, live_repositories: Sequence[str] = (),
         docker_bin: str = "docker", now: Optional[float] = None, max_parked_bytes: int = 0) -> Dict[str, int]:
    """Delete expired snapshots and leftovers whose owner is gone. Returns counts.

    ``live_repositories`` are image repositories this process is using right now;
    they are never touched. Records owned by another live process are skipped.
    With ``max_parked_bytes``, parked sandboxes are also deleted oldest first
    until together they use no more than that.
    """
    now = now or time.time()
    host = hostname()
    live = set(live_repositories)
    counts = {"expired": 0, "recovered": 0, "containers": 0, "images": 0, "over_size_cap": 0}

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
                docker("rm", "-f", f"{container}-net", timeout=60)
            record.update(status="parked", parked_at=now, expires_at=record.get("updated_at", now) + keep_seconds,
                          owner_pid=None, container=None)
            store.save(record)
            counts["recovered"] += 1
        if record.get("status") == "parked" and is_expired(record, now):
            _delete_record(store, record, docker)
            counts["expired"] += 1

    # The size cap: oldest parked sandboxes go first. Live ones are never touched.
    if max_parked_bytes:
        parked = sorted((r for r in store.records()
                         if r.get("status") == "parked" and r.get("repository") not in live),
                        key=lambda r: float(r.get("parked_at") or r.get("updated_at") or 0))
        sized = [(r, record_bytes(r, docker)) for r in parked]
        total = sum(size for _, size in sized)
        for record, size in sized:
            if total <= max_parked_bytes:
                break
            _delete_record(store, record, docker)
            total -= size
            counts["over_size_cap"] += 1

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
