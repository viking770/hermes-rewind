"""The Rewind sandbox: a Docker container whose filesystem can be rolled back.

Snapshots are ``docker commit`` images tagged ``hermes-rewind/<task>:<id>``.
Restoring replaces the container with a fresh one started from a snapshot
image. Docker commands go to the Engine API over the daemon socket when it can
be reached (see docker_api.py) and to the ``docker`` CLI otherwise, so the
plugin has no Python dependencies.
"""
from __future__ import annotations

import base64
import contextlib
import ipaddress
import os
import posixpath
import re
import shlex
import shutil
import socket
import subprocess
import tarfile
import tempfile
import threading
import time
import uuid
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable, Dict, List, Optional, Sequence, Tuple

from . import audit, policy, registry, store as store_mod
from .docker_api import ApiRunner
from .redact import redact
from .store import Store

# Pinned by digest: a tag on Docker Hub can be re-pointed, a digest can't. This is the
# multi-platform index (amd64, arm64, ...) of python:3.12-slim built 2026-10-28.
# To update: `docker pull python:3.12-slim` then
# `docker image inspect python:3.12-slim -f "{{index .RepoDigests 0}}"`.
SLIM_IMAGE = "python:3.12-slim@sha256:aa943ce411423c7582288f18707ff66eddcbaeb510502d747a72aeb34f30d159"
# The default sandbox image: the pinned slim image plus git and curl, built
# locally once per machine, so "clone a repo" works in a fresh sandbox without
# an apt-get first. Bump the tag when the Dockerfile changes. If it can't be
# built (offline, say), the sandbox starts from SLIM_IMAGE. REWIND_IMAGE overrides both.
TOOLS_IMAGE = "hermes-rewind-base:1"
_TOOLS_DOCKERFILE = (
    f"FROM {SLIM_IMAGE}\n"
    "RUN apt-get update && apt-get install -y --no-install-recommends git curl ca-certificates "
    "&& rm -rf /var/lib/apt/lists/*\n"
)
DEFAULT_IMAGE = TOOLS_IMAGE
DEFAULT_CWD = "/workspace"
DEFAULT_MAX_SNAPSHOTS = 25
DEFAULT_COMPACT_MB = 256
DEFAULT_KEEP_HOURS = 24
DEFAULT_EXPORT_MAX_MB = 500
DEFAULT_EXPORT_TOTAL_MB = 2000
# Lists files under /workspace as "path<TAB>size<TAB>mtime" for restore summaries.
_LIST_FILES = (
    f"cd {DEFAULT_CWD} 2>/dev/null && find . -xdev \\( -type f -o -type l \\) "
    "-printf '%P\\t%s\\t%T@\\n' 2>/dev/null | head -n 20000"
)
_SUMMARY_LIMIT = 20

# ------------------------------------------------------------- hardening
# The same baseline as Hermes's own Docker backend: drop every capability and
# add back only what package managers need (file ownership, and setuid/setgid
# so apt can drop to its _apt user), and forbid gaining privileges.
_SECURITY_ARGS = (
    "--cap-drop", "ALL",
    "--cap-add", "CHOWN", "--cap-add", "DAC_OVERRIDE", "--cap-add", "FOWNER",
    "--cap-add", "SETUID", "--cap-add", "SETGID",
    "--security-opt", "no-new-privileges",
)
DEFAULT_PIDS_LIMIT = 2048  # Hermes's default; a fork bomb stops here
DEFAULT_CPUS = 1.0  # Hermes's terminal.container_cpu default
DEFAULT_MEMORY_MB = 5120  # Hermes's terminal.container_memory default
_LIMIT_ERROR = re.compile(r"cgroup|NanoCPUs|pids|memory limit|Minimum memory|cpus", re.IGNORECASE)

NETWORK_MODES = ("internet", "none", "full")
# Destinations the sandbox may not reach in "internet" mode: this computer
# (Docker Desktop's host.docker.internal is 192.168.65.254), the LAN, carrier
# NAT, link-local and cloud metadata (169.254.169.254), multicast, reserved, and
# Azure's platform address 168.63.129.16 (WireServer: VM configuration on port 80,
# and the default DNS resolver on Azure VMs, so not in any private range).
_BLOCKED_V4 = ("0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "168.63.129.16/32",
               "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.168.0.0/16", "198.18.0.0/15",
               "224.0.0.0/4", "240.0.0.0/4")
# NAT64 (64:ff9b::/96, 64:ff9b:1::/48) and 6to4 (2002::/16) embed IPv4 addresses,
# so they could reach the blocked IPv4 ranges through a translator.
_BLOCKED_V6 = ("::1/128", "::ffff:0:0/96", "64:ff9b::/96", "64:ff9b:1::/48", "2002::/16",
               "fc00::/7", "fe80::/10", "ff00::/8")
GUARD_IMAGE = "hermes-rewind-netguard:2"  # bump when the Dockerfile or its base changes
_GUARD_OK = "REWIND_GUARD_OK"
_GUARD_DOCKERFILE = (
    f"FROM {SLIM_IMAGE}\n"
    "RUN apt-get update && apt-get install -y --no-install-recommends iptables "
    "&& rm -rf /var/lib/apt/lists/*\n"
)


def _clean_addresses(addresses: Sequence[str]) -> List[str]:
    """Valid, specific IP addresses only, deduplicated, in a stable order.
    Everything here ends up in a shell script, so nothing else gets through."""
    out: List[str] = []
    for raw in addresses:
        try:
            ip = ipaddress.ip_address(str(raw).split("%", 1)[0].strip())
        except ValueError:
            continue
        if ip.is_unspecified or ip.is_loopback:
            continue
        if str(ip) not in out:
            out.append(str(ip))
    return out


_HOST_CACHE_SECONDS = 300.0
_HOSTNAME_LOOKUP_SECONDS = 1.0
_host_cache: Tuple[float, List[str]] = (0.0, [])
_host_cache_lock = threading.Lock()


def _hostname_addresses(timeout: float) -> List[str]:
    """Addresses the hostname resolves to, giving up after ``timeout``: on macOS
    resolving the machine's own name can block for ~30 s (an mDNS timeout),
    and this runs on every sandbox start."""
    found: List[str] = []

    def work() -> None:
        try:
            found.extend(info[4][0] for info in socket.getaddrinfo(socket.gethostname(), None))
        except (OSError, UnicodeError):
            pass

    worker = threading.Thread(target=work, name="rewind-hostname", daemon=True)
    worker.start()
    worker.join(timeout)
    return list(found) if not worker.is_alive() else []


def host_addresses() -> List[str]:
    """This computer's own addresses, as seen by the plugin process.

    On a server with a public IP, the blocked private ranges don't cover the
    host itself: a sandbox could reach anything listening on 0.0.0.0 (Hermes's
    gateway, databases, admin panels) through that public address. Found from
    the source address the system would use to reach the internet (a UDP
    connect, which sends no packets and returns at once) and from the hostname
    (time-boxed). Cached for a few minutes: the guard runs on every restart."""
    global _host_cache
    with _host_cache_lock:
        cached_at, cached = _host_cache
        if cached and time.monotonic() - cached_at < _HOST_CACHE_SECONDS:
            return list(cached)
        found: List[str] = []
        for family, probe in ((socket.AF_INET, "192.0.2.1"), (socket.AF_INET6, "2001:db8::1")):
            try:
                with socket.socket(family, socket.SOCK_DGRAM) as sock:
                    sock.connect((probe, 9))
                    found.append(sock.getsockname()[0])
            except OSError:
                pass
        found += _hostname_addresses(_HOSTNAME_LOOKUP_SECONDS)
        result = _clean_addresses(found)
        _host_cache = (time.monotonic(), result)
        return list(result)


def _guard_script(nameservers: Sequence[str], host_ips: Sequence[str] = ()) -> str:
    """Shell for the guard helper: allow loopback and DNS to the sandbox's own
    resolvers, reject every blocked range and this computer's own addresses,
    then confirm the rules are in. Fails (no OK) when the sandbox has IPv6 but
    it can't be filtered, so the caller starts it with no network instead."""
    nameservers = _clean_addresses(nameservers)
    host_ips = _clean_addresses(host_ips)
    v4 = [ns for ns in nameservers if ":" not in ns]
    v6 = [ns for ns in nameservers if ":" in ns]
    lines = ["set -e", "iptables -A OUTPUT -o lo -j ACCEPT"]
    # A resolver is reachable for DNS only, wherever it is: on cloud VMs it can be a
    # platform address that serves more than DNS (Azure's 168.63.129.16 serves the
    # VM's configuration on port 80), and it may sit outside every blocked range.
    for ns in v4:
        lines += [f"iptables -A OUTPUT -d {ns} -p {p} --dport 53 -j ACCEPT" for p in ("udp", "tcp")]
        lines.append(f"iptables -A OUTPUT -d {ns} -j REJECT")
    lines += [f"iptables -A OUTPUT -d {net} -j REJECT" for net in _BLOCKED_V4]
    lines += [f"iptables -A OUTPUT -d {ip}/32 -j REJECT" for ip in host_ips if ":" not in ip]
    v6_rules = ["ip6tables -A OUTPUT -o lo -j ACCEPT"]
    for ns in v6:
        v6_rules += [f"ip6tables -A OUTPUT -d {ns} -p {p} --dport 53 -j ACCEPT" for p in ("udp", "tcp")]
        v6_rules.append(f"ip6tables -A OUTPUT -d {ns} -j REJECT")
    v6_rules += [f"ip6tables -A OUTPUT -d {net} -j REJECT" for net in _BLOCKED_V6]
    v6_rules += [f"ip6tables -A OUTPUT -d {ip}/128 -j REJECT" for ip in host_ips if ":" in ip]
    v6_rules.append("ip6tables -S OUTPUT | grep -q REJECT")
    # IPv6 is often disabled in containers. When it's on, it must be filtered:
    # an address on any interface but lo with no ip6tables means fail closed.
    lines += [
        "if ip6tables -S OUTPUT >/dev/null 2>&1; then",
        # One rule per line, so `set -e` stops at any that fails (in an && list it wouldn't).
        *("  " + rule for rule in v6_rules),
        "elif [ -r /proc/net/if_inet6 ] && grep -qv ' lo$' /proc/net/if_inet6; then",
        "  echo 'IPv6 is enabled in the sandbox but ip6tables cannot filter it'; exit 1",
        "fi",
        f"iptables -S OUTPUT | grep -q REJECT && echo {_GUARD_OK}",
    ]
    return "\n".join(lines)


def _default_gateways(route_table: str) -> List[str]:
    """IPv4 default gateways from the text of /proc/net/route (hex, little-endian)."""
    found = []
    for line in route_table.splitlines()[1:]:
        cols = line.split()
        if len(cols) > 2 and cols[1] == "00000000" and re.fullmatch(r"[0-9A-Fa-f]{8}", cols[2]):
            found.append(socket.inet_ntoa(bytes.fromhex(cols[2])[::-1]))
    return [g for g in found if g != "0.0.0.0"]
# overlay2 refuses images deeper than ~125 layers. Each compaction adds one,
# so stop compacting well before that and let snapshots grow instead.
MAX_LAYERS = 100
_CWD_MARKER = "__REWIND_CWD__"
# Base64 characters per command. Linux allows 128 KB per argument, but on Windows
# the whole `docker` command line is capped at 32,767 characters (CreateProcess),
# which the CLI path hits; the API path has no such limit but the smaller size
# costs it only a few more fast calls.
_STDIN_CHUNK = 24 * 1024 if os.name == "nt" else 96 * 1024
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
    # Saved by restore() just before it rolled back, so the restore can be
    # undone. "last" skips these, so repeating a restore is harmless.
    restore_point: bool = False
    # The image the container was started from when this was committed. The
    # snapshot's own data is roughly its size minus the parent's.
    parent: str = ""

    @classmethod
    def from_dict(cls, data: dict) -> "Snapshot":
        fields = cls.__dataclass_fields__
        return cls(**{k: v for k, v in data.items() if k in fields})

    def describe(self) -> dict:
        info = asdict(self)
        info["age_seconds"] = round(time.time() - self.created_at, 1)
        info["state"] = self.state()
        return info

    def state(self) -> str:
        """What the snapshot holds, in words. A snapshot is the state *before*
        its command ran, which models (and people) easily misread."""
        if self.restore_point:
            return f"{self.label} (restore this to undo that restore)"
        if self.auto and self.command:
            return f"state before running: {self.command}"
        return f"checkpoint: {self.label}"


@dataclass
class _Pending:
    """A snapshot committed in the background that nothing has claimed yet."""
    id: str
    image: str
    cwd: str
    created_at: float
    parent: str = ""


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
        network="internet",
        compact_mb: int = DEFAULT_COMPACT_MB,
        docker_api: bool = True,
        background: bool = True,
        runner: Optional[Runner] = None,
        docker_bin: str = "docker",
        keep_hours: float = 0,
        store: Optional[Store] = None,
        export_max_mb: int = DEFAULT_EXPORT_MAX_MB,
        export_total_mb: int = DEFAULT_EXPORT_TOTAL_MB,
        cpus: Optional[float] = DEFAULT_CPUS,
        memory_mb: Optional[int] = DEFAULT_MEMORY_MB,
        pids_limit: Optional[int] = DEFAULT_PIDS_LIMIT,
    ) -> None:
        if snapshot_mode not in policy.MODES:
            raise ValueError(f"snapshot_mode must be one of {policy.MODES}, got {snapshot_mode!r}")
        self.task_id = task_id
        self.cwd = cwd if cwd and cwd.startswith("/") else DEFAULT_CWD
        self.timeout = timeout
        self.base_image = image or DEFAULT_IMAGE
        self.snapshot_mode = snapshot_mode
        self.max_snapshots = max(1, int(max_snapshots))
        # True/False are the pre-0.2.1 spelling: on = "internet" (now firewalled), off = "none".
        mode = {True: "internet", False: "none"}.get(network, network)
        if mode not in NETWORK_MODES:
            raise ValueError(f"network must be one of {NETWORK_MODES}, got {network!r}")
        self.network_mode = mode
        self.network = mode != "none"
        self._limits: List[str] = []
        if pids_limit:
            self._limits += ["--pids-limit", str(int(pids_limit))]
        if cpus:
            self._limits += ["--cpus", f"{float(cpus):g}"]
        if memory_mb:
            self._limits += ["--memory", f"{int(memory_mb)}m"]
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
        self._cwd_from_restore = False
        self._lock = threading.RLock()
        # Parking (see store.py): with a store and keep_hours > 0, cleanup()
        # keeps the snapshots so the next sandbox for this task resumes them.
        self.keep_seconds = max(0.0, float(keep_hours)) * 3600
        self._store = store
        self.export_max_mb = export_max_mb
        self.export_total_mb = export_total_mb
        self.last_export_removed: List[str] = []
        self._tar_reader = _popen_tar_reader  # tests swap in a fake
        self._host_addresses = host_addresses  # tests swap in a fake
        self._note = ""  # said once, with the next command's output
        self.last_restore_changes: Optional[dict] = None
        if store is not None:
            try:
                self._adopt()
            except (OSError, ValueError, KeyError, TypeError):
                pass  # a damaged record must never stop the sandbox from starting
        registry.add(task_id, self)

    # ------------------------------------------------------------------ docker
    def _docker(self, *args: str, timeout: float = 120.0, check: bool = True) -> Tuple[int, str]:
        code, out = self._run([self.docker_bin, *args], timeout)
        if check and code != 0:
            raise RewindError(f"docker {args[0]} failed (exit {code}): {out.strip()[-500:]}")
        return code, out

    def _start_container(self, image: str) -> None:
        if not image or image.startswith("-"):  # never let an image name become a docker option
            raise RewindError(f"Refusing to start the sandbox from image {image!r}.")
        if image == TOOLS_IMAGE:
            image = self._ensure_tools_image()
        mode = self.network_mode
        try:
            self._run_container(image, "none" if mode == "none" else "bridge")
        except RewindError as exc:
            if not self._limits or not _LIMIT_ERROR.search(str(exc)):
                raise
            # This Docker can't apply cgroup limits (e.g. an unprivileged LXC host).
            self._limits = []
            audit.log("limits_unavailable", task_id=self.task_id, error=str(exc)[:200])
            self._note += ("[rewind] warning: this Docker can't apply CPU/memory/process limits, "
                           f"so the sandbox runs without them ({str(exc)[:200]}).\n")
            try:
                self._run_container(image, "none" if mode == "none" else "bridge")
            except RewindError as retry_exc:
                raise RewindError(f"{retry_exc} (after: {str(exc)[:300]})") from exc
        self._image = image
        if mode == "internet":
            try:
                self._guard_network()
            except (RewindError, subprocess.TimeoutExpired, OSError) as exc:
                # Fail closed: a sandbox that can reach this computer is worse than one with no network.
                self._docker("rm", "-f", self.container, timeout=60, check=False)
                self._run_container(image, "none")
                audit.log("network_guard_failed", task_id=self.task_id, error=str(exc)[:200],
                          fallback="no network")
                self._note += (
                    "[rewind] warning: couldn't firewall the sandbox's network, so it has no network "
                    f"this time ({str(exc)[:200]}). Set REWIND_NETWORK=full to allow unrestricted access.\n"
                )

    def _run_container(self, image: str, network: str) -> None:
        argv = [
            "run", "-d",
            "--name", self.container,
            "--label", "hermes.rewind=1",
            "--label", f"hermes.rewind.task={self.task_id}",
            # Who owns it, so a later Rewind can tell a crashed owner's leftovers
            # from a sandbox another live process is using (store.reap).
            "--label", f"{store_mod.PID_LABEL}={os.getpid()}",
            "--label", f"{store_mod.HOST_LABEL}={store_mod.hostname()}",
            *_SECURITY_ARGS, *self._limits,
        ]
        if network == "none":
            argv += ["--network", "none"]
        # The starting directory is created only in a brand-new sandbox. A restored or
        # resumed one keeps its files as they were: a folder the agent deleted stays deleted.
        dirs = [DEFAULT_CWD] + ([self.cwd] if image == self.base_image and self.cwd != DEFAULT_CWD else [])
        keepalive = f"mkdir -p {' '.join(shlex.quote(d) for d in dirs)}; while :; do sleep 3600; done"
        argv += ["--entrypoint", "/bin/sh", image, "-c", keepalive]
        # The first run may pull the image, which can take a while.
        try:
            self._docker(*argv, timeout=900)
        except (RewindError, subprocess.TimeoutExpired, OSError):
            # A failed or timed-out run can leave a container behind under our
            # name, which would make every retry fail with a name conflict.
            self._docker("rm", "-f", self.container, timeout=60, check=False)
            self._wait_until_gone()
            raise

    def _wait_until_gone(self, seconds: float = 15.0) -> None:
        """Wait until no container has our name. A forced removal can still be
        finishing when `docker rm -f` returns, and a retry would then collide."""
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            try:
                code, _ = self._docker("container", "inspect", "--format", "{{.Id}}", self.container,
                                       timeout=30, check=False)
            except (subprocess.TimeoutExpired, OSError):
                return
            if code != 0:
                return
            self._docker("rm", "-f", self.container, timeout=60, check=False)
            time.sleep(0.5)

    # --------------------------------------------------------- network guard
    def _guard_network(self) -> None:
        """Block the host, private networks and cloud metadata from inside the
        sandbox's network namespace, leaving DNS and the internet reachable.

        A short-lived helper container joins the sandbox's namespace with
        NET_ADMIN and installs the rules. The sandbox itself runs with every
        capability dropped, so nothing inside it can change them back.
        """
        self._ensure_guard_image()
        _, resolv = self._docker("exec", self.container, "cat", "/etc/resolv.conf", timeout=30, check=False)
        servers = [line.split()[1] for line in resolv.splitlines()
                   if line.startswith("nameserver") and len(line.split()) > 1
                   and re.fullmatch(r"[0-9a-fA-F:.]+", line.split()[1])]
        # This computer as the sandbox sees it: its gateway (usually the host's
        # side of the Docker network), plus the host's own addresses.
        _, routes = self._docker("exec", self.container, "cat", "/proc/net/route", timeout=30, check=False)
        host_ips = _default_gateways(routes) + self._host_addresses()
        code, out = self._docker(
            "run", "--rm", "--network", f"container:{self.container}",
            "--cap-drop", "ALL", "--cap-add", "NET_ADMIN", "--entrypoint", "sh", GUARD_IMAGE,
            "-c", _guard_script(servers, host_ips), timeout=120, check=False,
        )
        if code != 0 or _GUARD_OK not in out:
            raise RewindError(f"network rules failed (exit {code}): {out.strip()[-300:]}")

    def _ensure_tools_image(self) -> str:
        """Build the default image (slim + git + curl) if this machine doesn't
        have it yet, and return the image to start from: it, or the plain slim
        image when it can't be built."""
        if self._inspect_image_exists(TOOLS_IMAGE):
            return TOOLS_IMAGE
        started = time.time()
        try:
            with tempfile.TemporaryDirectory(prefix="rewind-base-") as build_dir:
                Path(build_dir, "Dockerfile").write_text(_TOOLS_DOCKERFILE, encoding="utf-8")
                self._docker("build", "--quiet", "-t", TOOLS_IMAGE, build_dir, timeout=900)
        except (RewindError, subprocess.TimeoutExpired, OSError) as exc:
            audit.log("base_image_build_failed", task_id=self.task_id, error=str(exc)[:200], fallback=SLIM_IMAGE)
            self._note += (f"[rewind] warning: couldn't build the sandbox image with git and curl "
                           f"({str(exc)[:200]}), so this sandbox starts without them.\n")
            if self.base_image == TOOLS_IMAGE:
                self.base_image = SLIM_IMAGE
            return SLIM_IMAGE
        audit.log("base_image_built", task_id=self.task_id, image=TOOLS_IMAGE, seconds=int(time.time() - started))
        self._note += (f"[rewind] First run on this machine: built the sandbox image {TOOLS_IMAGE} "
                       f"(Python, git, curl) in {int(time.time() - started)}s. Later sandboxes start at once.\n")
        return TOOLS_IMAGE

    def _ensure_guard_image(self) -> None:
        if self._inspect_image_exists(GUARD_IMAGE):
            return
        # Built once per machine from the default base image, which Rewind pulls anyway.
        with tempfile.TemporaryDirectory(prefix="rewind-guard-") as build_dir:
            Path(build_dir, "Dockerfile").write_text(_GUARD_DOCKERFILE, encoding="utf-8")
            self._docker("build", "--quiet", "-t", GUARD_IMAGE, build_dir, timeout=900)

    def _ensure_started(self) -> None:
        if self._started:
            return
        self._start_container(self._image)
        code, _ = self._docker("exec", self.container, "sh", "-c", "command -v bash", check=False)
        self._shell = "bash" if code == 0 else "sh"
        self._started = True
        self._persist()

    # ------------------------------------------------------------- persisting
    def _record(self, status: str) -> dict:
        return {
            "task_id": self.task_id, "status": status, "repository": self.repository,
            "container": self.container if status == "live" else None,
            "owner_pid": os.getpid() if status == "live" else None, "host": store_mod.hostname(),
            "base_image": self.base_image, "image": self._image, "seq": self._seq, "cwd": self.cwd,
            "snapshots": [asdict(s) for s in self.snapshots], "dropped_images": list(self._dropped_images),
            "carried_changes": dict(self._carried_changes),
        }

    def _persist(self) -> None:
        """Keep the on-disk record current while live, so a crash loses as little as possible."""
        if self._store is None or self.keep_seconds <= 0:
            return
        try:
            self._store.save(self._record("live"))
        except OSError:
            pass

    def _adopt(self) -> None:
        """Pick up the snapshots a previous sandbox for this task parked."""
        record = self._store.load(self.task_id)
        if not record or store_mod.is_expired(record):
            return
        if record.get("status") == "live":
            if record.get("host") != store_mod.hostname() or store_mod.pid_alive(record.get("owner_pid")):
                return  # another live process owns it
            old = record.get("container")
            if old:  # its owner died: keep the state it was in
                code, _ = self._docker("commit", "--message", "rewind recovered", old,
                                       f"{record['repository']}:recovered", timeout=300, check=False)
                if code == 0:
                    record["image"] = f"{record['repository']}:recovered"
                self._docker("rm", "-f", old, timeout=60, check=False)
        image = record.get("image") or ""
        if not image or self._inspect_image(image) == (0, 0):
            return  # the images are gone (pruned by hand?): start fresh
        self.repository = record["repository"]
        self._seq = int(record.get("seq", 0))
        self.snapshots = [Snapshot.from_dict(s) for s in record.get("snapshots", [])]
        self._dropped_images = list(record.get("dropped_images", []))
        self._carried_changes = dict(record.get("carried_changes", {}))
        self._image = image
        cwd = record.get("cwd") or self.cwd
        self.cwd = cwd if cwd.startswith("/") else self.cwd
        self._cwd_from_restore = True  # the resumed directory wins over Hermes's default once
        age = time.time() - float(record.get("parked_at") or record.get("updated_at") or time.time())
        audit.log("resumed", task_id=self.task_id, snapshots=len(self.snapshots), parked_seconds=int(age),
                  recovered_from_crash=record.get("image", "").endswith(":recovered"))
        self._note = (
            f"[rewind] Resumed this session's sandbox from {_ago(age)} ago with "
            f"{len(self.snapshots)} snapshot(s); earlier changes can still be undone.\n"
        )

    # ----------------------------------------------------------- environment
    def execute(
        self, command: str, cwd: str = "", *, timeout: Optional[int] = None,
        stdin_data: Optional[str] = None, **kwargs,
    ) -> dict:
        """Run ``command`` in the sandbox. Follows Hermes's environment contract:
        returns ``output`` and ``returncode`` (plus ``exit_code`` for older
        callers), and ``cwd`` when the command reported its final directory.
        ``stdin_data`` (how Hermes's file tools send file contents) is fed to
        the command's stdin."""
        with self._lock:
            self._finish_background()
            if self._cwd_from_restore:
                # Hermes passes the directory it tracked before the restore;
                # the restored snapshot's directory wins once, and the result
                # reports it so Hermes tracks that from now on.
                self._cwd_from_restore = False
                cwd = self.cwd
            cwd = cwd or self.cwd
            try:
                self._ensure_started()
            except (RewindError, subprocess.TimeoutExpired, OSError) as exc:
                return _result(f"[rewind] could not start the sandbox: {exc}", 1)

            note, self._note = self._note, ""
            if policy.should_snapshot(command, self.snapshot_mode):
                try:
                    self._take_snapshot(label="auto", command=command, auto=True)
                except (RewindError, subprocess.TimeoutExpired, OSError) as exc:
                    note += f"[rewind] warning: snapshot failed, so this command cannot be undone ({exc})\n"
            outside = policy.irreversible_reason(command) if self.network else None
            after = (
                f"\n[rewind] note: {outside}. Snapshots only cover files in this sandbox, "
                "so rewind_restore cannot take that back." if outside else ""
            )
            try:
                self._ensure_started()  # in case a compaction could not restart it
            except (RewindError, subprocess.TimeoutExpired, OSError) as exc:
                return _result(f"[rewind] could not start the sandbox: {exc}", 1)

            limit = timeout or self.timeout
            stdin_file = None
            if stdin_data is not None:
                try:
                    stdin_file = self._stage_stdin(stdin_data)
                except (RewindError, subprocess.TimeoutExpired, OSError) as exc:
                    return _result(f"[rewind] could not pass stdin to the command: {exc}", 1)
            pid_file = f"/tmp/.rewind-pid-{uuid.uuid4().hex[:12]}"
            marker = _cwd_marker()
            argv = [self.docker_bin, "exec", self.container, self._shell, "-c",
                    _wrap(command, cwd, stdin_file, pid_file, marker)]
            stopped = True
            try:
                code, out = self._run(argv, limit)
            except subprocess.TimeoutExpired as exc:
                # Abandoning the client doesn't stop the command: `docker exec`
                # leaves it running in the container, still changing files.
                stopped = self._kill_command(pid_file, stdin_file)
                code, out = 124, _decode(exc.output) + f"\n[rewind] command timed out after {limit}s" + (
                    " and was stopped." if stopped else
                    "; it could not be stopped and may still be running in the sandbox, so no snapshot "
                    "was taken of this state."
                )
                audit.log("command_timeout", task_id=self.task_id, seconds=limit, stopped=stopped)

            output, new_cwd = _split_cwd(out, marker)
            if new_cwd:
                self.cwd = new_cwd
            # The state after this command is the state before the next one,
            # so capture it now, while the agent reads this output and decides
            # what to do. A read-only command leaves the pending snapshot valid.
            # Never while a timed-out command may still be changing files: that
            # snapshot would hold a half-finished state labelled as a clean one.
            if self._pending is None and stopped:
                self._start_background()
            return _result(note + output + after, code, new_cwd)

    def _kill_command(self, pid_file: str, stdin_file: Optional[str] = None) -> bool:
        """Stop a timed-out command and everything it started. True when
        nothing of it is left running."""
        try:
            code, out = self._docker("exec", self.container, "sh", "-c",
                                     _kill_script(pid_file, stdin_file), timeout=60, check=False)
        except (RewindError, subprocess.TimeoutExpired, OSError):
            return False
        return code == 0 and _KILL_OK in out

    def _stage_stdin(self, data: str) -> str:
        """Write ``data`` to a temp file in the sandbox and return its path.

        Docker can't close an exec's stdin over a Windows named pipe, so the
        bytes travel base64-encoded inside commands instead: portable to any
        shell with ``base64``, and byte-exact (Hermes's write_file checks a
        hash). Large payloads go in chunks to stay under Linux's 128 KB limit
        on a single argument."""
        path = f"/tmp/.rewind-stdin-{uuid.uuid4().hex[:12]}"
        encoded = base64.b64encode(data.encode("utf-8")).decode("ascii")
        for start in range(0, max(len(encoded), 1), _STDIN_CHUNK):
            chunk = encoded[start:start + _STDIN_CHUNK]
            self._docker("exec", self.container, "sh", "-c", f"printf '%s' '{chunk}' >> {path}.b64", timeout=60)
        self._docker("exec", self.container, "sh", "-c",
                     f"base64 -d {path}.b64 > {path} && rm -f {path}.b64", timeout=60)
        return path

    def cleanup(self) -> None:
        """Called by Hermes when the session ends *and* when its idle reaper shuts
        the sandbox down, which look the same from here. So with parking on, keep
        the snapshots for keep_hours and let the next sandbox resume them."""
        with self._lock:
            self._finish_background()
            if self._store is not None and self.keep_seconds > 0 and self.snapshots:
                try:
                    self._park()
                    registry.remove(self)
                    return
                except (RewindError, subprocess.TimeoutExpired, OSError):
                    pass  # couldn't park: clean up fully rather than leak
            self._delete_everything()

    def _park(self) -> None:
        previous = self._image
        if self._started:
            self._drop_pending()  # the parked state is the state now (see restore)
            state = self._commit().image
            self._docker("rm", "-f", self.container, timeout=60)
            self._started = False
            self._image = state
        keep = {s.image for s in self.snapshots} | {self._image, self.base_image}
        if previous not in keep:  # an earlier parked state, now superseded
            self._dropped_images.append(previous)
        if self._dropped_images:
            self._docker("rmi", "-f", *self._dropped_images, timeout=120, check=False)
            self._dropped_images = [i for i in self._dropped_images if self._inspect_image_exists(i)]
        record = self._record("parked")
        now = time.time()
        record.update(parked_at=now, expires_at=now + self.keep_seconds)
        self._store.save(record)

    def _inspect_image_exists(self, image: str) -> bool:
        self._image_info.pop(image, None)
        return self._inspect_image(image) != (0, 0)

    def _delete_everything(self) -> None:
        if self._started:
            self._docker("rm", "-f", self.container, timeout=60, check=False)
            self._started = False
        images = [s.image for s in self.snapshots] + self._dropped_images
        if self._pending is not None:
            images.append(self._pending.image)
            self._pending = None
        if self._image != self.base_image and self._image not in images:
            images.append(self._image)  # a resumed or compacted state
        if images:
            self._docker("rmi", "-f", *images, timeout=120, check=False)
        self.snapshots.clear()
        self._dropped_images.clear()
        if self._store is not None:
            try:
                self._store.delete(self.task_id)
            except OSError:
                pass
        registry.remove(self)

    # -------------------------------------------------------------- snapshots
    def snapshot(self, label: str = "manual") -> Snapshot:
        with self._lock:
            self._finish_background()
            self._ensure_started()
            self._drop_pending()  # a checkpoint holds the state now, not the last background commit
            snap = self._take_snapshot(label=label or "manual", command="", auto=False)
            # The state is unchanged, so the next command can have a snapshot ready too.
            self._start_background()
            return snap

    def _take_snapshot(
        self, *, label: str, command: str, auto: bool, compact: bool = True, restore_point: bool = False
    ) -> Snapshot:
        """Record the current state as a snapshot: the pending background one if
        there is one (it already holds this state), otherwise a fresh commit."""
        fresh = self._pending is None
        if fresh:
            pending = self._commit()
        else:
            pending, self._pending = self._pending, None
        # Secrets typed into a command must not end up in records that outlive the chat.
        snap = Snapshot(
            pending.id, pending.image, redact(label), redact(command), pending.cwd, pending.created_at, auto,
            restore_point, pending.parent,
        )
        if fresh:
            if compact:
                self._maybe_compact(snap.image)
        self.snapshots.append(snap)
        self._prune()
        self._persist()
        return snap

    def _drop_pending(self) -> None:
        """Discard an unclaimed background snapshot, for callers that need the
        state as it is now: it may predate a write the read-only check missed."""
        if self._pending is not None:
            image, self._pending = self._pending.image, None
            self._docker("rmi", "-f", image, timeout=120, check=False)

    def _commit(self) -> _Pending:
        self._seq += 1
        sid = f"s{self._seq}"
        image = f"{self.repository}:{sid}"
        parent = self._image
        self._docker("commit", "--message", f"rewind {sid}", self.container, image, timeout=300)
        return _Pending(sid, image, self.cwd, time.time(), parent)

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
            # The newest snapshot that isn't a restore's undo point. Otherwise a
            # second restore("last") would pick the state saved by the first
            # one and undo it. Undoing a restore takes its explicit id.
            for snap in reversed(self.snapshots):
                if not snap.restore_point:
                    return snap
            if self.snapshots:
                raise RewindError(
                    "The only snapshots are ones saved before a restore. Pass a snapshot id "
                    "from rewind_list to restore one of them."
                )
            raise RewindError("There are no snapshots yet.")
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
            before = self._list_files_in_container()
            # The undo point must hold the state as it is *now*. A background snapshot
            # may predate a write the read-only check missed, and reusing it would make
            # "undo the undo" lose that write, so this one is always a fresh commit.
            self._drop_pending()
            # No compaction: the container is replaced right after anyway.
            safety = self._take_snapshot(
                label=f"before restoring {target.id}", command="", auto=False, compact=False,
                restore_point=True,
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
            self._cwd_from_restore = True
            after = self._list_files_in_container()
            self.last_restore_changes = _file_changes(before, after)
            self._persist()
            self._start_background()  # ready for the first change after the restore
            return target, safety

    def forget(self) -> int:
        """Delete every snapshot of this sandbox now (the current state stays).
        Returns how many were deleted. Undo history is gone afterwards."""
        with self._lock:
            self._finish_background()
            images = [s.image for s in self.snapshots] + self._dropped_images
            if self._pending is not None:
                images.append(self._pending.image)
                self._pending = None
            count = len(self.snapshots)
            in_use = self._image if self._image in images else None  # the running container's image
            doomed = [i for i in images if i != in_use]
            if doomed:
                self._docker("rmi", "-f", *doomed, timeout=120, check=False)
            self.snapshots.clear()
            self._dropped_images = [in_use] if in_use else []  # deleted with the container later
            self._persist()
            if self._started:
                self._start_background()
            return count

    def undo(self) -> Tuple[Snapshot, Snapshot]:
        """Undo the most recent change: restore("last")."""
        return self.restore("last")

    def preview(self, snapshot_id: str) -> Tuple[Snapshot, Optional[dict]]:
        """What restoring ``snapshot_id`` would change under /workspace, without restoring.
        The dict is None when the file lists couldn't be read."""
        with self._lock:
            self._finish_background()
            self._ensure_started()
            target = self.find(snapshot_id)
            before = self._list_files_in_container()
            after = self._list_files_in_image(target.image)
            # Nothing changed, so any waiting background snapshot is still valid.
            return target, _file_changes(before, after)

    # ------------------------------------------------------------ file lists
    def _list_files_in_container(self) -> Optional[Dict[str, str]]:
        try:
            code, out = self._docker("exec", self.container, "sh", "-c", _LIST_FILES, timeout=60, check=False)
        except (subprocess.TimeoutExpired, OSError):
            return None
        return _parse_listing(out) if code == 0 else None

    def _list_files_in_image(self, image: str) -> Optional[Dict[str, str]]:
        try:
            code, out = self._docker("run", "--rm", "--network", "none", "--entrypoint", "sh", image,
                                     "-c", _LIST_FILES, timeout=120, check=False)
        except (subprocess.TimeoutExpired, OSError):
            return None
        return _parse_listing(out) if code == 0 else None

    # ----------------------------------------------------------------- export
    def export(self, path: str, dest_root: Path) -> Path:
        """Copy ``path`` (a file or folder in the sandbox) to a new folder under
        ``dest_root`` on the host and return the copy's host path. Never
        overwrites: each export gets its own timestamped folder."""
        with self._lock:
            self._finish_background()
            self._ensure_started()
            src = posixpath.normpath(path if path.startswith("/") else posixpath.join(self.cwd, path))
            code, out = self._docker("exec", self.container, "sh", "-c",
                                     f"test -e {shlex.quote(src)} && du -sk {shlex.quote(src)} | cut -f1",
                                     timeout=120, check=False)
            if code != 0:
                raise RewindError(f"{src} does not exist in the sandbox.")
            try:
                size_kb = int(out.strip().splitlines()[-1])
            except (ValueError, IndexError):
                size_kb = 0
            if self.export_max_mb and size_kb > self.export_max_mb * 1024:
                raise RewindError(
                    f"{src} is {size_kb // 1024} MB, over the {self.export_max_mb} MB export limit "
                    "(REWIND_EXPORT_MAX_MB)."
                )
            # A cap on everything exported, so repeated exports can't fill the disk.
            used_kb = _tree_bytes(Path(dest_root)) // 1024
            if self.export_total_mb and used_kb + size_kb > self.export_total_mb * 1024:
                raise RewindError(
                    f"Exports already use {used_kb // 1024} MB of the {self.export_total_mb} MB allowed "
                    f"(REWIND_EXPORT_TOTAL_MB) in {dest_root}. Delete old exports there first."
                )
            slug = _SLUG.sub("-", self.task_id.lower()).strip("-")[-40:] or "task"
            dest = Path(dest_root) / slug / time.strftime("%Y%m%d-%H%M%S")
            n = 1
            while dest.exists():
                n += 1
                dest = dest.with_name(f"{dest.name.split('_')[0]}_{n}")
            dest.mkdir(parents=True)
            # Stream it as a tar and unpack only plain files and folders. A symlink
            # (to a host path, say), device or fifo is never created on this
            # computer, and no entry may land outside `dest`. Letting `docker cp`
            # unpack it instead would recreate links, and on Windows it fails
            # outright on the first one.
            argv = [self.docker_bin, "cp", f"{self.container}:{src}", "-"]
            try:
                with self._tar_reader(argv) as stream:
                    self.last_export_removed = _extract_plain(stream, dest, self.export_max_mb)
            except (tarfile.TarError, OSError) as exc:
                raise RewindError(f"Couldn't copy {src} out of the sandbox: {exc}") from exc
            name = posixpath.basename(src.rstrip("/")) or "root"
            return dest / name

    # ------------------------------------------------------------- disk usage
    def snapshot_size(self, snap: Snapshot) -> Optional[int]:
        """Roughly how many bytes this snapshot adds: its size minus its parent's."""
        size, _ = self._inspect_image(snap.image)
        if not size or not snap.parent:
            return None
        parent_size, _ = self._inspect_image(snap.parent)
        return max(0, size - parent_size) if parent_size else None

    def changes(self, limit: int = 200) -> List[str]:
        """Filesystem changes since the sandbox was created or last restored."""
        with self._lock:
            self._finish_background()
            self._ensure_started()
            _, out = self._docker("diff", self.container, timeout=60)
            merged = dict(self._carried_changes)
            _merge_diff(merged, out)
            return [f"{kind} {path}" for path, kind in sorted(merged.items())][:limit]

    def list_snapshots(self, sizes: bool = False) -> List[dict]:
        with self._lock:
            listed = []
            for snap in self.snapshots:
                info = snap.describe()
                if sizes:
                    size = self.snapshot_size(snap)
                    info["size_mb"] = round(size / 1e6, 1) if size is not None else None
                listed.append(info)
            return listed


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


def _tree_bytes(root: Path) -> int:
    """Total size of the regular files under ``root`` (0 if it doesn't exist)."""
    total = 0
    for dirpath, _dirs, files in os.walk(root):
        for name in files:
            try:
                total += os.lstat(os.path.join(dirpath, name)).st_size
            except OSError:
                pass
    return total


@contextlib.contextmanager
def _popen_tar_reader(argv: Sequence[str]):
    """`docker cp container:path -` as a byte stream (a tar archive)."""
    proc = subprocess.Popen(list(argv), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        yield proc.stdout
        _, err = proc.communicate(timeout=600)
        if proc.returncode:
            raise RewindError(f"docker cp failed (exit {proc.returncode}): {_decode(err).strip()[-300:]}")
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()


def _extract_plain(stream, dest: Path, max_mb: int = 0) -> List[str]:
    """Unpack a tar stream into ``dest``, writing only regular files and folders.

    Skips (and returns, as paths) symlinks, devices, fifos, entries whose path
    is absolute or climbs out with "..", and names this system can't store. A
    hard link becomes a plain copy, but only of a regular file this same export
    already wrote: tar stores the second name of a hard-linked file as a link
    to the first, and skipping it would silently drop a real file. Files are
    written without setuid/setgid bits. ``max_mb`` caps the total written,
    whatever the archive claims.
    """
    root = Path(dest).resolve()
    removed, written, cap = [], 0, max_mb * 1024 * 1024 if max_mb else 0
    extracted: Dict[str, Path] = {}  # archive path -> regular file written by this export
    with tarfile.open(fileobj=stream, mode="r|") as archive:
        for member in archive:
            raw = member.name.replace("\\", "/")
            parts = [p for p in raw.split("/") if p not in ("", ".")]
            if not parts:
                continue
            shown = "/".join(parts)
            if raw.startswith("/") or ".." in parts or ":" in parts[0]:  # absolute, climbing, or C:...
                removed.append(shown)
                continue
            target = root.joinpath(*parts)
            resolved = target.resolve()
            if resolved != root and root not in resolved.parents:
                removed.append(shown)
                continue
            try:
                if member.isdir():
                    target.mkdir(parents=True, exist_ok=True)
                elif member.isfile():
                    if cap and written + member.size > cap:
                        raise RewindError(f"The export is bigger than the {max_mb} MB limit.")
                    target.parent.mkdir(parents=True, exist_ok=True)
                    source = archive.extractfile(member)
                    with open(target, "xb") as out:  # never overwrite
                        shutil.copyfileobj(source, out)
                    os.chmod(target, member.mode & 0o755 | 0o600)
                    written += member.size
                    extracted[shown] = target
                elif member.islnk():
                    link = "/".join(p for p in member.linkname.replace("\\", "/").split("/") if p not in ("", "."))
                    original = extracted.get(link)
                    if original is None:  # not a file this export wrote: never follow it
                        removed.append(shown)
                        continue
                    size = original.stat().st_size
                    if cap and written + size > cap:
                        raise RewindError(f"The export is bigger than the {max_mb} MB limit.")
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with open(original, "rb") as src, open(target, "xb") as out:
                        shutil.copyfileobj(src, out)
                    os.chmod(target, member.mode & 0o755 | 0o600)
                    written += size
                    extracted[shown] = target
                else:
                    removed.append(shown)  # symlink, device, fifo
            except (OSError, ValueError):
                removed.append(shown)  # e.g. a name Windows can't store ("a:b", "con")
    return removed


def _parse_listing(out: str) -> Dict[str, str]:
    """``path<TAB>size<TAB>mtime`` lines -> {path: "size/mtime"}; other lines are ignored."""
    files = {}
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) == 3 and parts[0]:
            size, mtime = parts[1], parts[2].split(".")[0]
            files[parts[0]] = f"{size}/{mtime}"
    return files


def _file_changes(before: Optional[Dict[str, str]], after: Optional[Dict[str, str]]) -> Optional[dict]:
    """How /workspace differs going from ``before`` to ``after`` (None if either is unknown)."""
    if before is None or after is None:
        return None
    back = sorted(set(after) - set(before))
    gone = sorted(set(before) - set(after))
    changed = sorted(p for p in set(before) & set(after) if before[p] != after[p])
    out = {"root": DEFAULT_CWD}
    for key, paths in (("appear", back), ("disappear", gone), ("change", changed)):
        out[key] = paths[:_SUMMARY_LIMIT]
        out[f"{key}_count"] = len(paths)
    return out


def describe_changes(changes: Optional[dict]) -> str:
    """One readable line for a _file_changes dict."""
    if changes is None:
        return "Couldn't compare the file lists."
    parts = []
    for key, verb in (("appear", "come back"), ("disappear", "go away"), ("change", "change")):
        count = changes.get(f"{key}_count", 0)
        if count:
            shown = ", ".join(changes[key])
            more = f" and {count - len(changes[key])} more" if count > len(changes[key]) else ""
            parts.append(f"{count} file(s) {verb} ({shown}{more})")
    if not parts:
        return f"No files under {changes.get('root', DEFAULT_CWD)} change."
    return f"Under {changes.get('root', DEFAULT_CWD)}: " + "; ".join(parts) + "."


def _ago(seconds: float) -> str:
    seconds = max(0, int(seconds))
    if seconds < 90:
        return f"{seconds}s"
    if seconds < 5400:
        return f"{seconds // 60} min"
    return f"{seconds / 3600:.1f} h"


def _result(output: str, code: int, cwd: Optional[str] = None) -> dict:
    result = {"output": output, "returncode": code, "exit_code": code}
    if cwd:
        # Hermes records a session's cwd only when cwd_observed is set.
        result["cwd"] = cwd
        result["cwd_observed"] = True
    return result


def _wrap(command: str, cwd: str, stdin_file: Optional[str] = None, pid_file: Optional[str] = None,
          marker: str = _CWD_MARKER) -> str:
    """Run ``command`` in ``cwd`` and report the final directory so cd persists.
    With ``stdin_file``, the command reads it as stdin and it is removed after.
    With ``pid_file``, the shell's PID is written there while the command runs,
    so a timed-out command can be found and stopped (see _kill_script)."""
    q = shlex.quote(cwd)
    if stdin_file:
        # A group, not a subshell, so a `cd` inside still carries over.
        command = f"{{\n{command}\n}} < {stdin_file}\n__rewind_rc=$?\nrm -f {stdin_file}\n(exit $__rewind_rc)"
    start = f"echo $$ > {pid_file}\n" if pid_file else ""
    end = f"rm -f {pid_file}\n" if pid_file else ""
    return (
        start
        # A directory that no longer exists (the last command deleted it) is not
        # recreated: the command runs in /workspace instead, and says so.
        + f"cd {q} 2>/dev/null || {{ mkdir -p {DEFAULT_CWD} && cd {DEFAULT_CWD} && "
        f"echo \"[rewind] note: {_sh_note(cwd)} no longer exists, so this ran in {DEFAULT_CWD}.\" >&2; }}\n"
        f"{command}\n"
        "__rewind_rc=$?\n"
        + end
        + f"printf '\\n{marker}%s\\n' \"$(pwd)\"\n"
        "exit $__rewind_rc\n"
    )


def _sh_note(text: str) -> str:
    """``text`` made safe inside a double-quoted shell string."""
    return re.sub(r'[\\"$`]', "", text)[:200]


_KILL_OK = "REWIND_KILL_OK"


def _kill_script(pid_file: str, stdin_file: Optional[str] = None) -> str:
    """Shell that stops the command whose shell PID is in ``pid_file``, and
    every process it started. Plain POSIX sh reading /proc, so it works
    without procps. ``docker exec`` makes the command's shell a session and
    process-group leader, so its processes are found by session and group
    (which catches ones that double-forked and were reparented to PID 1) and
    by parent PID (which catches ones that called setsid). They are frozen,
    so they can't fork or move away, found again, then killed. Prints
    _KILL_OK once none of them is left running."""
    leftovers = f" {stdin_file} {stdin_file}.b64" if stdin_file else ""
    return "\n".join([
        f"f={pid_file}",
        f'[ -f "$f" ] || {{ rm -f{leftovers}; echo {_KILL_OK}; exit 0; }}',
        'read -r root < "$f"',
        'case "$root" in ""|*[!0-9]*) exit 1;; esac',
        # /proc/PID/stat is "pid (comm) state ppid pgrp session ...": comm can
        # hold spaces, so everything up to the last ") " is dropped first.
        "tree() {",
        '  all=" $root "; more=1',
        '  while [ "$more" = 1 ]; do more=0',
        "    for d in /proc/[0-9]*; do",
        "      p=${d#/proc/}",
        '      case "$all" in *" $p "*) continue;; esac',
        '      { read -r s < "$d/stat"; } 2>/dev/null || continue',
        '      set -- ${s##*) }',
        '      if [ "$4" = "$root" ] || [ "$3" = "$root" ]; then all="$all$p "; more=1; continue; fi',
        '      case "$all" in *" $2 "*) all="$all$p "; more=1;; esac',
        "    done",
        "  done",
        '  echo $all',
        "}",
        "alive() {",
        "  for p in $1; do",
        '    { read -r s < "/proc/$p/stat"; } 2>/dev/null || continue',
        '    set -- ${s##*) }',
        '    [ "$1" != Z ] && return 0',
        "  done",
        "  return 1",
        "}",
        "pids=$(tree); kill -STOP $pids 2>/dev/null",
        "pids=$(tree); kill -KILL $pids 2>/dev/null",
        "for i in 1 2 3 4 5 6 7 8 9 10; do",
        '  alive "$pids" || { rm -f "$f"' + leftovers + f"; echo {_KILL_OK}; exit 0; }}",
        "  kill -KILL $pids 2>/dev/null; sleep 1",  # whole seconds: not every sleep takes fractions
        "done",
        "exit 1",
    ])


_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


def _cwd_marker() -> str:
    """A marker for one command's final directory. Random, so output that happens
    to contain (or deliberately prints) a marker can't set the working directory."""
    return f"__REWIND_CWD_{uuid.uuid4().hex[:16]}__"


def _split_cwd(out: str, marker: str = _CWD_MARKER) -> Tuple[str, Optional[str]]:
    """Take the final directory the wrapper printed out of ``out``. Only an
    absolute path with no control characters counts; anything else (an
    unterminated heredoc that swallowed the wrapper's last lines, say) leaves
    the output alone and the working directory unchanged."""
    idx = out.rfind(marker)
    if idx == -1:
        return out, None
    cwd, _, trailing = out[idx + len(marker):].partition("\n")
    cwd = cwd.strip()
    if not cwd.startswith("/") or _CONTROL.search(cwd) or len(cwd) > 4096:
        return out, None
    body = out[:idx]
    if body.endswith("\n"):  # the newline _wrap printed before the marker
        body = body[:-1]
    return body + trailing, cwd


def _decode(data) -> str:
    if data is None:
        return ""
    if isinstance(data, bytes):
        return data.decode("utf-8", errors="replace")
    return str(data)
