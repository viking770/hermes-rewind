# Changelog

## 0.2.4 (2026-11-06)

Hardening after a product and security review, an in-house stress test and an
independent adversarial QA pass. The catalog entry pins the commit for this
release; `git log c6e8b71..` lists every change.

### Security
- **Agent tools respect chat isolation.** From a messaging platform (Telegram,
  Discord, Slack...), the `rewind_*` tools now reach only that chat's own
  sandbox, never the sandbox Hermes shares on purpose for local chats. This is
  the same rule `/rewind` already followed.
- **Commands that time out are stopped inside the sandbox**, together with
  everything they started: children, background jobs, anything in their
  session or process group, and any process that started after them (which
  catches ones that detached twice). This works even if the command deleted
  Rewind's tracking file. Background processes from earlier commands keep
  running. Before, only the client gave up, and the command kept changing
  files while a snapshot of that state was taken.
- **The "internet" network mode no longer reaches this computer.** It now also
  blocks the sandbox's gateway and this computer's own addresses, including a
  server's public IPv4 and IPv6 addresses. It blocks NAT64 and 6to4, and gives
  the sandbox no network when it has IPv6 that can't be filtered.
- **The DNS resolver is reachable for DNS only, wherever it is.** On Azure VMs,
  where GitHub Actions and many Hermes gateways run, the resolver is
  `168.63.129.16`. That address also serves the VM's platform configuration
  (WireServer) on port 80, and it isn't in any private range, so before this
  change a sandbox there could reach it. Only port 53 to the resolver is
  allowed now, and `168.63.129.16` is blocked outright.
- **Approval before irreversible commands works from the first command on.**
  Before, the first command of a process, for example right after
  `hermes gateway restart`, could `git push` without asking.
- **The approval check catches more spellings:** `bash -lc '...'`, `$(...)`
  and backticks, `sudo -u x ...`, `env -i ...` and `env -S '...'`, and curl's
  combined short options (`-sSXPOST`, `-d@file`, `-T` uploads).
- **The working-directory marker is random per command.** Output that
  contains a marker, or an unterminated heredoc, can no longer set a bogus
  working directory or lose undo history at the next restart.
- **Tampered parked records can't steer Docker.** A record's container must be
  its own (it is named after the record's repository), and a sandbox resumes
  only from its own snapshots or an allowed base image. Before, someone who
  could write the state folder could make a record start any local image, or
  commit and remove another chat's container.
- **More secrets are masked** in snapshot history and the audit log:
  `curl -uuser:pass`, password, token and secret fields in JSON bodies, Stripe
  `sk_`/`rk_` keys and `whsec_` webhook secrets, and URL passwords that contain
  `@`. `-u` values without a `user:password` shape (`sort -u file`) are no
  longer masked by mistake.
- **`hermes rewind log` shows control characters as `\x1b`-style escapes**, so
  agent-written text can't send codes to your terminal.
- **`rg --pre` and `sort --compress-program` get a snapshot first**, since both
  run another program.

### Fixed
- **Undo could lose a write.** If a command that wrote files was mistaken for
  a read-only one, undo followed by "undo the undo" lost those writes. A
  restore, a manual checkpoint and an idle shutdown now always save the state
  as it is at that moment. The read-only check also catches `sed -ni`,
  `>&file`, `git diff --output`, `git -c`, `awk -f`, process substitution and
  `NAME=value` prefixes.
- **Exports dropped files with hard links.** A file with two names arrived as
  one. Both names now arrive as plain copies; links to anything outside the
  export are still skipped.
- **A folder deleted by the agent came back empty.** This happened when a
  command deleted its own working directory. The next command now runs in
  `/workspace` and says so.
- **On Windows, writing a file over about 24 KB failed** when Rewind used the
  docker CLI (command lines are capped at 32,767 characters). File contents now
  go in smaller pieces there.
- **On macOS, every sandbox start could stall for about 35 s** while the
  network guard looked up the machine's own hostname. The lookup now gives up
  after 1 s and is cached.
- **A failed sandbox start could hide its real error behind "name already in
  use"** when it retried without resource limits.
- **Stdin that isn't valid text** (a lone surrogate character) now gives a
  clear error instead of raising an exception into Hermes.

- **Restore points are pruned** to the same cap as automatic snapshots, so
  repeated undos no longer pile up images. The newest stay, so the latest
  restores can still be undone.
- **A command ending in `exit` no longer leaves Rewind's temporary files**
  behind, where they ended up in the next snapshot.
- **Command output is capped** at `REWIND_MAX_OUTPUT_KB` (1 MB). The first and
  last half are kept, with a note; before, 50 MB of output went to Hermes whole.
- **Exports:** at most `REWIND_EXPORT_MAX_FILES` (20,000) entries. Files are
  owner-only on Linux and macOS and carry the "downloaded from the internet"
  mark on Windows. Each skipped item is listed with its real reason; a name
  Windows can't store was reported as a link or special file before.
- **A warning when a sandbox grows past `REWIND_MAX_SANDBOX_GB`** (20 GB) of
  its own data, since every snapshot stores it again.

### Changed
- **The default sandbox image includes `git` and `curl`.** It is
  `hermes-rewind-base:1`, built once from the digest-pinned
  `python:3.12-slim`, so "clone a repo" works in a fresh sandbox. If the build
  fails, the sandbox starts from the slim image and says so.
- **`hermes doctor` checks that the Docker daemon is running**, not just that
  the `docker` command is installed.
- **The plugin folder ships its README**, so the catalog page shows it, and the
  risk disclosure also covers the read-only check of Hermes's `config.yaml` and
  the background work.

### Testing
- CI on every push: unit tests on Linux for Python 3.11 to 3.14 and on Windows
  and macOS; Docker integration tests; and the stress test.
- `scripts/stress_test.py`: 121 attacks on every protection against real
  Docker, with a report of what the sandbox did each time
  ([docs/stress-report.md](docs/stress-report.md)).
- `tests/test_qa_logic.py` and `scripts/qa_stress.py`: an independent
  adversarial pass with 41 unit tests and 19 Docker probes.

### Known limits
All issues from the review, the stress test and the QA pass are fixed. What
remains are documented design limits:
- Snapshots cover the sandbox's files only, not running processes or anything
  sent over the network; the approval prompt for such commands is best effort.
- The default network mode reaches the internet, so a misled agent can send
  what is in the sandbox to a website. `REWIND_NETWORK=none` turns that off.
- Commands run as root inside the container (with most capabilities dropped),
  so package managers work.
- There is no hard per-sandbox disk quota (Docker Desktop can't enforce one),
  only the size warning.
- The firewall's IPv6 rules have not been exercised against a sandbox with
  real IPv6 connectivity; without filterable IPv6 the sandbox gets no network.

## 0.2.3

Validated parked-sandbox records, the base image pinned by digest, the audit
log, and a disk cap for kept snapshots.
