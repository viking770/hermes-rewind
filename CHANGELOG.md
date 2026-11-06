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
  their children, background jobs and anything in their session or process
  group. Before, only the client gave up, and the command kept changing files
  while a snapshot of that state was taken. The README lists the two ways a
  process can still escape a timeout.
- **The "internet" network mode no longer reaches this computer.** It now also
  blocks the sandbox's gateway and this computer's own addresses, including a
  server's public IPv4 and IPv6 addresses. It blocks NAT64 and 6to4, and gives
  the sandbox no network when it has IPv6 that can't be filtered.
- **Approval before irreversible commands works from the first command on.**
  Before, the first command of a process, for example right after
  `hermes gateway restart`, could `git push` without asking.
- **The approval check catches more spellings:** `bash -lc '...'`, `$(...)`
  and backticks, `sudo -u x ...`, `env -i ...` and `env -S '...'`, and curl's
  combined short options (`-sSXPOST`, `-d@file`, `-T` uploads).
- **The working-directory marker is random per command.** Output that
  contains a marker, or an unterminated heredoc, can no longer set a bogus
  working directory or lose undo history at the next restart.

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
- `scripts/stress_test.py`: 120 attacks on every protection against real
  Docker, with a report of what the sandbox did each time
  ([docs/stress-report.md](docs/stress-report.md)).
- `tests/test_qa_logic.py` and `scripts/qa_stress.py`: an independent
  adversarial pass with 41 unit tests and 19 Docker probes.

### Known issues
Tracked as `expectedFailure` tests in `tests/test_qa_logic.py` (one per issue)
and as `BUG(...)` results in `scripts/qa_stress.py`. All are Low or documented:
- A process that both leaves the command's session and is orphaned, or a
  command that deletes Rewind's tracking file in `/tmp`, can survive a timeout.
- Someone who can already write Rewind's state folder can make a parked record
  start another local image, or remove another chat's container.
- Some secrets aren't masked: `curl -uuser:pw`, JSON password fields, Stripe
  `sk_live_` keys, and a URL password containing `@`.
- Restore points are not pruned. Command output has no size cap.
- Exports have no file-count cap.
- Stdin with a lone surrogate character raises an error.
- Terminal escape codes in commands reach `hermes rewind log`.
- A command that ends with `exit` leaves small temporary files.

## 0.2.3

Validated parked-sandbox records, the base image pinned by digest, the audit
log, and a disk cap for kept snapshots.
