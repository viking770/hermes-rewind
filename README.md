# Rewind: an undo button for your agent's terminal

[![tests](https://github.com/viking770/hermes-rewind/actions/workflows/tests.yml/badge.svg)](https://github.com/viking770/hermes-rewind/actions/workflows/tests.yml)

**Stress-tested against real Docker:** 121 attacks on every protection below, from fork bombs and memory hogs to reaching this computer through the firewall, with what the sandbox did each time: [stress test report](https://github.com/viking770/hermes-rewind/blob/main/docs/stress-report.md).

Rewind is a [Hermes Agent](https://hermes-agent.nousresearch.com) terminal backend. It runs every command in a Docker sandbox and **snapshots the sandbox before any command that can change files**. If the agent deletes the wrong folder, breaks a dependency or ruins a refactor, you or the agent can roll back in one step.

```
you   > clean up the build artifacts
agent > $ rm -rf src build        ← oops
you   > /rewind undo
rewind> Rolled back to s7 (state before running: rm -rf src build).
        Under /workspace: 214 file(s) come back (src/app.py, src/util.py, ...).
        To undo this, run /rewind restore s8.
```

## Why it's a plugin and not a prompt
A prompt can ask the agent to "be careful". Rewind makes mistakes reversible. It replaces the terminal itself, so every shell command and every file tool (`read_file`, `write_file`, `patch`) goes through an environment that can roll back.

## Install

```bash
hermes plugins install viking770/hermes-rewind --enable
hermes config set terminal.backend rewind
```

Requires Docker (Docker Desktop on macOS/Windows, Docker Engine on Linux).

**After updating the plugin, run `hermes gateway restart`.** Hermes loads plugins once per process and the gateway keeps running after you close a chat, so it keeps the old code until it restarts. `/rewind status`, `rewind_list` and `hermes doctor` warn when the running version doesn't match the files on disk.

## Undo it yourself: `/rewind`
`/rewind` works in any Hermes chat and runs Rewind directly, so undo doesn't depend on the model picking the right tool.

| Command | What it does |
|---|---|
| `/rewind` | Lists the snapshots, newest last |
| `/rewind undo` | Undoes the most recent change. Running it again is harmless: it restores the same point |
| `/rewind restore ID` | Rolls back to a snapshot, e.g. `s3`. This is also how you undo an undo |
| `/rewind preview ID` | Shows which files would come back or go away, without changing anything |
| `/rewind changes` | Files added, changed or deleted since the sandbox started or was last restored |
| `/rewind export PATH` | Copies a file or folder out of the sandbox onto your computer (local chats only; plain files and folders only) |
| `/rewind forget` | Deletes this chat's snapshots now, after asking (`/rewind forget yes`). The files stay as they are |
| `/rewind status` | Plugin version, and the sandboxes Rewind is keeping |

(`/undo`, `/rollback` and `/snapshot` are Hermes's own commands for conversation turns and checkpoints. They don't touch the Rewind sandbox.)

On the command line, `hermes rewind status` shows the same status, `hermes rewind gc` deletes expired snapshots and leftovers now, `hermes rewind purge` deletes every kept snapshot right away (`--exports` also deletes everything exported), and `hermes rewind log` shows what Rewind did recently (see [Audit log](#audit-log)).

## Agent tools

| Tool | What it does |
|---|---|
| `rewind_undo` | Undoes the most recent change; safe to repeat. Reports which files came back or went away |
| `rewind_list` | Lists snapshots with a plain `state` ("state before running: rm -rf x"), size, and the plugin version |
| `rewind_restore` | Rolls back to a snapshot id or `last`. With `preview: true` it only reports what would change |
| `rewind_snapshot` | Saves a named checkpoint, e.g. "before refactor" |
| `rewind_changes` | Shows files added, changed or deleted since the sandbox was created or last restored |
| `rewind_export` | Copies a file or folder out of the sandbox onto the user's computer. Hermes asks the user first; local chats only |

Hermes's tool search keeps plugin tools out of the default list, so models find these through tool search. Rewind also adds a short system-prompt section that tells the model they exist, that a snapshot is the state *before* its command, and to undo once rather than recreate files by hand.

## How it works
- On the first command, Rewind starts a container (Python 3.12 with `git` and `curl` by default, so the agent can clone a repo straight away) with `/workspace` as the working directory. The terminal and file tools run there, not on your computer.
- Before each command, it decides whether the command could change anything. `ls`, `cat`, `grep`, `git status` and similar are treated as read-only. Anything it doesn't recognise counts as a change: `rm`, `pip install`, `> file`, `sed -i`, `git checkout`, scripts, and so on. If it's a change, Rewind runs `docker commit` first.
- **A snapshot is the state before its command ran.** The snapshot listed with `rm -rf demo` still has `demo` in it.
- Snapshots are taken in the background. The state right after a command is the state right before the next one, so Rewind commits it while the agent reads the output and decides what to do. The next command that needs a snapshot finds it ready and runs at once (it only waits if the commit hasn't finished). Read-only commands don't change anything, so the waiting snapshot stays valid until something does.
- `docker commit` saves everything changed since the container started, so after a big install every snapshot would store it again. Once the changes pass `REWIND_COMPACT_MB`, Rewind restarts the container from the snapshot it just took, and later snapshots only hold what changed after that.
- Restoring replaces the container with a fresh one started from the chosen snapshot. It saves the current state first, so a restore can itself be undone. `last` always means the newest snapshot that isn't one of those undo points, so undoing twice in a row doesn't undo the undo.
- `cd` carries over between commands, and restoring also restores the working directory.
- Rewind talks to the Docker Engine API over the daemon's socket (a named pipe on Windows), which skips the 0.5 to 1 second it takes to start the `docker` CLI on Docker Desktop. If the API can't be reached, for example with a `tcp://` `DOCKER_HOST`, it uses the CLI.
- Hermes decides which sessions share a sandbox (`terminal.container_persistent`). The `rewind_*` tools and `/rewind` act only on the calling session's own sandbox, or on the one Hermes shares on purpose (`default`, `profile:…`, `shared:…`), never on "whichever sandbox is running". See [Security](#security).

## Security
**The sandbox is hardened like Hermes's own Docker backend.** Every capability is dropped except the five package managers need (`CHOWN`, `DAC_OVERRIDE`, `FOWNER`, `SETUID`, `SETGID`), with `no-new-privileges`, a 2048-process limit, and Hermes's `terminal.container_cpu` and `terminal.container_memory` (1 CPU and 5 GB by default). Nothing from your computer is mounted and no environment variables are passed in. Commands run as root *inside* the container so `apt` and `pip` work.

**The network reaches the internet, not your computer or your LAN.** With the default `REWIND_NETWORK=internet`, a short-lived helper container installs firewall rules in the sandbox's network namespace before the first command, and again after every restart. The rules block this computer (Docker Desktop's `host.docker.internal`, the sandbox's gateway, and this computer's own addresses, including a server's public IPv4 and IPv6 addresses), private and link-local ranges (10/8, 172.16/12, 192.168/16, 100.64/10, 169.254/16 including cloud metadata), loopback outside the container, and IPv6 equivalents including NAT64 and 6to4, which can lead back to private IPv4 addresses. DNS to the sandbox's own resolver is allowed. The sandbox has no `NET_ADMIN`, so nothing inside it can change the rules. If the rules can't be applied, including when the sandbox has IPv6 but `ip6tables` can't filter it, the sandbox starts with **no network** rather than an unprotected one. The helper image (`hermes-rewind-netguard:2`, the pinned `python:3.12-slim` plus `iptables`) is built once on first use.
- `REWIND_NETWORK=none`: no network at all. The safest choice for untrusted code.
- `REWIND_NETWORK=full`: unrestricted, the behavior before 0.2.1. Only if the agent must reach something on your machine or LAN.

The internet is still reachable in `internet` mode, so a misled agent can still send anything that is in the sandbox to a website. Don't put secrets in the sandbox that you wouldn't want to leave it, or use `none`.

**Each chat only reaches its own sandbox.** From a messaging platform (Telegram, Discord, Slack and so on), `/rewind` and the agent's `rewind_*` tools act only on that chat's own sandbox, `/rewind status` doesn't list other chats, and `/rewind export` is refused because it writes to the Hermes host's disk. The sandbox Hermes shares on purpose is reachable from local chats (CLI, TUI, desktop app) only, so a messaging chat whose own sandbox isn't running yet (or is paused) gets an error, never the local user's sandbox.

**Exports only bring plain files onto your computer.** The agent's `rewind_export` makes Hermes ask you first, and only works in local chats. The copy is streamed as a tar and unpacked by Rewind itself: symlinks (to a host path, say), hard links, devices and FIFOs are skipped and listed, nothing can land outside the export folder, setuid bits are dropped, and nothing is overwritten. Each export is capped by `REWIND_EXPORT_MAX_MB`, and all exports together by `REWIND_EXPORT_TOTAL_MB`.

**Secrets in commands aren't kept.** Before Rewind stores a snapshot's command, it masks common secrets: `Authorization` and API-key headers, passwords in URLs, `curl -u`, `--password`/`--token` options, `NAME_TOKEN=…`-style variables, and well-known token formats (GitHub, GitLab, Slack, OpenAI/Anthropic, AWS, Google, Hugging Face, npm, JWTs, private keys). This is best effort, and the snapshots themselves still hold whatever files the agent created. Records are owner-only (`0600`) on Linux and macOS. `/rewind forget` and `hermes rewind purge` delete history immediately.

**Kept data can't steer Docker.** Every parked-sandbox record is checked when it's read: image, container and repository names must be Rewind's own (`hermes-rewind/<name>:<tag>` in the record's own repository, `hermes-rewind-<name>`), and ids, times and paths must have the right shape. A record that fails is ignored completely, so an edited file can't make Rewind remove someone else's container or start an arbitrary image. Image names that look like options are refused too.

**The base image is pinned.** The default sandbox image, `hermes-rewind-base:1`, is built on this machine the first time it's needed (about a minute, once) from `python:3.12-slim` pinned by digest (the multi-platform index for amd64, arm64 and others), plus `git`, `curl` and CA certificates from Debian's repositories. A tag on Docker Hub can be re-pointed and a digest can't. If the build fails (offline, say), the sandbox starts from the pinned slim image without `git` and `curl`, and says so. The firewall helper is built from the same pinned image. Set `REWIND_IMAGE` to use another image; pin it with `@sha256:` too.

**Kept snapshots have a disk cap.** Beyond the 24-hour expiry, parked sandboxes together may use at most `REWIND_MAX_PARKED_GB` (20 GB); past that the oldest are deleted first. Sizes count each image's own data, not the shared base image. Sandboxes in use are never touched.

The "can't undo" prompt is a reminder, not a security boundary. It sees through `bash -c '…'`, `eval`, `xargs`, `timeout`, `git -C dir push` and inline scripts that call `requests.post`, `fetch(… method: 'POST')`, `smtplib` and similar, but a determined script can always hide a request. Approving "always" covers one action (`git push`), not the whole program. The network mode is the real control.

### When the sandbox goes away
Hermes shuts a sandbox down when its session ends **and** when it has been idle for `terminal.lifetime_seconds` (300 seconds by default), even if the chat is still open. Rewind can't tell those apart, so it keeps the undo history either way:

- The container is removed, but the snapshots are **parked**: their images stay, and a small record goes in `<HERMES_HOME>/rewind/`.
- The next time Hermes needs a sandbox for that session (after a break, or after `hermes gateway restart`), Rewind resumes it in the state it was in, with the same snapshots, and says so in the next command's output.
- Parked snapshots are deleted after `REWIND_KEEP_HOURS` (24 by default). Set it to `0` to delete everything when the sandbox shuts down, as before 0.2.0.
- If Hermes crashes or is killed, the next Rewind to start notices the dead owner, keeps that session's snapshots the same way, and deletes containers and images nobody owns. `hermes rewind gc` does it on demand.

### Audit log
Rewind appends one line per event to `<HERMES_HOME>/rewind/audit.log`: undos and restores, exports (and refused exports, with what was skipped), `/rewind forget`, `hermes rewind purge`, cleanups, approvals it asked Hermes for, sandboxes resumed after an idle shutdown or a crash, and network-guard or resource-limit fallbacks. Each line says when, for which session, and through what: the agent's tool, `/rewind`, the CLI, or Rewind itself. Text is redacted like snapshot commands, the file is owner-only on Linux and macOS, and it rotates to `audit.log.1` at 5 MB. `hermes rewind log [-n 50]` prints the latest entries; `REWIND_AUDIT=0` turns it off.

### Commands Rewind can't undo
Snapshots only cover the sandbox's files. Before a command that reaches outside it (`git push`, `npm publish`, `docker push`, deploys, `kubectl apply`, `curl -X POST`, `ssh`, sending email and similar), Rewind asks Hermes to get your approval first. The command's output also notes that it can't be undone. Set `REWIND_CONFIRM_IRREVERSIBLE=0` to turn the prompt off. With `REWIND_NETWORK=none` such commands can't reach anything, so Rewind doesn't ask. The check covers the common cases; not being flagged doesn't prove a command is safe.

## Settings (environment variables)

| Variable | Default | Meaning |
|---|---|---|
| `REWIND_IMAGE` | `hermes-rewind-base:1` (built from `python:3.12-slim@sha256:aa94…d159` plus `git` and `curl`) | Base image for the sandbox (pin yours by digest too) |
| `REWIND_SNAPSHOT_MODE` | `mutating` | `mutating`, `always`, or `off` |
| `REWIND_MAX_SNAPSHOTS` | `25` | Automatic snapshots to keep (manual ones are never pruned) |
| `REWIND_NETWORK` | `internet` | `internet` (this computer and the LAN blocked), `none`, or `full` (unrestricted). `1`/`0` still mean `internet`/`none` |
| `REWIND_CPUS` | Hermes's `terminal.container_cpu` (1) | CPU limit (`0` = none) |
| `REWIND_MEMORY_MB` | Hermes's `terminal.container_memory` (5120) | Memory limit in MB (`0` = none) |
| `REWIND_PIDS_LIMIT` | `2048` | Process limit, a fork-bomb guard (`0` = none) |
| `REWIND_COMPACT_MB` | `256` | Compact snapshots once this many MB have changed (`0` turns it off) |
| `REWIND_DOCKER_API` | `1` | Set to `0` to always use the `docker` CLI instead of the Engine API |
| `REWIND_BACKGROUND` | `1` | Set to `0` to snapshot right before each command instead of in the background |
| `REWIND_KEEP_HOURS` | `24` | How long snapshots are kept after the sandbox shuts down (`0` = delete right away) |
| `REWIND_STATE_DIR` | `<HERMES_HOME>/rewind` | Where the records of parked sandboxes live |
| `REWIND_EXPORT_DIR` | `<state dir>/exports` | Where `rewind_export` and `/rewind export` put copies |
| `REWIND_EXPORT_MAX_MB` | `500` | Largest single export allowed |
| `REWIND_EXPORT_TOTAL_MB` | `2000` | Cap on everything in the export folder together |
| `REWIND_CONFIRM_EXPORT` | `1` | Set to `0` to stop asking before the agent exports files |
| `REWIND_CONFIRM_IRREVERSIBLE` | `1` | Set to `0` to stop asking before commands Rewind can't undo |
| `REWIND_AUTO_GC` | `1` | Set to `0` to stop the automatic cleanup of expired snapshots and leftovers |
| `REWIND_MAX_PARKED_GB` | `20` | Disk cap for kept snapshots together; the oldest go first (`0` = no cap) |
| `REWIND_AUDIT` | `1` | Set to `0` to stop writing the audit log |

To give yourself longer before Hermes shuts an idle sandbox down, raise Hermes's own setting, e.g. `hermes config set terminal.lifetime_seconds 1800`.

## What this plugin does on your machine (risk disclosure)
- **Runs shell commands** inside a Docker container through the Docker Engine API (the same socket the `docker` CLI uses), or the `docker` CLI itself. Commands do not run on your host.
- **Creates Docker images** (`hermes-rewind/<task>:sN`) for snapshots, labelled `hermes.rewind=1` with the id of the Hermes process that made them. They are kept for `REWIND_KEEP_HOURS` after the sandbox shuts down, then deleted. `/rewind` shows each snapshot's size. To delete everything by hand: `docker ps -aq --filter label=hermes.rewind=1 | xargs docker rm -f` and `docker images 'hermes-rewind/*' -q | xargs docker rmi -f`.
- **Runs in the background** while a sandbox is in use: the sandbox container itself (until Hermes shuts it down when idle), a snapshot commit right after each command, and a cleanup of expired snapshots at most every 10 minutes.
- **Reads Hermes's `config.yaml`**, through Hermes's own config reader and read-only, to see whether `terminal.backend` is `rewind`, so it can ask before irreversible commands from the first command on. It reads no other files outside its own folder.
- **Writes small JSON records** of parked sandboxes to `<HERMES_HOME>/rewind/sandboxes/`, and an audit log to `<HERMES_HOME>/rewind/audit.log`. Both are owner-only on Linux and macOS.
- **Writes to your computer only when you approve an export:** plain files and folders only, into a new timestamped folder under `REWIND_EXPORT_DIR`, never overwriting, within the size caps. Local chats only.
- **Network:** by default the sandbox reaches the internet but not this computer or the LAN (see [Security](#security)). The first run pulls the base image from Docker Hub, installs `git` and `curl` from Debian's repositories to build the sandbox image, and builds the small firewall helper image. The plugin makes no other network calls and has no telemetry.
- **Credentials:** Rewind reads none and passes none into the sandbox. Snapshots keep whatever files the agent puts in the sandbox for up to `REWIND_KEEP_HOURS` after the chat ends; command text in records has common secrets masked. Delete it all sooner with `/rewind forget` or `hermes rewind purge`.

## Limits
- Snapshots cover the container filesystem only. Running processes, and anything sent over the network (a `git push`, an API call), cannot be undone.
- Restores, compactions and resuming a parked sandbox restart the container, which stops background processes such as a dev server.
- Each snapshot takes roughly 0.1 to 1 second on Linux, and about 1 second on Docker Desktop, where the daemon's commit is slower. Background snapshots hide this as long as the agent takes longer than that to send its next command, which it usually does.
- A background snapshot captures the sandbox when the commit runs, just after the previous command. If a background process (a dev server, say) writes files in between, those writes are part of the snapshot. Set `REWIND_SNAPSHOT_MODE=off` and use `rewind_snapshot` by hand if you need speed.
- Restore and preview summaries list files under `/workspace` only; changes elsewhere are still restored.
- Commands run one at a time per session, so a restore can never happen in the middle of a running command. A command that times out is stopped inside the sandbox together with the processes it started: its children, background jobs (`&`, `nohup`) and anything still in its session or process group. If it can't be confirmed stopped, Rewind says so and takes no snapshot of that state. The search is best effort: a process that deliberately leaves the command's session *and* is orphaned (`(setsid cmd &)`), or a command that deletes Rewind's tracking file in `/tmp`, can keep running after the timeout, and Rewind may then report it as stopped. If a timeout matters, restart the sandbox with `/rewind restore last`, which replaces the container and so ends every process in it (the current files are saved first, so that restore can be undone too).

## Development

```bash
python3 -m unittest discover -s tests -t .                                  # unit tests, no Docker needed
REWIND_INTEGRATION=1 python3 -m unittest tests.test_docker_integration -v  # real Docker
python3 scripts/stress_test.py   # 121 attacks on every protection, real Docker; writes stress-report.md/.json
hermes plugins validate ./rewind --install-deps
python3 scripts/dev_install.py   # copy into Hermes and restart the gateway
python3 scripts/e2e_hermes.py    # scripted chat with a real model; checks the tool results
```

Close your own Hermes chats before `e2e_hermes.py`: with Hermes's shared sandbox it would act on theirs. The plugin lives in `rewind/` (the catalog `subdir`). The tests and scripts are not shipped.

## License
MIT
