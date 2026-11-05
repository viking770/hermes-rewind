# Rewind: an undo button for your agent's terminal

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
| `/rewind export PATH` | Copies a file or folder out of the sandbox onto your computer |
| `/rewind status` | Plugin version, and the sandboxes Rewind is keeping |

(`/undo`, `/rollback` and `/snapshot` are Hermes's own commands for conversation turns and checkpoints. They don't touch the Rewind sandbox.)

On the command line, `hermes rewind status` shows the same status and `hermes rewind gc` deletes expired snapshots and leftovers now.

## Agent tools

| Tool | What it does |
|---|---|
| `rewind_undo` | Undoes the most recent change; safe to repeat. Reports which files came back or went away |
| `rewind_list` | Lists snapshots with a plain `state` ("state before running: rm -rf x"), size, and the plugin version |
| `rewind_restore` | Rolls back to a snapshot id or `last`. With `preview: true` it only reports what would change |
| `rewind_snapshot` | Saves a named checkpoint, e.g. "before refactor" |
| `rewind_changes` | Shows files added, changed or deleted since the sandbox was created or last restored |
| `rewind_export` | Copies a file or folder out of the sandbox onto the user's computer |

Hermes's tool search keeps plugin tools out of the default list, so models find these through tool search. Rewind also adds a short system-prompt section that tells the model they exist, that a snapshot is the state *before* its command, and to undo once rather than recreate files by hand.

## How it works
- On the first command, Rewind starts a container (`python:3.12-slim` by default) with `/workspace` as the working directory. The terminal and file tools run there, not on your computer.
- Before each command, it decides whether the command could change anything. `ls`, `cat`, `grep`, `git status` and similar are treated as read-only. Anything it doesn't recognise counts as a change: `rm`, `pip install`, `> file`, `sed -i`, `git checkout`, scripts, and so on. If it's a change, Rewind runs `docker commit` first.
- **A snapshot is the state before its command ran.** The snapshot listed with `rm -rf demo` still has `demo` in it.
- Snapshots are taken in the background. The state right after a command is the state right before the next one, so Rewind commits it while the agent reads the output and decides what to do. The next command that needs a snapshot finds it ready and runs at once (it only waits if the commit hasn't finished). Read-only commands don't change anything, so the waiting snapshot stays valid until something does.
- `docker commit` saves everything changed since the container started, so after a big install every snapshot would store it again. Once the changes pass `REWIND_COMPACT_MB`, Rewind restarts the container from the snapshot it just took, and later snapshots only hold what changed after that.
- Restoring replaces the container with a fresh one started from the chosen snapshot. It saves the current state first, so a restore can itself be undone. `last` always means the newest snapshot that isn't one of those undo points, so undoing twice in a row doesn't undo the undo.
- `cd` carries over between commands, and restoring also restores the working directory.
- Rewind talks to the Docker Engine API over the daemon's socket (a named pipe on Windows), which skips the 0.5 to 1 second it takes to start the `docker` CLI on Docker Desktop. If the API can't be reached, for example with a `tcp://` `DOCKER_HOST`, it uses the CLI.
- By default Hermes shares one sandbox between sessions (`terminal.container_persistent: true`). Set `hermes config set terminal.container_persistent false` to give each session its own sandbox and its own snapshots. The `rewind_*` tools and `/rewind` always act on the sandbox Hermes uses for the calling session, and refuse to guess if they can't tell.

### When the sandbox goes away
Hermes shuts a sandbox down when its session ends **and** when it has been idle for `terminal.lifetime_seconds` (300 seconds by default), even if the chat is still open. Rewind can't tell those apart, so it keeps the undo history either way:

- The container is removed, but the snapshots are **parked**: their images stay, and a small record goes in `<HERMES_HOME>/rewind/`.
- The next time Hermes needs a sandbox for that session (after a break, or after `hermes gateway restart`), Rewind resumes it in the state it was in, with the same snapshots, and says so in the next command's output.
- Parked snapshots are deleted after `REWIND_KEEP_HOURS` (24 by default). Set it to `0` to delete everything when the sandbox shuts down, as before 0.2.0.
- If Hermes crashes or is killed, the next Rewind to start notices the dead owner, keeps that session's snapshots the same way, and deletes containers and images nobody owns. `hermes rewind gc` does it on demand.

### Commands Rewind can't undo
Snapshots only cover the sandbox's files. Before a command that reaches outside it (`git push`, `npm publish`, `docker push`, deploys, `kubectl apply`, `curl -X POST`, `ssh`, sending email and similar), Rewind asks Hermes to get your approval first. The command's output also notes that it can't be undone. Set `REWIND_CONFIRM_IRREVERSIBLE=0` to turn the prompt off. With `REWIND_NETWORK=0` such commands can't reach anything, so Rewind doesn't ask. The check covers the common cases; not being flagged doesn't prove a command is safe.

## Settings (environment variables)

| Variable | Default | Meaning |
|---|---|---|
| `REWIND_IMAGE` | `python:3.12-slim` | Base image for the sandbox |
| `REWIND_SNAPSHOT_MODE` | `mutating` | `mutating`, `always`, or `off` |
| `REWIND_MAX_SNAPSHOTS` | `25` | Automatic snapshots to keep (manual ones are never pruned) |
| `REWIND_NETWORK` | `1` | Set to `0` to give the sandbox no network access |
| `REWIND_COMPACT_MB` | `256` | Compact snapshots once this many MB have changed (`0` turns it off) |
| `REWIND_DOCKER_API` | `1` | Set to `0` to always use the `docker` CLI instead of the Engine API |
| `REWIND_BACKGROUND` | `1` | Set to `0` to snapshot right before each command instead of in the background |
| `REWIND_KEEP_HOURS` | `24` | How long snapshots are kept after the sandbox shuts down (`0` = delete right away) |
| `REWIND_STATE_DIR` | `<HERMES_HOME>/rewind` | Where the records of parked sandboxes live |
| `REWIND_EXPORT_DIR` | `<state dir>/exports` | Where `rewind_export` and `/rewind export` put copies |
| `REWIND_EXPORT_MAX_MB` | `500` | Largest export allowed |
| `REWIND_CONFIRM_IRREVERSIBLE` | `1` | Set to `0` to stop asking before commands Rewind can't undo |
| `REWIND_AUTO_GC` | `1` | Set to `0` to stop the automatic cleanup of expired snapshots and leftovers |

To give yourself longer before Hermes shuts an idle sandbox down, raise Hermes's own setting, e.g. `hermes config set terminal.lifetime_seconds 1800`.

## What this plugin does on your machine (risk disclosure)
- **Runs shell commands** inside a Docker container through the Docker Engine API (the same socket the `docker` CLI uses), or the `docker` CLI itself. Commands do not run on your host.
- **Creates Docker images** (`hermes-rewind/<task>:sN`) for snapshots, labelled `hermes.rewind=1` with the id of the Hermes process that made them. They are kept for `REWIND_KEEP_HOURS` after the sandbox shuts down, then deleted. `/rewind` shows each snapshot's size. To delete everything by hand: `docker ps -aq --filter label=hermes.rewind=1 | xargs docker rm -f` and `docker images 'hermes-rewind/*' -q | xargs docker rmi -f`.
- **Writes small JSON records** of parked sandboxes to `<HERMES_HOME>/rewind/sandboxes/`.
- **Writes to your computer only when asked to export:** `rewind_export` copies into a new timestamped folder under `REWIND_EXPORT_DIR` and never overwrites anything.
- **Network:** the sandbox has network access unless `REWIND_NETWORK=0`. The first run pulls the base image from Docker Hub. The plugin makes no other network calls and has no telemetry.
- **No credentials** are read or stored.

## Limits
- Snapshots cover the container filesystem only. Running processes, and anything sent over the network (a `git push`, an API call), cannot be undone.
- Restores, compactions and resuming a parked sandbox restart the container, which stops background processes such as a dev server.
- Each snapshot takes roughly 0.1 to 1 second on Linux, and about 1 second on Docker Desktop, where the daemon's commit is slower. Background snapshots hide this as long as the agent takes longer than that to send its next command, which it usually does.
- A background snapshot captures the sandbox when the commit runs, just after the previous command. If a background process (a dev server, say) writes files in between, those writes are part of the snapshot. Set `REWIND_SNAPSHOT_MODE=off` and use `rewind_snapshot` by hand if you need speed.
- Restore and preview summaries list files under `/workspace` only; changes elsewhere are still restored.
- Commands run one at a time per session, so a restore can never happen in the middle of a running command.

## Development

```bash
python3 -m unittest discover -s tests -t .                                  # unit tests, no Docker needed
REWIND_INTEGRATION=1 python3 -m unittest tests.test_docker_integration -v  # real Docker
hermes plugins validate ./rewind --install-deps
python3 scripts/dev_install.py   # copy into Hermes and restart the gateway
python3 scripts/e2e_hermes.py    # scripted chat with a real model; checks the tool results
```

Close your own Hermes chats before `e2e_hermes.py`: with Hermes's shared sandbox it would act on theirs. The plugin lives in `rewind/` (the catalog `subdir`). The tests and scripts are not shipped.

## License
MIT
