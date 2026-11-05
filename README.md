# Rewind: an undo button for your agent's terminal

Rewind is a [Hermes Agent](https://hermes-agent.nousresearch.com) terminal backend. It runs every command in a Docker sandbox and **snapshots the sandbox before any command that can change files**. If the agent deletes the wrong folder, breaks a dependency or ruins a refactor, it can roll back with one tool call.

```
you   > clean up the build artifacts
agent > $ rm -rf src build        ← oops
you   > you deleted my source code
agent > rewind_restore("last")    → sandbox is back to before the rm, restore saved as s7 in case you want the deletion after all
```

## Why it's a plugin and not a prompt
A prompt can ask the agent to "be careful". Rewind makes mistakes reversible. It replaces the terminal itself, so every shell command and every file tool (`read_file`, `write_file`, `patch`) goes through an environment that can roll back.

## Install

```bash
hermes plugins install viking770/hermes-rewind --enable
hermes config set terminal.backend rewind
```

Requires Docker (Docker Desktop on macOS/Windows, Docker Engine on Linux).

## How it works
- On the first command, Rewind starts a container (`python:3.12-slim` by default) with `/workspace` as the working directory.
- Before each command, it decides whether the command could change anything. `ls`, `cat`, `grep`, `git status` and similar are treated as read-only. Anything it doesn't recognise counts as a change: `rm`, `pip install`, `> file`, `sed -i`, `git checkout`, scripts, and so on. If it's a change, Rewind runs `docker commit` first.
- Snapshots are taken in the background. The state right after a command is the state right before the next one, so Rewind commits it while the agent reads the output and decides what to do. The next command that needs a snapshot finds it ready and runs at once (it only waits if the commit hasn't finished). Read-only commands don't change anything, so the waiting snapshot stays valid until something does.
- `docker commit` saves everything changed since the container started, so after a big install every snapshot would store it again. Once the changes pass `REWIND_COMPACT_MB`, Rewind restarts the container from the snapshot it just took, and later snapshots only hold what changed after that.
- `rewind_restore` replaces the container with a fresh one started from the chosen snapshot. It saves the current state first, so a restore can itself be undone.
- `cd` carries over between commands, and restoring also restores the working directory.
- Rewind talks to the Docker Engine API over the daemon's socket (a named pipe on Windows), which skips the 0.5 to 1 second it takes to start the `docker` CLI on Docker Desktop. If the API can't be reached, for example with a `tcp://` `DOCKER_HOST`, it uses the CLI.
- When the session ends, the container and all snapshot images are removed.

## Agent tools

| Tool | What it does |
|---|---|
| `rewind_list` | Lists the snapshots (id, the command that triggered it, age, working directory) |
| `rewind_snapshot` | Saves a named checkpoint, e.g. "before refactor" |
| `rewind_restore` | Rolls back to a snapshot id, or `last` |
| `rewind_changes` | Shows files added, changed or deleted since the sandbox was created or last restored |

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

## What this plugin does on your machine (risk disclosure)
- **Runs shell commands** inside a Docker container through the Docker Engine API (the same socket the `docker` CLI uses), or the `docker` CLI itself. Commands do not run on your host.
- **Creates Docker images** (`hermes-rewind/<task>:sN`) for snapshots. They are deleted when the session ends. If Hermes is killed, clean up with `docker ps -aq --filter label=hermes.rewind=1 | xargs docker rm -f` and `docker images 'hermes-rewind/*' -q | xargs docker rmi -f`.
- **Network:** the sandbox has network access unless `REWIND_NETWORK=0`. The first run pulls the base image from Docker Hub. The plugin makes no other network calls and has no telemetry.
- **No credentials** are read or stored.

## Limits
- Snapshots cover the container filesystem only. Running processes, and anything sent over the network (a `git push`, an API call), cannot be undone.
- Restores and compactions restart the container, which stops background processes such as a dev server.
- Each snapshot takes roughly 0.1 to 1 second on Linux, and about 1 second on Docker Desktop, where the daemon's commit is slower. Background snapshots hide this as long as the agent takes longer than that to send its next command, which it usually does.
- A background snapshot captures the sandbox when the commit runs, just after the previous command. If a background process (a dev server, say) writes files in between, those writes are part of the snapshot. Set `REWIND_SNAPSHOT_MODE=off` and use `rewind_snapshot` by hand if you need speed.
- Commands run one at a time per session, so a restore can never happen in the middle of a running command.

## Development

```bash
python3 -m unittest discover -s tests -t .                                  # unit tests, no Docker needed
REWIND_INTEGRATION=1 python3 -m unittest tests.test_docker_integration -v  # real Docker
hermes plugins validate ./rewind --install-deps
```

The plugin lives in `rewind/` (the catalog `subdir`). The tests are not shipped.

## License
MIT
