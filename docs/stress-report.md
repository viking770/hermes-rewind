# Rewind stress test report

**121/121 checks passed** in 244s. All checks passed.

Rewind 0.2.4 (commit `6ba09b6`) · Docker 29.9.1 (linux/amd64) · Windows 11 · Python 3.14.9 · 2026-11-06 16:56 UTC

Every check runs real commands in real Docker sandboxes and records what the sandbox actually did. Produced by [`scripts/stress_test.py`](../scripts/stress_test.py).

| Section | What it attacks | Passed | Time |
|---|---|---|---|
| ✅ [hardening](#hardening) | Container hardening: capabilities, privileges, limits, nothing from the host. | 14/14 | 23s |
| ✅ [network](#network) | Network guard: internet yes, this computer / LAN / metadata no. | 17/17 | 49s |
| ✅ [evasion](#evasion) | Firewall evasion: disguised addresses, DNS tricks, IPv6 mapping, UDP, tampering. | 16/16 | 15s |
| ✅ [undo](#undo) | Snapshots, undo, restore, undo of undo, preview, history limits. | 13/13 | 58s |
| ✅ [stdin](#stdin) | Hermes's file tools send contents on stdin: must arrive byte-exact. | 1/1 | 6s |
| ✅ [timeout](#timeout) | A command that times out is stopped, with everything it started. | 4/4 | 14s |
| ✅ [compaction](#compaction) | Big changes don't make every later snapshot store them again. | 2/2 | 19s |
| ✅ [export](#export) | Exports bring only plain files onto this computer. | 9/9 | 7s |
| ✅ [isolation](#isolation) | Each chat reaches only its own sandbox. | 10/10 | 11s |
| ✅ [approval](#approval) | Commands Rewind can't undo need the user's approval first. | 23/23 | 0s |
| ✅ [parking](#parking) | Undo history survives Hermes shutting an idle sandbox down. | 6/6 | 23s |
| ✅ [audit](#audit) | The audit log records what happened, with secrets masked. | 5/5 | 10s |
| ✅ [cleanup](#cleanup) | Every container and image the run created is removed. | 1/1 | 9s |

## hardening

| | Check | What happened |
|---|---|---|
| ✅ | only the 5 package-manager capabilities | CapEff=0xcb (expected 0xcb: CHOWN, DAC_OVERRIDE, FOWNER, SETGID, SETUID) |
| ✅ | no NET_ADMIN or NET_RAW (firewall can't be changed from inside) | bits 12 and 13 of CapEff=0xcb are clear |
| ✅ | no SYS_ADMIN | bit 21 of CapEff=0xcb is clear |
| ✅ | no-new-privileges is set | NoNewPrivs: 1 |
| ✅ | can't mount filesystems | mount -t tmpfs: mount: /mnt: permission denied. |
| ✅ | raw sockets refused | SOCK_RAW: PermissionError: [Errno 1] Operation not permitted |
| ✅ | Docker socket not mounted | /var/run/docker.sock: absent |
| ✅ | no host environment passed in | variables in the sandbox: GPG_KEY HOME HOSTNAME LANG OLDPWD PATH PWD PYTHON_SHA256 PYTHON_VERSION SHLVL _ |
| ✅ | process limit is 2048 | pids.max=2048 |
| ✅ | memory limit is 5 GB | memory.max=5368709120 |
| ✅ | CPU limit is 1 CPU | cpu.max=100000 100000 |
| ✅ | fork bomb stops at the process limit | tried 500 forks with a 64-process limit: stopped: Resource temporarily unavailable, forked 60 |
| ✅ | memory hog is killed at the memory limit | allocating 400 MB with a 128 MB limit: exit 137 (array(400*1024*1024); print('"'"'ALLOC'"'"'+'"'"'ATED'"'"')') |
| ✅ | sandbox survives both | next command printed: alive |

## network

| | Check | What happened |
|---|---|---|
| ✅ | guard installed (no fallback warning) | first command printed: up |
| ✅ | internet reachable (HTTPS) | GET https://example.com -> 200 |
| ✅ | DNS works | example.com resolves to 104.20.23.154 |
| ✅ | sandbox gateway 172.17.0.1 blocked | connect 172.17.0.1:80 -> connection refused |
| ✅ | cloud metadata 169.254.169.254 blocked | connect 169.254.169.254:80 -> connection refused |
| ✅ | Azure platform address 168.63.129.16 (WireServer) blocked | connect 168.63.129.16:80 -> connection refused |
| ✅ | LAN 10.0.0.1 blocked | connect 10.0.0.1:22 -> connection refused |
| ✅ | LAN 192.168.0.1 blocked | connect 192.168.0.1:80 -> connection refused |
| ✅ | LAN 172.16.0.1 blocked | connect 172.16.0.1:80 -> connection refused |
| ✅ | carrier NAT 100.64.0.1 blocked | connect 100.64.0.1:80 -> connection refused |
| ✅ | this computer (own address #1) blocked | connect own address #1:445 -> connection refused |
| ✅ | this computer (own address #6) blocked | connect own address #6:445 -> connection refused |
| ✅ | host.docker.internal (192.168.65.254) blocked | connect 192.168.65.254:80 -> connection refused |
| ✅ | the sandbox's own loopback still works | connect 127.0.0.1:8765 -> connected (a server inside the sandbox) |
| ✅ | NAT64 to 10.0.0.1 blocked | connect 64:ff9b::a00:1:80 -> network unreachable |
| ✅ | IPv6 ULA fd00::1 blocked | connect fd00::1:80 -> network unreachable |
| ✅ | network=none has no internet | connect 1.1.1.1:443 -> network unreachable |

## evasion

| | Check | What happened |
|---|---|---|
| ✅ | this computer as one decimal number blocked | resolved to own address #1: refused or unreachable (errno 111) |
| ✅ | this computer in hex blocked | resolved to own address #1: refused or unreachable (errno 111) |
| ✅ | this computer in octal blocked | resolved to own address #1: refused or unreachable (errno 111) |
| ✅ | this computer in short form (a.b.cd) blocked | resolved to own address #1: refused or unreachable (errno 111) |
| ✅ | cloud metadata as decimal (2852039166) blocked | resolved to 169.254.169.254: refused or unreachable (errno 111) |
| ✅ | cloud metadata in hex (0xa9fea9fe) blocked | resolved to 169.254.169.254: refused or unreachable (errno 111) |
| ✅ | this computer as IPv4-mapped IPv6 blocked | resolved to ::ffff:own address #1: refused or unreachable (errno 111) |
| ✅ | cloud metadata as IPv4-mapped IPv6 blocked | resolved to ::ffff:169.254.169.254: refused or unreachable (errno 111) |
| ✅ | DNS name resolving to cloud metadata (nip.io) blocked | resolved to 169.254.169.254: refused or unreachable (errno 111) |
| ✅ | DNS name resolving to this computer (nip.io) blocked | resolved to own address #1: refused or unreachable (errno 111) |
| ✅ | 0.0.0.0 blocked | resolved to 0.0.0.0: refused or unreachable (errno 111) |
| ✅ | UDP to this computer blocked | blocked: Operation not permitted |
| ✅ | DNS resolver reachable only on port 53 | connect 192.168.65.7:80 -> connection refused |
| ✅ | can't create a private network namespace to escape the rules | unshare: unshare failed: Operation not permitted |
| ✅ | no firewall tools inside the sandbox | iptables/nft/ip6tables absent |
| ✅ | can't open raw packet sockets (no hand-built packets) | refused: Operation not permitted |

## undo

| | Check | What happened |
|---|---|---|
| ✅ | rm -rf of the working directory took effect (not recreated) | after rm -rf /workspace/app (the working directory): [rewind] note: /workspace/app no longer exists, so this ran in /workspace. |
| ✅ | says the working directory is gone and runs in /workspace | gone / pwd=/workspace |
| ✅ | undo brings the folder back | restored s2 (state before running: rm -rf /workspace/app); f2.txt=v2 |
| ✅ | undo of the undo removes it again | restored s3; /workspace/app: gone |
| ✅ | undo again is repeat-safe (same state) | /workspace/app has 3 files |
| ✅ | read-only commands take no snapshot | 6 read-only commands: snapshots 5 -> 5 |
| ✅ | changes outside /workspace are restored too | /etc/rewind-outside=outside |
| ✅ | preview changes nothing | preview of s10 listed 1 change(s); p.txt still=after |
| ✅ | history is capped at max_snapshots | after 10 more changes: 6 automatic snapshots kept (max_snapshots=6) |
| ✅ | pruned snapshots' images are deleted | 11 images for 10 snapshots |
| ✅ | cd carries over between commands | next command's pwd=/workspace/deep/dir |
| ✅ | restore brings back the working directory | pwd after undo=/workspace/deep/dir |
| ✅ | secrets typed in commands are masked in snapshot history | recorded as: GITHUB_TOKEN=[REDACTED] touch /workspace/tok |

## stdin

| | Check | What happened |
|---|---|---|
| ✅ | 300 KB payload arrives byte-exact | sent 300,049 bytes (Unicode, quotes, $, backticks); sha256 b114846be54b1530… vs b114846be54b1530… |

## timeout

| | Check | What happened |
|---|---|---|
| ✅ | returns soon after the limit | 4 s limit: returned after 7.6s with exit 124 |
| ✅ | reports that it was stopped | [rewind] command timed out after 4s and was stopped. |
| ✅ | detached, setsid and nohup children are all killed | `(sleep 301 &); setsid sleep 302 & nohup sleep 303 >/dev/null 2>&1 & sleep 304`: 0 of its sleep processes left running |
| ✅ | sandbox still works and can undo after a timeout | after undo, /workspace/w: missing |

## compaction

| | Check | What happened |
|---|---|---|
| ✅ | compaction keeps the layer count bounded | 4 x 3 MB changes with compact_mb=1: newest snapshot has 8 layers |
| ✅ | a snapshot from before compaction still restores | restored s2: 1 blob(s) present, as at that point |

## export

| | Check | What happened |
|---|---|---|
| ✅ | plain file exported | arrived: hardlink.txt, ok.txt, suid |
| ✅ | symlinks are not created on this computer | skipped: out/link-to-host, out/link-to-passwd, out/pipe |
| ✅ | both names of a hard-linked file arrive as plain files | ok.txt and hardlink.txt both contain 'hello' |
| ✅ | FIFOs are not created | pipe is in the skipped list |
| ✅ | setuid bit dropped | sandbox mode 4755 -> exported mode 666 |
| ✅ | nothing lands outside the export folder | every exported path is under the export folder |
| ✅ | a second export never overwrites the first | first: …/20261106-222552, second: …/20261106-222552_2 |
| ✅ | export over the size cap is refused | /workspace/huge is 3 MB, over the 2 MB export limit (REWIND_EXPORT_MAX_MB). |
| ✅ | export of a missing path is refused | /workspace/does-not-exist does not exist in the sandbox. |

## isolation

| | Check | What happened |
|---|---|---|
| ✅ | a chat's tools see its own snapshots | rewind_list for alice: 1 snapshot(s), all alice's |
| ✅ | an unknown chat gets no sandbox, not someone else's | This session has no Rewind sandbox yet. Run a terminal command first (and check `hermes config get terminal.backend` says rewind). |
| ✅ | Telegram chat can't reach the shared sandbox (rewind_list) | This session has no Rewind sandbox yet. Run a terminal command first (and check `hermes config get terminal.backend` say |
| ✅ | Telegram chat can't reach the shared sandbox (rewind_changes) | This session has no Rewind sandbox yet. Run a terminal command first (and check `hermes config get terminal.backend` say |
| ✅ | Telegram chat can't reach the shared sandbox (rewind_undo) | This session has no Rewind sandbox yet. Run a terminal command first (and check `hermes config get terminal.backend` say |
| ✅ | rewind_export refused from a messaging platform | rewind_export writes to the Hermes host's disk, so it is only available in local chats (this one is on telegram). Show t |
| ✅ | /rewind undo from Telegram can't touch the shared sandbox | Rewind: This chat has no Rewind sandbox yet: run a terminal command first. |
| ✅ | shared sandbox untouched | /workspace/precious=local-user-work |
| ✅ | /rewind export refused from Discord | Rewind: /rewind export writes to the Hermes host's disk, so it only works from a local chat (CLI, TUI or desktop app), n |
| ✅ | the shared sandbox is reachable from a local chat | rewind_list from the CLI: ok=True |

## approval

| | Check | What happened |
|---|---|---|
| ✅ | asks before: git push origin main | Rewind can't undo this: `git push` sends commits outside the sandbox. Snapshots only cover the sandbox's files. Run it? |
| ✅ | asks before: npm publish | Rewind can't undo this: `npm publish` changes a remote service. Snapshots only cover the sandbox's files. Run it? |
| ✅ | asks before: docker push me/img | Rewind can't undo this: `docker push` changes a remote service. Snapshots only cover the sandbox's files. Run it? |
| ✅ | asks before: curl -X POST https://x.io/hook -d @f | Rewind can't undo this: `curl` sends an HTTP POST request. Snapshots only cover the sandbox's files. Run it? |
| ✅ | asks before: bash -c 'git push' | Rewind can't undo this: `git push` sends commits outside the sandbox. Snapshots only cover the sandbox's files. Run it? |
| ✅ | asks before: bash -lc 'git push origin main' | Rewind can't undo this: `git push` sends commits outside the sandbox. Snapshots only cover the sandbox's files. Run it? |
| ✅ | asks before: echo $(git push) | Rewind can't undo this: `git push` sends commits outside the sandbox. Snapshots only cover the sandbox's files. Run it? |
| ✅ | asks before: sudo -u bob git push | Rewind can't undo this: `git push` sends commits outside the sandbox. Snapshots only cover the sandbox's files. Run it? |
| ✅ | asks before: env -i git push | Rewind can't undo this: `git push` sends commits outside the sandbox. Snapshots only cover the sandbox's files. Run it? |
| ✅ | asks before: curl -sSXPOST https://x.io/hook | Rewind can't undo this: `curl` sends an HTTP POST request. Snapshots only cover the sandbox's files. Run it? |
| ✅ | asks before: eval "git push" | Rewind can't undo this: `git push` sends commits outside the sandbox. Snapshots only cover the sandbox's files. Run it? |
| ✅ | asks before: git -C repo push | Rewind can't undo this: `git push` sends commits outside the sandbox. Snapshots only cover the sandbox's files. Run it? |
| ✅ | asks before: kubectl apply -f k.yaml | Rewind can't undo this: `kubectl apply` changes a cluster outside the sandbox. Snapshots only cover the sandbox's files. Run it? |
| ✅ | asks before: ssh prod 'rm -rf /srv' | Rewind can't undo this: `ssh` runs commands on another machine or database. Snapshots only cover the sandbox's files. Run it? |
| ✅ | asks before: python3 -c 'import requests; requests.post('"'"' | Rewind can't undo this: a script calls `requests.post`, which sends data outside the sandbox. Snapshots only cover the sandbox's files. Run |
| ✅ | no prompt for: ls -la | no prompt |
| ✅ | no prompt for: cat README.md | no prompt |
| ✅ | no prompt for: git status | no prompt |
| ✅ | no prompt for: pip install requests | no prompt |
| ✅ | no prompt for: python3 app.py | no prompt |
| ✅ | asks through the tool-search bridge too | Rewind can't undo this: `git push` sends commits outside the sandbox. Snapshots only cover the sandbox's files. Run it? |
| ✅ | asks before an export | The agent wants to copy '/workspace' out of the Rewind sandbox onto this computer (into ~\AppData\Local\Tem |
| ✅ | no prompt when the sandbox has no network | git push with REWIND_NETWORK=none: no prompt (it can't reach anything) |

## parking

| | Check | What happened |
|---|---|---|
| ✅ | idle shutdown parks the snapshots | record status=parked, 2 snapshot(s) |
| ✅ | no container left running while parked | docker ps finds none |
| ✅ | next sandbox resumes the history | [rewind] Resumed this session's sandbox from 0s ago with 2 snapshot(s); earlier changes can still be undone. |
| ✅ | undo works across the shutdown | kept.txt after undo=kept |
| ✅ | a tampered record is ignored (starts fresh) | record edited to base_image='--privileged': started fresh with 0 snapshots |
| ✅ | tampered image name never reaches docker | started from hermes-rewind-base:1 |

## audit

| | Check | What happened |
|---|---|---|
| ✅ | audit log has 'undo' events | 1 of 24 entries |
| ✅ | audit log has 'approval_requested' events | 18 of 24 entries |
| ✅ | audit log has 'command_timeout' events | 2 of 24 entries |
| ✅ | the approval request itself is logged | approval_requested written for the git push |
| ✅ | secrets are masked in the audit log | logged command: TOKEN=[REDACTED] git push |

## cleanup

| | Check | What happened |
|---|---|---|
| ✅ | no stress-test containers left behind | docker ps finds no stress-test containers |
