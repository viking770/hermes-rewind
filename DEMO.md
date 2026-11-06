# 90-second demo script (Rewind)

**Before recording.** Run one terminal command through Rewind once (any command), so the one-time image builds (about a minute) happen off camera. The sandbox then has `git` and `curl` from the first command.

**0–10s.** Title card: "Rewind: an undo button for your AI agent's terminal." Show `hermes config set terminal.backend rewind`.

**10–30s.** In a Hermes session: "Clone a small repo into /workspace and get its tests passing." The agent works, and the status/tool calls show snapshots being taken (`rewind_list` shows s1…s4).

**30–50s.** The disaster: "Clean up everything except the source." The agent runs a broad `rm -rf` and the tests now fail. (Stage it with a prompt that makes this plausible, or tell it to do it on camera.)

**50–65s.** Type `/rewind` to show the snapshots ("state before running: rm -rf …"), then `/rewind undo`. No model involved: Rewind answers at once with which files came back, and the tests pass again. Optionally ask the agent to "undo that" instead and show it calling `rewind_undo`.

**65–75s.** Undo the undo: `/rewind restore s<N>` with the id the undo printed, to show that a rollback is itself reversible.

**75–85s.** Safety net for what files can't cover: ask the agent to `git push`. Hermes stops and asks first, with Rewind's message that a push can't be undone.

**85–90s.** End card: "Every command reversible. `hermes plugins install …/hermes-rewind`". Tag @NousResearch.
