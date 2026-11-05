# 90-second demo script (Rewind)

**0–10s.** Title card: "Rewind: an undo button for your AI agent's terminal." Show `hermes config set terminal.backend rewind`.

**10–30s.** In a Hermes session: "Clone a small repo into /workspace and get its tests passing." The agent works, and the status/tool calls show snapshots being taken (`rewind_list` shows s1…s4).

**30–50s.** The disaster: "Clean up everything except the source." The agent runs a broad `rm -rf` and the tests now fail. (Stage it with a prompt that makes this plausible, or tell it to do it on camera.)

**50–70s.** "Undo that." The agent calls `rewind_restore("last")`. The tests pass again, and `rewind_changes` shows the files came back.

**70–85s.** Undo the undo: restore the safety snapshot to show that a rollback is itself reversible.

**85–90s.** End card: "Every command reversible. `hermes plugins install …/hermes-rewind`". Tag @NousResearch.
