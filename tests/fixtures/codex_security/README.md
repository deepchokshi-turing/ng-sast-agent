# Codex CLI 0.162.1 event streams

Real `codex exec --json` output of the pinned Codex CLI (openai/codex `rust-v0.162.1`, linux x86_64 musl), used by `tests/test_codex_security_driver.py`.

- `exec_ok_0.162.1.jsonl`: a run in Docker (`--network none`, `--security-opt seccomp=unconfined` so Codex's bubblewrap sandbox can start) against a local fake Responses API that answers with one `exec_command` call and then a final message. The first lines are Codex's WebSocket attempts failing against the fake server before it falls back to HTTPS.
- `exec_401_0.162.1.jsonl`: a run with a made-up key against the real api.openai.com, which refused it (shortened to a few of its reconnect messages, and the made-up key in the messages rewritten in a masked `sk-fake-***STKEY` form, as `codex login status` prints it).

No real key was used for either.
