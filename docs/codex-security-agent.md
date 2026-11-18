# Codex security review agent: design notes

`sast.codex_security.agent:CodexSecurityAgent` runs a security review with the open-source OpenAI Codex CLI (openai/codex, `rust-v0.162.1`, published 2026-10-09) on a benchmark task. Its engine is named **codex exec security review** in the run metadata (`engine`) and in the SARIF (`tool.driver.name` `codex-exec-security-review`, `properties.engine`). It is not OpenAI's Codex Security product, and its results must never be reported as that product's. This file records what was found about the tools, why the agent is built this way, and what has and has not been checked.

## Codex Security CLI or `codex exec`

Checked on 2026-10-12 against primary sources:

- **Codex Security CLI exists.** Its CLI reference is at `https://learn.chatgpt.com/docs/security/cli/reference.md`. The package is `@openai/codex-security` on npm (latest `0.2.0`, published 2026-10-06, Apache-2.0, binary `codex-security`, Node `^22.13.0 || ^24 || ^26`, and Python 3.10+ for scans). The commands earlier research named are real: `scan` with `--headless`, `--max-cost USD` (an estimate, "not a hard cap"), `--json`, `--output-dir`, `--model` (default `gpt-5.6-sol`), `--effort` (default `xhigh`), `--auth {auto,chatgpt,api-key}`; `export <scan_dir> --export-format sarif`. An API key works headlessly (`OPENAI_API_KEY` or `CODEX_API_KEY`, or `codex-security login --with-api-key` on stdin).
- **It is gated.** Its docs say "Scans using OpenAI inference require Codex Security access", and that full-repository scans may also require Trusted Access for Cyber. They do not say that a plain API key has that access. The package also depends on 18 other npm packages (among them `@openai/codex` and `@openai/codex-sdk` at `0.162.0-alpha.15`), so pinning it would take a lockfile of its whole dependency tree.
- **So this agent runs the faithful fallback**: the Codex CLI's non-interactive `codex exec`, with a fixed security review prompt, a JSON output schema, Codex's read-only sandbox, no approvals, the `--json` event stream and an isolated config. Running the Codex Security CLI itself, once access is confirmed for the key, is a follow-up (a second engine, its own pins with an npm lockfile, Node from nodejs.org with SHA256, and its `export --export-format sarif` output normalised the same way).

Every Codex flag and config key used here was verified on the pinned binary (`codex --help`, `codex exec --help`, `codex login --help`, `codex sandbox --help`, `codex features list`, `codex debug models --bundled`, `codex debug prompt-input`) and in the source at the release tag (`codex-rs/exec/src/exec_events.rs` for the event stream, `codex-rs/core/config.schema.json` for the config, `codex-rs/core/src/client_common.rs` for the schema's `strict: true`, `codex-rs/prompts/templates/review/rubric.md` for Codex's own review format).

## Install (`pins.py`, `install.py`)

Three release assets per CPU (x86_64 and aarch64, static musl builds), each a `.tar.gz` holding one executable, downloaded from the GitHub release at setup into `<work dir>/codex-security` (or used from `/opt/sast/codex-security` when a tools image bakes it; none does yet):

| File | Why |
|---|---|
| `bin/codex` | the CLI. `codex --version` must print `codex-cli 0.162.1` |
| `bin/codex-code-mode-host` | the newer models of the bundled catalog (`tool_mode: code_mode_only`, among them the default `gpt-5.6-sol`) reach the shell through this JavaScript tool host. Without it 0.162.1 reports "Code Mode is unavailable ... host executable was not found" and fails the tool closed (seen on the real binary) |
| `bin/codex-resources/bwrap` | the bubblewrap build Codex's Linux sandbox uses. Without it `codex sandbox` panics "bubblewrap is unavailable" |

Each tarball must match the sha256 GitHub publishes as the asset's `digest` (checked against the downloads), and each extracted executable its own pinned sha256, before anything runs. The npm package `@openai/codex@0.162.1` ships the same binaries in its platform packages (about 450 MB unpacked each), so the release assets are used and Node.js is not needed. Download size per setup is about 140 MB (x86_64), within Harbor's setup limit on a normal link; baking the part into the tools image is a follow-up.

## Credential

`OPENAI_API_KEY` or `CODEX_API_KEY` on the host (option `auth`: `auto`, `openai_api_key`, `codex_api_key`; `auto` prefers `OPENAI_API_KEY`). Both names are real: Codex Security's docs name both, and the Codex source's exec tests set `CODEX_API_KEY`. The key is handled with the Claude review's helpers: uploaded into a mode 700 folder, copied under umask 077 into a mode 600 file, removed in a `finally`. The driver reads that file and gives the key to `codex login --with-api-key` on its stdin. Codex stores it in the private `CODEX_HOME/auth.json` (mode 600, `cli_auth_credentials_store = "file"`), and the driver deletes the whole `CODEX_HOME` in a `finally`. The key is never on a command line, in Harbor's exec env, in Codex's environment, in the metadata, a log or an artifact. All kept output is scrubbed of the key and of masked forms of it (`sk-...***abcd`), which OpenAI's error messages and `codex login status` print.

## Scope

The driver copies the in-scope files (task `scanner_roots` minus `excluded_paths`, decided on the host as for every agent) and `security_manifest.json`, at the same relative paths, into `<work dir>/codex-scope`, and runs Codex there (`-C`). In the read-only sandbox the model's commands also cannot read `/app/repo`, the key folder, `CODEX_HOME` (auth.json), the agent's `out/` folder or `/logs`: the config's permissions profile denies them. Every command the model ran is kept from the event stream (the command only, scrubbed and cut to 300 characters, never its output) and a command that names one of those paths is flagged (`commands_outside_scope`, also in the SARIF's `runs[0].properties.sastAgent.commandsOutsideScope`). Reported paths under the copy are made relative again; anything else must pass the usual scope and line checks.

## The sandbox

Codex's Linux sandbox is bubblewrap with unprivileged user namespaces. **A default Docker container does not allow those** (Docker's seccomp profile blocks them): on the pinned binary in `python:3.12-slim`, every sandboxed command fails with "bwrap: No permissions to create a new namespace". With `--security-opt seccomp=unconfined` the same container runs it, reads work, writes fail with "Read-only file system" and the denied paths give "Permission denied" (checked with `codex sandbox` and with a whole `codex exec` run). Harbor sets it through a Compose overlay: `harbor run ... --extra-docker-compose harbor/codex-sandbox.compose.yaml` adds `security_opt: [seccomp=unconfined]` to the task container (`main`) only. Checked in a real Harbor run on 2026-10-13 on `crewai-code-interpreter-a`: with the overlay the sandbox probe passes (exit 0, no sandbox failures) and the run reaches the OpenAI API; without it the trial stops with `sandbox_unavailable`. Trade-off: the task container loses Docker's syscall filter, while every model command runs in the read-only bubblewrap sandbox that sees only the in-scope copy. Daytona's support is unknown.

Option `sandbox`:

- `read-only` (default): the config's permissions profile `sast-review` extends Codex's built-in `:read-only` (read anywhere, write nowhere, no network) with `deny` entries for the private paths above. The driver first runs `codex sandbox -- true` with that config. If it fails, the run stops with `sandbox_unavailable` (an infrastructure error) instead of producing a review in which every command failed. A review in which every command failed in the sandbox anyway is also an error (`sandbox_failed`).
- `container`: an explicit opt-in that turns Codex's sandbox off (`--dangerously-bypass-approvals-and-sandbox`, `sandbox_mode = "danger-full-access"`) and leaves the task container as the only boundary. The model's commands can then read `/app/repo` (including excluded paths), `CODEX_HOME/auth.json` and the key file while it exists, write files and use the network. Only the prompt, the working directory and the flagged command list stand between the review and out-of-scope files. Use it only where that is acceptable, and report such runs as such (`sandbox` is in the metadata and the SARIF). This mode has run only against the scripted fake CLI, not the real binary.

## Isolation from user and repository configuration

`CODEX_HOME` and `HOME` are fresh private folders, and Codex gets only an allow-listed environment (the Claude driver's list: PATH, locale, temp dir, CA bundles, proxies), so no `OPENAI_*`, `CODEX_*` or other host setting reaches it. The config file (checked with `codex exec --strict-config` on the real binary) sets: the model and optional `model_reasoning_effort`; `approval_policy = "never"`; `web_search = "disabled"`; `project_doc_max_bytes = 0` and `project_root_markers = []` (no AGENTS.md of the reviewed code is read, verified with `codex debug prompt-input` on a folder holding one); analytics, feedback, update checks and history off; the features `apps`, `plugins`, `multi_agent`, `hooks`, `browser_use`, `computer_use`, `image_generation`, `memories`, `goals` and `daemon_auto_start` off; bundled skills and the skills block off. No MCP server is configured. `codex exec` also gets `--ignore-rules` (no execpolicy files), `--ephemeral`, `--skip-git-repo-check` and `--color never`. With this config the model-visible prompt is only Codex's own instructions, the permissions block, the environment context and our prompt.

## Prompt, schema and modes (`request.py`)

- **stock**: `stock_prompt.txt`, a fixed whole-repository security review prompt written in the style of Codex's own review rubric (discrete, actionable, no speculation, short line ranges, priorities P0 to P3), and an output schema with Codex's own review finding shape (`title`, `body`, `confidence_score`, `priority`, `code_location.absolute_file_path`, `code_location.line_range.start/end`) plus `category` and a `cwe` list, and an `analysis_summary` (`files_reviewed`, `review_completed`). Nothing task-specific.
- **scoped**: the same prompt plus the task's output contract, read from the instruction Harbor passes to `run` with `sast/claude_review/contract.py` and written with the Claude review's fixed preamble (`contract.scan_instructions`, one sentence about upstream Claude's free-text field removed): read `security_manifest.json` first, the Scope table, the six fields and the Recommendation catalogue. The schema adds `rule_id`, `path` (file, line, role), `control_status`, `residual_risk` and `recommendation_ids` with the contract's own vocabularies as enums. When the instruction carries no contract, the harness's own constants are used (`contract_source: harness_constants`).

Codex sends the schema to the Responses API with `strict: true` (verified in the request the real binary made to a local fake API), so every object lists all its properties as required, forbids others, and an optional value is a `null` union. A test checks that no prompt shares a six-word run with any ground truth.

## Normalisation (`normalise.py`)

The Claude review's rules and helpers (`sast.claude_review.normalise`): a location must be an in-scope text file the driver counted and a line inside it (`line_range.end` is used when valid, else the start line, counted as `end_line_replaced`); CWEs come from the model's list when one is well formed, else the Claude review's category table (`table_fallback`); in scoped mode a valid `rule_id` decides the ruleId (an ambiguous CWE set without one is dropped and counted), path steps, control status, residual risk and catalogue ids are kept only when valid, and everything rejected is counted. Codex's `priority` gives the level: P0 and P1 `error`/high, P2 `warning`/medium, P3 `note`/low, anything else `warning`/medium (counted). Stock mode uses none of the assessed fields. A finding the SARIF writer cannot map to a task ruleId is not emitted and is counted (`unmappedCwe`). Drops and re-maps are in `runs[0].properties.sastAgent`.

## Failures

Infrastructure (`ScannerError`, trial errored and re-runnable): no key on the host, install or hash failure, the network check fails, `codex login` fails, the API refuses the key (`api_auth`), no quota, an unknown model, rate limiting or network errors that outlast Codex's own retries, the sandbox cannot start, every turn failed on the service side (`cli_failed`). Tool outcomes (`ToolOutcome`, no SARIF, scored 0): the deadline (`deadline`), `review_completed` false, `files_reviewed` 0, a context-window overflow (`prompt_too_long`), an answer that is not the schema's JSON after all attempts (`bad_review_output`), codex crashing without an answer (`tool_crashed`), more than 5,000 files in scope. An attempt without a usable answer is retried (`attempts`, default 2); a refused key, an unknown model, no quota or a closed network stop at once.

## Metadata

`engine`, `model`, `model_source`, `reasoning_effort`, `mode`, `sandbox`, `auth_source` (the variable's name, never its value), the pinned and reported Codex version, the scan duration, token usage per attempt and in total (`usage`: input, cached input, output and reasoning tokens; Codex reports no cost, so `cost_usd` is null), the thread id, the attempts, the commands and the flagged ones, the sandbox probe, the deny list, the scope copy, prompt/schema/config sha256, and the normaliser's counts. The driver's whole result document is kept as the artifact `codex_security.json`.

## Deviations from Codex's defaults, and why

| Codex default | Here | Why |
|---|---|---|
| the user's `~/.codex` config, auth, skills, plugins, MCP servers | a fresh private `CODEX_HOME` with our config only | the reviewer must not be configured by the host or the repository |
| AGENTS.md of the working tree is read into the prompt | `project_doc_max_bytes = 0` | the repository is task content |
| `workspace-write` or `read-only` sandbox | `read-only` plus a deny list, or the explicit `container` opt-in | read-only review, no access to the real repository or the key |
| approvals on request | `approval_policy = "never"` | non-interactive |
| web search cached | disabled | static review of the given files |
| model and effort from the user's config or the catalog | `gpt-5.6-sol` (Codex Security's documented default scan model) unless `model` says otherwise; effort is the model's own default (`low` for `gpt-5.6-sol` in the 0.162.1 catalog) unless `reasoning_effort` says otherwise | a fixed model per run, recorded. Codex Security itself defaults to effort `xhigh`; pass `--ak reasoning_effort=xhigh` to match it |
| free-form final message | `--output-schema` (strict JSON) | parseable findings, never inferred from prose |
| no cost or turn cap | none either; only the agent's time limit | `codex exec` has no budget or turn flag |

## Verified, and not verified

Verified for real (no key, no OpenAI call except one with a made-up key):

- The Codex Security CLI's existence, flags, gating and package facts, from its docs and the npm registry.
- The pinned release assets: downloaded, sha256 equal to GitHub's published digests, extracted file hashes pinned; `install.py` installed them from a local server in Docker and `codex --version` printed `codex-cli 0.162.1`.
- Every flag and config key, on the binary, including `--strict-config` acceptance of the generated config.
- `codex login --with-api-key` reads stdin and writes `auth.json` mode 600, offline; `codex login status` reports an API key login.
- The event stream of a whole `codex exec` run of the real binary against a local fake Responses API in Docker (`--network none`): the schema sent with `strict: true`, the shell command run in the scope copy, the final answer in the stream and in the `-o` file, token usage. The driver ran end to end on a copy of `crewai-code-interpreter-a` with the real binary: login, sandbox probe, review, a finding with a path, relativisation, `CODEX_HOME` removed, the key in no file. The fake API received the key as `Authorization: Bearer`, so the stored login is what Codex uses.
- The read-only sandbox in Docker: fails by default; with `seccomp=unconfined` it reads the scope, denies `/app/repo`, auth.json and the key file, and blocks writes (seen in the command output the real binary returned to the fake API).
- A made-up key against the real api.openai.com: `turn.failed` with "401 Unauthorized ... invalid_api_key", classified `api_auth`.

Not verified (needs a real key):

- Any real review: findings quality, run time, token use, and whether the default model `gpt-5.6-sol` is available to the key.
- That the Responses API accepts the generated schemas under `strict: true` (enums with `null`, nested objects). They follow the documented rules.
- The `container` sandbox mode on the real binary (not run here).
- The Codex Security CLI itself, and whether a plain API key has Codex Security access.

## Follow-ups

- Bake `/opt/sast/codex-security` into the tools image (and add it to `sast/manifest.py`'s `PARTS`, so the install is rehashed against `MANIFEST.json`).
- Done: `harbor/codex-sandbox.compose.yaml` lets the default read-only sandbox run under Harbor's Docker environment. Daytona and other environments still unchecked.
- A second engine for the Codex Security CLI once access is confirmed.
