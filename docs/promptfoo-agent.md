# Promptfoo Code Scanning agent: design notes

`sast.promptfoo.agent:PromptfooCodeScanAgent` runs [Promptfoo Code Scanning](https://www.promptfoo.dev/docs/code-scanning/cli/) (`promptfoo code-scans run`) on a task. The CLI is open source (pinned at promptfoo 0.124.1); the scan itself runs on the hosted Promptfoo service at `https://api.promptfoo.app`, which needs a Promptfoo API key and outbound HTTPS (websocket) from the task container. The agent follows the Claude Code security review agent's standard (`docs/claude-review-agent.md`): pinned and hash-checked install at setup, the key in a mode 600 file and nowhere else, a scoped copy of the repository, the task's own output contract as guidance in scoped mode, a strict normaliser, and the same split between infrastructure errors and tool outcomes.

## How a run works

1. `setup` uploads `install.py`, `scan.py`, `pins.json`, `package.json` and `package-lock.json` and runs `install.py` with the sandbox's `python3`. It installs Node.js, git and promptfoo into `<work dir>/promptfoo-local` (a part baked at `/opt/sast/promptfoo` would be used instead, but the tools image does not bake it yet). Measured in `python:3.12-slim` (the task base image) on 2026-10-12: about 21 s, 491 MB on disk.
2. `scan` lists the in-scope files (the task's `scanner_roots` minus `excluded_paths`, as every agent does), writes the key file, and runs `scan.py` once, bounded by `timeout -k`.
3. `scan.py` copies the in-scope files and `security_manifest.json` into `<work dir>/scope-promptfoo` (same relative paths, no links, nothing else of `/app/repo`), turns that copy into a git repository with an empty commit on `main` and every file committed on `scan`, and runs `promptfoo code-scans run <copy> --base main --compare scan -f json` (plus `--guidance-file` in scoped mode). The whole scope is the change set, which is what the owner's working recipe does by hand.
4. The JSON response is normalised (`normalise.py`) into findings, which the shared SARIF writer turns into the task's SARIF profile.

## Deviations from promptfoo's defaults, and why

- **A synthetic change set.** promptfoo scans what changed between two git refs; on a repository with no changes it answers "No files to scan". The copy-and-commit recipe makes every in-scope file an added file. It also keeps everything evaluator-only out of reach: the service only sees the diff of the copy and, through promptfoo's filesystem MCP server, files under the copy (verified: the pinned server refuses `/etc/passwd` with "path outside allowed directories").
- **git from Debian.** The task images have no git, and promptfoo shells out to it (`git diff --raw/--numstat/--patch`, `cat-file`, `status`, `branch`, `rev-parse`, `log`). The installer takes only `/usr/bin/git` from the pinned `git_2.47.3-0+deb13u1` .deb (all those commands are built into it; it links libc, libpcre2-8 and zlib, which the image has). System and global git config are ignored, hooks are off, and `git add -A -f` makes a `.gitignore` in the copy hide nothing.
- **`-f json`, not SARIF.** promptfoo builds its SARIF from the same response (`scanResponseToSarif`) and adds nothing: one generic rule `promptfoo/code-scan-finding`, the severity, the prose, `fix` and `aiAgentPrompt`. The JSON keeps `startLine` and `line` apart and keeps the "none" (all clear) comments, so it carries a little more.
- **The key in the child's environment.** promptfoo reads `--api-key`, then `PROMPTFOO_API_KEY`, then its stored login (`resolveBaseAuthCredentials`). The agent uses the variable, set in the promptfoo process's own environment only, never `--api-key` (which would put it on a command line).
- **A private, empty working directory.** promptfoo loads `.env` from its working directory, so it never runs in the copy (a repository's `.env` could change its settings or key). Its `HOME` and `PROMPTFOO_CONFIG_DIR` are private and deleted after the run (they may hold logs), the environment is an allow-list (no `PROMPTFOO_*` or proxy override from the host other than the standard proxy and CA variables), and `PROMPTFOO_DISABLE_TELEMETRY=1` and `PROMPTFOO_DISABLE_UPDATE=1` are set.
- **No `api_host` option.** The key only ever goes to promptfoo's default host.
- **A pruned lock.** promptfoo 0.124.1 has 27 optional dependencies (cloud SDKs, sharp, agent SDKs); a full install is 1.4 GB. `npm/prune_lock.py` keeps what is reachable through required edges plus the glibc libsql binding, which promptfoo loads at start-up (373 entries, 270 MB). The filesystem MCP server, optional in promptfoo's own package.json, is a direct dependency of ours. `npm ci` refuses a pruned lock ("not in sync"), so `install.py` installs it the way `npm ci --ignore-scripts` would: every tarball from registry.npmjs.org only, checked against the lock's sha512 integrity, unpacked at the lock's path, no install scripts, links in archives skipped.
- **Defaults kept.** `--min-severity` is not passed (promptfoo's default, medium) and `--diffs-only` is off (promptfoo's default, "diffs + tracing into repo"). Both are options.

## Modes

**Stock** passes no guidance. promptfoo's findings name no task ruleId, CWE, path, control status or recommendation, so none of them can be scored: the SARIF has no results, and every finding is kept in `runs[0].properties.sastAgent.toolFindings` and `dropped.noTaskRule` and in the run metadata (`tool_findings`, `dropped_no_task_rule`). A stock run therefore scores like an empty SARIF; its value is the record of what promptfoo found. No mapping from promptfoo's prose to a ruleId is made (it would be guessing); one can be added if the owner approves a rule.

**Scoped** passes `--guidance-file` with a fixed preamble and the task's own tables, parsed from the instruction Harbor passes to `run` (`sast/claude_review/contract.py`; the harness's own ids when the instruction has none, recorded as `guidance_source: builtin`). The guidance asks every finding to start with a header (`pf-header-1`):

```text
RULE=LLM03.EA.FUNCTIONALITY; CWE=CWE-94; CONTROL=none; RISK=high; RECS=REC-NARROW-TYPED-TOOLS,REC-POLICY-GATE
PATH:
src/app/agent.py:40 model_decision
src/app/tools.py:12-14 sink

The calculator tool passes the model's expression to eval() ...
```

The normaliser reads only that header (the first non-empty line, after an optional code fence, with Markdown emphasis or backticks around it removed) and never the prose:

- `RULE` must be one of the contract's ruleIds; without it the finding is not emitted (counted in `dropped.noTaskRule`). The header's CWEs are not used to guess a ruleId.
- `CWE` keeps well-formed `CWE-<n>` ids; `CONTROL`, `RISK` keep the profile's values; `RECS` keeps catalogue ids; each `PATH` step `<file>:<line>[-<end>] <role>` must be an in-scope text file of the copy and a line range inside it. Every rejected value is counted (`dropped.headerValues`, `dropped.pathSteps`).
- The finding's location is promptfoo's own `file`, `startLine` and `line`, checked the same way. Severity gives the SARIF level (critical/high: error, medium: warning, low: note) and the heuristic residual risk under `properties.heuristics`.

## Failure policy

Infrastructure (`ScannerError`, the trial is errored and can be re-run): no `PROMPTFOO_API_KEY` on the host (also refused at preflight), install failures, a refused key ("Authentication failed: Invalid API token"), the service unreachable or busy ("Failed to connect to server", "Server at capacity"), a broken git or MCP set-up, an unreadable runner result.

Tool outcomes (`ToolOutcome`, no SARIF, scored 0): the scan budget ran out (`deadline`), promptfoo failed with any other error (`tool_crashed`), its stdout held no JSON response (`bad_review_output`), or it scanned nothing ("No files to scan", a skip reason: `tool_saw_nothing`).

## What the metadata records

`promptfoo_scan`: versions, mode, `min_severity`, `diffs_only`, `auth_source` (the variable name, never the value), the guidance source and sha256, the contract ids, the scope copy (files, skipped, binary, and the files promptfoo will leave out of the change set: over its 512 kB blob limit or in its denylist, such as `build/`, `dist/` or `*.lock`), the git change set, promptfoo's argv and environment names, exit code, seconds, stderr tail, review summary, comment count, and `cost_usd: null` (promptfoo reports no cost, tokens or model; `model` is null with `model_source` saying the service chooses it). The normaliser adds `headers` (valid/missing/malformed), `tool_findings`, the drop lists and `assessed_fields`. Artifacts: `promptfoo_scan.json` (the runner's result, key-scrubbed) and `promptfoo_guidance.txt`.

## Verified and not verified

Verified for real (2026-10-12, in `python:3.12-slim@sha256:a6e34c59...`, the task base image):

- `install.py` installs Node.js 24.21.0, git 2.47.3 and the 371 linux-x64 packages of the pruned lock with every hash checked, in about 21 s; `promptfoo --version` prints 0.124.1 and `code-scans run --help` lists the flags the owner listed.
- `scan.py` on `crewai-code-interpreter-a` builds the copy (19 files) and the two-commit repository with the pinned git, starts promptfoo with the key only in its environment, reaches `api.promptfoo.app`, and with a made-up key gets "Authentication failed: Invalid API token", classified as `auth`. With no key: "Authentication required".
- The pinned filesystem MCP server starts with the copy as its root and refuses paths outside it.
- The nodejs.org tarballs (both CPUs) and the git .debs (both CPUs) were downloaded and match their pinned sha256; promptfoo's `dist.integrity` equals the lock's.

Only with fakes (the key is on the owner's host only): a real scan through the service, the response's shape beyond promptfoo's own zod schema (`CommentSchema`), whether the service follows the scoped header, how long a scan takes, and the arm64 install. The agent's own logic (options, key handling, request, guidance, normaliser, outcomes, SARIF, grading on `smoke_eval`) is covered by `tests/test_promptfoo_*.py`.

## Follow-ups

- Bake the part into the tools image (`install.py --build --target /opt/sast/promptfoo`) to drop the setup downloads (nodejs.org, deb.debian.org or snapshot.debian.org, registry.npmjs.org) from every trial.
- After the first real scoped runs, check the header rate (`headers` in the metadata) and adjust the guidance wording if the service ignores it.
- To change a pin: edit `npm/package.json`, run `npm install --package-lock-only --ignore-scripts` in a scratch copy, prune it with `python npm/prune_lock.py <full lock> npm/package-lock.json`, update `pins.py` (versions, integrity, lock sha256 with LF line ends, entry count) and bump `sast.__version__`.
