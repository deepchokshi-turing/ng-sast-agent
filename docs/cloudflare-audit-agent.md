# Cloudflare security-audit skill agent

`sast.cloudflare_audit.agent:CloudflareAuditAgent` runs Cloudflare's open-source security-audit agent skill ([cloudflare/security-audit-skill](https://github.com/cloudflare/security-audit-skill), MIT) inside the Claude Code CLI, in the task sandbox, and turns the skill's own `findings.json` into the benchmark's SARIF profile. The SARIF driver name is `cloudflare-security-audit-skill`; the agent name is `cloudflare-security-audit`.

## What the tool is (checked against its source)

The desk research was checked against a read-only clone at commit `c1c8a8c` (2026-09-14). Where it was right and where it was not:

- It is an agent skill, not a program: `SKILL.md` plus companion Markdown files (reconnaissance, hunting, attack classes, validation and reporting, and domain files such as `AI-AND-LLM.md`), a JSON schema for `findings.json` (`report-schema.json`) and two zero-dependency Node.js validators (`validate-findings.cjs`, `validate-coverage-ledger.cjs`). No code of its own calls a model.
- It needs sub-agents: a full audit runs reconnaissance agents, hunter agents per coverage unit, coverage critics and a fresh verifier per candidate, through "the platform's delegation or sub-agent mechanism" (in Claude Code the `Task`/`Agent` tool).
- Harnesses: the skill says it is agent-neutral (any coding agent with tool use and parallel sub-agents), and upstream installs it with the Skills CLI (`npx skills add`), which supports several agents. Only Claude Code is used here: it is the harness we have pinned, and the only credential we have that fits is `CLAUDE_CODE_OAUTH_TOKEN` (Claude Code only). Codex with `OPENAI_API_KEY` would be the other candidate; it is not built.
- Structured traces: yes. Every record has a `trace` of `{kind: entrypoint | propagation | sink, file, line, scope, description}`; the validator enforces that a multi-step trace starts at `entrypoint`, ends at `sink` and has only `propagation` between.
- "A fix per finding": only for `confirmed` records (`remediation.strategy` and optional `remediation.code_changes`). `needs_validation` records carry `blockers` and a `validation_plan` instead; `rejected` records carry a `reason`.
- Vulnerability classes: `AI-AND-LLM.md` covers prompt-injection consequences, "Excessive agency and confused-deputy authority", tool-argument injection, sub-agent and MCP trust, insecure output rendering and "Sensitive context extraction". It does not use OWASP ids (no "LLM02" string anywhere); the mapping to the task's ruleIds is ours (see Mapping).
- What it does not give: no CWE, no ruleId, no single "code that must change" location, no control status, residual risk or catalogue recommendation. `report-schema.json` forbids extra fields (`additionalProperties: false`), so these cannot be added to `findings.json` itself.

Fit verdict: it fits, with one side file. It runs headless (`claude -p`) on a local folder with the subscription token we have, and its traces and fixes are structured. The missing fields are asked for in a separate file, `sast-annotations.json`, keyed by the record's fingerprint (see Request).

## What a run does

1. Setup installs, hash-checked, into `<work dir>/cloudflare-audit` (the "-local" suffix is added when the work dir is `/opt/sast`): the Claude Code 2.1.296 native binary (the same npm tarball, sha256 and sha512 integrity as the Claude review agent, through its installer), `bin/node` from the official Node.js 24.21.0 tarball (nodejs.org, sha256 from SHASUMS256.txt, the Promptfoo agent's pin), and the 19 pinned skill files from raw.githubusercontent.com at commit `c1c8a8c`, each checked against its sha256 (the validators' own `*.test.cjs` files are not installed). `claude --version` and `node --version` must print the pinned versions. Nothing is baked into the tools image yet (follow-up).
2. The in-scope files (task `scanner_roots` minus `excluded_paths`) and `security_manifest.json` are copied to `<work dir>/cloudflare-scope`, at the same relative paths. That copy is the audit's target. `/app/repo`, the task's `tests/`, `solution/` and `validation/` are never in it.
3. The skill's files are copied (sha256 checked again) to `$HOME/.claude/skills/security-audit` of a fresh private HOME, where Claude Code loads user skills. The init message must list `security-audit` among its skills.
4. Claude Code runs in the scope copy: `claude -p --output-format stream-json --verbose --model <m> --permission-mode dontAsk --settings <private settings> --setting-sources user --strict-mcp-config --no-session-persistence --add-dir <output root> <skill dir>`, prompt on stdin. The init message must name the requested model, credential source `none` (token) or `apiKeyHelper` (API key), permission mode `dontAsk`, a sub-agent tool (`Task` or `Agent`), and none of the denied tools; otherwise the run stops before anything is spent.
5. Afterwards the driver reads `run-metadata.json`, `findings.json`, `coverage-ledger.json`, `sast-annotations.json` and `REPORT.md` from the output folder, runs both validators itself under the pinned Node.js, and makes trace, evidence and annotation paths relative to the target again.
6. `normalise.py` turns the records into findings (Mapping below), and the shared SARIF writer writes `/app/output/findings.sarif`.

Permissions (`--permission-mode dontAsk`: anything not allowed is refused without asking): Read on the scope copy, the skill and the output root; Edit and Write on the output root only; Bash only for the two validator command lines, `mkdir -p` inside the output root and read-only commands (`ls`, `cat`, `head`, `tail`, `wc`, `grep`, `rg`, `find`, `file`, `stat`, `cd`, `pwd`, `echo`, `printf`, `sort`, `uniq`, `cut`, `tr`, `nl`, `diff`, `basename`, `dirname`, `realpath`, `du`, `test`, `true`). Denied: WebFetch, WebSearch, NotebookEdit, cron, worktree, Workflow, DesignSync and RemoteTrigger tools; Read of `/app/repo`, the key folder, the agent's request and result folder and `/proc`; Bash patterns `*-exec*`, `*-ok *`, `*-delete*`, `*-fprint*`, `*--pre*` (find and rg options that run programs or delete), anything naming `/proc`, `/app`, `secret`, `environ`, `CLAUDE_CODE`, `OAUTH`, `ANTHROPIC` or expanding `${...}`. Every tool call (path, pattern, command or sub-agent type, never a prompt) is recorded, scrubbed, with calls the rules refused marked `refused` and calls naming a denied path flagged.

The credential is handled as in the Claude review: read on the host from `CLAUDE_CODE_OAUTH_TOKEN` (or `ANTHROPIC_API_KEY`), never on a command line or in Harbor's exec env, uploaded into a mode 600 file in a mode 700 folder, given only to the CLI process (the token as `CLAUDE_CODE_OAUTH_TOKEN` in that process's own environment; an API key through an `apiKeyHelper` that reads the file), removed in a `finally`, and scrubbed from every output kept. The shell commands the CLI runs inherit its environment, so with a token they could see it: Claude Code's `CLAUDE_CODE_SUBPROCESS_ENV_SCRUB=1` would strip it, but in 2.1.296 that switch requires bubblewrap, which the task images lack (the CLI exits at once; seen in a real trial), so instead commands naming `CLAUDE_CODE`, `OAUTH` or `ANTHROPIC`, expanding `${...}` or reading `/proc` are denied, and `env`/`printenv` are not on the allow list.

## Request

The skill is unchanged. The request is the user turn that starts it, as the skill's README shows (`do a security review, output to ~/audits/my-project`), with the answers the skill would otherwise ask a user for:

- an explicit full-audit request (so the skill runs its six phases, not guidance mode);
- the skill directory, the target (a plain copy, source ref `unversioned-copy`), the output directory (`<work dir>/cloudflare-audit-out/run-1`, outside the target, as the skill requires), the profile, the budget, "no prior runs";
- "no OS-enforced sandbox for target-controlled code: do not build, run or test target code" (the skill's own rule keeps such leads `needs_validation`);
- the tool limits above and the two validator command lines, each to be run on its own.

Then the side file, `sast-annotations.json`, `{"findings": [...]}`, one entry per `confirmed` or `needs_validation` record, keyed by `fingerprint`:

- stock mode: `cwe` only (the skill gives none, and without a CWE no finding can be mapped to a task ruleId);
- scoped mode (the default): the task's output contract, parsed from the instruction Harbor passes to `run()` (`sast/claude_review/contract.py`; the harness constants when the instruction carries none), as guidance (ruleId definitions, the `security_manifest.json` pointer, the catalogue), and per entry `rule_id`, `cwe`, `location` (file, start and end line of the code that must change), `trace_roles` (one per trace entry), `control_status`, `residual_risk`, `recommendation_ids`. A record that is both a disclosure and an agency risk gets two entries.

## Mapping

| SARIF field | From |
|---|---|
| `ruleId` | scoped: the side file's `rule_id` when it is one of the five task ids; otherwise (and in stock mode) the side file's CWEs through `cwe_map`. No valid id and no mapped CWE: not emitted, counted (`unmappedCwe`) |
| `locations[0]` | scoped: the side file's `location` when it is an in-scope text file and a line of it; else the trace's `sink` step; else the record is dropped and counted |
| `codeFlows` | the skill's `trace`. `entrypoint` -> `source` (or `model_decision` from `trace_roles`), `propagation` -> no role unless `trace_roles` names `context_assembly`, `model_consumption`, `control_point` or `root_cause`, `sink` -> `sink`. Each step must be an in-scope file and line; a trace that no longer runs from its entrypoint to its sink is dropped whole |
| `properties.cwe` | the side file's `cwe` (well-formed ids only) |
| `controlStatus`, `residualRisk`, `recommendations` | scoped only, the side file's values when they are the contract's values or catalogue ids |
| `level` | the skill's `severity.overall_severity` (critical/high: error, medium: warning, low/informational: note); `needs_validation` has no severity (warning) |
| `properties.toolProperties` | verbatim, for a later LLM judge: `recommendation` (remediation strategy), `remediationCodeChanges` (JSON), `rootCause`, `intendedBehavior`, `exploitScenario`, `observedResult`, `blockers`, `validationPlan`, plus verdict, fingerprint, title, confidence, severity, trace kinds, location and CWE source |

`rejected` records are never reported; `needs_validation` records are reported by default (`include_needs_validation=false` turns that off). Every drop and re-map is in the run metadata and in `runs[0].properties.sastAgent` (`badRecord`, `notReported`, `traceDropped`, `noAnnotation`, `outOfScope`, `badLocation`, `remapped`, `toolUsesOutsideScope`, `runStatus`, `recordsByVerdict`, `validators`).

Graded now: ruleId, location, codeFlows roles, controlStatus/residualRisk and REC ids (scoped mode, from the side file). Waiting for an LLM judge: the skill's own fix text, root cause, exploit scenario and validation plan, kept verbatim under `toolProperties`; no catalogue id is ever derived from that prose.

## Failure policy

Tool outcomes (no SARIF, scored 0): the deadline; `run_status` in `run-metadata.json` other than `complete` (the skill's own terminal states are `complete` and `incomplete` with a reason; a run that stopped mid-workflow leaves `in_progress`); no `findings.json`; a findings file that is not a list of objects; the CLI's turn or budget limit; a prompt too long. Infrastructure errors (`ScannerError`, re-run): install failures, a missing or refused credential, no network to api.anthropic.com, a wrong model, a CLI that would not take the permission settings, no sub-agent tool, the skill not loaded, a tampered skill file, a CLI that failed on every attempt.

## Deviations from the tool's defaults, and why

- Installed by hash-pinned download into `~/.claude/skills/`, not with `npx skills add` (no unpinned installer).
- Profile `quick` by default (the skill's default is `standard`): one hunter wave, one critic, one verifier per candidate, to fit a benchmark time limit. `--ak profile=standard|deep` restores it.
- No target code is executed (no OS sandbox inside the task container that meets the skill's requirements); the skill then keeps execution-dependent leads `needs_validation`, which is why those are reported by default.
- Tools are restricted by `dontAsk` permissions (above); the skill's own write-isolation procedure (descriptor-based promotion) is not needed because nothing target-controlled runs.
- The side file `sast-annotations.json` is added; `findings.json` stays schema-valid.
- The model is fixed by the agent (`claude-opus-5-5` by default; the skill names none) and checked in the CLI's init message.

## Options (`--ak key=value`, or `CLOUDFLARE_AUDIT_<KEY>` on the host)

| Option | Default | Meaning |
|---|---|---|
| `model` | `claude-opus-5-5` | Claude Code `--model`; Harbor's `-m` is used when it names an Anthropic model |
| `mode` | `scoped` | `stock`: the skill's audit plus a CWE side file. `scoped`: plus the task's contract and the full side file |
| `auth` | `auto` | `oauth` (`CLAUDE_CODE_OAUTH_TOKEN`), `api_key` (`ANTHROPIC_API_KEY`), `auto` (API key first) |
| `profile` | `quick` | the skill's `quick`, `standard` or `deep` |
| `agent_budget` | none | the skill's strict budget (agent invocations) |
| `include_needs_validation` | `true` | report `needs_validation` records |
| `max_turns`, `max_budget_usd`, `reasoning_effort` | none | Claude Code `--max-turns`, `--max-budget-usd`, `--effort` |
| `timeout_sec` | task timeout minus 120 s | wall-clock limit of the audit; keep Harbor's limit 120 s above it |
| `attempts` | 1 | CLI runs when a run ends without `findings.json` |
| `scan_roots`, `exclude` | the task's | as for the other agents |

## Verified, and not verified

Verified for real (2026-10-14, local Docker, the task base image): the pinned install (Claude Code 2.1.296, Node.js v24.21.0, 19 skill files, all hashes) in the sandbox; the CLI's flags (`--add-dir`, `--permission-mode dontAsk`, `--setting-sources user`, `--strict-mcp-config`, `--no-session-persistence`, `--effort`) from the pinned binary's `--help`; that `--setting-sources user` loads the skill from `~/.claude/skills` (init `skills`), that the sub-agent tool is called `Task` in the init list and `Agent` in tool calls, and the full audit run end to end with the subscription token on `crewai-code-interpreter-a` (see the trial below).

Verified with fakes only (`tests/test_cloudflare_audit_*.py`): option parsing, pins and install hash checks, the credential never on argv, env, metadata, logs or artifacts, the scope copy, the permission settings and argv, the init checks, every failure code, the normaliser on valid, invalid and partial outputs, the SARIF profile and the grade of a fake answer on the sample task `smoke_eval`.

Real trials on `crewai-code-interpreter-a` (local Docker, scoped, `claude-opus-5-5`, subscription token; the task copied to a scratch folder with only its first `FROM` changed to the local `sast-tools:0.5.0` tag, because local Docker cannot pull the digest-pinned GCR image without registry credentials):

- Run 1 (first build): the audit ran end to end (7 sub-agents, about 10 minutes, CLI-reported $4.78) but every validator command was refused, because the model chained it with `echo $?`; the skill then recorded `run_status: incomplete`, so the trial was a tool outcome, reward 0. Fixed by allowing more read-only commands and telling the model to run each validator on its own.
- Run 2: `run_status: complete`, both validators passed, one `needs_validation` record with two side-file entries (LLM02.SID.HIGH and LLM03.EA.AUTONOMY): reward 0.801 (detection 1.0, classification 0.8, path 0.37, controls 1.0, recommendations 1.0; 2 TP, 0 FP, 0 FN), CLI-reported $6.29, 875 s.
- A try with `CLAUDE_CODE_SUBPROCESS_ENV_SCRUB=1` failed at once (the CLI needs bubblewrap for it); that setting was removed.
- Run 3 (the final code): `run_status: complete`, validators passed, one `needs_validation` record with three side-file entries: reward 0.7333 (detection 0.8, classification 0.8, path 0.378, controls 1.0, recommendations 1.0; 2 TP, 1 FP, 0 FN), 9 sub-agent calls, CLI-reported $5.65, 743 s, key file removed, no credential in any kept file. 11 shell calls were refused (shell `for` loops, `sed`, and `mkdir -p` in the output folder, which the rule `Bash(mkdir -p <out>/*)` does not let through; the Write tool creates folders anyway), and 2 reads of the CLI's own saved tool output under its HOME were flagged as outside the audit's folders.

Every run reported its records as `needs_validation`, as expected when no target code may run, so the skill's remediation text (confirmed records only) was not exercised for real; its mapping is tested with fakes.

Not verified: `ANTHROPIC_API_KEY` auth for real (no key), Claude Code's handling of every deny pattern with a leading wildcard (refused calls are recorded so it can be checked per trial), other harnesses, and `standard`/`deep` profiles.
