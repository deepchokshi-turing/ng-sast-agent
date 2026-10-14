# Claude Code security review agent: design notes

`sast.claude_review.agent:ClaudeReviewAgent` runs
anthropics/claude-code-security-review at commit
`0c6a49f1fa56a1d472575da86a94dbc1edb78eda` (2026-02-11) on a benchmark task.
README.md has the setup and the commands. This file records why it is built
this way and what has and has not been checked.

## Why a driver instead of the GitHub Action

The action (`action.yml`, `claudecode/github_action_audit.py`) needs a pull
request on GitHub, a token and a PR number. Its library parts do not:
`prompts.get_security_audit_prompt` only reads a few PR fields,
`json_parser` is pure, and `FindingsFilter` and `ClaudeAPIClient` take the key
and the model as arguments. `sast/claude_review/driver.py` calls them directly
inside the sandbox. The scanner sees only the repository and its
`security_manifest.json` (client spec section 2.1): the synthetic pull request
holds the in-scope files and a neutral title, nothing from the task.

The scope is the task's `scanner_roots` minus `excluded_paths`, decided on the
host with `sast.scope.in_scope` from a `find` listing of the sandbox, as for
the other agents. Every finding is checked against that scope again.

The CLI's reads are confined to that scope (audit A8). The driver copies the in-scope files, at the same relative paths, and `security_manifest.json` into a scratch folder under the work dir (`make_scope_copy`) and runs the CLI there, with a `Read` deny rule on `/app/repo` itself and on the folders that hold the agent's request and result. Out-of-scope files such as `README.md`, `LICENSE` or an excluded `tests/` are not in the folder the review works in. Finding and path files that name the scratch folder are made relative again (`relativise_review`), and `REPO_PATH`, from which the upstream filter reads a finding's file, points at the copy. Every `tool_use` record of the CLI's stream-json is kept (tool name and only the `file_path`, `notebook_path`, `path`, `pattern` and `glob` fields of its input, scrubbed and cut to 300 characters), with any call outside the copy or at a file not in scope flagged in `tool_uses_outside_scope`. They are in `claude_review.json` (`cli.tool_uses`) and, the first 500, in the run metadata.

## Deviations from upstream, and why

| Upstream | Here | Why |
|---|---|---|
| `claude --output-format json` with no `-p` | `-p --output-format stream-json --verbose` | `-p` makes print mode explicit. stream-json ends with the same result object, and its first line, the init message, says which model, key source and tools the CLI really uses, so a wrong one is stopped before the review spends anything |
| no settings, project settings load | our own user settings, `--setting-sources user`, `--strict-mcp-config`, `--no-session-persistence` | the repository is task content and must not configure the reviewer. The settings deny Bash, WebFetch, WebSearch, Edit, MultiEdit, Write and NotebookEdit, and reads of the key and CLI home folders |
| `ANTHROPIC_API_KEY` in the environment | `apiKeyHelper` that reads a mode 600 key file | keeps the key out of every process environment and command line |
| the CLI inherits the runner's environment | an allow-list of variables | no host Claude setting can change the model, the endpoint or the credential |
| filter access check with `claude-3-5-haiku-20241022`, failure turns the filter off silently | check with the filter's own model, failure is an error | that Haiku model is retired, so upstream would always fall back to the regex rules |
| failed filter call keeps the finding at confidence 10 | error | a finding the filter never judged is not a filtered finding |
| a reply with no findings JSON counts as a clean review | retried, then an error | a failed review must not look like a clean one |
| `is_error` and subtypes unchecked | checked, `error_max_turns` and `error_max_budget_usd` are fatal | as above |
| 20 minutes per CLI attempt, the timeout input is dead | one deadline for the whole review, split between CLI and filter, and `timeout -k` around the driver | Harbor must not kill the agent first |
| the CLI runs in the checked-out repository | the CLI runs in a copy of the in-scope files plus `security_manifest.json`, the real repository is denied, and every tool call is kept | the task's excluded paths must be out of the reviewer's reach, and there must be a record of what it read (audit A8) |
| no preflight | network check and one tiny request per model (skipped with a subscription token) | a bad key, a retired model or a blocked network fails in seconds instead of after the CLI's own long retries |
| filter with the Claude stage when filtering is on | with a subscription token, the regex rules only | the token cannot call the API. See "Subscription tokens" below |

Kept unchanged: the prompt text, the custom instruction mechanism, the
filter's prompts, retries and regex rules, the `@generated` rule, the
PROMPT_TOO_LONG fallback to the file list, and 3 CLI attempts.

## The model

The upstream default is `constants.DEFAULT_CLAUDE_MODEL`,
`claude-opus-4-1-20250805`, for both stages. The agent keeps it as its default
and lets the run choose another with `--ak model=<model id>` or
`CLAUDE_REVIEW_MODEL`. Anthropic may retire that model, and a key may not have
it enabled, so naming a model is usually the safer choice.

No model id is refused up front. An earlier version refused the upstream
default and three other ids because Claude Code 2.1.296 reported
`claude-opus-5-5` for them in its init message. That was seen only inside a
host-managed dev container (`CLAUDE_CODE_PROVIDER_MANAGED_BY_HOST=1` and other
host `CLAUDE_CODE_*` settings), where the host can choose the model, so it says
nothing about a clean environment and the static list was removed.

What protects the result instead, at run time:

- The driver sends one 1-token request per model first, so a retired or
  unknown model fails in seconds (`model_unavailable`).
- The CLI gets an allow-listed environment (PATH, locale, temp dir, CA bundles,
  proxies, HOME and the telemetry switches), so no host `ANTHROPIC_*`,
  `CLAUDE_*` or `CLAUDE_CODE_*` setting reaches it.
- The driver reads the CLI's init message and kills the CLI at once when the
  model there is not the requested one, and checks the result's `modelUsage`
  the same way (`model_remapped`). The error tells the user to pass
  `--ak model=<model id>`.

## Subscription tokens (auth oauth)

A Claude subscription token made with `claude setup-token` is read by Claude
Code from `CLAUDE_CODE_OAUTH_TOKEN`. It is not an API key. It cannot be sent
as `x-api-key` with the Anthropic Python SDK, and it must not go through
`apiKeyHelper`, which is for API keys. So with `auth=oauth` (or `auto` with
only the token set):

- The token goes through the same file as the API key (mode 600 file in a
  mode 700 directory, removed in a `finally`, scrubbed from every kept
  output). The driver reads it and puts it only into the CLI child process's
  environment as `CLAUDE_CODE_OAUTH_TOKEN`. That is the one Claude variable
  added to the CLI's allow-listed environment, and every other `ANTHROPIC_*`
  and `CLAUDE_*` variable is still dropped. The settings file has no
  `apiKeyHelper`.
- The driver's per-model API preflight is skipped (`"preflight":
  "skipped_oauth"`). The network check still runs, with no credential.
- The filter runs its regex rules only. An explicit `filter=claude` with a
  token is refused at Harbor preflight. The driver refuses it too.
- Before the upstream package is imported, the driver puts a stand-in
  `anthropic` module into `sys.modules`. `from anthropic import Anthropic`
  still works for the upstream imports, but making a client raises. The real
  SDK is never loaded, and the filter is given no key. A test checks that the
  fake SDK is neither imported nor called.
- A failed CLI attempt whose output says the credential was refused
  (`Invalid API key`, `Please run /login`, `OAuth token revoked`, `Failed to
  authenticate`, `API Error: 401` and similar) stops the review at once with
  `cli_oauth_refused`, and the agent reports "the subscription token was
  refused. Run `claude setup-token` again". It is not retried.

Which credential source the CLI reports. The init message's `apiKeySource`
names where an API key came from. In the pinned Claude Code 2.1.296 binary
(read as text, never run with a credential) its schema reads: "'none' (no API
key in use - e.g. claude.ai OAuth login, a bearer token, or a third-party
cloud provider)". The function that picks the key returns `none` when there is
no `ANTHROPIC_API_KEY`, no `apiKeyHelper` and no key stored by `/login`, and
the OAuth token is tracked apart from it as `tokenSource`, which the init
message does not carry. So with a token `check_init` accepts `none` only and
rejects `apiKeyHelper`, `ANTHROPIC_API_KEY` and `/login managed key`, any of
which would mean an API key from somewhere else, possibly another account's.
The allow-listed environment already rules out a bearer token
(`ANTHROPIC_AUTH_TOKEN`) and the cloud providers. The reported source is kept
in the metadata as `cli_credential_source`.

Results of a token run are a different configuration from upstream stock
(no Claude filter stage), so they are labelled "stock CLI + hard-rule filter"
(`results_label` in the metadata) and should be reported apart from API-key
runs.

## Scoped mode

The custom scan instructions, passed as upstream's `custom_scan_instructions`, are built at run time from the task's own output contract: the instruction text Harbor passes to `run`, which every task's `instruction.md` now carries (audit A2). `contract.py` reads the Scope table (ruleIds and definitions), the path roles, the `controlStatus` and `residualRisk` values and the Recommendation catalogue, and writes them in the upstream `**Category:**` format after a fixed preamble. The preamble tells the reviewer to read `security_manifest.json` first and to add six fields to each finding: a `rule_id`, a `cwe` list, a `path` (file, line and role per step), `control_status`, `residual_risk` and `recommendation_ids`, with the vocabularies the contract gives. So every scanner and this reviewer are told the same thing, by the task, and client measurements 2 to 4 (path, controls, recommendations) can be scored for this agent. When the instruction carries no contract, `scoped_scan_instructions.txt` (written from the same contract) is used instead. The metadata records which (`scan_instructions_source`: `task_instruction` or `bundled`), the text's sha256, the contract's ids and values, and any id the normaliser would not accept (`contract_ids_not_accepted`). No upstream code changes: upstream's JSON parser and filter keep every field the model adds, and only our normaliser reads them. Tests check that the generated and the bundled texts share no six-word run with any ground truth (the sample tasks, and the published tasks when they are next to this repository).

In scoped mode any well-formed `CWE-<n>` from the model is accepted (`ccsr-category-map-2`, audit A9); only malformed values are rejected and counted (`cwes_rejected_count`). The old allow-list rejected CWE ids the ground truth accepts, such as CWE-184 and CWE-1289, and the model's `rule_id` decides the family in this mode anyway.

Scoped results are not stock upstream, so reports show them next to stock results, never alone (signed off by the lead on 2026-10-12). Upstream's prompt asks for its own schema "exactly", after our instructions, so the model may leave the extra fields out. `assessed_fields` in the metadata counts how often it gave each one. Upstream also asks only for findings the model is more than 80% sure are exploitable, so `control_status` will lean towards `none`.

`scoped_filter_instructions.txt` is the upstream default filter text without 2 of its 16 hard exclusions, 7 ("A lack of hardening measures") and 14 ("Including user-controlled content in AI system prompts is not a vulnerability"), generated from the upstream source and checked against it by a test. Scoped runs therefore keep findings the stock filter would drop. Every run discloses this in `filter_exclusions_dropped` (upstream number and text) and the SARIF's `runs[0].properties.sastAgent.filterExclusionsDropped`. The text is read only by the Claude filter stage: with the hard-rule filter (a subscription token) it changes nothing, which `filter_exclusions_dropped_apply` records. Both texts' sha256 go into the metadata.

## Tool outcomes and what the SARIF records

A review that did not deliver is a tool outcome, not an infrastructure error (audit A5, `sast/errors.py`): the deadline (`deadline`, also `timeout` and the driver killed by `timeout -k`), `review_completed` false, `files_reviewed` 0, the CLI's `--max-turns` or `--max-budget-usd` limit (`cli_limit`), a prompt too long even without the diff, findings that are not JSON objects, more than 5,000 files in scope. The agent then writes no SARIF, records `tool_outcome` with the reason, and returns normally, so the verifier runs and scores the trial 0 on both twins. A missing or refused credential, an unreachable API, a CLI that would use another model, credential or tool set, a failed filter call and a CLI that failed every attempt stay `ScannerError` (errored, re-run).

The SARIF's `runs[0].properties.sastAgent` records what the harness dropped or re-mapped (audit F-B2): categories the category map does not know, findings left out for an unmapped or ambiguous CWE, out of scope or at a bad location, every result whose ruleId the harness derived from the category or CWE rather than the model's `rule_id`, and the upstream filter's exclusions (stage, reason, `file:line`). Counts and the first 20 rows of each; it never changes which results are emitted.

## Hardening after the PR #4 review

- The CLI's settings also deny `Read(//proc/**)`: with a subscription token the token is in the CLI process's environment.
- The per-finding filter client makes one request per attempt (the SDK's own retries are off, `max_retries=0`), checks the review's deadline before every attempt, and caps each attempt's timeout at the time left. When the time runs out the driver stops with error `deadline` instead of being killed by `timeout -k`.
- A refused subscription token is recognised only from the CLI's own words: stderr, and the final result's text when it is an error (or the CLI's plain-text lines when there is no result). The model's text and tool output are not searched, so repository content quoting such a message cannot stop a run.
- The credential is scrubbed from the full output before any part of it is cut and kept, in the driver and in the agent's `_exec` error tail.
- Line numbers and line counts split on `\n` only, so a form feed, vertical tab or U+2028 in a file no longer shifts them.
- Merged SARIF results keep the family they were merged under (see README, "Decisions"), so the writer can no longer crash on a generic CWE next to a `NOT_DISCLOSURE_CWES` entry.

Not changed: `max_budget_usd` still defaults to none (a cap that is too low would fail a paid review), and an explicit `timeout_sec` above Harbor's multiplied limit still gets only a note, because Harbor does not tell an agent that limit.

## Verified and not verified

Checked on 2026-10-12, in a dev container:

- The installer, end to end against a local HTTP server: the real
  `@anthropic-ai/claude-code-linux-x64` 2.1.296 tarball (sha256 and npm
  integrity), the upstream files at 0c6a49f, and a venv built with uv from
  `requirements.lock` with `--require-hashes`. The venv imports the upstream
  package with anthropic 0.79.0 and requests 2.32.5. The pip path of the
  fallback (no uv) also builds a working venv from the same lock file.
- The driver with the real venv and the real SDK against the real API with a
  fake key: classified as `api_auth` in under a second.
- The real CLI accepts the exact command line, uses the `apiKeyHelper`
  (`"apiKeySource": "apiKeyHelper"` in its init message) and leaves the denied
  tools out of its tool list.
- That `claude-3-5-haiku-20241022` is no longer available (the CLI answers
  "There's an issue with the selected model"). This was also seen in the
  host-managed container, so treat it with the same care.

Run since, with a real subscription token (`auth=oauth`, hard-rule filter): reviews of 10 dataset tasks against the real model, once per task, in stock and scoped mode. These runs predate the scope copy, the contract-built scoped prompt and the tool-outcome split above, which are covered by the unit tests with the scripted CLI only.

Not checked:

- The exact text the CLI prints when it refuses a token was taken from the binary's strings, so `cli_oauth_refused` may miss a wording it does not list. Such a failure is then retried and ends as `cli_failed` with the CLI's output in the attempt record.
- The scope copy and the `Read` deny rules with the real CLI: that the CLI's tools stay inside the copy, and that `tool_use` records come out of the real stream-json as the parser expects, were checked with the scripted CLI only.

- A full review with a real key. No key was available, so cost, time, the
  shape of real findings and how often the model returns the JSON as asked
  are unknown. The unit tests use a scripted CLI and a fake SDK.
- That `claude-opus-4-1-20250805`, `claude-opus-5-5` or any other model is
  available to the key that will be used, and which model the CLI really runs
  for each id outside a host-managed environment. The runtime checks above
  catch a mismatch either way.
- That the `Read(//<folder>/**)` deny rules block reads of the key folder.
  Print mode denies reads outside the working folder anyway, but this was not
  observed.
- Building the tools image with Docker, the download of the upstream files
  from raw.githubusercontent.com (blocked here, the pinned hashes come from a
  clean clone) and the aarch64 binary.
- Egress from Daytona sandboxes to api.anthropic.com.
