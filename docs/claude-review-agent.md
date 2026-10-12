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

`scoped_scan_instructions.txt` is passed as upstream's
`custom_scan_instructions`. It holds the task instruction's public scope
table in the upstream `**Category:**` format, a pointer to
`security_manifest.json`, and asks for a `cwe` list per finding. It was
written once from the public instruction and never from a task. A test checks
that it shares no six-word run with any sample task's ground truth.
`scoped_filter_instructions.txt` is the upstream default filter text without
hard exclusions 7 and 14, generated from the upstream source and checked
against it by a test. Both texts' sha256 go into the metadata.

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

Not checked:

- Any run with a real subscription token. No token was available, and the
  real CLI was not run with any credential. That `apiKeySource` is `none`
  with a token comes from reading the 2.1.296 binary, not from watching it.
  If a later CLI reports something else for a token, the review stops at
  once with `cli_auth` and the reported value in the message, before it
  spends anything. The exact text the CLI prints when it refuses a token was
  also taken from the binary's strings, so `cli_oauth_refused` may miss a
  wording it does not list. Such a failure is then retried and ends as
  `cli_failed` with the CLI's output in the attempt record.

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
