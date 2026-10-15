# Datadog SAIST agent

`sast.datadog_saist.agent:DatadogSaistAgent` runs datadog-saist, Datadog's open-source AI-native SAST engine (github.com/DataDog/datadog-saist, Apache-2.0, "preview"), as a Harbor scanner agent. It is the same engine Datadog ships in its Code Security product, run here standalone with our own model key and no Datadog account.

## How the tool works (read from its source at v0.0.32)

- CLI: `datadog-saist --directory <dir> --output <sarif> --detection-model M --validation-model M [--request-timeout-sec N] [--file-concurrency N] [--debug] [--local-prompts] [--skip-indexing]` (`cmd/datadog-saist/main.go`; confirmed with the real binary's `-h` in a container).
- Rules: by default downloaded at every run from `https://api.datadoghq.com/api/v2/static-analysis/ai/prompts` (public, no key; `internal/api/datadog_api.go`). On 2026-10-14 that endpoint served 379 rules: 30 kinds over 14 languages, 29 of them for Python. `--local-prompts` uses only the 12 rules compiled into the binary (cmdi, sqli, xpathi, xss for Go, Java, Python).
- For each file, a keyword prefilter picks the rules that apply; each (file, rule) pair is one detection prompt (the rule's markdown plus the numbered file and some related files, capped at about 8k tokens) and, for each violation, a validation prompt.
- The model's answer schema is fixed by the binary's system prompt: `startLine`, `startColumn`, `endLine`, `endColumn`, `reason`. The location must be the sink.
- SARIF (`internal/sarif/sarif.go`): `ruleId` `datadog/<language>-<kind>`, one location, `message.text` = the rule's short description, tags `CWE:<n>`, `DATADOG_CONFIDENCE:HIGH`, `DATADOG_CONFIDENCE_REASON:<model reason>`, a fingerprint; per-file artifacts tagged `RULE_SUCCESS:`/`RULE_FAILURE:`; run tags with total input/output tokens. No `codeFlows` (the code has none), no control status, residual risk or recommendation.
- Models it accepts directly: `openai-gpt5-mini`, `openai-gpt5.2`, `openai-gpt5.2-codex`, `claude-4.5-sonnet`, `claude-4.5-haiku`, `gemini-2.5-pro`, `gemini-2.5-flash`, `gemini-2.0-flash-lite`, `gemini-3-flash`. Keys come from `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GOOGLE_API_KEY` (or `--api-key`, which would put the key on a command line, so it is not used).

## Fit trial (2026-10-14, before building)

In a `python:3.12-slim` container, the pinned v0.0.32 linux-amd64 zip was downloaded, its sha256 checked against GitHub's digest and `checksums.txt`, and the binary run on a copy of the in-scope files of `crewai-code-interpreter-a` (`src`, `config`, `fixtures`, `security_manifest.json`, `pyproject.toml`, no `tests`) with `openai-gpt5-mini` and the host's `OPENAI_API_KEY` given only through a mode 600 file sourced into the tool's environment.

- It runs headless on a local folder: it fetched the 379 rules, discovered 13 files, and its prefilter chose 12 (file, rule) scans (excessiveagency x4, cmdi x2, xss x2, sensitiveinfodisclosure, systempromptleakage, promptinjection, integeroverflow).
- OpenAI refused the key (`401 invalid_api_key`, also from a direct `curl`; a Codex run with the same key had worked at 17:52 that day). datadog-saist still exited 0 and wrote a SARIF with 0 results, all 12 scans tagged `RULE_FAILURE` and 0 tokens; without `--debug` nothing in its output says why. That SARIF and the `--debug` log are kept as fixtures (`tests/fixtures/datadog_saist/`).
- So no real finding was seen. The result shape (ruleIds, tags, no `codeFlows`, the reason only in a tag) is taken from the source and the real empty SARIF.
- Extra instructions: none possible at run time. The rule text comes from Datadog's endpoint or the binary, the system prompt and answer schema are compiled in, and there is no flag for a custom rule or prompt directory. The only way to add instructions would be to rebuild the binary with extra embedded rule files (a Go and cgo build with tree-sitter); that would no longer be Datadog's tool, so it is not done. Hence no scoped mode.

## Rule mapping (frozen before any scoring: `datadog-map-1`)

Keyed by rule kind (the same for every language), from each rule's own description and CWE as served on 2026-10-14. The OWASP numbers in Datadog's descriptions (for example improper output handling labelled "LLM10:2026") are not used. LLM rules are decided on their description against the task's scope table; classic rules by their CWE through `cwe-map-5`, as for every pattern scanner. A kind that is not in the table is not reported and is counted (`ruleNotInMap`).

| Datadog kind | CWE | Task ruleId | Why |
|---|---|---|---|
| `sensitiveinfodisclosure` | 200 | `LLM02.SID.MEDIUM` | secrets or PII interpolated into an LLM call's messages: data reaches model-visible state; the rule does not establish a further boundary crossing |
| `systempromptleakage` | 540 | `LLM02.SID.HIGH` | the system prompt or tool schemas (confidential business data) flow into an HTTP response or accessible log |
| `excessiveagency` | 250 | `LLM03.EA.FUNCTIONALITY` | an agent's tools are broader than its stated purpose; the rule checks capability, not a credential's scope (cwe-map-5 would say PERMISSIONS for CWE-250) |
| `improperoutputhandling` | 74 | `LLM03.EA.AUTONOMY` | LLM output drives a dangerous operation (SQL, shell, path, URL) with no validation gate |
| `accesscontrol` | 284 | `LLM02.SID.MEDIUM` | cwe-map-5 |
| `errorinfoleak` | 209 | `LLM02.SID.MEDIUM` | cwe-map-5 |
| `cmdi`, `codei`, `deserialization`, `pathtraversal`, `sqli`, `xpathi`, `zipslip` | 78, 94, 502, 22, 89, 643, 73 | `LLM03.EA.FUNCTIONALITY` | cwe-map-5 |
| `promptinjection`, `misinformation`, `unboundedconsumption`, `datamodelpoisoning`, `supplychain`, `vectorembeddingweaknesses` | 1427, 1426, 400, 345, 829, 349 | not reported | outside the five ruleIds (supplychain: artifact integrity, not a tool's operations) |
| `brokencrypto`, `insecurecookie`, `integeroverflow`, `ldapi`, `loginjection`, `openredirect`, `prototypepollution`, `trustboundary`, `weakhash`, `weakrandomness`, `xss` | various | not reported | cwe-map-5 maps none |

No Datadog rule describes a tool credential's scope, so `LLM03.EA.PERMISSIONS` is never reported.

## Deviations from the tool's defaults

- `--request-timeout-sec 120` instead of 30: reasoning models exceed 30 s on its prompts.
- `--debug` always: without it a failed model call leaves no trace except the `RULE_FAILURE` tag, so a refused key would look like a clean scan.
- Default model `openai-gpt5.2` for both detection and validation (the tool has no default; this is its strongest general OpenAI model, the provider the benchmark has a key for). Harbor's `-m` is used only when it names a supported OpenAI model.
- The tool scans a copy of the in-scope files plus `security_manifest.json`, outside `/app/repo`, with an allow-listed environment and a private HOME (no `DD_*`, `OPENAI_BASE_URL` or other host settings).

## Normalisation

- RuleId from the frozen table only; findings outside it are counted (`ruleOutsideTaskRules`, `ruleNotInMap`).
- Location: the file must be an in-scope text file and the start line inside it; a bad end line becomes the start line (counted). Anything else is dropped and counted.
- CWE: the result's `CWE:` tag, else the rule's. Level and the heuristic residual risk: the rule's `SEVERITY` tag.
- Free text kept verbatim under `properties.toolProperties` for a later LLM judge: `reason` (the model's reason for the finding) and `ruleRemediation` (the rule's "How to remediate" section, generic for the rule). Also `datadogRuleId`, `ruleShortDescription`, `confidence`, `fingerprint`, `mapVersion`.
- `runs[0].properties.sastAgent` records the drops, the re-mapping of each result, failed (file, rule) scans and the sha256 of the rule set the run used.

## What is graded now and what waits for a judge

- Graded now: the ruleId (from the table) and the location.
- Never available: `codeFlows` (path), `controlStatus`, `residualRisk`, catalogue `recommendations`. The tool does not produce them in any form.
- For a later judge: the model's reason and the rule's remediation text.

## Failures

- Infrastructure (`ScannerError`, re-run): missing key on the host, install hash mismatch, the provider or rule endpoint unreachable, a refused key, no quota, an unknown model, every model call failing, the rule download failing.
- Tool outcomes (`ToolOutcome`, no SARIF, scored 0): the deadline, the binary exiting with an error, no readable SARIF, no file analysed.
- Some scans failing without a fatal error (for example retries exhausted on one file) are kept as the tool reports them and counted in `scanFailures`.

## Verified

- For real (Docker, 2026-10-14): download and sha256 of the v0.0.32 zips (amd64 run, arm64 hashed only), the binary's `-h` and flags, a headless run on the task's in-scope copy, the rule endpoint and its 379 rules, the SARIF shape of a run, and that a refused key gives exit 0 with all scans tagged `RULE_FAILURE`.
- For real (Harbor, local Docker, 2026-10-14, `crewai-code-interpreter-a` with `--ak mode=scoped`): setup installed and hash-checked the binary in the task container in 9 s; the driver copied the scope, reached the rule endpoint (HTTP 200, 379 rules) and ran the binary (7 s); OpenAI refused the host key, all 12 scans failed, and the agent stopped the trial as `ScannerError` `api_auth` (no SARIF, no reward) with the key file removed and no trace of the key in the trial folder. The task's Dockerfile had to be run from a scratch copy whose first `FROM` names the local `sast-tools:0.5.0` image, because pulling the registry image was blocked on this host (gcloud Context Aware Access); the dataset was not changed.
- With fakes only: the agent lifecycle, the key file, the driver against a scripted binary, normalisation of non-empty results, the grade of a fake answer on the sample task.
- Not verified: a run with a working key (the host key was refused), so the real findings, reasons, token counts and run time on the tasks are unknown.

## Follow-ups

- Bake the binary into the tools image.
- The rule set is live; runs on different days may use different rules (compare `rulesSha256`).
