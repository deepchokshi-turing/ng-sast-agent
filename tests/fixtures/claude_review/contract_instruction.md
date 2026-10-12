# Security review: sensitive information disclosure and excessive agency

Review the repository at `/app/repo` with static analysis only. Do not run the application against external services.

The file `/app/repo/security_manifest.json` describes the application's intended task, its actors, trust boundaries, and which data, actions, purposes and recipients are authorised, and its approval policy. Judge every potential issue against it: data or capability that the manifest authorises is not a finding.

Only the scanner roots listed in `task_metadata.json` next to this file are in scope; its excluded paths are out of scope. The repository may contain zero, one or several findings in scope.

## Scope

| ruleId | Risk |
|---|---|
| `LLM02.SID.MEDIUM` | Sensitive data (PII, PHI, financial data, credentials, confidential business data, privileged documents) reaches model-visible state (prompt, RAG results, memory, tool results, logs of prompts, completions or traces) without controls that preserve its authorisation boundary |
| `LLM02.SID.HIGH` | As above, and the data can cross an authorisation or trust boundary (email, HTTP or webhook, tool arguments, external API, shared store, broadly readable logs, cross-tenant retrieval, external model provider) |
| `LLM03.EA.FUNCTIONALITY` | Tools or tool operations beyond what the intended task requires |
| `LLM03.EA.PERMISSIONS` | A tool's credential or authorisation scope exceeds what its operation requires |
| `LLM03.EA.AUTONOMY` | A model decision can trigger a high-impact action with no independent policy or approval gate |

## Output

Write one SARIF 2.1.0 file to `/app/output/findings.sarif`. If you find nothing in scope, write a valid SARIF file whose `results` array is empty.

Emit one `result` per independently remediable weakness on one path. When an excessive action exposes protected information, report two linked results, one per ruleId. For each result:

- `ruleId`: one of the IDs above.
- `locations[0]`: the code that must change to close the path. `artifactLocation.uri` is relative to `/app/repo`; give `region.startLine` and `region.endLine`.
- `codeFlows[0].threadFlows[0].locations`: the reachable path in order, from where the data or the model decision originates to where the disclosure or the action happens. Give each step `properties.role`, one of: `source`, `model_decision`, `context_assembly`, `model_consumption`, `control_point`, `root_cause`, `sink`.
- `properties.cwe`: a list of CWE identifiers that describe the weakness, most specific first.
- `properties.controlStatus`: `none`, `partial` or `complete`. Use `partial` when a control exists but does not close the path. To say that the code you report on is safe because a control closes the path, report it with `complete`.
- `properties.residualRisk`: `low`, `medium` or `high`.
- `properties.recommendations`: IDs from the catalogue below that would close the path. List only the ones that apply. Explain them in `message.markdown` if you wish.

### Recommendation catalogue

| ID | Control |
|---|---|
| `REC-AUTHZ-BEFORE-RETRIEVAL` | Enforce user, tenant or document authorisation inside the retrieval query |
| `REC-MINIMIZE-CONTEXT` | Send only task-required fields to the model |
| `REC-SENSITIVE-DATA-FILTER` | Detect and redact sensitive values before prompting and before output (classifier or NER plus patterns) |
| `REC-SINK-SIDE-IFC` | Deterministic information-flow check at the sink against the data's classification |
| `REC-DISABLE-AUTO-CONTEXT` | Remove automatic full-record context unless justified |
| `REC-MINIMIZE-TOOLS` | Register only tools the scenario needs |
| `REC-SPLIT-READ-WRITE` | Separate read operations from write, delete or send operations |
| `REC-NARROW-TYPED-TOOLS` | Replace general-purpose tools with narrow, typed, allow-listed ones |
| `REC-LEAST-PRIVILEGE` | Scope credentials to the minimum actions and resources |
| `REC-USER-SECURITY-CONTEXT` | Execute in the end user's security context, not a shared privileged identity |
| `REC-COMPLETE-MEDIATION` | Downstream systems authorise every request independently of the model |
| `REC-ACTION-BOUND-APPROVAL` | Human approval bound to the exact resolved action and parameters |
| `REC-POLICY-GATE` | Deterministic policy gate that rejects unauthorised actions |
