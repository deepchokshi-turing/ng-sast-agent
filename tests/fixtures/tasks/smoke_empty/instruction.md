# Security review: GenAI data-disclosure and agency risks

Review the repository at `/app/repo` using static analysis only. Do not run the
application against external services.

`/app/repo/security_manifest.json` describes the application's intended task, its
actors, trust boundaries, and what data, actions, purposes and recipients are
authorised. Judge every potential issue against that manifest: data or capability
that the manifest authorises is not a finding.

The repository may contain zero, one, or several findings in scope.

## Scope

| ruleId | Risk |
|---|---|
| `LLM02.SID.MEDIUM` | Sensitive data reaches model-visible state (prompt, RAG results, memory, tool results, logs of prompts/completions/traces) without controls that preserve its authorisation boundary |
| `LLM02.SID.HIGH` | As above, and the data can cross an authorisation or trust boundary (email, HTTP/webhook, tool arguments, external API, shared store, broadly readable logs, cross-tenant retrieval, external model provider) |
| `LLM03.EA.FUNCTIONALITY` | Tools or tool operations beyond what the intended task requires |
| `LLM03.EA.PERMISSIONS` | A tool's credential or authorisation scope exceeds what its operation requires |
| `LLM03.EA.AUTONOMY` | A model decision can trigger a high-impact action with no independent policy or approval gate |

## Output

Write one SARIF 2.1.0 file to `/app/output/findings.sarif`. If you find nothing in
scope, write a valid SARIF file whose `results` array is empty.

Emit one `result` per independently fixable weakness on one path. For each result:

- `ruleId`: one of the IDs above.
- `locations[0]`: the primary weakness (the code that must change to fix it).
  `artifactLocation.uri` is relative to `/app/repo`; give `region.startLine` and
  `region.endLine`.
- `codeFlows[0].threadFlows[0].locations`: the reachable path in order, from where
  the data or decision originates to where the disclosure or action happens. Give
  each step `properties.role`, one of: `source`, `root_cause`, `context_assembly`,
  `model_consumption`, `model_decision`, `control_point`, `sink`.
- `properties.cwe`: list of CWE IDs, e.g. `["CWE-359"]`.
- `properties.controlStatus`: `none`, `partial`, or `complete`. Use `partial` when a
  control exists but does not close the path.
- `properties.residualRisk`: `low`, `medium`, or `high`.
- `properties.recommendations`: IDs from the catalogue below that would close the
  path. Explain them in `message.markdown` if you wish.

### Recommendation catalogue

| ID | Control |
|---|---|
| `REC-AUTHZ-BEFORE-RETRIEVAL` | Enforce user/tenant/document authorisation inside the retrieval query |
| `REC-MINIMIZE-CONTEXT` | Send only task-required fields to the model |
| `REC-SENSITIVE-DATA-FILTER` | Detect and redact sensitive values before prompting and before output (classifier/NER plus patterns) |
| `REC-SINK-SIDE-IFC` | Deterministic information-flow check at the sink against the data's classification |
| `REC-DISABLE-AUTO-CONTEXT` | Remove automatic full-record context unless justified |
| `REC-MINIMIZE-TOOLS` | Register only tools the scenario needs |
| `REC-SPLIT-READ-WRITE` | Separate read operations from write/delete/send operations |
| `REC-NARROW-TYPED-TOOLS` | Replace general-purpose tools with narrow, typed, allow-listed ones |
| `REC-LEAST-PRIVILEGE` | Scope credentials to the minimum actions and resources |
| `REC-USER-SECURITY-CONTEXT` | Execute in the end user's security context, not a shared privileged identity |
| `REC-COMPLETE-MEDIATION` | Downstream systems authorise every request independently of the model |
| `REC-ACTION-BOUND-APPROVAL` | Human approval bound to the exact resolved action and parameters |
| `REC-POLICY-GATE` | Deterministic policy gate that rejects unauthorised actions |
