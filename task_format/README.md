# Task format: grader v3.2

`grade.py` here is the task grader, and the only one: every task in harbor-tasks and every sample task under `tests/fixtures/tasks` carries a byte-identical copy. Every field added since v1 is optional, so older ground truths still grade; the earlier graders and their comparison test were removed on 2026-10-12.

To use it, copy `grade.py` into each task's `tests/grade.py`. `test.sh` doesn't
change.

## What the grader measures

The client spec asks every task to support four measurements. The grader keeps
a separate score for each, and the composite `reward` weights them with the
task's `scoring_weights`.

| Client measurement | Where it shows up |
|---|---|
| 1. Risk detection, including both risks or neither | `detection` (F1 of matched findings), and the task-level risk outcome per risk type |
| 2. Reachability and path tracing | `path` (share of required path steps covered by the result's codeFlows) |
| 3. Mitigation detection | `controls` (controlStatus and residualRisk agree with the ground truth) |
| 4. Mitigation recommendation | `recommendations` (a required recommendation given, no inapplicable ones) |

`classification` (rule id and CWE agree) is a fifth sub-score. All five are
means over the task's ground-truth findings, where a missed finding scores 0.
`grading_detail.json` also has `measurements_on_detected`, the same means over
matched findings only, so path quality can be read apart from detection.

Where the client spec is silent we follow OWASP Benchmark scoring
(BenchmarkScore.calculateMetrics). There each test case is labelled true or
false for one CWE category, a tool result counts only with an exact CWE match in
the test case's file, results outside test case files are ignored, and every
category gets a TPR, an FPR and a score of TPR minus FPR. Our mapping is below.

| OWASP Benchmark | This benchmark |
|---|---|
| test case | one task and one OWASP subtype it is labelled with |
| category | `LLM02.SID` (severity dropped) or `LLM03.EA.FUNCTIONALITY`, `.PERMISSIONS`, `.AUTONOMY` |
| true test case | a positive task, labelled with the rule ids of its findings |
| false test case | a minimal-contrast negative, labelled with its `contrast_rule_ids` |
| exact CWE match | `matching.require_cwe` with the finding's `acceptable_cwes` |
| results outside test case files ignored | `fp_outside_scope`, never a false positive: from v3.2 a result outside the scanner roots or in an excluded path (before v3.2, outside `fix_changed_files` on a positive, and away from the fix and the traps on a negative) |

The category outcome is TP when a finding of that category is matched and FN
when none is. On a negative it is FP when a result of the same OWASP risk family
fails the negative (near the fixed code or on one of its traps, see below) and
TN otherwise. The risk family (LLM02 or LLM03) is
what decides a match, and the subtype a tool picks is scored under
`classification`. This keeps subtype naming, which tools do not agree on, from
turning a correct detection into a miss.

## Matching results to findings

A result can match a finding when it has the finding's risk family, lands
within `line_tolerance` of the finding's primary location or one of its
alternative locations, and (under `require_cwe`) shares a CWE with it. Each
result matches at most one finding and each finding at most one result.

Among all such one-to-one matchings the grader picks the one with the highest
reward. As long as every matched result sits inside `fix_changed_files` (or
the task names no fix files), each matched pair adds the same detection credit
and its own weighted measurement scores, so the reward is a sum over the pairs
and the grader finds the best matching exactly with the Hungarian algorithm,
using exact fractions. A result that matches through a location outside the
fix files gets the same detection credit in that sum, which is a close
approximation. It applies only to findings with an accepted location (primary
or alternative) outside `fix_changed_files`, for example a linked disclosure
finding whose primary location is where the data leaves. When two matchings give
the same reward, the grader reads the results in file order and gives each one
the earliest finding it can, and prefers matching a result to leaving it
unmatched. That is what the earlier greedy pass did, so a SARIF that greedy
already matched optimally gets exactly the same grade, and a partial-credit
result no longer takes a finding away from an exact one (audit 040, L3). The
code is in `assign` and `max_weight_matching` in `grade.py`, and it needs only
the Python standard library.

## v3 fields

### `matching.require_cwe`

```json
"matching": {"line_tolerance": 10, "path_line_tolerance": 10, "require_cwe": true}
```

When true a result matches a finding only if its `properties.cwe` shares a CWE
with the finding's `acceptable_cwes` plus `primary_cwe`. This applies to the
primary location and to every alternative location. CWE ids are read as
`CWE-<n>` anywhere in the value, so "CWE-22", "cwe-22" and "A01:2021 - CWE-22"
agree. A bare number counts only when it is the whole value ("22" or 22), so the
digits of an OWASP id are never read as a CWE. `properties.cwe` may be a list
or a single string. The default is false, which keeps the v2 rule (risk family and
location only). A result with the right location and the wrong CWE is a false
positive when it lies inside `fix_changed_files`.

### Negative tasks

```json
"variant_role": "negative",
"risk_types_present": [],
"findings": [],
"contrast_rule_ids": ["LLM03.EA.FUNCTIONALITY", "LLM02.SID.HIGH"],
"fixed_locations": [{"file": "src/mini/tools/file_tool.py", "start_line": 20, "end_line": 24, "why": "..."}],
"fix_changed_files": ["src/mini/tools/file_tool.py"]
```

A negative scores 1.0 unless one of its results falls in a failure bucket.

From v3.2 there is a third bucket, `in_scope` (any contrast-family result in scope), a `"complete"` result never fails, and traps may name exact `trap_rule_ids`; see "v3.2" below. The rest of this section describes the v3 rules, which still apply.

- `near_fix` is a result whose rule id starts with one of the contrast prefixes
  (LLM02 or LLM03, taken from `contrast_rule_ids`) and that lands within
  `line_tolerance` of `fixed_locations`.
- `trap` is a result that hits one of the negative's own `hard_negative_trap`
  entries in `negative_analyses`, meaning its prefix is in the trap's
  `trap_rule_prefixes` and it lands within `line_tolerance` of the trap lines.
  A `minimal_contrast` entry is not a trap.

Neither bucket needs CWE agreement, because on a negative any claim of that
risk at the fixed code or at a labelled trap is wrong. A result in both buckets
counts once, as `near_fix`. Every other result is `fp_outside_scope`. That
includes results elsewhere in `fix_changed_files`, which no longer fail a
negative, so a noisy file the fix happens to touch does not fail the twin. A
negative without `contrast_rule_ids` keeps the old rule.

`grading_detail.json` has `failure_bucket` (`near_fix`, `trap`,
`near_fix+trap` or null), `results_near_fixed_code` and `trap_hits` (each hit
names its traps). `reward.json` has the flat flags `neg.fail.near_fix` and
`neg.fail.trap` (0 or 1), and `trap_hits` counts the trap results. `fp` counts
the results in both buckets.

### Linked findings

`linked_finding_ids` and `link_relation` on a finding (for example an
excessive-agency finding that exposes a disclosure, `ea_exposes_sid`) are
copied into that finding's entry in `grading_detail.json`. Each linked finding is
still matched and scored on its own.

## v3.1: complete controls on negatives

A negative may list the complete controls its fix adds, next to `fixed_locations`:

```json
"controls": [{"name": "path_confinement", "status": "complete",
              "at": {"file": "src/mini/tools/file_tool.py", "start_line": 20, "end_line": 24},
              "contrast_of": "F1", "note": "..."}],
"control_status": "complete",
"residual_risk": "low"
```

`at` is one of the negative's `fixed_locations`. Every negative in harbor-tasks uses `residual_risk: "low"`: the client spec asks to "assess residual risk" but never calls it none, and the negatives keep traps and residual review notes.

A result names a complete control when its rule id has a contrast prefix, its `properties.controlStatus` is `"complete"`, and it lands within `line_tolerance` of the control's `at`. Such a result is not a failure (whichever bucket it would otherwise fall in) and is listed under `complete_control_recognised` in `grading_detail.json`. Each control scores 0.75 when a result names it, plus 0.25 when that result's `residualRisk` equals the negative's `residual_risk`, and the mean over the controls is the negative-side controls sub-score `neg.controls` in `reward.json` (with `neg.complete_control_recognised`, the number of such results). `complete_controls` in `grading_detail.json` shows each control, whether it was recognised and by which result.

`neg.controls` is reported but does not enter the reward. A silent negative still scores 1.0, any other result is judged by the near-fix and trap rules above, and a negative without `controls` is graded exactly as before (no `neg.controls` key). A SARIF that recognises a control and also has a failing result still fails. The oracle SARIF of every negative names each of its complete controls, so it scores 1.0 with `neg.controls` 1.0.

## v3.2: scoring changes made in response to the external audit

These are scoring changes made in response to the external audit (`external_audit/B4-agent-summary.md` items A3, A5, A6, A7, with A1 added and then reverted and `external_audit/D-tasks-critique-summary.md` items F-B1, F-M1, F-M5, m9). They were signed off as part of "fix all valid audit items" on 2026-10-12. `GRADER_VERSION` in `grade.py` is `v3.2` and is written to `grading_detail.json` as `grader_version`. The grader scores exactly what the shared output contract (`instruction.md`, identical in every task) asks for. Where a v3.2 rule reads a new ground-truth field and the field is absent, the grader falls back to the older field as stated below.

### Scope

The scope is where a result is scored. It is `matching.scanner_roots` minus `matching.excluded_paths` (both copied from `task.toml`) when the ground truth has scanner roots, else `fix_changed_files` minus the excluded paths, else the whole repo minus the excluded paths. A root or excluded path matches the path itself and everything under it, and a pattern with `*`, `?` or `[` is a glob. `grading_detail.json` names the mode used under `scope` (`scanner_roots`, `fix_changed_files` or `repo`). Results outside the scope are `fp_outside_scope` and cost nothing.

### Negatives fail on a false alarm anywhere in scope (F-B1, A7)

Before v3.2 a negative failed only on a result near `fixed_locations` or on one of its traps, so a confident false alarm elsewhere in the code scored 1.0. A negative now also fails on any result in scope whose OWASP prefix (LLM02 or LLM03) is the prefix of one of its `contrast_rule_ids`. This is a third failure bucket, `in_scope`, with the flat flag `neg.fail.in_scope` in `reward.json` and the list `results_in_scope` in `grading_detail.json`. The buckets are checked in the order `near_fix`, `trap`, `in_scope`, each result is counted once, and `failure_bucket` joins the buckets that fired with `+` (for example `near_fix+in_scope`). `fp` counts the results in all three buckets.

A result whose `properties.controlStatus` is `"complete"` says that a control closes the path, so it is never a failure, wherever it lands (at the fix, on a trap or elsewhere). Near one of the negative's complete `controls` it still earns the v3.1 `neg.controls` credit. Any other such result is listed under `complete_claims` and is not counted in `fp_outside_scope`.

An empty SARIF still scores 1.0 on a negative: the tool said the code is clean. A missing SARIF (the tool wrote no answer, for example after a timeout) still scores 0 on a negative as on a positive, with `sarif_missing: 1`, so not finishing is never rewarded (A5).

### Positives count false positives across the scanner roots (F-M1)

An unmatched result is a false positive when it is in scope, not only when it is in `fix_changed_files`. A tool that adds 30 unrelated results in the scanner roots to one correct result now gets a detection F1 of 2/32 instead of 1.0. Results outside the roots or in excluded paths stay `fp_outside_scope`. A ground truth without scanner roots is graded as before (false positives only inside `fix_changed_files`).

A result with `controlStatus: "complete"` claims no weakness, so on a positive it neither matches a finding nor counts as a false positive. It is listed under `complete_claims` and the finding it sits on stays a miss. Without this, a tool could mark every result "complete" and pass every negative at no cost on the positives.

### No cross-family match (A1 reverted)

A result matches only a finding of its own risk family. A cross-family match on a shared CWE was added in v3.2 for scanners whose rule id comes from a CWE map, and reverted on 2026-10-12: the client spec is followed first and OWASP Benchmark where it is silent, and an OWASP Benchmark result counts only in its own category. Those CWE-map scanners (Semgrep, CodeQL, SonarQube) are to be dropped from the benchmark, which will evaluate AI-based scanners that choose the rule id themselves. `per_finding` still carries `cross_family`, always false, so older readers keep working.

### Path score (A3)

The path score used to be the share of required steps covered, so a reversed path with every role set to `sink` scored 1.0. It is now

`path = coverage * (0.2 + 0.8 * order * role) * precision`

- `coverage`: the share of required ground-truth steps that some emitted threadFlow location lands within `path_line_tolerance` of (the step or one of its `alternatives`), as before.
- `order`: over the covered steps, the longest chain of them, in ground-truth order, whose covering emitted locations do not go backwards in the flow (two steps may share one emitted location), divided by the number of covered steps.
- `role`: the share of covered steps whose covering location carries the step's role in the threadFlow location's `properties.role`. `source` and `model_decision` are one start role. Legacy ground-truth roles are read as their contract roles: `tool_output` as `model_consumption`, `pass_through` as `context_assembly`, `action` as `sink`, `control` as `control_point`.
- `precision`: `min(1, (len(path) + 2) / emitted steps)`, where `len(path)` counts every ground-truth step (required or not) and emitted steps are all threadFlow locations of the result. A flow far longer than the labelled path loses credit, so blanket coverage no longer pays.

Order and role multiply rather than add because steps within tolerance of each other cannot be ordered by line (order is 1 whichever way the flow runs), so only their roles tell a reversed path from the right one. The additive form first suggested (`0.7 + 0.15 * order + 0.15 * role`) cannot go below 0.7 for a fully covered path, so it could not meet the 0.6 target. A correct oracle path scores exactly 1.0. Reversing every positive oracle's flows and setting every role to `sink` gives at most 0.6 per finding (0.6 only for a two-step path whose steps sit within tolerance of each other, where the sink role is right), and typically 0.25 to 0.47. A correct path without roles scores 0.2, and one with only the first step as `source` and the last as `sink` (as the pattern scanners write it) scores 0.2 plus 0.8 times the share of covered steps those two roles get right. A finding with no required steps still scores 1.0. `path_steps` in `per_finding` now shows `role_ok` per step.

### Traps name the wrong claim (F-M5)

A `hard_negative_trap` entry may list `trap_rule_ids`, the exact rule ids that would be a wrong claim there. When it does, only a result with one of those rule ids within tolerance of the trap hits it, so a different weakness reported a few lines away no longer hits the trap. A trap without `trap_rule_ids` (or with an empty list) keeps the prefix rule (`trap_rule_prefixes`). This applies to trap hits on negatives and on positives. On a negative a contrast-family result in scope still fails under the `in_scope` rule above, so `trap_rule_ids` decides only for results outside the contrast family and for traps outside the scope. `--check-truth` accepts a trap with `trap_rule_ids` and no `trap_rule_prefixes`, and reports a `trap_rule_ids` that is not a list of strings.

### Category outcomes on negatives (A6)

A failing result on a negative used to count against the contrast category that shares its prefix, so an `LLM03.EA.PERMISSIONS` result on an AUTONOMY contrast was an AUTONOMY false positive. It now counts against the category it claims: `reward.json` gets `cat.LLM03.EA.PERMISSIONS.truth: 0` and `cat.LLM03.EA.PERMISSIONS.detected: 1`, and the contrast category stays `truth: 0, detected: 0` (TN) unless a result of that category fails too. The key names are unchanged (`cat.<category>.truth` and `cat.<category>.detected`), so `tools/report.py` reads them as before; a negative can now carry a category key that is not one of its contrast categories. A rule id that names no known category (`LLM02.SID`, `LLM03.EA.FUNCTIONALITY`, `.PERMISSIONS`, `.AUTONOMY`) falls back to the contrast categories of its prefix.

### Paths in SARIF (m9)

`norm_uri` now also strips a `file://` scheme (any case), everything up to and including `/app/repo/` wherever it appears, any leading `/` and `./`, and a leading `repo/`, and reads a backslash as `/`. `file:///app/repo/src/a.py`, `/home/runner/app/repo/src/a.py` and `repo/src/a.py` all give `src/a.py`.

### What the ground truth must provide

`matching.scanner_roots` and `matching.excluded_paths` (copied from `task.toml`) on every ground truth, so that the negative `in_scope` rule and the positive false-positive count use the scanner's scope, and `trap_rule_ids` on every `hard_negative_trap`. `--check-truth` reports roots or excluded paths that are not lists of paths.

## Ground truth gt-0.2

`schema_version: "gt-0.2"` adds evaluator-only annotation fields. None of them changes how a positive is graded, and `--check-truth` requires them only from gt-0.2 on (and checks their shape whenever they are present).

- `snippet_id` and `snippet_sha256` on every location (primary and alternative locations, path steps and their alternatives, control locations, `negative_analyses`, `fixed_locations`). `snippet_id` is `<task_id>:<file>:<start_line>-<end_line>`, the primary key that ties a label to a code snippet (spec comment SS1). `snippet_sha256` is the SHA-256 of those lines of `environment/repo/<file>`, read with CRLF as LF and joined with `
` (`snippet_sha256` in `grade.py`). Line numbers are unchanged. Regenerate with `python tools/snippet_ids.py ../harbor-tasks` from `ng-sast-agent` (`--check` writes nothing and exits 1 when a file is out of date). The tool is deterministic and keeps each file's indent and key order.
- `affected_asset` per finding (spec 1, measurement 2): `fixture_ids`, `data_class`, `classification` and `canary_ids` from the manifest `fixtures` and `data_classification`, matched through `evidence.canary_id`. An excessive-agency finding without data names the `resource` and the `manifest_path` it comes from instead.
- `egress` on every path step whose role is `sink` or `action`: `{"kind": "external" | "internal", "boundary": "<trust_boundaries id>"}` (spec comment SS3, internal and external egress points).
- `consequence` on every excessive-agency finding: one sentence of the finding's own `rationale`.
- `violates` per finding: a list of `{"manifest_path": "authorized_recipients[1].data_scope", "summary": "..."}`, the manifest entries the finding breaks.
- The first `source` or `model_decision` path step of every finding is `required` (spec 1, measurement 2, "from source or model decision to sink or action").
- Negatives carry `controls`, `control_status` and `residual_risk` as above.

## Scoring changes made after seeing results

2026-10-12: `matching.require_cwe` is now `false` on every harbor-tasks ground truth. Reason: the client spec defines detection by risk type and location, not CWE. A result now matches a finding on risk family and location alone, and CWE agreement still feeds the classification sub-score (`0.8 * rule + 0.2 * cwe_ok`). The grader code did not change for this, only the labels. Signed off by the lead on 2026-10-12.

## Task-level outcomes

For client measurement 1 the grader decides, per task, which risk types the
tool claimed. On a positive only a result that matched a finding counts. On a
negative only a result that fails the negative (either bucket above) counts.
Each risk type then gets TP, FP, FN or TN against `risk_types_present`, which
covers tasks labelled with both risks, one, or neither. Category detection uses
the same rule.

The older loose rule is kept next to it as `tl.pred_loose.SID` and
`tl.pred_loose.EA` (and `risk_types_loose` in `grading_detail.json`). There a
result also counts when it is an unmatched result inside `fix_changed_files`
(anywhere when a positive names no fix files), or any result near
`fixed_locations` or inside `fix_changed_files` on a negative. The loose
variant can credit a risk to a result at the wrong place, so read it only as
"the tool said something about this risk in the changed files".

Harbor only accepts numbers in `reward.json`, so these outcomes are written
there as flat 0 or 1 flags, and in full in `grading_detail.json`:

```json
"tl.truth.SID": 1, "tl.pred.SID": 1, "tl.pred_loose.SID": 1,
"tl.truth.EA": 1, "tl.pred.EA": 0, "tl.pred_loose.EA": 1,
"cat.LLM02.SID.truth": 1, "cat.LLM02.SID.detected": 1,
"cat.LLM03.EA.FUNCTIONALITY.truth": 1, "cat.LLM03.EA.FUNCTIONALITY.detected": 0
```

```json
"task_level": {
  "truth_risk_types": ["excessive_agency", "sensitive_information_disclosure"],
  "predicted_risk_types": ["sensitive_information_disclosure"],
  "risk_types": {"sensitive_information_disclosure": "TP", "excessive_agency": "FN"},
  "categories": {"LLM02.SID": "TP", "LLM03.EA.FUNCTIONALITY": "FN"},
  "predicted_risk_types_loose": ["excessive_agency", "sensitive_information_disclosure"],
  "risk_types_loose": {"sensitive_information_disclosure": "TP", "excessive_agency": "TP"}
}
```

A missing SARIF file adds `"sarif_missing": 1`, and a grader crash adds
`"grader_error": 1`. The report leaves those trials out of the category tables.

The reader is lenient about two shapes tools emit. `"results": null` in a run
is read as no results, and a `recommendations` property given as one string is
read as a one-item list (anything else that is not a list of strings is
ignored).

## Ground-truth check

```bash
python3 grade.py --check-truth --truth tests/ground_truth.json
```

This validates a ground truth instead of grading and exits 1 on any problem.
Run it on every task at build time. It reports

- missing top-level or per-finding fields, and scoring weights that are not
  numbers,
- line ranges that are not integers from 1 up, or that end before they start,
  in accepted locations, path steps, `fixed_locations` and `negative_analyses`,
- a finding that has no usable `primary_cwe` or `acceptable_cwes` while
  `require_cwe` is true, since it could never match,
- accepted locations (primary or alternative) of two different findings in the
  same file whose `line_tolerance` windows overlap, when one result could match
  both (same risk type and, under `require_cwe`, a shared CWE). Such a result
  could be credited to either finding, so which finding it detected is not
  well defined. `task_781350`'s F1
  and F2 alternative at `_instrumentation.py:115` and `:107` are an example.

- from gt-0.2 on, the fields of "Ground truth gt-0.2" above: a missing snippet id or hash, a missing `affected_asset`, `violates`, `egress` on a sink or action step, `consequence` on an excessive-agency finding, a first `source` or `model_decision` step that is not required, and on a negative a missing `controls` entry or `residual_risk`,
- whatever the version, a malformed new field: an `egress` kind other than external or internal, a `consequence` that is not text of the rationale, a negative control that is not complete or whose `at` is not one of `fixed_locations`,
- with the repo (`--repo <dir>`, by default `../environment/repo` next to the truth's folder when it exists): a `snippet_sha256` that no longer matches the code, a location outside its file, and, from the repo's `security_manifest.json`, an `egress` boundary that is not a trust boundary id, an `affected_asset` fixture that does not exist or misses the fixtures carrying the finding's canary, a `data_class` that is not their asset class, and a `violates` or `affected_asset` `manifest_path` that does not resolve.

A hash mismatch means the code or the label moved. Check that the label still points at the right lines before rerunning `tools/snippet_ids.py`.

`check_truth(truth, repo=None, manifest=None)` in `grade.py` returns the same problems as a list.

## v2 fields (unchanged)

`fixed_locations` on a twin with `"findings": []` and no `contrast_rule_ids`
fails the twin when any result lands near the fixed lines. `fix_changed_files`
on a positive task limits false positives to the files the fix changed, and
other results are recorded as `fp_outside_scope`. Sink and dispatch locations go
in `alternative_primary_locations`, with a `why` starting "sink:".

## Dataset report

`tools/report.py` takes a Harbor job or jobs directory, or a list of
`reward.json` files, and prints the per-trial table (including `fp_out`) and
these dataset views. `--write <dir>` also writes `report.json` and `report.md`.

- Per category TP, FN, TN, FP, TPR, FPR and Youden score (TPR minus FPR).
- Overall in the OWASP Benchmark style, with mean TPR and mean FPR across
  categories (not pooled) and their difference, then precision pooled over
  categories and F1 from pooled precision and mean TPR.
- A binary table each for sensitive information disclosure and excessive
  agency, and how often the predicted risk set equals the labelled one for tasks
  labelled both, one, or neither.
- Mean detection, classification, path, controls and recommendations over
  positive tasks.
- Mean task reward for positives and for negatives, reported apart, and how
  many negatives failed near the fix or on a trap. There is no mean over both
  together. An empty SARIF scores 1.0 on every negative, so a combined mean,
  including the job-level mean Harbor writes to its `result.json`, rewards
  saying nothing and is not a score.

## Heuristic leak check

`tools/leak_scan.py <harbor-tasks dir>` is a heuristic leak check. It catches
common ways a label reaches the scanner but is not a proof that none does (it
cannot, for example, see a fix-only name that both twins share). It

- searches every file under each task's `environment/` for words that would
  give the label away,
- checks that ground truth, repro tests and provenance are not under
  `environment/`,
- looks for ground-truth prose in the repo. Every string in
  `tests/ground_truth.json` with at least six words (rationales, `why` notes,
  summaries and so on) is cut into six-word shingles, and none of them may
  appear in a text file under `environment/` (case and punctuation ignored),
- checks that `environment/Dockerfile` copies only `repo/` into the image
  (`COPY --from` of another build stage is allowed),
- searches `task.toml` and `instruction.md` for the same words, since the
  harness and the scanner can read them,
- checks that twin pairs differ only in the original positive's
  `fix_changed_files` with identical manifest and fixtures. With role-free ids
  the pairs come from `VARIANTS.json`. The original positive is the twin whose
  role is positive and whose ground truth lists `fix_changed_files`. When both
  twins qualify (a twin with the upstream fix relabelled as a partial-control
  positive), `former_name` decides, then `lineage.code_state` (`source_commit`)
  in provenance, and a pair that is still open is reported,
- checks that twin `task.toml` files differ only in `task_id`, `variant_id` and
  `related_variant_ids`.

It exits non-zero on any problem. `--write-qc` records "pass" or "fail" in
`validation/provenance.json` under `qc.label_leak_scan`.

`--image` (with Docker) also builds each task's `environment/` and checks the
image as the scanner will see it: no tests, solution or validation files or
copies of them under `/app`, no evaluator file names, and the same six-word
ground-truth check against the files inside the image. Limit it with
`--task <name>` (repeatable), since every build takes a while.

## Examples

`tests/fixtures/tasks/smoke_eval_twin` is a v2 twin using `fixed_locations`, and
`tests/fixtures/tasks/smoke_eval` uses `fix_changed_files`. Semgrep flags an unrelated
`shell=True` helper in both.

| Task | Original grader | Grader v2 and v3 |
|---|---|---|
| `smoke_eval` (positive) | 0.28 (1 false positive) | 0.40, `fp_outside_scope` 1 |
| `smoke_eval_twin` | 0.00 (failed) | 1.00, `fp_outside_scope` 1 |

`tests/test_grader_v3.py` builds a positive with two linked findings and its
minimal-contrast negative and checks every v3 rule above. `tests/test_grader_v32.py` checks every v3.2 change, including the auditor's probes (spray, reversed all-sink path, confident false alarm away from the fix, complete-control result, no cross-family match, `trap_rule_ids`).
