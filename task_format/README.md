# Task format: grader v3

`grade.py` here is the task grader. Every field added since v1 is optional. A
ground truth without the v3 fields is graded exactly as by v2, and one without
the v2 fields exactly as by the original grader (`tests/test_grader_v2.py`
checks this). Tasks can move over one at a time.

To use it, copy `grade.py` into each task's `tests/grade.py`. `test.sh` doesn't
change. The same file is kept as `v3/common/grade_v3.py`.

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
| results outside test case files ignored | `fp_outside_scope`, never a false positive |

The category outcome is TP when a finding of that category is matched and FN
when none is. On a negative it is FP when a result of the same OWASP risk family
lands on the changed code and TN otherwise. The risk family (LLM02 or LLM03) is
what decides a match, and the subtype a tool picks is scored under
`classification`. This keeps subtype naming, which tools do not agree on, from
turning a correct detection into a miss.

## v3 fields

### `matching.require_cwe`

```json
"matching": {"line_tolerance": 10, "path_line_tolerance": 10, "require_cwe": true}
```

When true a result matches a finding only if its `properties.cwe` shares a CWE
with the finding's `acceptable_cwes` plus `primary_cwe`. This applies to the
primary location and to every alternative location. CWE ids are normalised, so
"CWE-22", "cwe-22", "22" and 22 agree, and `properties.cwe` may be a list or a
single string. The default is false, which keeps the v2 rule (risk family and
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

A negative scores 1.0 unless a result whose rule id starts with one of the
contrast prefixes (LLM02 or LLM03, taken from `contrast_rule_ids`) lands within
`line_tolerance` of `fixed_locations` or anywhere inside `fix_changed_files`.
Such a result needs no CWE agreement to count as a false positive, because on a
negative any claim of that risk at the changed code is wrong. Results elsewhere,
and results of a risk family the task does not contrast, are
`fp_outside_scope`. A negative without `contrast_rule_ids` keeps the old rule.

### Linked findings

`linked_finding_ids` and `link_relation` on a finding (for example an
excessive-agency finding that exposes a disclosure, `ea_exposes_sid`) are
copied into that finding's entry in `grading_detail.json`. Each linked finding is
still matched and scored on its own.

## Task-level outcomes

For client measurement 1 the grader decides, per task, which risk types the
tool claimed. A result counts when it is in scope, meaning it matched a finding,
or it lies in `fix_changed_files`, or it is near `fixed_locations` on a negative.
When a positive task names no fix files every result is in scope, as in v1.
Each risk type then gets TP, FP, FN or TN against `risk_types_present`, which
covers tasks labelled with both risks, one, or neither.

Harbor only accepts numbers in `reward.json`, so these outcomes are written
there as flat 0 or 1 flags, and in full in `grading_detail.json`:

```json
"tl.truth.SID": 1, "tl.pred.SID": 1, "tl.truth.EA": 1, "tl.pred.EA": 0,
"cat.LLM02.SID.truth": 1, "cat.LLM02.SID.detected": 1,
"cat.LLM03.EA.FUNCTIONALITY.truth": 1, "cat.LLM03.EA.FUNCTIONALITY.detected": 0
```

```json
"task_level": {
  "truth_risk_types": ["excessive_agency", "sensitive_information_disclosure"],
  "predicted_risk_types": ["sensitive_information_disclosure"],
  "risk_types": {"sensitive_information_disclosure": "TP", "excessive_agency": "FN"},
  "categories": {"LLM02.SID": "TP", "LLM03.EA.FUNCTIONALITY": "FN"}
}
```

A missing SARIF file adds `"sarif_missing": 1`, and a grader crash adds
`"grader_error": 1`. The report leaves those trials out of the category tables.

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

## Leak scan

`tools/leak_scan.py <harbor-tasks dir>` checks every file under each task's
`environment/` for words that would give the label away, checks that ground
truth, repro tests and provenance are not under `environment/`, and checks that
twin pairs differ only in the positive's `fix_changed_files` with identical
manifest and fixtures. It exits non-zero on any problem. `--write-qc` records
"pass" or "fail" in `validation/provenance.json` under `qc.label_leak_scan`.

## Examples

`dev/tasks/smoke_eval_twin` is a v2 twin using `fixed_locations`, and
`dev/tasks/smoke_eval` uses `fix_changed_files`. Semgrep flags an unrelated
`shell=True` helper in both.

| Task | Original grader | Grader v2 and v3 |
|---|---|---|
| `smoke_eval` (positive) | 0.28 (1 false positive) | 0.40, `fp_outside_scope` 1 |
| `smoke_eval_twin` | 0.00 (failed) | 1.00, `fp_outside_scope` 1 |

`tests/test_grader_v3.py` builds a positive with two linked findings and its
minimal-contrast negative and checks every v3 rule above.
