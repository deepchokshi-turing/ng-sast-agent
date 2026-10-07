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
| results outside test case files ignored | `fp_outside_scope`, never a false positive (on a negative, anything away from the fix and the traps) |

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
approximation. No current task has such a location. When two matchings give
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

`check_truth(truth)` in `grade.py` returns the same problems as a list.

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
- checks that twin pairs differ only in the positive's `fix_changed_files` with
  identical manifest and fixtures.

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
minimal-contrast negative and checks every v3 rule above.
