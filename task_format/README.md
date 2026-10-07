# Task format: grader v2

`grade.py` here is the task grader with two **optional** ground-truth fields.
A task without them is graded exactly as by the original `grade.py`
(`tests/test_grader_v2.py` checks this), so tasks can move over one at a time.

To use it, copy `grade.py` into each task's `tests/grade.py`. `test.sh` doesn't
change.

## 1. Fixed twins: `fixed_locations`

A fixed-twin task (`"findings": []`) passes unless a result lands **near the
code the fix changed**. Results elsewhere in the repository are recorded as
`fp_outside_scope` and don't fail the twin.

```json
"findings": [],
"fixed_locations": [
  {"file": "libs/core/langchain_core/load/dump.py", "start_line": 120, "end_line": 134,
   "why": "dumps(): user dicts are now escaped"}
]
```

- Use the lines the fix commit changed, on the **fixed** side of the diff.
- "Near" uses the task's `matching.line_tolerance` (±10 lines).
- Without `fixed_locations`, a twin still needs a completely empty SARIF (the
  old rule).

## 2. Positive tasks: `fix_changed_files`

A result that matches no finding counts as a false positive only inside the files
the fix changed. Others are recorded as `fp_outside_scope`.

```json
"fix_changed_files": ["libs/core/langchain_core/load/dump.py", "libs/core/langchain_core/load/load.py"]
```

Use the code files the fix commit changed (the "Vulnerable files" column in the
case sheet), with paths relative to `/app/repo`. Without this field, every
unmatched result in the repository is a false positive (the old rule).

## 3. Sink locations: no grader change

SAST tools usually report where the data ends up (the sink) or where the action
is dispatched, not at the root cause. Add those to the existing field:

```json
"primary_location": {"file": "src/app/retrieval.py", "start_line": 11, "end_line": 11},
"alternative_primary_locations": [
  {"file": "src/app/tools.py", "start_line": 16, "end_line": 20, "why": "sink: data leaves by email"},
  {"file": "src/app/agent.py", "start_line": 41, "end_line": 41, "why": "dispatch of the model's send_email call"}
]
```

## New output field

`reward.json` gains `fp_outside_scope` (0 when the new fields are absent).
`tools/report.py` shows it as `fp_out`.

## Example

`dev/tasks/smoke_eval_twin` is a complete twin task using `fixed_locations`, and
`dev/tasks/smoke_eval` uses `fix_changed_files`. Semgrep flags an unrelated
`shell=True` helper in both:

| Task | Old grader | Grader v2 |
|---|---|---|
| `smoke_eval` (positive) | 0.28 (1 false positive) | 0.40, `fp_outside_scope` 1 |
| `smoke_eval_twin` | 0.00 (failed) | 1.00, `fp_outside_scope` 1 |
