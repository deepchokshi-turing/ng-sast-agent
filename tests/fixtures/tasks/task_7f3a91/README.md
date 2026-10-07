# task_7f3a91 — sample task package (evaluator-facing)

One task from repository family `fam_2c81` (support copilot), variant A.
Label: positive, `LLM02:2026` Sensitive Information Disclosure, high severity
(cross-tenant retrieval → model context → email).

Format: **Harbor** for packaging, **SARIF 2.1.0** for scanner output,
**RealVuln-style JSON** (extended with paths, controls and manifest context) for ground truth.

## What each part is and who can see it

| Path | Scanner sees? | Purpose |
|---|---|---|
| `instruction.md` | Yes | Scope, rule IDs, SARIF output profile, recommendation catalogue |
| `environment/Dockerfile` | Builds the container | Pinned build; runs compile + app smoke tests |
| `environment/repo/` | Yes (at `/app/repo`) | Source, config, synthetic fixtures, `security_manifest.json` |
| `task.toml` | No | Harbor config + spec §5.2 non-label task fields |
| `solution/` | No | Oracle SARIF; `solve.sh` copies it to `/app/output/` |
| `tests/` | No (copied in at verify time) | `ground_truth.json`, `grade.py`, `test.sh` |
| `validation/` | No (never shipped into a run) | Label proof (`repro_test.py`) and `provenance.json` |

## Run it locally

```bash
# 1. Prove the label (vulnerable leaks the canary; one-line fix blocks it)
python3 validation/repro_test.py

# 2. Oracle must score 1.0
python3 tests/grade.py --sarif solution/findings.sarif --out /tmp/verifier
```

## Scoring (per task, written to /logs/verifier/reward.json)

| Sub-score | Weight | Rule |
|---|---|---|
| detection | 0.35 | Finding-level F1. Match = same risk type (ruleId prefix) and `locations[0]` within ±10 lines of the root cause (or an accepted alternative fix site) |
| classification | 0.05 | Exact ruleId (SID.MEDIUM gets half credit) ×0.8 + any acceptable CWE ×0.2 |
| path | 0.30 | Share of required path steps (root cause, context assembly, model consumption, sink) covered by the SARIF `threadFlow` |
| controls | 0.15 | `controlStatus` exact ×0.75 + `residualRisk` exact ×0.25 |
| recommendations | 0.15 | Required rec present = 1.0, only acceptable ones = 0.5, −0.25 per inapplicable rec |

`tp`, `fp`, `fn` and `trap_hits` are also written so dataset-level precision, recall and F3 can be computed across tasks.
Hard-negative traps in this task: `admin_export.py` (N1), prompt-free audit log (N2), self-addressed `send_email` (N3).

## Grader checks already run

| Input | Reward |
|---|---|
| Oracle SARIF | 1.00 |
| Missing / empty / malformed SARIF | 0.00 (reward file still written) |
| Noisy scanner (right finding as SID.MEDIUM, partial path, wrong control status, 2 trap hits) | 0.43 |
| Flags only the sink as primary location | 0.00 (counts as 1 FP + 1 FN) |
