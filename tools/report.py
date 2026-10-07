#!/usr/bin/env python3
"""Per-trial table and pooled detection metrics for a scanner job.

    python tools/report.py <harbor job dir> [--tasks <dir holding the task folders>] [--json]

The task reward is a composite built for agents that also explain paths,
controls and recommendations; a scanner can earn at most 0.40 of it. So the
headline for SAST is **detection, pooled across tasks**:

- precision / recall / F1 from the verifier's tp, fp, fn (location within the
  grader's tolerance and the right OWASP prefix);
- **location recall**: ground-truth findings with any security finding near them,
  mapped to a ruleId or not ("the tool looked at the right code");
- **location + CWE recall**: the same, where the finding's CWEs include one of the
  ground truth's acceptable CWEs;
- **zero-finding tasks clean**: tasks with no ground-truth finding where the
  output had no false positive (fp == 0).

``fp_out`` is grader v2's ``fp_outside_scope``: results outside the files the fix
changed (positive tasks) or away from the fixed code (twins). They are not
counted as false positives.

Uses only the standard library; runs anywhere the job directory is.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def ground_truth(trial: dict, tasks_dir: Path | None) -> dict | None:
    candidates = []
    path = ((trial.get("config") or {}).get("task") or {}).get("path")
    if path:
        candidates.append(Path(path))
    if tasks_dir is not None:
        name = str(trial.get("task_name") or "").split("/")[-1]
        candidates.append(tasks_dir / name)
    for task in candidates:
        gt = task / "tests" / "ground_truth.json"
        if gt.is_file():
            return json.loads(gt.read_text())
    return None


def ground_truth_hits(rows: list, truth: dict) -> tuple[int, int, int]:
    """(gt findings, with a finding near them, with a near finding of an acceptable CWE)."""
    findings = truth.get("findings") or []
    tol = (truth.get("matching") or {}).get("line_tolerance", 10)
    near_any = near_cwe = 0
    for gt in findings:
        targets = [gt["primary_location"], *(gt.get("alternative_primary_locations") or [])]
        acceptable = set(gt.get("acceptable_cwes") or [])
        hit = hit_cwe = False
        for _rule, cwes, file, start, end, _emitted in rows:
            for t in targets:
                t_end = t.get("end_line", t["start_line"])
                if file == t["file"] and start <= t_end + tol and end >= t["start_line"] - tol:
                    hit = True
                    hit_cwe = hit_cwe or bool(acceptable & set(cwes))
        near_any += hit
        near_cwe += hit_cwe
    return len(findings), near_any, near_cwe


def trial_results(job: Path) -> list[tuple[Path, dict]]:
    """Trial result.json files (they carry a trial_name; the job's own does not)."""
    found = []
    for result_file in sorted(job.glob("*/result.json")):
        data = json.loads(result_file.read_text())
        if "trial_name" in data:
            found.append((result_file, data))
    return found


def rows_for(job: Path, tasks_dir: Path | None) -> list[dict]:
    out = []
    for result_file, trial in trial_results(job):
        meta = (trial.get("agent_result") or {}).get("metadata") or {}
        rewards = (trial.get("verifier_result") or {}).get("rewards") or {}
        truth = ground_truth(trial, tasks_dir)
        exception = trial.get("exception_info") or {}
        scanned = truth is not None and meta.get("status") == "ok"
        gt_n, near, near_cwe = ground_truth_hits(meta.get("findings_compact") or [], truth) if scanned else (None,) * 3
        out.append({
            "task": str(trial.get("task_name") or result_file.parent.name),
            "status": "errored" if exception else meta.get("status", "?"),
            "reward": rewards.get("reward"),
            "tp": rewards.get("tp"),
            "fp": rewards.get("fp"),
            "fn": rewards.get("fn"),
            "gt": rewards.get("gt_findings"),
            "fp_out": rewards.get("fp_outside_scope"),
            "raw": meta.get("results_raw"),
            "security": meta.get("findings_security"),
            "emitted": meta.get("results_emitted"),
            "near": near,
            "near_cwe": near_cwe,
            "scan_s": meta.get("scan_seconds"),
            "setup_s": (meta.get("install") or {}).get("setup_seconds"),
            "error": (exception.get("exception_message") or meta.get("error") or "")[:120],
        })
    return out


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("job", type=Path, help="a Harbor job directory (holds one folder per trial)")
    parser.add_argument("--tasks", type=Path, help="folder holding the task directories, for ground truth")
    parser.add_argument("--json", action="store_true", help="print JSON instead of a table")
    args = parser.parse_args()

    job = args.job
    if not trial_results(job):  # a jobs dir: use its latest job
        nested = sorted(p for p in job.iterdir() if p.is_dir() and trial_results(p))
        job = nested[-1] if nested else job
    rows = rows_for(job, args.tasks)
    if args.json:
        json.dump(rows, sys.stdout, indent=2)
        print()
        return

    columns = ["task", "status", "reward", "tp", "fp", "fn", "fp_out", "gt", "near", "near_cwe", "raw", "security",
               "emitted", "setup_s", "scan_s", "error"]
    table = [[("" if r[c] is None else str(r[c])) for c in columns] for r in rows]
    widths = [max(len(c), *(len(row[i]) for row in table)) if table else len(c) for i, c in enumerate(columns)]
    print("  ".join(c.ljust(w) for c, w in zip(columns, widths)))
    for row in table:
        print("  ".join(v.ljust(w) for v, w in zip(row, widths)))

    graded = [r for r in rows if r["reward"] is not None]
    print(f"\ntrials {len(rows)}, graded {len(graded)}, errored {len(rows) - len(graded)}")
    positives = [r for r in graded if (r["gt"] or 0) > 0]
    if positives:
        tp = sum(r["tp"] or 0 for r in positives)
        fp = sum(r["fp"] or 0 for r in positives)
        fn = sum(r["fn"] or 0 for r in positives)
        gt = sum(r["gt"] for r in positives)
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / gt if gt else 0.0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
        print(f"detection, pooled over {len(positives)} tasks with findings ({gt} ground-truth findings):")
        print(f"  tp {tp}  fp {fp}  fn {fn}  precision {precision:.3f}  recall {recall:.3f}  F1 {f1:.3f}")
        with_meta = [r for r in positives if r["near"] is not None]
        if with_meta:
            gt_meta = sum(r["gt"] for r in with_meta)
            print(f"  location recall (any security finding, any OWASP side): "
                  f"{sum(r['near'] for r in with_meta)}/{gt_meta}")
            print(f"  location + acceptable-CWE recall: {sum(r['near_cwe'] for r in with_meta)}/{gt_meta}")
    zero = [r for r in graded if r["gt"] == 0]
    if zero:
        print(f"zero-finding tasks clean (fp == 0): {sum(1 for r in zero if (r['fp'] or 0) == 0)}/{len(zero)}")
    if graded:
        print(f"mean task reward (composite; scanner ceiling 0.40 per finding): "
              f"{sum(r['reward'] for r in graded) / len(graded):.3f}")


if __name__ == "__main__":
    main()
