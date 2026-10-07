#!/usr/bin/env python3
"""Per-trial table, OWASP Benchmark style category scores and client measurements.

    python tools/report.py <harbor job or jobs dir> [--tasks <dir>] [--json] [--write <dir>]
    python tools/report.py <trial>/verifier/reward.json [...more reward.json files]

The task reward is a composite built for agents that also explain paths,
controls and recommendations, so a scanner can earn at most 0.40 of it. The
report therefore shows several views:

- **Per trial**: reward, tp, fp, fn, ``fp_out`` (grader v2+ ``fp_outside_scope``:
  results outside the files the fix changed or away from the fixed code, not
  counted as false positives), location recall helpers when the agent wrote
  ``findings_compact`` metadata.
- **Pooled detection** over tasks with findings: precision, recall, F1.
- **Categories (OWASP Benchmark scoring)**: every graded task is a test case for
  each category it is labelled with (grader v3 ``cat.<category>.truth`` and
  ``.detected``). Per category TP, FN, TN, FP, TPR, FPR and Youden score
  (TPR minus FPR). Overall TPR and FPR are the means across categories, not
  pooled. Precision is pooled over categories. F1 uses pooled precision and
  mean TPR.
- **Risk types** (client measurement 1): a binary table each for
  sensitive_information_disclosure and excessive_agency, and the exact-set
  result for tasks labelled both, one, or neither.
- **Measurements** (client measurements 2 to 4): mean path, controls and
  recommendations score over positive tasks (missed findings count 0).

Trials whose SARIF was missing or whose grader crashed are left out of the
category and risk tables and counted separately.

Uses only the standard library.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

RISKS = {"SID": "sensitive_information_disclosure", "EA": "excessive_agency"}
MEASURES = ("detection", "classification", "path", "controls", "recommendations")


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


def labels_from(rewards: dict) -> dict:
    """Task-level flags of grader v3 from a flat reward dict."""
    cats = {}
    for key, value in rewards.items():
        if key.startswith("cat.") and key.endswith((".truth", ".detected")):
            cat, field = key[4:].rsplit(".", 1)
            cats.setdefault(cat, {})[field] = int(value)
    risks = {}
    for short in RISKS:
        if f"tl.truth.{short}" in rewards:
            risks[short] = {"truth": int(rewards[f"tl.truth.{short}"]), "pred": int(rewards.get(f"tl.pred.{short}", 0))}
    return {"categories": cats, "risks": risks}


def base_row(task: str, rewards: dict, status: str = "ok", error: str = "") -> dict:
    return {
        "task": task,
        "status": status,
        "reward": rewards.get("reward"),
        "tp": rewards.get("tp"),
        "fp": rewards.get("fp"),
        "fn": rewards.get("fn"),
        "gt": rewards.get("gt_findings"),
        "fp_out": rewards.get("fp_outside_scope"),
        **{m: rewards.get(m) for m in MEASURES},
        "sarif_missing": bool(rewards.get("sarif_missing")) or bool(rewards.get("grader_error")),
        **labels_from(rewards),
        "error": error,
    }


def rows_for(job: Path, tasks_dir: Path | None) -> list[dict]:
    out = []
    for result_file, trial in trial_results(job):
        meta = (trial.get("agent_result") or {}).get("metadata") or {}
        rewards = (trial.get("verifier_result") or {}).get("rewards") or {}
        truth = ground_truth(trial, tasks_dir)
        exception = trial.get("exception_info") or {}
        scanned = truth is not None and meta.get("status") == "ok"
        gt_n, near, near_cwe = ground_truth_hits(meta.get("findings_compact") or [], truth) if scanned else (None,) * 3
        row = base_row(str(trial.get("task_name") or result_file.parent.name), rewards,
                       "errored" if exception else meta.get("status", "?"),
                       (exception.get("exception_message") or meta.get("error") or "")[:120])
        row.update({
            "raw": meta.get("results_raw"),
            "security": meta.get("findings_security"),
            "emitted": meta.get("results_emitted"),
            "near": near,
            "near_cwe": near_cwe,
            "scan_s": meta.get("scan_seconds"),
            "setup_s": (meta.get("install") or {}).get("setup_seconds"),
        })
        out.append(row)
    return out


def rows_from_reward_files(files: list[Path]) -> list[dict]:
    rows = []
    for f in files:
        task = f.parent.parent.name if f.parent.name == "verifier" else f.parent.name
        rows.append(base_row(task, json.loads(f.read_text())))
    return rows


# ---- aggregation ---------------------------------------------------------------------

def ratio(num: float, den: float) -> float | None:
    return num / den if den else None


def usable(rows: list[dict]) -> list[dict]:
    return [r for r in rows if r["reward"] is not None and r["status"] != "errored" and not r["sarif_missing"]]


def category_table(rows: list[dict]) -> dict:
    cats: dict[str, dict] = {}
    for r in usable(rows):
        for cat, flags in r["categories"].items():
            c = cats.setdefault(cat, {"TP": 0, "FN": 0, "TN": 0, "FP": 0})
            truth, det = flags.get("truth", 0), flags.get("detected", 0)
            c[{(1, 1): "TP", (1, 0): "FN", (0, 1): "FP", (0, 0): "TN"}[(truth, det)]] += 1
    for c in cats.values():
        c["TPR"] = ratio(c["TP"], c["TP"] + c["FN"])
        c["FPR"] = ratio(c["FP"], c["FP"] + c["TN"])
        c["youden"] = c["TPR"] - c["FPR"] if c["TPR"] is not None and c["FPR"] is not None else None
    tprs = [c["TPR"] for c in cats.values() if c["TPR"] is not None]
    fprs = [c["FPR"] for c in cats.values() if c["FPR"] is not None]
    tp = sum(c["TP"] for c in cats.values())
    fp = sum(c["FP"] for c in cats.values())
    fn = sum(c["FN"] for c in cats.values())
    mean_tpr = sum(tprs) / len(tprs) if tprs else None
    mean_fpr = sum(fprs) / len(fprs) if fprs else None
    precision = ratio(tp, tp + fp)
    f1 = (2 * precision * mean_tpr / (precision + mean_tpr)
          if precision is not None and mean_tpr is not None and precision + mean_tpr else None)
    overall = {
        "categories": len(cats), "mean_TPR": mean_tpr, "mean_FPR": mean_fpr,
        "score": mean_tpr - mean_fpr if mean_tpr is not None and mean_fpr is not None else None,
        "precision_pooled": precision, "recall_pooled": ratio(tp, tp + fn), "F1": f1,
    }
    return {"per_category": dict(sorted(cats.items())), "overall": overall}


def risk_table(rows: list[dict]) -> dict:
    out = {}
    graded = [r for r in usable(rows) if r["risks"]]
    for short, name in RISKS.items():
        c = {"TP": 0, "FN": 0, "TN": 0, "FP": 0}
        for r in graded:
            t, p = r["risks"][short]["truth"], r["risks"][short]["pred"]
            c[{(1, 1): "TP", (1, 0): "FN", (0, 1): "FP", (0, 0): "TN"}[(t, p)]] += 1
        c["TPR"] = ratio(c["TP"], c["TP"] + c["FN"])
        c["FPR"] = ratio(c["FP"], c["FP"] + c["TN"])
        c["precision"] = ratio(c["TP"], c["TP"] + c["FP"])
        out[name] = c
    combos: dict[str, dict] = {}
    for r in graded:
        truth = tuple(s for s in RISKS if r["risks"][s]["truth"])
        pred = tuple(s for s in RISKS if r["risks"][s]["pred"])
        label = {("SID", "EA"): "both", ("SID",): "SID only", ("EA",): "EA only", (): "neither"}[truth]
        c = combos.setdefault(label, {"tasks": 0, "exact": 0})
        c["tasks"] += 1
        c["exact"] += truth == pred
    for c in combos.values():
        c["exact_rate"] = ratio(c["exact"], c["tasks"])
    out["by_truth_set"] = combos
    return out


def measurement_means(rows: list[dict]) -> dict:
    positives = [r for r in rows if r["reward"] is not None and (r["gt"] or 0) > 0]
    return {"tasks": len(positives),
            **{m: (sum(r[m] or 0 for r in positives) / len(positives) if positives else None) for m in MEASURES}}


def pooled_detection(rows: list[dict]) -> dict | None:
    positives = [r for r in rows if r["reward"] is not None and (r["gt"] or 0) > 0]
    if not positives:
        return None
    tp = sum(r["tp"] or 0 for r in positives)
    fp = sum(r["fp"] or 0 for r in positives)
    fn = sum(r["fn"] or 0 for r in positives)
    gt = sum(r["gt"] for r in positives)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / gt if gt else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {"tasks": len(positives), "gt": gt, "tp": tp, "fp": fp, "fn": fn,
            "precision": precision, "recall": recall, "F1": f1}


def summarise(rows: list[dict]) -> dict:
    graded = [r for r in rows if r["reward"] is not None]
    zero = [r for r in graded if r["gt"] == 0]
    return {
        "trials": len(rows), "graded": len(graded),
        "excluded_from_category_tables": len(rows) - len(usable(rows)),
        "mean_reward": sum(r["reward"] for r in graded) / len(graded) if graded else None,
        "fp_outside_scope": sum(r["fp_out"] or 0 for r in graded),
        "pooled_detection": pooled_detection(rows),
        "zero_finding_tasks_clean": [sum(1 for r in zero if (r["fp"] or 0) == 0), len(zero)],
        "categories": category_table(rows),
        "risk_types": risk_table(rows),
        "measurements_positive_tasks": measurement_means(rows),
    }


# ---- rendering -------------------------------------------------------------------------

def fmt(v) -> str:
    if v is None:
        return ""
    return f"{v:.3f}" if isinstance(v, float) else str(v)


def md_table(columns: list[str], rows: list[list]) -> list[str]:
    lines = ["", "| " + " | ".join(columns) + " |", "|" + "---|" * len(columns)]
    lines += ["| " + " | ".join(fmt(v) for v in row) + " |" for row in rows]
    return lines


def text_table(columns: list[str], rows: list[list]) -> list[str]:
    table = [[fmt(v) for v in row] for row in rows]
    widths = [max(len(c), *(len(row[i]) for row in table)) if table else len(c) for i, c in enumerate(columns)]
    return ["  ".join(c.ljust(w) for c, w in zip(columns, widths))] + [
        "  ".join(v.ljust(w) for v, w in zip(row, widths)) for row in table]


TRIAL_COLUMNS = ["task", "status", "reward", "tp", "fp", "fn", "fp_out", "gt", "near", "near_cwe", "raw",
                 "security", "emitted", "setup_s", "scan_s", "error"]


def render(rows: list[dict], summary: dict, table=text_table) -> str:
    out = []
    cols = [c for c in TRIAL_COLUMNS if any(c in r for r in rows)]
    out += table(cols, [[r.get(c) for c in cols] for r in rows])
    out.append(f"\ntrials {summary['trials']}, graded {summary['graded']}, "
               f"errored {summary['trials'] - summary['graded']}")
    det = summary["pooled_detection"]
    if det:
        out.append(f"detection, pooled over {det['tasks']} tasks with findings ({det['gt']} ground-truth findings):")
        out.append(f"  tp {det['tp']}  fp {det['fp']}  fn {det['fn']}  precision {det['precision']:.3f}  "
                   f"recall {det['recall']:.3f}  F1 {det['F1']:.3f}")
        with_meta = [r for r in rows if (r["gt"] or 0) > 0 and r["reward"] is not None and r.get("near") is not None]
        if with_meta:
            gt_meta = sum(r["gt"] for r in with_meta)
            out.append(f"  location recall (any security finding, any OWASP side): "
                       f"{sum(r['near'] for r in with_meta)}/{gt_meta}")
            out.append(f"  location + acceptable-CWE recall: {sum(r['near_cwe'] for r in with_meta)}/{gt_meta}")
    clean, zero = summary["zero_finding_tasks_clean"]
    if zero:
        out.append(f"zero-finding tasks clean (fp == 0): {clean}/{zero}")
    if summary["mean_reward"] is not None:
        out.append(f"mean task reward (composite; scanner ceiling 0.40 per finding): {summary['mean_reward']:.3f}")
    out.append(f"fp_outside_scope total: {summary['fp_outside_scope']}")

    cats = summary["categories"]
    if cats["per_category"]:
        out.append("\ncategories (OWASP Benchmark scoring, one test case per task and category):")
        out += table(["category", "TP", "FN", "TN", "FP", "TPR", "FPR", "youden"],
                     [[k, c["TP"], c["FN"], c["TN"], c["FP"], c["TPR"], c["FPR"], c["youden"]]
                      for k, c in cats["per_category"].items()])
        o = cats["overall"]
        na = {k: (fmt(v) or "n/a") for k, v in o.items()}
        out.append(f"overall: mean TPR {na['mean_TPR']}  mean FPR {na['mean_FPR']}  "
                   f"score {na['score']}  precision (pooled) {na['precision_pooled']}  "
                   f"F1 {na['F1']}  over {o['categories']} categories")
    risks = summary["risk_types"]
    if risks["by_truth_set"]:
        out.append("\nrisk types (task level, in-scope results):")
        out += table(["risk_type", "TP", "FN", "TN", "FP", "TPR", "FPR", "precision"],
                     [[k, c["TP"], c["FN"], c["TN"], c["FP"], c["TPR"], c["FPR"], c["precision"]]
                      for k, c in risks.items() if k != "by_truth_set"])
        out.append("labelled risk set (both, one, neither), predicted set equal to labelled set:")
        out += table(["truth_set", "tasks", "exact", "exact_rate"],
                     [[k, c["tasks"], c["exact"], c["exact_rate"]] for k, c in sorted(risks["by_truth_set"].items())])
    m = summary["measurements_positive_tasks"]
    if m["tasks"]:
        out.append(f"\nmeasurements, mean over {m['tasks']} positive tasks (missed findings score 0):")
        out += table(list(MEASURES), [[m[k] for k in MEASURES]])
    if summary["excluded_from_category_tables"]:
        out.append(f"\nleft out of category and risk tables (errored, no SARIF, grader error): "
                   f"{summary['excluded_from_category_tables']}")
    return "\n".join(out)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("inputs", type=Path, nargs="+",
                        help="a Harbor job or jobs directory, or one or more reward.json files")
    parser.add_argument("--tasks", type=Path, help="folder holding the task directories, for ground truth")
    parser.add_argument("--json", action="store_true", help="print the per-trial rows as JSON instead of tables")
    parser.add_argument("--write", type=Path, help="also write report.json and report.md into this directory")
    args = parser.parse_args()

    files = [p for p in args.inputs if p.is_file()]
    if files:
        rows = rows_from_reward_files(files)
    else:
        job = args.inputs[0]
        if not trial_results(job):  # a jobs dir: use its latest job
            nested = sorted(p for p in job.iterdir() if p.is_dir() and trial_results(p))
            job = nested[-1] if nested else job
        rows = rows_for(job, args.tasks)
    summary = summarise(rows)

    if args.write:
        args.write.mkdir(parents=True, exist_ok=True)
        (args.write / "report.json").write_text(json.dumps({"summary": summary, "trials": rows}, indent=2))
        (args.write / "report.md").write_text("# SAST benchmark report\n\n" + render(rows, summary, md_table) + "\n")
    if args.json:
        json.dump(rows, sys.stdout, indent=2)
        print()
        return
    print(render(rows, summary))


if __name__ == "__main__":
    main()
