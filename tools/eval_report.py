#!/usr/bin/env python3
"""Compile several Harbor scanner jobs into one comparative eval report.

    python tools/eval_report.py <job dir> [<job dir> ...] [--tasks <tasks dir>] [--variants <file>] [--out <dir>]

Each <job dir> is a Harbor job (holding trial folders) or a jobs folder such as
harbor-jobs/semgrep-v040-all, in which case its latest job is used. One job per
tool is expected; the tool name comes from the agent metadata. Two jobs of the
same tool get distinct names (the job folder is added), and a folder with no
trials is skipped with a warning instead of stopping the report.

A task's family and role (positive or negative) come from the private variant
map ``--variants`` (default ``<tasks>/VARIANTS.json`` when present, of the form
``{"<task dir>": {"family": "...", "role": "positive"|"negative"}}``), else
from a ``task_<family>_<role>`` name, else from the ground truth. The reward
never decides a role. See tools/report.py.

The per-tool numbers are the ones tools/report.py computes (it is imported, so
both reports always agree). On top of them this script adds:

- the dataset (families, positives, negatives, ground-truth findings per
  taxonomy category, and the categories the dataset does not cover),
- warnings (skipped jobs, tools run on different task sets, trials with no
  grading_detail.json or no ground truth, trials that were not scored),
- a scoreboard with one column per tool, the same rows in the Markdown and
  the HTML,
- measurement 1 (risk types, strict and loose) and measurements 2 to 4 (path,
  controls, recommendations), each shown as "not supported by this tool" when
  no graded result of the tool carries the SARIF field the grader reads,
- OWASP category and risk-type tables side by side, with their denominators,
- a task matrix (one row per task, grouped by family, every tool, with the
  runs of a repeated task summed up),
- the result funnel per tool: raw tool results, security results, results
  mapped to an OWASP rule, results written to the SARIF, and the CWEs that
  were dropped because no OWASP rule covers them,
- every true positive, every scored false positive and the results outside
  the scored scope, read from each trial's verifier/grading_detail.json.

A tool that wrote no result at all carries a "no results, scores not
meaningful" badge everywhere it is named. Harbor's job-level means are never
shown or stored, since they average positives and negatives.

With --out it writes eval_report.md, eval_report.json, eval_report.html and
trials.csv there. The HTML is tools/eval_report.html with the JSON embedded,
laid out along the client's four measurements (risk detection, reachability and
path tracing, mitigation detection, mitigation recommendation), with the
ambiguous negatives, the per-family results and the scanner output after them.
Paths in the outputs are relative to the working directory (or just the folder
name when outside it). The Markdown is always printed. Standard library only.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import report  # noqa: E402  (tools/report.py)

fmt = report.fmt
NOT_SUPPORTED = report.NOT_SUPPORTED
NO_RESULTS_BADGE = report.NO_RESULTS_BADGE


def read_json(path: Path):
    return report.read_json_file(path)


def display_path(path: Path | str | None) -> str | None:
    """A path relative to the working directory, or its last two parts when outside it."""
    if path is None:
        return None
    p = Path(path)
    try:
        rel = os.path.relpath(p.resolve(), Path.cwd().resolve())
    except ValueError:  # another drive on Windows
        rel = None
    if rel is not None and not rel.startswith(".."):
        return Path(rel).as_posix()
    parts = p.resolve().parts
    return "/".join(parts[-2:]) if len(parts) >= 2 else p.name


def resolve_job(path: Path) -> Path | None:
    """A job dir, or the latest job inside a jobs dir. None when there are no trials."""
    if report.trial_results(path):
        return path
    try:
        nested = sorted(p for p in path.iterdir() if p.is_dir() and report.trial_results(p))
    except OSError:
        return None
    return nested[-1] if nested else None


def sarif_results(trial_dir: Path) -> list:
    """The results of the SARIF the verifier graded (the agent's own copy)."""
    for candidate in (trial_dir / "agent" / "findings.sarif",
                      trial_dir / "artifacts" / "logs" / "artifacts" / "sast" / "findings.sarif"):
        data = read_json(candidate)
        if isinstance(data, dict):
            return [r for run in data.get("runs") or [] for r in run.get("results") or []]
    return []


def result_at(results: list, index) -> dict:
    return results[index] if isinstance(index, int) and 0 <= index < len(results) else {}


def res_location(res: dict) -> list:
    try:
        phys = res["locations"][0]["physicalLocation"]
        region = phys.get("region") or {}
        return [phys["artifactLocation"]["uri"], region.get("startLine"), region.get("endLine")]
    except (KeyError, IndexError, TypeError):
        return []


def mean(values):
    values = [v for v in values if v is not None]
    return sum(values) / len(values) if values else None


def task_id(task: str) -> tuple[str, str]:
    """task_3c67f1_positive -> ("3c67f1", "positive"). Other names give (name, "")."""
    return report.parse_task_name(task)


# ---- per job ---------------------------------------------------------------------------

def collect(job: Path, tasks_dir: Path | None, variants: dict | None = None) -> dict:
    rows = report.rows_for(job, tasks_dir, variants or {})
    summary = report.summarise(rows)
    funnel = Counter()
    unmapped = Counter()
    by_rule = Counter()
    versions = Counter()
    manifest = Counter()
    models = Counter()
    hits, false_positives, outside, warnings = [], [], [], []
    runs = Counter(r["task"] for r in rows)
    seen: Counter = Counter()
    for (result_file, trial), row in zip(report.trial_results(job), rows):
        trial_dir = result_file.parent
        meta = (trial.get("agent_result") or {}).get("metadata") or {}
        task = row["task"]
        seen[task] += 1
        # A task run more than once (harbor -k N) gets its run number, so its lines stay apart.
        row["run"] = seen[task] if runs[task] > 1 else None
        where = {"task": task, "family": row["family"], "role": row["role"]}
        if row["run"]:
            where["run"] = row["run"]
        detail_file = trial_dir / "verifier" / "grading_detail.json"
        detail = read_json(detail_file)
        if not isinstance(detail, dict):
            detail = {}
            if row["reward"] is not None:
                warnings.append({**where, "warning": "verifier/grading_detail.json is missing or unreadable, so "
                                 "this trial's matched results and false positives are not listed"})
        if row.get("relabelled"):
            warnings.append({**where, "warning": f"this job ran the task under its name before the rename, which "
                             f"called it a {report.parse_task_name(task)[1]}. The variant map now says "
                             f"{row['role']}, and the grade was computed against the old label, so the trial is "
                             "not scored. Rerun it for a grade under the current ground truth."})
        if row["reward"] is not None and not row.get("has_truth"):
            warnings.append({**where, "warning": "no ground truth found for this task, so location recall and "
                             "taxonomy coverage leave it out"})
        if meta.get("model"):
            models[str(meta["model"])] += 1
        for key in ("results_raw", "findings_security", "findings_mapped", "results_emitted"):
            value = meta.get(key)
            if value is None and key == "results_raw":
                # Agents that call a model report their raw findings under their own record.
                value = (meta.get("claude_review") or {}).get("findings_raw")
            funnel[key] += value or 0
        unmapped.update(meta.get("unmapped_by_cwe") or {})
        by_rule.update(meta.get("results_by_rule") or {})
        versions[meta.get("agent_version") or meta.get("tool_version") or "?"] += 1
        im = meta.get("image_manifest") or {}
        if im.get("manifest_sha256"):
            manifest[im["manifest_sha256"][:12]] += 1
        if not report.is_scored(row):
            continue
        results = sarif_results(trial_dir)
        for f in detail.get("per_finding") or []:
            if f.get("matched"):
                res = result_at(results, f.get("result_index"))
                hits.append({**where, "finding": f.get("finding"), "rule": f.get("ruleId", ""),
                             "location": res_location(res), "cwe_ok": f.get("cwe_ok"),
                             "scores": f.get("scores") or {}, "has_flow": bool(res.get("codeFlows"))})
        # On a positive, trap_hits only tag results already listed as unmatched.
        traps_by_index: dict = {}
        for th in detail.get("trap_hits") or []:
            if "result_index" in th:
                traps_by_index.setdefault(th["result_index"], []).append(th.get("trap", ""))
        for kind, key in (("unmatched", "unmatched_results"), ("trap", "trap_hits"),
                          ("near_fix", "results_near_fixed_code")):
            for res in detail.get(key) or []:
                if kind == "trap" and "result_index" in res:
                    continue
                traps = list(res.get("traps") or []) + traps_by_index.get(res.get("index"), [])
                false_positives.append({**where, "kind": kind, "rule": res.get("ruleId", ""),
                                        "location": res.get("location") or "", "traps": ",".join(traps)})
        for res in detail.get("outside_scope_results") or []:
            outside.append({**where, "rule": res.get("ruleId", ""), "location": res.get("location") or ""})
    tool = next((r["tool"] for r in rows if r.get("tool")), job.parent.name)
    job_result = read_json(job / "result.json") or {}
    stats = job_result.get("stats") or {}
    return {
        "tool": tool, "job": display_path(job), "rows": rows, "summary": summary,
        "funnel": dict(funnel), "unmapped_by_cwe": dict(unmapped.most_common()),
        "results_by_rule": dict(by_rule.most_common()), "agent_versions": dict(versions),
        "models": dict(models),
        "image_manifests": dict(manifest), "hits": hits, "false_positives": false_positives,
        "outside_scope": outside, "warnings": warnings,
        "task_outcomes": task_outcomes(rows),
        # Counts only. Harbor's job-level metrics are means over positives and negatives, not scores.
        "harbor_job": {"n_total_trials": job_result.get("n_total_trials"),
                       "n_completed_trials": stats.get("n_completed_trials"),
                       "n_errored_trials": stats.get("n_errored_trials")},
    }


def assign_keys(jobs: list[dict]) -> None:
    """Unique tool keys (two jobs of one tool get the job folder added) and display labels."""
    counts = Counter(j["tool"] for j in jobs)
    names = Counter((j["tool"], Path(j["job"]).name) for j in jobs)
    # Two runs of a model-backed tool on different models are told apart by the model.
    model_of = {id(j): ", ".join(j.get("models") or {}) for j in jobs}
    model_counts = Counter((j["tool"], model_of[id(j)]) for j in jobs)
    used: set = set()
    for j in jobs:
        job = Path(j["job"])
        # The job folder tells two runs apart, or the jobs folder above it when the job names match.
        tag = job.name if names[(j["tool"], job.name)] == 1 else (job.parent.name or job.name)
        if model_of[id(j)] and model_counts[(j["tool"], model_of[id(j)])] == 1:
            tag = model_of[id(j)]
        key = j["tool"] if counts[j["tool"]] == 1 else f"{j['tool']} ({tag})"
        base, n = key, 2
        while key in used:
            key, n = f"{base} #{n}", n + 1
        used.add(key)
        j["key"] = key
        j["no_results"] = bool(j["summary"]["no_results_emitted"])
        j["label"] = f"{key} [{NO_RESULTS_BADGE}]" if j["no_results"] else key
        j["measures"] = measures_of(j)


def measures_of(j: dict) -> dict:
    """Per-tool figures for measurements 2 to 4, shared by the Markdown and the HTML."""
    s = j["summary"]
    rows = report.by_role(j["rows"], "positive")
    det = s["pooled_detection"] or {}
    with_meta = [r for r in rows if r.get("near") is not None]
    gt_meta = sum(r["gt"] or 0 for r in with_meta)
    m = s["measurements_positive_tasks"]
    neg = s["reward_by_role"]["negative"]
    clean, negatives = s["zero_finding_tasks_clean"]
    return {
        "gt": det.get("gt", 0), "matched": det.get("tp", 0), "finding_recall": det.get("recall"),
        "gt_with_metadata": gt_meta,
        "near": sum(r["near"] for r in with_meta) if with_meta else None,
        "near_cwe": sum(r["near_cwe"] for r in with_meta) if with_meta else None,
        "near_recall": report.ratio(sum(r["near"] for r in with_meta), gt_meta) if with_meta else None,
        "near_cwe_recall": report.ratio(sum(r["near_cwe"] for r in with_meta), gt_meta) if with_meta else None,
        "path": m.get("path"), "controls": m.get("controls"), "recommendations": m.get("recommendations"),
        "supported": m.get("supported") or {},
        "results_with": s["measurement_support"]["results_with"],
        "hits": len(j["hits"]), "hits_with_flow": sum(1 for h in j["hits"] if h.get("has_flow")),
        "negatives_clean": clean, "negatives": negatives,
        "failed_near_fix": neg.get("failed_near_fix", 0), "failed_trap": neg.get("failed_trap", 0),
    }


def measure_value(j: dict, key: str) -> str:
    if j["measures"]["supported"].get(key) is False:
        return NOT_SUPPORTED
    return fmt(j["measures"][key]) or "n/a"


# ---- dataset ---------------------------------------------------------------------------

def dataset(jobs: list[dict]) -> dict:
    """Families, roles and findings over the union of the tasks every tool ran on."""
    tasks: dict[str, dict] = {}
    for j in jobs:
        for r in j["rows"]:
            t = tasks.setdefault(r["task"], {"family": r["family"], "role": r["role"], "gt": None,
                                              "gt_rules": None, "risks": None})
            if r.get("gt_rules") is not None:
                t["gt"], t["gt_rules"] = r["gt"], r["gt_rules"]
            elif t["gt"] is None and report.is_scored(r):
                t["gt"] = r["gt"]
            if t["risks"] is None and report.is_scored(r) and r["risks"]:
                t["risks"] = tuple(s for s in report.RISKS if r["risks"][s]["truth"])
            if not t["role"] and r["role"]:
                t["role"] = r["role"]
    positives = [t for t in tasks.values() if t["role"] == "positive"]
    negatives = [t for t in tasks.values() if t["role"] == "negative"]
    sets = Counter()
    for t in positives:
        if t["risks"] is not None:
            sets[{("SID", "EA"): "both", ("SID",): "SID only", ("EA",): "EA only"}.get(t["risks"], "neither")] += 1
    all_rows = [r for j in jobs for r in j["rows"]]
    per_tool = {j["key"]: sorted({r["task"] for r in j["rows"]}) for j in jobs}
    union = sorted(tasks)
    return {
        "tasks": len(tasks), "families": len({t["family"] for t in tasks.values()}),
        "positives": len(positives), "negatives": len(negatives),
        "unknown_role": sum(1 for t in tasks.values() if t["role"] not in report.ROLES),
        "gt_findings": sum(t["gt"] or 0 for t in positives),
        "gt_unknown": sum(1 for t in positives if t["gt"] is None),
        "positives_by_risk_set": dict(sets),
        "taxonomy_coverage": report.taxonomy_coverage(all_rows),
        "tasks_by_tool": {k: len(v) for k, v in per_tool.items()},
        "same_task_set": all(v == union for v in per_tool.values()),
        "missing_by_tool": {k: [t for t in union if t not in set(v)] for k, v in per_tool.items()
                            if v != union},
    }


def warnings_of(jobs: list[dict], data: dict, skipped: list[str]) -> list[str]:
    out = [f"No Harbor trials were found under {name}, so it was left out of the report." for name in skipped]
    if not data["same_task_set"]:
        parts = ", ".join(f"{k} ran {data['tasks_by_tool'][k]}" for k in data["tasks_by_tool"])
        out.append(f"The tools ran on different task sets ({parts}, {data['tasks']} tasks in all). "
                   "Their scores are over different tasks and are not directly comparable.")
    for j in jobs:
        bad = report.not_scored(j["rows"])
        if bad:
            det = j["summary"]["pooled_detection"] or {}
            extra = (f" Recall leaves out {det.get('gt_not_scored', 0)} ground-truth findings on "
                     f"{det.get('tasks_not_scored', 0)} of them.") if det.get("tasks_not_scored") else ""
            out.append(f"{j['key']}: {len(bad)} trial(s) did not finish cleanly and are not scored "
                       f"(listed under 'Trials that did not finish cleanly').{extra}")
        missing_detail = [w for w in j["warnings"] if "grading_detail" in w["warning"]]
        if missing_detail:
            out.append(f"{j['key']}: {len(missing_detail)} trial(s) have no readable grading_detail.json, so "
                       "their matched and false-positive results are not listed (see 'Warnings per trial').")
        no_truth = [w for w in j["warnings"] if "no ground truth" in w["warning"]]
        if no_truth:
            out.append(f"{j['key']}: no ground truth was found for {len(no_truth)} trial(s). Pass --tasks with "
                       "the task folders to get location recall and taxonomy coverage.")
        relabelled = [w for w in j["warnings"] if "before the rename" in w["warning"]]
        if relabelled:
            out.append(f"{j['key']}: {len(relabelled)} trial(s) ran before the rename under a name with a role "
                       "that has since changed. They were graded under the old role, so they are not scored and "
                       "are listed with the trials that did not finish cleanly (see 'Warnings per trial').")
        unknown = j["summary"]["reward_by_role"].get("unknown_role")
        if unknown:
            out.append(f"{j['key']}: {unknown} trial(s) have no known role (no variant map entry, no "
                       "task_<family>_<role> name and no ground truth) and are left out of every table.")
    return out


def coverage_sentence(data: dict) -> str | None:
    cov = data["taxonomy_coverage"]
    if not cov["known"]:
        return None
    present = [f"{k} {v}" for k, v in cov["findings_by_rule"].items() if v]
    missing = cov["missing"]
    text = "Ground-truth findings per taxonomy ruleId: " + (", ".join(present) or "none") + "."
    if missing:
        names = missing[0] if len(missing) == 1 else ", ".join(missing[:-1]) + " or " + missing[-1]
        text += (" The dataset has no finding for " + names + ", so those categories are not "
                 "measured here. The category scores also drop the disclosure severity (LLM02.SID covers "
                 "Medium and High), so Medium and High cannot be told apart in them.")
    return text


# ---- rendering helpers ---------------------------------------------------------------

def headline(jobs: list[dict]) -> list[list]:
    """The scoreboard rows, shared by the Markdown and the HTML."""
    def row(label, fn):
        return [label] + [fn(j) for j in jobs]

    def det(j, key):
        return (j["summary"]["pooled_detection"] or {}).get(key)

    def role(j, r, key):
        return j["summary"]["reward_by_role"][r].get(key)

    def cat(j, key):
        return j["summary"]["categories"]["overall"].get(key)

    def risk_mean(j, key):
        return mean([j["summary"]["risk_types"][r][key] for r in report.RISKS.values()])

    def exact(j, r):
        v = j["summary"]["risk_types"]["exact_by_role"][r]
        return f"{v['exact']}/{v['tasks']}"

    def scored(j):
        return len(report.usable(j["rows"]))

    def gt(j):
        d = j["summary"]["pooled_detection"] or {}
        extra = f" (+{d['gt_not_scored']} not scored)" if d.get("tasks_not_scored") else ""
        return f"{d.get('gt', 0)}{extra}"

    def scan(j):
        return mean([r.get("scan_s") for r in j["rows"]])

    def setup(j):
        return mean([r.get("setup_s") for r in j["rows"]])

    def emitted_trials(j):
        return sum(1 for r in j["rows"] if (r.get("emitted") or 0) > 0)

    neg_clean = lambda j: "{}/{}".format(*j["summary"]["zero_finding_tasks_clean"])  # noqa: E731
    return [
        row("Trials scored (not scored)", lambda j: f"{scored(j)} ({len(j['rows']) - scored(j)})"),
        row("Results written to the SARIF (trials with any)",
            lambda j: f"{j['funnel'].get('results_emitted', 0)} ({emitted_trials(j)})"),
        row("Ground-truth findings on scored positives", gt),
        row("True positives (findings matched)", lambda j: det(j, "tp")),
        row("False positives on positives", lambda j: det(j, "fp")),
        row("False negatives", lambda j: det(j, "fn")),
        row("Precision", lambda j: fmt(det(j, "precision")) or "n/a"),
        row("Recall", lambda j: fmt(det(j, "recall")) or "n/a"),
        row("F1", lambda j: fmt(det(j, "F1")) or "n/a"),
        row("Risk detection, mean TPR over the two risks", lambda j: fmt(risk_mean(j, "TPR")) or "n/a"),
        row("Risk detection, mean FPR over the two risks (negatives)", lambda j: fmt(risk_mean(j, "FPR")) or "n/a"),
        row("Exact risk set, positives", lambda j: exact(j, "positive")),
        row("Exact risk set, negatives (neither)", lambda j: exact(j, "negative")),
        row("Negatives clean", neg_clean),
        row("Negatives failed on a decoy / next to the fix",
            lambda j: f"{role(j, 'negative', 'failed_trap')} / {role(j, 'negative', 'failed_near_fix')}"),
        row("Mean reward, positives", lambda j: fmt(role(j, "positive", "mean_reward")) or "n/a"),
        row("Mean reward, negatives", lambda j: fmt(role(j, "negative", "mean_reward")) or "n/a"),
        row("Path tracing (measurement 2), mean on positives", lambda j: measure_value(j, "path")),
        row("Mitigation detection (measurement 3), mean on positives", lambda j: measure_value(j, "controls")),
        row("Recommendation (measurement 4), mean on positives", lambda j: measure_value(j, "recommendations")),
        row("OWASP mean TPR", lambda j: fmt(cat(j, "mean_TPR")) or "n/a"),
        row("OWASP mean FPR", lambda j: fmt(cat(j, "mean_FPR")) or "n/a"),
        row("OWASP score (mean TPR minus mean FPR)", lambda j: fmt(cat(j, "score")) or "n/a"),
        row("Results outside scope (not scored)", lambda j: j["summary"]["fp_outside_scope"]),
        row("Mean setup seconds", lambda j: f"{setup(j):.1f}" if setup(j) is not None else "n/a"),
        row("Mean scan seconds", lambda j: f"{scan(j):.1f}" if scan(j) is not None else "n/a"),
    ]


def measurement_rows(jobs: list[dict]) -> list[list]:
    def frac(a, b):
        return f"{a}/{b}" if a is not None else "n/a"

    def withr(j, key):
        return j["measures"]["results_with"].get(key, 0)

    return [
        ["Findings matched / ground-truth findings"] + [f"{j['measures']['matched']}/{j['measures']['gt']}" for j in jobs],
        ["Finding recall"] + [fmt(j["measures"]["finding_recall"]) or "n/a" for j in jobs],
        ["Raw result near the finding (location recall)"] +
        [frac(j["measures"]["near"], j["measures"]["gt_with_metadata"]) for j in jobs],
        ["Near, with an acceptable CWE"] + [frac(j["measures"]["near_cwe"], j["measures"]["gt_with_metadata"]) for j in jobs],
        ["Path score, mean on positives (measurement 2)"] + [measure_value(j, "path") for j in jobs],
        ["Matched detections with a code flow"] + [f"{j['measures']['hits_with_flow']}/{j['measures']['hits']}" for j in jobs],
        ["Control and residual-risk score, mean on positives (measurement 3)"] + [measure_value(j, "controls") for j in jobs],
        ["Negatives clean (measurement 3, other side)"] +
        [f"{j['measures']['negatives_clean']}/{j['measures']['negatives']}" for j in jobs],
        ["Recommendation score, mean on positives (measurement 4)"] + [measure_value(j, "recommendations") for j in jobs],
        ["Graded results with codeFlows / controlStatus or residualRisk / recommendations"] +
        [f"{withr(j, 'codeFlows')} / {max(withr(j, 'controlStatus'), withr(j, 'residualRisk'))} / "
         f"{withr(j, 'recommendations')}" for j in jobs],
    ]


def category_rows(jobs: list[dict]) -> list[list]:
    cats = sorted({c for j in jobs for c in j["summary"]["categories"]["per_category"]})
    out = []
    for c in cats:
        line = [c]
        for j in jobs:
            v = j["summary"]["categories"]["per_category"].get(c)
            line.append("" if not v else
                        f"TPR {fmt(v['TPR']) or 'n/a'} ({v['TP']} of {v['positives']} positives), "
                        f"FPR {fmt(v['FPR']) or 'n/a'} ({v['FP']} of {v['negatives']} negatives), "
                        f"score {fmt(v['youden']) or 'n/a'}")
        out.append(line)
    return out


def risk_rows(jobs: list[dict], key: str) -> list[list]:
    out = []
    for risk in report.RISKS.values():
        line = [risk]
        for j in jobs:
            v = j["summary"][key][risk]
            text = (f"TPR {fmt(v['TPR']) or 'n/a'} ({v['TP']} of {v['TP'] + v['FN']} positives), "
                    f"FPR {fmt(v['FPR']) or 'n/a'} ({v['FP']} of {v['FP'] + v['TN']} negatives), "
                    f"precision {fmt(v['precision']) or 'n/a'}")
            if v.get("FP_other_pos"):
                n = v["FP_other_pos"]
                text += f", also flagged on {n} positive{'' if n == 1 else 's'} without it"
            line.append(text)
        out.append(line)
    order = ["both", "SID only", "EA only", "neither"]
    exact = sorted({k for j in jobs for k in j["summary"][key]["by_truth_set"]},
                   key=lambda k: order.index(k) if k in order else 9)
    for k in exact:
        line = [f"exact risk set, labelled {k}"]
        for j in jobs:
            v = j["summary"][key]["by_truth_set"].get(k)
            line.append(f"{v['exact']}/{v['tasks']}" if v else "")
        out.append(line)
    return out


def _runs(n: int, k: int) -> str:
    return "" if k == 1 else f" in {n} of {k} runs"


def task_outcomes(rows: list[dict]) -> list[dict]:
    """One entry per task (not per role), so a family with two positives keeps both, and the
    runs of a task run more than once (harbor -k N) are summed up instead of the last one
    winning. kind is ok, bad, mixed (some runs each way) or na (nothing scored)."""
    by_task: dict[str, list[dict]] = {}
    for r in rows:
        by_task.setdefault(r["task"], []).append(r)
    out = []
    for task, group in by_task.items():
        first = group[0]
        role = first["role"] or "unknown"
        scored = [r for r in group if report.is_scored(r)]
        unscored = [r for r in group if not report.is_scored(r)]
        k = len(scored)
        if not scored:
            text, kind = "not scored (" + ", ".join(sorted({r["status"] for r in unscored})) + ")", "na"
        elif role == "positive":
            gt = next((r["gt"] for r in scored if r["gt"] is not None), 0) or 0
            by_tp = Counter(r["tp"] or 0 for r in scored)
            text = ", ".join(f"{tp}/{gt} found{_runs(n, k)}" for tp, n in sorted(by_tp.items(), reverse=True))
            fp = sum(r["fp"] or 0 for r in scored)
            if fp:
                text += f", {fp} FP" + ("" if k == 1 else " in total")
            found = sum(1 for r in scored if (r["tp"] or 0) > 0)
            kind = "ok" if found == k else "bad" if found == 0 else "mixed"
        elif role == "negative":
            failed = [r for r in scored if (r["fp"] or 0) > 0]
            fp = sum(r["fp"] or 0 for r in failed)
            if not failed:
                text, kind = "clean" + _runs(k, k), "ok"
            elif k == 1:
                text, kind = f"FAIL ({fp} FP)", "bad"
            else:
                text = f"FAIL{_runs(len(failed), k)} ({fp} FP in total)"
                kind = "bad" if len(failed) == k else "mixed"
        else:
            text, kind = f"role unknown ({task})", "na"
        if scored and unscored:
            text += f" (+{len(unscored)} not scored)"
        out.append({"task": task, "family": first["family"], "role": role, "runs": len(group), "scored": k,
                    "text": text, "kind": kind,
                    "gt": next((r["gt"] for r in group if r["gt"] is not None), None)})
    return out


ROLE_ORDER = {"positive": 0, "negative": 1}


def matrix_rows(jobs: list[dict]) -> list[list]:
    """One row per task: family, task, role, then each tool's outcome over all its runs."""
    tasks: dict[str, dict] = {}
    cells: list[dict] = []
    for j in jobs:
        mine = {}
        for o in j.get("task_outcomes") or task_outcomes(j["rows"]):
            mine[o["task"]] = o["text"]
            t = tasks.setdefault(o["task"], {"family": o["family"], "role": o["role"]})
            if t["role"] == "unknown" and o["role"] != "unknown":
                t["role"] = o["role"]
        cells.append(mine)
    order = sorted(tasks, key=lambda k: (str(tasks[k]["family"]), ROLE_ORDER.get(tasks[k]["role"], 2), k))
    return [[tasks[k]["family"], k, tasks[k]["role"]] + [c.get(k, "not run") for c in cells] for k in order]


def funnel_rows(jobs: list[dict]) -> list[list]:
    labels = [("results_raw", "Raw tool results"), ("findings_security", "Security results"),
              ("findings_mapped", "Mapped to an OWASP rule"), ("results_emitted", "Written to the SARIF")]
    rows = [[label] + [j["funnel"].get(key, 0) for j in jobs] for key, label in labels]
    rows.append(["Top dropped CWEs (no OWASP rule)"] +
                [", ".join(f"{k} x{v}" for k, v in list(j["unmapped_by_cwe"].items())[:6]) for j in jobs])
    rows.append(["Emitted by OWASP rule"] +
                [", ".join(f"{k} x{v}" for k, v in j["results_by_rule"].items()) for j in jobs])
    return rows


def run_label(x: dict) -> str:
    """The task name, with the run number when the task ran more than once."""
    return f"{x['task']} (run {x['run']})" if x.get("run") else x["task"]


def loc(v) -> str:
    if isinstance(v, (list, tuple)) and v:
        return f"{v[0]}:{v[1]}" if len(v) > 1 else str(v[0])
    if isinstance(v, dict):
        return f"{v.get('file', '')}:{v.get('start_line', '')}"
    return str(v or "")


def observations(jobs: list[dict]) -> list[dict]:
    """[{"tool": key or None, "text": ...}]. Tool notes are hidden with the tool in the HTML."""
    notes = []
    for j in jobs:
        s = j["summary"]
        det = s["pooled_detection"] or {}
        if j["no_results"]:
            notes.append({"tool": j["key"], "text": f"{j['key']} wrote no result on any task, so its negatives "
                          "pass by default, its FPR is 0 and its OWASP score is 0. Those scores say nothing "
                          "about the tool."})
        if det and not det.get("tp") and det.get("gt"):
            raw = j["funnel"].get("results_raw", 0)
            notes.append({"tool": j["key"], "text": f"{j['key']} found none of the {det.get('gt')} ground-truth "
                          f"findings. It produced {raw} raw results, of which "
                          f"{j['funnel'].get('results_emitted', 0)} reached the SARIF."})
        neg = s["reward_by_role"]["negative"]
        if neg.get("failed"):
            parts = []
            if neg["failed_trap"]:
                parts.append(f"{neg['failed_trap']} on a decoy")
            if neg["failed_near_fix"]:
                parts.append(f"{neg['failed_near_fix']} next to the fixed code")
            notes.append({"tool": j["key"], "text": f"{j['key']} failed {neg['failed']} of {neg['tasks']} "
                          f"negatives ({' and '.join(parts)}), so it flags safe code as vulnerable there."})
    unsupported = [m for m in ("path", "controls", "recommendations")
                   if jobs and all(j["measures"]["supported"].get(m) is False for j in jobs)]
    if unsupported:
        names = {"path": "code flows (measurement 2)", "controls": "control status or residual risk "
                 "(measurement 3)", "recommendations": "recommendations (measurement 4)"}
        listed = [names[m] for m in unsupported]
        joined = listed[0] if len(listed) == 1 else ", ".join(listed[:-1]) + " or " + listed[-1]
        notes.append({"tool": None, "text": "No tool put " + joined +
                      " in a field the grader reads, so those measurements are shown as not supported by "
                      "these tools rather than as 0."})
    tps = [(j["summary"]["pooled_detection"] or {}).get("tp") or 0 for j in jobs]
    if jobs and max(tps) == 0:
        notes.append({"tool": None, "text": "No tool detected any ground-truth finding. The OWASP scores are "
                      "therefore driven only by false alarms on negatives, and 0 is also what reporting "
                      "nothing earns."})
    return notes


METHOD = [
    "Each task is a small runnable repository. Scanners receive only the repository source, configuration and "
    "safe fixtures plus the security-context manifest. Labels, expected findings and reproduction tests stay "
    "evaluator-only.",
    "A reported result can match a ground-truth finding only when its OWASP risk family (LLM02 or LLM03, read "
    "from the ruleId prefix) is the finding's risk type, it lands within the task's line tolerance of the "
    "finding's primary or an alternative location, and, when the task sets require_cwe, "
    "its CWEs include the finding's primary CWE or one of its acceptable CWEs. The exact ruleId does not gate "
    "the match.",
    "Results and findings are paired one to one by an optimal assignment that maximises the task reward. "
    "Classification then gives 80% weight to the reported ruleId (full credit for an acceptable rule, half "
    "for a partial-credit rule) and 20% to the CWE.",
    "On a positive, an unmatched result in a file the fix changed is a false positive. Results in other files "
    "are outside scope and not scored. A task that lists no changed files counts every unmatched result.",
    "A negative fails on a result whose OWASP prefix is one of the contrasted prefixes and that lands within "
    "the line tolerance of the fixed code (next to the fix), or on a result with a decoy's prefix within "
    "tolerance of that decoy. No CWE agreement is needed to fail. Every other result is outside scope.",
    "Risk detection (measurement 1) counts a risk as predicted only from results that matched a finding or "
    "that fail the negative. TPR is over the positives labelled with the risk and FPR over the negatives only, "
    "since a positive without a risk can never predict it under this rule.",
    "Category scores are OWASP Benchmark style: TPR minus FPR per category, then the mean over categories. "
    "A positive is a test case for the categories of its findings, a negative for the categories it contrasts. "
    "On a negative a category counts as flagged when a failing result has the same OWASP prefix, so an "
    "LLM03.EA.FUNCTIONALITY result also flags an EA permissions negative. The category drops the disclosure "
    "severity.",
    "Measurements 2 to 4 are scored on matched findings only: path from the result's codeFlows, controls from "
    "the top-level controlStatus (75%) and residualRisk (25%), recommendations from the recommendations "
    "property. When no graded result of a tool carries the field, the measurement is shown as not supported "
    "by that tool. Agents that write heuristic values under properties.heuristics are not scored on them.",
    "Trials that errored, whose agent reported an error, whose SARIF was missing or whose grader crashed are "
    "not scored. Neither is a trial recorded before the role-free rename under a name whose role has since "
    "changed, since it was graded against the old label. Their findings are named apart and not added to recall.",
    "A task's role and family come from the private variant map when present, else from the task name, else "
    "from the ground truth. The reward never decides a role.",
]


def md_section(out: list, title: str, intro: str | None, table: list[str] | None = None) -> None:
    out += ["", f"## {title}"]
    if intro:
        out += ["", intro]
    if table:
        out += table


def render(jobs: list[dict], tasks_dir: Path | None, data: dict | None = None,
           warnings: list[str] | None = None) -> str:
    t = report.md_table
    data = data or dataset(jobs)
    warnings = warnings if warnings is not None else warnings_of(jobs, data, [])
    labels = [j["label"] for j in jobs]
    tasks_text = display_path(tasks_dir) if tasks_dir else "the paths recorded in the trials, where found"
    out = ["# SAST scanner eval report", "",
           f"Generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} from "
           f"{len(jobs)} Harbor jobs. Ground truth from {tasks_text}.", ""]
    for j in jobs:
        versions = ", ".join(j["agent_versions"])
        manifests = ", ".join(j["image_manifests"]) or "not recorded"
        badge = f" **{NO_RESULTS_BADGE}.**" if j["no_results"] else ""
        out.append(f"- **{j['key']}**: agent {versions}, image manifest {manifests}, job `{j['job']}`.{badge}")
    if warnings:
        md_section(out, "Warnings", None)
        out += [""] + [f"- {w}" for w in warnings]
    notes = observations(jobs)
    if notes:
        md_section(out, "Key observations", None)
        out += [""] + [f"- {n['text']}" for n in notes]
    sets = data["positives_by_risk_set"]
    md_section(out, "Dataset",
               f"{data['families']} repository families, {data['positives']} positive tasks (vulnerable) and "
               f"{data['negatives']} ambiguous negatives (fixed twins), with {data['gt_findings']} ground-truth "
               f"findings on the positives. Positives by labelled risk set: both {sets.get('both', 0)}, "
               f"disclosure only {sets.get('SID only', 0)}, agency only {sets.get('EA only', 0)}.")
    cov = coverage_sentence(data)
    if cov:
        out += ["", cov]
    md_section(out, "Scoreboard",
               "Positive tasks hold the vulnerable code, negative tasks the fixed twin. Rewards are never "
               "averaged over both, since an empty SARIF scores 1.0 on every negative. "
               f"\"{NOT_SUPPORTED}\" means no graded result of the tool carries the field the grader reads.",
               t(["Measure"] + labels, headline(jobs)))
    md_section(out, "Measurement 1: risk detection",
               "Whether the scanner says the repository has Sensitive Information Disclosure, Excessive Agency, "
               "both or neither. A risk counts as detected on a task only when a result matched a finding of "
               "that risk, or failed the negative. TPR is over the positives labelled with the risk, FPR over "
               "the negatives only.",
               t(["Risk type"] + labels, risk_rows(jobs, "risk_types")))
    md_section(out, "Measurement 1, loose rule (secondary view)",
               "The grader's older, looser flag: a risk counts as predicted from any result in the files the "
               "fix changed or next to the fixed code, matched or not. It shows how often a tool flagged the "
               "right area with no matching finding. It is not the score.",
               t(["Risk type"] + labels, risk_rows(jobs, "risk_types_loose")))
    md_section(out, "Measurements 2 to 4: path, controls and recommendations",
               "Scored on positives against each ground-truth finding, so a missed finding scores 0. The near "
               "rows look at the tool's raw output before OWASP mapping and show how close it came. The "
               "ambiguous negatives test mitigation detection from the other side.",
               t(["Measure"] + labels, measurement_rows(jobs)))
    md_section(out, "OWASP categories",
               "One test case per task and category (OWASP Benchmark style, with the matching rules of the "
               "method section, not the OWASP Benchmark's own test cases). TPR is over the positives labelled "
               "with the category, FPR over the negatives that contrast it. On a negative a category is flagged "
               "by any failing result with the same OWASP prefix (LLM02 or LLM03). The overall score is the "
               "mean over the categories that have both positives and negatives.",
               t(["Category"] + labels, category_rows(jobs)))
    md_section(out, "Result funnel",
               "Where each tool's results went. Results whose CWEs no OWASP LLM02 or LLM03 rule covers are "
               "dropped before the SARIF is written, and results of one family on the same file and line are "
               "merged into one, so fewer can be written than were mapped.",
               t(["Stage"] + labels, funnel_rows(jobs)))
    md_section(out, "Task matrix", "Every task of every family per tool: findings matched out of the ground "
               "truth on a positive, and whether a negative stayed clean. A family can hold more than one "
               "positive. A task run more than once shows how many of its runs gave each result.",
               t(["Family", "Task", "Role"] + labels, matrix_rows(jobs)))
    hits = [[j["label"], run_label(h), h["finding"], h["rule"], loc(h["location"]), h["cwe_ok"],
             h["scores"].get("detection"), h["scores"].get("classification")] for j in jobs for h in j["hits"]]
    md_section(out, "True positives", "Every result matched to a ground-truth finding.",
               t(["Tool", "Task", "Finding", "Rule", "Location", "CWE ok", "Detection", "Classification"], hits)
               if hits else ["", "None. No tool matched any ground-truth finding."])
    fps = [[j["label"], run_label(f), f["kind"], f["rule"], loc(f["location"]), f["traps"]]
           for j in jobs for f in j["false_positives"]]
    md_section(out, "False positives",
               "`unmatched` is a result on a positive, in a file the fix changed, that matched no finding (Traps "
               "names a decoy it landed on). `trap` is a result on a negative's decoy, `near_fix` a result on a "
               "negative next to the fixed code.",
               t(["Tool", "Task", "Kind", "Rule", "Location", "Traps"], fps) if fps else ["", "None."])
    outside = Counter((j["label"], run_label(o)) for j in jobs for o in j["outside_scope"])
    rules: dict = {}
    for j in jobs:
        for o in j["outside_scope"]:
            rules.setdefault((j["label"], run_label(o)), Counter())[o["rule"]] += 1
    md_section(out, "Results outside scope (not scored)",
               "Results the tool reported away from the code the grader looks at, per task. They are neither "
               "true nor false positives.",
               t(["Tool", "Task", "Results", "Rules"],
                 [[k[0], k[1], n, ", ".join(f"{r} x{c}" for r, c in rules[k].items())]
                  for k, n in sorted(outside.items())]) if outside else ["", "None."])
    errors = [[j["label"], run_label(r), r["role"] or "unknown", r["status"], r["gt"] if r["gt"] is not None else "?",
               r["error"]] for j in jobs for r in j["rows"] if not report.is_scored(r)]
    if errors:
        md_section(out, "Trials that did not finish cleanly",
                   "Not scored and left out of every table. Ground-truth findings on these positives are not "
                   "counted in recall.", t(["Tool", "Task", "Role", "Status", "GT findings", "Error"], errors))
    per_trial = [[j["label"], run_label(w), w["warning"]] for j in jobs for w in j["warnings"]]
    if per_trial:
        md_section(out, "Warnings per trial", None, t(["Tool", "Task", "Warning"], per_trial))
    md_section(out, "Method", None)
    out += [""] + [f"- {m}" for m in METHOD]
    md_section(out, "Note", report.HARBOR_MEAN_WARNING)
    out.append("")
    return "\n".join(out)


HTML_TEMPLATE = Path(__file__).resolve().parent / "eval_report.html"
DATA_MARKER = '<script id="report-data" type="application/json">null</script>'


def build_payload(jobs: list[dict], tasks_dir: Path | None, data: dict | None = None,
                  warnings: list[str] | None = None) -> dict:
    """What eval_report.json holds and the HTML view reads."""
    data = data or dataset(jobs)
    warnings = warnings if warnings is not None else warnings_of(jobs, data, [])
    labels = ["Measure"] + [j["key"] for j in jobs]
    return {
        "schema": "sast-eval-report/2",
        "generated": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "tasks_dir": display_path(tasks_dir) if tasks_dir else None,
        "dataset": data,
        "coverage_note": coverage_sentence(data),
        "warnings": warnings,
        "observations": observations(jobs),
        "scoreboard": {"columns": labels, "rows": headline(jobs)},
        "measurement_rows": measurement_rows(jobs),
        "method": METHOD,
        "not_supported": NOT_SUPPORTED,
        "no_results_badge": NO_RESULTS_BADGE,
        "harbor_mean_warning": report.HARBOR_MEAN_WARNING,
        "tools": [{k: v for k, v in j.items() if k != "rows"} | {"trials": j["rows"]} for j in jobs],
    }


def render_html(payload: dict) -> str:
    """tools/eval_report.html with the report embedded, so the file opens on its own.

    The template also works without embedded data: served next to an
    eval_report.json it fetches it, and opened from disk it offers a file picker.
    """
    template = HTML_TEMPLATE.read_text(encoding="utf-8")
    if DATA_MARKER not in template:
        raise SystemExit("eval_report: eval_report.html has no data placeholder")
    # "<" escaped so no string in the data can close the script element.
    data = json.dumps(payload, default=str).replace("<", "\\u003c")
    return template.replace(DATA_MARKER, DATA_MARKER.replace(">null<", ">" + data + "<"), 1)


CSV_COLUMNS = ["tool", "task", "family", "role", "status", "reward", "tp", "fp", "fn", "gt", "fp_out", "raw",
               "security", "emitted", "setup_s", "scan_s", "detection", "classification", "path", "controls",
               "recommendations", "neg_fail_trap", "neg_fail_near_fix", "error"]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("jobs", type=Path, nargs="+", help="Harbor job dirs or jobs folders, one per tool")
    parser.add_argument("--tasks", type=Path, help="folder holding the task directories, for ground truth")
    parser.add_argument("--variants", type=Path,
                        help="private map of task dir to family and role (default: <tasks>/VARIANTS.json)")
    parser.add_argument("--out", type=Path, help="write eval_report.md, eval_report.json and trials.csv here")
    args = parser.parse_args()

    variants = report.load_variants(report.default_variants(args.tasks, args.variants))
    jobs, skipped = [], []
    for path in args.jobs:
        job = resolve_job(path)
        if job is None:
            print(f"eval_report: warning: no Harbor trials found under {path}, skipping it", file=sys.stderr)
            skipped.append(display_path(path))
            continue
        jobs.append(collect(job, args.tasks, variants))
    if not jobs:
        sys.exit("eval_report: no Harbor trials found in any of the given folders")
    assign_keys(jobs)
    data = dataset(jobs)
    warnings = warnings_of(jobs, data, skipped)
    markdown = render(jobs, args.tasks, data, warnings)
    if args.out:
        args.out.mkdir(parents=True, exist_ok=True)
        (args.out / "eval_report.md").write_text(markdown, encoding="utf-8")
        payload = build_payload(jobs, args.tasks, data, warnings)
        (args.out / "eval_report.json").write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
        (args.out / "eval_report.html").write_text(render_html(payload), encoding="utf-8")
        with open(args.out / "trials.csv", "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=CSV_COLUMNS, extrasaction="ignore")
            writer.writeheader()
            for j in jobs:
                for r in j["rows"]:
                    writer.writerow({**r, "tool": j["key"]})
    sys.stdout.reconfigure(encoding="utf-8")
    print(markdown)


if __name__ == "__main__":
    main()
