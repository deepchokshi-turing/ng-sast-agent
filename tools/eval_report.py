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
- the versions every job was graded under (agent, CWE map, heuristics,
  Claude category map) and the task set's git commit and work-tree state,
  with a warning when they differ within or across jobs, and per Claude review
  job its mode, auth and results label, with the stock-mode caveat (scores
  depend on the frozen category map, and the findings it dropped are counted),
- measurement 1 (risk types, strict and loose) and measurements 2 to 4 (path,
  controls, recommendations), each shown as "not supported by this tool" when
  the tool matched a finding and no graded result of it carries the SARIF
  field the grader reads, and as "n/a (no results)" when it matched nothing,
- OWASP category and risk-type tables side by side, with their denominators,
- a task matrix (one row per task, grouped by family, every tool, with the
  runs of a repeated task summed up),
- the result funnel per tool: raw tool results, security results, results
  mapped to an OWASP rule, results written to the SARIF, and the CWEs that
  were dropped because no OWASP rule covers them,
- every true positive, every scored false positive and the results outside
  the scored scope, read from each trial's verifier/grading_detail.json.
- the external-audit additions: fixed-answer and empty-SARIF baselines, the
  matched-findings means, the strict view, fixed apps with any result, harness
  and filter effects per Claude job, category n with the categories a tool
  cannot emit left out of its mean, and the task's own family_id as the family
  key (the variant map's name in brackets).

A tool that wrote no result at all carries a "no results, scores not
meaningful" badge everywhere it is named. Harbor's job-level means are never
shown or stored, since they average positives and negatives.

With --out it writes eval_report.md, eval_report.json, eval_report.html,
trials.csv and the summary's measurement charts (charts/*.svg, linked from the
Markdown) there. The HTML is tools/eval_report.html with the JSON embedded,
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
import math
import os
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import report  # noqa: E402  (tools/report.py)

fmt = report.fmt
NOT_SUPPORTED = report.NOT_SUPPORTED
NO_RESULTS_MEASURE = report.NO_RESULTS_MEASURE
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


#: Free-text result properties (under properties.toolProperties) -> the measurement they speak to.
FREE_TEXT_FIELDS = {"exploitScenario": "path", "recommendation": "recommendations"}


def risk_family(rule) -> str:
    """LLM03.EA.PERMISSIONS -> LLM03, else ""."""
    head = str(rule or "").split(".")[0]
    return head if head in ("LLM02", "LLM03") else ""


def _int(v):
    return v if isinstance(v, int) and not isinstance(v, bool) else None


def wrong_type_findings(detail: dict, results: list, truth: dict | None) -> list[str]:
    """Known findings the tool missed although one of its unmatched results lands within the line
    tolerance of the finding's location under the other risk family (LLM02 for an LLM03 finding,
    or the reverse). Location only: the CWE is not checked. Unknown ground-truth fields are ignored."""
    if not isinstance(truth, dict) or not isinstance(detail, dict):
        return []
    per = [f for f in detail.get("per_finding") or [] if isinstance(f, dict)]
    matched_ids = {f.get("finding") for f in per if f.get("matched")}
    used = {f.get("result_index") for f in per if f.get("matched")}
    tol = _int((truth.get("matching") or {}).get("line_tolerance")) if isinstance(truth.get("matching"), dict) else None
    tol = 10 if tol is None else tol
    out = []
    for gt in truth.get("findings") or []:
        if not isinstance(gt, dict) or gt.get("id") in matched_ids or gt.get("is_vulnerable") is False:
            continue
        family = risk_family(gt.get("rule_id"))
        if not family:
            continue
        targets = [t for t in [gt.get("primary_location"), *(gt.get("alternative_primary_locations") or [])]
                   if isinstance(t, dict) and t.get("file") and _int(t.get("start_line")) is not None]
        for i, res in enumerate(results):
            other = risk_family(res.get("ruleId") if isinstance(res, dict) else None)
            if i in used or not other or other == family:
                continue
            loc_ = res_location(res)
            if len(loc_) < 2 or _int(loc_[1]) is None:
                continue
            start = loc_[1]
            end = _int(loc_[2]) if len(loc_) > 2 and _int(loc_[2]) is not None else start
            if any(loc_[0] == t["file"] and start <= (_int(t.get("end_line")) or t["start_line"]) + tol
                   and end >= t["start_line"] - tol for t in targets):
                out.append(str(gt.get("id")))
                break
    return out


def full_task_set(tasks_dir: Path | None, variants: dict | None = None) -> dict | None:
    """How many apps (task folders) and app families the whole task set holds, or None when unknown.
    A task folder holds a task.toml or a tests/ground_truth.json. Families come from the variant map."""
    if tasks_dir is None:
        return None
    try:
        names = sorted(p.name for p in Path(tasks_dir).iterdir()
                       if p.is_dir() and not p.name.startswith((".", "_"))
                       and ((p / "task.toml").is_file() or (p / "tests" / "ground_truth.json").is_file()))
    except OSError:
        return None
    if not names:
        return None
    families = None
    if variants:
        fams = {(variants.get(n) or {}).get("family") for n in names}
        if None not in fams:
            families = len(fams)
    return {"tasks": len(names), "families": families}


# ---- per job ---------------------------------------------------------------------------

def collect(job: Path, tasks_dir: Path | None, variants: dict | None = None) -> dict:
    rows = report.rows_for(job, tasks_dir, variants or {})
    for r in rows:
        # The task's own family_id (task_metadata.json or task.toml) is the family key, with the
        # private variant map's family name kept beside it.
        r["family_name"] = r["family"]
        if r.get("family_id"):
            r["family"] = r["family_id"]
    summary = report.summarise(rows)
    funnel = Counter()
    unmapped = Counter()
    by_rule = Counter()
    versions = Counter()
    manifest = Counter()
    models = Counter()
    hits, false_positives, outside, warnings = [], [], [], []
    free_text: Counter = Counter()
    wrong_type = results_written = 0
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
        results = sarif_results(trial_dir)
        results_written += len(results)
        # Free-text fields a tool wrote that the checker cannot score (a stock Claude review's
        # exploit scenario and recommendation), counted over every result it wrote.
        for res in results:
            props = ((res.get("properties") or {}).get("toolProperties") or {}) if isinstance(res, dict) else {}
            for field, key in FREE_TEXT_FIELDS.items():
                if isinstance(props, dict) and props.get(field):
                    free_text[key] += 1
        if not report.is_scored(row):
            continue
        if row["role"] == "positive":
            wrong_type += len(wrong_type_findings(detail, results, report.ground_truth(trial, tasks_dir, variants)))
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
                          ("near_fix", "results_near_fixed_code"), ("in_scope", "results_in_scope")):
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
        "free_text": dict(free_text), "wrong_type_findings": wrong_type,
        "results_written": results_written,
        "task_outcomes": task_outcomes(rows),
        # Counts only. Harbor's job-level metrics are means over positives and negatives, not scores.
        "harbor_job": {"n_total_trials": job_result.get("n_total_trials"),
                       "n_completed_trials": stats.get("n_completed_trials"),
                       "n_errored_trials": stats.get("n_errored_trials")},
    }


def common_truths(jobs: list[dict]) -> dict:
    """{task: ground truth} of every scored positive over all jobs, each task once."""
    truths: dict = {}
    for j in jobs:
        for r in report.by_role(j["rows"], "positive"):
            if r.get("_truth"):
                truths.setdefault(r["task"], r["_truth"])
    return truths


def apply_common_baselines(jobs: list[dict]) -> str | None:
    """Recompute every job's measurement 4 baseline with the one recommendation id that is most common
    over all the jobs' ground truths, so every tool is compared with the same fixed answer."""
    rec_id = report.common_recommendation(list(common_truths(jobs).values()))
    for j in jobs:
        j["summary"]["fixed_answer_baselines"] = report.fixed_answer_baselines(j["rows"], rec_id)
    return rec_id


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
        "no_results": m.get("no_results") or [],
        "results_with": s["measurement_support"]["results_with"],
        "hits": len(j["hits"]), "hits_with_flow": sum(1 for h in j["hits"] if h.get("has_flow")),
        "negatives_clean": clean, "negatives": negatives,
        "negatives_any_result": neg.get("any_result", 0),
        "failed_near_fix": neg.get("failed_near_fix", 0), "failed_trap": neg.get("failed_trap", 0),
        "failed_in_scope": neg.get("failed_in_scope", 0),
        "cross_family": sum(r.get("cross_family") or 0 for r in rows),
        "complete_claims": sum(r.get("complete_claims") or 0 for r in report.usable(j["rows"])),
        "matched_only": s.get("measurements_matched_only") or {},
        "fixed_answer": s.get("fixed_answer_baselines") or {},
        "empty_sarif": s.get("empty_sarif_baseline") or {},
        "strict": s.get("strict") or {},
    }


def measure_value(j: dict, key: str) -> str:
    if j["measures"]["supported"].get(key) is False:
        return NOT_SUPPORTED
    if key in (j["measures"].get("no_results") or []):
        return NO_RESULTS_MEASURE
    return fmt(j["measures"][key]) or "n/a"


def matched_value(j: dict, key: str) -> str:
    """A measurement over the matched findings only (unsupported and no-results as measure_value)."""
    if j["measures"]["supported"].get(key) is False:
        return NOT_SUPPORTED
    if key in (j["measures"].get("no_results") or []):
        return NO_RESULTS_MEASURE
    matched = j["measures"].get("matched_only") or {}
    return fmt(matched.get(key)) or "n/a"


def baseline_value(j: dict, key: str, which: str = "per_app") -> str:
    """The fixed-answer baseline of measurement 3 or 4 on this tool's scored positives."""
    b = (j["measures"].get("fixed_answer") or {}).get(key) or {}
    return fmt(b.get(which)) or "n/a"


def strict_text(j: dict, role: str, key: str) -> str:
    v = ((j["measures"].get("strict") or {}).get(role) or {})
    if key == "recall":
        return f"{fmt(v.get('recall')) or 'n/a'} ({v.get('tp', 0)}/{v.get('gt', 0)})" if v else "n/a"
    if key == "failed":
        return f"{v.get('failed', 0)}/{v.get('tasks', 0)}" if v else "n/a"
    return fmt(v.get(key)) or "n/a"


def empty_text(j: dict) -> str:
    e = j["measures"].get("empty_sarif") or {}
    pos, neg = (e.get("positive") or {}), (e.get("negative") or {})
    if not (pos.get("tasks") or neg.get("tasks")):
        return "n/a"
    return f"{fmt(pos.get('mean_reward')) or 'n/a'} / {fmt(neg.get('mean_reward')) or 'n/a'}"


# ---- versions --------------------------------------------------------------------------

def versions_of(j: dict) -> dict:
    return j["summary"].get("versions") or report.run_versions(j["rows"])


def version_rows(jobs: list[dict]) -> list[list]:
    """Versions and run configuration per tool, shared by the Markdown and the HTML."""
    def field(name):
        return lambda j: report.counted(versions_of(j)["fields"].get(name) or {})

    def claude(key):
        def get(j):
            c = versions_of(j).get("claude")
            return report.counted(c.get(key) or {}) if c else ""
        return get

    def dropped(j):
        c = versions_of(j).get("claude")
        if not c:
            return ""
        if c["dropped_unmapped"] is None:
            return "not recorded"
        top = ", ".join(f"{k} x{v}" for k, v in list(c["unmapped_by_category"].items())[:4])
        unknown = f", not recorded for {c['dropped_unknown_trials']} trial(s)" if c["dropped_unknown_trials"] else ""
        return f"{c['dropped_unmapped']}{' (' + top + ')' if top else ''}{unknown}"

    rows = [("Agent version", field("agent_version")), ("CWE map", field("cwe_map")),
            ("Heuristics", field("heuristics")), ("Grader version", field("grader_version"))]
    if any(versions_of(j).get("claude") or versions_of(j)["fields"].get("category_map") for j in jobs):
        def category_map(j):
            v = versions_of(j)
            return field("category_map")(j) if v.get("claude") or v["fields"].get("category_map") else ""

        rows += [("Claude category map", category_map), ("Claude review mode", claude("mode")),
                 ("Claude auth", claude("auth")), ("Claude results label", claude("results_label")),
                 ("Claude findings dropped, category not in the map", dropped),
                 (HARNESS_LABEL, harness_text)]
    return [[label] + [fn(j) for j in jobs] for label, fn in rows]


HARNESS_LABEL = ("Removed or changed before grading (harness and filter effects, not scanner false alarms)")


def harness_text(j: dict) -> str:
    """Per Claude review job: what the harness and the reviewer's false-alarm filter removed or changed
    before grading, from the SARIF run properties or the agent metadata."""
    if not versions_of(j).get("claude"):
        return ""
    effects = j["summary"].get("harness_effects")
    if effects is None:
        effects = report.harness_totals(j["rows"])
    if not effects:
        return "not recorded"
    nonzero = {k: v for k, v in effects.items() if v}
    return ", ".join(f"{k} {v}" for k, v in nonzero.items()) if nonzero else "none"


def version_warnings(jobs: list[dict]) -> list[str]:
    """Mixed versions within a job, and across jobs (the agent version by its release, before the "+")."""
    out = []
    for j in jobs:
        text = report.mixed_versions_warning(versions_of(j), f"the trials of {j['key']}")
        if text:
            out.append(text[0].upper() + text[1:])
    for name in ("agent_version", "cwe_map", "heuristics", "category_map", "grader_version"):
        values: dict = {}
        for j in jobs:
            for v in versions_of(j)["fields"].get(name) or {}:
                v = v.split("+")[0] if name == "agent_version" else v
                values.setdefault(v, []).append(j["key"])
        if len(values) > 1:
            label = "agent release" if name == "agent_version" else report.VERSION_LABELS[name]
            parts = ", ".join(f"{v} ({', '.join(dict.fromkeys(keys))})" for v, keys in values.items())
            out.append(f"Mixed {label} across jobs: {parts}. Results graded under different versions are not "
                       "directly comparable.")
    return out


def task_set_warning(state: dict | None) -> str | None:
    if state and state.get("dirty"):
        return (f"The task set has uncommitted changes ({state['changed_files']} changed file(s) on top of commit "
                f"{state['commit'][:12]}), so the ground truth read now may differ from any recorded state.")
    return None


def stock_mode_note(j: dict) -> str | None:
    text = report.stock_mode_caveat(versions_of(j))
    return f"{j['key']} ran in {text[0].lower() + text[1:]}" if text else None


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
    # One scored positive per task, over every job, for the baselines over the whole run.
    first_pos: dict = {}
    for r in all_rows:
        if r.get("role") == "positive" and r.get("_truth") and report.is_scored(r):
            first_pos.setdefault(r["task"], r)
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
        "fixed_answer_baselines": report.fixed_answer_baselines(list(first_pos.values())),
        "empty_sarif_baseline": report.empty_sarif_baseline(all_rows),
    }


def warnings_of(jobs: list[dict], data: dict, skipped: list[str], task_set: dict | None = None) -> list[str]:
    out = [f"No Harbor trials were found under {name}, so it was left out of the report." for name in skipped]
    out += version_warnings(jobs)
    dirty = task_set_warning(task_set)
    if dirty:
        out.append(dirty)
    if not data["same_task_set"]:
        parts = ", ".join(f"{k} ran {data['tasks_by_tool'][k]}" for k in data["tasks_by_tool"])
        out.append(f"The tools ran on different task sets ({parts}, {data['tasks']} tasks in all). "
                   "Their scores are over different tasks and are not directly comparable.")
    for j in jobs:
        bad = report.not_scored(j["rows"])
        if bad:
            det = j["summary"]["pooled_detection"] or {}
            extra = ""
            n, unknown = det.get("tasks_not_scored", 0), det.get("gt_not_scored_unknown", 0)
            if n and unknown == n:
                extra = (f" Recall leaves out an unknown number of ground-truth findings on {n} of them (their "
                         "ground truth was not found).")
            elif unknown:
                extra = (f" Recall leaves out {det.get('gt_not_scored', 0)} ground-truth findings on {n - unknown} "
                         f"of them, and an unknown number on the other {unknown} (their ground truth was not found).")
            elif n:
                extra = f" Recall leaves out {det.get('gt_not_scored', 0)} ground-truth findings on {n} of them."
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
        if not d:
            return "0"
        extra = ""
        if d.get("tasks_not_scored"):
            unknown = d.get("gt_not_scored_unknown", 0)
            if unknown == d["tasks_not_scored"]:
                extra = f" (+ unknown on {unknown} not scored)"
            elif unknown:
                extra = f" (+{d['gt_not_scored']} not scored, + unknown on {unknown} more)"
            else:
                extra = f" (+{d['gt_not_scored']} not scored)"
        return f"{report.gt_text(d)}{extra}"

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
        row("Negatives with any result in scope (counted or not)",
            lambda j: f"{j['measures']['negatives_any_result']}/{j['measures']['negatives']}"),
        row("Negatives failed on a decoy / next to the fix / anywhere in scope",
            lambda j: f"{role(j, 'negative', 'failed_trap')} / {role(j, 'negative', 'failed_near_fix')} / "
                      f"{role(j, 'negative', 'failed_in_scope') or 0}"),
        row("Mean reward, positives", lambda j: fmt(role(j, "positive", "mean_reward")) or "n/a"),
        row("Mean reward, negatives", lambda j: fmt(role(j, "negative", "mean_reward")) or "n/a"),
        row(STRICT_ROWS[0], lambda j: strict_text(j, "positive", "recall")),
        row(STRICT_ROWS[1], lambda j: strict_text(j, "positive", "mean_reward")),
        row(STRICT_ROWS[2], lambda j: strict_text(j, "negative", "failed")),
        row(STRICT_ROWS[3], lambda j: strict_text(j, "negative", "mean_reward")),
        row(EMPTY_ROW, empty_text),
        row("Path tracing (measurement 2), mean on positives", lambda j: measure_value(j, "path")),
        row("Path tracing (measurement 2), matched findings only", lambda j: matched_value(j, "path")),
        row("Mitigation detection (measurement 3), mean on positives", lambda j: measure_value(j, "controls")),
        row("Mitigation detection (measurement 3), matched findings only", lambda j: matched_value(j, "controls")),
        row(CONTROLS_BASELINE, lambda j: baseline_value(j, "controls")),
        row("Recommendation (measurement 4), mean on positives", lambda j: measure_value(j, "recommendations")),
        row("Recommendation (measurement 4), matched findings only",
            lambda j: matched_value(j, "recommendations")),
        row(recs_baseline_label(jobs), lambda j: baseline_value(j, "recommendations")),
        row("OWASP mean TPR", lambda j: report.macro_text(j["summary"]["categories"]["overall"], "mean_TPR")),
        row("OWASP mean FPR", lambda j: report.macro_text(j["summary"]["categories"]["overall"], "mean_FPR")),
        row("OWASP score (mean TPR minus mean FPR)",
            lambda j: report.macro_text(j["summary"]["categories"]["overall"], "score")),
        row("Results outside scope (not scored)", lambda j: j["summary"]["fp_outside_scope"]),
        row("Mean setup seconds", lambda j: f"{setup(j):.1f}" if setup(j) is not None else "n/a"),
        row("Mean scan seconds", lambda j: f"{scan(j):.1f}" if scan(j) is not None else "n/a"),
    ]


STRICT_ROWS = ("Recall, strict (unfinished trials count as misses)",
               "Mean reward, positives, strict (unfinished trials score 0)",
               "Negatives failed, strict (unfinished trials count as failed)",
               "Mean reward, negatives, strict (unfinished trials score 0)")
EMPTY_ROW = "Empty SARIF baseline, mean reward on positives / negatives (current grader)"
CONTROLS_BASELINE = "Fixed answer baseline: controlStatus none, residualRisk high on every finding (mean on positives)"


def recs_baseline_label(jobs: list[dict]) -> str:
    rec = next((((j["measures"].get("fixed_answer") or {}).get("recommendation_id")) for j in jobs
                if (j["measures"].get("fixed_answer") or {}).get("recommendation_id")), None)
    return (f"Fixed answer baseline: recommendations [{rec or 'none found'}] on every finding (mean on positives)")


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
        ["Path score, matched findings only"] + [matched_value(j, "path") for j in jobs],
        ["Matched detections with a code flow"] + [f"{j['measures']['hits_with_flow']}/{j['measures']['hits']}" for j in jobs],
        ["Control and residual-risk score, mean on positives (measurement 3)"] + [measure_value(j, "controls") for j in jobs],
        ["Control and residual-risk score, matched findings only"] + [matched_value(j, "controls") for j in jobs],
        [CONTROLS_BASELINE] + [baseline_value(j, "controls") for j in jobs],
        ["Fixed answer none/high, mean per finding (compare with matched findings only)"] +
        [baseline_value(j, "controls", "per_finding") for j in jobs],
        ["Negatives clean (measurement 3, other side)"] +
        [f"{j['measures']['negatives_clean']}/{j['measures']['negatives']}" for j in jobs],
        ["Negatives with any result in scope (counted or not)"] +
        [f"{j['measures']['negatives_any_result']}/{j['measures']['negatives']}" for j in jobs],
        ["Recommendation score, mean on positives (measurement 4)"] + [measure_value(j, "recommendations") for j in jobs],
        ["Recommendation score, matched findings only"] + [matched_value(j, "recommendations") for j in jobs],
        [recs_baseline_label(jobs)] + [baseline_value(j, "recommendations") for j in jobs],
        ["Fixed recommendation, mean per finding (compare with matched findings only)"] +
        [baseline_value(j, "recommendations", "per_finding") for j in jobs],
        ["Matched findings credited across risk families through the CWE (cross_family)"] +
        [str(j["measures"].get("cross_family", 0)) for j in jobs],
        ["Results claiming a complete control (complete_claims, neither failed nor counted as FP)"] +
        [str(j["measures"].get("complete_claims", 0)) for j in jobs],
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
            cannot = c in (j["summary"]["categories"]["overall"].get("cannot_emit") or [])
            text = "" if not v else (
                f"n {count_of(v['positives'], 'positive')}, {count_of(v['negatives'], 'negative')}: "
                f"TPR {fmt(v['TPR']) or 'n/a'} ({v['TP']} of {v['positives']}), "
                f"FPR {fmt(v['FPR']) or 'n/a'} ({v['FP']} of {v['negatives']}), "
                f"score {fmt(v['youden']) or 'n/a'}")
            if cannot:
                text = (text + ". " if text else "") + CANNOT_EMIT
            line.append(text)
        out.append(line)
    out.append(["Mean score over the categories it can emit"] +
               [report.macro_text(j["summary"]["categories"]["overall"], "score") for j in jobs])
    return out


CANNOT_EMIT = "Cannot emit this category (ruleIds from the CWE map), left out of its mean"


def count_of(n: int, noun: str) -> str:
    return f"{n} {noun}{'' if n == 1 else 's'}"


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
    names = {}
    for j in jobs:
        for r in j["rows"]:
            if r.get("family_name") and r["family_name"] != r["family"]:
                names.setdefault(r["task"], r["family_name"])
    order = sorted(tasks, key=lambda k: (str(tasks[k]["family"]), ROLE_ORDER.get(tasks[k]["role"], 2), k))
    return [[tasks[k]["family"] + (f" ({names[k]})" if names.get(k) else ""), k, tasks[k]["role"]] +
            [c.get(k, "not run") for c in cells] for k in order]


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
        stock = stock_mode_note(j)
        if stock:
            notes.append({"tool": j["key"], "text": stock})
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
            if neg.get("failed_in_scope"):
                parts.append(f"{neg['failed_in_scope']} anywhere in scope")
            notes.append({"tool": j["key"], "text": f"{j['key']} failed {neg['failed']} of {neg['tasks']} "
                          f"negatives ({' and '.join(parts)}), so it flags safe code as vulnerable there."})
        overall = s["categories"]["overall"]
        if overall.get("excluded_cannot_emit"):
            notes.append({"tool": j["key"], "text": f"{j['key']} takes its ruleIds from the CWE map, which no CWE "
                          f"maps to {', '.join(overall['excluded_cannot_emit'])}. That category is shown in its "
                          "row but left out of the tool's OWASP mean."})
        strict = s.get("strict") or {}
        if strict.get("differs"):
            sp, sn = strict["positive"], strict["negative"]
            reasons = Counter()
            for role in report.ROLES:
                reasons.update(strict[role].get("reasons") or {})
            notes.append({"tool": j["key"], "text": f"{j['key']}: {sp['unfinished'] + sn['unfinished']} trial(s) "
                          f"ended without a scored answer ({', '.join(f'{k} x{v}' for k, v in reasons.items())}). "
                          f"The strict view counts them as misses and failures: recall "
                          f"{fmt(sp.get('recall')) or 'n/a'} ({sp.get('tp', 0)}/{sp.get('gt', 0)}), negatives "
                          f"failed {sn.get('failed', 0)}/{sn['tasks']}."})
        effects = j["summary"].get("harness_effects") or {}
        if versions_of(j).get("claude") and any(effects.values()):
            notes.append({"tool": j["key"], "text": f"{j['key']}: before grading, the harness and the reviewer's "
                          "false-alarm filter removed or changed findings ("
                          + ", ".join(f"{k} {v}" for k, v in effects.items() if v) +
                          "). These are harness and filter effects, not scanner false alarms, and some of them "
                          "may have been correct findings."})
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
    if any(j["summary"]["categories"]["overall"].get("too_few_tasks") for j in jobs):
        notes.append({"tool": None, "text": f"The OWASP category means are shown as \"{report.TOO_FEW}\": a mean "
                      f"is only given when every category in it has at least {report.MIN_CATEGORY_TASKS} positives "
                      f"and {report.MIN_CATEGORY_TASKS} negatives. The per-category rows still give n."})
    tps = [(j["summary"]["pooled_detection"] or {}).get("tp") or 0 for j in jobs]
    if jobs and max(tps) == 0:
        notes.append({"tool": None, "text": "No tool detected any ground-truth finding. The OWASP scores are "
                      "therefore driven only by false alarms on negatives, and 0 is also what reporting "
                      "nothing earns."})
    return notes


# ---- plain-English summary ---------------------------------------------------------------
# The first part of the report, for readers who are not security-tool specialists. Every figure
# comes from the same per-tool numbers as the scoreboard, and the payload's "summary" block holds
# the text, so the Markdown and the HTML say the same thing. No scanner-testing terms are used here.

TOOL_KINDS = {
    "semgrep": ("Semgrep", "a pattern-matching code scanner"),
    "codeql": ("CodeQL", "a code-analysis scanner from GitHub"),
    "sonarqube": ("SonarQube", "a code-quality and security scanner"),
    "claude-code-security-review": ("Claude", "an AI reviewer"),
}
NOT_PROVIDED = "not provided by this tool"
FREE_TEXT = "given as free text, not scorable"
NOTHING_TO_JUDGE = "nothing to judge"
FREE_TEXT_NOUNS = {"path": "how each issue is reached", "controls": "the existing protections",
                   "recommendations": "its suggested fixes"}
STOCK_HOW = ("It read the app's code, including the app's security description, and ran in stock mode, with the "
             "reviewer's own instructions and answer format.")
SCOPED_HOW = ("It read the app's code, including the app's security description, and ran in scoped mode: on top "
              "of that it was given the client's risk definitions and told the answer format our checker scores "
              "(risk type, how the issue is reached, existing protections, and a fix chosen from a fixed list). "
              "So its scores for paths, protections and fixes are not like-for-like with tools that were not "
              "told that format.")
SUMMARY_MEASURES = [
    ("path", "Described how the issue is reached", "paths", "describing how the issue is reached"),
    ("controls", "Judged existing protections", "protections", "judging existing protections"),
    ("recommendations", "Suggested fixes", "fixes", "suggesting fixes"),
]
RISK_PREFIX = {"disclosure": "LLM02", "agency": "LLM03"}
DETAILS_INTRO = ("The sections below are the full technical results, for people checking the numbers. They use "
                 "the scanner-testing terms the summary above avoids, and the method section explains them.")


def whole_percent(value: float) -> int:
    """0.204 -> 20, rounding halves up (Python's round() rounds them to even)."""
    return math.floor(value * 100 + 0.5)


def joined(items: list[str], word: str = "and") -> str:
    return items[0] if len(items) == 1 else ", ".join(items[:-1]) + f" {word} " + items[-1]


def model_name(model: str) -> str:
    """claude-opus-5-5 -> Opus 5.5. A date suffix (claude-sonnet-4-5-20250929) is left out."""
    parts = [p for p in str(model).split("-") if p and not (p.isdigit() and len(p) >= 6)]
    if parts and parts[0].lower() == "claude":
        parts = parts[1:]
    words = [p for p in parts if not p.isdigit()]
    digits = [p for p in parts if p.isdigit()]
    name = " ".join(w.capitalize() for w in words)
    return f"{name} {'.'.join(digits)}".strip() if digits else (name or str(model))


def tool_identity(j: dict) -> dict:
    """Short name, kind and the "What was tested" sentence, from the agent metadata and versions."""
    name, kind = TOOL_KINDS.get(j["tool"], (j["key"], "a security scanner"))
    claude = versions_of(j).get("claude")
    if j["tool"] == "claude-code-security-review" or claude:
        models = list(((claude or {}).get("model") or {}) or j.get("models") or {})
        pretty = ", ".join(model_name(m) for m in models)
        modes = set((claude or {}).get("mode") or {})
        if j["tool"] in TOOL_KINDS:
            # The mode is part of the name, so stock and scoped runs of one model stay apart.
            label = ", ".join(x for x in (pretty, " and ".join(sorted(modes))) if x)
            name = f"Claude ({label})" if label else "Claude"
        if modes == {"stock"}:
            how = STOCK_HOW
        elif modes == {"scoped"}:
            how = SCOPED_HOW
        elif modes:
            how = ("Some of its runs were in stock mode, with the reviewer's own instructions, and some in scoped "
                   "mode, which adds the client's risk definitions and the answer format our checker scores.")
        else:
            how = "Whether it ran in stock or scoped mode was not recorded."
        model_text = f", using the {pretty} model" if pretty else ""
        return {"name": name, "kind": kind,
                "tested": f"{name}: Claude Code security review, {kind}{model_text}. {how}"}
    return {"name": name, "kind": kind, "tested": f"{name}: {kind}."}


def free_text_measures(j: dict) -> set:
    """The measurements a tool answered only in free text the checker cannot score: from the free-text
    fields of its results, and always path and fixes for a stock-mode Claude review (it writes an
    exploit scenario and a recommendation as prose)."""
    out = {key for key, n in (j.get("free_text") or {}).items() if n}
    claude = versions_of(j).get("claude") or {}
    if j["tool"] == "claude-code-security-review" and set(claude.get("mode") or {}) == {"stock"}:
        out |= set(FREE_TEXT_FIELDS.values())
    return out


def summary_measure(j: dict, key: str) -> dict:
    """One of the three measurement cells: a whole percent, free text only, not provided, or nothing
    to judge."""
    m = j["measures"]
    if m["supported"].get(key) is False:
        if key in free_text_measures(j):
            return {"status": "free_text", "text": FREE_TEXT, "value": None}
        return {"status": "not_provided", "text": NOT_PROVIDED, "value": None}
    if key in (m.get("no_results") or []):
        return {"status": "nothing_to_judge", "text": NOTHING_TO_JUDGE, "value": None}
    value = m.get(key)
    if value is None:
        return {"status": "not_available", "text": "not available", "value": None}
    return {"status": "scored", "text": f"{whole_percent(value)}%", "value": value}


def risk_issues(j: dict) -> dict:
    """Known issues found per risk type, over the scored vulnerable apps. A total is None when an
    app's known issues could not be read."""
    out = {}
    positives = report.by_role(j["rows"], "positive")
    for risk, prefix in RISK_PREFIX.items():
        # The grader only matches a result to an issue of the same risk family, so the result's
        # rule prefix gives the issue's risk type.
        found = sum(1 for h in j["hits"] if str(h.get("rule") or "").startswith(prefix))
        if any(r.get("gt_rules") is None for r in positives):
            total = None
        else:
            total = sum(1 for r in positives for rule in r["gt_rules"] if str(rule).startswith(prefix))
        out[risk] = {"found": found, "total": total}
    return out


def of_text(found, total) -> str:
    return f"{found} of {total}" if total is not None else f"{found} (total not known)"


def tool_meaning(t: dict, j: dict) -> list[str]:
    """One or two plain sentences on a tool, then its caveats."""
    name = t["name"]
    first = f"{name} found {of_text(t['found'], t['total'])} known issues"
    alarms = t["false_alarms"]
    parts = [f"raised {alarms} false alarm{'' if alarms == 1 else 's'} on the vulnerable apps"] if alarms else []
    if t["fixed_apps"]:
        parts.append(f"wrongly flagged {t['fixed_flagged']} of {t['fixed_apps']} fixed apps" if t["fixed_flagged"]
                     else "raised no alarm on the fixed apps")
    out = [joined([first] + parts) + "."]
    by_status: dict = {}
    for key, _, noun, verb in SUMMARY_MEASURES:
        by_status.setdefault(t[key]["status"], []).append((key, noun, verb))
    if by_status.get("nothing_to_judge"):
        nouns = [n for _, n, _ in by_status["nothing_to_judge"]]
        out.append(f"Because it found no known issue, there was nothing to judge for {joined(nouns, 'or')}.")
    if by_status.get("scored"):
        out.append("It scored " + joined([f"{t[k]['text']} on {v}" for k, _, v in by_status["scored"]]) + ".")
    if by_status.get("free_text"):
        nouns = [FREE_TEXT_NOUNS[k] for k, _, _ in by_status["free_text"]]
        out.append(f"It wrote {joined(nouns)} as free text, which our checker cannot score.")
    if by_status.get("not_provided"):
        nouns = [n for _, n, _ in by_status["not_provided"]]
        out.append(f"It did not describe {joined(nouns, 'or')} in a form that can be scored.")
    wrong = t.get("wrong_type") or 0
    if wrong:
        out.append(f"It pointed at {wrong} more known issue{'' if wrong == 1 else 's'} but under the wrong risk "
                   f"type, so {'it was' if wrong == 1 else 'they were'} not counted.")
    if j["no_results"]:
        out.append(f"{name} reported nothing, so its clean results on fixed apps say nothing about it.")
    claude = versions_of(j).get("claude")
    if claude and "stock" in (claude.get("mode") or {}):
        dropped = claude.get("dropped_unmapped")
        n = ("The number dropped was not recorded." if dropped is None
             else "None were dropped here." if dropped == 0
             else f"{dropped} finding{' was' if dropped == 1 else 's were'} dropped here.")
        out.append("In stock mode some of the AI reviewer's findings can be dropped because their category names "
                   f"are not in our fixed list. {n}")
    if filter_off(claude):
        out.append(f"{name} was run on a subscription token, without the extra AI check that normally removes "
                   "false alarms.")
    for key, verb, answer in (("controls", "judging existing protections", "a fixed answer"),
                              ("recommendations", "suggesting fixes", "always suggesting the same fix")):
        base = ((j["measures"].get("fixed_answer") or {}).get(key) or {}).get("per_app")
        if t[key]["status"] == "scored" and base is not None and abs(t[key]["value"] - base) <= CLOSE + 1e-9:
            out.append(f"Its {t[key]['text']} on {verb} is within 5 points of the {whole_percent(base)}% that "
                       f"{answer} gets on the same apps, so that score shows little real skill.")
    effects = dict(j["summary"].get("harness_effects") or {})
    if claude and "stock" in (claude.get("mode") or {}):
        # Already said above, in the sentence on the category list.
        effects.pop(report.HARNESS_FIELDS[1][1], None)
    removed = sum(v for v in effects.values() if isinstance(v, int))
    if claude and removed:
        out.append(f"Before our checker saw its answers, {removed} of its findings "
                   f"{'was' if removed == 1 else 'were'} removed or changed by the reviewer's own false-alarm "
                   f"filter or by our test setup. {'It is' if removed == 1 else 'They are'} not counted as its false alarms.")
    return out


CLOSE = 0.05  # "within 5 points" of a fixed-answer score


def filter_off(claude: dict | None) -> bool:
    """A Claude review run without the reviewer's second AI check (subscription-token runs)."""
    if not claude:
        return False
    filters = set(claude.get("filter_mode") or {})
    return bool((filters and "claude" not in filters) or (not filters and "oauth" in (claude.get("auth") or {})))


#: Plain names of the issue kinds, by risk family: (group words, qualifier).
CATEGORY_WORDS = {
    "LLM02.SID.HIGH": ("disclosure", "high"), "LLM02.SID.MEDIUM": ("disclosure", "medium"),
    "LLM03.EA.FUNCTIONALITY": ("agency", "extra-feature"), "LLM03.EA.PERMISSIONS": ("agency", "permission"),
    "LLM03.EA.AUTONOMY": ("agency", "approval"),
}
FEW_RESULTS = 2  # a tool that wrote this many results or fewer in all "reported almost nothing"


def category_phrase(rules: list[str]) -> str:
    """["LLM03.EA.PERMISSIONS", "LLM03.EA.AUTONOMY"] -> "Excessive-agency permission and approval issues"."""
    groups: dict = {}
    for rule in rules:
        group, qual = CATEGORY_WORDS.get(rule, ("other", rule))
        groups.setdefault(group, []).append(qual)
    parts = []
    if groups.get("disclosure"):
        parts.append(f"data disclosure issues of {joined(groups['disclosure'])} severity")
    if groups.get("agency"):
        parts.append(f"excessive-agency {joined(groups['agency'])} issues")
    if groups.get("other"):
        parts.append(f"{joined(groups['other'])} issues")
    text = joined(parts)
    return text[0].upper() + text[1:]


def read_first(jobs: list[dict], data: dict, tools: list[dict]) -> list[str]:
    """The main caveats, right under the first line of the summary. Only the ones that apply."""
    out = []
    counts = sorted({n for j in jobs for n in Counter(r["task"] for r in j["rows"]).values()})
    if counts == [1]:
        out.append("Each tool ran once per app, so differences of one or two issues between tools are not "
                   "meaningful.")
    elif len(counts) == 1:
        out.append(f"Each tool ran {counts[0]} times per app, and the counts add up all its runs. Differences of "
                   "one or two issues between tools are still not meaningful.")
    elif counts:
        out.append(f"The tools ran between {counts[0]} and {counts[-1]} times per app, and the counts add up all "
                   "their runs. Differences of one or two issues between tools are not meaningful.")
    claude_tools = [(j, t) for j, t in zip(jobs, tools) if versions_of(j).get("claude")]
    off = [t["name"] for j, t in claude_tools if filter_off(versions_of(j)["claude"])]
    if off:
        if len(off) == len(claude_tools) and len(off) > 1:
            out.append("Every AI reviewer run used a subscription token, so the reviewer's second AI check that "
                       "removes false alarms was off, and the AI reviewer may show more false alarms than usual.")
        else:
            out.append(f"{joined(off)} {'was' if len(off) == 1 else 'were'} run on a subscription token, so the "
                       "reviewer's second AI check that removes false alarms was off, and it may show more false "
                       "alarms than usual.")
    if any("scoped" in (versions_of(j)["claude"].get("mode") or {}) for j, _ in claude_tools):
        out.append("In scoped mode the AI reviewer was told the answer format our checker scores, so its scores "
                   "for paths, protections and fixes are not like-for-like with the other tools. Its filter that "
                   "removes false alarms is also slightly looser in scoped mode, because two of the usual "
                   "exclusion rules are switched off.")
    fixed = fixed_answer_caveat(data, tools)
    if fixed:
        out.append(fixed)
    cov = data.get("taxonomy_coverage") or {}
    if cov.get("known"):
        by_rule = cov.get("findings_by_rule") or {}
        known = [r for r in report.TAXONOMY]
        missing = [r for r in known if not by_rule.get(r)]
        single = [r for r in known if by_rule.get(r) == 1]
        parts = []
        if missing:
            parts.append(f"{category_phrase(missing)} are not in this set, so no tool is tested on them.")
        if single:
            parts.append(f"{category_phrase(single)} have only one example"
                         f"{' each' if len(single) > 1 else ''}, so one hit or miss swings the result.")
        if parts:
            out.append(" ".join(parts))
    quiet = [(t["name"], j.get("results_written", 0)) for j, t in zip(jobs, tools)
             if j.get("results_written", 0) <= FEW_RESULTS]
    if quiet:
        wrote = joined([f"{name} wrote {'no results' if n == 0 else f'{n} result' + ('' if n == 1 else 's')}"
                        for name, n in quiet])
        one = len(quiet) == 1
        out.append(f"{joined([name for name, _ in quiet])} reported almost nothing ({wrote} across all apps), so "
                   f"{'its' if one else 'their'} few false alarms say little about {'it' if one else 'them'}.")
    return out


def fixed_answer_caveat(data: dict, tools: list[dict]) -> str | None:
    """What a fixed answer scores on judging protections and suggesting fixes, over all the vulnerable
    apps, when some tool was scored on that measurement."""
    base = data.get("fixed_answer_baselines") or {}
    parts = []
    ctrl = (base.get("controls") or {}).get("per_app")
    if ctrl is not None and any(t["controls"]["status"] == "scored" for t in tools):
        parts.append(f"Answering \"no protection, high risk\" for every known issue, without reading the code, "
                     f"would score {whole_percent(ctrl)}% on judging existing protections.")
    recs = (base.get("recommendations") or {}).get("per_app")
    if recs is not None and any(t["recommendations"]["status"] == "scored" for t in tools):
        parts.append(f"Suggesting the same fix for every known issue, the most common one on our list, would "
                     f"score {whole_percent(recs)}% on suggesting fixes.")
    if not parts:
        return None
    return ("A fixed answer already scores well on part of this. " + " ".join(parts) +
            " Read the tools' scores there against these figures.")


def strict_lines(jobs: list[dict], tools: list[dict]) -> list[str]:
    """One plain line per tool whose numbers change when unfinished runs count as misses."""
    out = []
    for j, t in zip(jobs, tools):
        strict = j["summary"].get("strict") or {}
        if not strict.get("differs"):
            continue
        sp, sn = strict["positive"], strict["negative"]
        k = sp["unfinished"] + sn["unfinished"]
        parts = []
        if sp["unfinished"]:
            parts.append(f"found {sp.get('tp', 0)} of {sp.get('gt', 0)} known issues (not {t['found']} of "
                         f"{t['total']})")
        if sn["unfinished"]:
            parts.append(f"wrongly flagged {sn.get('failed', 0)} of {sn['tasks']} fixed apps (not "
                         f"{t['fixed_flagged']} of {t['fixed_apps']})")
        out.append(f"{t['name']}: {k} of its runs did not finish or gave no answer, and the numbers above leave "
                   f"{'it' if k == 1 else 'them'} out. Counting {'it as a miss' if k == 1 else 'them as misses'}, "
                   f"it " + joined(parts) + ".")
    return out


def empty_report_line(data: dict) -> str | None:
    e = data.get("empty_sarif_baseline") or {}
    pos, neg = (e.get("positive") or {}).get("mean_reward"), (e.get("negative") or {}).get("mean_reward")
    if pos is None and neg is None:
        return None
    parts = []
    if pos is not None:
        parts.append(f"{whole_percent(pos)} on the vulnerable apps")
    if neg is not None:
        parts.append(f"{whole_percent(neg)} on the fixed apps")
    return ("A tool that warned about nothing at all would get an average score of " + joined(parts) +
            " from our checker, so a perfect score on the fixed apps alone says nothing.")


def summary_notes(jobs: list[dict], data: dict, tools: list[dict] | None = None) -> list[str]:
    """Caveats that apply to the whole comparison, after the tools. The main ones are in read_first."""
    notes = []
    if version_warnings(jobs):
        notes.append("The tools were run under different versions of our test setup, so compare them with care.")
    if not data["same_task_set"]:
        notes.append("The tools were not all run on the same apps, so their numbers are not directly comparable.")
    unfinished = sum(len(report.not_scored(j["rows"])) for j in jobs)
    if unfinished:
        notes.append(f"{unfinished} run{' did' if unfinished == 1 else 's did'} not finish cleanly and "
                     f"{'is' if unfinished == 1 else 'are'} left out of the numbers.")
    notes += strict_lines(jobs, tools or [])
    empty = empty_report_line(data)
    if empty:
        notes.append(empty)
    return notes


def coverage_line(data: dict, full: dict | None) -> str:
    """How many apps of the whole set were run, e.g. "10 of 30 apps (5 of 15 app families) were run"."""
    apps, fams = data["positives"] + data["negatives"], data["families"]

    def plural(n, one, many):
        return f"{n} {one if n == 1 else many}"
    if not full:
        return f"{plural(apps, 'app', 'apps')} ({plural(fams, 'app family', 'app families')}) were run"
    total, total_fams = full["tasks"], full.get("families")
    if apps >= total and (total_fams is None or fams >= total_fams):
        fam_text = f" ({plural(total_fams if total_fams is not None else fams, 'app family', 'app families')})"
        return f"All {plural(total, 'app', 'apps')}{fam_text} in the set were run"
    fam_text = f" ({fams} of {plural(total_fams, 'app family', 'app families')})" if total_fams is not None else ""
    return f"{apps} of {plural(total, 'app', 'apps')}{fam_text} were run"


def task_set_size(tasks_dir: Path | None, variants_file: Path | None = None) -> dict | None:
    """full_task_set with the variant map read from --variants or <tasks>/VARIANTS.json."""
    if tasks_dir is None:
        return None
    return full_task_set(tasks_dir, report.load_variants(report.default_variants(tasks_dir, variants_file)))


FIXED_ANY = "Fixed apps with any warning in the checked code"


def build_summary(jobs: list[dict], data: dict, generated: datetime | None = None,
                  full: dict | None = None) -> dict:
    """The plain-English summary: the numbers and the sentences, shared by the Markdown and the HTML.
    ``full`` is the whole task set's size (full_task_set), for the coverage line."""
    generated = generated or datetime.now(timezone.utc)
    tools = []
    names = Counter(tool_identity(j)["name"] for j in jobs)
    for j in jobs:
        ident = tool_identity(j)
        if names[ident["name"]] > 1:  # two jobs of one tool: the key tells them apart
            ident["name"] = j["key"]
            ident["tested"] = f"{j['key']}: {ident['tested'].split(': ', 1)[1]}"
        det = j["summary"]["pooled_detection"] or {}
        clean, fixed = j["summary"]["zero_finding_tasks_clean"]
        reward = j["summary"]["reward_by_role"]["positive"].get("mean_reward")
        t = {"key": j["key"], "name": ident["name"], "kind": ident["kind"], "tested": ident["tested"],
             "found": det.get("tp") or 0, "total": det.get("gt") or 0, "false_alarms": det.get("fp") or 0,
             "fixed_flagged": fixed - clean, "fixed_apps": fixed,
             "fixed_any": j["summary"]["reward_by_role"]["negative"].get("any_result", 0),
             "score": whole_percent(reward) if reward is not None else None,
             "no_results": j["no_results"], "risks": risk_issues(j),
             "wrong_type": j.get("wrong_type_findings") or 0}
        for key, *_ in SUMMARY_MEASURES:
            t[key] = summary_measure(j, key)
        t["meaning"] = tool_meaning(t, j)
        tools.append(t)
    columns = [""] + [t["name"] for t in tools]
    glance = [
        ["Known issues found"] + [of_text(t["found"], t["total"]) for t in tools],
        ["False alarms on the vulnerable apps"] + [str(t["false_alarms"]) for t in tools],
        ["Fixed apps wrongly flagged"] + [f"{t['fixed_flagged']} of {t['fixed_apps']}" for t in tools],
        [FIXED_ANY] + [f"{t['fixed_any']} of {t['fixed_apps']}" for t in tools],
        ["Average score on vulnerable apps (0–100)"] +
        [str(t["score"]) if t["score"] is not None else "not available" for t in tools],
    ] + [[label] + [t[key]["text"] for t in tools] for key, label, *_ in SUMMARY_MEASURES]
    by_risk = [
        ["Data disclosure issues found"] + [of_text(**t["risks"]["disclosure"]) for t in tools],
        ["Excessive agency issues found"] + [of_text(**t["risks"]["agency"]) for t in tools],
    ]
    glossary = [
        {"term": "Vulnerable app", "text": "One of the small AI-agent apps we built with security problems left in "
         "on purpose."},
        {"term": "Fixed app", "text": "A copy of a vulnerable app with those problems fixed. A good tool reports "
         "it as clean."},
        {"term": "Known issue", "text": "A security problem we put in a vulnerable app and wrote down, with where "
         "it is and how it should be fixed. The tools never see this list."},
        {"term": "False alarm", "text": "A warning near the code we check that is not one of the known issues. On "
         "a fixed app, a warning about the fixed code, or about safe code made to look risky, counts as one. With "
         "the newest checker, so does a warning of the fixed risk type anywhere in the checked code. Other "
         "warnings in a fixed app are not counted, but the row on fixed apps with any warning shows them."},
        {"term": "Data disclosure", "text": "Private or sensitive data reaching someone who is not allowed to see "
         "it."},
        {"term": "Excessive agency", "text": "The AI agent can do more than its job needs: extra tool features, "
         "permissions that are too broad, or high-impact actions taken without a person approving them."},
        {"term": "Score (0–100)", "text": "The grade our checker gives a tool on each vulnerable app, for finding "
         "its known issues and describing them correctly, averaged over the vulnerable apps. 100 is perfect."},
    ]
    if any(versions_of(j).get("claude") for j in jobs):
        glossary.append({"term": "Stock and scoped mode", "text": "In both modes the AI reviewer reads the app's "
                         "code, including the app's security description. Stock mode uses the reviewer's own "
                         "instructions and answer format. Scoped mode adds extra instructions: the client's "
                         "definitions of each risk, and the answer format our checker scores (risk type, how the "
                         "issue is reached, existing protections, and a fix chosen from a fixed list)."})
    first = read_first(jobs, data, tools)
    if any("fixed answer" in line for line in first) or any(
            "fixed answer" in line or "the same fix" in line for t in tools for line in t["meaning"]):
        glossary.append({"term": "Fixed answer", "text": "The same answer given for every known issue without "
                         "reading the code. Its score shows how much of a tool's score could come from that."})
    if any(t[key]["status"] == "free_text" for t in tools for key, *_ in SUMMARY_MEASURES):
        glossary.append({"term": "Free text, not scorable", "text": "The tool wrote this in its own words. Our "
                         "checker only scores answers in a fixed format, so it cannot give these a score, even "
                         "when they are good."})
    apps = data["positives"] + data["negatives"]
    return {
        "title": "Scanner evaluation: summary",
        "date": generated.strftime("%Y-%m-%d"),
        "intro": f"{generated.day} {generated.strftime('%B %Y')}. {coverage_line(data, full)}: "
                 f"{data['positives']} vulnerable, "
                 f"{data['negatives']} fixed cop{'y' if data['negatives'] == 1 else 'ies'}, "
                 f"with {data['gt_findings']} known issue{'' if data['gt_findings'] == 1 else 's'} in the "
                 "vulnerable apps.",
        "coverage": {"apps_run": apps, "families_run": data["families"],
                     "apps_total": (full or {}).get("tasks"), "families_total": (full or {}).get("families")},
        "read_first": first,
        "apps": apps, "vulnerable_apps": data["positives"], "fixed_apps": data["negatives"],
        "known_issues": data["gt_findings"],
        "tools": tools,
        "at_a_glance": {"columns": columns, "rows": glance},
        "by_risk": {"columns": columns, "rows": by_risk},
        "charts_intro": CHARTS_INTRO,
        "charts": summary_charts(tools),
        "notes": summary_notes(jobs, data, tools),
        "glossary": glossary,
        "labels": {"not_provided": NOT_PROVIDED, "free_text": FREE_TEXT, "nothing_to_judge": NOTHING_TO_JUDGE},
        "details_title": "Details for reviewers",
        "details_intro": DETAILS_INTRO,
    }


def summary_markdown(summary: dict) -> list[str]:
    t = report.md_table
    out = [f"# {summary['title']}", "", summary["intro"], ""]
    if summary.get("read_first"):
        out += ["## Read this first", ""] + [f"- {r}" for r in summary["read_first"]] + [""]
    out += ["## What was tested", ""]
    out += [f"- {tool['tested']}" for tool in summary["tools"]]
    out += ["", "## Results at a glance"]
    out += t(summary["at_a_glance"]["columns"], summary["at_a_glance"]["rows"])
    out += ["", "## Results by risk type"]
    out += t(summary["by_risk"]["columns"], summary["by_risk"]["rows"])
    if summary.get("charts"):
        out += ["", "## Measurements at a glance", "", summary["charts_intro"]]
        for c in summary["charts"]:
            out += ["", f"![{c['title']}]({c['file']})", "", c["caption"]]
    out += ["", "## What this means", ""]
    out += [f"- {' '.join(tool['meaning'])}" for tool in summary["tools"]]
    out += [f"- {n}" for n in summary["notes"]]
    out += ["", "## Words used in this report", ""]
    out += [f"- **{g['term']}**: {g['text']}" for g in summary["glossary"]]
    return out


# ---- measurement charts ----------------------------------------------------------------
# One horizontal bar per tool on a 0 to 100% axis, in one colour: the row label says which tool
# it is. A value that cannot be drawn (not provided, nothing to judge, no total) is written in
# the tool's row instead of a bar, so it never reads as a zero. The specs live in the summary
# block, so the HTML draws the same charts as the SVG files the Markdown links to.

CHARTS_INTRO = ("The four measurements as bars, one per tool, from the tables above. A tool with no bar has its "
                "reason written in its row instead.")
PER_APP = ("averaged over the vulnerable apps. An app's score counts each of its known issues, and a missed issue "
           "counts as zero.")
CHART_TEXT = {
    "issues": ("Measurement 1: risk detection", "Known issues found, by risk type",
               "How many of the known issues each tool found, for each risk type. Longer bars are better."),
    "flagged": ("Measurement 1: risk detection", "Fixed apps wrongly flagged",
                "How many fixed apps each tool still warned about. A separate job from finding issues, and "
                "shorter bars are better here."),
    "path": ("Measurement 2: path tracing", "Described how the issue is reached",
             "How well each tool described how each known issue is reached, " + PER_APP + " Longer bars are better."),
    "controls": ("Measurement 3: mitigation detection", "Judged existing protections",
                 "How well each tool judged the protections already in the code, " + PER_APP +
                 " Longer bars are better."),
    "recommendations": ("Measurement 4: recommendation", "Suggested fixes",
                        "How well each tool suggested a fix for each known issue, " + PER_APP +
                        " Longer bars are better."),
}
CHART_FILES = {"issues": "m1-issues-found", "flagged": "m1-fixed-flagged", "path": "m2-path",
               "controls": "m3-protections", "recommendations": "m4-fixes"}


def count_row(t: dict, found: int, total, empty: str) -> dict:
    """A bar for found of total, or the reason there is none."""
    row = {"key": t["key"], "tool": t["name"]}
    if total is None:
        return row | {"state": "not_known", "value": None, "text": f"{found} found, total not known"}
    if not total:
        return row | {"state": "none", "value": None, "text": empty}
    return row | {"state": "scored", "value": found / total,
                  "text": f"{found} of {total} ({whole_percent(found / total)}%)"}


def measure_row(t: dict, key: str) -> dict:
    cell = t[key]
    return {"key": t["key"], "tool": t["name"], "state": cell["status"],
            "value": cell["value"] if cell["status"] == "scored" else None, "text": cell["text"]}


def summary_charts(tools: list[dict]) -> list[dict]:
    """The five charts of "Measurements at a glance": two for measurement 1, one each for 2 to 4."""
    facets = {
        "issues": [{"title": "Data disclosure", "rows": [
                       count_row(t, **t["risks"]["disclosure"], empty="no known issues of this type") for t in tools]},
                   {"title": "Excessive agency", "rows": [
                       count_row(t, **t["risks"]["agency"], empty="no known issues of this type") for t in tools]}],
        "flagged": [{"title": None, "rows": [
            count_row(t, t["fixed_flagged"], t["fixed_apps"], "no fixed apps tested") for t in tools]}],
    }
    for key, *_ in SUMMARY_MEASURES:
        facets[key] = [{"title": None, "rows": [measure_row(t, key) for t in tools]}]
    out = []
    for key, (measurement, title, caption) in CHART_TEXT.items():
        out.append({"id": CHART_FILES[key], "group": measurement, "title": title, "caption": caption,
                    "file": f"charts/{CHART_FILES[key]}.svg", "facets": facets[key]})
    return out


# Colours: the page's chart tokens (tools/eval_report.html), checked with the data-viz palette
# validator. One bar hue, stepped separately for the dark surface.
SVG_COLORS = {
    "light": {"bg": "#fcfcfb", "ink": "#0b0b0b", "ink2": "#52514e", "muted": "#6f6d68", "grid": "#e1e0d9",
              "axis": "#c3c2b7", "bar": "#2a78d6"},
    "dark": {"bg": "#1a1a19", "ink": "#ffffff", "ink2": "#c3c2b7", "muted": "#9a988f", "grid": "#2c2c2a",
             "axis": "#383835", "bar": "#3987e5"},
}
SVG_FONT = "system-ui, -apple-system, 'Segoe UI', sans-serif"
SVG_W, SVG_PAD, SVG_LABEL_MAX, SVG_LINE = 680, 16, 210, 14


def text_px(text: str, size: float = 12) -> float:
    """A generous estimate of the rendered width, so labels get room without measuring."""
    return len(text) * size * 0.58


def wrap_label(text: str, width: float) -> list[str]:
    lines, cur = [], ""
    for word in text.split(" "):
        nxt = f"{cur} {word}".strip()
        if cur and text_px(nxt) > width:
            lines.append(cur)
            cur = word
        else:
            cur = nxt
    return lines + [cur]


def xml_text(text) -> str:
    return str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def n(v: float) -> str:
    """A coordinate with at most one decimal, the same on every run."""
    s = f"{v:.1f}"
    return s[:-2] if s.endswith(".0") else s


def bar_path(x0: float, y: float, w: float, h: float) -> str:
    """A bar square at the baseline with a 4px rounded end."""
    r = min(4.0, w, h / 2)
    return (f"M{n(x0)},{n(y)}H{n(x0 + w - r)}A{n(r)},{n(r)} 0 0 1 {n(x0 + w)},{n(y + r)}"
            f"V{n(y + h - r)}A{n(r)},{n(r)} 0 0 1 {n(x0 + w - r)},{n(y + h)}H{n(x0)}Z")


def chart_svg(chart: dict) -> str:
    """A standalone SVG of one chart: inline styles, a dark-mode media query, a title and a text
    description holding every value. The same chart always gives the same bytes."""
    rows = [r for f in chart["facets"] for r in f["rows"]]
    names = {r["tool"]: wrap_label(r["tool"], SVG_LABEL_MAX) for r in rows}
    label_w = min(SVG_LABEL_MAX, max([text_px(line) for ls in names.values() for line in ls] or [0]))
    x0 = SVG_PAD + label_w + 12
    right = max([text_px(r["text"]) for r in rows if r["value"] is not None] or [0]) + 10
    plot = SVG_W - SVG_PAD - right - x0
    x = lambda v: x0 + max(0.0, min(1.0, v)) * plot  # noqa: E731
    body, y = [], SVG_PAD
    body.append(f'<text class="muted" x="{SVG_PAD}" y="{y + 11}" font-size="12">{xml_text(chart["group"])}</text>')
    body.append(f'<text class="ink" x="{SVG_PAD}" y="{y + 31}" font-size="15" font-weight="600">'
                f'{xml_text(chart["title"])}</text>')
    y += 44
    for facet in chart["facets"]:
        if facet["title"]:
            y += 6
            body.append(f'<text class="ink2" x="{SVG_PAD}" y="{y + 12}" font-size="12" font-weight="600">'
                        f'{xml_text(facet["title"])}</text>')
            y += 18
        top = y
        heights = [max(28, 14 + SVG_LINE * len(names[r["tool"]])) for r in facet["rows"]]
        bottom = top + sum(heights)
        for tick in (0, .25, .5, .75, 1):
            cls = "axis" if tick == 0 else "grid"
            body.append(f'<line class="{cls}" x1="{n(x(tick))}" x2="{n(x(tick))}" y1="{n(top)}" y2="{n(bottom)}" '
                        'stroke-width="1"/>')
        for r, h in zip(facet["rows"], heights):
            mid = y + h / 2
            lines = names[r["tool"]]
            first = mid - (len(lines) - 1) * SVG_LINE / 2 + 4
            spans = "".join(f'<tspan x="{n(x0 - 12)}" y="{n(first + i * SVG_LINE)}">{xml_text(line)}</tspan>'
                            for i, line in enumerate(lines))
            parts = [f"<title>{xml_text(r['tool'])}: {xml_text(r['text'])}</title>",
                     f'<text class="ink" text-anchor="end" font-size="12">{spans}</text>']
            if r["value"] is None:
                parts.append(f'<text class="muted state" x="{n(x0 + 6)}" y="{n(mid + 4)}" font-size="12" '
                             f'font-style="italic">{xml_text(r["text"])}</text>')
            else:
                w = x(r["value"]) - x0
                if w > 0:
                    parts.append(f'<path class="bar" d="{bar_path(x0, mid - 7, w, 14)}"/>')
                else:  # a real zero: a 2px stub on the baseline, so it is not mistaken for a missing value
                    parts.append(f'<rect class="bar" x="{n(x0)}" y="{n(mid - 7)}" width="2" height="14"/>')
                parts.append(f'<text class="ink" x="{n(x0 + max(w, 2) + 6)}" y="{n(mid + 4)}" font-size="12">'
                             f'{xml_text(r["text"])}</text>')
            body.append("<g>" + "".join(parts) + "</g>")
            y += h
    y += 4
    for tick in (0, .25, .5, .75, 1):
        body.append(f'<text class="muted" x="{n(x(tick))}" y="{n(y + 12)}" font-size="11" text-anchor="middle">'
                    f'{round(tick * 100)}%</text>')
    height = y + 16 + SVG_PAD
    desc = chart["caption"] + " " + " ".join(
        f"{(facet['title'] + ', ') if facet['title'] else ''}{r['tool']}: {r['text']}."
        for facet in chart["facets"] for r in facet["rows"])
    style = (lambda c: f".bg{{fill:{c['bg']}}}.ink{{fill:{c['ink']}}}.ink2{{fill:{c['ink2']}}}"
             f".muted{{fill:{c['muted']}}}.grid{{stroke:{c['grid']}}}.axis{{stroke:{c['axis']}}}"
             f".bar{{fill:{c['bar']}}}.state{{stroke:{c['bg']}}}")
    cid = chart["id"]
    return "\n".join([
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{SVG_W}" height="{n(height)}" '
        f'viewBox="0 0 {SVG_W} {n(height)}" role="img" aria-labelledby="{cid}-title {cid}-desc" '
        f'font-family="{SVG_FONT}">',
        f'<title id="{cid}-title">{xml_text(chart["group"])}. {xml_text(chart["title"])}</title>',
        f'<desc id="{cid}-desc">{xml_text(desc)}</desc>',
        "<style>" + style(SVG_COLORS["light"]) + ".state{stroke-width:3px;paint-order:stroke}"
        "g:hover .bar{opacity:.8}@media (prefers-color-scheme: dark){" + style(SVG_COLORS["dark"]) + "}</style>",
        f'<rect class="bg" width="{SVG_W}" height="{n(height)}" rx="8"/>',
        *body,
        "</svg>", ""])


def write_charts(out_dir: Path, summary: dict) -> list[Path]:
    paths = []
    for chart in summary.get("charts") or []:
        path = out_dir / chart["file"]
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8", newline="\n") as f:
            f.write(chart_svg(chart))
        paths.append(path)
    return paths


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
    "tolerance of that decoy. Under grader v3.2 it also fails on a contrasted-prefix result anywhere in the "
    "scanned scope (in_scope), and a failure counts against the category the result emitted. A result that "
    "claims a complete control (controlStatus complete) is listed apart and neither fails a negative nor counts "
    "as a false positive. No CWE agreement is needed to fail. Every other result is outside scope.",
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
    "property. When a tool matched at least one finding and no graded result of it carries the field, the "
    "measurement is shown as not supported by that tool. When it matched none, it is shown as n/a (no "
    "results), since that shows nothing about the field. Agents that write heuristic values under "
    "properties.heuristics are not scored on them.",
    "Constant-answer baselines for measurements 3 and 4 are scored with the grader's own functions on the same "
    "ground truths: controlStatus none and residualRisk high for every finding, and the one recommendation id "
    "most often required over all the jobs' findings for every finding. They assume every finding was "
    "matched, so they are what a fixed answer earns, not what a tool earns by finding issues. The matched-"
    "findings rows average the per-finding scores of matched findings only.",
    "The empty SARIF baseline is the mean reward the current grader gives a SARIF with no results on the same "
    "tasks, per role.",
    "Trials that errored, whose agent reported an error, whose SARIF was missing or whose grader crashed are "
    "not scored. Neither is a trial recorded before the role-free rename under a name whose role has since "
    "changed, since it was graded against the old label. Their findings are named apart and not added to recall. "
    "The strict rows count every such trial (except the renamed ones), and every trial whose agent recorded a "
    "tool_outcome, as a miss on a positive (reward 0, its findings unfound) and as a failure on a negative.",
    "Category means (OWASP score) leave out the categories a tool cannot emit: the CWE map reaches no "
    "LLM03.EA.AUTONOMY, so Semgrep, CodeQL, SonarQube and a stock Claude review are not averaged over it. A "
    f"mean is shown only when every category in it has at least {report.MIN_CATEGORY_TASKS} positives and "
    f"{report.MIN_CATEGORY_TASKS} negatives, else it reads \"{report.TOO_FEW}\".",
    "The near rows (location recall) pair findings with raw results one to one, so a result within tolerance of "
    "two findings counts for one of them.",
    "Families are named by the task's own family_id (task_metadata.json or task.toml), with the private variant "
    "map's family name in brackets in the task matrix.",
    "A task's role and family come from the private variant map when present, else from the task name, else "
    "from the ground truth. The reward never decides a role.",
]


def md_section(out: list, title: str, intro: str | None, table: list[str] | None = None) -> None:
    # Every technical section sits under "Details for reviewers", one level below it.
    out += ["", f"### {title}"]
    if intro:
        out += ["", intro]
    if table:
        out += table


def render(jobs: list[dict], tasks_dir: Path | None, data: dict | None = None,
           warnings: list[str] | None = None, task_set: dict | None = None, summary: dict | None = None) -> str:
    t = report.md_table
    data = data or dataset(jobs)
    task_set = task_set if task_set is not None else report.task_set_state(tasks_dir)
    warnings = warnings if warnings is not None else warnings_of(jobs, data, [], task_set)
    summary = summary or build_summary(jobs, data, full=task_set_size(tasks_dir))
    labels = [j["label"] for j in jobs]
    tasks_text = display_path(tasks_dir) if tasks_dir else "the paths recorded in the trials, where found"
    # The plain summary first, then every technical section under "Details for reviewers".
    out = summary_markdown(summary)
    out += ["", f"## {summary['details_title']}", "", summary["details_intro"], "",
            f"Generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} from "
            f"{len(jobs)} Harbor jobs. Ground truth from {tasks_text}, task set "
            f"{report.task_set_text(task_set)}.", ""]
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
    md_section(out, "Versions and run configuration", VERSIONS_INTRO + " Task set: "
               + report.task_set_text(task_set) + ".", t(["Field"] + labels, version_rows(jobs)))
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
               f"\"{NOT_SUPPORTED}\" means the tool matched a finding but no graded result of it carries the field "
               f"the grader reads. \"{NO_RESULTS_MEASURE}\" means it matched no finding, so that cannot be told.",
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
               "negative next to the fixed code, `in_scope` (grader v3.2) a result of a contrasted family anywhere "
               "in the scanned scope of a negative.",
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


VERSIONS_INTRO = ("The versions the results were graded under, from the agent metadata (else the SARIF). A "
                  "value with a count in brackets means the trials of that job differ. Claude review rows "
                  "show the mode: in stock mode the reviewer's free-text category is mapped to a CWE by exact "
                  "lookup in the frozen category map and categories outside it are dropped, so stock-mode "
                  "scores depend on that map. Scoped runs give their own CWE lists and can write code flows, "
                  "control status and recommendations, so measurements 2 to 4 apply to them as to any tool.")


HTML_TEMPLATE = Path(__file__).resolve().parent / "eval_report.html"
DATA_MARKER = '<script id="report-data" type="application/json">null</script>'


def build_payload(jobs: list[dict], tasks_dir: Path | None, data: dict | None = None,
                  warnings: list[str] | None = None, task_set: dict | None = None,
                  summary: dict | None = None) -> dict:
    """What eval_report.json holds and the HTML view reads."""
    data = data or dataset(jobs)
    task_set = task_set if task_set is not None else report.task_set_state(tasks_dir)
    warnings = warnings if warnings is not None else warnings_of(jobs, data, [], task_set)
    summary = summary or build_summary(jobs, data, full=task_set_size(tasks_dir))
    labels = ["Measure"] + [j["key"] for j in jobs]
    return {
        "schema": "sast-eval-report/2",
        "generated": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "tasks_dir": display_path(tasks_dir) if tasks_dir else None,
        "summary": summary,
        "dataset": data,
        "coverage_note": coverage_sentence(data),
        "warnings": warnings,
        "observations": observations(jobs),
        "scoreboard": {"columns": labels, "rows": headline(jobs)},
        "measurement_rows": measurement_rows(jobs),
        "versions": {"columns": ["Field"] + [j["key"] for j in jobs], "rows": version_rows(jobs),
                     "intro": VERSIONS_INTRO, "task_set": task_set, "task_set_text": report.task_set_text(task_set)},
        "method": METHOD,
        "not_supported": NOT_SUPPORTED,
        "no_results_measure": NO_RESULTS_MEASURE,
        "no_results_badge": NO_RESULTS_BADGE,
        "harbor_mean_warning": report.HARBOR_MEAN_WARNING,
        "tools": [{k: v for k, v in j.items() if k != "rows"} | {"trials": [report.public_row(r) for r in j["rows"]]}
                  for j in jobs],
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
               "recommendations", "neg_fail_trap", "neg_fail_near_fix", "neg_fail_in_scope", "grader_version", "error"]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("jobs", type=Path, nargs="+", help="Harbor job dirs or jobs folders, one per tool")
    parser.add_argument("--tasks", type=Path, help="folder holding the task directories, for ground truth")
    parser.add_argument("--variants", type=Path,
                        help="private map of task dir to family and role (default: <tasks>/VARIANTS.json)")
    parser.add_argument("--out", type=Path, help="write eval_report.md, .json, .html, trials.csv and charts/*.svg here")
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
    apply_common_baselines(jobs)
    assign_keys(jobs)
    data = dataset(jobs)
    task_set = report.task_set_state(args.tasks)  # read once, so every output states the same
    warnings = warnings_of(jobs, data, skipped, task_set)
    # Built once, so the Markdown and the HTML show the same text.
    summary = build_summary(jobs, data, full=task_set_size(args.tasks, args.variants))
    markdown = render(jobs, args.tasks, data, warnings, task_set, summary)
    if args.out:
        args.out.mkdir(parents=True, exist_ok=True)
        (args.out / "eval_report.md").write_text(markdown, encoding="utf-8")
        payload = build_payload(jobs, args.tasks, data, warnings, task_set, summary)
        (args.out / "eval_report.json").write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
        (args.out / "eval_report.html").write_text(render_html(payload), encoding="utf-8")
        write_charts(args.out, summary)
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
