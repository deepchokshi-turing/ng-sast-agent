#!/usr/bin/env python3
"""Per-trial table, OWASP Benchmark style category scores and client measurements.

    python tools/report.py <harbor job or jobs dir> [--tasks <dir>] [--variants <file>] [--json] [--write <dir>]
    python tools/report.py <trial>/verifier/reward.json [...more reward.json files]

The task reward is a composite built for agents that also explain paths,
controls and recommendations, and a plain scanner that reports no paths,
controls or recommendations earns only part of it. The task reward also means
different things on positives and negatives, since an empty SARIF scores 1.0
on every negative. The report therefore never averages it over both, and
warns that Harbor's own job-level mean in result.json is not a score. It shows
these views:

- **Per trial**: reward, tp, fp, fn, ``fp_out`` (grader v2+ ``fp_outside_scope``:
  results outside the files the fix changed or away from the fixed code, not
  counted as false positives), location recall helpers when the agent wrote
  ``findings_compact`` metadata.
- **Pooled detection** over the positives that were scored: precision,
  recall, F1. Findings on positives that were not scored (errored trial,
  missing SARIF, grader crash) are counted apart and named next to recall.
- **Categories (OWASP Benchmark style scoring)**: every scored task is a test
  case for each category it is labelled with (grader v3 ``cat.<category>.truth``
  and ``.detected``). A positive is a test case for the categories of its
  findings, a negative for the categories of its ``contrast_rule_ids``. Per
  category TP, FN (positives), FP, TN (negatives), TPR, FPR and Youden score
  (TPR minus FPR). Overall TPR and FPR are the means over the categories that
  have both positives and negatives, so the score is the mean of the
  per-category scores. Precision is pooled over categories. F1 uses pooled
  precision and mean TPR.
- **Risk types** (client measurement 1): a binary table each for
  sensitive_information_disclosure and excessive_agency, and the exact-set
  result for tasks labelled both, one, or neither, and for positives and
  negatives apart. A risk counts as predicted only from results matched to a
  finding or failing a negative (grader ``tl.pred``). TPR is over the positives
  labelled with the risk. FPR is over the negatives only: under the strict rule
  a positive can predict a risk only through a matched finding of that risk, so
  a positive without the risk can never be a false positive for it. Positives
  without the risk that were still flagged (possible under the loose rule) are
  counted as ``FP_other_pos`` and enter precision. The looser grader flag
  ``tl.pred_loose`` gets its own table.
- **Task reward by role**: mean reward over positives and over negatives,
  separately, and how many negatives failed near the fix or on a trap
  (grader ``neg.fail.near_fix`` and ``neg.fail.trap``).
- **Measurements** (client measurements 2 to 4): mean path, controls and
  recommendations score over the scored positives (missed findings count 0).
  When the graded SARIFs are readable and no result of the tool carries the
  fields the grader reads (``codeFlows`` for path, top-level
  ``properties.controlStatus`` or ``residualRisk`` for controls,
  ``properties.recommendations`` for recommendations), the measurement is
  reported as not supported by the tool instead of 0.

A task's role (positive or negative) and family come from, in order: the
private variant map (``--variants``, default ``<tasks>/VARIANTS.json``, of the
form ``{"<task dir>": {"family": "...", "role": "positive"|"negative"}}``, an
entry's ``former_name`` also matching jobs recorded before the rename), the
task name ``task_<family>_<role>``, the ground truth (``variant_role``, else
positive when it lists findings, and ``family_id``), and last the grader's
``gt_findings`` count, which is not used when the grader crashed (it then
writes 0). The reward itself never decides a role.

Trials whose run errored, whose agent reported a status other than ok, whose
SARIF was missing or whose grader crashed are not scored. Nor is a trial
recorded before the rename under a name whose role has since changed (status
``graded_as_old_role``): it was graded against the old label. They are left out of
every table and listed apart, with their findings counted as not scored.

A tool that reported nothing scores exactly what an empty SARIF scores (1.0
on every negative, FPR 0, "neither" exact 1.0). When no scored trial of a tool
emitted a result, the report says so on its first line. The count comes from
the agent metadata (``results_emitted``, in a job's result.json or a
``metadata.json`` next to the trial's ``verifier`` folder). For a bare
reward.json with neither, a trial with tp, fp and fp_outside_scope all 0 counts
as having no result.

Precision is n/a when there is no result to take it over (tp + fp = 0).

Uses only the standard library.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

RISKS = {"SID": "sensitive_information_disclosure", "EA": "excessive_agency"}
MEASURES = ("detection", "classification", "path", "controls", "recommendations")
ROLES = ("positive", "negative")
#: The five ruleIds of the client taxonomy (spec section 3).
TAXONOMY = ("LLM02.SID.MEDIUM", "LLM02.SID.HIGH", "LLM03.EA.FUNCTIONALITY", "LLM03.EA.PERMISSIONS",
            "LLM03.EA.AUTONOMY")
#: Statuses of trials that are not scored.
NOT_SCORED = ("errored", "sarif_missing", "grader_error", "graded_as_old_role")
#: SARIF fields the grader reads for measurements 2 to 4 (grade.py score_match).
SUPPORT_FIELDS = {"path": ("codeFlows",), "controls": ("controlStatus", "residualRisk"),
                  "recommendations": ("recommendations",)}


# ---- inputs ------------------------------------------------------------------------------

def read_json_file(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def load_variants(path: Path | None) -> dict:
    """The private variant map {"<task dir>": {"family": ..., "role": ...}}, or {}.

    An entry may carry ``former_name``, the task's name before the role-free
    rename (for example task_ef77cd_negative). Jobs recorded before the rename
    use that name, so the entry is also indexed under it, with ``current_name``
    set. A former name never hides a current task of the same name.
    """
    if path is None or not path.is_file():
        return {}
    data = read_json_file(path)
    if not isinstance(data, dict):
        raise SystemExit(f"report: {path.name} is not a JSON object of task name to family and role")
    out = {}
    former = {}
    for name, entry in data.items():
        if not isinstance(entry, dict):
            continue
        role = entry.get("role")
        out[str(name)] = {"family": str(entry.get("family") or name),
                          "role": role if role in ROLES else ""}
        if entry.get("former_name"):
            former[str(entry["former_name"])] = {**out[str(name)], "current_name": str(name)}
    for old, entry in former.items():
        out.setdefault(old, entry)
    return out


def default_variants(tasks_dir: Path | None, explicit: Path | None) -> Path | None:
    if explicit is not None:
        return explicit
    if tasks_dir is not None and (tasks_dir / "VARIANTS.json").is_file():
        return tasks_dir / "VARIANTS.json"
    return None


def parse_task_name(task: str) -> tuple[str, str]:
    """task_3c67f1_positive -> ("3c67f1", "positive"). Other names give (name, "")."""
    name = str(task).split("/")[-1]
    parts = name.split("_")
    if len(parts) >= 3 and parts[0] == "task" and parts[-1] in ROLES:
        return "_".join(parts[1:-1]), parts[-1]
    return name, ""


def family_and_role(task: str, truth: dict | None, variants: dict, rewards: dict) -> tuple[str, str, str]:
    """(family, role, source). See the module docstring for the order."""
    name = str(task).split("/")[-1]
    entry = variants.get(name)
    if entry and entry["role"]:
        return entry["family"], entry["role"], "variants (former name)" if entry.get("current_name") else "variants"
    family, role = parse_task_name(name)
    if role:
        return (entry or {}).get("family") or family, role, "task name"
    if truth is not None:
        role = truth.get("variant_role")
        if role not in ROLES:
            role = "positive" if truth.get("findings") else "negative"
        return (entry or {}).get("family") or str(truth.get("family_id") or name), role, "ground truth"
    gt = rewards.get("gt_findings")
    if gt is not None and not rewards.get("grader_error"):
        return (entry or {}).get("family") or name, "positive" if gt > 0 else "negative", "grader gt_findings"
    return (entry or {}).get("family") or name, "", "unknown"


def ground_truth(trial: dict, tasks_dir: Path | None, variants: dict | None = None) -> dict | None:
    """The task's ground truth from <tasks>/<task name>, else from the folder a former
    name was renamed to, else from the task path recorded in the trial."""
    candidates = []
    if tasks_dir is not None:
        name = str(trial.get("task_name") or "").split("/")[-1]
        if name:
            candidates.append(tasks_dir / name)
            current = ((variants or {}).get(name) or {}).get("current_name")
            if current:
                candidates.append(tasks_dir / current)
    path = ((trial.get("config") or {}).get("task") or {}).get("path")
    if path:
        candidates.append(Path(path))
    for task in candidates:
        try:
            gt = task / "tests" / "ground_truth.json"
            if gt.is_file():
                return json.loads(gt.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
    return None


def ground_truth_hits(rows: list, truth: dict) -> tuple[int, int, int]:
    """(gt findings, with a finding near them, with a near finding of an acceptable or primary CWE)."""
    findings = truth.get("findings") or []
    tol = (truth.get("matching") or {}).get("line_tolerance", 10)
    near_any = near_cwe = 0
    for gt in findings:
        targets = [gt["primary_location"], *(gt.get("alternative_primary_locations") or [])]
        acceptable = set(gt.get("acceptable_cwes") or [])
        if gt.get("primary_cwe"):
            acceptable.add(gt["primary_cwe"])
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
    """Trial result.json files (they carry a trial_name, the job's own does not)."""
    found = []
    try:
        files = sorted(job.glob("*/result.json"))
    except OSError:
        return found
    for result_file in files:
        data = read_json_file(result_file)
        if isinstance(data, dict) and "trial_name" in data:
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
            pred = int(rewards.get(f"tl.pred.{short}", 0))
            risks[short] = {"truth": int(rewards[f"tl.truth.{short}"]), "pred": pred,
                            "pred_loose": int(rewards.get(f"tl.pred_loose.{short}", pred))}
    return {"categories": cats, "risks": risks}


def sarif_fields(trial_dir: Path) -> dict | None:
    """How many results of the graded SARIF carry each field the grader reads, or None."""
    for candidate in (trial_dir / "agent" / "findings.sarif",
                      trial_dir / "artifacts" / "logs" / "artifacts" / "sast" / "findings.sarif"):
        data = read_json_file(candidate)
        if not isinstance(data, dict):
            continue
        results = [r for run in data.get("runs") or [] for r in (run or {}).get("results") or []
                   if isinstance(r, dict)]
        counts = {"results": len(results), "codeFlows": 0, "controlStatus": 0, "residualRisk": 0,
                  "recommendations": 0}
        for r in results:
            props = r.get("properties") or {}
            counts["codeFlows"] += bool(r.get("codeFlows"))
            for key in ("controlStatus", "residualRisk", "recommendations"):
                counts[key] += props.get(key) not in (None, "", [])
        return counts
    return None


def base_row(task: str, rewards: dict, status: str = "ok", error: str = "", truth: dict | None = None,
             variants: dict | None = None) -> dict:
    family, role, role_source = family_and_role(task, truth, variants or {}, rewards)
    old_role = parse_task_name(task)[1]
    # A job recorded before the rename under a name whose role is no longer the task's role: its
    # grade was computed against the old label, so it is not scored under either role.
    relabelled = bool(role_source == "variants (former name)" and old_role and old_role != role)
    if relabelled:
        status, error = "graded_as_old_role", (f"graded as a {old_role} before the rename, the task is now a "
                                               f"{role}. Rerun it")
    elif rewards.get("grader_error"):
        status, error = "grader_error", error or "the grader crashed"
    elif rewards.get("sarif_missing"):
        status, error = "sarif_missing", error or "no SARIF was written"
    gt = len(truth.get("findings") or []) if truth is not None else rewards.get("gt_findings")
    if truth is None and rewards.get("grader_error"):
        gt = None
    return {
        "task": task,
        "family": family,
        "role": role,
        "role_source": role_source,
        # A job recorded before the rename under a name whose role is no longer the task's role.
        "relabelled": relabelled,
        "tool": None,
        "status": status,
        "reward": rewards.get("reward"),
        "tp": rewards.get("tp"),
        "fp": rewards.get("fp"),
        "fn": rewards.get("fn"),
        "gt": gt,
        "gt_rules": [f.get("rule_id") for f in truth.get("findings") or []] if truth is not None else None,
        "contrast_rules": list(truth.get("contrast_rule_ids") or []) if truth is not None else None,
        "fp_out": rewards.get("fp_outside_scope"),
        **{m: rewards.get(m) for m in MEASURES},
        "sarif_missing": bool(rewards.get("sarif_missing")) or bool(rewards.get("grader_error")),
        "neg_fail_near_fix": rewards.get("neg.fail.near_fix"),
        "neg_fail_trap": rewards.get("neg.fail.trap"),
        **labels_from(rewards),
        "sarif_fields": None,
        "error": error,
    }


def rows_for(job: Path, tasks_dir: Path | None, variants: dict | None = None) -> list[dict]:
    out = []
    for result_file, trial in trial_results(job):
        meta = (trial.get("agent_result") or {}).get("metadata") or {}
        rewards = (trial.get("verifier_result") or {}).get("rewards") or {}
        truth = ground_truth(trial, tasks_dir, variants)
        exception = trial.get("exception_info") or {}
        scanned = truth is not None and meta.get("status") == "ok"
        gt_n, near, near_cwe = ground_truth_hits(meta.get("findings_compact") or [], truth) if scanned else (None,) * 3
        row = base_row(str(trial.get("task_name") or result_file.parent.name).split("/")[-1], rewards,
                       "errored" if exception else meta.get("status", "?"),
                       (exception.get("exception_message") or meta.get("error") or "")[:120],
                       truth, variants)
        row.update({
            "trial": trial.get("trial_name") or result_file.parent.name,
            "tool": meta.get("tool") or meta.get("agent"),
            "raw": meta.get("results_raw"),
            "security": meta.get("findings_security"),
            "emitted": meta.get("results_emitted"),
            "near": near,
            "near_cwe": near_cwe,
            "scan_s": meta.get("scan_seconds"),
            "setup_s": (meta.get("install") or {}).get("setup_seconds"),
            "has_truth": truth is not None,
            "sarif_fields": sarif_fields(result_file.parent),
        })
        out.append(row)
    return out


def _trial_metadata(reward_file: Path) -> dict:
    """The agent metadata next to a reward.json, when the trial folder has it."""
    trial = reward_file.parent.parent if reward_file.parent.name == "verifier" else reward_file.parent
    for candidate, pick in ((trial / "result.json", lambda d: (d.get("agent_result") or {}).get("metadata")),
                            (trial / "metadata.json", lambda d: d)):
        if candidate.is_file():
            try:
                meta = pick(json.loads(candidate.read_text(encoding="utf-8")))
            except (ValueError, AttributeError):
                continue
            if isinstance(meta, dict):
                return meta
    return {}


def rows_from_reward_files(files: list[Path], tasks_dir: Path | None = None, variants: dict | None = None) -> list[dict]:
    rows = []
    for f in files:
        trial_dir = f.parent.parent if f.parent.name == "verifier" else f.parent
        task = trial_dir.name
        truth = ground_truth({"task_name": task}, tasks_dir, variants) if tasks_dir is not None else None
        row = base_row(task, json.loads(f.read_text(encoding="utf-8")), truth=truth, variants=variants)
        meta = _trial_metadata(f)
        if meta:
            row["tool"] = meta.get("tool") or meta.get("agent")
            row["emitted"] = meta.get("results_emitted")
            if meta.get("status") and row["status"] == "ok":
                row["status"] = meta["status"]
        row["has_truth"] = truth is not None
        row["sarif_fields"] = sarif_fields(trial_dir)
        rows.append(row)
    return rows


# ---- aggregation ---------------------------------------------------------------------

def ratio(num: float, den: float) -> float | None:
    return num / den if den else None


def is_scored(r: dict) -> bool:
    """A trial whose grade counts: graded, ran cleanly, SARIF present, grader did not crash."""
    return (r["reward"] is not None and r["status"] in ("ok", "?") and not r["sarif_missing"])


def usable(rows: list[dict]) -> list[dict]:
    return [r for r in rows if is_scored(r)]


def not_scored(rows: list[dict]) -> list[dict]:
    return [r for r in rows if not is_scored(r)]


def by_role(rows: list[dict], role: str) -> list[dict]:
    return [r for r in usable(rows) if r.get("role") == role]


def category_table(rows: list[dict]) -> dict:
    cats: dict[str, dict] = {}
    for r in usable(rows):
        for cat, flags in r["categories"].items():
            c = cats.setdefault(cat, {"TP": 0, "FN": 0, "TN": 0, "FP": 0})
            truth, det = flags.get("truth", 0), flags.get("detected", 0)
            c[{(1, 1): "TP", (1, 0): "FN", (0, 1): "FP", (0, 0): "TN"}[(truth, det)]] += 1
    for c in cats.values():
        c["positives"] = c["TP"] + c["FN"]
        c["negatives"] = c["FP"] + c["TN"]
        c["TPR"] = ratio(c["TP"], c["positives"])
        c["FPR"] = ratio(c["FP"], c["negatives"])
        c["youden"] = c["TPR"] - c["FPR"] if c["TPR"] is not None and c["FPR"] is not None else None
    # Means over the categories that have both sides, so the score is the mean of the per-category scores.
    scored = [c for c in cats.values() if c["youden"] is not None]
    tp = sum(c["TP"] for c in cats.values())
    fp = sum(c["FP"] for c in cats.values())
    fn = sum(c["FN"] for c in cats.values())
    mean_tpr = sum(c["TPR"] for c in scored) / len(scored) if scored else None
    mean_fpr = sum(c["FPR"] for c in scored) / len(scored) if scored else None
    precision = ratio(tp, tp + fp)
    f1 = (2 * precision * mean_tpr / (precision + mean_tpr)
          if precision is not None and mean_tpr is not None and precision + mean_tpr else None)
    overall = {
        "categories": len(scored), "mean_TPR": mean_tpr, "mean_FPR": mean_fpr,
        "score": mean_tpr - mean_fpr if mean_tpr is not None and mean_fpr is not None else None,
        "precision_pooled": precision, "recall_pooled": ratio(tp, tp + fn), "F1": f1,
        "categories_one_sided": sorted(k for k, c in cats.items() if c["youden"] is None),
    }
    return {"per_category": dict(sorted(cats.items())), "overall": overall}


def risk_table(rows: list[dict], pred: str = "pred") -> dict:
    """pred: "pred" (matched or failing results only) or "pred_loose".

    TPR over the positives labelled with the risk, FPR over the negatives only.
    """
    out = {}
    graded = [r for r in usable(rows) if r["risks"] and r.get("role") in ROLES]
    for short, name in RISKS.items():
        c = {"TP": 0, "FN": 0, "TN": 0, "FP": 0, "FP_other_pos": 0, "TN_other_pos": 0}
        for r in graded:
            t, p = r["risks"][short]["truth"], r["risks"][short][pred]
            if r["role"] == "negative":
                c["FP" if p else "TN"] += 1
            elif t:
                c["TP" if p else "FN"] += 1
            else:
                c["FP_other_pos" if p else "TN_other_pos"] += 1
        c["TPR"] = ratio(c["TP"], c["TP"] + c["FN"])
        c["FPR"] = ratio(c["FP"], c["FP"] + c["TN"])
        c["precision"] = ratio(c["TP"], c["TP"] + c["FP"] + c["FP_other_pos"])
        out[name] = c
    combos: dict[str, dict] = {}
    exact_by_role = {role: {"tasks": 0, "exact": 0} for role in ROLES}
    for r in graded:
        truth = tuple(s for s in RISKS if r["risks"][s]["truth"])
        predicted = tuple(s for s in RISKS if r["risks"][s][pred])
        label = {("SID", "EA"): "both", ("SID",): "SID only", ("EA",): "EA only", (): "neither"}[truth]
        c = combos.setdefault(label, {"tasks": 0, "exact": 0})
        c["tasks"] += 1
        c["exact"] += truth == predicted
        exact_by_role[r["role"]]["tasks"] += 1
        exact_by_role[r["role"]]["exact"] += truth == predicted
    for c in [*combos.values(), *exact_by_role.values()]:
        c["exact_rate"] = ratio(c["exact"], c["tasks"])
    out["by_truth_set"] = combos
    out["exact_by_role"] = exact_by_role
    return out


def measurement_support(rows: list[dict]) -> dict:
    """Per measurement 2 to 4: True when a scored result carries a field the grader reads,
    False when the SARIFs were readable and none did, None when no SARIF could be read."""
    known = [r["sarif_fields"] for r in usable(rows) if r.get("sarif_fields") is not None]
    out = {}
    for measure, fields in SUPPORT_FIELDS.items():
        if not known:
            out[measure] = None
        else:
            out[measure] = any(k.get(f, 0) for k in known for f in fields)
    out["results_with"] = {f: sum(k.get(f, 0) for k in known)
                           for f in ("codeFlows", "controlStatus", "residualRisk", "recommendations")}
    out["sarifs_read"] = len(known)
    return out


def measurement_means(rows: list[dict]) -> dict:
    positives = by_role(rows, "positive")
    support = measurement_support(rows)
    out = {"tasks": len(positives)}
    for m in MEASURES:
        if support.get(m) is False:
            out[m] = None
        else:
            out[m] = sum(r[m] or 0 for r in positives) / len(positives) if positives else None
    out["supported"] = {m: support[m] for m in SUPPORT_FIELDS}
    return out


def pooled_detection(rows: list[dict]) -> dict | None:
    positives = by_role(rows, "positive")
    skipped = [r for r in not_scored(rows) if r.get("role") == "positive"]
    if not positives and not skipped:
        return None
    tp = sum(r["tp"] or 0 for r in positives)
    fp = sum(r["fp"] or 0 for r in positives)
    fn = sum(r["fn"] or 0 for r in positives)
    gt = sum(r["gt"] or 0 for r in positives)
    precision = tp / (tp + fp) if tp + fp else None  # undefined with no result
    recall = tp / gt if gt else (0.0 if positives else None)
    if precision is None or recall is None:
        f1 = None
    else:
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {"tasks": len(positives), "gt": gt, "tp": tp, "fp": fp, "fn": fn,
            "precision": precision, "recall": recall, "F1": f1,
            "tasks_not_scored": len(skipped),
            "gt_not_scored": sum(r["gt"] or 0 for r in skipped),
            "gt_not_scored_unknown": sum(1 for r in skipped if r["gt"] is None)}


def reward_by_role(rows: list[dict]) -> dict:
    """Mean task reward for positives and negatives apart. Never one mean over both."""
    out = {}
    for role in ROLES:
        group = by_role(rows, role)
        out[role] = {"tasks": len(group),
                     "mean_reward": sum(r["reward"] for r in group) / len(group) if group else None,
                     "not_scored": sum(1 for r in not_scored(rows) if r.get("role") == role)}
    negs = by_role(rows, "negative")
    out["negative"]["failed"] = sum(1 for r in negs if r["reward"] < 1.0)
    out["negative"]["failed_near_fix"] = sum(1 for r in negs if r.get("neg_fail_near_fix"))
    out["negative"]["failed_trap"] = sum(1 for r in negs if r.get("neg_fail_trap"))
    out["unknown_role"] = sum(1 for r in rows if r.get("role") not in ROLES)
    return out


def taxonomy_coverage(rows: list[dict]) -> dict:
    """Ground-truth findings and contrasts per taxonomy ruleId, over distinct tasks."""
    tasks = {}
    for r in rows:
        if r.get("gt_rules") is not None:
            tasks.setdefault(r["task"], r)
    findings = {k: 0 for k in TAXONOMY}
    contrasts = {k: 0 for k in TAXONOMY}
    for r in tasks.values():
        for rule in r["gt_rules"] or []:
            findings[rule] = findings.get(rule, 0) + 1
        for rule in r.get("contrast_rules") or []:
            contrasts[rule] = contrasts.get(rule, 0) + 1
    known = bool(tasks)
    return {"known": known, "tasks": len(tasks), "findings_by_rule": findings, "contrasts_by_rule": contrasts,
            "missing": [k for k in TAXONOMY if not findings.get(k)] if known else None}


def _emitted(row: dict) -> int | None:
    """Results the agent wrote, from its metadata, else from the grader's counts."""
    if row.get("emitted") is not None:
        return int(row["emitted"])
    if row.get("sarif_fields") is not None:
        return int(row["sarif_fields"]["results"])
    if row["reward"] is None:
        return None
    counts = [row.get("tp"), row.get("fp"), row.get("fp_out")]
    if all(c is None for c in counts):
        return None
    return 0 if all(not c for c in counts) else None


def emitted_by_tool(rows: list[dict]) -> dict:
    """Per tool: scored trials, trials with a known result count, and their total.
    ``no_results`` is True when every scored trial is known to have emitted nothing."""
    out: dict[str, dict] = {}
    for r in usable(rows):
        tool = r.get("tool") or "all trials"
        e = out.setdefault(tool, {"graded": 0, "known": 0, "emitted": 0})
        e["graded"] += 1
        n = _emitted(r)
        if n is not None:
            e["known"] += 1
            e["emitted"] += n
    for e in out.values():
        e["no_results"] = e["graded"] > 0 and e["known"] == e["graded"] and e["emitted"] == 0
    return out


NO_RESULTS_WARNING = ("no results emitted, scores equal an empty SARIF: {tool} reported nothing on any of its "
                      "{graded} scored trials, so every negative scores 1.0, FPR is 0 and the 'neither' row is "
                      "exact by default. These numbers say nothing about the tool.")

NO_RESULTS_BADGE = "no results, scores not meaningful"

NOT_SUPPORTED = "not supported by this tool"

HARBOR_MEAN_WARNING = ("Harbor's job-level means (result.json) average positives and negatives together, "
                       "for the reward and for every sub-score, so such a mean is not a score: an empty SARIF "
                       "earns 1.0 on every negative. Quote the pooled detection, category and per-role figures "
                       "instead.")


def summarise(rows: list[dict]) -> dict:
    scored = usable(rows)
    emitted = emitted_by_tool(rows)
    negatives = by_role(rows, "negative")
    return {
        "no_results_emitted": sorted(t for t, e in emitted.items() if e["no_results"]),
        "results_emitted_by_tool": emitted,
        "trials": len(rows), "graded": len(scored),
        "not_scored": [{"task": r["task"], "role": r.get("role"), "status": r["status"], "gt": r["gt"],
                        "error": r.get("error", "")} for r in not_scored(rows)],
        "excluded_from_category_tables": len(rows) - len(scored),
        "reward_by_role": reward_by_role(rows),
        "warning": HARBOR_MEAN_WARNING,
        "fp_outside_scope": sum(r["fp_out"] or 0 for r in scored),
        "pooled_detection": pooled_detection(rows),
        "zero_finding_tasks_clean": [sum(1 for r in negatives if (r["fp"] or 0) == 0), len(negatives)],
        "categories": category_table(rows),
        "risk_types": risk_table(rows),
        "risk_types_loose": risk_table(rows, "pred_loose"),
        "measurements_positive_tasks": measurement_means(rows),
        "measurement_support": measurement_support(rows),
        "taxonomy_coverage": taxonomy_coverage(rows),
    }


# ---- rendering -------------------------------------------------------------------------

def fmt(v) -> str:
    if v is None:
        return ""
    return f"{v:.3f}" if isinstance(v, float) else str(v)


def md_cell(v) -> str:
    return fmt(v).replace("|", "\\|").replace("\n", " ")


def md_table(columns: list[str], rows: list[list]) -> list[str]:
    lines = ["", "| " + " | ".join(md_cell(c) for c in columns) + " |", "|" + "---|" * len(columns)]
    lines += ["| " + " | ".join(md_cell(v) for v in row) + " |" for row in rows]
    return lines


def text_table(columns: list[str], rows: list[list]) -> list[str]:
    table = [[fmt(v) for v in row] for row in rows]
    widths = [max(len(c), *(len(row[i]) for row in table)) if table else len(c) for i, c in enumerate(columns)]
    return ["  ".join(c.ljust(w) for c, w in zip(columns, widths))] + [
        "  ".join(v.ljust(w) for v, w in zip(row, widths)) for row in table]


TRIAL_COLUMNS = ["task", "role", "status", "reward", "tp", "fp", "fn", "fp_out", "gt", "near", "near_cwe", "raw",
                 "security", "emitted", "setup_s", "scan_s", "error"]


def measure_text(m: dict, key: str) -> str:
    if m.get("supported", {}).get(key) is False:
        return NOT_SUPPORTED
    return fmt(m.get(key))


def render(rows: list[dict], summary: dict, table=text_table) -> str:
    out = []
    for tool in summary["no_results_emitted"]:
        graded = summary["results_emitted_by_tool"][tool]["graded"]
        out.append("WARNING: " + NO_RESULTS_WARNING.format(tool=tool, graded=graded))
    if out:
        out.append("")
    display = [{**r, "role": r.get("role") or "unknown"} for r in rows]
    cols = [c for c in TRIAL_COLUMNS if any(c in r for r in rows)]
    out += table(cols, [[r.get(c) for c in cols] for r in display])
    out.append(f"\ntrials {summary['trials']}, graded {summary['graded']}, "
               f"not scored {summary['trials'] - summary['graded']}")
    for r in summary["not_scored"]:
        out.append(f"  not scored: {r['task']} ({r['role'] or 'unknown role'}, {r['status']}"
                   f"{', ' + r['error'] if r['error'] else ''})")
    det = summary["pooled_detection"]
    if det:
        out.append(f"detection, pooled over {det['tasks']} scored positives ({det['gt']} ground-truth findings):")
        out.append(f"  tp {det['tp']}  fp {det['fp']}  fn {det['fn']}  precision {fmt(det['precision']) or 'n/a'}  "
                   f"recall {fmt(det['recall']) or 'n/a'}  F1 {fmt(det['F1']) or 'n/a'}")
        if det["tasks_not_scored"]:
            out.append(f"  recall leaves out {det['gt_not_scored']} findings on {det['tasks_not_scored']} "
                       f"positives that were not scored")
        with_meta = [r for r in by_role(rows, "positive") if r.get("near") is not None]
        if with_meta:
            gt_meta = sum(r["gt"] or 0 for r in with_meta)
            out.append(f"  location recall (any security finding, any OWASP side): "
                       f"{sum(r['near'] for r in with_meta)}/{gt_meta}")
            out.append(f"  location + acceptable-CWE recall: {sum(r['near_cwe'] for r in with_meta)}/{gt_meta}")
    clean, zero = summary["zero_finding_tasks_clean"]
    if zero:
        out.append(f"negatives clean (fp == 0): {clean}/{zero}")
    roles = summary["reward_by_role"]
    pos, neg = roles["positive"], roles["negative"]
    if pos["tasks"]:
        out.append(f"mean task reward, positives only ({pos['tasks']} tasks): {fmt(pos['mean_reward'])}")
    if neg["tasks"]:
        out.append(f"mean task reward, negatives only ({neg['tasks']} tasks): {fmt(neg['mean_reward'])}  "
                   f"(failed {neg['failed']}: near the fix {neg['failed_near_fix']}, on a trap {neg['failed_trap']})")
    out.append(f"warning: {summary['warning']}")
    out.append(f"fp_outside_scope total: {summary['fp_outside_scope']}")

    cats = summary["categories"]
    if cats["per_category"]:
        out.append("\ncategories (OWASP Benchmark style, one test case per task and category; "
                   "TPR over the positives labelled with it, FPR over the negatives contrasted with it):")
        out += table(["category", "TP", "FN", "TN", "FP", "TPR", "FPR", "youden"],
                     [[k, c["TP"], c["FN"], c["TN"], c["FP"], c["TPR"], c["FPR"], c["youden"]]
                      for k, c in cats["per_category"].items()])
        o = cats["overall"]
        na = {k: (fmt(v) or "n/a") for k, v in o.items() if k != "categories_one_sided"}
        out.append(f"overall: mean TPR {na['mean_TPR']}  mean FPR {na['mean_FPR']}  "
                   f"score {na['score']}  precision (pooled) {na['precision_pooled']}  "
                   f"F1 {na['F1']}  over {o['categories']} categories")
        if o["categories_one_sided"]:
            out.append("  left out of the means (no positives or no negatives): " + ", ".join(o["categories_one_sided"]))
    for key, title in (("risk_types", "task level, results matched to a finding or failing the negative"),
                       ("risk_types_loose", "task level, loose: any result in the fix files or near the fix")):
        risks = summary[key]
        if not risks["by_truth_set"]:
            continue
        out.append(f"\nrisk types ({title}; TPR over positives with the risk, FPR over negatives only):")
        out += table(["risk_type", "TP", "FN", "TN", "FP", "FP_other_pos", "TPR", "FPR", "precision"],
                     [[k, c["TP"], c["FN"], c["TN"], c["FP"], c["FP_other_pos"], c["TPR"], c["FPR"], c["precision"]]
                      for k, c in risks.items() if k in RISKS.values()])
        out.append("labelled risk set (both, one, neither), predicted set equal to labelled set:")
        out += table(["truth_set", "tasks", "exact", "exact_rate"],
                     [[k, c["tasks"], c["exact"], c["exact_rate"]] for k, c in sorted(risks["by_truth_set"].items())])
    m = summary["measurements_positive_tasks"]
    if m["tasks"]:
        out.append(f"\nmeasurements, mean over {m['tasks']} scored positives (missed findings score 0):")
        out += table(list(MEASURES), [[measure_text(m, k) for k in MEASURES]])
    cov = summary["taxonomy_coverage"]
    if cov["known"] and cov["missing"]:
        out.append("\ntaxonomy categories with no ground-truth finding: " + ", ".join(cov["missing"]))
    if summary["excluded_from_category_tables"]:
        out.append(f"\nleft out of every table (errored, agent error, no SARIF, grader error): "
                   f"{summary['excluded_from_category_tables']}")
    return "\n".join(out)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("inputs", type=Path, nargs="+",
                        help="a Harbor job or jobs directory, or one or more reward.json files")
    parser.add_argument("--tasks", type=Path, help="folder holding the task directories, for ground truth")
    parser.add_argument("--variants", type=Path,
                        help="private map of task dir to family and role (default: <tasks>/VARIANTS.json)")
    parser.add_argument("--json", action="store_true", help="print the per-trial rows as JSON instead of tables")
    parser.add_argument("--write", type=Path, help="also write report.json and report.md into this directory")
    args = parser.parse_args()
    variants = load_variants(default_variants(args.tasks, args.variants))

    files = [p for p in args.inputs if p.is_file()]
    if files:
        rows = rows_from_reward_files(files, args.tasks, variants)
    else:
        job = args.inputs[0]
        if not trial_results(job):  # a jobs dir: use its latest job
            nested = sorted(p for p in job.iterdir() if p.is_dir() and trial_results(p))
            job = nested[-1] if nested else job
        rows = rows_for(job, args.tasks, variants)
    summary = summarise(rows)

    if args.write:
        args.write.mkdir(parents=True, exist_ok=True)
        (args.write / "report.json").write_text(json.dumps({"summary": summary, "trials": rows}, indent=2), encoding="utf-8")
        (args.write / "report.md").write_text("# SAST benchmark report\n\n" + render(rows, summary, md_table) + "\n", encoding="utf-8")
    if args.json:
        json.dump(rows, sys.stdout, indent=2)
        print()
        return
    print(render(rows, summary))


if __name__ == "__main__":
    main()
