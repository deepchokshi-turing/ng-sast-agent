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
  reported as not supported by the tool instead of 0. That needs at least one
  matched result on a scored positive (the grader reads the fields on matched
  results only): with none, the measurement is "n/a (no results)", since a tool
  that matched nothing shows neither that it can nor that it cannot fill them.
- **Versions**: the agent version, CWE map, heuristics and Claude category map
  the results were graded under (agent metadata, else the SARIF driver
  properties), and the task set's git commit and whether its work tree is dirty
  (``--tasks`` in a git work tree, skipped quietly otherwise). More than one
  value of a field across the trials is a warning.
- **Claude review runs**: the mode (stock or scoped), the auth and the results
  label. Stock-mode scores depend on the frozen category-to-CWE map, since
  categories outside it are dropped, and the report says how many were.

- **Baselines and strict view** (external audit A4, A5, F-B1): what a fixed
  answer earns on measurements 3 and 4 (controls ``none``/``high`` and the most
  common required recommendation id on every finding), and what an empty SARIF
  earns per role, both scored by ``task_format/grade.py`` itself; measurements
  2 to 4 over matched findings only; and a strict view that counts every
  unfinished trial (errored, no SARIF, grader error, ``tool_outcome``) as a
  miss on positives and a failure on negatives.
- **Category means** leave out the categories a tool cannot emit (its ruleIds
  come from the CWE map, which never gives LLM03.EA.AUTONOMY) and read "too few
  tasks" when a category in them has fewer than 5 tasks on either side.
- **Harness effects**: findings the harness or the reviewer's filter removed or
  re-mapped before grading (SARIF run properties, else agent metadata).

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

Uses only the standard library (and, when present, task_format/grade.py and sast/cwe_map.py,
loaded read-only for the baselines and the categories a tool can emit).
"""

from __future__ import annotations

import argparse
import importlib.util
import inspect
import json
import re
import subprocess
import sys
import tempfile
from collections import Counter
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
#: Versions every report states: field -> the SARIF driver property that also records it.
VERSION_FIELDS = {"agent_version": None, "cwe_map": "cweMap", "heuristics": "heuristics",
                  "category_map": "categoryMap", "grader_version": None}
VERSION_LABELS = {"agent_version": "agent version", "cwe_map": "CWE map", "heuristics": "heuristics",
                  "category_map": "Claude category map", "grader_version": "grader version"}
#: A category mean (OWASP score) is only shown when every category in it has this many tasks on each side.
MIN_CATEGORY_TASKS = 5
#: Tools whose ruleId is decided by the frozen CWE map (sast/cwe_map.py), not by the tool. A Claude review
#: in stock mode is one too (its category goes through a CWE).
CWE_MAP_TOOLS = ("semgrep", "codeql", "sonarqube")
CLAUDE_TOOL = "claude-code-security-review"
#: The constant control answer of the measurement 3 baseline.
FIXED_CONTROLS = {"controlStatus": "none", "residualRisk": "high"}

ROOT = Path(__file__).resolve().parents[1]
GRADE_FILE = ROOT / "task_format" / "grade.py"
CWE_MAP_FILE = ROOT / "sast" / "cwe_map.py"
_MODULES: dict = {}


def _module(name: str, path: Path):
    """A repo module loaded from its file (as tools/snippet_ids.py loads grade.py), or None."""
    if name not in _MODULES:
        mod = None
        try:
            spec = importlib.util.spec_from_file_location(name, path)
            if spec is not None and spec.loader is not None:
                mod = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(mod)
        except Exception:  # noqa: BLE001  (a broken or missing module only hides the baselines)
            mod = None
        _MODULES[name] = mod
    return _MODULES[name]


def grader():
    """task_format/grade.py, the grader the tasks ship, or None when it cannot be loaded."""
    return _module("_report_grade", GRADE_FILE)


#: Parameter names the grader's functions may use, by the value they stand for.
_ALIASES = {"result": ("res", "result", "r"), "finding": ("f", "finding"),
            "ptol": ("ptol", "path_tol", "path_line_tolerance", "tol"), "truth": ("truth", "gt", "ground_truth"),
            "sarif_path": ("sarif_path", "sarif", "sarif_file")}


def _call(fn, **known):
    """Call a grader function by its parameter names, so a renamed or added optional parameter does not
    break the report. Raises TypeError when a required parameter is unknown."""
    args = []
    for name, param in inspect.signature(fn).parameters.items():
        value = next((known[k] for k, names in _ALIASES.items() if name in names and k in known), inspect._empty)
        if value is inspect._empty:
            if param.default is inspect._empty:
                raise TypeError(f"unknown required parameter {name}")
            break
        args.append(value)
    return fn(*args)


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
        # former_names lists every earlier name (the role-free task_<hex> ids, and the
        # task_<family>_<role> names before them); former_name is the most recent one.
        olds = [entry.get("former_name")] + list(entry.get("former_names") or [])
        for old in olds:
            if old:
                former[str(old)] = {**out[str(name)], "current_name": str(name)}
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


def strip_trial_suffix(name: str) -> str:
    """task_1496ad2e__itb9wZY -> task_1496ad2e (Harbor names a trial folder <task>__<suffix>)."""
    return name.rsplit("__", 1)[0] if "__" in name else name


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


def task_folders(trial: dict, tasks_dir: Path | None, variants: dict | None = None) -> list[Path]:
    """Where the task's folder may be: <tasks>/<task name>, the folder a former name was renamed to,
    and the task path recorded in the trial."""
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
    return candidates


def ground_truth(trial: dict, tasks_dir: Path | None, variants: dict | None = None) -> dict | None:
    """The task's ground truth from <tasks>/<task name>, else from the folder a former
    name was renamed to, else from the task path recorded in the trial."""
    for task in task_folders(trial, tasks_dir, variants):
        try:
            gt = task / "tests" / "ground_truth.json"
            if gt.is_file():
                return json.loads(gt.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
    return None


_FAMILY_TOML = re.compile(r'^\s*family_id\s*=\s*"([^"]+)"', re.M)


def task_family_id(trial: dict, tasks_dir: Path | None, variants: dict | None = None) -> str | None:
    """The task's own ``family_id`` (task_metadata.json, else task.toml), or None. It is the
    scanner-visible family key, unlike the private variant map's family name."""
    for task in task_folders(trial, tasks_dir, variants):
        meta = read_json_file(task / "task_metadata.json")
        if isinstance(meta, dict) and meta.get("family_id"):
            return str(meta["family_id"])
        try:
            match = _FAMILY_TOML.search((task / "task.toml").read_text(encoding="utf-8"))
        except OSError:
            match = None
        if match:
            return match.group(1)
    return None


def _max_matching(edges: list[set]) -> int:
    """Size of a maximum matching of findings (list index) to results (the set members)."""
    owner: dict = {}

    def augment(i: int, seen: set) -> bool:
        for j in edges[i]:
            if j in seen:
                continue
            seen.add(j)
            if j not in owner or augment(owner[j], seen):
                owner[j] = i
                return True
        return False
    return sum(augment(i, set()) for i in range(len(edges)))


def ground_truth_hits(rows: list, truth: dict) -> tuple[int, int, int]:
    """(gt findings, findings with a result near them, findings with a near result of an acceptable or
    primary CWE). A result counts for at most one finding: the counts are the sizes of a maximum
    matching of findings to the results near them, so one result within tolerance of two findings
    is one hit, not two."""
    findings = truth.get("findings") or []
    tol = (truth.get("matching") or {}).get("line_tolerance", 10)
    near_edges, cwe_edges = [], []
    for gt in findings:
        targets = [gt["primary_location"], *(gt.get("alternative_primary_locations") or [])]
        acceptable = set(gt.get("acceptable_cwes") or [])
        if gt.get("primary_cwe"):
            acceptable.add(gt["primary_cwe"])
        near_set, cwe_set = set(), set()
        for k, (_rule, cwes, file, start, end, _emitted) in enumerate(rows):
            for t in targets:
                t_end = t.get("end_line", t["start_line"])
                if file == t["file"] and start <= t_end + tol and end >= t["start_line"] - tol:
                    near_set.add(k)
                    if acceptable & set(cwes):
                        cwe_set.add(k)
        near_edges.append(near_set)
        cwe_edges.append(cwe_set)
    return len(findings), _max_matching(near_edges), _max_matching(cwe_edges)


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
        # grader v3.2: a contrast-family result anywhere in the scanned scope fails a negative.
        "neg_fail_in_scope": rewards.get("neg.fail.in_scope"),
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
        row = base_row(str(trial.get("task_name") or strip_trial_suffix(result_file.parent.name)).split("/")[-1],
                       rewards,
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
            "run_info": run_info(meta, result_file.parent),
        })
        row.update(trial_extras(meta, result_file.parent, truth, task_family_id(
            {**trial, "task_name": row["task"]}, tasks_dir, variants)))
        if row.get("grader_version") and isinstance(row.get("run_info"), dict):
            row["run_info"]["grader_version"] = row["grader_version"]
        out.append(row)
    return out


def matched_scores(trial_dir: Path) -> list | None:
    """The measurement scores of every matched finding (verifier/grading_detail.json), or None."""
    detail = read_json_file(trial_dir / "verifier" / "grading_detail.json")
    if not isinstance(detail, dict):
        return None
    return [dict(f.get("scores") or {}) for f in detail.get("per_finding") or []
            if isinstance(f, dict) and f.get("matched")]


def detail_info(trial_dir: Path) -> dict:
    """From grading_detail.json (grader v3.2): the grader version, the results that claimed a complete
    control (neither failing a negative nor counted as a false positive), and the matched findings
    credited across risk families through the CWE. Missing fields read as None."""
    detail = read_json_file(trial_dir / "verifier" / "grading_detail.json")
    if not isinstance(detail, dict):
        return {"grader_version": None, "complete_claims": None, "cross_family": None}
    per = [f for f in detail.get("per_finding") or [] if isinstance(f, dict) and f.get("matched")]
    claims = detail.get("complete_claims")
    return {"grader_version": str(detail["grader_version"]) if detail.get("grader_version") else None,
            "complete_claims": len(claims) if isinstance(claims, list) else None,
            "cross_family": sum(1 for f in per if f.get("cross_family")) if any("cross_family" in f for f in per)
            else (0 if per and "grader_version" in detail else None)}


def trial_extras(meta: dict, trial_dir: Path, truth: dict | None, family_id: str | None) -> dict:
    """Fields every row carries on top of base_row. ``_truth`` (the ground truth, for the baselines)
    starts with an underscore, so it is left out of every file the reports write."""
    outcome = meta.get("tool_outcome")
    info = detail_info(trial_dir)
    return {
        **info,
        "tool_outcome": (outcome if isinstance(outcome, str) else json.dumps(outcome)) if outcome else None,
        "family_id": family_id,
        "matched_scores": matched_scores(trial_dir),
        "harness": harness_effects(meta, trial_dir),
        "_truth": truth,
    }


def public_row(row: dict) -> dict:
    """A row without its private fields (the ground truth), as the reports write it."""
    return {k: v for k, v in row.items() if not str(k).startswith("_")}


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
        # The task name from the trial's result.json, else the folder name without Harbor's __<suffix>,
        # so the variant map and the task folders are looked up under the task's own name.
        trial = read_json_file(trial_dir / "result.json")
        trial = trial if isinstance(trial, dict) else {}
        task = str(trial.get("task_name") or strip_trial_suffix(trial_dir.name)).split("/")[-1]
        truth = ground_truth({**trial, "task_name": task}, tasks_dir, variants) if tasks_dir is not None else None
        row = base_row(task, json.loads(f.read_text(encoding="utf-8")), truth=truth, variants=variants)
        row["trial"] = trial_dir.name
        meta = _trial_metadata(f)
        if meta:
            row["tool"] = meta.get("tool") or meta.get("agent")
            row["emitted"] = meta.get("results_emitted")
            if meta.get("status") and row["status"] == "ok":
                row["status"] = meta["status"]
        row["has_truth"] = truth is not None
        row["sarif_fields"] = sarif_fields(trial_dir)
        row["run_info"] = run_info(meta, trial_dir)
        row.update(trial_extras(meta, trial_dir, truth, task_family_id(
            {**trial, "task_name": task}, tasks_dir, variants) if tasks_dir is not None else None))
        if row.get("grader_version") and isinstance(row.get("run_info"), dict):
            row["run_info"]["grader_version"] = row["grader_version"]
        rows.append(row)
    return rows


SAST_ARTIFACTS = Path("artifacts") / "logs" / "artifacts" / "sast"


def sarif_driver_properties(trial_dir: Path) -> dict:
    """properties of the graded SARIF's tool driver (cweMap, heuristics, categoryMap, mode, ...), or {}."""
    for candidate in (trial_dir / "agent" / "findings.sarif", trial_dir / SAST_ARTIFACTS / "findings.sarif"):
        data = read_json_file(candidate)
        if not isinstance(data, dict):
            continue
        for run in data.get("runs") or []:
            props = (((run or {}).get("tool") or {}).get("driver") or {}).get("properties")
            if isinstance(props, dict):
                return props
        return {}
    return {}


def _json_object(path: Path) -> dict:
    data = read_json_file(path)
    return data if isinstance(data, dict) else {}


def run_info(meta: dict | None, trial_dir: Path | None = None) -> dict:
    """The versions a trial was graded under and, for a Claude review run, its mode, auth and how many
    findings the category map dropped. Read from the agent metadata, else the metadata.json and
    claude_review.json the agent saved, else the graded SARIF's driver properties."""
    meta = dict(meta or {})
    review_file: dict = {}
    driver: dict = {}
    if trial_dir is not None:
        if not all(meta.get(k) for k in ("agent_version", "cwe_map", "heuristics")):
            meta = {**_json_object(trial_dir / SAST_ARTIFACTS / "metadata.json"), **meta}
        review_file = _json_object(trial_dir / SAST_ARTIFACTS / "claude_review.json")
        driver = sarif_driver_properties(trial_dir)
    review = meta.get("claude_review") if isinstance(meta.get("claude_review"), dict) else {}
    info: dict = {}
    for field, prop in VERSION_FIELDS.items():
        value = meta.get(field) or review.get(field) or (driver.get(prop) if prop else None)
        info[field] = str(value) if value else None
    if not (review or review_file or info["category_map"]):
        info["claude"] = None
        return info
    options = review.get("request_options") or review_file.get("request_options") or {}
    mode = meta.get("mode") or review.get("mode") or options.get("mode") or driver.get("mode")
    by_category = meta.get("unmapped_by_category")
    unmapped = meta.get("findings_unmapped")
    if isinstance(by_category, dict) and by_category:
        dropped = sum(int(v or 0) for v in by_category.values())
    elif isinstance(by_category, dict) or isinstance(unmapped, int):
        dropped = int(unmapped or 0)
    else:
        dropped = None
    info["claude"] = {
        "mode": str(mode) if mode else None,
        "auth": (meta.get("auth") or review.get("auth") or review_file.get("auth") or options.get("auth")
                 or driver.get("auth")),
        "results_label": review.get("results_label") or review_file.get("results_label"),
        "filter_mode": meta.get("filter_mode") or review.get("filter_mode") or review_file.get("filter_mode"),
        "model": meta.get("model") or review.get("model") or driver.get("model"),
        "unmapped_by_category": dict(by_category) if isinstance(by_category, dict) else None,
        "dropped_unmapped": dropped,
    }
    return info


#: What the harness or the reviewer's false-alarm filter removed or changed before grading, by the
#: field that records it: (label, keys in the SARIF run properties, keys in the agent metadata).
HARNESS_FIELDS = (
    ("filter_excluded", "excluded by the false-alarm filter",
     ("findings_excluded", "filter_excluded", "excluded"), ("claude_review.findings_excluded",)),
    ("unmapped_category", "dropped, category not in the category map",
     ("unmapped_by_category", "findings_unmapped_category"), ("unmapped_by_category",)),
    ("remapped", "re-mapped to another rule or risk type",
     ("findings_remapped", "remapped", "remapped_by_category", "re_mapped"), ("findings_remapped",)),
    ("unmapped_cwe", "dropped, no rule for its CWE",
     ("findings_unmapped", "unmapped_by_cwe"), ()),
    ("ambiguous_cwe", "dropped, CWEs in two risk families",
     ("results_cwe_ambiguous", "findings_ambiguous"), ("results_cwe_ambiguous",)),
    ("bad_location", "dropped, location not usable",
     ("dropped_bad_location_count", "dropped_bad_location"), ("dropped_bad_location_count",)),
    ("out_of_scope", "dropped, outside the scanned files",
     ("dropped_out_of_scope_count", "dropped_out_of_scope"), ("dropped_out_of_scope_count",)),
)
HARNESS_WORDS = ("excluded", "dropped", "unmapped", "remapped", "re_mapped", "filtered")


def _count(value) -> int | None:
    """A count from an int, a list (its length) or a dict of counts (their sum)."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, list):
        return len(value)
    if isinstance(value, dict):
        nums = [v for v in value.values() if isinstance(v, int) and not isinstance(v, bool)]
        return sum(nums) if nums or not value else None
    return None


def sarif_run_properties(trial_dir: Path) -> dict:
    """The merged ``runs[].properties`` of the graded SARIF, or {}."""
    for candidate in (trial_dir / "agent" / "findings.sarif", trial_dir / SAST_ARTIFACTS / "findings.sarif"):
        data = read_json_file(candidate)
        if not isinstance(data, dict):
            continue
        out: dict = {}
        for run in data.get("runs") or []:
            props = (run or {}).get("properties") if isinstance(run, dict) else None
            if isinstance(props, dict):
                out.update(props)
        return out
    return {}


def harness_effects(meta: dict | None, trial_dir: Path | None = None) -> dict:
    """{label: count} of findings the harness or the reviewer's filter removed or changed before
    grading, from the SARIF run properties first, else the agent metadata. Unknown run-property keys
    that name a drop, exclusion or re-mapping are kept under their own name. Empty when nothing is
    recorded."""
    meta = meta or {}
    props = sarif_run_properties(trial_dir) if trial_dir is not None else {}
    review = meta.get("claude_review") if isinstance(meta.get("claude_review"), dict) else {}
    out: dict = {}
    used = set()
    for _key, label, prop_keys, meta_keys in HARNESS_FIELDS:
        value = None
        for k in prop_keys:
            if k in props:
                used.add(k)
                value = _count(props[k]) if value is None else value
        if value is None:
            for k in meta_keys:
                source = review if k.startswith("claude_review.") else meta
                v = source.get(k.split(".", 1)[1] if k.startswith("claude_review.") else k)
                if v is not None and _count(v) is not None:
                    value = _count(v)
                    break
        if value is not None:
            out[label] = value
    for k, v in props.items():
        if k not in used and any(w in k.lower() for w in HARNESS_WORDS) and _count(v) is not None:
            out[k] = _count(v)
    return out


def _git(folder: str, *args: str) -> str | None:
    try:
        proc = subprocess.run(["git", "-C", folder, *args], capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return None
    return proc.stdout if proc.returncode == 0 else None


def task_set_state(tasks_dir: Path | None) -> dict | None:
    """The git commit of the task folder and whether its work tree is dirty, or None when the folder
    is not in a git work tree or git is not available."""
    if tasks_dir is None or not Path(tasks_dir).is_dir():
        return None
    folder = str(Path(tasks_dir).resolve())
    head = _git(folder, "rev-parse", "HEAD")
    if not head:
        return None
    status = _git(folder, "status", "--porcelain", "--", ".")
    changed = [line for line in (status or "").splitlines() if line.strip()]
    return {"commit": head.strip(), "dirty": bool(changed) if status is not None else None,
            "changed_files": len(changed) if status is not None else None}


def task_set_text(state: dict | None) -> str:
    if not state:
        return "not recorded (no --tasks folder in a git work tree, or git is not available)"
    if state["dirty"] is None:
        tree = "work tree state unknown"
    elif state["dirty"]:
        tree = f"work tree dirty, {state['changed_files']} changed file(s)"
    else:
        tree = "work tree clean"
    return f"git commit {state['commit'][:12]} ({tree})"


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


def category_of(rule_id: str) -> str:
    """OWASP-style category as the grader names it: LLM02.SID (severity dropped), LLM03.EA.<SUBTYPE>."""
    parts = (rule_id or "").split(".")
    if parts[0] == "LLM02":
        return ".".join(parts[:2])
    if parts[0] == "LLM03":
        return ".".join(parts[:3])
    return rule_id or ""


def cwe_map_rules() -> set:
    """The task ruleIds the frozen CWE map can give a result (sast/cwe_map.py, read only). An LLM02
    family entry can come out as HIGH or MEDIUM. Without the module, every rule but AUTONOMY."""
    mod = _module("_report_cwe_map", CWE_MAP_FILE)
    table = getattr(mod, "CWE_MAP", None) if mod is not None else None
    if not isinstance(table, dict):
        return set(TAXONOMY) - {"LLM03.EA.AUTONOMY"}
    rules = {v[0] if isinstance(v, (tuple, list)) else v for v in table.values()}
    if any(str(r).startswith("LLM02.") for r in rules):
        rules |= {"LLM02.SID.HIGH", "LLM02.SID.MEDIUM"}
    return {str(r) for r in rules}


def rule_source(row: dict) -> str | None:
    """"cwe_map" when the trial's ruleIds come from the CWE map (Semgrep, CodeQL, SonarQube, a stock
    Claude review), "tool" when the tool names them itself (a scoped Claude review), None if unknown."""
    tool = str(row.get("tool") or "")
    if tool in CWE_MAP_TOOLS:
        return "cwe_map"
    if tool == CLAUDE_TOOL:
        mode = str((((row.get("run_info") or {}).get("claude") or {}).get("mode")) or "")
        return {"stock": "cwe_map", "scoped": "tool"}.get(mode)
    return None


def cannot_emit_categories(rows: list[dict]) -> list[str]:
    """Taxonomy categories the tool cannot report at all: when every trial's ruleIds come from the
    CWE map, the categories no mapped CWE reaches (LLM03.EA.AUTONOMY under cwe-map-5)."""
    sources = {rule_source(r) for r in rows if r.get("tool")}
    if sources != {"cwe_map"}:
        return []
    reachable = {category_of(r) for r in cwe_map_rules()}
    return sorted({category_of(r) for r in TAXONOMY} - reachable)


def category_table(rows: list[dict], cannot_emit: list[str] | None = None) -> dict:
    """Per category TP, FN, TN, FP, rates and the Youden score, and the means over categories.

    Categories the tool cannot emit (``cannot_emit``, by default from :func:`cannot_emit_categories`)
    stay in the table, marked, and are left out of the means. The means are kept in the data but
    ``suppressed`` is set when no category is left or any category in them has fewer than
    MIN_CATEGORY_TASKS tasks on either side: the reports then print "too few tasks" instead."""
    cannot = set(cannot_emit_categories(rows) if cannot_emit is None else cannot_emit)
    cats: dict[str, dict] = {}
    for r in usable(rows):
        for cat, flags in r["categories"].items():
            c = cats.setdefault(cat, {"TP": 0, "FN": 0, "TN": 0, "FP": 0})
            truth, det = flags.get("truth", 0), flags.get("detected", 0)
            c[{(1, 1): "TP", (1, 0): "FN", (0, 1): "FP", (0, 0): "TN"}[(truth, det)]] += 1
    for k, c in cats.items():
        c["positives"] = c["TP"] + c["FN"]
        c["negatives"] = c["FP"] + c["TN"]
        c["TPR"] = ratio(c["TP"], c["positives"])
        c["FPR"] = ratio(c["FP"], c["negatives"])
        c["youden"] = c["TPR"] - c["FPR"] if c["TPR"] is not None and c["FPR"] is not None else None
        c["cannot_emit"] = k in cannot
    # Means over the categories that have both sides and that the tool can emit, so the score is the
    # mean of the per-category scores.
    scored = {k: c for k, c in cats.items() if c["youden"] is not None and not c["cannot_emit"]}
    tp = sum(c["TP"] for c in cats.values())
    fp = sum(c["FP"] for c in cats.values())
    fn = sum(c["FN"] for c in cats.values())
    mean_tpr = sum(c["TPR"] for c in scored.values()) / len(scored) if scored else None
    mean_fpr = sum(c["FPR"] for c in scored.values()) / len(scored) if scored else None
    precision = ratio(tp, tp + fp)
    f1 = (2 * precision * mean_tpr / (precision + mean_tpr)
          if precision is not None and mean_tpr is not None and precision + mean_tpr else None)
    too_few = sorted(k for k, c in scored.items()
                     if c["positives"] < MIN_CATEGORY_TASKS or c["negatives"] < MIN_CATEGORY_TASKS)
    overall = {
        "categories": len(scored), "mean_TPR": mean_tpr, "mean_FPR": mean_fpr,
        "score": mean_tpr - mean_fpr if mean_tpr is not None and mean_fpr is not None else None,
        "precision_pooled": precision, "recall_pooled": ratio(tp, tp + fn), "F1": f1,
        "categories_one_sided": sorted(k for k, c in cats.items() if c["youden"] is None),
        "excluded_cannot_emit": sorted(k for k in cats if k in cannot),
        "cannot_emit": sorted(cannot),
        "min_tasks_per_side": MIN_CATEGORY_TASKS,
        "too_few_tasks": too_few,
        "suppressed": bool(too_few) or not scored,
    }
    return {"per_category": dict(sorted(cats.items())), "overall": overall}


TOO_FEW = "too few tasks"


def macro_text(overall: dict, key: str) -> str:
    """A category mean as the reports print it: "too few tasks" when suppressed, else the value."""
    if overall.get("suppressed"):
        return TOO_FEW
    return fmt(overall.get(key)) or "n/a"


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
    """Per measurement 2 to 4: True when a scored result carries a field the grader reads, False
    when the SARIFs were readable, a scored positive had a matched result and no result carried it,
    None when that cannot be told: no SARIF could be read (``undetermined`` "no_sarif") or no
    scored positive had a matched result (``undetermined`` "no_results")."""
    known = [r["sarif_fields"] for r in usable(rows) if r.get("sarif_fields") is not None]
    # The grader reads the fields on matched results only, so a tool that matched nothing gives
    # no evidence either way.
    matched = sum(r["tp"] or 0 for r in by_role(rows, "positive"))
    out = {}
    undetermined = {}
    for measure, fields in SUPPORT_FIELDS.items():
        if not known:
            out[measure] = None
            undetermined[measure] = "no_sarif"
        elif any(k.get(f, 0) for k in known for f in fields):
            out[measure] = True
        elif not matched:
            out[measure] = None
            undetermined[measure] = "no_results"
        else:
            out[measure] = False
    out["undetermined"] = undetermined
    out["matched_results"] = matched
    out["results_with"] = {f: sum(k.get(f, 0) for k in known)
                           for f in ("codeFlows", "controlStatus", "residualRisk", "recommendations")}
    out["sarifs_read"] = len(known)
    return out


def measurement_means(rows: list[dict]) -> dict:
    positives = by_role(rows, "positive")
    support = measurement_support(rows)
    out = {"tasks": len(positives)}
    for m in MEASURES:
        if support.get(m) is False or support["undetermined"].get(m) == "no_results":
            out[m] = None
        else:
            out[m] = sum(r[m] or 0 for r in positives) / len(positives) if positives else None
    out["supported"] = {m: support[m] for m in SUPPORT_FIELDS}
    out["no_results"] = [m for m in SUPPORT_FIELDS if support["undetermined"].get(m) == "no_results"]
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
    # A task run more than once (harbor -k N) adds its findings once per run. gt_distinct counts them once.
    runs = Counter(r["task"] for r in positives)
    gt_by_task: dict = {}
    for r in positives:
        if gt_by_task.get(r["task"]) is None:
            gt_by_task[r["task"]] = r["gt"]
    gt_distinct = sum(v or 0 for v in gt_by_task.values())
    precision = tp / (tp + fp) if tp + fp else None  # undefined with no result
    recall = tp / gt if gt else (0.0 if positives else None)
    if precision is None or recall is None:
        f1 = None
    else:
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {"tasks": len(positives), "gt": gt, "tp": tp, "fp": fp, "fn": fn,
            "distinct_tasks": len(runs), "gt_distinct": gt_distinct, "runs_per_task": sorted(set(runs.values())),
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
    # Any result at all on the fixed app, counted or not (results away from the fixed code cost nothing).
    out["negative"]["any_result"] = sum(1 for r in negs if has_result(r))
    out["negative"]["failed_near_fix"] = sum(1 for r in negs if r.get("neg_fail_near_fix"))
    out["negative"]["failed_trap"] = sum(1 for r in negs if r.get("neg_fail_trap"))
    out["negative"]["failed_in_scope"] = sum(1 for r in negs if r.get("neg_fail_in_scope"))
    out["unknown_role"] = sum(1 for r in rows if r.get("role") not in ROLES)
    return out


def has_result(row: dict) -> bool:
    """Whether the trial wrote any result, from the agent's count, else the SARIF, else the grader."""
    n = _emitted(row)
    if n is None:
        n = (row.get("tp") or 0) + (row.get("fp") or 0) + (row.get("fp_out") or 0)
    return n > 0


# ---- strict view and baselines ---------------------------------------------------------------

def unfinished(row: dict) -> bool:
    """A trial the strict view counts as a miss (positive) or a failure (negative): it errored, its
    agent reported an error, it had no SARIF, the grader crashed, or the agent recorded a
    ``tool_outcome`` (it ended without a usable answer). A trial graded under an old role is not one."""
    if row.get("role") not in ROLES or row.get("status") == "graded_as_old_role":
        return False
    return not is_scored(row) or bool(row.get("tool_outcome"))


def strict_view(rows: list[dict]) -> dict:
    """The scored-only numbers recomputed with every unfinished trial in: a positive scores 0 and
    finds nothing, a negative fails and scores 0."""
    out: dict = {}
    for role in ROLES:
        done = [r for r in by_role(rows, role) if not r.get("tool_outcome")]
        missed = [r for r in rows if r.get("role") == role and unfinished(r)]
        n = len(done) + len(missed)
        entry = {"tasks": n, "unfinished": len(missed),
                 "reasons": dict(Counter((f"tool_outcome {r['tool_outcome']}" if r.get("tool_outcome")
                                          else r["status"]) for r in missed)),
                 "mean_reward": sum(r["reward"] for r in done) / n if n else None}
        if role == "positive":
            gt = sum(r["gt"] or 0 for r in done) + sum(r["gt"] or 0 for r in missed)
            tp = sum(r["tp"] or 0 for r in done)
            entry.update({"tp": tp, "gt": gt, "gt_unknown": sum(1 for r in missed if r["gt"] is None),
                          "recall": tp / gt if gt else None})
        else:
            entry["failed"] = sum(1 for r in done if r["reward"] < 1.0) + len(missed)
        out[role] = entry
    out["differs"] = any(out[role]["unfinished"] for role in ROLES)
    return out


def _findings(truth: dict | None) -> list:
    return [f for f in (truth or {}).get("findings") or [] if isinstance(f, dict)]


def common_recommendation(truths: list) -> str | None:
    """The recommendation id named most often in ``required_any_of`` over the findings (ties: the first
    by name), or None."""
    counts: Counter = Counter()
    for truth in truths:
        for f in _findings(truth):
            spec = f.get("recommendations") if isinstance(f.get("recommendations"), dict) else {}
            counts.update({r for r in spec.get("required_any_of") or [] if isinstance(r, str)})
    if not counts:
        return None
    top = max(counts.values())
    return sorted(k for k, v in counts.items() if v == top)[0]


def _fixed_scores(truth: dict, rec_id: str | None) -> dict | None:
    """What one fixed answer earns on each finding of a positive, scored by the grader's own functions:
    controls ``none``/``high`` and recommendations ``[rec_id]``. Per finding and per task (the
    grader's per-task mean over the task's findings). None when the grader cannot score it."""
    g = grader()
    findings = _findings(truth)
    if g is None or not findings:
        return None
    matching = truth.get("matching") or {}
    ptol = matching.get("path_line_tolerance", matching.get("line_tolerance", 10))
    per: dict = {"controls": [], "recommendations": []}
    try:
        for f in findings:
            base = {"ruleId": f.get("rule_id", ""), "locations": []}
            res = {**base, "properties": dict(FIXED_CONTROLS)}
            if hasattr(g, "score_controls"):
                ctrl = _call(g.score_controls, result=res, finding=f, ptol=ptol, truth=truth)
                ctrl = ctrl[0] if isinstance(ctrl, (tuple, list)) else ctrl
            else:
                ctrl = _call(g.score_match, result=res, finding=f, ptol=ptol, truth=truth)["controls"]
            per["controls"].append(float(ctrl))
            if rec_id is not None:
                rec = _call(g.score_recs, result={**base, "properties": {"recommendations": [rec_id]}},
                            finding=f, ptol=ptol, truth=truth)
                per["recommendations"].append(float(rec[0] if isinstance(rec, (tuple, list)) else rec))
    except Exception:  # noqa: BLE001  (a ground truth the grader cannot read has no baseline)
        return None
    return {k: {"findings": v, "task": sum(v) / len(findings)} for k, v in per.items() if v}


def fixed_answer_baselines(rows: list[dict], rec_id: str | None = None) -> dict:
    """Measurement 3 and 4 baselines over the scored positives: every finding answered with controls
    ``none``/``high``, and with the one most common required recommendation id. ``per_app`` is
    comparable with the measurement means (a mean over the positives), ``per_finding`` with the
    matched-findings means."""
    positives = [r for r in by_role(rows, "positive") if r.get("_truth")]
    if rec_id is None:
        rec_id = common_recommendation([r["_truth"] for r in positives])
    out: dict = {"controls_answer": dict(FIXED_CONTROLS), "recommendation_id": rec_id}
    scored = [sc for sc in (_fixed_scores(r["_truth"], rec_id) for r in positives) if sc]
    for key in ("controls", "recommendations"):
        tasks = [sc[key] for sc in scored if key in sc]
        per_finding = [v for t in tasks for v in t["findings"]]
        out[key] = {"tasks": len(tasks), "findings": len(per_finding),
                    "per_app": sum(t["task"] for t in tasks) / len(tasks) if tasks else None,
                    "per_finding": sum(per_finding) / len(per_finding) if per_finding else None}
    return out


EMPTY_SARIF = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "empty-report-baseline"}}, "results": []}]}
_EMPTY_CACHE: dict = {}


def empty_sarif_reward(truth: dict) -> float | None:
    """The reward the grader gives an empty SARIF on this ground truth, or None when it cannot grade."""
    g = grader()
    if g is None or not isinstance(truth, dict):
        return None
    key = json.dumps(truth, sort_keys=True, default=str)
    if key not in _EMPTY_CACHE:
        value = None
        try:
            with tempfile.TemporaryDirectory() as folder:
                path = Path(folder) / "findings.sarif"
                path.write_text(json.dumps(EMPTY_SARIF), encoding="utf-8")
                summary = _call(g.grade, sarif_path=path, truth=truth)
                summary = summary[0] if isinstance(summary, tuple) else summary
                value = float(summary["reward"])
        except Exception:  # noqa: BLE001
            value = None
        _EMPTY_CACHE[key] = value
    return _EMPTY_CACHE[key]


def empty_sarif_baseline(rows: list[dict]) -> dict:
    """The mean reward an empty SARIF earns on the trials' tasks (each task once), per role and over
    all of them, graded by the current grader."""
    tasks: dict = {}
    for r in rows:
        if r.get("role") in ROLES and r.get("_truth") and r["task"] not in tasks:
            tasks[r["task"]] = (r["role"], empty_sarif_reward(r["_truth"]))
    out: dict = {}
    for role in (*ROLES, "all"):
        values = [v for rl, v in tasks.values() if v is not None and role in (rl, "all")]
        out[role] = {"tasks": len(values), "mean_reward": sum(values) / len(values) if values else None}
    return out


def matched_means(rows: list[dict]) -> dict:
    """Measurements 2 to 4 over the matched findings only (the per-finding scores in
    grading_detail.json), next to the means over every positive, where a missed finding scores 0."""
    scores = [sc for r in by_role(rows, "positive") for sc in (r.get("matched_scores") or [])]
    out: dict = {"findings": len(scores)}
    for m in SUPPORT_FIELDS:
        values = [sc[m] for sc in scores if isinstance(sc.get(m), (int, float))]
        out[m] = sum(values) / len(values) if values else None
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


def run_versions(rows: list[dict]) -> dict:
    """Over every trial: each version field's values and counts, the fields with more than one
    value (``mixed``), and the Claude review runs' mode, auth, results label and dropped categories."""
    infos = [r.get("run_info") or {} for r in rows]
    fields = {}
    for field in VERSION_FIELDS:
        fields[field] = dict(Counter(i[field] for i in infos if i.get(field)).most_common())
    claude_infos = [i["claude"] for i in infos if i.get("claude")]
    claude = None
    if claude_infos:
        dropped_known = [c["dropped_unmapped"] for c in claude_infos if c.get("dropped_unmapped") is not None]
        by_category: Counter = Counter()
        for c in claude_infos:
            by_category.update(c.get("unmapped_by_category") or {})
        claude = {
            "trials": len(claude_infos),
            **{key: dict(Counter(str(c[key]) for c in claude_infos if c.get(key)).most_common())
               for key in ("mode", "auth", "results_label", "filter_mode", "model")},
            "dropped_unmapped": sum(dropped_known) if dropped_known else None,
            "dropped_unknown_trials": len(claude_infos) - len(dropped_known),
            "unmapped_by_category": dict(by_category.most_common()),
        }
    return {"fields": fields, "mixed": [f for f, v in fields.items() if len(v) > 1], "claude": claude}


def counted(values: dict) -> str:
    """{"a": 3} -> "a", {"a": 3, "b": 1} -> "a (3), b (1)", {} -> "not recorded"."""
    if not values:
        return "not recorded"
    if len(values) == 1:
        return next(iter(values))
    return ", ".join(f"{k} ({v})" for k, v in values.items())


def versions_text(versions: dict) -> str:
    f = versions["fields"]
    if not any(f.values()):
        return "versions not recorded (no agent metadata or SARIF driver properties)"
    return "graded under " + ", ".join(f"{VERSION_LABELS[k]} {counted(f[k])}" for k in VERSION_FIELDS
                                       if k != "category_map" or f[k])


def mixed_versions_warning(versions: dict, where: str = "the trials") -> str | None:
    if not versions["mixed"]:
        return None
    parts = [f"{VERSION_LABELS[k]} {counted(versions['fields'][k])}" for k in versions["mixed"]]
    return (f"mixed versions across {where}: " + ", ".join(parts) + ". Results graded under different "
            "versions are not directly comparable.")


def stock_mode_caveat(versions: dict) -> str | None:
    """The limitation every report that quotes stock-mode numbers states, or None."""
    claude = versions.get("claude")
    if not claude or "stock" not in claude["mode"]:
        return None
    cmap = counted(versions["fields"].get("category_map") or {})
    if claude["dropped_unmapped"] is None:
        dropped = "the number dropped is not recorded"
    else:
        dropped = f"{claude['dropped_unmapped']} finding(s) were dropped this way"
        if claude["dropped_unknown_trials"]:
            dropped += f" (not recorded for {claude['dropped_unknown_trials']} trial(s))"
        top = list(claude["unmapped_by_category"].items())[:5]
        if top:
            dropped += " (" + ", ".join(f"{k} x{v}" for k, v in top) + ")"
    return ("stock mode: the upstream reviewer reports a free-text category, which is mapped to a CWE by exact "
            f"lookup in the frozen category map {cmap}. Categories outside the map are dropped before grading, "
            f"and {dropped}. Stock-mode scores therefore measure the category map as well as the reviewer.")


def claude_text(versions: dict) -> str | None:
    claude = versions.get("claude")
    if not claude:
        return None
    return (f"Claude review ({claude['trials']} trials): mode {counted(claude['mode'])}, auth "
            f"{counted(claude['auth'])}, results {counted(claude['results_label'])}.")


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

NO_RESULTS_MEASURE = "n/a (no results)"

HARBOR_MEAN_WARNING = ("Harbor's job-level means (result.json) average positives and negatives together, "
                       "for the reward and for every sub-score, so such a mean is not a score: an empty SARIF "
                       "earns 1.0 on every negative. Quote the pooled detection, category and per-role figures "
                       "instead.")


def harness_totals(rows: list[dict]) -> dict:
    """The harness and filter effects summed over the trials: {label: count}."""
    total: Counter = Counter()
    for r in rows:
        total.update(r.get("harness") or {})
    return dict(total)


def summarise(rows: list[dict], tasks_dir: Path | None = None, rec_id: str | None = None) -> dict:
    """``rec_id``: the recommendation id of the measurement 4 baseline, by default the most common
    required one over these trials' ground truths."""
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
        "measurements_matched_only": matched_means(rows),
        "fixed_answer_baselines": fixed_answer_baselines(rows, rec_id),
        "empty_sarif_baseline": empty_sarif_baseline(rows),
        "strict": strict_view(rows),
        "harness_effects": harness_totals(rows),
        "taxonomy_coverage": taxonomy_coverage(rows),
        "versions": run_versions(rows),
        "task_set": task_set_state(tasks_dir),
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
    if key in (m.get("no_results") or []):
        return NO_RESULTS_MEASURE
    return fmt(m.get(key))


def gt_text(det: dict) -> str:
    """Ground-truth findings on scored positives, saying when repeated runs count a finding more than once."""
    gt, distinct = det["gt"], det.get("gt_distinct", det["gt"])
    if gt == distinct:
        return str(gt)
    runs = det.get("runs_per_task") or []
    if len(runs) == 1:
        return f"{gt} ({distinct} findings x {runs[0]} runs)"
    return f"{gt} over all runs ({distinct} distinct findings)"


def not_scored_text(det: dict) -> str:
    """What recall leaves out on the positives that were not scored, including counts that are unknown."""
    n, unknown = det["tasks_not_scored"], det.get("gt_not_scored_unknown", 0)
    known = det["gt_not_scored"]
    findings = f"{known} finding{'' if known == 1 else 's'}"
    if unknown == n:
        findings = "an unknown number of findings"
    elif unknown:
        findings += f" (and an unknown number on {unknown} of them, whose ground truth was not found)"
    were = "positive that was" if n == 1 else "positives that were"
    return f"recall leaves out {findings} on {n} {were} not scored"


def render(rows: list[dict], summary: dict, table=text_table) -> str:
    out = []
    for tool in summary["no_results_emitted"]:
        graded = summary["results_emitted_by_tool"][tool]["graded"]
        out.append("WARNING: " + NO_RESULTS_WARNING.format(tool=tool, graded=graded))
    versions = summary.get("versions")
    if versions:
        for text in (mixed_versions_warning(versions), stock_mode_caveat(versions)):
            if text:
                out.append("WARNING: " + text)
    if out:
        out.append("")
    if versions:
        out.append(versions_text(versions) + f", task set {task_set_text(summary.get('task_set'))}")
        if claude_text(versions):
            out.append(claude_text(versions))
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
        out.append(f"detection, pooled over {det['tasks']} scored positives ({gt_text(det)} ground-truth findings):")
        out.append(f"  tp {det['tp']}  fp {det['fp']}  fn {det['fn']}  precision {fmt(det['precision']) or 'n/a'}  "
                   f"recall {fmt(det['recall']) or 'n/a'}  F1 {fmt(det['F1']) or 'n/a'}")
        if det["tasks_not_scored"]:
            out.append("  " + not_scored_text(det))
        with_meta = [r for r in by_role(rows, "positive") if r.get("near") is not None]
        if with_meta:
            gt_meta = sum(r["gt"] or 0 for r in with_meta)
            out.append(f"  location recall (any security finding, any OWASP side): "
                       f"{sum(r['near'] for r in with_meta)}/{gt_meta}")
            out.append(f"  location + acceptable-CWE recall: {sum(r['near_cwe'] for r in with_meta)}/{gt_meta}"
                       " (each result counts for at most one finding)")
    clean, zero = summary["zero_finding_tasks_clean"]
    if zero:
        out.append(f"negatives clean (fp == 0): {clean}/{zero}, negatives with any result in scope: "
                   f"{summary['reward_by_role']['negative'].get('any_result', 0)}/{zero}")
    roles = summary["reward_by_role"]
    pos, neg = roles["positive"], roles["negative"]
    if pos["tasks"]:
        out.append(f"mean task reward, positives only ({pos['tasks']} tasks): {fmt(pos['mean_reward'])}")
    if neg["tasks"]:
        out.append(f"mean task reward, negatives only ({neg['tasks']} tasks): {fmt(neg['mean_reward'])}  "
                   f"(failed {neg['failed']}: near the fix {neg['failed_near_fix']}, on a trap {neg['failed_trap']}, "
                   f"anywhere in scope {neg.get('failed_in_scope', 0)})")
    strict = summary.get("strict") or {}
    if strict.get("differs"):
        sp, sn = strict["positive"], strict["negative"]
        out.append(f"strict view (errored, no SARIF, grader error or tool_outcome counted as a miss on positives "
                   f"and a failure on negatives): recall {fmt(sp.get('recall')) or 'n/a'} ({sp.get('tp', 0)}/"
                   f"{sp.get('gt', 0)}), mean reward positives {fmt(sp['mean_reward']) or 'n/a'} over "
                   f"{sp['tasks']}, negatives failed {sn.get('failed', 0)}/{sn['tasks']}, mean reward negatives "
                   f"{fmt(sn['mean_reward']) or 'n/a'}")
    empty = summary.get("empty_sarif_baseline") or {}
    if any((empty.get(k) or {}).get("tasks") for k in ROLES):
        out.append("empty SARIF baseline (current grader): " + ", ".join(
            f"{label} {fmt(empty[k]['mean_reward']) or 'n/a'} over {empty[k]['tasks']}"
            for k, label in (("positive", "positives"), ("negative", "negatives"), ("all", "all tasks"))))
    out.append(f"warning: {summary['warning']}")
    out.append(f"fp_outside_scope total: {summary['fp_outside_scope']}")
    harness = summary.get("harness_effects") or {}
    if any(harness.values()):
        out.append("removed or changed before grading (harness and filter effects, not scanner false alarms): "
                   + ", ".join(f"{k} {v}" for k, v in harness.items()))

    cats = summary["categories"]
    if cats["per_category"]:
        out.append("\ncategories (OWASP Benchmark style, one test case per task and category; "
                   "TPR over the positives labelled with it, FPR over the negatives contrasted with it):")
        out += table(["category", "n_pos", "n_neg", "TP", "FN", "TN", "FP", "TPR", "FPR", "youden", "note"],
                     [[k, c["positives"], c["negatives"], c["TP"], c["FN"], c["TN"], c["FP"], c["TPR"], c["FPR"],
                       c["youden"], "cannot emit, not in the mean" if c.get("cannot_emit") else ""]
                      for k, c in cats["per_category"].items()])
        o = cats["overall"]
        out.append(f"overall: mean TPR {macro_text(o, 'mean_TPR')}  mean FPR {macro_text(o, 'mean_FPR')}  "
                   f"score {macro_text(o, 'score')}  precision (pooled) {fmt(o['precision_pooled']) or 'n/a'}  "
                   f"F1 {macro_text(o, 'F1')}  over {o['categories']} categories")
        if o.get("suppressed") and o.get("too_few_tasks"):
            out.append(f"  means not shown: fewer than {o['min_tasks_per_side']} positives or negatives in "
                       + ", ".join(o["too_few_tasks"]))
        if o.get("excluded_cannot_emit"):
            out.append("  left out of the means, the tool cannot emit them (its ruleIds come from the CWE map): "
                       + ", ".join(o["excluded_cannot_emit"]))
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
        matched = summary.get("measurements_matched_only") or {}
        if matched.get("findings"):
            out.append(f"on matched findings only ({matched['findings']}): " + "  ".join(
                f"{k} {measure_text({**m, k: matched.get(k)}, k) or 'n/a'}" for k in SUPPORT_FIELDS))
        base = summary.get("fixed_answer_baselines") or {}
        for key, answer in (("controls", "controls none/high"),
                            ("recommendations", f"recommendation {base.get('recommendation_id')}")):
            b = base.get(key) or {}
            if b.get("tasks"):
                out.append(f"fixed answer baseline, {answer} for every finding: {key} {fmt(b['per_app'])} per "
                           f"positive ({b['tasks']}), {fmt(b['per_finding'])} per finding ({b['findings']})")
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
    summary = summarise(rows, args.tasks)

    if args.write:
        args.write.mkdir(parents=True, exist_ok=True)
        (args.write / "report.json").write_text(json.dumps({"summary": summary, "trials": [public_row(r) for r in rows]},
                                                           indent=2), encoding="utf-8")
        (args.write / "report.md").write_text("# SAST benchmark report\n\n" + render(rows, summary, md_table) + "\n", encoding="utf-8")
    if args.json:
        json.dump([public_row(r) for r in rows], sys.stdout, indent=2)
        print()
        return
    print(render(rows, summary))


if __name__ == "__main__":
    main()
