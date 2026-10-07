#!/usr/bin/env python3
"""Grade a scanner's SARIF output against ground_truth.json.

grader v3 (2026-10-07, revised after the audit the same day). Every new field
is optional. A ground truth without them is graded exactly as by v2 (and a v2
task without the v2 fields exactly as by v1).

v2 fields:

- ``fixed_locations`` (fixed twins, ``findings: []``): the twin passes when no
  result lands within ``line_tolerance`` of these lines. Results elsewhere are
  ``fp_outside_scope``.
- ``fix_changed_files`` (positive tasks): an unmatched result is a false
  positive only inside these files, others are ``fp_outside_scope``.

v3 fields:

- ``matching.require_cwe`` (default false): a result matches a finding only
  when its ``properties.cwe`` intersects the finding's ``acceptable_cwes`` plus
  ``primary_cwe``. CWE ids are read as ``CWE-<n>`` anywhere in the value
  ("CWE-22", "cwe-22", "A01:2021 - CWE-22" agree), and a bare number is read as
  a CWE id only when it is the whole value ("22" or 22).
- ``variant_role: "negative"`` with ``contrast_rule_ids``: a minimal-contrast
  negative. It scores 1.0 unless it fails in one of two buckets. ``near_fix``
  is a result whose OWASP prefix (LLM02, LLM03) is one of the contrast prefixes
  and that lands within ``line_tolerance`` of ``fixed_locations``. ``trap`` is
  a result that hits one of the negative's own ``hard_negative_trap`` entries in
  ``negative_analyses`` (its prefix is in the trap's ``trap_rule_prefixes`` and
  it lands within tolerance of the trap lines). No CWE agreement is needed for
  either. Every other result, including one elsewhere in
  ``fix_changed_files``, is ``fp_outside_scope``. The buckets are written to
  grading_detail.json (``failure_bucket``) and as the flat flags
  ``neg.fail.near_fix`` and ``neg.fail.trap`` in reward.json.
- ``linked_finding_ids`` / ``link_relation`` per finding are echoed in the
  per-finding detail.

Task-level outcomes (client measurement 1, "both risks or neither") and the
OWASP Benchmark style category outcomes are computed for every task. A risk
type or category counts as predicted only from results that matched a finding
(positives) or that fail the negative (negatives). The older, looser rule
(any result inside ``fix_changed_files`` or near ``fixed_locations``) is kept
as ``tl.pred_loose.<risk>``. Harbor only accepts numbers in reward.json, so
these are written there as flat 0/1 keys (``tl.truth.SID``, ``tl.pred.EA``,
``tl.pred_loose.EA``, ``cat.<category>.truth``, ``cat.<category>.detected``)
and in structured form, with outcomes spelled out, in grading_detail.json under
``task_level``.

Robustness: ``"results": null`` is read as no results, and a
``recommendations`` value given as one string is read as a one-item list.

``--check-truth`` validates the ground truth instead of grading (missing
fields, bad line ranges, findings with no CWE under ``require_cwe``, and
accepted locations of different findings whose tolerance windows overlap, so
that one result could match either). Run it
at task build time. It exits 1 when there is a problem.

Writes:
  <out>/reward.txt          single float in [0, 1]
  <out>/reward.json         flat numeric sub-scores, counts and outcome flags
  <out>/grading_detail.json human-readable match log, task_level, measurements

A reward file is written on every exit path, including a crash, so a broken
run is scored 0 rather than left unscored.
"""

import argparse
import json
import re
import sys
import traceback
from pathlib import Path

RISK_PREFIX = {"LLM02": "sensitive_information_disclosure", "LLM03": "excessive_agency"}
RISK_SHORT = {"sensitive_information_disclosure": "SID", "excessive_agency": "EA"}
MEASUREMENTS = ("classification", "path", "controls", "recommendations")


def norm_uri(uri: str) -> str:
    uri = uri.replace("file://", "")
    for prefix in ("/app/repo/", "app/repo/", "./"):
        if uri.startswith(prefix):
            uri = uri[len(prefix):]
    return uri.lstrip("/")


CWE_RE = re.compile(r"CWE-(\d+)", re.IGNORECASE)


def norm_cwe(value) -> str | None:
    """"CWE-22", "cwe-22", "A01:2021 - CWE-22", "22" and 22 all give "CWE-22".

    A number counts on its own only when it is the whole value, so the "01" or
    "2021" of an OWASP id is never read as a CWE.
    """
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int):
        return f"CWE-{value}" if value >= 0 else None
    text = str(value).strip()
    if text.isdigit():
        return f"CWE-{int(text)}"
    m = CWE_RE.search(text)
    return f"CWE-{int(m.group(1))}" if m else None


def cwe_set(values) -> set:
    if values is None:
        return set()
    if isinstance(values, (str, int)):
        values = [values]
    return {c for c in (norm_cwe(v) for v in values) if c}


def finding_cwes(f: dict) -> set:
    return cwe_set(f.get("acceptable_cwes")) | cwe_set(f.get("primary_cwe"))


def phys(loc: dict):
    """(file, start, end) from a SARIF location or threadFlowLocation."""
    loc = loc.get("location", loc)
    pl = loc.get("physicalLocation", {})
    uri = norm_uri(pl.get("artifactLocation", {}).get("uri", ""))
    region = pl.get("region", {})
    start = region.get("startLine")
    end = region.get("endLine", start)
    return uri, start, end


def primary_of(res: dict):
    return phys(res["locations"][0]) if res.get("locations") else ("", None, None)


def near(file, start, end, target: dict, tol: int) -> bool:
    if not file or start is None or file != target["file"]:
        return False
    t_start = target["start_line"]
    t_end = target.get("end_line", t_start)
    return start <= t_end + tol and (end or start) >= t_start - tol


def rule_prefix(rule_id: str) -> str:
    return (rule_id or "").split(".")[0]


def risk_of(rule_id: str):
    return RISK_PREFIX.get(rule_prefix(rule_id))


def category_of(rule_id: str) -> str:
    """OWASP-style category: LLM02.SID (severity dropped), LLM03.EA.<SUBTYPE>."""
    parts = (rule_id or "").split(".")
    if parts[0] == "LLM02":
        return ".".join(parts[:2])
    if parts[0] == "LLM03":
        return ".".join(parts[:3])
    return rule_id or ""


def load_results(sarif_path: Path):
    sarif = json.loads(sarif_path.read_text())
    if sarif.get("version") != "2.1.0":
        raise ValueError("SARIF version must be 2.1.0")
    results = []
    for run in sarif.get("runs") or []:
        results.extend(r for r in (run or {}).get("results") or [] if isinstance(r, dict))
    return results


def score_path(result: dict, finding: dict, tol: int):
    flows = result.get("codeFlows") or []
    steps = []
    for flow in flows:
        for tf in flow.get("threadFlows", []):
            steps.extend(phys(l) for l in tf.get("locations", []))
    required = [s for s in finding["path"] if s["required"]]
    covered = []
    for s in required:
        targets = [s] + s.get("alternatives", [])
        hit = any(near(f, a, b, t, tol) for (f, a, b) in steps for t in targets)
        covered.append({"step": s["step"], "role": s["role"], "covered": hit})
    score = sum(c["covered"] for c in covered) / len(required) if required else 1.0
    return score, covered


def rec_set(value) -> set:
    """Recommendation ids from a SARIF property: a list, or one string as a one-item list."""
    if isinstance(value, str):
        return {value}
    if isinstance(value, (list, tuple)):
        return {v for v in value if isinstance(v, str)}
    return set()


def score_recs(result: dict, finding: dict):
    recs = rec_set((result.get("properties") or {}).get("recommendations"))
    spec = finding["recommendations"]
    applicable = set(spec["required_any_of"]) | set(spec.get("acceptable", []))
    has_required = bool(recs & set(spec["required_any_of"]))
    inapplicable = recs - applicable
    score = 1.0 if has_required else (0.5 if recs & applicable else 0.0)
    score = max(0.0, score - 0.25 * len(inapplicable))
    return score, sorted(inapplicable)


# ---- task-level outcomes ---------------------------------------------------------

def outcome(truth: bool, predicted: bool) -> str:
    return {(True, True): "TP", (True, False): "FN", (False, True): "FP", (False, False): "TN"}[(truth, predicted)]


def task_level(truth_risks, predicted_risks, categories: dict, loose_risks=None) -> dict:
    """categories: {category: (truth, detected)}.

    ``predicted_risks`` come from results that matched a finding or fail the
    negative. ``loose_risks`` (default: the same) keep the pre-audit rule, any
    result inside the fix files or near the fixed code.
    """
    truth_risks, predicted_risks = set(truth_risks), set(predicted_risks)
    loose_risks = predicted_risks if loose_risks is None else set(loose_risks)
    return {
        "truth_risk_types": sorted(truth_risks),
        "predicted_risk_types": sorted(predicted_risks),
        "risk_types": {r: outcome(r in truth_risks, r in predicted_risks) for r in RISK_SHORT},
        "categories": {c: outcome(t, d) for c, (t, d) in sorted(categories.items())},
        "predicted_risk_types_loose": sorted(loose_risks),
        "risk_types_loose": {r: outcome(r in truth_risks, r in loose_risks) for r in RISK_SHORT},
    }


def flat_task_level(tl: dict) -> dict:
    flat = {}
    for risk, short in RISK_SHORT.items():
        flat[f"tl.truth.{short}"] = int(risk in tl["truth_risk_types"])
        flat[f"tl.pred.{short}"] = int(risk in tl["predicted_risk_types"])
        flat[f"tl.pred_loose.{short}"] = int(risk in tl["predicted_risk_types_loose"])
    for cat, out in tl["categories"].items():
        flat[f"cat.{cat}.truth"] = int(out in ("TP", "FN"))
        flat[f"cat.{cat}.detected"] = int(out in ("TP", "FP"))
    return flat


def truth_risk_types(truth: dict) -> set:
    present = truth.get("risk_types_present")
    if present is None:
        present = [f["risk_type"] for f in truth.get("findings") or []]
    return set(present)


# ---- grading -----------------------------------------------------------------------

def grade(sarif_path: Path, truth: dict) -> tuple[dict, dict]:
    tol = truth["matching"]["line_tolerance"]
    ptol = truth["matching"]["path_line_tolerance"]
    require_cwe = bool(truth["matching"].get("require_cwe", False))
    w = truth["scoring_weights"]
    findings = truth["findings"]
    traps = truth["negative_analyses"]
    # A v3 negative names the contrast rules. An older negative without them keeps
    # the v1 rule (any result fails it).
    negative = truth.get("variant_role") == "negative" and not findings and "contrast_rule_ids" in truth

    if not sarif_path.exists():
        cats = {}
        if negative:
            cats = {category_of(r): (False, False) for r in truth.get("contrast_rule_ids") or []}
        else:
            cats = {category_of(f["rule_id"]): (True, False) for f in findings}
        tl = task_level(truth_risk_types(truth), set(), cats)
        detail = {"error": f"missing {sarif_path}", "task_level": tl}
        summary = _summarise(0.0, 0, 0, len(findings), 0, {}, w, findings)
        summary.update(flat_task_level(tl), sarif_missing=1)
        if negative:
            summary.update({"neg.fail.near_fix": 0, "neg.fail.trap": 0})
        return summary, detail

    results = load_results(sarif_path)
    if negative:
        return grade_negative(results, truth, w, tol)
    if not findings and truth.get("fixed_locations"):
        return grade_twin(results, truth, w, tol)
    scope_files = set(truth.get("fix_changed_files") or [])
    matched = {}
    unmatched, trap_hits, outside = [], [], []

    for idx, res in enumerate(results):
        rule = res.get("ruleId", "")
        risk = risk_of(rule)
        primary = primary_of(res)
        res_cwes = cwe_set((res.get("properties") or {}).get("cwe"))
        hit = None
        for f in findings:
            if f["id"] in matched or risk != f["risk_type"]:
                continue
            if require_cwe and not (res_cwes & finding_cwes(f)):
                continue
            targets = [f["primary_location"]] + f.get("alternative_primary_locations", [])
            if any(near(*primary, t, tol) for t in targets):
                hit = f
                break
        if hit:
            matched[hit["id"]] = (idx, res)
            continue
        if scope_files and primary[0] not in scope_files:
            outside.append({"index": idx, "ruleId": rule, "location": primary})
            continue
        unmatched.append({"index": idx, "ruleId": rule, "location": primary})
        for trap in traps:
            if rule_prefix(rule) in (trap.get("trap_rule_prefixes") or []) and near(*primary, trap, tol):
                trap_hits.append({"trap": trap["id"], "result_index": idx})

    tp, fp, fn = len(matched), len(unmatched), len(findings) - len(matched)
    sub = {k: 0.0 for k in MEASUREMENTS}
    on_detected = {k: [] for k in MEASUREMENTS}
    per_finding = []

    for f in findings:
        links = {k: f[k] for k in ("linked_finding_ids", "link_relation") if k in f}
        if f["id"] not in matched:
            per_finding.append({"finding": f["id"], "matched": False, **links})
            continue
        idx, res = matched[f["id"]]
        props = res.get("properties") or {}
        rule = res.get("ruleId", "")
        cls = 1.0 if rule in f["acceptable_rule_ids"] else (0.5 if rule in f.get("partial_credit_rule_ids", []) else 0.0)
        cwe_ok = bool(cwe_set(props.get("cwe")) & finding_cwes(f))
        cls = 0.8 * cls + 0.2 * cwe_ok
        path_score, path_cov = score_path(res, f, ptol)
        ctrl = 0.75 * (props.get("controlStatus") == f["control_status"]) + 0.25 * (props.get("residualRisk") == f["residual_risk"])
        rec_score, inapplicable = score_recs(res, f)
        for k, v in (("classification", cls), ("path", path_score), ("controls", ctrl), ("recommendations", rec_score)):
            sub[k] += v / len(findings)
            on_detected[k].append(v)
        per_finding.append({
            "finding": f["id"], "matched": True, "result_index": idx, "ruleId": rule,
            "cwe_ok": cwe_ok, "path_steps": path_cov, "controlStatus": props.get("controlStatus"),
            "residualRisk": props.get("residualRisk"), "inapplicable_recommendations": inapplicable,
            "scores": {"classification": round(cls, 4), "path": round(path_score, 4),
                       "controls": round(ctrl, 4), "recommendations": round(rec_score, 4)},
            **links,
        })

    if findings:
        precision = tp / (tp + fp) if (tp + fp) else 0.0
        recall = tp / len(findings)
        detection = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    else:
        detection = 1.0 if not results else 0.0
        sub = {k: (1.0 if not results else 0.0) for k in sub}

    # Task level: a risk is predicted only by a result that matched a finding.
    # The loose variant also counts results counted as false positives (inside
    # the fix files, or anywhere when the task names no fix files).
    matched_results = [res for _, res in matched.values()]
    predicted = {risk_of(r.get("ruleId", "")) for r in matched_results} - {None}
    loose = {risk_of(r.get("ruleId", "")) for r in matched_results + [results[u["index"]] for u in unmatched]} - {None}
    cats = {}
    for f in findings:
        cat = category_of(f["rule_id"])
        cats[cat] = (True, cats.get(cat, (True, False))[1] or f["id"] in matched)
    tl = task_level(truth_risk_types(truth), predicted, cats, loose)

    summary = _summarise(detection, tp, fp, fn, len(trap_hits), sub, w, findings, len(outside))
    summary.update(flat_task_level(tl))
    detail = {"per_finding": per_finding, "unmatched_results": unmatched, "trap_hits": trap_hits,
              "outside_scope_results": outside, "task_level": tl,
              "measurements": {"detection": summary["detection"], **{k: summary[k] for k in MEASUREMENTS}},
              "measurements_on_detected": {k: (round(sum(v) / len(v), 4) if v else None)
                                           for k, v in on_detected.items()},
              "require_cwe": require_cwe}
    return summary, detail


def is_trap(entry: dict) -> bool:
    return entry.get("kind", "hard_negative_trap") == "hard_negative_trap" and bool(entry.get("trap_rule_prefixes"))


def grade_negative(results: list, truth: dict, w: dict, tol: int) -> tuple[dict, dict]:
    """A minimal-contrast negative (near-fix rule plus the negative's own traps).

    The negative fails on a result in one of two buckets:

    - ``near_fix``: its OWASP prefix is a contrast prefix and it lands within
      ``line_tolerance`` of ``fixed_locations``;
    - ``trap``: it hits a ``hard_negative_trap`` entry of ``negative_analyses``
      (prefix in ``trap_rule_prefixes``, within tolerance of the trap lines).

    A result in both buckets is counted once, under ``near_fix``. Every other
    result is ``fp_outside_scope``, including one elsewhere in
    ``fix_changed_files``. No CWE agreement is needed to fail.
    """
    contrast = truth.get("contrast_rule_ids") or []
    prefixes = {rule_prefix(r) for r in contrast}
    fixed = truth.get("fixed_locations") or []
    traps = [t for t in truth.get("negative_analyses") or [] if is_trap(t)]
    scope_files = set(truth.get("fix_changed_files") or [])
    near_fix, trap_hits, outside, loose = [], [], [], set()
    for idx, res in enumerate(results):
        rule = res.get("ruleId", "")
        primary = primary_of(res)
        entry = {"index": idx, "ruleId": rule, "location": primary}
        is_near = any(near(*primary, loc, tol) for loc in fixed)
        if risk_of(rule) and (is_near or primary[0] in scope_files):
            loose.add(risk_of(rule))
        if is_near and rule_prefix(rule) in prefixes:
            near_fix.append(entry)
            continue
        hit = [t["id"] for t in traps if rule_prefix(rule) in t["trap_rule_prefixes"] and near(*primary, t, tol)]
        if hit:
            trap_hits.append({**entry, "traps": hit})
        else:
            outside.append(entry)
    failing = near_fix + trap_hits
    bucket = ("near_fix" if near_fix else "") + ("+" if near_fix and trap_hits else "") + ("trap" if trap_hits else "")
    clean = 0.0 if failing else 1.0
    sub = {k: clean for k in MEASUREMENTS}
    predicted = {risk_of(e["ruleId"]) for e in failing} - {None}
    flagged = {rule_prefix(e["ruleId"]) for e in failing}
    cats = {category_of(r): (False, rule_prefix(r) in flagged) for r in contrast}
    tl = task_level(truth_risk_types(truth), predicted, cats, loose)
    summary = _summarise(clean, 0, len(failing), 0, len(trap_hits), sub, w, [], len(outside))
    summary.update(flat_task_level(tl))
    summary.update({"neg.fail.near_fix": int(bool(near_fix)), "neg.fail.trap": int(bool(trap_hits))})
    detail = {"negative": True, "contrast_rule_ids": contrast, "failure_bucket": bucket or None,
              "results_near_fixed_code": near_fix, "trap_hits": trap_hits,
              "outside_scope_results": outside, "task_level": tl}
    return summary, detail


def grade_twin(results: list, truth: dict, w: dict, tol: int) -> tuple[dict, dict]:
    """A v2 fixed twin: pass unless a result claims an issue near the fixed code."""
    near_fix, outside = [], []
    for idx, res in enumerate(results):
        rule = res.get("ruleId", "")
        primary = primary_of(res)
        entry = {"index": idx, "ruleId": rule, "location": primary}
        if any(near(*primary, loc, tol) for loc in truth["fixed_locations"]):
            near_fix.append(entry)
        else:
            outside.append(entry)
    clean = 0.0 if near_fix else 1.0
    sub = {k: clean for k in MEASUREMENTS}
    predicted = {risk_of(e["ruleId"]) for e in near_fix} - {None}
    tl = task_level(truth_risk_types(truth), predicted, {})
    summary = _summarise(clean, 0, len(near_fix), 0, 0, sub, w, [], len(outside))
    summary.update(flat_task_level(tl))
    detail = {"twin": True, "results_near_fixed_code": near_fix, "outside_scope_results": outside,
              "task_level": tl}
    return summary, detail


def _summarise(detection, tp, fp, fn, traps, sub, w, findings, outside=0):
    sub = {k: sub.get(k, 0.0) for k in MEASUREMENTS}
    reward = w["detection"] * detection + sum(w[k] * v for k, v in sub.items())
    return {
        "reward": round(reward, 4),
        "detection": round(detection, 4),
        **{k: round(v, 4) for k, v in sub.items()},
        "tp": tp, "fp": fp, "fn": fn, "trap_hits": traps,
        "fp_outside_scope": outside,
        "gt_findings": len(findings),
    }


# ---- ground-truth schema check ---------------------------------------------------------

FINDING_FIELDS = ("id", "risk_type", "rule_id", "acceptable_rule_ids", "primary_location", "path",
                  "control_status", "residual_risk", "recommendations")


def _is_line(v) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and v >= 1


def _location_problems(loc, where: str) -> list[str]:
    if not isinstance(loc, dict):
        return [f"{where}: not an object"]
    problems = []
    if not isinstance(loc.get("file"), str) or not loc.get("file"):
        problems.append(f"{where}: missing file")
    start, end = loc.get("start_line"), loc.get("end_line", loc.get("start_line"))
    if not _is_line(start):
        problems.append(f"{where}: start_line must be an integer >= 1, got {start!r}")
    elif not _is_line(end) or end < start:
        problems.append(f"{where}: end_line {end!r} is not an integer >= start_line {start}")
    return problems


def _gap(a: dict, b: dict) -> int:
    """Lines between two ranges in one file (0 when they overlap)."""
    a_end, b_end = a.get("end_line", a["start_line"]), b.get("end_line", b["start_line"])
    return max(0, a["start_line"] - b_end, b["start_line"] - a_end)


def check_truth(truth: dict) -> list[str]:
    """Problems in a ground truth that would make grading silently wrong. Empty when fine.

    Checks required fields, line ranges, that every finding has a CWE when
    ``matching.require_cwe`` is true (otherwise it can never match), and that
    no two different findings have accepted locations (primary or alternative)
    whose ``line_tolerance`` windows overlap (at most twice the tolerance
    apart in one file), when one result could match both (same risk type and,
    under require_cwe, a shared CWE). Such a result is always credited to
    whichever finding comes first.
    """
    if not isinstance(truth, dict):
        return ["ground truth is not a JSON object"]
    problems = []
    matching = truth.get("matching")
    if not isinstance(matching, dict):
        problems.append("missing matching")
        matching = {}
    for key in ("line_tolerance", "path_line_tolerance"):
        v = matching.get(key)
        if not isinstance(v, int) or isinstance(v, bool) or v < 0:
            problems.append(f"matching.{key} must be an integer >= 0, got {v!r}")
    tol = matching.get("line_tolerance") if isinstance(matching.get("line_tolerance"), int) else 0
    require_cwe = bool(matching.get("require_cwe", False))
    weights = truth.get("scoring_weights")
    if not isinstance(weights, dict):
        problems.append("missing scoring_weights")
    else:
        for key in ("detection", *MEASUREMENTS):
            if not isinstance(weights.get(key), (int, float)) or isinstance(weights.get(key), bool):
                problems.append(f"scoring_weights.{key} must be a number")
    findings = truth.get("findings")
    if not isinstance(findings, list):
        problems.append("findings must be a list")
        findings = []
    if not isinstance(truth.get("negative_analyses"), list):
        problems.append("negative_analyses must be a list")

    ids = [f.get("id") for f in findings if isinstance(f, dict)]
    for dup in sorted({i for i in ids if ids.count(i) > 1}, key=str):
        problems.append(f"duplicate finding id {dup!r}")
    good = []
    for n, f in enumerate(findings):
        name = f"finding {f.get('id', n) if isinstance(f, dict) else n}"
        if not isinstance(f, dict):
            problems.append(f"{name}: not an object")
            continue
        missing = [k for k in FINDING_FIELDS if k not in f]
        problems += [f"{name}: missing {k}" for k in missing]
        if "risk_type" in f and f["risk_type"] not in RISK_SHORT:
            problems.append(f"{name}: unknown risk_type {f['risk_type']!r}")
        if require_cwe and not finding_cwes(f):
            problems.append(f"{name}: require_cwe is true but primary_cwe and acceptable_cwes give no CWE")
        locs = []
        if "primary_location" in f:
            locs.append(("primary_location", f["primary_location"]))
        alts = f.get("alternative_primary_locations", [])
        if not isinstance(alts, list):
            problems.append(f"{name}: alternative_primary_locations must be a list")
            alts = []
        locs += [(f"alternative_primary_locations[{i}]", a) for i, a in enumerate(alts)]
        loc_ok = True
        for where, loc in locs:
            p = _location_problems(loc, f"{name} {where}")
            problems += p
            loc_ok = loc_ok and not p
        path = f.get("path", [])
        if not isinstance(path, list):
            problems.append(f"{name}: path must be a list")
            path = []
        for i, step in enumerate(path):
            where = f"{name} path[{i}]"
            if not isinstance(step, dict):
                problems.append(f"{where}: not an object")
                continue
            problems += [f"{where}: missing {k}" for k in ("step", "role", "required") if k not in step]
            problems += _location_problems(step, where)
            for j, alt in enumerate(step.get("alternatives", []) or []):
                problems += _location_problems(alt, f"{where} alternatives[{j}]")
        recs = f.get("recommendations")
        if "recommendations" in f and not (isinstance(recs, dict) and isinstance(recs.get("required_any_of"), list)):
            problems.append(f"{name}: recommendations.required_any_of must be a list")
        if loc_ok and not missing:
            good.append((f, [loc for _, loc in locs]))

    for i, entry in enumerate(truth.get("fixed_locations") or []):
        problems += _location_problems(entry, f"fixed_locations[{i}]")
    for i, entry in enumerate(truth.get("negative_analyses") or []):
        if isinstance(entry, dict) and "file" in entry:
            problems += _location_problems(entry, f"negative_analyses[{i}] ({entry.get('id', '?')})")
        if isinstance(entry, dict) and is_trap(entry) and not isinstance(entry.get("trap_rule_prefixes"), list):
            problems.append(f"negative_analyses[{i}]: trap_rule_prefixes must be a list")
    if truth.get("variant_role") == "negative" and "contrast_rule_ids" in truth and not truth.get("fixed_locations"):
        problems.append("negative with contrast_rule_ids has no fixed_locations")

    for a in range(len(good)):
        for b in range(a + 1, len(good)):
            (fa, la), (fb, lb) = good[a], good[b]
            if fa["risk_type"] != fb["risk_type"]:
                continue
            if require_cwe and not (finding_cwes(fa) & finding_cwes(fb)):
                continue
            for x in la:
                for y in lb:
                    if x["file"] == y["file"] and _gap(x, y) <= 2 * tol:
                        problems.append(
                            f"findings {fa['id']} and {fb['id']} have overlapping accepted locations "
                            f"(line_tolerance {tol}): {x['file']}:{x['start_line']} and "
                            f"{y['file']}:{y['start_line']}, "
                            f"a result there is always credited to {fa['id']}")
    return problems


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sarif", default="/app/output/findings.sarif")
    ap.add_argument("--truth", default=str(Path(__file__).with_name("ground_truth.json")))
    ap.add_argument("--out", default="/logs/verifier")
    ap.add_argument("--check-truth", action="store_true",
                    help="validate the ground truth and exit (1 on any problem), without grading")
    args = ap.parse_args()
    if args.check_truth:
        try:
            problems = check_truth(json.loads(Path(args.truth).read_text()))
        except (OSError, ValueError) as exc:
            problems = [f"cannot read {args.truth}: {exc}"]
        for p in problems:
            print(f"{args.truth}: {p}")
        print(f"{args.truth}: {'ok' if not problems else f'{len(problems)} problems'}")
        sys.exit(1 if problems else 0)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    try:
        truth = json.loads(Path(args.truth).read_text())
        summary, detail = grade(Path(args.sarif), truth)
    except BaseException as exc:  # never leave a run unscored
        summary = {"reward": 0.0, "detection": 0.0, "classification": 0.0, "path": 0.0,
                   "controls": 0.0, "recommendations": 0.0, "tp": 0, "fp": 0, "fn": 0,
                   "trap_hits": 0, "fp_outside_scope": 0, "gt_findings": 0, "grader_error": 1}
        detail = {"error": repr(exc), "traceback": traceback.format_exc()}

    (out / "reward.txt").write_text(f"{summary['reward']}\n")
    (out / "reward.json").write_text(json.dumps(summary, indent=2))
    (out / "grading_detail.json").write_text(json.dumps(detail, indent=2))
    print(json.dumps(summary))


if __name__ == "__main__":
    main()
    sys.exit(0)
