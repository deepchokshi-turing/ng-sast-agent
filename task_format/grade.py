#!/usr/bin/env python3
"""Grade a scanner's SARIF output against ground_truth.json.

grader v3 (2026-10-07). Every new field is optional. A ground truth without
them is graded exactly as by v2 (and a v2 task without the v2 fields exactly as
by v1).

v2 fields:

- ``fixed_locations`` (fixed twins, ``findings: []``): the twin passes when no
  result lands within ``line_tolerance`` of these lines. Results elsewhere are
  ``fp_outside_scope``.
- ``fix_changed_files`` (positive tasks): an unmatched result is a false
  positive only inside these files, others are ``fp_outside_scope``.

v3 fields:

- ``matching.require_cwe`` (default false): a result matches a finding only
  when its ``properties.cwe`` intersects the finding's ``acceptable_cwes`` plus
  ``primary_cwe``. CWE ids are normalised ("CWE-22", "cwe-22" and "22" agree).
- ``variant_role: "negative"`` with ``contrast_rule_ids``: a minimal-contrast
  negative. It scores 1.0 unless a result whose OWASP prefix (LLM02, LLM03) is
  one of the contrast prefixes lands near ``fixed_locations`` or inside
  ``fix_changed_files``. No CWE agreement is needed for that false positive.
- ``linked_finding_ids`` / ``link_relation`` per finding are echoed in the
  per-finding detail.

Task-level outcomes (client measurement 1, "both risks or neither") and the
OWASP Benchmark style category outcomes are computed for every task. Harbor
only accepts numbers in reward.json, so they are written there as flat 0/1 keys
(``tl.truth.SID``, ``tl.pred.EA``, ``cat.<category>.truth``,
``cat.<category>.detected``) and in structured form, with outcomes spelled out,
in grading_detail.json under ``task_level``.

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


def norm_cwe(value) -> str | None:
    m = re.search(r"(\d+)", str(value or ""))
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
    for run in sarif.get("runs", []):
        results.extend(run.get("results", []))
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


def score_recs(result: dict, finding: dict):
    recs = set((result.get("properties") or {}).get("recommendations", []))
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


def task_level(truth_risks, predicted_risks, categories: dict) -> dict:
    """categories: {category: (truth, detected)}."""
    truth_risks, predicted_risks = set(truth_risks), set(predicted_risks)
    return {
        "truth_risk_types": sorted(truth_risks),
        "predicted_risk_types": sorted(predicted_risks),
        "risk_types": {r: outcome(r in truth_risks, r in predicted_risks) for r in RISK_SHORT},
        "categories": {c: outcome(t, d) for c, (t, d) in sorted(categories.items())},
    }


def flat_task_level(tl: dict) -> dict:
    flat = {}
    for risk, short in RISK_SHORT.items():
        flat[f"tl.truth.{short}"] = int(risk in tl["truth_risk_types"])
        flat[f"tl.pred.{short}"] = int(risk in tl["predicted_risk_types"])
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
            if rule_prefix(rule) in trap["trap_rule_prefixes"] and near(*primary, trap, tol):
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

    # Task level: in scope = matched, or counted as a false positive (inside the
    # fix files, or anywhere when the task names no fix files).
    in_scope = [res for _, res in matched.values()] + [results[u["index"]] for u in unmatched]
    predicted = {risk_of(r.get("ruleId", "")) for r in in_scope} - {None}
    cats = {}
    for f in findings:
        cat = category_of(f["rule_id"])
        cats[cat] = (True, cats.get(cat, (True, False))[1] or f["id"] in matched)
    tl = task_level(truth_risk_types(truth), predicted, cats)

    summary = _summarise(detection, tp, fp, fn, len(trap_hits), sub, w, findings, len(outside))
    summary.update(flat_task_level(tl))
    detail = {"per_finding": per_finding, "unmatched_results": unmatched, "trap_hits": trap_hits,
              "outside_scope_results": outside, "task_level": tl,
              "measurements": {"detection": summary["detection"], **{k: summary[k] for k in MEASUREMENTS}},
              "measurements_on_detected": {k: (round(sum(v) / len(v), 4) if v else None)
                                           for k, v in on_detected.items()},
              "require_cwe": require_cwe}
    return summary, detail


def grade_negative(results: list, truth: dict, w: dict, tol: int) -> tuple[dict, dict]:
    """A minimal-contrast negative: fail only on a contrast-family result at the fixed code."""
    contrast = truth.get("contrast_rule_ids") or []
    prefixes = {rule_prefix(r) for r in contrast}
    fixed = truth.get("fixed_locations") or []
    scope_files = set(truth.get("fix_changed_files") or [])
    near_fix, outside, predicted = [], [], set()
    for idx, res in enumerate(results):
        rule = res.get("ruleId", "")
        primary = primary_of(res)
        entry = {"index": idx, "ruleId": rule, "location": primary}
        in_scope = primary[0] in scope_files or any(near(*primary, loc, tol) for loc in fixed)
        if in_scope and risk_of(rule):
            predicted.add(risk_of(rule))
        if in_scope and rule_prefix(rule) in prefixes:
            near_fix.append(entry)
        else:
            outside.append(entry)
    clean = 0.0 if near_fix else 1.0
    sub = {k: clean for k in MEASUREMENTS}
    flagged = {rule_prefix(e["ruleId"]) for e in near_fix}
    cats = {category_of(r): (False, rule_prefix(r) in flagged) for r in contrast}
    tl = task_level(truth_risk_types(truth), predicted, cats)
    summary = _summarise(clean, 0, len(near_fix), 0, 0, sub, w, [], len(outside))
    summary.update(flat_task_level(tl))
    detail = {"negative": True, "contrast_rule_ids": contrast, "results_near_fixed_code": near_fix,
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


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sarif", default="/app/output/findings.sarif")
    ap.add_argument("--truth", default=str(Path(__file__).with_name("ground_truth.json")))
    ap.add_argument("--out", default="/logs/verifier")
    args = ap.parse_args()
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
