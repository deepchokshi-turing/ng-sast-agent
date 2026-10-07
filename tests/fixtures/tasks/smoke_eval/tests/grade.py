#!/usr/bin/env python3
"""Grade a scanner's SARIF output against ground_truth.json.

grader v2 (2026-10-07). Two optional ground-truth fields; a task without them is
graded exactly as by v1:

- ``fixed_locations`` (fixed-twin tasks, ``findings: []``): the lines the fix
  changed. The twin passes when no result lands within ``line_tolerance`` of
  them. Results elsewhere in the repository are reported as ``fp_outside_scope``
  and do not fail the twin. (v1: any result anywhere failed it.)
- ``fix_changed_files`` (positive tasks): the files the fix changed. A result
  that matches no finding counts as a false positive only inside these files;
  others are reported as ``fp_outside_scope``. (v1: every unmatched result in the
  repository was a false positive.)

Sink and dispatch locations are accepted through the existing
``alternative_primary_locations``; no grader change is needed for that.

Writes:
  <out>/reward.txt          single float in [0, 1]
  <out>/reward.json         numeric sub-scores and counts (for dataset-level F3 etc.)
  <out>/grading_detail.json human-readable match log

A reward file is written on every exit path, including a crash, so a broken
run is scored 0 rather than left unscored.
"""

import argparse
import json
import sys
import traceback
from pathlib import Path

RISK_PREFIX = {"LLM02": "sensitive_information_disclosure", "LLM03": "excessive_agency"}


def norm_uri(uri: str) -> str:
    uri = uri.replace("file://", "")
    for prefix in ("/app/repo/", "app/repo/", "./"):
        if uri.startswith(prefix):
            uri = uri[len(prefix):]
    return uri.lstrip("/")


def phys(loc: dict):
    """(file, start, end) from a SARIF location or threadFlowLocation."""
    loc = loc.get("location", loc)
    pl = loc.get("physicalLocation", {})
    uri = norm_uri(pl.get("artifactLocation", {}).get("uri", ""))
    region = pl.get("region", {})
    start = region.get("startLine")
    end = region.get("endLine", start)
    return uri, start, end


def near(file, start, end, target: dict, tol: int) -> bool:
    if not file or start is None or file != target["file"]:
        return False
    t_start = target["start_line"]
    t_end = target.get("end_line", t_start)
    return start <= t_end + tol and (end or start) >= t_start - tol


def risk_of(rule_id: str):
    return RISK_PREFIX.get((rule_id or "").split(".")[0])


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


def grade(sarif_path: Path, truth: dict) -> tuple[dict, dict]:
    tol = truth["matching"]["line_tolerance"]
    ptol = truth["matching"]["path_line_tolerance"]
    w = truth["scoring_weights"]
    findings = truth["findings"]
    traps = truth["negative_analyses"]

    if not sarif_path.exists():
        detail = {"error": f"missing {sarif_path}"}
        tp, fp, fn = 0, 0, len(findings)
        return _summarise(0.0, tp, fp, fn, 0, {}, w, findings), detail

    results = load_results(sarif_path)
    if not findings and truth.get("fixed_locations"):
        return grade_twin(results, truth, w, tol)
    scope_files = set(truth.get("fix_changed_files") or [])
    matched = {}
    unmatched, trap_hits, outside = [], [], []

    for idx, res in enumerate(results):
        rule = res.get("ruleId", "")
        risk = risk_of(rule)
        primary = phys(res["locations"][0]) if res.get("locations") else ("", None, None)
        hit = None
        for f in findings:
            if f["id"] in matched or risk != f["risk_type"]:
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
            if rule.split(".")[0] in trap["trap_rule_prefixes"] and near(*primary, trap, tol):
                trap_hits.append({"trap": trap["id"], "result_index": idx})

    tp, fp, fn = len(matched), len(unmatched), len(findings) - len(matched)
    sub = {"classification": 0.0, "path": 0.0, "controls": 0.0, "recommendations": 0.0}
    per_finding = []

    for f in findings:
        if f["id"] not in matched:
            per_finding.append({"finding": f["id"], "matched": False})
            continue
        idx, res = matched[f["id"]]
        props = res.get("properties") or {}
        rule = res.get("ruleId", "")
        cls = 1.0 if rule in f["acceptable_rule_ids"] else (0.5 if rule in f.get("partial_credit_rule_ids", []) else 0.0)
        cwe_ok = bool(set(props.get("cwe", [])) & set(f["acceptable_cwes"]))
        cls = 0.8 * cls + 0.2 * cwe_ok
        path_score, path_cov = score_path(res, f, ptol)
        ctrl = 0.75 * (props.get("controlStatus") == f["control_status"]) + 0.25 * (props.get("residualRisk") == f["residual_risk"])
        rec_score, inapplicable = score_recs(res, f)
        for k, v in (("classification", cls), ("path", path_score), ("controls", ctrl), ("recommendations", rec_score)):
            sub[k] += v / len(findings)
        per_finding.append({
            "finding": f["id"], "matched": True, "result_index": idx, "ruleId": rule,
            "cwe_ok": cwe_ok, "path_steps": path_cov, "controlStatus": props.get("controlStatus"),
            "residualRisk": props.get("residualRisk"), "inapplicable_recommendations": inapplicable,
        })

    if findings:
        precision = tp / (tp + fp) if (tp + fp) else 0.0
        recall = tp / len(findings)
        detection = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    else:
        detection = 1.0 if not results else 0.0
        sub = {k: (1.0 if not results else 0.0) for k in sub}

    summary = _summarise(detection, tp, fp, fn, len(trap_hits), sub, w, findings, len(outside))
    detail = {"per_finding": per_finding, "unmatched_results": unmatched, "trap_hits": trap_hits,
              "outside_scope_results": outside}
    return summary, detail


def grade_twin(results: list, truth: dict, w: dict, tol: int) -> tuple[dict, dict]:
    """A fixed twin: pass unless a result claims an issue near the fixed code."""
    near_fix, outside = [], []
    for idx, res in enumerate(results):
        rule = res.get("ruleId", "")
        primary = phys(res["locations"][0]) if res.get("locations") else ("", None, None)
        entry = {"index": idx, "ruleId": rule, "location": primary}
        if any(near(*primary, loc, tol) for loc in truth["fixed_locations"]):
            near_fix.append(entry)
        else:
            outside.append(entry)
    clean = 0.0 if near_fix else 1.0
    sub = {k: clean for k in ("classification", "path", "controls", "recommendations")}
    summary = _summarise(clean, 0, len(near_fix), 0, 0, sub, w, [], len(outside))
    detail = {"twin": True, "results_near_fixed_code": near_fix, "outside_scope_results": outside}
    return summary, detail


def _summarise(detection, tp, fp, fn, traps, sub, w, findings, outside=0):
    sub = {k: sub.get(k, 0.0) for k in ("classification", "path", "controls", "recommendations")}
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
                   "trap_hits": 0, "fp_outside_scope": 0, "gt_findings": 0}
        detail = {"error": repr(exc), "traceback": traceback.format_exc()}

    (out / "reward.txt").write_text(f"{summary['reward']}\n")
    (out / "reward.json").write_text(json.dumps(summary, indent=2))
    (out / "grading_detail.json").write_text(json.dumps(detail, indent=2))
    print(json.dumps(summary))


if __name__ == "__main__":
    main()
    sys.exit(0)
