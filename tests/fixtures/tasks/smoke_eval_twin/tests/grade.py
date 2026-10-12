#!/usr/bin/env python3
"""Grade a scanner's SARIF output against ground_truth.json.

grader v3.3 (v3: 2026-10-07, revised after the audit the same day; v3.1 and
v3.2: 2026-10-12; v3.3: 2026-10-13). Every field added since v1 is optional. v3.2 changes how
some results are scored whatever the fields (see "v3.2" below); without the
v3.2 fields it falls back to ``fix_changed_files`` and ``trap_rule_prefixes``.

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

v3.1 (2026-10-12):

- Complete controls on a negative. A negative may list ``controls`` with
  ``status: "complete"`` and an ``at`` location (one of its
  ``fixed_locations``). A result whose OWASP prefix is a contrast prefix, whose
  ``properties.controlStatus`` is ``"complete"`` and that lands within
  ``line_tolerance`` of such a control's ``at`` names that control instead of
  claiming a weakness. It is not a failure, whichever bucket it would
  otherwise fall in, and is recorded as ``complete_control_recognised``. Each
  complete control scores 0.75 for being recognised plus 0.25 when the same
  result's ``residualRisk`` equals the negative's ``residual_risk``, and the
  mean over the controls is reported as ``neg.controls`` in reward.json (and
  ``complete_controls`` in grading_detail.json). It does not enter the reward:
  a silent negative still scores 1.0, and every other result is judged by
  the v3 rule above.
- Ground truth schema gt-0.2 (checked by ``--check-truth``): every location
  carries ``snippet_id`` and ``snippet_sha256`` (the hash of its lines, see
  ``snippet_sha256``), which are recomputed against the repo when one is
  given; findings carry ``affected_asset``, ``violates``, ``egress`` on every
  sink and action path step, ``consequence`` on excessive-agency findings, and
  a required first ``source`` or ``model_decision`` step; negatives carry
  their complete ``controls`` and ``residual_risk``. None of these fields
  changes how a positive is graded.

v3.2 (2026-10-12, scoring changes made in response to the external audit; see
task_format/README.md, "v3.2"). ``GRADER_VERSION`` is written to grading_detail.json.

- Scope (``scope_of``): ``matching.scanner_roots`` minus ``matching.excluded_paths``,
  else ``fix_changed_files``, else the whole repo.
- Negatives (F-B1, A7): a contrast-family result anywhere in scope fails the
  negative (bucket ``in_scope``, flag ``neg.fail.in_scope``), next to
  ``near_fix`` and ``trap``. A result with ``controlStatus`` "complete" is never
  a failure (``complete_claims``); the v3.1 complete-control credit is kept.
  An empty SARIF scores 1.0, a missing SARIF 0 on both sides.
- Positives (F-M1): an unmatched result in scope is a false positive. A
  "complete" result claims no weakness: it neither matches nor counts as a
  false positive.
- No cross-family match: a result matches only a finding of its own risk
  family (OWASP Benchmark categories). A cross-family match on a shared CWE
  (audit A1) was added in v3.2 and reverted on 2026-10-12.
- Path (A3): ``coverage * (0.2 + 0.8 * order * role) * precision`` (``score_path``).
- Traps (F-M5): ``trap_rule_ids`` on a trap, when present, are the exact rule
  ids that fail it; otherwise ``trap_rule_prefixes`` as before.

v3.3 (2026-10-13, final audit D2): the negative ``in_scope`` bucket takes a
result of either risk family (LLM02 or LLM03), not only a contrast-family one.
A negative's task-level label is "neither" (client spec, measurement 1), so any
risk claim in scope that is not "complete" is a false alarm.
- Categories (A6): a failing result on a negative counts against its own
  category (``cat.<category>.detected``), not the contrast prefix.
- ``norm_uri`` (m9) also strips ``file://``, everything up to ``/app/repo/``,
  leading ``/`` and a leading ``repo/``.

Matching (revised after audit 040, L3): results are matched to findings one to
one by an optimal assignment that maximises the reward (see ``assign``), not
greedily in file order. A partial-credit result therefore no longer takes a
finding from an exact one. Where the greedy matching was already optimal the
grade is unchanged.

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
that one result could match either, plus the gt-0.2 fields above). With
``--repo`` (by default ``../environment/repo`` next to the truth's folder,
when it exists) it also recomputes every ``snippet_sha256`` from the code and
resolves trust boundaries, fixtures and ``violates`` paths in the repo's
``security_manifest.json``. Run it at task build time. It exits 1 when there
is a problem.

Writes:
  <out>/reward.txt          single float in [0, 1]
  <out>/reward.json         flat numeric sub-scores, counts and outcome flags
  <out>/grading_detail.json human-readable match log, task_level, measurements

A reward file is written on every exit path, including a crash, so a broken
run is scored 0 rather than left unscored.
"""

import argparse
import hashlib
import json
import re
import sys
import traceback
from pathlib import Path

GRADER_VERSION = "v3.3"
RISK_PREFIX = {"LLM02": "sensitive_information_disclosure", "LLM03": "excessive_agency"}
RISK_SHORT = {"sensitive_information_disclosure": "SID", "excessive_agency": "EA"}
MEASUREMENTS = ("classification", "path", "controls", "recommendations")
KNOWN_CATEGORIES = ("LLM02.SID", "LLM03.EA.FUNCTIONALITY", "LLM03.EA.PERMISSIONS", "LLM03.EA.AUTONOMY")


def norm_uri(uri) -> str:
    """A repo-relative path from a SARIF uri.

    Strips a ``file://`` scheme, everything up to and including ``/app/repo/``,
    leading ``/`` and ``./``, and a leading ``repo/``. Backslashes are read as ``/``.
    """
    uri = str(uri or "").strip().replace("\\", "/")
    if uri.lower().startswith("file://"):
        uri = uri[len("file://"):]
    cut = ("/" + uri).find("/app/repo/")
    if cut >= 0:
        uri = ("/" + uri)[cut + len("/app/repo/"):]
    while True:
        stripped = uri.lstrip("/")
        if stripped.startswith("./"):
            stripped = stripped[2:]
        if stripped == uri:
            break
        uri = stripped
    if uri.startswith("repo/"):
        uri = uri[len("repo/"):]
    return uri


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
    sarif = json.loads(sarif_path.read_text(encoding="utf-8"))
    if sarif.get("version") != "2.1.0":
        raise ValueError("SARIF version must be 2.1.0")
    results = []
    for run in sarif.get("runs") or []:
        results.extend(r for r in (run or {}).get("results") or [] if isinstance(r, dict))
    return results


# Path roles. The output contract names seven roles. source and model_decision are
# both the start of a path and count as one role. Older ground truths may still use
# four legacy roles, which are read as their contract equivalents.
ROLE_ALIASES = {"model_decision": "source", "tool_output": "model_consumption",
                "pass_through": "context_assembly", "action": "sink", "control": "control_point"}
# path = coverage * (PATH_BASE + (1 - PATH_BASE) * order * role) * precision
PATH_BASE = 0.2
PATH_SLACK = 2  # emitted steps allowed beyond the ground-truth path before precision drops


def norm_role(role):
    if not isinstance(role, str):
        return None
    role = role.strip().lower()
    return ROLE_ALIASES.get(role, role) or None


def flow_steps(result: dict) -> list:
    """(file, start, end, role) of every threadFlow location of every codeFlow, in order."""
    steps = []
    for flow in result.get("codeFlows") or []:
        if not isinstance(flow, dict):
            continue
        for tf in flow.get("threadFlows") or []:
            if not isinstance(tf, dict):
                continue
            for loc in tf.get("locations") or []:
                if not isinstance(loc, dict):
                    continue
                role = (loc.get("properties") or {}).get("role")
                if role is None and isinstance(loc.get("location"), dict):
                    role = (loc["location"].get("properties") or {}).get("role")
                steps.append((*phys(loc), role))
    return steps


def longest_chain(candidates: list) -> int:
    """Longest run of steps, in ground-truth order, whose emitted positions do not go back.

    ``candidates[k]`` lists the emitted step indexes that cover the k-th covered
    ground-truth step. Each step may use any one of its candidates, and two steps
    may share one emitted step (both within tolerance of it).
    """
    best = []  # best[k][e]: longest chain ending at step k on emitted index e
    top = 0
    for k, cands in enumerate(candidates):
        row = {}
        for e in cands:
            prev = [best[i][x] for i in range(k) for x in best[i] if x <= e]
            row[e] = 1 + max(prev, default=0)
            top = max(top, row[e])
        best.append(row)
    return top


def score_path(result: dict, finding: dict, tol: int):
    """Path score in [0, 1] and the per-step detail.

    ``coverage`` is the share of required ground-truth steps that some emitted
    threadFlow location lands within ``tol`` of (the step or one of its
    ``alternatives``). Over the covered steps, ``order`` is the longest chain of
    them whose emitted positions follow the ground-truth order, divided by the
    covered count, and ``role`` is the share whose covering location carries the
    step's role (``norm_role``). ``precision`` is ``min(1, (len(path) + 2) /
    emitted steps)``, so a flow much longer than the labelled path costs credit.
    The score is ``coverage * (0.2 + 0.8 * order * role) * precision``. Order and role
    multiply because steps within tolerance of each other cannot be ordered by line
    (order is then 1 whichever way the flow runs), so only their roles tell a
    reversed path from the right one, and a path needs both to be right.
    """
    steps = flow_steps(result)
    required = [s for s in finding["path"] if s["required"]]
    covered, candidates = [], []
    for s in required:
        targets = [s] + (s.get("alternatives") or [])
        idx = [i for i, (f, a, b, _) in enumerate(steps) if any(near(f, a, b, t, tol) for t in targets)]
        role_ok = any(norm_role(steps[i][3]) == norm_role(s["role"]) for i in idx)
        covered.append({"step": s["step"], "role": s["role"], "covered": bool(idx), "role_ok": role_ok})
        if idx:
            candidates.append(idx)
    if not required:
        return 1.0, covered
    if not candidates:
        return 0.0, covered
    coverage = len(candidates) / len(required)
    order = longest_chain(candidates) / len(candidates)
    role = sum(c["role_ok"] for c in covered) / len(candidates)
    precision = min(1.0, (len(finding["path"]) + PATH_SLACK) / len(steps))
    # Divided by the same expression at order = role = 1, so a perfect path is exactly 1.0.
    shape = (PATH_BASE + (1 - PATH_BASE) * order * role) / (PATH_BASE + (1 - PATH_BASE))
    return min(1.0, coverage * shape * precision), covered


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


# ---- matching ----------------------------------------------------------------------

# ---- scope, traps and claims --------------------------------------------------------------

def _under(uri: str, patterns) -> bool:
    """``uri`` is one of ``patterns`` or lies under one (a glob when it has * ? or [)."""
    from fnmatch import fnmatchcase
    for p in patterns:
        p = norm_uri(p).rstrip("/")
        if p in ("", "."):
            return True
        if any(ch in p for ch in "*?["):
            if fnmatchcase(uri, p) or fnmatchcase(uri, p + "/*"):
                return True
        elif uri == p or uri.startswith(p + "/"):
            return True
    return False


def scope_of(truth: dict):
    """(mode, predicate on a repo-relative path): where a result is scored.

    ``matching.scanner_roots`` minus ``matching.excluded_paths`` when the ground
    truth has roots (the scope the scanner was given), else ``fix_changed_files``
    (minus the exclusions), else the whole repo (minus the exclusions).
    """
    m = truth.get("matching") or {}
    roots = [r for r in m.get("scanner_roots") or [] if isinstance(r, str)]
    excluded = [x for x in m.get("excluded_paths") or [] if isinstance(x, str)]
    fix = set(truth.get("fix_changed_files") or [])
    if roots:
        return "scanner_roots", lambda uri: bool(uri) and _under(uri, roots) and not _under(uri, excluded)
    if fix:
        return "fix_changed_files", lambda uri: uri in fix and not _under(uri, excluded)
    return "repo", lambda uri: not _under(uri, excluded)


def trap_rules(trap: dict):
    """("ids", [...]) when the trap lists ``trap_rule_ids``, else ("prefixes", [...])."""
    ids = trap.get("trap_rule_ids")
    if isinstance(ids, list) and ids:
        return "ids", [r for r in ids if isinstance(r, str)]
    return "prefixes", list(trap.get("trap_rule_prefixes") or [])


def hits_trap(rule: str, primary, trap: dict, tol: int) -> bool:
    """A wrong claim on the trap: the trap's exact rule ids (else its prefixes), within tolerance."""
    kind, rules = trap_rules(trap)
    claimed = rule in rules if kind == "ids" else rule_prefix(rule) in rules
    return claimed and near(*primary, trap, tol)


def is_complete_claim(res: dict) -> bool:
    """controlStatus "complete": the result says a control closes the path (not a weakness)."""
    return (res.get("properties") or {}).get("controlStatus") == "complete"


def score_match(res: dict, f: dict, ptol: int, cross: bool = False) -> dict:
    """The four measurement scores a result earns when it is matched to a finding.

    ``cross`` is kept for compatibility and is never set (cross-family matching was
    reverted); when true the rule part of classification would be 0.
    """
    props = res.get("properties") or {}
    rule = res.get("ruleId", "")
    cls = 1.0 if rule in f["acceptable_rule_ids"] else (0.5 if rule in f.get("partial_credit_rule_ids", []) else 0.0)
    if cross:
        cls = 0.0
    cwe_ok = bool(cwe_set(props.get("cwe")) & finding_cwes(f))
    cls = 0.8 * cls + 0.2 * cwe_ok
    path_score, path_cov = score_path(res, f, ptol)
    ctrl = 0.75 * (props.get("controlStatus") == f["control_status"]) + 0.25 * (props.get("residualRisk") == f["residual_risk"])
    rec_score, inapplicable = score_recs(res, f)
    return {"classification": cls, "path": path_score, "controls": ctrl, "recommendations": rec_score,
            "cwe_ok": cwe_ok, "path_steps": path_cov, "inapplicable": inapplicable, "cross_family": cross}


def assign(scores: dict, n_results: int, n_findings: int, w: dict, in_scope: int) -> dict:
    """Optimal one-to-one matching of results to findings: {result index: finding index}.

    ``scores`` holds every (result, finding) pair that may match. The matching
    maximises the reward. A matched pair adds ``2 * w.detection / (in_scope +
    n_findings)`` to the detection F1 (one more true positive and one fewer
    false positive, since fp + tp is fixed at the number of in-scope results)
    plus the weighted measurement scores divided by ``n_findings``, so the
    reward is a sum over the matched pairs and an assignment that maximises
    that sum maximises the reward. The one case where this is not exact is a
    result that matches through a location outside ``fix_changed_files``. It
    gets the same detection credit here, a close approximation that applies
    only to findings whose accepted locations (primary or alternative) lie
    outside ``fix_changed_files``. The sums are exact fractions. Ties go to the matching that, reading the results in order,
    gives each result the earliest finding it can, and match rather than leave
    a result unmatched. This is the matching the old greedy pass made, so a
    ground truth where greedy was optimal is graded exactly as before.
    """
    if not scores:
        return {}
    from fractions import Fraction
    from math import lcm

    rows = sorted({i for i, _ in scores})  # results that can match something
    det = 2 * Fraction(w["detection"]) / (in_scope + n_findings)
    value = {}
    for (i, j), m in scores.items():
        value[(i, j)] = det + sum(Fraction(w[k]) * Fraction(m[k]) for k in MEASUREMENTS) / n_findings
    scale = lcm(*(v.denominator for v in value.values()))
    base = n_findings + 1
    tie_span = base ** len(rows)  # every tie-break sum is below this
    weight = [[0] * n_findings for _ in rows]
    for r, i in enumerate(rows):
        for j in range(n_findings):
            if (i, j) in value:
                tie = (n_findings - j) * base ** (len(rows) - 1 - r)
                weight[r][j] = int(value[(i, j)] * scale) * tie_span + tie
    return {rows[r]: j for r, j in max_weight_matching(weight).items()}


def max_weight_matching(weight: list) -> dict:
    """Maximum weight matching on a rectangular matrix of integers >= 0 (Hungarian algorithm).

    A weight of 0 means the pair cannot match. Returns {row: column} for the
    matched pairs with a positive weight.
    """
    n_rows, n_cols = len(weight), len(weight[0]) if weight else 0
    size = max(n_rows, n_cols)
    top = max((x for row in weight for x in row), default=0)
    # Square cost matrix (1-indexed) for a minimum cost assignment.
    cost = [[0] * (size + 1)] + [
        [0] + [top - (weight[r][c] if r < n_rows and c < n_cols else 0) for c in range(size)]
        for r in range(size)]
    inf = float("inf")
    u, v, p, way = [0] * (size + 1), [0] * (size + 1), [0] * (size + 1), [0] * (size + 1)
    for i in range(1, size + 1):
        p[0], j0 = i, 0
        minv, used = [inf] * (size + 1), [False] * (size + 1)
        while True:
            used[j0] = True
            i0, delta, j1 = p[j0], inf, 0
            for j in range(1, size + 1):
                if not used[j]:
                    cur = cost[i0][j] - u[i0] - v[j]
                    if cur < minv[j]:
                        minv[j], way[j] = cur, j0
                    if minv[j] < delta:
                        delta, j1 = minv[j], j
            for j in range(size + 1):
                if used[j]:
                    u[p[j]] += delta
                    v[j] -= delta
                else:
                    minv[j] -= delta
            j0 = j1
            if p[j0] == 0:
                break
        while j0:
            j1 = way[j0]
            p[j0] = p[j1]
            j0 = j1
    pairs = {}
    for c in range(1, size + 1):
        r = p[c] - 1
        if r < n_rows and c - 1 < n_cols and weight[r][c - 1] > 0:
            pairs[r] = c - 1
    return pairs


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
        # No SARIF is no answer: 0 on a positive and on a negative alike (an empty
        # SARIF, the tool saying "clean", is what scores 1.0 on a negative).
        detail = {"grader_version": GRADER_VERSION, "error": f"missing {sarif_path}", "task_level": tl}
        summary = _summarise(0.0, 0, 0, len(findings), 0, {}, w, findings)
        summary.update(flat_task_level(tl), sarif_missing=1)
        if negative:
            summary.update({"neg.fail.near_fix": 0, "neg.fail.trap": 0, "neg.fail.in_scope": 0})
            if complete_controls(truth):
                summary.update({"neg.controls": 0.0, "neg.complete_control_recognised": 0})
        return summary, detail

    results = load_results(sarif_path)
    if negative:
        return grade_negative(results, truth, w, tol)
    if not findings and truth.get("fixed_locations"):
        return grade_twin(results, truth, w, tol)
    scope_mode, in_scope_at = scope_of(truth)
    traps = [t for t in traps or [] if isinstance(t, dict) and is_trap(t)]
    unmatched, trap_hits, outside, complete_claims = [], [], [], []

    def accepts(f, primary):
        targets = [f["primary_location"]] + f.get("alternative_primary_locations", [])
        return any(near(*primary, t, tol) for t in targets)

    scores = {}  # (result index, finding index) -> score_match() of every pair that may match
    for idx, res in enumerate(results):
        if is_complete_claim(res):  # says a control closes the path: not a claim of a weakness
            continue
        risk = risk_of(res.get("ruleId", ""))
        primary = primary_of(res)
        res_cwes = cwe_set((res.get("properties") or {}).get("cwe"))
        # A result matches only a finding of its own risk family, as an OWASP Benchmark result
        # counts only in its own category. (v3.2 briefly allowed a cross-family match on a shared
        # CWE for CWE-map scanners; reverted 2026-10-12, the client spec is followed first and
        # OWASP Benchmark where it is silent.)
        for j, f in enumerate(findings):
            if risk is None or risk != f["risk_type"] or not accepts(f, primary):
                continue
            if require_cwe and not (res_cwes & finding_cwes(f)):
                continue
            scores[(idx, j)] = score_match(res, f, ptol)
    in_scope = sum(1 for res in results if not is_complete_claim(res) and in_scope_at(primary_of(res)[0]))
    pairs = assign(scores, len(results), len(findings), w, in_scope)
    matched = {findings[j]["id"]: (idx, results[idx]) for idx, j in pairs.items()}

    for idx, res in enumerate(results):
        rule = res.get("ruleId", "")
        primary = primary_of(res)
        if idx in pairs:
            continue
        if is_complete_claim(res):
            complete_claims.append({"index": idx, "ruleId": rule, "location": primary})
            continue
        if not in_scope_at(primary[0]):
            outside.append({"index": idx, "ruleId": rule, "location": primary})
            continue
        unmatched.append({"index": idx, "ruleId": rule, "location": primary})
        for trap in traps:
            if hits_trap(rule, primary, trap, tol):
                trap_hits.append({"trap": trap["id"], "result_index": idx})

    tp, fp, fn = len(matched), len(unmatched), len(findings) - len(matched)
    sub = {k: 0.0 for k in MEASUREMENTS}
    on_detected = {k: [] for k in MEASUREMENTS}
    per_finding = []

    for j, f in enumerate(findings):
        links = {k: f[k] for k in ("linked_finding_ids", "link_relation") if k in f}
        if f["id"] not in matched:
            per_finding.append({"finding": f["id"], "matched": False, **links})
            continue
        idx, res = matched[f["id"]]
        props = res.get("properties") or {}
        m = scores[(idx, j)]
        for k in MEASUREMENTS:
            sub[k] += m[k] / len(findings)
            on_detected[k].append(m[k])
        per_finding.append({
            "finding": f["id"], "matched": True, "result_index": idx, "ruleId": res.get("ruleId", ""),
            "cwe_ok": m["cwe_ok"], "path_steps": m["path_steps"], "controlStatus": props.get("controlStatus"),
            "residualRisk": props.get("residualRisk"), "inapplicable_recommendations": m["inapplicable"],
            "cross_family": m["cross_family"],
            "scores": {k: round(m[k], 4) for k in MEASUREMENTS},
            **links,
        })

    if findings:
        precision = tp / (tp + fp) if (tp + fp) else 0.0
        recall = tp / len(findings)
        detection = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    else:
        claims = [r for r in results if not is_complete_claim(r)]
        detection = 1.0 if not claims else 0.0
        sub = {k: (1.0 if not claims else 0.0) for k in sub}

    # Task level: a risk is predicted only by a result that matched a finding, and it
    # predicts the finding's risk type.
    # The loose variant also counts the rule family of every matched result and of
    # the results counted as false positives (unmatched inside the scope).
    matched_results = [res for _, res in matched.values()]
    predicted = {f["risk_type"] for f in findings if f["id"] in matched}
    loose = predicted | ({risk_of(r.get("ruleId", "")) for r in matched_results
                          + [results[u["index"]] for u in unmatched]} - {None})
    cats = {}
    for f in findings:
        cat = category_of(f["rule_id"])
        cats[cat] = (True, cats.get(cat, (True, False))[1] or f["id"] in matched)
    tl = task_level(truth_risk_types(truth), predicted, cats, loose)

    summary = _summarise(detection, tp, fp, fn, len(trap_hits), sub, w, findings, len(outside))
    summary.update(flat_task_level(tl))
    detail = {"grader_version": GRADER_VERSION, "per_finding": per_finding, "unmatched_results": unmatched,
              "trap_hits": trap_hits, "outside_scope_results": outside, "complete_claims": complete_claims,
              "scope": scope_mode, "task_level": tl,
              "measurements": {"detection": summary["detection"], **{k: summary[k] for k in MEASUREMENTS}},
              "measurements_on_detected": {k: (round(sum(v) / len(v), 4) if v else None)
                                           for k, v in on_detected.items()},
              "require_cwe": require_cwe}
    return summary, detail


def is_trap(entry: dict) -> bool:
    return entry.get("kind", "hard_negative_trap") == "hard_negative_trap" and \
        bool(entry.get("trap_rule_prefixes") or entry.get("trap_rule_ids"))


def grade_negative(results: list, truth: dict, w: dict, tol: int) -> tuple[dict, dict]:
    """A minimal-contrast negative.

    The negative fails on a result in one of three buckets (checked in this order,
    each result counted once):

    - ``near_fix``: its OWASP prefix is a contrast prefix and it lands within
      ``line_tolerance`` of ``fixed_locations``;
    - ``trap``: it hits a ``hard_negative_trap`` entry of ``negative_analyses``
      (its rule id is one of the trap's ``trap_rule_ids``, or, when the trap has
      none, its prefix is in ``trap_rule_prefixes``; within tolerance of the trap);
    - ``in_scope`` (v3.2; v3.3: either risk family): its OWASP prefix is LLM02
      or LLM03 and it lies anywhere in the scope (``scope_of``: the scanner roots minus the excluded
      paths, else ``fix_changed_files``).

    A result whose ``controlStatus`` is "complete" says a control closes the path
    and is never a failure. When it is a contrast-prefix result within tolerance
    of one of the negative's complete ``controls``, it is
    ``complete_control_recognised`` and feeds the ``neg.controls`` sub-score,
    which is reported but not part of the reward; any other is listed under
    ``complete_claims``. Every remaining result is ``fp_outside_scope``. No CWE
    agreement is needed to fail. An empty SARIF scores 1.0.
    """
    contrast = truth.get("contrast_rule_ids") or []
    prefixes = {rule_prefix(r) for r in contrast}
    fixed = truth.get("fixed_locations") or []
    traps = [t for t in truth.get("negative_analyses") or [] if isinstance(t, dict) and is_trap(t)]
    fix_files = set(truth.get("fix_changed_files") or [])
    scope_mode, in_scope_at = scope_of(truth)
    controls = complete_controls(truth)
    ctrl_best = [0.0] * len(controls)
    ctrl_by = [None] * len(controls)
    near_fix, trap_hits, in_scope, outside, loose, recognised, complete_claims = [], [], [], [], set(), [], []
    for idx, res in enumerate(results):
        rule = res.get("ruleId", "")
        primary = primary_of(res)
        entry = {"index": idx, "ruleId": rule, "location": primary}
        props = res.get("properties") or {}
        if is_complete_claim(res):
            named = [c for c, ctrl in enumerate(controls) if near(*primary, ctrl["at"], tol)]
            if named and rule_prefix(rule) in prefixes:
                score = 0.75 + 0.25 * (props.get("residualRisk") == truth.get("residual_risk"))
                for c in named:
                    if score > ctrl_best[c]:
                        ctrl_best[c], ctrl_by[c] = score, idx
                recognised.append({**entry, "controls": [controls[c].get("name") for c in named]})
            else:
                complete_claims.append(entry)
            continue
        is_near = any(near(*primary, loc, tol) for loc in fixed)
        if risk_of(rule) and (is_near or primary[0] in fix_files):
            loose.add(risk_of(rule))
        if is_near and rule_prefix(rule) in prefixes:
            near_fix.append(entry)
            continue
        hit = [t["id"] for t in traps if hits_trap(rule, primary, t, tol)]
        if hit:
            trap_hits.append({**entry, "traps": hit})
        elif risk_of(rule) and in_scope_at(primary[0]):
            in_scope.append(entry)
        else:
            outside.append(entry)
    failing = near_fix + trap_hits + in_scope
    bucket = "+".join(name for name, hits in (("near_fix", near_fix), ("trap", trap_hits), ("in_scope", in_scope))
                      if hits)
    clean = 0.0 if failing else 1.0
    sub = {k: clean for k in MEASUREMENTS}
    predicted = {risk_of(e["ruleId"]) for e in failing} - {None}
    # A6: a failing result is a false positive of the category it claims (its own rule
    # id), not of the contrast category that shares its prefix. A rule id that names
    # no known category falls back to the contrast categories of its prefix.
    flagged = set()
    for e in failing:
        cat = category_of(e["ruleId"])
        if cat in KNOWN_CATEGORIES:
            flagged.add(cat)
        else:
            flagged |= {category_of(r) for r in contrast if rule_prefix(r) == rule_prefix(e["ruleId"])}
    cats = {category_of(r): (False, False) for r in contrast}
    cats.update({c: (False, True) for c in flagged})
    tl = task_level(truth_risk_types(truth), predicted, cats, loose | predicted)
    summary = _summarise(clean, 0, len(failing), 0, len(trap_hits), sub, w, [], len(outside))
    summary.update(flat_task_level(tl))
    summary.update({"neg.fail.near_fix": int(bool(near_fix)), "neg.fail.trap": int(bool(trap_hits)),
                    "neg.fail.in_scope": int(bool(in_scope))})
    detail = {"grader_version": GRADER_VERSION, "negative": True, "contrast_rule_ids": contrast,
              "failure_bucket": bucket or None, "scope": scope_mode,
              "results_near_fixed_code": near_fix, "trap_hits": trap_hits, "results_in_scope": in_scope,
              "complete_claims": complete_claims, "outside_scope_results": outside, "task_level": tl}
    if controls:
        summary["neg.controls"] = round(sum(ctrl_best) / len(controls), 4)
        summary["neg.complete_control_recognised"] = len(recognised)
        detail["complete_control_recognised"] = recognised
        detail["complete_controls"] = [
            {"name": ctrl.get("name"), "at": ctrl["at"], "recognised": ctrl_by[c] is not None,
             "result_index": ctrl_by[c], "score": ctrl_best[c]} for c, ctrl in enumerate(controls)]
    return summary, detail


def complete_controls(truth: dict) -> list:
    """The negative's ``controls`` with status "complete" and a usable ``at`` location."""
    out = []
    for ctrl in truth.get("controls") or []:
        if not isinstance(ctrl, dict):
            continue
        at = ctrl.get("at")
        if ctrl.get("status") == "complete" and isinstance(at, dict) and at.get("file") and _is_line(at.get("start_line")):
            out.append(ctrl)
    return out


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
    detail = {"grader_version": GRADER_VERSION, "twin": True, "results_near_fixed_code": near_fix, "outside_scope_results": outside,
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


# ---- snippet ids and the gt-0.2 annotation fields ----------------------------------------

SINK_ROLES = ("sink", "action")
EGRESS_KINDS = ("external", "internal")
PATH_START_ROLES = ("source", "model_decision")
MANIFEST_PATH_RE = re.compile(r"[A-Za-z_]\w*(\[\d+\])*(\.[A-Za-z_]\w*(\[\d+\])*)*")


def snippet_id(task_id: str, file: str, start: int, end: int) -> str:
    """The stable primary key of a labelled code snippet: ``<task_id>:<file>:<start>-<end>``."""
    return f"{task_id}:{file}:{start}-{end}"


def snippet_text(repo, file: str, start: int, end: int) -> str:
    """Lines ``start`` to ``end`` (1-based, inclusive) of ``repo/file``, CRLF read as LF, joined with LF."""
    if Path(file).is_absolute() or ".." in Path(file).parts:
        raise ValueError(f"{file}: not a repo-relative path")
    text = (Path(repo) / file).read_bytes().decode("utf-8").replace("\r\n", "\n")
    lines = text.split("\n")
    if text.endswith("\n"):
        lines.pop()
    if not (_is_line(start) and _is_line(end) and start <= end <= len(lines)):
        raise ValueError(f"{file}: lines {start}-{end} are outside the file ({len(lines)} lines)")
    return "\n".join(lines[start - 1:end])


def snippet_sha256(repo, file: str, start: int, end: int) -> str:
    """SHA-256 (hex) of ``snippet_text``, the value ``snippet_sha256`` holds in the ground truth."""
    return hashlib.sha256(snippet_text(repo, file, start, end).encode("utf-8")).hexdigest()


def _locations(node, where: str = ""):
    """(json path, object) for every location (an object with ``file`` and ``start_line``)."""
    if isinstance(node, dict):
        if isinstance(node.get("file"), str) and "start_line" in node:
            yield where, node
        for k, v in node.items():
            yield from _locations(v, f"{where}.{k}" if where else k)
    elif isinstance(node, list):
        for i, v in enumerate(node):
            yield from _locations(v, f"{where}[{i}]")


def _schema_at_least(truth: dict, major: int, minor: int) -> bool:
    m = re.fullmatch(r"gt-(\d+)\.(\d+)", str(truth.get("schema_version", "")))
    return bool(m) and (int(m.group(1)), int(m.group(2))) >= (major, minor)


def resolve_manifest_path(manifest, path: str):
    """The value at ``path`` (``authorized_recipients[1].data_scope``) in the manifest. KeyError if absent."""
    if not isinstance(path, str) or not MANIFEST_PATH_RE.fullmatch(path):
        raise KeyError(path)
    node = manifest
    for name, indexes in re.findall(r"([A-Za-z_]\w*)((?:\[\d+\])*)", path):
        if not isinstance(node, dict) or name not in node:
            raise KeyError(path)
        node = node[name]
        for i in re.findall(r"\[(\d+)\]", indexes):
            if not isinstance(node, list) or int(i) >= len(node):
                raise KeyError(path)
            node = node[int(i)]
    return node


def _norm_text(text: str) -> str:
    return " ".join(str(text).split()).lower().rstrip(".")


def _asset_problems(name: str, f: dict, manifest, fixtures) -> list[str]:
    asset = f["affected_asset"]
    if not isinstance(asset, dict) or not isinstance(asset.get("fixture_ids"), list):
        return [f"{name}: affected_asset must be an object with a fixture_ids list"]
    problems = []
    ids = asset["fixture_ids"]
    if not ids and not isinstance(asset.get("resource"), str):
        problems.append(f"{name}: affected_asset with no fixture_ids must name a resource")
    if fixtures is not None:
        problems += [f"{name}: affected_asset fixture {i!r} is not in the manifest" for i in ids if i not in fixtures]
        canary = (f.get("evidence") or {}).get("canary_id")
        if canary:
            want = sorted(k for k, x in fixtures.items() if x.get("canary_id") == canary)
            if not want:
                problems.append(f"{name}: evidence.canary_id {canary!r} is on no manifest fixture")
            elif not set(want) <= set(ids):
                problems.append(f"{name}: affected_asset.fixture_ids {ids} miss {want} (the fixtures carrying "
                                f"canary {canary})")
        classes = {x.get("asset_class") for i, x in fixtures.items() if i in ids}
        if ids and "data_class" in asset and asset["data_class"] not in classes:
            problems.append(f"{name}: affected_asset.data_class {asset['data_class']!r} is not the asset_class "
                            f"of its fixtures {sorted(map(str, classes))}")
    if "manifest_path" in asset and isinstance(manifest, dict):
        try:
            resolve_manifest_path(manifest, asset["manifest_path"])
        except KeyError:
            problems.append(f"{name}: affected_asset.manifest_path {asset['manifest_path']!r} is not in the manifest")
    return problems


def _finding_annotation_problems(name: str, f: dict, strict: bool, manifest, boundaries, fixtures) -> list[str]:
    problems = []
    if "affected_asset" in f:
        problems += _asset_problems(name, f, manifest, fixtures)
    elif strict:
        problems.append(f"{name}: missing affected_asset")
    for i, step in enumerate(f.get("path") or []):
        if not isinstance(step, dict):
            continue
        eg = step.get("egress")
        if eg is None:
            if strict and step.get("role") in SINK_ROLES:
                problems.append(f"{name} path[{i}] ({step.get('role')}): missing egress")
        elif not isinstance(eg, dict) or eg.get("kind") not in EGRESS_KINDS or not isinstance(eg.get("boundary"), str):
            problems.append(f"{name} path[{i}]: egress must be {{kind: external|internal, boundary: <id>}}")
        elif boundaries is not None and eg["boundary"] not in boundaries:
            problems.append(f"{name} path[{i}]: egress boundary {eg['boundary']!r} is not a manifest "
                            f"trust_boundaries id")
    cons = f.get("consequence")
    if cons is None:
        if strict and f.get("risk_type") == "excessive_agency":
            problems.append(f"{name}: missing consequence (excessive_agency)")
    elif not isinstance(cons, str) or not cons.strip():
        problems.append(f"{name}: consequence must be a sentence")
    elif isinstance(f.get("rationale"), str) and _norm_text(cons) not in _norm_text(f["rationale"]):
        problems.append(f"{name}: consequence is not taken from the rationale")
    vio = f.get("violates")
    if vio is None:
        if strict:
            problems.append(f"{name}: missing violates")
    elif not isinstance(vio, list) or not vio:
        problems.append(f"{name}: violates must be a non-empty list")
    else:
        for j, v in enumerate(vio):
            if not isinstance(v, dict) or not isinstance(v.get("manifest_path"), str) \
                    or not isinstance(v.get("summary"), str):
                problems.append(f"{name}: violates[{j}] needs manifest_path and summary")
                continue
            if isinstance(manifest, dict):
                try:
                    resolve_manifest_path(manifest, v["manifest_path"])
                except KeyError:
                    problems.append(f"{name}: violates[{j}].manifest_path {v['manifest_path']!r} is not in "
                                    f"the manifest")
    if strict:
        starts = [s for s in f.get("path") or [] if isinstance(s, dict) and s.get("role") in PATH_START_ROLES]
        if not starts:
            problems.append(f"{name}: path has no source or model_decision step")
        elif starts[0].get("required") is not True:
            problems.append(f"{name}: the first source or model_decision step (step {starts[0].get('step')}) "
                            f"must be required")
    for j, ctrl in enumerate(f.get("controls") or []):
        if isinstance(ctrl, dict):
            for key in ("expected_at", "at"):
                if key in ctrl:
                    problems += _location_problems(ctrl[key], f"{name} controls[{j}].{key}")
    return problems


def _negative_control_problems(truth: dict, strict: bool) -> list[str]:
    problems = []
    fixed = {(x.get("file"), x.get("start_line"), x.get("end_line", x.get("start_line")))
             for x in truth.get("fixed_locations") or [] if isinstance(x, dict)}
    ctrls = truth.get("controls")
    if ctrls is None:
        if strict:
            problems.append("negative: missing controls (the complete controls the fix adds)")
        ctrls = []
    elif not isinstance(ctrls, list) or (strict and not ctrls):
        problems.append("negative: controls must be a non-empty list")
        ctrls = []
    for j, ctrl in enumerate(ctrls):
        where = f"controls[{j}]"
        if not isinstance(ctrl, dict):
            problems.append(f"{where}: not an object")
            continue
        if ctrl.get("status") != "complete":
            problems.append(f"{where}: a negative's control must have status 'complete'")
        at = ctrl.get("at")
        p = _location_problems(at, f"{where}.at")
        problems += p
        if not p and (at["file"], at["start_line"], at.get("end_line", at["start_line"])) not in fixed:
            problems.append(f"{where}.at is not one of fixed_locations")
    if strict and not isinstance(truth.get("residual_risk"), str):
        problems.append("negative: missing residual_risk")
    return problems


def _annotation_problems(truth: dict, repo, manifest) -> list[str]:
    """The gt-0.2 checks. Shapes are checked whenever a field is present, presence from gt-0.2 on."""
    problems = []
    strict = _schema_at_least(truth, 0, 2)
    task_id = truth.get("task_id")
    for where, loc in _locations({k: v for k, v in truth.items() if k != "evidence"}):
        if strict and not ("snippet_id" in loc and "snippet_sha256" in loc):
            problems.append(f"{where}: missing snippet_id or snippet_sha256")
        start, end = loc.get("start_line"), loc.get("end_line", loc.get("start_line"))
        if not (_is_line(start) and _is_line(end)):
            continue
        if "snippet_id" in loc and task_id and loc["snippet_id"] != snippet_id(task_id, loc["file"], start, end):
            problems.append(f"{where}: snippet_id {loc['snippet_id']!r} does not name {loc['file']}:{start}-{end}")
        if "snippet_sha256" in loc and repo is not None:
            try:
                digest = snippet_sha256(repo, loc["file"], start, end)
            except (OSError, ValueError) as exc:
                problems.append(f"{where}: cannot hash snippet: {exc}")
                continue
            if digest != loc["snippet_sha256"]:
                problems.append(f"{where}: snippet_sha256 does not match the code at {loc['file']}:{start}-{end} "
                                f"(check the label still points at the right lines, then rerun "
                                f"tools/snippet_ids.py)")
    boundaries = fixtures = None
    if isinstance(manifest, dict):
        boundaries = {b.get("id") for b in manifest.get("trust_boundaries") or [] if isinstance(b, dict)}
        fixtures = {x.get("fixture_id"): x for x in manifest.get("fixtures") or [] if isinstance(x, dict)}
    for n, f in enumerate(truth.get("findings") or []):
        if isinstance(f, dict):
            problems += _finding_annotation_problems(f"finding {f.get('id', n)}", f, strict, manifest,
                                                     boundaries, fixtures)
    if truth.get("variant_role") == "negative" and "contrast_rule_ids" in truth:
        problems += _negative_control_problems(truth, strict)
    return problems


def check_truth(truth: dict, repo=None, manifest=None) -> list[str]:
    """Problems in a ground truth that would make grading silently wrong. Empty when fine.

    Checks required fields, line ranges, that every finding has a CWE when
    ``matching.require_cwe`` is true (otherwise it can never match), and that
    no two different findings have accepted locations (primary or alternative)
    whose ``line_tolerance`` windows overlap (at most twice the tolerance
    apart in one file), when one result could match both (same risk type and,
    under require_cwe, a shared CWE). Such a result can be credited to
    either finding, so which one detected the issue is not well defined.
    Two findings that name each other in ``shared_location_with`` are exempt:
    one fix there closes both, and each result is still credited once.
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
    for key in ("scanner_roots", "excluded_paths"):
        v = matching.get(key)
        if v is not None and not (isinstance(v, list) and all(isinstance(x, str) and x for x in v)):
            problems.append(f"matching.{key} must be a list of repo-relative paths, got {v!r}")
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
        if isinstance(entry, dict) and is_trap(entry):
            if "trap_rule_prefixes" in entry and not isinstance(entry["trap_rule_prefixes"], list):
                problems.append(f"negative_analyses[{i}]: trap_rule_prefixes must be a list")
            ids = entry.get("trap_rule_ids")
            if ids is not None and not (isinstance(ids, list) and all(isinstance(r, str) for r in ids)):
                problems.append(f"negative_analyses[{i}]: trap_rule_ids must be a list of rule ids")
            if not isinstance(entry.get("trap_rule_prefixes"), list) and not isinstance(ids, list):
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
            # v3.3: an explicit, two-sided waiver allows a shared fix point (one fix closes both
            # findings); the one-to-one assignment then credits one result to one of them.
            if fb.get("id") in (fa.get("shared_location_with") or []) and \
                    fa.get("id") in (fb.get("shared_location_with") or []):
                continue
            for x in la:
                for y in lb:
                    if x["file"] == y["file"] and _gap(x, y) <= 2 * tol:
                        problems.append(
                            f"findings {fa['id']} and {fb['id']} have overlapping accepted locations "
                            f"(line_tolerance {tol}): {x['file']}:{x['start_line']} and "
                            f"{y['file']}:{y['start_line']}, "
                            f"a result there can match either finding")
    if manifest is None and repo is not None:
        mf = Path(repo) / "security_manifest.json"
        if mf.is_file():
            try:
                manifest = json.loads(mf.read_text(encoding="utf-8"))
            except ValueError as exc:
                problems.append(f"cannot read {mf}: {exc}")
    problems += _annotation_problems(truth, repo, manifest)
    return problems


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sarif", default="/app/output/findings.sarif")
    ap.add_argument("--truth", default=str(Path(__file__).with_name("ground_truth.json")))
    ap.add_argument("--out", default="/logs/verifier")
    ap.add_argument("--check-truth", action="store_true",
                    help="validate the ground truth and exit (1 on any problem), without grading")
    ap.add_argument("--repo", default=None,
                    help="with --check-truth: the task repo to hash snippets against (default: "
                         "../environment/repo next to the truth's folder, when it exists)")
    args = ap.parse_args()
    if args.check_truth:
        repo = args.repo
        if repo is None:
            guess = Path(args.truth).resolve().parent.parent / "environment" / "repo"
            repo = guess if guess.is_dir() else None
        try:
            problems = check_truth(json.loads(Path(args.truth).read_text(encoding="utf-8")), repo)
        except (OSError, ValueError) as exc:
            problems = [f"cannot read {args.truth}: {exc}"]
        for p in problems:
            print(f"{args.truth}: {p}")
        print(f"{args.truth}: {'ok' if not problems else f'{len(problems)} problems'}")
        sys.exit(1 if problems else 0)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    try:
        truth = json.loads(Path(args.truth).read_text(encoding="utf-8"))
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
