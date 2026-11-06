#!/usr/bin/env python3
"""Bring solution/findings.sarif (the oracle) back in line with tests/ground_truth.json after a label edit.

    python tools/label_rules/sync_oracle.py <harbor-tasks dir> [--task NAME ...] [--check]

Positive tasks: every oracle result whose ``properties.findingId`` names a
ground-truth finding (or, with no ``findingId``, whose rule id only one
finding has) gets

* its code flow rebuilt from the finding's ``path`` (every step, in order, with
  ``properties.role`` and the step note as the message);
* ``controlStatus`` and ``residualRisk`` copied from the finding;
* ``recommendations`` cut to ids the finding lists (required or acceptable),
  with the first ``required_any_of`` id put in front when none is required.

The primary location is left alone while it lies within ``line_tolerance`` of
an accepted location, and reset to ``primary_location`` otherwise.

Negative tasks: a result naming a complete control (``properties.control``)
gets the negative's ``residual_risk``.

The result's rule id, message and other properties are kept. Then grade the
oracle with the task's own tests/grade.py; it must score 1.0. Idempotent.
"""

from __future__ import annotations

import _common as c

grade = c.load_grade()


def tfl(loc: dict, role: str | None, note: str | None) -> dict:
    out = {"location": {"physicalLocation": {
        "artifactLocation": {"uri": loc["file"]},
        "region": {"startLine": loc["start_line"], "endLine": loc.get("end_line", loc["start_line"])}}}}
    if note:
        out["location"]["message"] = {"text": note}
    if role:
        out["properties"] = {"role": role}
    return out


def sync_positive(sarif: dict, truth: dict, problems: list[str]) -> None:
    by_id = {f["id"]: f for f in truth.get("findings") or []}
    tol = truth["matching"]["line_tolerance"]
    seen = set()
    for run in sarif.get("runs") or []:
        for res in run.get("results") or []:
            props = res.setdefault("properties", {})
            f = by_id.get(props.get("findingId"))
            same_rule = [g for g in by_id.values() if g.get("rule_id") == res.get("ruleId")]
            if f is None and "findingId" not in props and len(same_rule) == 1:
                f = same_rule[0]  # an oracle written before findingId existed: the only finding of its rule
            if f is None:
                problems.append(f"oracle result {res.get('ruleId')} names no finding")
                continue
            seen.add(f["id"])
            accepted = [f["primary_location"]] + list(f.get("alternative_primary_locations") or [])
            prim = grade.primary_of(res)
            if not any(grade.near(*prim, a, tol) for a in accepted):
                pl = f["primary_location"]
                res["locations"] = [tfl(pl, None, None)["location"]]
            res["codeFlows"] = [{"threadFlows": [{"locations": [
                tfl(s, s.get("role"), s.get("note")) for s in f.get("path") or []]}]}]
            props["controlStatus"] = f["control_status"]
            props["residualRisk"] = f["residual_risk"]
            spec = f["recommendations"]
            ok = set(spec["required_any_of"]) | set(spec.get("acceptable") or [])
            recs = [r for r in grade.rec_set(props.get("recommendations")) if r in ok]
            recs = [r for r in (props.get("recommendations") or []) if r in recs] \
                if isinstance(props.get("recommendations"), list) else recs
            if not set(recs) & set(spec["required_any_of"]):
                recs = [spec["required_any_of"][0]] + recs
            props["recommendations"] = recs
    missing = sorted(set(by_id) - seen)
    if missing:
        problems.append(f"no oracle result for {missing}")


def sync_negative(sarif: dict, truth: dict) -> None:
    names = {ctrl.get("name") for ctrl in truth.get("controls") or []}
    for run in sarif.get("runs") or []:
        for res in run.get("results") or []:
            props = res.get("properties") or {}
            if props.get("control") in names and props.get("controlStatus") == "complete":
                props["residualRisk"] = truth.get("residual_risk")


def main() -> int:
    args = c.parser(__doc__).parse_args()
    bad = 0
    for task in c.tasks(args.root, args.task):
        sf = task / "solution" / "findings.sarif"
        if not sf.is_file():
            print(f"{task.name}: no oracle")
            continue
        _, truth = c.read_json(task / "tests" / "ground_truth.json")
        raw, sarif = c.read_json(sf)
        problems: list[str] = []
        if truth.get("findings"):
            sync_positive(sarif, truth, problems)
        else:
            sync_negative(sarif, truth)
        changed = c.write_json_like(sf, raw, sarif, args.check)
        if args.check and changed:
            problems.append("would change oracle")
        print(f"{task.name}: {'; '.join(problems) if problems else ('changed' if changed else 'ok')}")
        bad += bool(problems)
    return 1 if bad else 0


if __name__ == "__main__":
    c.run(main)
