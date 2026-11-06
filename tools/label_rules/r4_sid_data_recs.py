#!/usr/bin/env python3
"""R4: LLM02 findings may only be satisfied by data controls, not by a generic policy gate.

    python tools/label_rules/r4_sid_data_recs.py <harbor-tasks dir> [--task NAME ...] [--check] [--add REC ...]

Audit B4 A4: answering ``REC-POLICY-GATE`` alone earned full recommendation
credit on most disclosure findings. For every finding whose rule id starts
with ``LLM02``, ``recommendations.required_any_of`` keeps only the data
controls of spec section 3 (``REC-SINK-SIDE-IFC``, ``REC-SENSITIVE-DATA-FILTER``,
``REC-MINIMIZE-CONTEXT``, ``REC-AUTHZ-BEFORE-RETRIEVAL``,
``REC-DISABLE-AUTO-CONTEXT``). Any other id there (``REC-POLICY-GATE``,
``REC-LEAST-PRIVILEGE``, ...) moves to ``acceptable``, so it still earns half
credit and is never counted as inapplicable.

``--add REC`` (repeatable, data controls only) promotes ids into
``required_any_of`` of every LLM02 finding processed (use with ``--task``),
for a direct fix that the finding should credit in full (audit m12).

A finding left with no data control in ``required_any_of`` is reported (exit 1)
and not changed: pick its controls by hand. Idempotent.
"""

from __future__ import annotations

import _common as c


def fix(f: dict, add: list[str], problems: list[str]) -> None:
    recs = f.get("recommendations") or {}
    req = list(recs.get("required_any_of") or [])
    acc = list(recs.get("acceptable") or [])
    for r in add:
        if r not in req:
            req.append(r)
    keep = [r for r in req if r in c.DATA_RECS]
    if not keep:
        problems.append(f"{f.get('id')}: no data control in required_any_of {req}; choose by hand")
        return
    moved = [r for r in req if r not in c.DATA_RECS]
    acc = [r for r in acc if r not in keep] + [r for r in moved if r not in acc]
    recs["required_any_of"], recs["acceptable"] = keep, acc


def main() -> int:
    ap = c.parser(__doc__)
    ap.add_argument("--add", action="append", default=[], help="data control to require (repeatable)")
    args = ap.parse_args()
    wrong = [r for r in args.add if r not in c.DATA_RECS]
    if wrong:
        ap.error(f"--add takes data controls only, not {wrong}")
    bad = 0
    for task in c.tasks(args.root, args.task):
        gt = task / "tests" / "ground_truth.json"
        raw, truth = c.read_json(gt)
        problems: list[str] = []
        for f in truth.get("findings") or []:
            if str(f.get("rule_id", "")).startswith("LLM02"):
                fix(f, args.add, problems)
        changed = c.write_json_like(gt, raw, truth, args.check)
        if args.check and changed:
            problems.append("would change ground_truth")
        print(f"{task.name}: {'; '.join(problems) if problems else ('changed' if changed else 'ok')}")
        bad += bool(problems)
    return 1 if bad else 0


if __name__ == "__main__":
    c.run(main)
