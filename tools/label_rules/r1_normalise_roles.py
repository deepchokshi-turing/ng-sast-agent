#!/usr/bin/env python3
"""R1: normalise ground-truth and oracle path roles to the seven roles of the output contract.

    python tools/label_rules/r1_normalise_roles.py <harbor-tasks dir> [--task NAME ...] [--check]

The scanner contract (instruction.md) allows ``source``, ``root_cause``,
``context_assembly``, ``model_consumption``, ``model_decision``,
``control_point`` and ``sink``. Older labels used four more roles, which are
mapped (audit B4 A13):

    tool_output  -> model_consumption   (the tool result the model reads)
    pass_through -> context_assembly    (a hop that hands the value on)
    action       -> sink                (the consequential call)
    control      -> control_point

Applied to every ``path[].role`` in tests/ground_truth.json and every
``codeFlows[].threadFlows[].locations[].properties.role`` in
solution/findings.sarif. Any role still outside the contract after the map is
reported (exit 1) and left alone. Idempotent.

A step renamed to ``sink`` gets no ``egress`` here; ``grade.py --check-truth``
reports a sink without one, so add it by hand when that happens.
"""

from __future__ import annotations

from pathlib import Path

import _common as c

ROLE_MAP = {"tool_output": "model_consumption", "pass_through": "context_assembly",
            "action": "sink", "control": "control_point"}


def fix_truth(truth: dict, problems: list[str]) -> int:
    n = 0
    for f in truth.get("findings") or []:
        for step in f.get("path") or []:
            role = step.get("role")
            if role in ROLE_MAP:
                step["role"] = ROLE_MAP[role]
                n += 1
            elif role not in c.CONTRACT_ROLES:
                problems.append(f"{f.get('id')} step {step.get('step')}: unknown role {role!r}")
    return n


def fix_sarif(sarif: dict, problems: list[str]) -> int:
    n = 0
    for run in sarif.get("runs") or []:
        for res in run.get("results") or []:
            for flow in res.get("codeFlows") or []:
                for tf in flow.get("threadFlows") or []:
                    for loc in tf.get("locations") or []:
                        props = loc.get("properties") or {}
                        role = props.get("role")
                        if role in ROLE_MAP:
                            props["role"] = ROLE_MAP[role]
                            n += 1
                        elif role is not None and role not in c.CONTRACT_ROLES:
                            problems.append(f"oracle {res.get('ruleId')}: unknown role {role!r}")
    return n


def main() -> int:
    args = c.parser(__doc__).parse_args()
    bad = 0
    for task in c.tasks(args.root, args.task):
        problems: list[str] = []
        changed = []
        gt = task / "tests" / "ground_truth.json"
        raw, truth = c.read_json(gt)
        if fix_truth(truth, problems) and c.write_json_like(gt, raw, truth, args.check):
            changed.append("ground_truth")
        sf = task / "solution" / "findings.sarif"
        if sf.is_file():
            raw, sarif = c.read_json(sf)
            if fix_sarif(sarif, problems) and c.write_json_like(sf, raw, sarif, args.check):
                changed.append("oracle")
        if args.check and changed:
            problems.append("would change " + ", ".join(changed))
        print(f"{task.name}: {'; '.join(problems) if problems else ('changed ' + ', '.join(changed) if changed else 'ok')}")
        bad += bool(problems)
    return 1 if bad else 0


if __name__ == "__main__":
    c.run(main)
