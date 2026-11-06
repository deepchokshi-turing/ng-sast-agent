#!/usr/bin/env python3
"""R5: give every hard_negative_trap an explicit ``trap_rule_ids`` list.

    python tools/label_rules/r5_trap_rule_ids.py <harbor-tasks dir> [--task NAME ...] [--check] [--recompute]

``trap_rule_prefixes`` (LLM02, LLM03) says which risk a trap baits. The new
``trap_rule_ids`` names the exact rule ids a scanner would wrongly claim at the
trap lines. Default, per trap, restricted to the trap's prefixes:

* in a negative: its ``contrast_rule_ids`` (the rules the twin's findings carry)
  plus the twin positive's ``partial_credit_rule_ids`` (for example
  ``LLM02.SID.MEDIUM`` next to ``LLM02.SID.HIGH``, ``LLM03.EA.PERMISSIONS`` next
  to ``LLM03.EA.FUNCTIONALITY``), which are just as wrong on safe lines;
* in a positive: the rule ids and partial-credit ids of its own findings plus
  its twin's ``contrast_rule_ids`` (VARIANTS.json).

An existing ``trap_rule_ids`` is kept (it may have been set by hand) unless
``--recompute`` is given (replace it by the default) or ``--merge`` (add the
default ids to it, keeping hand-added ones such as ``LLM03.EA.AUTONOMY``). A trap whose ids come out empty, or whose ids are not
all under its ``trap_rule_prefixes``, is reported (exit 1): review it by hand.
The key is inserted right after ``trap_rule_prefixes``. Idempotent.
"""

from __future__ import annotations

import json

import _common as c


def finding_ids(findings) -> list[str]:
    out = []
    for f in findings or []:
        out += [f["rule_id"]] if f.get("rule_id") else []
        out += list(f.get("partial_credit_rule_ids") or [])
    return out


def default_ids(root, task, truth) -> list[str]:
    ids = list(truth.get("contrast_rule_ids") or [])
    twin = c.twin_of(root, task)
    tw = json.loads((twin / "tests" / "ground_truth.json").read_text(encoding="utf-8")) if twin else {}
    if truth.get("variant_role") == "negative":
        ids += finding_ids(tw.get("findings"))
    else:
        ids += finding_ids(truth.get("findings")) + list(tw.get("contrast_rule_ids") or [])
    return sorted(set(ids))


def with_key_after(entry: dict, anchor: str, key: str, value) -> dict:
    out = {}
    for k, v in entry.items():
        if k == key:
            continue
        out[k] = v
        if k == anchor:
            out[key] = value
    if key not in out:
        out[key] = value
    return out


def main() -> int:
    ap = c.parser(__doc__)
    ap.add_argument("--recompute", action="store_true", help="overwrite existing trap_rule_ids")
    ap.add_argument("--merge", action="store_true", help="add the default ids to existing trap_rule_ids")
    args = ap.parse_args()
    bad = 0
    for task in c.tasks(args.root, args.task):
        gt = task / "tests" / "ground_truth.json"
        raw, truth = c.read_json(gt)
        problems = []
        base = default_ids(args.root, task, truth)
        new = []
        for entry in truth.get("negative_analyses") or []:
            if not c.is_trap(entry):
                new.append(entry)
                continue
            prefixes = entry.get("trap_rule_prefixes") or []
            if not prefixes:
                problems.append(f"{entry.get('id')}: hard_negative_trap without trap_rule_prefixes")
            ids = entry.get("trap_rule_ids")
            dflt = [r for r in base if r.split(".")[0] in prefixes]
            if ids is None or args.recompute:
                ids = dflt
            elif args.merge:
                ids = sorted(set(ids) | set(dflt))
            if not ids:
                problems.append(f"{entry.get('id')}: no rule id under {prefixes}; set trap_rule_ids by hand")
            stray = [r for r in ids if r.split(".")[0] not in prefixes]
            if stray:
                problems.append(f"{entry.get('id')}: trap_rule_ids {stray} are outside trap_rule_prefixes {prefixes}")
            new.append(with_key_after(entry, "trap_rule_prefixes", "trap_rule_ids", ids))
        if "negative_analyses" in truth:
            truth["negative_analyses"] = new
        changed = c.write_json_like(gt, raw, truth, args.check)
        if args.check and changed:
            problems.append("would change ground_truth")
        print(f"{task.name}: {'; '.join(problems) if problems else ('changed' if changed else 'ok')}")
        bad += bool(problems)
    return 1 if bad else 0


if __name__ == "__main__":
    c.run(main)
