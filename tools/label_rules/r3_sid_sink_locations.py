#!/usr/bin/env python3
"""R3 (mechanical part): accept the disclosure sink of every LLM02 finding, and trap it in the fixed twin.

    python tools/label_rules/r3_sid_sink_locations.py <harbor-tasks dir> [--task NAME ...] [--check]

Spec 2.3: a disclosure finding "must identify where protected data becomes
available to an unauthorized recipient or channel" (audit D F-M4). So a
scanner that puts an LLM02 result on the disclosure sink must be credited.

Positive side. For every finding whose rule id starts with ``LLM02``, each
``sink`` path step (and each of that step's ``alternatives``) becomes an
``alternative_primary_locations`` entry, with ``why`` "disclosure sink: <step
note>", unless an accepted location of the finding already covers those
lines. The check_truth guard is applied first: a sink whose window
(``line_tolerance``) would overlap an accepted location of another finding of
the same risk type (and, under ``require_cwe``, a shared CWE) is NOT added and
is reported, because a result there could match either finding.

Negative side. The twin (VARIANTS.json) is a minimal-contrast negative. For
each such sink whose file is byte-identical in both twins (so the fix did not
touch it), that is not already within ``line_tolerance`` of the twin's
``fixed_locations`` and not already covered by an LLM02 trap, a
``hard_negative_trap`` is added to the twin's ``negative_analyses``:
``id`` ``<finding>-sink<k>``, ``contrast_of``, ``trap_rule_prefixes``
["LLM02"], ``trap_rule_ids`` [the finding's rule id] and a template
``why_not_a_finding``. Review those texts by hand: the template says the
protected data no longer reaches the sink, which must be true of the fix.

A sink in a file the fix changed is reported, not trapped (its lines may have
moved): decide by hand. New locations are stamped with ``snippet_id`` and
``snippet_sha256``. Idempotent.
"""

from __future__ import annotations

import json
from pathlib import Path

import _common as c

grade = c.load_grade()

LOC_KEYS = ("file", "start_line", "end_line")


def span(loc: dict) -> tuple[str, int, int]:
    return loc["file"], loc["start_line"], loc.get("end_line", loc["start_line"])


def covers(outer: dict, inner: dict) -> bool:
    f1, a1, b1 = span(outer)
    f2, a2, b2 = span(inner)
    return f1 == f2 and a1 <= a2 and b2 <= b1


def stamp(task_id: str, repo: Path, loc: dict) -> dict:
    f, a, b = span(loc)
    out = {"file": f, "start_line": a, "end_line": b,
           "snippet_id": grade.snippet_id(task_id, f, a, b),
           "snippet_sha256": grade.snippet_sha256(repo, f, a, b)}
    out.update({k: v for k, v in loc.items() if k not in out})
    return out


def accepted(f: dict) -> list[dict]:
    return [f["primary_location"]] + list(f.get("alternative_primary_locations") or [])


def sinks(f: dict) -> list[tuple[dict, str]]:
    out = []
    for step in f.get("path") or []:
        if step.get("role") != "sink":
            continue
        note = step.get("note", "").strip()
        for loc in [step] + list(step.get("alternatives") or []):
            out.append(({k: loc[k] for k in LOC_KEYS if k in loc}, note))
    return out


def clash(truth: dict, f: dict, loc: dict) -> str | None:
    tol = truth["matching"]["line_tolerance"]
    require_cwe = bool(truth["matching"].get("require_cwe"))
    for g in truth.get("findings") or []:
        if g is f or g.get("risk_type") != f.get("risk_type"):
            continue
        if require_cwe and not (grade.finding_cwes(f) & grade.finding_cwes(g)):
            continue
        for x in accepted(g):
            if x["file"] == loc["file"] and grade._gap(x, loc) <= 2 * tol:
                return f"{g['id']} at {x['file']}:{x['start_line']}"
    return None


def same_file(a: Path, b: Path) -> bool:
    return a.is_file() and b.is_file() and a.read_bytes().replace(b"\r\n", b"\n") == b.read_bytes().replace(b"\r\n", b"\n")


def main() -> int:
    args = c.parser(__doc__).parse_args()
    bad = 0
    for task in c.tasks(args.root, args.task):
        gt = task / "tests" / "ground_truth.json"
        raw, truth = c.read_json(gt)
        notes: list[str] = []
        problems: list[str] = []
        if truth.get("variant_role") == "negative" or not truth.get("findings"):
            print(f"{task.name}: skipped (not a positive)")
            continue
        repo = task / "environment" / "repo"
        twin = c.twin_of(args.root, task)
        twin_gt = twin / "tests" / "ground_truth.json" if twin else None
        traw, ttruth = c.read_json(twin_gt) if twin_gt and twin_gt.is_file() else (None, None)
        if ttruth is not None and ttruth.get("variant_role") != "negative":
            ttruth = None
        for f in truth["findings"]:
            if not str(f.get("rule_id", "")).startswith("LLM02"):
                continue
            k = 0
            for loc, note in sinks(f):
                if not any(covers(a, loc) for a in accepted(f)):
                    who = clash(truth, f, loc)
                    if who:
                        problems.append(f"{f['id']}: sink {loc['file']}:{loc['start_line']} not added, "
                                        f"it would overlap {who}")
                    else:
                        why = "disclosure sink: " + (note or "where the protected data reaches the recipient")
                        f.setdefault("alternative_primary_locations", []).append(
                            stamp(truth["task_id"], repo, {**loc, "why": why}))
                        notes.append(f"{f['id']}+{loc['file'].split('/')[-1]}:{loc['start_line']}")
                if ttruth is None:
                    continue
                trepo = twin / "environment" / "repo"
                if not same_file(repo / loc["file"], trepo / loc["file"]):
                    problems.append(f"{f['id']}: sink {loc['file']}:{loc['start_line']} is in a file the fix "
                                    f"changed; trap it in {twin.name} by hand if right")
                    continue
                tol = ttruth["matching"]["line_tolerance"]
                if any(grade.near(*span(loc), x, tol) for x in ttruth.get("fixed_locations") or []):
                    continue
                if any(c.is_trap(t) and "LLM02" in (t.get("trap_rule_prefixes") or []) and covers(t, loc)
                       for t in ttruth.get("negative_analyses") or []):
                    continue
                k += 1
                tid = f"{f['id']}-sink{k}"
                while any(t.get("id") == tid for t in ttruth.get("negative_analyses") or []):
                    k += 1
                    tid = f"{f['id']}-sink{k}"
                entry = stamp(ttruth["task_id"], trepo, loc)
                trap = {"id": tid, "kind": "hard_negative_trap", "contrast_of": f["id"], **entry,
                        "trap_rule_prefixes": ["LLM02"], "trap_rule_ids": [f["rule_id"]],
                        "why_not_a_finding": (f"This is the disclosure sink of {f['id']} in the other twin and "
                                              f"is unchanged here, but after the fix no protected data reaches "
                                              f"it, so an {f['rule_id']} result on these lines is a false alarm.")}
                ttruth.setdefault("negative_analyses", []).append(trap)
                notes.append(f"{twin.name}+{tid}")
        changed = c.write_json_like(gt, raw, truth, args.check)
        if ttruth is not None:
            changed = c.write_json_like(twin_gt, traw, ttruth, args.check) or changed
        if args.check and changed:
            problems.append("would change ground truth")
        msg = "; ".join(problems + (["added " + ", ".join(notes)] if notes else []))
        print(f"{task.name}: {msg or 'ok'}")
        bad += bool(problems)
    return 1 if bad else 0


if __name__ == "__main__":
    c.run(main)
