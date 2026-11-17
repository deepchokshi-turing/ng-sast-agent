#!/usr/bin/env python3
"""Fill solution/findings.sarif (the oracle) from tests/ground_truth.json, and keep it in line after a label edit.

    python tools/label_rules/sync_oracle.py <tasks dir | tasks/batch-N> [--task NAME ...] [--check] [--overwrite]

It turns the scaffold's oracle template (tools/scaffold_pair.py ``oracle()``:
one result per finding or complete control, ``TODO(builder)`` messages,
locations copied while the ground truth was still a template) into a complete
oracle, and on a built oracle it only rewrites what the ground truth decides.
A value counts as missing when it is absent, empty or a placeholder (a string
holding ``TODO``, such as the scaffold's ``TODO(builder): ...`` and
``TODO/path/relative/to/environment/repo``). Valid hand-written values are kept.

Positive tasks. Each oracle result is tied to a ground-truth finding by
``properties.findingId`` (or, with no ``findingId``, by a rule id only one
finding has). A finding with no result gets a new one (in the first run; the
run and the driver's rule entry are created when missing). Then, per result:

* ``ruleId`` (missing): the finding's ``rule_id``; ``level`` (missing): "error";
* ``message.text`` (missing): the finding's ``consequence``, else its required
  path steps' notes in order, joined with "; " (only the finding's own text);
* primary location: the finding's ``primary_location`` when the result has
  none, when it names a placeholder file, or when it lies outside
  ``line_tolerance`` of every accepted location (primary and alternatives);
* ``codeFlows``: rebuilt from the finding's ``path`` (every step, in order,
  with ``properties.role`` and the step note as the message);
* ``properties.findingId``: the finding id; ``controlStatus`` and
  ``residualRisk``: copied from the finding;
* ``properties.cwe`` (the property grade.py reads): placeholder entries are
  dropped; the rest is kept while it shares a CWE
  with the finding's ``primary_cwe``/``acceptable_cwes``, else set to
  ``[primary_cwe]`` (the first valid CWE of those when the primary is not one);
* ``properties.recommendations``: cut to ids the finding lists (required or
  acceptable), with the first ``required_any_of`` id put in front when none
  is required (so an empty or missing list gets that id).

Negative tasks. Each complete control (``controls[]`` with status "complete")
is tied to the result naming it in ``properties.control``; a control with no
result gets a new one (``contrast_rule_ids[0]``, level "note"). Per result:
missing ``ruleId``/``level``/``message`` (the control's ``note``) are filled,
a missing or placeholder location becomes the control's ``at``,
``controlStatus`` "complete" and the negative's ``residual_risk`` are set,
placeholder ``cwe`` entries are dropped, and missing ``cwe``/``recommendations``
become ``[]``.

A value that would have to come from a ground-truth field that is itself a
placeholder is left alone and reported, as is an oracle result naming no
finding. Then grade the oracle with the task's grader (task_format/grade.py,
the same code as the grader image); it must score 1.0. Idempotent: a second
run writes nothing.

``--overwrite`` (opt-in; without it the behaviour above is unchanged) also
replaces values that are present but stale, i.e. disagree with the ground
truth, and prints every present value it replaces as ``old -> new`` (with
``--check`` it prints them and writes nothing). On top of the default rewrites:

* positive: a ``ruleId`` other than the finding's ``rule_id``; a ``level``
  other than "error"; a primary location that is not exactly (file, start,
  end) the finding's ``primary_location`` or one of its alternatives, even
  inside ``line_tolerance`` (set to ``primary_location``); ``properties.cwe``
  entries outside ``primary_cwe``/``acceptable_cwes`` (dropped, then
  ``[primary_cwe]`` when none is left);
* negative: a ``ruleId`` not in ``contrast_rule_ids`` (set to the first); a
  ``level`` other than "note"; a location that is not exactly the control's
  ``at``;
* both: bare driver rule entries (``{"id": ...}`` only, as this script adds them)
  that no result names any more (removed).

It also prints the values the default always rewrites (``findingId``,
``codeFlows``, ``controlStatus``, ``residualRisk``, recommendations cut to the
finding's ids) when they change. ``message.text`` is builder prose and is
never overwritten, nor are a negative's ``cwe``/``recommendations``.
"""

from __future__ import annotations

import json

import _common as c

grade = c.load_grade()


class Log:
    """With ``--overwrite``, records each present value that is replaced; otherwise only assigns."""

    def __init__(self, on: bool):
        self.on = on
        self.lines: list[str] = []

    def put(self, obj: dict, key: str, new, label: str) -> None:
        """Set ``obj[key] = new``; log ``old -> new`` when the old value was present and differs."""
        old = obj.get(key)
        if self.on and not todo(old) and old != new:
            self.lines.append(f"{label} {key}: {short(old)} -> {short(new)}")
        obj[key] = new


def short(value) -> str:
    """One line: locations as file:start-end, code flows as role@file:start-end plus their JSON, the rest as JSON."""
    def loc(x):
        u, s, e = grade.phys(x)
        role = (x.get("properties") or {}).get("role")
        return f"{role + '@' if role else ''}{u}:{s}-{e}"
    js = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    try:
        if isinstance(value, list) and value and all(isinstance(x, dict) and "physicalLocation" in x for x in value):
            return "[" + ", ".join(loc(x) for x in value) + "]"
        if isinstance(value, list) and value and all(isinstance(x, dict) and "threadFlows" in x for x in value):
            steps = [loc(t) for cf in value for tf in cf.get("threadFlows") or [] for t in tf.get("locations") or []]
            return "[" + ", ".join(steps) + "] " + js
    except (AttributeError, TypeError, KeyError):
        pass
    return js


def exact(res: dict, target: dict) -> bool:
    """The result's primary location is exactly ``target`` (file, start line, end line)."""
    u, s, e = grade.primary_of(res)
    return u == target.get("file") and s == target.get("start_line") \
        and e == target.get("end_line", target.get("start_line"))


def todo(value) -> bool:
    """Missing, empty, or a scaffold placeholder (any string holding TODO)."""
    if value is None or value == "" or value == [] or value == {}:
        return True
    return isinstance(value, str) and "TODO" in value


def tfl(loc: dict, role: str | None, note: str | None) -> dict:
    out = {"location": {"physicalLocation": {
        "artifactLocation": {"uri": loc["file"]},
        "region": {"startLine": loc["start_line"], "endLine": loc.get("end_line", loc["start_line"])}}}}
    if note:
        out["location"]["message"] = {"text": note}
    if role:
        out["properties"] = {"role": role}
    return out


def placeholder_loc(loc) -> bool:
    return not isinstance(loc, dict) or todo(loc.get("file")) or not isinstance(loc.get("start_line"), int)


def message_of(f: dict) -> str | None:
    """The finding's own one-line account: its consequence, else its required step notes."""
    if not todo(f.get("consequence")):
        return f["consequence"].strip()
    notes = [s.get("note") for s in f.get("path") or [] if s.get("required")]
    if not notes or any(todo(n) for n in notes):
        return None
    text = "; ".join(n.strip().rstrip(".") for n in notes) + "."
    return text[0].upper() + text[1:]


def cwe_of(f: dict) -> list[str] | None:
    for v in [f.get("primary_cwe"), *(f.get("acceptable_cwes") or [])]:
        if grade.norm_cwe(v):
            return [v]
    return None


def drop_todo_cwes(props: dict) -> None:
    """Remove placeholder entries (the scaffold's "CWE-TODO") from properties.cwe."""
    if isinstance(props.get("cwe"), list):
        props["cwe"] = [v for v in props["cwe"] if not todo(v)]
    elif todo(props.get("cwe")) and "cwe" in props:
        props["cwe"] = []


def has_message(res: dict) -> bool:
    return not todo(((res.get("message") or {}).get("text") or "").strip())


def first_run(sarif: dict) -> dict:
    runs = sarif.setdefault("runs", [])
    if not runs:
        runs.append({"tool": {"driver": {"name": "oracle", "version": "gt-0.2", "rules": []}}, "results": []})
    return runs[0]


def ensure_rule(run: dict, rule_id: str) -> None:
    rules = run.setdefault("tool", {}).setdefault("driver", {"name": "oracle"}).setdefault("rules", [])
    if not any(isinstance(r, dict) and r.get("id") == rule_id for r in rules):
        rules.append({"id": rule_id})


def sync_positive(sarif: dict, truth: dict, problems: list[str], log: Log) -> None:
    by_id = {f["id"]: f for f in truth.get("findings") or []}
    tol = truth["matching"]["line_tolerance"]
    pairs, seen = [], set()
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
            pairs.append((run, res, f))
    for fid, f in by_id.items():
        if fid in seen:
            continue
        run = first_run(sarif)
        res = {"ruleId": f["rule_id"], "level": "error", "message": {"text": ""}, "locations": [],
               "properties": {"findingId": fid}}
        run.setdefault("results", []).append(res)
        pairs.append((run, res, f))
    ow = log.on
    for run, res, f in pairs:
        fid = f["id"]
        props = res.setdefault("properties", {})
        log.put(props, "findingId", fid, fid)
        if todo(res.get("ruleId")) or (ow and res.get("ruleId") != f["rule_id"]):
            log.put(res, "ruleId", f["rule_id"], fid)
        ensure_rule(run, res["ruleId"])
        res.setdefault("level", "error")
        if ow and res["level"] != "error":
            log.put(res, "level", "error", fid)
        if not has_message(res):
            text = message_of(f)
            if text is None:
                problems.append(f"{fid}: message left empty (consequence and path notes are placeholders)")
            else:
                res["message"] = {"text": text}
        accepted = [f["primary_location"]] + list(f.get("alternative_primary_locations") or [])
        prim = grade.primary_of(res)
        if todo(prim[0]) or not any(grade.near(*prim, a, tol) for a in accepted) \
                or (ow and not any(isinstance(a, dict) and exact(res, a) for a in accepted)):
            if placeholder_loc(f["primary_location"]):
                problems.append(f"{fid}: primary_location is a placeholder")
            else:
                log.put(res, "locations", [tfl(f["primary_location"], None, None)["location"]], fid)
        log.put(res, "codeFlows", [{"threadFlows": [{"locations": [
            tfl(s, s.get("role"), s.get("note")) for s in f.get("path") or []]}]}], fid)
        log.put(props, "controlStatus", f["control_status"], fid)
        log.put(props, "residualRisk", f["residual_risk"], fid)
        drop_todo_cwes(props)
        if ow and isinstance(props.get("cwe"), list):
            kept = [v for v in props["cwe"] if grade.cwe_set([v]) & grade.finding_cwes(f)]
            if kept != props["cwe"]:
                log.put(props, "cwe", kept, fid)
        if not grade.cwe_set(props.get("cwe")) & grade.finding_cwes(f):
            cwe = cwe_of(f)
            if cwe is None:
                problems.append(f"{fid}: primary_cwe and acceptable_cwes hold no CWE")
            else:
                log.put(props, "cwe", cwe, fid)
        spec = f["recommendations"]
        ok = set(spec["required_any_of"]) | set(spec.get("acceptable") or [])
        recs = [r for r in grade.rec_set(props.get("recommendations")) if r in ok]
        recs = [r for r in (props.get("recommendations") or []) if r in recs] \
            if isinstance(props.get("recommendations"), list) else recs
        if not set(recs) & set(spec["required_any_of"]):
            recs = [spec["required_any_of"][0]] + recs
        log.put(props, "recommendations", recs, fid)


def sync_negative(sarif: dict, truth: dict, problems: list[str], log: Log) -> None:
    controls = [ctrl for ctrl in truth.get("controls") or []
                if isinstance(ctrl, dict) and ctrl.get("status") == "complete"]
    by_name = {ctrl.get("name"): ctrl for ctrl in controls}
    rule = (truth.get("contrast_rule_ids") or [None])[0]
    seen = set()
    pairs = []
    if any(not todo(name) for name in by_name):
        # Drop the scaffold's template result (control "TODO_control_name") once the truth names real controls.
        for run in sarif.get("runs") or []:
            if run.get("results"):
                run["results"] = [r for r in run["results"]
                                  if not todo((r.get("properties") or {}).get("control"))]
    for run in sarif.get("runs") or []:
        for res in run.get("results") or []:
            props = res.get("properties") or {}
            ctrl = by_name.get(props.get("control"))
            if ctrl is not None and props.get("controlStatus") in ("complete", None, ""):
                seen.add(ctrl.get("name"))
                pairs.append((run, res, ctrl))
    for ctrl in controls:
        if ctrl.get("name") in seen:
            continue
        if todo(ctrl.get("name")) or rule is None:
            problems.append(f"control {ctrl.get('name')!r}: no oracle result, and its name or "
                            "contrast_rule_ids is a placeholder")
            continue
        run = first_run(sarif)
        res = {"ruleId": rule, "level": "note", "message": {"text": ""}, "locations": [],
               "properties": {"control": ctrl["name"]}}
        run.setdefault("results", []).append(res)
        pairs.append((run, res, ctrl))
    ow = log.on
    for run, res, ctrl in pairs:
        props = res.setdefault("properties", {})
        name = f"control {ctrl.get('name')}"
        if rule and (todo(res.get("ruleId")) or (ow and res.get("ruleId") not in truth["contrast_rule_ids"])):
            log.put(res, "ruleId", rule, name)
        if res.get("ruleId"):
            ensure_rule(run, res["ruleId"])
        res.setdefault("level", "note")
        if ow and res["level"] != "note":
            log.put(res, "level", "note", name)
        if not has_message(res):
            if todo(ctrl.get("note")):
                problems.append(f"control {ctrl.get('name')}: message left empty (its note is a placeholder)")
            else:
                res["message"] = {"text": ctrl["note"].strip()}
        tol = (truth.get("matching") or {}).get("line_tolerance", 0)
        stale = not placeholder_loc(ctrl.get("at")) and (not grade.near(*grade.primary_of(res), ctrl["at"], tol)
                                                           or (ow and not exact(res, ctrl["at"])))
        if todo(grade.primary_of(res)[0]) or stale:
            # Missing/placeholder location, or one left at stale (e.g. upstream) lines away from the control's ``at``.
            if placeholder_loc(ctrl.get("at")):
                problems.append(f"control {ctrl.get('name')}: at is a placeholder")
            else:
                log.put(res, "locations", [tfl(ctrl["at"], None, None)["location"]], name)
        log.put(props, "controlStatus", "complete", name)
        log.put(props, "residualRisk", truth.get("residual_risk"), name)
        drop_todo_cwes(props)
        props.setdefault("cwe", [])
        props.setdefault("recommendations", [])


def prune_rules(sarif: dict, log: Log) -> None:
    """``--overwrite``: drop bare rule entries (``{"id"}`` only, as ``ensure_rule`` adds) no result names."""
    for run in sarif.get("runs") or []:
        driver = (run.get("tool") or {}).get("driver") or {}
        if not isinstance(driver.get("rules"), list):
            continue
        used = {res.get("ruleId") for res in run.get("results") or []}
        kept = [r for r in driver["rules"] if not isinstance(r, dict) or set(r) != {"id"} or r.get("id") in used]
        if kept != driver["rules"]:
            log.put(driver, "rules", kept, "driver")


def main() -> int:
    ap = c.parser(__doc__)
    ap.add_argument("--overwrite", action="store_true",
                    help="also replace present values that disagree with the ground truth (ruleId, level, "
                         "inexact primary location, stray CWEs) and print each replaced value as old -> new; "
                         "message texts are never overwritten")
    args = ap.parse_args()
    bad = 0
    for task in c.tasks(args.root, args.task):
        sf = task / "solution" / "findings.sarif"
        if not sf.is_file():
            print(f"{task.name}: no oracle")
            continue
        _, truth = c.read_json(task / "tests" / "ground_truth.json")
        raw, sarif = c.read_json(sf)
        problems: list[str] = []
        log = Log(args.overwrite)
        if truth.get("findings"):
            sync_positive(sarif, truth, problems, log)
        else:
            sync_negative(sarif, truth, problems, log)
        if args.overwrite:
            prune_rules(sarif, log)
        changed = c.write_json_like(sf, raw, sarif, args.check)
        if args.check and changed:
            problems.append("would change oracle")
        print(f"{task.name}: {'; '.join(problems) if problems else ('changed' if changed else 'ok')}")
        for line in log.lines:
            print(f"  {'would replace' if args.check else 'replaced'} {line}")
        bad += bool(problems)
    return 1 if bad else 0


if __name__ == "__main__":
    c.run(main)
