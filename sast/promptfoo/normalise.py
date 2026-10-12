"""promptfoo's ``-f json`` comments -> ``Finding`` objects.

Each comment has ``file``, ``startLine`` (optional), ``line``, ``severity``
(critical/high/medium/low/none), ``finding`` (prose), ``fix`` and
``aiAgentPrompt``. ``-f json`` was chosen over ``-f sarif`` because it is the
same data with ``startLine`` and ``line`` kept apart and the "none" (all clear)
comments not dropped (``scanResponseToSarif`` in promptfoo 0.124.1 builds the
SARIF from this response and adds nothing).

- Location: ``file`` (made relative to the scope copy when it is absolute)
  must be one of the copied text files, inside the scope, and ``startLine``
  (``line`` when missing) to ``line`` a range within the file's line count.
  Anything else is dropped and counted. A comment with severity "none" is
  promptfoo's all-clear note, counted and never a finding.
- Fields (scoped mode only), from the header at the start of ``finding`` and
  nothing else (``guidance.HEADER_FORMAT``; the first non-empty line, after an
  optional code fence, with surrounding Markdown emphasis or backticks
  removed): ``RULE`` must be one of the task's ruleIds (the contract's, which
  are ``cwe_map.TASK_RULES``) and becomes ``Finding.task_rule``; ``CWE`` keeps
  well-formed ``CWE-<n>`` ids; ``CONTROL`` and ``RISK`` are kept when they are
  one of the profile's values; ``RECS`` keeps catalogue ids; each ``PATH``
  step ``<file>:<line>[-<end>] <role>`` must pass the same location checks
  and becomes a trace step (its role kept when it is one of
  ``findings.PATH_ROLES``, else the step is kept without one and the role is
  counted). Every rejected value is counted.
- No valid RULE, no finding: the CWE table is not used to guess the ruleId
  from the header's CWEs, and the prose is never read for one. Such comments
  are dropped and listed (``dropped_no_task_rule``). In stock mode no comment
  has a header, so every comment is listed there and the SARIF has no result:
  stock findings cannot be scored, and are kept in the run properties and the
  metadata only.
- Level and heuristic residual risk come from ``severity`` (critical/high:
  error/high, medium: warning/medium, low: note/low; missing: note/medium, as
  promptfoo's own SARIF writer does for the level).
- The prose (header removed) is the message; the severity, a short copy of the
  fix and the raw header line go to ``Finding.extra`` (``toolProperties``,
  never scored).
"""

from __future__ import annotations

import re
from collections import Counter
from typing import Any

from .. import cwe_map, heuristics
from ..findings import CONTROL_STATUSES, PATH_ROLES, RISK_LEVELS, Finding, TraceStep
from ..scope import in_scope, repo_path
from .guidance import HEADER_KEYS

TOOL_RULE_ID = "promptfoo/code-scan-finding"
LEVELS = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}
MESSAGE_CHARS = 1000
EXTRA_CHARS = 500
ROW_CHARS = 300
MAX_PATH_STEPS = 20
MAX_ROWS = 200
_CWE = re.compile(r"^CWE-[1-9][0-9]{0,4}$")
_STEP = re.compile(r"^(?:[-*]\s+)?(?P<file>\S+?):(?P<start>\d+)(?:-(?P<end>\d+))?\s+(?P<role>[A-Za-z_]+)\.?$")
_DECOR = " \t`*>_"


def _text(value: Any, limit: int) -> str:
    return " ".join(str(value or "").split())[:limit]


def _int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    return None


def _clean(line: str) -> str:
    """A header or path line without surrounding whitespace, Markdown emphasis, quote marks or backticks."""
    return line.strip().strip(_DECOR).strip()


def parse_header(text: str) -> tuple[dict[str, str] | None, list[str], str, str | None]:
    """(header fields, raw PATH step lines, prose, problem).

    The header is the first non-empty line of ``text`` (after an optional
    opening code fence). Fields are ``KEY=VALUE`` separated by ";". The result
    is (None, [], text, problem) when there is no header or it cannot be read.
    """
    lines = (text or "").replace("\r\n", "\n").split("\n")
    i = 0
    while i < len(lines) and not lines[i].strip():
        i += 1
    fenced = i < len(lines) and lines[i].strip().startswith("```")
    if fenced:
        i += 1
    if i >= len(lines) or not _clean(lines[i]).upper().startswith("RULE="):
        return None, [], (text or "").strip(), "missing"
    header_line = _clean(lines[i])
    fields: dict[str, str] = {}
    for part in header_line.split(";"):
        part = part.strip()
        if not part:
            continue
        key, sep, value = part.partition("=")
        key = key.strip().upper()
        if not sep or key not in HEADER_KEYS or key in fields:
            return None, [], (text or "").strip(), "malformed"
        fields[key] = value.strip()
    i += 1
    steps: list[str] = []
    if i < len(lines) and _clean(lines[i]).upper().rstrip(":") == "PATH":
        i += 1
        while i < len(lines) and lines[i].strip() and not lines[i].strip().startswith("```"):
            steps.append(_clean(lines[i]))
            i += 1
    if fenced:
        while i < len(lines) and not lines[i].strip().startswith("```"):
            i += 1
        i += 1
    prose = "\n".join(lines[i:]).strip()
    fields["_raw"] = header_line
    return fields, steps, prose, None


def _list(value: str | None) -> list[str]:
    if value is None:
        return []
    items = [v.strip() for v in re.split(r"[,\s]+", value) if v.strip()]
    return [] if [v.lower() for v in items] in (["none"], ["n/a"], ["-"]) else items


def _location_problem(file: str, start: int | None, end: int | None, line_counts: dict[str, int],
                      roots: list[str], excludes: list[str]) -> str | None:
    if not file:
        return "no file"
    if not in_scope(file, roots, excludes):
        return "out of scope"
    if file not in line_counts:
        return "not a text file of the scope"
    if start is None or end is None:
        return "no line"
    if start < 1 or end < start or end > line_counts[file]:
        return "line outside the file"
    return None


def _file(raw: Any, scope_dir: str | None) -> str:
    path = str(raw or "").replace("\\", "/")
    if scope_dir:
        prefix = scope_dir.rstrip("/") + "/"
        if path.startswith(prefix):
            path = path[len(prefix):]
    return repo_path(path)


def _path(steps: list[str], line_counts: dict[str, int], roots: list[str], excludes: list[str],
          scope_dir: str | None, dropped: list[list[Any]], roles_rejected: list[str]) -> tuple[TraceStep, ...]:
    trace: list[TraceStep] = []
    for raw in steps:
        match = _STEP.match(raw)
        if not match:
            dropped.append(["not <file>:<line> <role>", raw[:200]])
            continue
        file = _file(match.group("file"), scope_dir)
        start = int(match.group("start"))
        end = int(match.group("end")) if match.group("end") else start
        problem = _location_problem(file, start, end, line_counts, roots, excludes)
        if problem:
            dropped.append([problem, raw[:200]])
            continue
        if len(trace) == MAX_PATH_STEPS:
            dropped.append(["more than {} steps".format(MAX_PATH_STEPS), raw[:200]])
            continue
        role = match.group("role").lower()
        if role not in PATH_ROLES:
            roles_rejected.append(role[:40])
        trace.append(TraceStep(file=file, start_line=start, end_line=end, role=role if role in PATH_ROLES else None))
    return tuple(trace)


def normalise(
    comments: list[Any],
    *,
    mode: str,
    line_counts: dict[str, int],
    roots: list[str],
    excludes: list[str],
    scope_dir: str | None = None,
    rule_ids: tuple[str, ...] = cwe_map.TASK_RULES,
) -> tuple[list[Finding], dict[str, Any]]:
    """(findings, counts for the run metadata)."""
    allowed_rules = tuple(r for r in rule_ids if r in cwe_map.TASK_RULES)
    findings: list[Finding] = []
    tool_findings: list[list[Any]] = []
    dropped_location: list[list[Any]] = []
    dropped_scope: list[list[Any]] = []
    no_rule: list[list[Any]] = []
    headers: Counter[str] = Counter({"valid": 0, "missing": 0, "malformed": 0})
    severities: Counter[str] = Counter()
    rules_rejected: list[str] = []
    cwes_rejected: list[str] = []
    values_rejected: list[str] = []
    recs_rejected: list[str] = []
    path_dropped: list[list[Any]] = []
    roles_rejected: list[str] = []
    assessed: Counter[str] = Counter({"cwe": 0, "path": 0, "path_steps": 0, "control_status": 0, "residual_risk": 0,
                                      "recommendations": 0})
    all_clear = 0

    for item in comments:
        if not isinstance(item, dict):
            dropped_location.append(["not an object", None, None])
            continue
        severity = str(item.get("severity") or "").strip().lower()
        if severity == "none":
            all_clear += 1
            continue
        severities[severity if severity in LEVELS else "missing" if not severity else "other"] += 1
        text = str(item.get("finding") or "")
        raw_file = item.get("file")
        file = _file(raw_file, scope_dir)
        end = _int(item.get("line"))
        start = _int(item.get("startLine")) if item.get("startLine") is not None else end
        tool_findings.append([file or None, start, end, severity or None, _text(text, ROW_CHARS)])
        problem = _location_problem(file, start, end, line_counts, roots, excludes)
        if problem == "out of scope":
            dropped_scope.append([str(raw_file)[:200], item.get("line")])
            continue
        if problem:
            dropped_location.append([problem, file or None, item.get("line")])
            continue

        fields, steps, prose, header_problem = (None, [], text.strip(), "missing")
        if mode == "scoped":
            fields, steps, prose, header_problem = parse_header(text)
        headers[header_problem or "valid"] += 1
        rule = None
        if fields is not None:
            value = fields.get("RULE", "").strip().upper()
            if value in allowed_rules:
                rule = value
            else:
                rules_rejected.append(_text(fields.get("RULE"), 60))
        if rule is None:
            no_rule.append([file, start, end, severity or None,
                            "no header" if fields is None and mode == "scoped" else
                            "stock mode" if mode != "scoped" else "RULE not a task ruleId",
                            _text(text, ROW_CHARS)])
            continue

        cwes: list[str] = []
        for value in _list(fields.get("CWE")):
            cwe = value.upper()
            if _CWE.match(cwe):
                if cwe not in cwes:
                    cwes.append(cwe)
            else:
                cwes_rejected.append(value[:40])
        control = residual = None
        if fields.get("CONTROL"):
            control = fields["CONTROL"].strip().lower()
            if control not in CONTROL_STATUSES:
                values_rejected.append("CONTROL=" + _text(fields["CONTROL"], 40))
                control = None
        if fields.get("RISK"):
            residual = fields["RISK"].strip().lower()
            if residual not in RISK_LEVELS:
                values_rejected.append("RISK=" + _text(fields["RISK"], 40))
                residual = None
        recs: list[str] = []
        for value in _list(fields.get("RECS")):
            rec = value.upper()
            if rec in heuristics.CATALOGUE:
                if rec not in recs:
                    recs.append(rec)
            else:
                recs_rejected.append(value[:60])
        trace = _path(steps, line_counts, roots, excludes, scope_dir, path_dropped, roles_rejected)
        assessed.update({"cwe": bool(cwes), "path": bool(trace), "path_steps": len(trace),
                         "control_status": bool(control), "residual_risk": bool(residual),
                         "recommendations": bool(recs)})
        extra = [("severity", severity or "missing"), ("header", _text(fields.get("_raw"), ROW_CHARS))]
        if item.get("fix"):
            extra.append(("fix", _text(item.get("fix"), EXTRA_CHARS)))
        findings.append(Finding(
            tool_rule_id=TOOL_RULE_ID,
            cwes=tuple(cwes),
            file=file,
            start_line=start,
            end_line=end,
            message=_text(prose, MESSAGE_CHARS) or _text(text, MESSAGE_CHARS) or rule,
            level=LEVELS.get(severity, "note"),
            residual_risk=heuristics.residual_risk(severity, None),
            trace=trace,
            extra=tuple(extra),
            control_status=control,
            assessed_residual_risk=residual,
            recommendations=tuple(recs),
            task_rule=rule,
        ))

    counts = {
        "comments_total": len(comments),
        "comments_all_clear": all_clear,
        "tool_findings": tool_findings[:MAX_ROWS],
        "tool_findings_count": len(tool_findings),
        "findings_by_severity": dict(sorted(severities.items())),
        "dropped_bad_location": dropped_location[:MAX_ROWS],
        "dropped_bad_location_count": len(dropped_location),
        "dropped_out_of_scope": dropped_scope[:MAX_ROWS],
        "dropped_out_of_scope_count": len(dropped_scope),
        "headers": dict(headers),
        "dropped_no_task_rule": no_rule[:MAX_ROWS],
        "dropped_no_task_rule_count": len(no_rule),
        "rule_ids_rejected": rules_rejected[:MAX_ROWS],
        "cwes_rejected": cwes_rejected[:MAX_ROWS],
        "cwes_rejected_count": len(cwes_rejected),
        "assessed_fields": dict(assessed),
        "assessed_values_rejected": values_rejected[:MAX_ROWS],
        "recommendations_rejected": recs_rejected[:MAX_ROWS],
        "path_steps_dropped": path_dropped[:MAX_ROWS],
        "path_steps_dropped_count": len(path_dropped),
        # Steps kept without a role: the role is not one of the profile's.
        "path_roles_rejected": roles_rejected[:MAX_ROWS],
    }
    return findings, counts
