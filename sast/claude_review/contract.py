"""The task's output contract, read from the instruction Harbor passes to ``run``.

Every task's ``instruction.md`` carries the same output contract: a ``Scope``
table of ruleIds and their definitions, the SARIF fields to report (with the
path roles, ``controlStatus`` and ``residualRisk`` values), and a
``Recommendation catalogue`` table. Harbor hands that text to
``ScannerAgent.run(instruction, ...)``. In scoped mode the Claude review builds
its custom scan instructions from it at run time (:func:`scan_instructions`),
so the reviewer is told what every scanner is told, by the task itself, not by
a copy kept in this harness.

:func:`parse` reads only what the contract states and returns None when any
part is missing (an instruction with no contract, such as a placeholder): the
agent then falls back to the bundled ``scoped_scan_instructions.txt`` and
records which text it used.

The generated text has a fixed preamble (written here, the same for every
task) and the task's own tables. It follows the upstream prompt's format for
``custom_scan_instructions``: bold headers ending in a colon, then ``- `` list
items.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

#: A table row whose first cell is one backticked id: ``| `ID` | text |``.
_ROW = re.compile(r"^\s*\|\s*`([^`]+)`\s*\|\s*(.*?)\s*\|\s*$")
_RULE_ID = re.compile(r"^LLM\d\d\.[A-Z]+(?:\.[A-Z]+)+$")
_REC_ID = re.compile(r"^REC-[A-Z0-9-]+$")
_TICKED = re.compile(r"`([A-Za-z_][A-Za-z0-9_]*)`")


@dataclass(frozen=True)
class Contract:
    """What the instruction says, in its own order."""

    #: (ruleId, definition) rows of the Scope table.
    rules: tuple[tuple[str, str], ...]
    #: (REC id, control) rows of the Recommendation catalogue.
    recommendations: tuple[tuple[str, str], ...]
    #: The path step roles (``properties.role``).
    roles: tuple[str, ...]
    #: ``properties.controlStatus`` values.
    control_statuses: tuple[str, ...]
    #: ``properties.residualRisk`` values.
    residual_risks: tuple[str, ...]

    def describe(self) -> dict[str, list[str]]:
        """The ids and values, for the run metadata (no definitions)."""
        return {
            "rule_ids": [r for r, _ in self.rules],
            "recommendation_ids": [r for r, _ in self.recommendations],
            "roles": list(self.roles),
            "control_statuses": list(self.control_statuses),
            "residual_risks": list(self.residual_risks),
        }


def _values_after(flat: str, field: str, lead: str = "") -> tuple[str, ...]:
    """The backticked values that follow ``field`` up to the end of its sentence."""
    match = re.search(re.escape(field) + lead + r"(.+?)(?:\.\s|\.$|$)", flat)
    if not match:
        return ()
    values: list[str] = []
    for value in _TICKED.findall(match.group(1)):
        if value not in values:
            values.append(value)
    return tuple(values)


def parse(instruction: str | None) -> Contract | None:
    """The contract in ``instruction``, or None when any part of it is missing."""
    if not instruction:
        return None
    rules: list[tuple[str, str]] = []
    recs: list[tuple[str, str]] = []
    for line in instruction.splitlines():
        match = _ROW.match(line)
        if not match:
            continue
        ident, text = match.group(1).strip(), " ".join(match.group(2).split())
        if not text:
            continue
        if _RULE_ID.match(ident) and ident not in dict(rules):
            rules.append((ident, text))
        elif _REC_ID.match(ident) and ident not in dict(recs):
            recs.append((ident, text))
    flat = " ".join(instruction.split())
    roles = _values_after(flat, "`properties.role`", r"[^.]*?one of:?\s*")
    controls = _values_after(flat, "`properties.controlStatus`", r":\s*")
    risks = _values_after(flat, "`properties.residualRisk`", r":\s*")
    if not (rules and recs and roles and controls and risks):
        return None
    return Contract(rules=tuple(rules), recommendations=tuple(recs), roles=roles, control_statuses=controls,
                    residual_risks=risks)


def _quoted(values: tuple[str, ...] | list[str]) -> str:
    """``"a", "b" or "c"``."""
    items = ['"{}"'.format(v) for v in values]
    return items[0] if len(items) == 1 else ", ".join(items[:-1]) + " or " + items[-1]


def scan_instructions(contract: Contract) -> str:
    """The scoped mode's custom scan instructions: the fixed preamble and the task's tables."""
    rule_ids = [r for r, _ in contract.rules]
    roles = contract.roles
    example = [{"file": "src/app/tools.py", "line": 12, "role": roles[0]},
               {"file": "src/app/client.py", "line": 40, "role": roles[-1]}]
    example_text = "[" + ", ".join(
        '{{"file": "{file}", "line": {line}, "role": "{role}"}}'.format(**step) for step in example) + "]"
    lines = ["**Risks in scope for this review (the task's ruleIds):**"]
    lines += ["- {}: {}".format(rule, " ".join(text.split())) for rule, text in contract.rules]
    lines += [
        "",
        "**Application context and output for this review:**",
        "- Read the file security_manifest.json at the repository root first, before any other file. It describes "
        "the application's intended task, its actors, trust boundaries, and what data, actions, purposes and "
        "recipients are authorised. Judge every potential issue against it. Data or capability that the manifest "
        "authorises is not a finding.",
        "- Report each finding at the code that must change to fix it, one finding per independently fixable "
        "weakness.",
        "- In addition to the fields of the required output schema, give every finding the six JSON fields below.",
        '- "rule_id": the risk the finding belongs to, one of {}, as defined above. A weakness that is both a '
        "disclosure and an agency risk is two findings, one per rule_id.".format(_quoted(rule_ids)),
        '- "cwe": a JSON list of the CWE IDs that best describe the weakness, most specific first, for example '
        '["CWE-532"] or ["CWE-78", "CWE-77"]. Use real CWE IDs only.',
        '- "path": a JSON list of the steps of the reachable path in order, from where the data or the model '
        "decision originates to where the disclosure or the action happens, for example {}. Each step names a "
        "file relative to the repository root, a line in it and a role, which is one of {}.".format(
            example_text, _quoted(roles)),
        '- "control_status": one of {}, for the controls on the path.'.format(_quoted(contract.control_statuses)),
        '- "residual_risk": one of {}.'.format(_quoted(contract.residual_risks)),
        '- "recommendation_ids": a JSON list of the IDs from the recommendation catalogue below that would close '
        'the path. List only the controls that apply to this finding. The free text "recommendation" field stays '
        "as it is.",
        "",
        "**Recommendation catalogue:**",
    ]
    lines += ["- {}: {}".format(rec, " ".join(text.split())) for rec, text in contract.recommendations]
    return "\n".join(lines) + "\n"
