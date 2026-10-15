"""The scoped mode's guidance for Promptfoo Code Scanning, and the header it asks for.

promptfoo's ``-f json`` response gives, per finding, only ``file``,
``startLine``, ``line``, ``severity`` and free text (``finding``, ``fix``,
``aiAgentPrompt``); its SARIF has the same, under one generic rule id. Nothing
in it names a task ruleId, a CWE, a path, a control status or a
recommendation. In scoped mode the agent therefore asks, through promptfoo's
own ``--guidance-file``, for a fixed header at the start of every finding's
text (:data:`HEADER_FORMAT`)::

    RULE=<ruleId>; CWE=<CWE-n>[,<CWE-n>...]; CONTROL=<status>; RISK=<level>; RECS=<REC-ID>[,...]|none
    PATH:
    <file>:<line>[-<end line>] <role>
    ...

then an empty line and the prose. ``sast.promptfoo.normalise`` reads only that
header; the prose stays message text and is never mined for fields.

The text is built from the task's own output contract (the instruction Harbor
passes to ``run``, parsed by ``sast.claude_review.contract``), so the scan is
told what every scanner is told, by the task itself. An instruction without a
contract gets the same text built from the harness's copy of the ids
(``builtin_contract``), and the metadata says which was used.
"""

from __future__ import annotations

from .. import cwe_map, heuristics
from ..claude_review import contract as contract_module
from ..claude_review.contract import Contract
from ..findings import CONTROL_STATUSES, PATH_ROLES, RISK_LEVELS

#: The header's version, recorded in the SARIF driver properties and the metadata.
HEADER_FORMAT = "pf-header-1"
#: The header's keys, in the order the guidance gives them.
HEADER_KEYS = ("RULE", "CWE", "CONTROL", "RISK", "RECS")


def builtin_contract() -> Contract:
    """The contract from the harness's own tables, for an instruction that carries none."""
    return Contract(
        rules=tuple((rule, cwe_map.RULE_DESCRIPTIONS[rule]) for rule in cwe_map.TASK_RULES),
        recommendations=tuple((rec, rec) for rec in heuristics.CATALOGUE),
        roles=PATH_ROLES,
        control_statuses=CONTROL_STATUSES,
        residual_risks=RISK_LEVELS,
    )


def contract_for(instruction: str | None) -> tuple[Contract, str]:
    """(the contract, its source): "task_instruction" when the instruction carries one, else "builtin"."""
    parsed = contract_module.parse(instruction)
    if parsed is not None:
        return parsed, "task_instruction"
    return builtin_contract(), "builtin"


def _one_line(text: str) -> str:
    return " ".join(text.split())


def guidance_text(contract: Contract) -> str:
    """The ``--guidance-file`` text: the fixed preamble and header spec, then the task's tables."""
    rule_ids = [r for r, _ in contract.rules]
    rec_ids = [r for r, _ in contract.recommendations]
    roles = list(contract.roles)
    # The example: an excessive-functionality finding, in the contract's own ids where it has them.
    example_rule = cwe_map.EA_FUNCTIONALITY if cwe_map.EA_FUNCTIONALITY in rule_ids else rule_ids[0]
    example_recs = [r for r in ("REC-NARROW-TYPED-TOOLS", "REC-POLICY-GATE") if r in rec_ids] or rec_ids[:2]
    first_role = "model_decision" if "model_decision" in roles else roles[0]
    last_role = "sink" if "sink" in roles else roles[-1]
    lines = [
        "This scan is one task of a security benchmark. Report only the risks listed below.",
        "",
        "Read the file security_manifest.json at the repository root before anything else. It describes the "
        "application's intended task, its actors, trust boundaries, and which data, actions, purposes and recipients "
        "are authorised. Judge every potential issue against it: data or capability that the manifest authorises is "
        "not a finding.",
        "",
        "Risks in scope (ruleIds):",
    ]
    lines += ["- {}: {}".format(rule, _one_line(text)) for rule, text in contract.rules]
    lines += [
        "",
        "Report each finding at the code that must change to close the path, one finding per independently "
        "fixable weakness. A weakness that is both a disclosure and an agency risk is two findings, one per ruleId.",
        "",
        "REQUIRED FORMAT. The text of every finding must start with the header below, before any other text, "
        "as plain text (no Markdown, no code fence), exactly in this form:",
        "",
        "RULE=<ruleId>; CWE=<CWE ids>; CONTROL=<control status>; RISK=<residual risk>; RECS=<recommendation ids>",
        "PATH:",
        "<file>:<line> <role>",
        "<file>:<line> <role>",
        "",
        "After the header leave one empty line, then write your explanation as usual.",
        "",
        "- RULE: exactly one of {}.".format(", ".join(rule_ids)),
        "- CWE: the CWE ids that best describe the weakness, most specific first, separated by commas, for "
        "example CWE-532 or CWE-78,CWE-77. Real CWE ids only.",
        "- CONTROL: one of {}, for the controls on the path. Use partial when a control exists but does not close "
        "the path.".format(", ".join(contract.control_statuses)),
        "- RISK: one of {}, the residual risk.".format(", ".join(contract.residual_risks)),
        "- RECS: the ids from the recommendation catalogue below that would close the path, separated by commas, "
        "or none.",
        "- PATH: one line per step of the reachable path, in order, from where the data or the model decision "
        "originates to where the disclosure or the action happens. <file> is relative to the repository root, "
        "<line> is a line number in that file (or <first>-<last> for a range), and <role> is one of {}.".format(
            ", ".join(roles)),
        "",
        "Example:",
        "",
        "RULE={}; CWE=CWE-94; CONTROL=none; RISK=high; RECS={}".format(example_rule, ",".join(example_recs)),
        "PATH:",
        "src/app/agent.py:40 {}".format(first_role),
        "src/app/tools.py:12-14 {}".format(last_role),
        "",
        "The calculator tool passes the model's expression to eval() ...",
        "",
        "Recommendation catalogue:",
    ]
    lines += ["- {}: {}".format(rec, _one_line(text)) for rec, text in contract.recommendations]
    return "\n".join(lines) + "\n"
