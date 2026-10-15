"""What the agent asks Claude Code for: the audit request text.

Built on the host and sent to the driver in the request file. The skill itself
(SKILL.md and its companion files) is unchanged; this text is the user turn
that starts it, as the skill's README shows ("security audit this codebase",
"do a security review, output to ~/audits/my-project").

- Both modes: an explicit full-audit request (so the skill runs its six-phase
  workflow instead of guidance mode), the run's fixed settings that the skill
  would otherwise ask a user for (target, output directory, profile, budget,
  no prior runs, no execution sandbox for target code), the validator command
  lines, and one side file, ``sast-annotations.json``, next to the skill's own
  outputs. The skill's ``findings.json`` schema forbids extra fields, so what
  the SARIF profile needs and the skill does not record is asked for there,
  keyed by the record's ``fingerprint``.
- Stock mode: the side file carries a CWE list only. The skill records no CWE,
  and without one no finding could be mapped to a task ruleId.
- Scoped mode: the task's output contract, read from the instruction Harbor
  passes to ``run`` with ``sast.claude_review.contract`` (the bundled fallback
  when the instruction carries none), is added as guidance, and the side file
  also carries ``rule_id``, ``location``, ``trace_roles``,
  ``control_status``, ``residual_risk`` and ``recommendation_ids``, each
  restricted to the contract's own values.
"""

from __future__ import annotations

from ..claude_review.contract import Contract
from ..codex_security.request import fallback_contract

ANNOTATIONS_FILE = "sast-annotations.json"
#: Trace kinds of the skill's report schema, and the contract roles each may be refined to.
KIND_ROLES = {
    "entrypoint": ("source", "model_decision"),
    "propagation": ("context_assembly", "model_consumption", "control_point", "root_cause"),
    "sink": ("sink",),
}


def _quoted(values) -> str:
    items = ['"{}"'.format(v) for v in values]
    return items[0] if len(items) == 1 else ", ".join(items[:-1]) + " or " + items[-1]


def audit_request(*, target: str, out_dir: str, skill_dir: str, profile: str, budget: int | None) -> str:
    """The full-audit request with the run's settings (both modes)."""
    return "\n".join([
        "Run a full security audit of the codebase at {} with the security-audit skill. This is an explicit "
        "codebase audit request: use full audit mode and complete all six phases.".format(target),
        "",
        "Settings for this run. There is no user to answer questions, so do not ask any; use these:",
        "- Skill directory: {0}. Read {0}/SKILL.md first and follow it.".format(skill_dir),
        "- Target: {}. It is a plain copy of the repository's files with no version control; record the source "
        "ref as \"unversioned-copy\".".format(target),
        "- Output directory: {}. It does not exist yet and is outside the target; create it.".format(out_dir),
        "- Profile: {}.".format(profile),
        "- Budget: {}.".format("{} agent invocations".format(budget) if budget else "none (null)"),
        "- Prior runs: none.",
        "- No OS-enforced sandbox is available for target-controlled code. Do not build, run or test target code; "
        "keep a lead whose decisive fact needs execution as needs_validation, as the skill says.",
        "- Tools: the shell runs only read-only commands (such as ls, cat, grep, find, head, wc, sort), mkdir -p "
        "inside the output directory and the two validator commands below; anything else is refused. Write the "
        "output files with the file tools. Sub-agents have the same tools.",
        "- Run each validator as its own shell command, exactly as written, with nothing chained before or after it "
        "(its exit status and output are reported to you):",
        "  node {}/validate-coverage-ledger.cjs {}/coverage-ledger.json".format(skill_dir, out_dir),
        "  node {}/validate-findings.cjs {}/findings.json".format(skill_dir, out_dir),
        "",
    ])


def stock_annotations(out_dir: str) -> str:
    return "\n".join([
        "When Phase 6 is done, write one more file, {}/{}, for the tool that reads your results. Do not add "
        "fields to findings.json: its schema forbids them. The file is a JSON object {{\"findings\": [...]}} with "
        "one entry for each record of findings.json whose verdict is confirmed or needs_validation:".format(
            out_dir, ANNOTATIONS_FILE),
        '- "fingerprint": the record\'s fingerprint.',
        '- "cwe": a JSON list of the CWE IDs that best describe the weakness, most specific first, for example '
        '["CWE-78"]. Use real CWE IDs only.',
        "",
    ])


def scoped_annotations(out_dir: str, contract: Contract) -> str:
    """The task's contract as guidance, and the side file with the contract's fields."""
    rule_ids = [r for r, _ in contract.rules]
    roles = {kind: [r for r in allowed if r in contract.roles] for kind, allowed in KIND_ROLES.items()}
    lines = [
        "This audit is for a benchmark with its own scope. Keep the skill's workflow, evidence bar and outputs as "
        "they are, and also use the following.",
        "",
        "Risks in scope (the task's ruleIds):",
    ]
    lines += ["- {}: {}".format(rule, " ".join(text.split())) for rule, text in contract.rules]
    lines += [
        "",
        "Application context:",
        "- Read security_manifest.json at the target's root before any other file of the target. It describes the "
        "application's intended task, its actors, trust boundaries, and which data, actions, purposes and "
        "recipients are authorised. Judge every candidate against it: data or capability that the manifest "
        "authorises is not a finding.",
        "",
        "When Phase 6 is done, write one more file, {}/{}, for the tool that reads your results. Do not add "
        "fields to findings.json: its schema forbids them. The file is a JSON object {{\"findings\": [...]}} with "
        "one entry for each record of findings.json whose verdict is confirmed or needs_validation. A record that "
        "is both a disclosure risk and an agency risk gets two entries with the same fingerprint, one per rule_id. "
        "Each entry has these fields:".format(out_dir, ANNOTATIONS_FILE),
        '- "fingerprint": the record\'s fingerprint.',
        '- "rule_id": one of {}, as defined above.'.format(_quoted(rule_ids)),
        '- "cwe": a JSON list of the CWE IDs that best describe the weakness, most specific first, for example '
        '["CWE-532"]. Use real CWE IDs only.',
        '- "location": {"file": ..., "start_line": ..., "end_line": ...}: the code that must change to close the '
        "path, the file relative to the target's root.",
        '- "trace_roles": a JSON list with one role per entry of the record\'s trace, in the same order. An '
        "entrypoint entry is {}; a propagation entry is {}, or null when none fits; a sink entry is {}.".format(
            _quoted(roles["entrypoint"] or ["source"]), _quoted(roles["propagation"] or ["null"]),
            _quoted(roles["sink"] or ["sink"])),
        '- "control_status": one of {}, for the controls on the path. Use "partial" when a control exists but does '
        'not close the path, and "complete" when a control closes it.'.format(_quoted(contract.control_statuses)),
        '- "residual_risk": one of {}.'.format(_quoted(contract.residual_risks)),
        '- "recommendation_ids": a JSON list of the IDs from the catalogue below that would close the path. List '
        "only the ones that apply.",
        "",
        "Recommendation catalogue:",
    ]
    lines += ["- {}: {}".format(rec, " ".join(text.split())) for rec, text in contract.recommendations]
    return "\n".join(lines) + "\n"


def build_prompt(mode: str, contract: Contract | None, *, target: str, out_dir: str, skill_dir: str, profile: str,
                 budget: int | None) -> str:
    text = audit_request(target=target, out_dir=out_dir, skill_dir=skill_dir, profile=profile, budget=budget)
    if mode == "scoped":
        return text + scoped_annotations(out_dir, contract or fallback_contract())
    return text + stock_annotations(out_dir)
