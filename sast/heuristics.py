"""Fixed rules for the SARIF fields a pattern scanner cannot measure, ``heuristics-1``.

``controlStatus``, ``residualRisk`` and ``recommendations`` need judgment about
the code around a finding. A pattern or taint scanner has none, so these values
come from small, fixed tables and are the same for every task. They are
heuristics, not semantic analysis, and were written from the task's
recommendation catalogue and the rules' own metadata without looking at labels.

- ``controlStatus`` is always ``"none"``. A taint or pattern rule reports a
  finding exactly when it saw no sanitiser on the path, so "none" is what the
  tool itself is claiming. It never claims "partial" or "complete".
- ``residualRisk`` follows the rule's own severity and impact metadata:
  severity ERROR (or CRITICAL/HIGH) or ``metadata.impact: HIGH`` gives
  ``high``; else severity WARNING/MEDIUM gives ``medium``; else INFO/LOW gives
  ``low``. Anything unrecognised is ``medium``.
- ``recommendations`` come from :data:`RULE_RECOMMENDATIONS` (one per task
  ruleId) plus :data:`CWE_RECOMMENDATIONS` (CWE-specific, only within the same
  ruleId family), using only the task's REC-* catalogue ids.
- A dataflow sink "crosses a boundary" (used to pick ``LLM02.SID.HIGH`` over
  ``MEDIUM``) when the code the tool printed at the sink looks like a network,
  email, file-write or logging call (:data:`BOUNDARY_SINK_PATTERNS`).
"""

from __future__ import annotations

import re

VERSION = "heuristics-1"

CONTROL_STATUS = "none"

#: The task's recommendation catalogue (instruction.md), in its order.
CATALOGUE = (
    "REC-AUTHZ-BEFORE-RETRIEVAL",
    "REC-MINIMIZE-CONTEXT",
    "REC-SENSITIVE-DATA-FILTER",
    "REC-SINK-SIDE-IFC",
    "REC-DISABLE-AUTO-CONTEXT",
    "REC-MINIMIZE-TOOLS",
    "REC-SPLIT-READ-WRITE",
    "REC-NARROW-TYPED-TOOLS",
    "REC-LEAST-PRIVILEGE",
    "REC-USER-SECURITY-CONTEXT",
    "REC-COMPLETE-MEDIATION",
    "REC-ACTION-BOUND-APPROVAL",
    "REC-POLICY-GATE",
)

#: The control the client spec lists first for each risk the agent reports.
RULE_RECOMMENDATIONS: dict[str, tuple[str, ...]] = {
    # Data crosses a boundary: block it at the sink.
    "LLM02.SID.HIGH": ("REC-SINK-SIDE-IFC",),
    # Data reaches model-visible state: filter it before it gets there.
    "LLM02.SID.MEDIUM": ("REC-SENSITIVE-DATA-FILTER",),
    # Code/command/query/path/URL execution: narrow, typed, allow-listed tools.
    "LLM03.EA.FUNCTIONALITY": ("REC-NARROW-TYPED-TOOLS",),
    "LLM03.EA.PERMISSIONS": ("REC-LEAST-PRIVILEGE",),
}

#: Extra, CWE-specific controls, keyed by (ruleId family, CWE). The family is the
#: ruleId's first part (``LLM02``/``LLM03``), so a CWE only adds a control for
#: the risk it was reported under.
CWE_RECOMMENDATIONS: dict[tuple[str, str], tuple[str, ...]] = {
    # Missing or wrong authorisation on data: authorise inside the query.
    ("LLM02", "CWE-284"): ("REC-AUTHZ-BEFORE-RETRIEVAL",),
    ("LLM02", "CWE-285"): ("REC-AUTHZ-BEFORE-RETRIEVAL",),
    ("LLM02", "CWE-639"): ("REC-AUTHZ-BEFORE-RETRIEVAL",),
    ("LLM02", "CWE-862"): ("REC-AUTHZ-BEFORE-RETRIEVAL",),
    ("LLM02", "CWE-863"): ("REC-AUTHZ-BEFORE-RETRIEVAL",),
    # Sensitive values in logs, errors or exposed data: redact them.
    ("LLM02", "CWE-200"): ("REC-SENSITIVE-DATA-FILTER",),
    ("LLM02", "CWE-209"): ("REC-SENSITIVE-DATA-FILTER",),
    ("LLM02", "CWE-212"): ("REC-SENSITIVE-DATA-FILTER",),
    ("LLM02", "CWE-359"): ("REC-SENSITIVE-DATA-FILTER",),
    ("LLM02", "CWE-532"): ("REC-SENSITIVE-DATA-FILTER",),
    # Sent to another party or sphere: check the flow at the sink.
    ("LLM02", "CWE-201"): ("REC-SINK-SIDE-IFC",),
    ("LLM02", "CWE-538"): ("REC-SINK-SIDE-IFC",),
    ("LLM02", "CWE-668"): ("REC-SINK-SIDE-IFC",),
    # Privileged execution: run as the user, not a shared privileged identity.
    ("LLM03", "CWE-250"): ("REC-USER-SECURITY-CONTEXT",),
}

#: Code at a sink that sends data out of the process: network, email, file
#: write or logging. Matched case-insensitively against what the tool printed.
BOUNDARY_SINK_PATTERNS: dict[str, re.Pattern[str]] = {
    "network": re.compile(
        r"\b(requests|httpx|aiohttp|urllib\d?|urlopen|http\.client|axios|fetch|webhook|socket)"
        r"\b|\.(post|put|patch|request|send)\s*\(", re.IGNORECASE),
    "email": re.compile(r"smtp|send_?mail|send_?email|nodemailer|\bmail\b", re.IGNORECASE),
    "file_write": re.compile(
        r"\.write(lines)?\s*\(|write_(text|bytes)\s*\(|writeFile(Sync)?\s*\(|appendFile(Sync)?\s*\(|"
        r"\bjson\.dump\s*\(|createWriteStream", re.IGNORECASE),
    "logging": re.compile(
        r"\b(logging|logger|log|console)\s*\.\s*(debug|info|warn|warning|error|exception|critical|log|trace)\b",
        re.IGNORECASE),
}

_HIGH = {"ERROR", "CRITICAL", "HIGH"}
_MEDIUM = {"WARNING", "MEDIUM"}
_LOW = {"INFO", "LOW", "INVENTORY", "EXPERIMENT"}


def residual_risk(severity: str | None, impact: str | None) -> str:
    """``low``/``medium``/``high`` from the rule's severity and ``metadata.impact``."""
    sev = str(severity or "").strip().upper()
    if sev in _HIGH or str(impact or "").strip().upper() == "HIGH":
        return "high"
    if sev in _MEDIUM:
        return "medium"
    if sev in _LOW:
        return "low"
    return "medium"


def recommendations(rule: str, cwes: list[str] | tuple[str, ...]) -> list[str]:
    """Catalogue ids for a result, in catalogue order, no duplicates."""
    family = rule.split(".")[0]
    chosen = set(RULE_RECOMMENDATIONS.get(rule, ()))
    for cwe in cwes:
        chosen.update(CWE_RECOMMENDATIONS.get((family, cwe), ()))
    return [rec for rec in CATALOGUE if rec in chosen]


def boundary_sink_kind(code: str) -> str | None:
    """"network", "email", "file_write" or "logging" if the sink code looks like one."""
    for kind, pattern in BOUNDARY_SINK_PATTERNS.items():
        if pattern.search(code or ""):
            return kind
    return None
