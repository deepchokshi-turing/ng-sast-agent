"""Fixed tables for the fields a pattern scanner cannot measure, ``heuristics-1``.

``controlStatus``, ``residualRisk`` and ``recommendations`` need judgment about
the code around a finding. A pattern or taint scanner has none, so these values
come from small, fixed tables and are the same for every task. They are
heuristics, not semantic analysis, and were written from the task's
recommendation catalogue and the rules' own metadata without looking at labels.

The SARIF writer puts them under ``properties.heuristics``, never in the
top-level fields the grader scores. They are reported as a separate heuristic
track, because a constant that happens to match the dataset's most common label
would otherwise raise a tool-only score with nothing the tool found.

- ``controlStatus`` is always ``"none"``. That is what a taint rule claims (it
  reports a finding only when it saw no sanitiser on the path). A pattern or
  audit rule makes no claim about controls at all, so for those results the
  value is a default, not a measurement.
- ``residualRisk`` follows the rule's own severity and impact metadata:
  severity ERROR (or CRITICAL/HIGH) or ``metadata.impact: HIGH`` gives
  ``high``, else severity WARNING/MEDIUM gives ``medium``, else INFO/LOW gives
  ``low``. Anything unrecognised is ``medium``.
- ``recommendations`` come from :data:`RULE_RECOMMENDATIONS` (one per task
  ruleId) plus :data:`CWE_RECOMMENDATIONS` (CWE-specific, only within the same
  ruleId family), using only the task's REC-* catalogue ids. The per-rule choice
  is the author's pick of the control that fits a pattern finding best. It does
  not follow the order in which the client spec lists the controls (the spec
  lists REC-MINIMIZE-TOOLS first for excessive functionality and
  REC-AUTHZ-BEFORE-RETRIEVAL first for SID Medium).
"""

from __future__ import annotations

VERSION = "heuristics-1"

CONTROL_STATUS = "none"

#: The code copy of the REC-* catalogue ("Recommendation catalogue" table) of the output
#: contract in each task's ``instruction.md``, in its order.
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

#: One control per ruleId the agent reports (see the module docstring).
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

