"""datadog-saist rule -> task ruleId, version ``datadog-map-1``. Frozen: changing it is a new version.

datadog-saist names its rules ``datadog/<language>-<kind>`` (``datadog/python-
excessiveagency``). The table is keyed by ``<kind>``, the same for every
language. It was written on 2026-10-14 from the rule descriptions served by
Datadog's public rule endpoint that day (379 rules, 30 kinds over 14
languages) and the five ruleIds of the task's output contract, before any
datadog-saist result was scored, and without looking at task labels.

Two groups:

- **LLM rules** (Datadog's OWASP-LLM-style rules): decided by what the rule's
  own description says it detects, read against the task's scope table. The
  OWASP numbers Datadog writes in those descriptions (for example
  "LLM10:2026" on improper output handling) are not used: they do not follow
  the task's numbering.
- **Classic rules** (injection, crypto, web): decided by the rule's own CWE
  through ``sast.cwe_map`` version cwe-map-5, exactly as for every pattern
  scanner, and written out here so the table does not change if cwe_map does.

A kind that is not in the table (a rule Datadog adds later) is not reported and
is counted as ``rule_not_in_map``.
"""

from __future__ import annotations

from .. import cwe_map

VERSION = "datadog-map-1"

SID_HIGH, SID_MEDIUM = cwe_map.SID_HIGH, cwe_map.SID_MEDIUM
EA_FUNCTIONALITY, EA_PERMISSIONS, EA_AUTONOMY = cwe_map.EA_FUNCTIONALITY, cwe_map.EA_PERMISSIONS, cwe_map.EA_AUTONOMY

#: kind -> (task ruleId or None, Datadog's CWE for the rule, why).
RULE_MAP: dict[str, tuple[str | None, str, str]] = {
    # --- LLM rules, by description -------------------------------------------
    "sensitiveinfodisclosure": (SID_MEDIUM, "CWE-200",
        "secrets, credentials or PII interpolated into the messages of an LLM API call: sensitive data reaches "
        "model-visible state. The rule does not establish that the data then crosses a further boundary, so "
        "MEDIUM (cwe-map-5 gives the same for CWE-200 alone)"),
    "systempromptleakage": (SID_HIGH, "CWE-540",
        "the developer's system prompt, tool schemas or policy text (confidential business data) flow into an "
        "HTTP response or an accessible log: data crosses to end users or broadly readable logs, so HIGH"),
    "excessiveagency": (EA_FUNCTIONALITY, "CWE-250",
        "an agent is given tools or capabilities broader than its stated purpose (shell, unrestricted file, "
        "URL or SQL tools). That is the task's FUNCTIONALITY definition. Datadog tags CWE-250, which cwe-map-5 "
        "would map to PERMISSIONS, but the rule checks tool capability, not a credential's scope"),
    "improperoutputhandling": (EA_AUTONOMY, "CWE-74",
        "LLM output is used as input to a dangerous downstream operation (SQL, shell, file path, URL) with no "
        "validation: a model decision triggers a high-impact action with no independent policy gate, the "
        "task's AUTONOMY definition. Datadog labels it LLM10:2026; that number is not used"),
    "promptinjection": (None, "CWE-1427",
        "attacker text alters LLM instructions: an attack vector, not disclosure of sensitive data or excessive "
        "agency in itself"),
    "misinformation": (None, "CWE-1426", "LLM text returned without a disclaimer: outside the five ruleIds"),
    "unboundedconsumption": (None, "CWE-400", "no max_tokens or timeout on an LLM call: outside the five ruleIds"),
    "datamodelpoisoning": (None, "CWE-345", "untrusted input reaches model loading or training: outside"),
    "supplychain": (None, "CWE-829",
        "model artifacts loaded without integrity pinning: outside (cwe-map-5 would map CWE-829 to "
        "FUNCTIONALITY, but the rule is about artifact integrity, not a tool's operations)"),
    "vectorembeddingweaknesses": (None, "CWE-349", "untrusted input written to a vector store (RAG poisoning): outside"),
    # --- classic rules, by CWE through cwe-map-5 -----------------------------
    "accesscontrol": (SID_MEDIUM, "CWE-284", "cwe-map-5: CWE-284 alone gives LLM02.SID.MEDIUM"),
    "errorinfoleak": (SID_MEDIUM, "CWE-209", "cwe-map-5: CWE-209 alone gives LLM02.SID.MEDIUM"),
    "cmdi": (EA_FUNCTIONALITY, "CWE-78", "cwe-map-5"),
    "codei": (EA_FUNCTIONALITY, "CWE-94", "cwe-map-5"),
    "deserialization": (EA_FUNCTIONALITY, "CWE-502", "cwe-map-5"),
    "pathtraversal": (EA_FUNCTIONALITY, "CWE-22", "cwe-map-5"),
    "sqli": (EA_FUNCTIONALITY, "CWE-89", "cwe-map-5"),
    "xpathi": (EA_FUNCTIONALITY, "CWE-643", "cwe-map-5"),
    "zipslip": (EA_FUNCTIONALITY, "CWE-73", "cwe-map-5"),
    "brokencrypto": (None, "CWE-327", "cwe-map-5: not mapped"),
    "insecurecookie": (None, "CWE-614", "cwe-map-5: not mapped"),
    "integeroverflow": (None, "CWE-190", "cwe-map-5: not mapped"),
    "ldapi": (None, "CWE-90", "cwe-map-5: not mapped"),
    "loginjection": (None, "CWE-117", "cwe-map-5: not mapped"),
    "openredirect": (None, "CWE-601", "cwe-map-5: not mapped"),
    "prototypepollution": (None, "CWE-1321", "cwe-map-5: not mapped"),
    "trustboundary": (None, "CWE-501", "cwe-map-5: not mapped"),
    "weakhash": (None, "CWE-328", "cwe-map-5: not mapped"),
    "weakrandomness": (None, "CWE-330", "cwe-map-5: not mapped"),
    "xss": (None, "CWE-79", "cwe-map-5: not mapped"),
}


def kind_of(rule_id: str) -> str | None:
    """``datadog/python-excessiveagency`` -> ``excessiveagency``; None for any other shape."""
    prefix, sep, rest = str(rule_id or "").partition("/")
    if prefix != "datadog" or not sep:
        return None
    language, sep, kind = rest.partition("-")
    return kind if language and sep and kind else None


def lookup(rule_id: str) -> tuple[str, str | None, bool]:
    """(kind, task ruleId or None, whether the kind is in the table)."""
    kind = kind_of(rule_id) or ""
    entry = RULE_MAP.get(kind)
    return kind, (entry[0] if entry else None), entry is not None
