"""CWE -> task ruleId, version ``cwe-map-3``. Frozen: changing it is a new version.

The task asks every agent, LLM or scanner, to report only five ruleIds
(``instruction.md``). A scanner reports CWEs, so each CWE is assigned to one of
them **by what the CWE means**, using the scope definitions in the instruction:

- ``LLM02.SID.HIGH``: the weakness is a *flow* of sensitive data to a party or
  place it should not reach (exposure, sensitive data in logs, errors or sent
  data, missing authorisation on data). The instruction defines LLM02 as data
  reaching model-visible state or crossing a trust boundary; a secret sitting in
  code (hard-coded credentials), weak transport or storage, or XML entity
  handling are not such flows, so they are not mapped.
  The table names the LLM02 *family* (written as ``SID_HIGH``); the emitted
  severity is chosen by :func:`task_rule` (cwe-map-3): ``LLM02.SID.HIGH`` when
  any of the finding's CWEs is in :data:`BOUNDARY_CWES` (201, 918, 319, 532,
  359: weaknesses defined by data leaving its boundary); otherwise
  ``LLM02.SID.MEDIUM``.
  918 and 319 never put a finding into LLM02 on their own (918 is
  FUNCTIONALITY, 319 is unmapped); as a secondary CWE they still raise it.
- ``LLM03.EA.FUNCTIONALITY``: the weakness lets a tool or code path do more than
  its job (code or command execution, query injection, SSRF, path traversal and
  other name resolution, deserialisation, reflection).
- ``LLM03.EA.PERMISSIONS``: a process, credential or resource has more privilege
  than its operation needs.
- ``LLM03.EA.AUTONOMY``: no CWE describes a missing approval gate on a model
  decision, so a scanner never reports it.

A CWE not listed here (XSS, crypto strength, CSRF, cookies, DoS, missing
moderation, ...) is outside the five ruleIds and is not reported; the finding is
still counted in the run's metadata.

A finding is mapped by its rule's **primary** (first-listed) CWE only, so a rule
whose main weakness is out of scope (say XSS) is not reported through a secondary
CWE. (In the pinned rules no security rule has an unmapped primary and a mapped
secondary CWE, so this choice changes no finding today.)

The table was built from the CWE inventory of the pinned rules and these
definitions, without looking at task labels. It is not tuned after results.

History:
- cwe-map-1 (2026-10-07, dev tasks only): also mapped 312, 319, 522, 548, 611,
  798, 922 to LLM02 and used the first *mapped* CWE of a finding.
- cwe-map-2 (2026-10-07, before any dataset run): this table. Review point: 257
  of the 321 security rules mapped to LLM02 under map-1 were hard-coded
  credential rules (CWE-798), which are not disclosure flows.
- cwe-map-3 (2026-10-07, before any dataset run): same table; LLM02 results are
  now MEDIUM unless a boundary CWE or a boundary-crossing trace sink makes them
  HIGH (:func:`task_rule`). Before, every LLM02 result was HIGH.
  Agent 0.3.0 later dropped the trace-sink branch, because Semgrep OSS 1.179.0
  gives no dataflow trace in JSON without a login. The branch never fired on
  real output, so every emitted ruleId is unchanged and the version stays.
"""

from __future__ import annotations

VERSION = "cwe-map-3"

SID_HIGH = "LLM02.SID.HIGH"
SID_MEDIUM = "LLM02.SID.MEDIUM"
EA_FUNCTIONALITY = "LLM03.EA.FUNCTIONALITY"
EA_PERMISSIONS = "LLM03.EA.PERMISSIONS"

RULE_DESCRIPTIONS = {
    SID_HIGH: "Sensitive data can reach an unauthorised party across a trust boundary",
    SID_MEDIUM: "Sensitive data can reach model-visible or other unprotected state",
    EA_FUNCTIONALITY: "A tool or code path can do more than its task requires",
    EA_PERMISSIONS: "Privilege or permission scope exceeds what the operation requires",
}

# CWE -> (ruleId, why). One entry per CWE; a CWE is never on two sides.
CWE_MAP: dict[str, tuple[str, str]] = {
    # --- data reaches the wrong party -------------------------------------
    "CWE-200": (SID_HIGH, "exposure of sensitive information to an unauthorised actor"),
    "CWE-201": (SID_HIGH, "sensitive information inserted into sent data"),
    "CWE-209": (SID_HIGH, "error message contains sensitive information"),
    "CWE-212": (SID_HIGH, "sensitive information not removed before storage or transfer"),
    "CWE-284": (SID_HIGH, "improper access control over data"),
    "CWE-285": (SID_HIGH, "improper authorisation of access to data"),
    "CWE-359": (SID_HIGH, "exposure of private personal information"),
    "CWE-532": (SID_HIGH, "sensitive information written to a log"),
    "CWE-538": (SID_HIGH, "sensitive information put in an externally accessible file"),
    "CWE-639": (SID_HIGH, "user-controlled key bypasses authorisation to data"),
    "CWE-668": (SID_HIGH, "resource exposed to the wrong sphere"),
    "CWE-862": (SID_HIGH, "missing authorisation: the data's authorisation boundary is not enforced"),
    "CWE-863": (SID_HIGH, "incorrect authorisation: the data's authorisation boundary is not enforced"),
    # --- a tool or code path can do more than its job ---------------------
    "CWE-22": (EA_FUNCTIONALITY, "path traversal: access to files outside the intended scope"),
    "CWE-23": (EA_FUNCTIONALITY, "relative path traversal"),
    "CWE-59": (EA_FUNCTIONALITY, "link following: access to files outside the intended scope"),
    "CWE-73": (EA_FUNCTIONALITY, "external control of a file name or path"),
    "CWE-74": (EA_FUNCTIONALITY, "injection into a downstream component"),
    "CWE-77": (EA_FUNCTIONALITY, "command injection"),
    "CWE-78": (EA_FUNCTIONALITY, "OS command injection"),
    "CWE-88": (EA_FUNCTIONALITY, "argument injection"),
    "CWE-89": (EA_FUNCTIONALITY, "SQL injection: queries beyond the intended ones"),
    "CWE-91": (EA_FUNCTIONALITY, "XML injection"),
    "CWE-94": (EA_FUNCTIONALITY, "code injection"),
    "CWE-95": (EA_FUNCTIONALITY, "eval injection"),
    "CWE-96": (EA_FUNCTIONALITY, "static code injection"),
    "CWE-426": (EA_FUNCTIONALITY, "untrusted search path: other code gets executed"),
    "CWE-470": (EA_FUNCTIONALITY, "unsafe reflection: input selects the code that runs"),
    "CWE-502": (EA_FUNCTIONALITY, "deserialisation of untrusted data can run code"),
    "CWE-553": (EA_FUNCTIONALITY, "command shell reachable from outside"),
    "CWE-643": (EA_FUNCTIONALITY, "XPath injection"),
    "CWE-706": (EA_FUNCTIONALITY, "incorrectly resolved name: parent of path traversal and link following"),
    "CWE-749": (EA_FUNCTIONALITY, "exposed dangerous method or function"),
    "CWE-829": (EA_FUNCTIONALITY, "functionality included from an untrusted source"),
    "CWE-918": (EA_FUNCTIONALITY, "server-side request forgery: requests beyond the intended ones"),
    "CWE-943": (EA_FUNCTIONALITY, "data query injection"),
    "CWE-1336": (EA_FUNCTIONALITY, "template injection can run code"),
    # --- more privilege than needed ---------------------------------------
    "CWE-250": (EA_PERMISSIONS, "execution with unnecessary privileges"),
    "CWE-266": (EA_PERMISSIONS, "incorrect privilege assignment"),
    "CWE-269": (EA_PERMISSIONS, "improper privilege management"),
    "CWE-272": (EA_PERMISSIONS, "least privilege violation"),
    "CWE-276": (EA_PERMISSIONS, "incorrect default permissions"),
    "CWE-732": (EA_PERMISSIONS, "incorrect permission assignment for a critical resource"),
}


def rule_for(cwes: list[str] | tuple[str, ...]) -> str | None:
    """The ruleId for a finding: its rule's primary (first-listed) CWE, or None."""
    if not cwes:
        return None
    entry = CWE_MAP.get(cwes[0])
    return entry[0] if entry is not None else None


#: CWEs whose definition is data leaving its authorisation or trust boundary.
BOUNDARY_CWES = frozenset({"CWE-201", "CWE-918", "CWE-319", "CWE-532", "CWE-359"})


def task_rule(cwes: list[str] | tuple[str, ...]) -> str | None:
    """The ruleId a result is emitted under.

    :func:`rule_for` picks the family from the primary CWE. An LLM02 result is
    ``LLM02.SID.HIGH`` when any CWE is in :data:`BOUNDARY_CWES` and
    ``LLM02.SID.MEDIUM`` otherwise. Other families are unchanged.
    """
    rule = rule_for(cwes)
    if rule != SID_HIGH:
        return rule
    if BOUNDARY_CWES.intersection(cwes):
        return SID_HIGH
    return SID_MEDIUM
