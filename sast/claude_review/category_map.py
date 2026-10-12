"""Free-text review category -> CWE, version ``ccsr-category-map-1``. Frozen.

The upstream review reports a free snake_case ``category`` per finding (the
prompt's example is ``sql_injection``) and no CWE. In ``stock`` mode the agent
looks the category up here, after :func:`normalise` (lowercase, every run of
other characters becomes one ``_``). The lookup is exact: a category that is
not listed gets no CWE and is counted as unmapped, never guessed.

The entries follow the prompt's own category list (prompts.py:67-102) and the
common spellings of each, and give the CWE that names the weakness itself. The
table was written from those definitions before any run, without looking at
task labels. Whether a CWE is in scope is decided afterwards by
``sast.cwe_map``, exactly as for the other scanners, so several entries here
(XSS, XXE, hard-coded secrets, weak crypto, authentication) give a CWE that
``cwe_map`` leaves unmapped on purpose.

In ``scoped`` mode the model is asked for a CWE list per finding. Those CWEs
are used when at least one passes :func:`valid_cwes` (the format and
:data:`ALLOWED_CWES`); otherwise the category is looked up here as in stock
mode. Which source was used is recorded per finding (``cweSource``).

Changing anything here is a new version.
"""

from __future__ import annotations

import re

from .. import cwe_map

VERSION = "ccsr-category-map-1"

#: normalised category -> CWE.
CATEGORY_CWE: dict[str, str] = {
    # Input validation and injection
    "sql_injection": "CWE-89",
    "sqli": "CWE-89",
    "nosql_injection": "CWE-943",
    "query_injection": "CWE-943",
    "command_injection": "CWE-78",
    "os_command_injection": "CWE-78",
    "shell_injection": "CWE-78",
    "argument_injection": "CWE-88",
    "code_injection": "CWE-94",
    "remote_code_execution": "CWE-94",
    "rce": "CWE-94",
    "code_execution": "CWE-94",
    "arbitrary_code_execution": "CWE-94",
    "eval_injection": "CWE-95",
    "unsafe_eval": "CWE-95",
    "template_injection": "CWE-1336",
    "server_side_template_injection": "CWE-1336",
    "ssti": "CWE-1336",
    "path_traversal": "CWE-22",
    "directory_traversal": "CWE-22",
    "file_path_traversal": "CWE-22",
    "arbitrary_file_read": "CWE-22",
    "arbitrary_file_write": "CWE-22",
    "local_file_inclusion": "CWE-22",
    "ssrf": "CWE-918",
    "server_side_request_forgery": "CWE-918",
    "xpath_injection": "CWE-643",
    "ldap_injection": "CWE-90",
    "xml_injection": "CWE-91",
    "xxe": "CWE-611",
    "xxe_injection": "CWE-611",
    "xml_external_entity": "CWE-611",
    "unsafe_reflection": "CWE-470",
    # Deserialisation
    "insecure_deserialization": "CWE-502",
    "unsafe_deserialization": "CWE-502",
    "deserialization": "CWE-502",
    "pickle_injection": "CWE-502",
    "pickle_deserialization": "CWE-502",
    "yaml_deserialization": "CWE-502",
    "unsafe_yaml_load": "CWE-502",
    # Authentication and authorisation
    "authorization_bypass": "CWE-862",
    "authorisation_bypass": "CWE-862",
    "missing_authorization": "CWE-862",
    "missing_authorisation": "CWE-862",
    "broken_access_control": "CWE-284",
    "access_control": "CWE-284",
    "improper_access_control": "CWE-284",
    "idor": "CWE-639",
    "insecure_direct_object_reference": "CWE-639",
    "privilege_escalation": "CWE-269",
    "excessive_privileges": "CWE-250",
    "excessive_permissions": "CWE-250",
    "authentication_bypass": "CWE-287",
    "broken_authentication": "CWE-287",
    "missing_authentication": "CWE-306",
    "session_management": "CWE-384",
    "session_fixation": "CWE-384",
    "jwt_vulnerability": "CWE-347",
    "jwt_validation": "CWE-347",
    "csrf": "CWE-352",
    # Crypto and secrets
    "hardcoded_secret": "CWE-798",
    "hardcoded_secrets": "CWE-798",
    "hardcoded_credentials": "CWE-798",
    "hardcoded_api_key": "CWE-798",
    "weak_crypto": "CWE-327",
    "weak_cryptography": "CWE-327",
    "insecure_randomness": "CWE-330",
    "weak_randomness": "CWE-330",
    "certificate_validation_bypass": "CWE-295",
    "improper_certificate_validation": "CWE-295",
    # Data exposure
    "sensitive_data_logging": "CWE-532",
    "sensitive_data_in_logs": "CWE-532",
    "log_exposure": "CWE-532",
    "information_disclosure": "CWE-200",
    "information_exposure": "CWE-200",
    "data_exposure": "CWE-200",
    "sensitive_data_exposure": "CWE-200",
    "data_leakage": "CWE-200",
    "data_leak": "CWE-200",
    "api_data_leakage": "CWE-200",
    "pii_exposure": "CWE-359",
    "pii_handling": "CWE-359",
    "pii_leak": "CWE-359",
    "pii_leakage": "CWE-359",
    "privacy_violation": "CWE-359",
    "debug_info_exposure": "CWE-209",
    "debug_information_exposure": "CWE-209",
    "error_message_exposure": "CWE-209",
    "stack_trace_exposure": "CWE-209",
    # Web
    "xss": "CWE-79",
    "cross_site_scripting": "CWE-79",
    "open_redirect": "CWE-601",
    # GenAI
    "prompt_injection": "CWE-1427",
}

#: CWE ids a scoped finding may name, besides every CWE of ``cwe_map.CWE_MAP``
#: (added at lookup time). A real id the model gives that is not listed is
#: dropped and counted, as is anything that is not ``CWE-<number>``.
EXTRA_ALLOWED_CWES = frozenset({
    "CWE-20", "CWE-74", "CWE-79", "CWE-90", "CWE-98", "CWE-116", "CWE-117", "CWE-209", "CWE-269", "CWE-287",
    "CWE-295", "CWE-306", "CWE-307", "CWE-311", "CWE-312", "CWE-319", "CWE-327", "CWE-328", "CWE-330",
    "CWE-345", "CWE-347", "CWE-352", "CWE-384", "CWE-400", "CWE-434", "CWE-441", "CWE-522", "CWE-523",
    "CWE-525", "CWE-526", "CWE-539", "CWE-548", "CWE-552", "CWE-601", "CWE-602", "CWE-611", "CWE-620",
    "CWE-640", "CWE-641", "CWE-693", "CWE-697", "CWE-703", "CWE-770", "CWE-776", "CWE-798", "CWE-807",
    "CWE-915", "CWE-922", "CWE-1021", "CWE-1039", "CWE-1236", "CWE-1333", "CWE-1426", "CWE-1427",
})

_CWE_RE = re.compile(r"^CWE-([1-9][0-9]{0,4})$")
_SEPARATORS = re.compile(r"[^a-z0-9]+")


def allowed_cwes() -> frozenset[str]:
    return frozenset(cwe_map.CWE_MAP) | EXTRA_ALLOWED_CWES | frozenset(CATEGORY_CWE.values())


def normalise(category: object) -> str:
    """``SQL Injection`` and ``sql-injection`` both become ``sql_injection``."""
    return _SEPARATORS.sub("_", str(category or "").strip().lower()).strip("_")


def lookup(category: object) -> str | None:
    return CATEGORY_CWE.get(normalise(category))


def _one(value: object) -> str | None:
    """``"CWE-89"``, ``"cwe 89"``, ``89`` -> ``"CWE-89"``; anything else None."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        text = f"CWE-{value}"
    elif isinstance(value, str):
        text = re.sub(r"^CWE[\s_:-]*", "CWE-", value.strip().upper())
        if text.isdigit():
            text = f"CWE-{text}"
    else:
        return None
    return text if _CWE_RE.match(text) else None


def valid_cwes(raw: object) -> tuple[tuple[str, ...], list[str]]:
    """(accepted CWEs in the model's order without duplicates, rejected values as text)."""
    values = raw if isinstance(raw, (list, tuple)) else ([] if raw is None else [raw])
    allowed = allowed_cwes()
    accepted: list[str] = []
    rejected: list[str] = []
    for value in values:
        cwe = _one(value)
        if cwe is None or cwe not in allowed:
            rejected.append(str(value)[:40])
        elif cwe not in accepted:
            accepted.append(cwe)
    return tuple(accepted), rejected
