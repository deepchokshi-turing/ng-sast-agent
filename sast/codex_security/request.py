"""What the agent asks Codex for: the prompt, the output schema and the config.

All three are built on the host and sent to the driver in the request file.

- Stock mode: the fixed security review prompt ``stock_prompt.txt`` and the
  finding shape of Codex's own code review (``codex review``: ``title``,
  ``body``, ``confidence_score``, ``priority``, ``code_location`` with
  ``absolute_file_path`` and ``line_range``, from the review rubric of
  openai/codex at rust-v0.162.1, codex-rs/prompts/templates/review/rubric.md),
  plus two fields Codex's review has no use for but the SARIF profile needs:
  ``category`` and a ``cwe`` list. Without a CWE no finding could be mapped to a
  task ruleId. Nothing task-specific is in the prompt.
- Scoped mode: the same, plus the task's own output contract, read from the
  instruction Harbor passes to ``run`` with ``sast.claude_review.contract`` and
  written with the same fixed preamble the Claude review's scoped mode uses
  (``contract.scan_instructions``). The schema adds the contract's fields with
  the contract's own vocabularies as enums: ``rule_id``, ``path`` (file, line,
  role), ``control_status``, ``residual_risk`` and ``recommendation_ids``.
  Codex sends the schema with ``strict: true`` (verified against the 0.162.1
  binary), so the model can only answer with those values; the normaliser
  checks them again anyway.
- The config: a private ``config.toml`` for a private ``CODEX_HOME``, so no user
  config, MCP server, plugin, skill, hook, memory or AGENTS.md reaches the
  review (each key checked with ``codex exec --strict-config`` against the
  0.162.1 binary).

Every schema follows the Responses API's strict structured outputs: every
object lists all its properties as required and forbids others, and an
optional value is a union with ``null``.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .. import cwe_map, heuristics
from ..claude_review import contract as contract_module
from ..claude_review.contract import Contract
from ..findings import CONTROL_STATUSES, PATH_ROLES, RISK_LEVELS

_HERE = Path(__file__).parent
STOCK_PROMPT_FILE = _HERE / "stock_prompt.txt"

#: Codex features turned off for the review (``[features]`` in config.toml):
#: everything that would give the model tools or context beyond the shell in
#: the review folder. Names from ``codex features list`` of 0.162.1.
FEATURES_OFF = ("apps", "plugins", "multi_agent", "hooks", "browser_use", "computer_use", "image_generation",
                "memories", "goals", "daemon_auto_start")

#: The permissions profile of the read-only review: Codex's built-in ``:read-only`` profile (read anywhere,
#: write nowhere, no network) plus ``deny`` entries for the private paths. Checked against the 0.162.1 binary:
#: ``codex sandbox -- cat <denied file>`` gives "Permission denied", a write gives "Read-only file system".
PROFILE = "sast-review"


#: A sentence of ``contract.scan_instructions`` about a field only the Claude review's upstream schema has.
UPSTREAM_ONLY_SENTENCE = ' The free text "recommendation" field stays as it is.'


def stock_prompt() -> str:
    return STOCK_PROMPT_FILE.read_text(encoding="utf-8")


def fallback_contract() -> Contract:
    """The contract as this harness knows it, for an instruction that carries
    none (a placeholder): the five task ruleIds with their descriptions, the
    catalogue ids, roles and values the normaliser accepts."""
    return Contract(
        rules=tuple((rule, cwe_map.RULE_DESCRIPTIONS[rule]) for rule in cwe_map.TASK_RULES),
        recommendations=tuple((rec, rec.replace("REC-", "").replace("-", " ").lower())
                              for rec in heuristics.CATALOGUE),
        roles=PATH_ROLES, control_statuses=CONTROL_STATUSES, residual_risks=RISK_LEVELS)


def scoped_prompt(parsed: Contract) -> str:
    text = contract_module.scan_instructions(parsed)
    # The Claude review's text mentions upstream's free-text "recommendation" field, which this schema has not.
    text = text.replace(UPSTREAM_ONLY_SENTENCE, "")
    return stock_prompt() + "\nThis review has its own scope and output fields, given below.\n\n" + text


def _object(properties: dict[str, Any]) -> dict[str, Any]:
    return {"type": "object", "additionalProperties": False, "required": list(properties), "properties": properties}


def _enum(values, nullable: bool = True) -> dict[str, Any]:
    values = list(values)
    if nullable:
        return {"type": ["string", "null"], "enum": values + [None]}
    return {"type": "string", "enum": values}


def finding_properties() -> dict[str, Any]:
    """Codex's own review finding, plus ``category`` and ``cwe``."""
    return {
        "title": {"type": "string"},
        "body": {"type": "string"},
        "confidence_score": {"type": "number"},
        "priority": {"type": ["integer", "null"]},
        "category": {"type": "string"},
        "cwe": {"type": "array", "items": {"type": "string"}},
        "code_location": _object({
            "absolute_file_path": {"type": "string"},
            "line_range": _object({"start": {"type": "integer"}, "end": {"type": "integer"}}),
        }),
    }


def output_schema(mode: str, parsed: Contract | None = None) -> dict[str, Any]:
    """The JSON schema of the final answer for ``mode``."""
    properties = finding_properties()
    if mode == "scoped":
        if parsed is None:
            raise ValueError("scoped mode needs a contract")
        properties.update({
            "rule_id": _enum([r for r, _ in parsed.rules]),
            "path": {"type": "array", "items": _object({
                "file": {"type": "string"},
                "line": {"type": "integer"},
                "role": _enum(parsed.roles),
            })},
            "control_status": _enum(parsed.control_statuses),
            "residual_risk": _enum(parsed.residual_risks),
            "recommendation_ids": {"type": "array", "items": _enum([r for r, _ in parsed.recommendations],
                                                                   nullable=False)},
        })
    return _object({
        "findings": {"type": "array", "items": _object(properties)},
        "analysis_summary": _object({"files_reviewed": {"type": "integer"},
                                     "review_completed": {"type": "boolean"}}),
    })


def _toml(value: Any) -> str:
    """A TOML value. JSON's string escapes are valid TOML basic-string escapes."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str):
        return json.dumps(value)
    if isinstance(value, (list, tuple)):
        return "[" + ", ".join(_toml(v) for v in value) + "]"
    raise TypeError(f"no TOML for {value!r}")


def _key(key: str) -> str:
    """A TOML key: bare when it can be, else quoted (a path)."""
    return key if key.replace("_", "").replace("-", "").isalnum() else json.dumps(key)


def config_toml(model: str, sandbox: str, reasoning_effort: str | None = None,
                deny: tuple[str, ...] | list[str] = ()) -> str:
    """The review's config.toml. No secret in it.

    ``sandbox`` "read-only": the commands the model runs get the ``PROFILE``
    permissions profile, which can read the file system except the ``deny``
    paths (the real repository, the key and Codex's own home with auth.json,
    the agent's folders), write nothing and reach no network. "container":
    Codex's sandbox is off (``sandbox_mode = "danger-full-access"``) and no
    profile applies."""
    top: list[tuple[str, Any]] = [("model", model)]
    if reasoning_effort:
        top.append(("model_reasoning_effort", reasoning_effort))
    top += [
        ("approval_policy", "never"),
        ("web_search", "disabled"),
        # No AGENTS.md (or fallback file) of the reviewed code is read: 0 bytes of project docs.
        ("project_doc_max_bytes", 0),
        # No walk up from the review folder looking for a project root or a .codex folder.
        ("project_root_markers", []),
        ("check_for_update_on_startup", False),
        # The API key that `codex login --with-api-key` stores goes to $CODEX_HOME/auth.json, never a keyring.
        ("cli_auth_credentials_store", "file"),
    ]
    if sandbox == "read-only":
        top.append(("default_permissions", PROFILE))
    elif sandbox == "container":
        top.append(("sandbox_mode", "danger-full-access"))
    else:
        raise ValueError(f"unknown sandbox {sandbox!r}")
    lines = [f"{key} = {_toml(value)}" for key, value in top]
    tables: list[tuple[str, list[tuple[str, Any]]]] = [
        ("analytics", [("enabled", False)]),
        ("feedback", [("enabled", False)]),
        ("history", [("persistence", "none")]),
        ("features", [(name, False) for name in FEATURES_OFF]),
        ("skills", [("include_instructions", False)]),
        ("skills.bundled", [("enabled", False)]),
    ]
    if sandbox == "read-only":
        tables += [(f"permissions.{PROFILE}", [("extends", ":read-only")]),
                   (f"permissions.{PROFILE}.filesystem", [(path, "deny") for path in deny])]
    for name, rows in tables:
        lines += ["", f"[{name}]"] + [f"{_key(key)} = {_toml(value)}" for key, value in rows]
    return "\n".join(lines) + "\n"
