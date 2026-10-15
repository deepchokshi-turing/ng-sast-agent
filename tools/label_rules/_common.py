"""Shared helpers for the label-rule scripts (standard library only).

Every script in this folder takes the harbor-tasks directory and optional
``--task NAME`` filters, rewrites files only when their content changes, keeps
each JSON file's indent, ASCII escaping and trailing newline, writes LF line
endings, and is idempotent: a second run writes nothing.

Order used for the 2026-10-12 audit fixes (from ng-sast-agent, ``T`` being
``--task task_X --task task_Y ...``):

    python tools/label_rules/r1_normalise_roles.py ../harbor-tasks $T   # R1 roles
    python tools/label_rules/r6_matching_roots.py  ../harbor-tasks $T   # R6 matching scope
    python tools/label_rules/r4_sid_data_recs.py   ../harbor-tasks $T   # R4 LLM02 recommendations
    python tools/label_rules/r5_trap_rule_ids.py   ../harbor-tasks $T   # R5 trap_rule_ids
    (by hand: R2 missing SID path steps, then)
    python tools/label_rules/r3_sid_sink_locations.py ../harbor-tasks $T  # R3 sinks + twin traps
    (by hand: review the generated traps' why texts, fix-changed lines, R7, R8)
    python tools/snippet_ids.py ../harbor-tasks $T
    python tools/label_rules/sync_oracle.py ../harbor-tasks $T
    python task_format/grade.py --check-truth --truth ../harbor-tasks/<task>/tests/ground_truth.json

A script exits 1 when something needs a human decision; the message says what.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
import tomllib
from pathlib import Path

GRADE_PY = Path(__file__).resolve().parents[2] / "task_format" / "grade.py"

#: The step roles of the scanner output contract (instruction.md, sast/findings.py PATH_ROLES).
CONTRACT_ROLES = ("source", "root_cause", "context_assembly", "model_consumption", "model_decision",
                  "control_point", "sink")

#: Recommendations that act on the data itself (spec section 3, SID mitigations).
DATA_RECS = ("REC-SINK-SIDE-IFC", "REC-SENSITIVE-DATA-FILTER", "REC-MINIMIZE-CONTEXT",
             "REC-AUTHZ-BEFORE-RETRIEVAL", "REC-DISABLE-AUTO-CONTEXT")


def load_grade():
    spec = importlib.util.spec_from_file_location("_grade", GRADE_PY)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def parser(doc: str) -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description=doc.strip().split("\n")[0])
    ap.add_argument("root", type=Path, help="harbor-tasks directory")
    ap.add_argument("--task", action="append", default=[], help="only this task folder (repeatable)")
    ap.add_argument("--check", action="store_true", help="write nothing; exit 1 when a file would change")
    return ap


def tasks(root: Path, only: list[str]) -> list[Path]:
    out = sorted(p for p in root.iterdir() if (p / "tests" / "ground_truth.json").is_file())
    if only:
        out = [t for t in out if t.name in only]
    return out


def variants(root: Path) -> dict:
    f = root / "VARIANTS.json"
    return json.loads(f.read_text(encoding="utf-8")) if f.is_file() else {}


def twin_of(root: Path, task: Path) -> Path | None:
    entry = variants(root).get(task.name) or {}
    twin = entry.get("twin")
    return root / twin if twin and (root / twin).is_dir() else None


def read_json(path: Path):
    raw = path.read_bytes().decode("utf-8")
    return raw, json.loads(raw)


def dump_like(raw: str, data) -> str:
    """Serialise ``data`` in the style of ``raw`` (indent, ASCII escaping, trailing newline), LF only."""
    lines = raw.replace("\r\n", "\n").split("\n")
    indent = len(lines[1]) - len(lines[1].lstrip(" ")) if len(lines) > 1 else 2
    return json.dumps(data, indent=indent or 2, ensure_ascii=raw.isascii()) + ("\n" if raw.endswith("\n") else "")


def write_json_like(path: Path, raw: str, data, check: bool) -> bool:
    """Write ``data`` back in ``raw``'s style. Returns True when the content changes."""
    new = dump_like(raw, data)
    if new == raw:
        return False
    if not check:
        path.write_bytes(new.encode("utf-8"))
    return True


def task_toml(task: Path) -> dict:
    f = task / "task.toml"
    return tomllib.loads(f.read_text(encoding="utf-8")) if f.is_file() else {}


def is_trap(entry: dict) -> bool:
    return isinstance(entry, dict) and entry.get("kind", "hard_negative_trap") == "hard_negative_trap" \
        and "file" in entry


def run(main_fn) -> None:
    sys.exit(main_fn())
