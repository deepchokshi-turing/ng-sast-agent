"""Shared helpers for the label-rule scripts (standard library only).

Every script in this folder takes the dataset directory (``tasks``: every
``batch-*`` folder under it plus any task folder directly under it, so old flat
datasets such as ``_poc/harbor-tasks`` keep working) or one batch
(``tasks/batch-N``), and optional ``--task NAME`` filters. VARIANTS.json is read
from the given directory, else from its parent (the dataset root). Each script
rewrites files only when their content changes, keeps each JSON file's indent,
ASCII escaping and trailing newline, writes LF line endings, and is idempotent:
a second run writes nothing.

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
    ap.add_argument("root", type=Path, help="dataset directory (tasks) or one batch (tasks/batch-N)")
    ap.add_argument("--task", action="append", default=[], help="only this task folder (repeatable)")
    ap.add_argument("--check", action="store_true", help="write nothing; exit 1 when a file would change")
    return ap


def task_dirs(root: Path) -> list[Path]:
    """Every folder that may hold a task: those directly under ``root`` and those inside its
    ``batch-*`` folders. ``root`` is the dataset root (``tasks``, families in ``tasks/batch-N/``;
    an old flat dataset has its tasks directly under it) or one batch (``tasks/batch-N``).
    Callers filter on the files a task holds, so a family's ``_work`` folder never qualifies."""
    out = []
    for p in sorted(root.iterdir()):
        if not p.is_dir():
            continue
        if p.name.startswith("batch-"):
            out.extend(sorted(q for q in p.iterdir() if q.is_dir()))
        else:
            out.append(p)
    return out


def dataset_file(root: Path, name: str) -> Path:
    """A dataset-wide file (VARIANTS.json, vocabulary.json): in ``root``, else in its parent (when
    ``root`` is one batch). Returns the path in ``root`` when neither exists."""
    for d in (root, root.parent):
        if (d / name).is_file():
            return d / name
    return root / name


def tasks(root: Path, only: list[str]) -> list[Path]:
    out = [p for p in task_dirs(root) if (p / "tests" / "ground_truth.json").is_file()]
    if only:
        out = [t for t in out if t.name in only]
    return out


def variants(root: Path) -> dict:
    f = dataset_file(root, "VARIANTS.json")
    return json.loads(f.read_text(encoding="utf-8")) if f.is_file() else {}


def twin_of(root: Path, task: Path) -> Path | None:
    """The task's twin (VARIANTS.json ``twin``): its sibling (same batch), else a task folder of
    ``root`` or, when ``root`` is one batch, of the dataset root above it."""
    twin = (variants(root).get(task.name) or {}).get("twin")
    if not twin:
        return None
    if (task.parent / twin).is_dir():
        return task.parent / twin
    for base in (root, root.parent):
        for p in task_dirs(base):
            if p.name == twin:
                return p
    return None


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
