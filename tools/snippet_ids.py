#!/usr/bin/env python3
"""Stamp every location in each task's ground truth with a stable snippet id and hash.

    python tools/snippet_ids.py <harbor-tasks dir> [--task NAME ...] [--check]

Every object in ``tests/ground_truth.json`` that has a ``file`` and a
``start_line`` (primary and alternative locations, path steps and their
alternatives, control locations, ``negative_analyses`` entries,
``fixed_locations``) gets two keys, inserted right after ``end_line``:

- ``snippet_id``: ``<task_id>:<file>:<start_line>-<end_line>``, the primary
  key that ties a label to a code snippet (spec comment SS1). The same lines
  always get the same id.
- ``snippet_sha256``: SHA-256 of those lines of ``environment/repo/<file>``,
  line endings normalised to LF and the lines joined with ``\\n`` (no trailing
  newline). See ``snippet_sha256`` in ``task_format/grade.py``.

Line numbers are never changed. ``grade.py --check-truth`` recomputes the hash
from the repo and reports a label whose lines no longer match the code, so a
code edit cannot silently move a label.

The script is deterministic and rerunnable: running it twice writes the same
bytes. It keeps each file's indent (1 or 2 spaces), key order, ASCII escaping
and trailing newline. ``--check`` writes nothing and exits 1 when a file would
change or a location cannot be read.

Uses only the standard library.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path

_GRADE = Path(__file__).resolve().parents[1] / "task_format" / "grade.py"
_spec = importlib.util.spec_from_file_location("_grade", _GRADE)
grade = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(grade)


def is_location(node) -> bool:
    return isinstance(node, dict) and isinstance(node.get("file"), str) and "start_line" in node


def stamp(node, task_id: str, repo: Path, problems: list[str], where: str = ""):
    """A copy of ``node`` with every location stamped. Problems are appended to ``problems``."""
    if isinstance(node, list):
        return [stamp(v, task_id, repo, problems, f"{where}[{i}]") for i, v in enumerate(node)]
    if not isinstance(node, dict):
        return node
    out = {k: stamp(v, task_id, repo, problems, f"{where}.{k}" if where else k)
           for k, v in node.items() if k not in ("snippet_id", "snippet_sha256")}
    if not is_location(node):
        return out
    start = node["start_line"]
    end = node.get("end_line", start)
    try:
        digest = grade.snippet_sha256(repo, node["file"], start, end)
    except (OSError, ValueError) as exc:
        problems.append(f"{where}: {exc}")
        return dict(node)  # leave it as it was
    extra = {"snippet_id": grade.snippet_id(task_id, node["file"], start, end), "snippet_sha256": digest}
    anchor = "end_line" if "end_line" in out else "start_line"
    stamped = {}
    for k, v in out.items():
        stamped[k] = v
        if k == anchor:
            stamped.update(extra)
    return stamped


def dump_like(raw: str, data) -> str:
    """Serialise ``data`` in the style of ``raw`` (indent, ASCII escaping, trailing newline)."""
    lines = raw.split("\n")
    indent = len(lines[1]) - len(lines[1].lstrip(" ")) if len(lines) > 1 else 2
    ascii_only = raw.isascii()
    return json.dumps(data, indent=indent or 2, ensure_ascii=ascii_only) + ("\n" if raw.endswith("\n") else "")


def process(task: Path, check: bool) -> list[str]:
    gt_file = task / "tests" / "ground_truth.json"
    raw = gt_file.read_text(encoding="utf-8")
    truth = json.loads(raw)
    task_id = truth.get("task_id") or task.name
    problems: list[str] = []
    new = dump_like(raw, stamp(truth, task_id, task / "environment" / "repo", problems))
    if new != raw:
        if check:
            problems.append("snippet ids are out of date (run tools/snippet_ids.py)")
        else:
            gt_file.write_bytes(new.encode("utf-8"))
    return problems


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("root", type=Path, help="harbor-tasks directory")
    ap.add_argument("--task", action="append", default=[], help="only this task folder (repeatable)")
    ap.add_argument("--check", action="store_true", help="write nothing, exit 1 when a file would change")
    args = ap.parse_args()
    tasks = sorted(p for p in args.root.iterdir() if (p / "tests" / "ground_truth.json").is_file())
    if args.task:
        tasks = [t for t in tasks if t.name in args.task]
    bad = 0
    for task in tasks:
        problems = process(task, args.check)
        print(f"{task.name}: {'ok' if not problems else '; '.join(problems)}")
        bad += bool(problems)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
