#!/usr/bin/env python3
"""R6: copy task.toml's scanner_roots and excluded_paths into the ground truth's ``matching``.

    python tools/label_rules/r6_matching_roots.py <harbor-tasks dir> [--task NAME ...] [--check]

The grader decides which results are in scope from the ground truth alone, so
the scanner scope of task.toml ``[metadata]`` (``scanner_roots``,
``excluded_paths``) is mirrored as ``matching.scanner_roots`` and
``matching.excluded_paths``. task.toml is the source of truth: a rerun after a
task.toml change overwrites the copies. A key missing from task.toml is
reported and not written. Idempotent.
"""

from __future__ import annotations

import _common as c

KEYS = ("scanner_roots", "excluded_paths")


def main() -> int:
    args = c.parser(__doc__).parse_args()
    bad = 0
    for task in c.tasks(args.root, args.task):
        meta = c.task_toml(task).get("metadata") or {}
        problems = [f"task.toml has no metadata.{k}" for k in KEYS if not isinstance(meta.get(k), list)]
        gt = task / "tests" / "ground_truth.json"
        raw, truth = c.read_json(gt)
        matching = truth.setdefault("matching", {})
        for k in KEYS:
            if isinstance(meta.get(k), list):
                matching[k] = list(meta[k])
        changed = c.write_json_like(gt, raw, truth, args.check)
        if args.check and changed:
            problems.append("would change ground_truth")
        print(f"{task.name}: {'; '.join(problems) if problems else ('changed' if changed else 'ok')}")
        bad += bool(problems)
    return 1 if bad else 0


if __name__ == "__main__":
    c.run(main)
