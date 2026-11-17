#!/usr/bin/env python3
"""Write a two-entry VARIANTS.json for one task pair into a scratch dataset.

    python tools/pair_variants.py <scratch dir> <family> [<VARIANTS.json>]

The QC and regeneration scripts copy ``<family>-a`` and ``<family>-b`` into a scratch folder and
need the pair's VARIANTS.json entries there (leak_scan.py and export_views.py read them). The
entries come from, in this order:

1. the given VARIANTS.json, when it has both folder names (the lead's dataset, ``tasks/VARIANTS.json``);
2. each twin's own ``tests/evaluator_view.json`` ``variant_map_entry`` (written by
   tools/export_views.py from VARIANTS.json, so a downloaded pair carries its own entry);
3. task.toml ``[metadata]`` (task_id, variant_id, family_id), with a = positive and b = negative.

Prints one line saying which source was used. Uses only the standard library.
"""

from __future__ import annotations

import json
import sys
import tomllib
from pathlib import Path

LETTERS = (("a", "positive", "b"), ("b", "negative", "a"))


def from_variants_file(path: Path | None, names: tuple[str, str]) -> dict | None:
    if path is None or not path.is_file():
        return None
    try:
        known = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if isinstance(known, dict) and all(isinstance(known.get(n), dict) for n in names):
        return {n: known[n] for n in names}
    return None


def from_evaluator_views(root: Path, family: str) -> dict | None:
    """The entries export_views.py embedded in each twin's evaluator view (``family`` is stored as
    ``family_key`` there)."""
    out = {}
    for letter, role, twin in LETTERS:
        name = f"{family}-{letter}"
        view = root / name / "tests" / "evaluator_view.json"
        try:
            entry = json.loads(view.read_text(encoding="utf-8")).get("variant_map_entry")
        except (OSError, json.JSONDecodeError, AttributeError):
            return None
        if not isinstance(entry, dict) or entry.get("role") != role or entry.get("twin") != f"{family}-{twin}":
            return None
        rest = {k: v for k, v in entry.items() if k != "family_key"}
        out[name] = {"family": entry.get("family_key") or family, **rest}
    return out


def from_task_toml(root: Path, family: str) -> dict:
    out = {}
    for letter, role, twin in LETTERS:
        meta = tomllib.loads((root / f"{family}-{letter}" / "task.toml").read_text(encoding="utf-8")).get("metadata", {})
        out[f"{family}-{letter}"] = {"family": family, "family_id": meta.get("family_id"), "role": role,
                                     "twin": f"{family}-{twin}", "task_id": meta.get("task_id"),
                                     "variant_id": meta.get("variant_id")}
    return out


def pair_variants(root: Path, family: str, variants_file: Path | None) -> tuple[dict, str]:
    names = (f"{family}-a", f"{family}-b")
    found = from_variants_file(variants_file, names)
    if found is not None:
        return found, f"VARIANTS.json entries from {variants_file}"
    found = from_evaluator_views(root, family)
    if found is not None:
        return found, "VARIANTS.json entries from the twins' tests/evaluator_view.json (variant_map_entry)"
    return from_task_toml(root, family), ("VARIANTS.json has no entries for this pair; synthesised them from "
                                          "task.toml (a = positive)")


def main(argv: list[str]) -> int:
    if len(argv) not in (2, 3):
        print(__doc__.strip().splitlines()[2].strip(), file=sys.stderr)
        return 2
    root, family = Path(argv[0]), argv[1]
    variants_file = Path(argv[2]) if len(argv) == 3 and argv[2] else None
    entries, source = pair_variants(root, family, variants_file)
    (root / "VARIANTS.json").write_text(json.dumps(entries, indent=2), encoding="utf-8")
    print(source)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
