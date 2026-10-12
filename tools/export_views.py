#!/usr/bin/env python3
"""Generate the scanner-visible and evaluator-only JSON views of each task, and prove they are separate (spec 5.2).

    python tools/export_views.py <harbor-tasks dir> [--task NAME ...] [--check]

Inputs per task: task.toml ``[metadata]``, environment/repo/security_manifest.json,
tests/ground_truth.json, validation/provenance.json and the evaluator-only
VARIANTS.json next to the task folders (for the twin and the role).

Outputs per task (JSON, sorted keys, two-space indent, LF, so a rerun on the
same inputs writes the same bytes):

* ``task_metadata.json`` at the task root (not under environment/repo, so the
  twin diff stays limited to the fix files). It holds exactly the keys in
  ``METADATA_ALLOWLIST``: the scanner-visible 5.2 task fields copied from
  task.toml, plus ``security_manifest_path`` (repository-relative) and
  ``security_manifest_fields`` (which of intended_task, actors,
  trust_boundaries, authorized_*, required_approval_policy and fixtures the
  manifest holds). Those manifest fields stay in the manifest and are not
  copied.
* ``tests/evaluator_view.json``: the evaluator-only fields, keyed by the same
  ``task_id``: source_url, source_commit, license, modifications,
  variant_role, risk_types_present, findings, negative_analyses, rationale
  and recommendations (per finding / negative analysis id), the remaining
  ground-truth keys under ``ground_truth_other``, the VARIANTS.json entry,
  and the rest of provenance.json (lineage, review, QC) under ``provenance``.

Proof step, run for every task before anything is written:

1. task_metadata.json has exactly the allowlisted keys.
2. No evaluator-only key (any key at any depth of the evaluator view that is
   not one of ``SHARED_KEYS``) is a key of task_metadata.json.
3. No role word (positive, negative, vulnerable, fixed, ...) is in a
   task_metadata.json value, and no evaluator string value of at least
   ``MIN_VALUE_LEN`` characters (findings text, rule ids, role words, fix
   locations, rationales, ...) occurs in a task_metadata.json value, unless it
   is itself a scanner-visible value (one that task_metadata.json or the
   security manifest holds exactly, such as the entrypoint or a canary id).
   Strings shorter than ``MIN_VALUE_LEN`` are ignored, and plain words or
   one-word strings shorter than ``MIN_TOKEN_LEN`` without a label shape
   ("high", "adapted", "modifications") only fail when they equal a whole
   task_metadata.json value; see ``distinctive``.
4. No such distinctive evaluator string occurs in the text of a file under
   environment/repo, unless the twin's file at the same path contains it too
   (so it was already there in both twins and says nothing about the label)
   or it is a scanner-visible value as in 3. Without a twin, every
   occurrence counts.

A task that fails the proof gets no files written and the script exits 1.
``--check`` writes nothing and exits 1 when a view on disk differs from what
would be generated (stale) or the proof fails.

Uses only the standard library.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import tomllib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
# The allowlist and the role-word pattern live in the stdlib-only leak scanner, so both tools use one copy.
from leak_scan import METADATA_ALLOWLIST, METADATA_FILE, ROLE_RE  # noqa: E402
from leak_scan import METADATA_TOML_FIELDS as TOML_FIELDS  # noqa: E402

#: 5.2 fields that live in the security manifest (scanner-visible, not copied).
MANIFEST_FIELDS = (
    "intended_task", "actors", "trust_boundaries", "authorized_data", "authorized_actions",
    "authorized_purposes", "authorized_recipients", "required_approval_policy", "fixtures",
)
MANIFEST_REL = "security_manifest.json"
EVALUATOR_FILE = "tests/evaluator_view.json"
#: Provenance keys that used to be in task.toml and now only live in the evaluator view.
SOURCE_FIELDS = ("source_url", "source_commit", "license", "modifications")
#: Ground-truth keys copied to the top of the evaluator view (the rest go under ground_truth_other).
LABEL_FIELDS = ("variant_role", "risk_types_present", "findings", "negative_analyses")
#: Keys that are in both views by design (identifiers and build facts recorded in provenance).
SHARED_KEYS = frozenset({"schema_version", "task_id", "repository_id", "family_id", "variant_id",
                         "related_variant_ids", "source_origin", "package_versions",
                         "entrypoint", "build_command", "test_command",
                         # The scan scope is scanner-visible in task.toml and copied into the ground truth's
                         # matching block for the grader (v3.2), so it is in both views by design.
                         "scanner_roots", "excluded_paths"})
MIN_VALUE_LEN = 6
#: An evaluator string counts as label content when it is prose (at least PROSE_WORDS words), an id with a label
#: shape (rule id, CWE, recommendation id, advisory, CVE), or a single identifier-like token (not only letters) of
#: at least MIN_TOKEN_LEN characters (a control name, a fix location, a commit hash). Plain words ("high",
#: "adapted", "modifications") are too common to say anything and are only checked for exact equality with a
#: metadata value.
PROSE_WORDS = 6
MIN_TOKEN_LEN = 12
LABEL_ID_RE = re.compile(r"LLM0[23]|CWE-\d|REC-[A-Z]|GHSA-|CVE-\d", re.IGNORECASE)


class ViewError(Exception):
    """An input is missing or malformed."""


def dumps(data: dict) -> str:
    return json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def _load_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ViewError(f"cannot read {path.name}: {exc}") from exc


def build_metadata(task: Path) -> dict:
    try:
        meta = tomllib.loads((task / "task.toml").read_text(encoding="utf-8")).get("metadata") or {}
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ViewError(f"cannot read task.toml: {exc}") from exc
    missing = [k for k in TOML_FIELDS if k not in meta]
    if missing:
        raise ViewError(f"task.toml [metadata] lacks {', '.join(missing)}")
    manifest = _load_json(task / "environment" / "repo" / MANIFEST_REL)
    absent = [k for k in MANIFEST_FIELDS if k not in manifest]
    if absent:
        raise ViewError(f"{MANIFEST_REL} lacks {', '.join(absent)}")
    out = {k: meta[k] for k in TOML_FIELDS}
    out["security_manifest_path"] = MANIFEST_REL
    out["security_manifest_fields"] = list(MANIFEST_FIELDS)
    return out


def _by_id(items, field: str) -> dict:
    return {str(i.get("id")): i[field] for i in items or [] if isinstance(i, dict) and field in i}


def _family_id(task: Path):
    try:
        return (tomllib.loads((task / "task.toml").read_text(encoding="utf-8")).get("metadata") or {}).get("family_id")
    except (OSError, tomllib.TOMLDecodeError):
        return None


def build_evaluator(task: Path, variants: dict) -> dict:
    gt = _load_json(task / "tests" / "ground_truth.json")
    prov = _load_json(task / "validation" / "provenance.json")
    entry = variants.get(task.name) or {}
    # Scanner-visible id: opaque task_<8 hex> from VARIANTS.json (final audit D1); the folder name is the
    # harness name and is kept here, evaluator-side, as task_name.
    task_id = entry.get("task_id") or task.name
    for name, data in (("ground_truth.json", gt), ("provenance.json", prov)):
        if data.get("task_id") not in (None, task.name, task_id):
            raise ViewError(f"{name} task_id {data.get('task_id')!r} is neither the task id nor the folder name")
    view: dict = {"task_id": task_id, "task_name": task.name, "view": "evaluator_only",
                  "generated_from": ["task.toml", "tests/ground_truth.json", "validation/provenance.json",
                                     "VARIANTS.json at the dataset root (evaluator-only, not shipped with the task)"]}
    for k in SOURCE_FIELDS:
        view[k] = prov.get(k)
    view["variant_role"] = gt.get("variant_role", entry.get("role"))
    view["risk_types_present"] = gt.get("risk_types_present", [])
    view["findings"] = gt.get("findings", [])
    view["negative_analyses"] = gt.get("negative_analyses", [])
    view["rationale"] = {**_by_id(view["findings"], "rationale"), **_by_id(view["negative_analyses"], "rationale")}
    view["recommendations"] = _by_id(view["findings"], "recommendations")
    view["ground_truth_other"] = {k: v for k, v in gt.items() if k not in LABEL_FIELDS and k != "task_id"}
    # VARIANTS.json "family" is the dataset's internal family key; family_id is the task.toml value.
    view["variant_map_entry"] = {**{k: v for k, v in entry.items() if k != "family"},
                                 "family_key": entry.get("family"), "family_id": _family_id(task)}
    view["provenance"] = {k: v for k, v in prov.items() if k not in SOURCE_FIELDS and k != "task_id"}
    return view


def all_keys(node, skip_children_of: frozenset = frozenset()) -> set[str]:
    out: set[str] = set()
    if isinstance(node, dict):
        for k, v in node.items():
            out.add(str(k))
            if k not in skip_children_of:
                out |= all_keys(v, skip_children_of)
    elif isinstance(node, list):
        for v in node:
            out |= all_keys(v, skip_children_of)
    return out


def all_strings(node) -> set[str]:
    if isinstance(node, str):
        return {node}
    if isinstance(node, dict):
        return set().union(*(all_strings(v) for v in node.values())) if node else set()
    if isinstance(node, list):
        return set().union(*(all_strings(v) for v in node)) if node else set()
    return set()


def distinctive(s: str) -> bool:
    """Whether an evaluator string is specific enough that finding it in scanner input means it leaked."""
    text = s.strip()
    return (len(text.split()) >= PROSE_WORDS or bool(LABEL_ID_RE.search(text))
            or (len(text) >= MIN_TOKEN_LEN and not any(c.isspace() for c in text) and not text.isalpha()))


def repo_texts(task: Path) -> dict[str, str]:
    repo = task / "environment" / "repo"
    out = {}
    for p in sorted(repo.rglob("*")):
        if p.is_file():
            data = p.read_bytes()
            if b"\0" not in data[:4096]:
                out[p.relative_to(repo).as_posix()] = data.decode("utf-8", errors="replace")
    return out


def prove(task: Path, metadata: dict, evaluator: dict, twin: Path | None) -> list[str]:
    """Problems that show evaluator-only content in task_metadata.json or environment/repo."""
    problems = []
    keys = set(metadata)
    if keys != METADATA_ALLOWLIST:
        extra, missing = sorted(keys - METADATA_ALLOWLIST), sorted(METADATA_ALLOWLIST - keys)
        if extra:
            problems.append(f"{METADATA_FILE} has keys outside the allowlist: {', '.join(extra)}")
        if missing:
            problems.append(f"{METADATA_FILE} lacks allowlisted keys: {', '.join(missing)}")
    eval_keys = all_keys(evaluator) - SHARED_KEYS
    meta_keys = all_keys(metadata, skip_children_of=frozenset({"package_versions"}))
    for k in sorted(meta_keys & eval_keys):
        problems.append(f"evaluator-only key {k!r} is a key of {METADATA_FILE}")

    manifest = _load_json(task / "environment" / "repo" / MANIFEST_REL)
    visible = all_strings(metadata) | all_strings(manifest)
    meta_values = sorted(all_strings(metadata) | (meta_keys - METADATA_ALLOWLIST))
    for v in meta_values:
        m = ROLE_RE.search(v)
        if m:
            problems.append(f"role word {m.group(0).strip('_-:.')!r} in {METADATA_FILE} value {v!r}")
    candidates = sorted(s for s in all_strings(evaluator) if len(s.strip()) >= MIN_VALUE_LEN and s not in visible)
    secrets = [s for s in candidates if distinctive(s)]
    meta_set = set(meta_values)
    for s in candidates:
        if s in meta_set:
            problems.append(f"evaluator value {s[:80]!r} is a {METADATA_FILE} value")
    for s in secrets:
        for v in meta_values:
            if s in v and s != v:
                problems.append(f"evaluator value {s[:80]!r} occurs in {METADATA_FILE} value {v[:80]!r}")

    texts = repo_texts(task)
    twin_texts = repo_texts(twin) if twin else {}
    for rel, text in texts.items():
        other = twin_texts.get(rel)
        for s in secrets:
            if s in text and (other is None or s not in other):
                why = "no twin" if twin is None else ("the twin has no such file" if other is None
                                                      else "the twin's file does not contain it")
                problems.append(f"evaluator value {s[:80]!r} occurs in environment/repo/{rel} ({why})")
    return problems


def load_variants(root: Path) -> dict:
    f = root / "VARIANTS.json"
    if not f.is_file():
        return {}
    data = _load_json(f)
    if not isinstance(data, dict):
        raise ViewError("VARIANTS.json is not an object")
    return data


def write(path: Path, text: str) -> None:
    with path.open("w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)


def export(root: Path, only: list[str] | None = None, check: bool = False) -> dict[str, list[str]]:
    """Generate (or with check=True compare) both views for every task; returns problems per task."""
    tasks = sorted(d for d in root.iterdir() if d.is_dir() and (d / "task.toml").is_file()
                   and (d / "environment").is_dir())
    if only:
        tasks = [t for t in tasks if t.name in only]
    try:
        variants = load_variants(root)
    except ViewError as exc:
        return {t.name: [str(exc)] for t in tasks}
    results: dict[str, list[str]] = {}
    for t in tasks:
        try:
            metadata = build_metadata(t)
            evaluator = build_evaluator(t, variants)
        except ViewError as exc:
            results[t.name] = [str(exc)]
            continue
        twin_name = (variants.get(t.name) or {}).get("twin")
        twin = root / twin_name if twin_name and (root / twin_name).is_dir() else None
        problems = prove(t, metadata, evaluator, twin)
        outputs = {t / METADATA_FILE: dumps(metadata), t / EVALUATOR_FILE: dumps(evaluator)}
        if check:
            for path, text in outputs.items():
                current = path.read_text(encoding="utf-8") if path.is_file() else None
                if current != text:
                    problems.append(f"{path.relative_to(t).as_posix()} is missing or stale; rerun export_views.py")
        elif not problems:
            for path, text in outputs.items():
                write(path, text)
        results[t.name] = problems
    return results


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("tasks", type=Path, help="the harbor-tasks directory")
    ap.add_argument("--task", action="append", default=[], metavar="NAME", help="only this task (repeatable)")
    ap.add_argument("--check", action="store_true", help="write nothing; fail when a view is stale or leaks")
    args = ap.parse_args()
    results = export(args.tasks, args.task, args.check)
    if not results:
        print(f"no task folders under {args.tasks}")
        return 1
    for name, problems in results.items():
        print(f"{name}  {'FAIL' if problems else 'ok'}" + (f"  ({len(problems)} problems)" if problems else ""))
        for p in problems:
            print(f"    {p}")
    failed = sum(1 for p in results.values() if p)
    verb = "checked" if args.check else "written"
    print(f"\nviews {verb}: {len(results) - failed}/{len(results)} tasks ok; proof that evaluator-only values are "
          f"absent from {METADATA_FILE} and environment/repo (beyond what both twins share) "
          f"{'passed' if not failed else 'FAILED'}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
