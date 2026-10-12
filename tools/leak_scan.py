#!/usr/bin/env python3
"""Heuristic leak check: look for common ways a label reaches the scanner.

    python tools/leak_scan.py <harbor-tasks dir> [--write-qc]

This is a heuristic, not a proof that no label leaks (spec section 5.2). It
cannot see, for example, a fix-only name that both twins share, or a hint that
paraphrases the ground truth in fewer than six words.

For every task folder (one holding task.toml or environment/):

1. Every file under environment/ (names and text) is searched for banned words
   that would reveal the label (advisory ids, bug-class words, rule ids, CWE ids).
2. Evaluator-only files (ground truth, repro tests, provenance) must not be
   under environment/.
3. Ground-truth prose must not appear in environment/. Every string in
   tests/ground_truth.json with at least six words (rationales, ``why`` notes,
   summaries, and so on) is cut into six-word shingles after lowercasing and
   dropping punctuation, and no shingle may occur in a text file under
   environment/.
4. environment/Dockerfile may copy only ``repo/`` into the image. ``COPY
   --from=<stage>`` (files from another image) is allowed. Any other COPY or ADD
   source, for example ``tests/`` or ``.``, is a problem.
5. task.toml and instruction.md are searched for the same banned words. They
   are the task files the harness and the scanner can read besides
   environment/.
6. For twins (paired through VARIANTS.json, or by the folder names
   ``task_<id>_positive`` / ``task_<id>_negative`` when there is no map): the environment/
   trees may differ only in files listed in the original positive's
   ``fix_changed_files`` (paths relative to environment/repo), and
   security_manifest.json and fixtures/ must be byte-identical. See
   ``twin_pairs`` for how the original positive is chosen.
7. Twin task.toml files are parsed and may differ only in ``task_id``,
   ``variant_id`` and ``related_variant_ids``. Any other key that differs (a
   package version, an architecture line, a tag) could tell the twins apart.
8. Because those three keys escape point 7, ``task_id`` (when set) must equal
   the task folder name, and none of the three may hold a role word
   (positive, negative, vulnerable, patch, fixed, benign, or a pos, neg,
   vuln, fix, safe, unsafe, bad or good part between separators).
9. Twin instruction.md files must be byte-identical.
10. task.toml must not hold ``source_url``, ``source_commit``, ``license`` or
    ``modifications``: spec 5.1 makes source origin, license and lineage
    evaluator-only, so they live in validation/provenance.json (and the
    generated tests/evaluator_view.json). ``source_origin`` stays.
11. ``package_versions`` in task.toml must pin exact versions: no range or
    wildcard (``>=3.10``, ``~=1.2``, ``1.*``, ``3.12.x``).
12. When vocabulary.json sits next to the tasks, the task.toml values of
    ``source_origin``, ``languages``, ``frameworks`` and ``architecture`` must
    be listed in it (controlled values, spec 5.2).
13. task_metadata.json (the scanner-visible view written by
    tools/export_views.py), when present, may only have the keys in
    ``METADATA_ALLOWLIST``, is searched for banned words like
    task.toml, and twin copies may differ only in the keys of point 7.

A VARIANTS.json that cannot be read or does not have the shape above fails
every task with a message instead of stopping the scan.

Prints one line per task and exits 1 when any task has a problem.
``--write-qc`` sets ``qc.label_leak_scan`` to "pass" or "fail" in each task's
validation/provenance.json.

Image mode looks at what the built task image holds instead of the source tree::

    python tools/leak_scan.py <harbor-tasks dir> --image [--task NAME ...] [--tools-image IMG]

For every task it runs ``docker build -q`` on environment/ (with
``--build-arg SAST_TOOLS_IMAGE=<value>``, where the value is ``--tools-image``
or else the ``ARG SAST_TOOLS_IMAGE=`` default in the task's Dockerfile), lists
every file under /app with ``docker run --rm --entrypoint sh <image> -c 'find
/app -type f -print0'``, and reads them out of a created (never started)
container with ``docker cp <container>:/app -``, which streams a tar archive.
Then it checks that:

a. no folder named tests, solution or validation sits directly under /app,
b. no file in the image has the same bytes as a file in the task's tests/,
   solution/ or validation/ (ground_truth.json included),
c. no file has an evaluator file name (ground truth, repro tests, provenance,
   grade.py, test.sh, solve.sh, findings.sarif),
d. the six-word ground-truth shingle check of point 3 passes on the files as
   they exist in the image (files written by the build, such as generated
   sources, are covered too).

It removes the container and every image it built, also when a check fails.
It needs the docker CLI on PATH and nothing else: subprocess calls take list
arguments and use no shell on the host, so it runs the same way from Windows
PowerShell with Docker Desktop. ``--write-qc`` is not available in this mode.

Uses only the standard library.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import re
import subprocess
import sys
import tarfile
import tomllib
from pathlib import Path

BANNED = ["cve-", "ghsa-", "vulnerab", "exploit", "patch", "fixed", "insecure", "bypass", "traversal", "ssrf",
          "injection", "malicious", "LLM02", "LLM03", "CWE-"]
BANNED_RE = re.compile("|".join(re.escape(w) for w in BANNED), re.IGNORECASE)
EVALUATOR_ONLY = [re.compile(p) for p in (r"^ground_truth.*\.json$", r"^repro_test.*\.py$", r"^provenance.*\.json$")]
TWIN_RE = re.compile(r"^(task_.+)_(positive|negative)$")
#: The scanner-visible view written by tools/export_views.py, and the only keys it may have (spec 5.2 task fields
#: from task.toml plus a pointer to the security manifest). export_views.py imports these.
METADATA_FILE = "task_metadata.json"
METADATA_TOML_FIELDS = (
    "schema_version", "task_id", "repository_id", "family_id", "variant_id", "source_origin",
    "languages", "frameworks", "package_versions", "architecture",
    "entrypoint", "build_command", "test_command", "scanner_roots", "excluded_paths", "related_variant_ids",
)
METADATA_POINTER_FIELDS = ("security_manifest_path", "security_manifest_fields")
METADATA_ALLOWLIST = frozenset(METADATA_TOML_FIELDS + METADATA_POINTER_FIELDS)
#: Files outside environment/ that the harness or the scanner can read.
VISIBLE_TASK_FILES = ("task.toml", "instruction.md", METADATA_FILE)
#: The only task.toml keys that may differ between twins.
TOML_TWIN_KEYS = {"task_id", "variant_id", "related_variant_ids"}
#: Words in an id that would say which twin a task is. Long words match anywhere in the id; the short ones
#: only as a whole part between separators (``_``, ``-``, ``:``, ``.``) so that random hex cannot match.
ROLE_RE = re.compile(r"positive|negative|vulnerab|patch|fixed|benign"
                     r"|(?:^|[^a-z0-9])(?:pos|neg|vuln|fix|safe|unsafe|bad|good)(?=[^a-z0-9]|$)", re.IGNORECASE)
SHINGLE = 6
#: Provenance keys that are evaluator-only (spec 5.1) and must not be in task.toml.
PROVENANCE_TOML_KEYS = ("source_url", "source_commit", "license", "modifications")
#: task.toml [metadata] fields whose values must come from vocabulary.json.
VOCABULARY_FIELDS = ("source_origin", "languages", "frameworks", "architecture")
VOCABULARY_FILE = "vocabulary.json"
#: An exact version: digits and dots, then optional pre/post/dev/local parts; no operator, comma, space or wildcard.
EXACT_VERSION_RE = re.compile(r"^\d+(?:\.\d+)*(?:[a-z]+\d*)?(?:\.?(?:post|dev)\d+)*(?:\+[a-z0-9.]+)?$",
                              re.IGNORECASE)
WORD_RE = re.compile(r"[a-z0-9_]+")


def is_task(d: Path) -> bool:
    return d.is_dir() and ((d / "task.toml").is_file() or (d / "environment").is_dir())


def env_files(task: Path) -> dict[str, bytes]:
    env = task / "environment"
    if not env.is_dir():
        return {}
    return {p.relative_to(env).as_posix(): p.read_bytes() for p in sorted(env.rglob("*")) if p.is_file()}


def banned_hits(files: dict[str, bytes]) -> list[str]:
    hits = []
    for rel, data in files.items():
        m = BANNED_RE.search(rel)
        if m:
            hits.append(f"banned word '{m.group(0)}' in path {rel}")
        if b"\0" in data[:4096]:
            continue  # binary
        text = data.decode("utf-8", errors="replace")
        for n, line in enumerate(text.splitlines(), 1):
            m = BANNED_RE.search(line)
            if m:
                hits.append(f"banned word '{m.group(0)}' at environment/{rel}:{n}")
    return hits


def visible_file_hits(task: Path) -> list[str]:
    """Banned words in task.toml and instruction.md."""
    hits = []
    for name in VISIBLE_TASK_FILES:
        f = task / name
        if not f.is_file():
            continue
        for n, line in enumerate(f.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            m = BANNED_RE.search(line)
            if m:
                hits.append(f"banned word '{m.group(0)}' at {name}:{n}")
    return hits


def _flatten(node: dict, prefix: str = "") -> dict[str, object]:
    out = {}
    for k, v in node.items():
        if isinstance(v, dict):
            out.update(_flatten(v, f"{prefix}{k}."))
        else:
            out[f"{prefix}{k}"] = v
    return out


def toml_twin_problems(a: Path, b: Path) -> list[str]:
    """Keys other than task_id, variant_id and related_variant_ids that differ between twin task.toml files."""
    fa, fb = a / "task.toml", b / "task.toml"
    if not fa.is_file() and not fb.is_file():
        return []
    if not fa.is_file() or not fb.is_file():
        return ["task.toml exists in only one twin"]
    try:
        ta = _flatten(tomllib.loads(fa.read_text(encoding="utf-8")))
        tb = _flatten(tomllib.loads(fb.read_text(encoding="utf-8")))
    except (tomllib.TOMLDecodeError, UnicodeDecodeError) as exc:
        return [f"cannot parse task.toml: {exc}"]
    differing = sorted(k for k in set(ta) | set(tb)
                       if ta.get(k) != tb.get(k) and k.rsplit(".", 1)[-1] not in TOML_TWIN_KEYS)
    return [f"task.toml differs between twins in {k}" for k in differing]


def toml_id_problems(task: Path) -> list[str]:
    """``task_id`` other than the folder name, or a role word in task_id, variant_id or related_variant_ids.

    These keys may differ between twins, so they are the one place in task.toml
    where a role could hide without the twin diff seeing it."""
    f = task / "task.toml"
    if not f.is_file():
        return []
    try:
        flat = _flatten(tomllib.loads(f.read_text(encoding="utf-8")))
    except (tomllib.TOMLDecodeError, UnicodeDecodeError) as exc:
        return [f"cannot parse task.toml: {exc}"]
    problems = []
    for key, value in sorted(flat.items()):
        leaf = key.rsplit(".", 1)[-1]
        if leaf not in TOML_TWIN_KEYS:
            continue
        if leaf == "task_id" and value != task.name:
            problems.append(f"task.toml {key} = {value!r} is not the folder name {task.name!r}")
        for item in value if isinstance(value, list) else [value]:
            m = ROLE_RE.search(str(item))
            if m:
                problems.append(f"role word '{m.group(0).strip('_-:.')}' in task.toml {key} = {item!r}")
    return problems


def _metadata_table(task: Path) -> tuple[dict | None, list[str]]:
    f = task / "task.toml"
    if not f.is_file():
        return None, []
    try:
        data = tomllib.loads(f.read_text(encoding="utf-8"))
    except (tomllib.TOMLDecodeError, UnicodeDecodeError) as exc:
        return None, [f"cannot parse task.toml: {exc}"]
    return data.get("metadata") or {}, []


def toml_field_problems(task: Path, vocabulary: dict | None) -> list[str]:
    """Points 10 to 12: no provenance keys, exact package pins, controlled values."""
    meta, problems = _metadata_table(task)
    if meta is None:
        return problems
    flat = _flatten(tomllib.loads((task / "task.toml").read_text(encoding="utf-8")))
    for key in sorted(flat):
        if key.rsplit(".", 1)[-1] in PROVENANCE_TOML_KEYS:
            problems.append(f"task.toml has {key}, which is evaluator-only (keep it in validation/provenance.json)")
    pins = meta.get("package_versions")
    if pins is not None:
        if not isinstance(pins, dict):
            problems.append(f"task.toml package_versions is not a table: {pins!r}")
        else:
            for name, version in sorted(pins.items()):
                if not isinstance(version, str) or not EXACT_VERSION_RE.match(version.strip()):
                    problems.append(f"task.toml package_versions.{name} = {version!r} is not an exact version")
    if vocabulary is None:
        return problems
    for field in VOCABULARY_FIELDS:
        if field not in meta:
            continue
        allowed = vocabulary.get(field)
        if not isinstance(allowed, list):
            problems.append(f"{VOCABULARY_FILE} has no list for {field}")
            continue
        value = meta[field]
        for item in value if isinstance(value, list) else [value]:
            if item not in allowed:
                problems.append(f"task.toml {field} value {item!r} is not in {VOCABULARY_FILE}")
    return problems


def load_vocabulary(root: Path) -> tuple[dict | None, str | None]:
    """(vocabulary, error); (None, None) when there is no vocabulary.json."""
    f = root / VOCABULARY_FILE
    if not f.is_file():
        return None, None
    try:
        data = json.loads(f.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError("expected an object of {field: [allowed values]}")
    except (OSError, ValueError) as exc:
        return None, f"cannot read {VOCABULARY_FILE}: {exc}"
    return data, None


def _read_metadata_view(task: Path) -> tuple[dict | None, list[str]]:
    f = task / METADATA_FILE
    if not f.is_file():
        return None, []
    try:
        data = json.loads(f.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError("expected an object")
    except (OSError, ValueError) as exc:
        return None, [f"cannot read {METADATA_FILE}: {exc}"]
    return data, []


def metadata_view_problems(task: Path) -> list[str]:
    """Point 13: task_metadata.json keys stay within the allowlist."""
    data, problems = _read_metadata_view(task)
    if data is None:
        return problems
    extra = sorted(set(data) - METADATA_ALLOWLIST)
    if extra:
        problems.append(f"{METADATA_FILE} has keys outside the scanner-visible allowlist: {', '.join(extra)}")
    if "task_id" in data and data["task_id"] != task.name:
        problems.append(f"{METADATA_FILE} task_id = {data['task_id']!r} is not the folder name {task.name!r}")
    return problems


def metadata_view_twin_problems(a: Path, b: Path) -> list[str]:
    """Twin task_metadata.json files may differ only in task_id, variant_id and related_variant_ids."""
    da, pa = _read_metadata_view(a)
    db, pb = _read_metadata_view(b)
    if pa or pb:
        return []  # already reported per task
    if da is None and db is None:
        return []
    if da is None or db is None:
        return [f"{METADATA_FILE} exists in only one twin"]
    fa, fb = _flatten(da), _flatten(db)
    differing = sorted(k for k in set(fa) | set(fb)
                       if fa.get(k) != fb.get(k) and k.rsplit(".", 1)[-1] not in TOML_TWIN_KEYS)
    return [f"{METADATA_FILE} differs between twins in {k}" for k in differing]


def instruction_twin_problems(a: Path, b: Path) -> list[str]:
    """Twin instruction.md files must have the same bytes."""
    fa, fb = a / "instruction.md", b / "instruction.md"
    if not fa.is_file() and not fb.is_file():
        return []
    if not fa.is_file() or not fb.is_file():
        return ["instruction.md exists in only one twin"]
    return [] if fa.read_bytes() == fb.read_bytes() else ["instruction.md differs between twins"]


def evaluator_files(files: dict[str, bytes]) -> list[str]:
    return [f"evaluator-only file under environment/: {rel}" for rel in files
            if any(p.match(rel.rsplit("/", 1)[-1]) for p in EVALUATOR_ONLY)]


def words(text: str) -> list[str]:
    return WORD_RE.findall(text.lower())


def shingles(tokens: list[str], n: int = SHINGLE) -> set[tuple[str, ...]]:
    return {tuple(tokens[i:i + n]) for i in range(len(tokens) - n + 1)}


def truth_strings(node, path: str = "") -> list[tuple[str, str]]:
    """(json path, string) for every string in the ground truth."""
    if isinstance(node, str):
        return [(path, node)]
    if isinstance(node, dict):
        return [x for k, v in node.items() for x in truth_strings(v, f"{path}.{k}" if path else k)]
    if isinstance(node, list):
        return [x for i, v in enumerate(node) for x in truth_strings(v, f"{path}[{i}]")]
    return []


def overlap_problems(task: Path, files: dict[str, bytes], prefix: str = "environment/") -> list[str]:
    """Six-word shingles of ground-truth strings that also occur in the given files.

    ``prefix`` goes before the file names in the messages (environment/ for
    the source tree, /app/ for a built image)."""
    gt_file = task / "tests" / "ground_truth.json"
    if not gt_file.is_file():
        return []
    try:
        truth = json.loads(gt_file.read_text(encoding="utf-8"))
    except ValueError as exc:
        return [f"cannot read tests/ground_truth.json: {exc}"]
    wanted: dict[tuple[str, ...], str] = {}
    for where, text in truth_strings(truth):
        tokens = words(text)
        if len(text.split()) < SHINGLE or len(tokens) < SHINGLE:
            continue
        for sh in shingles(tokens):
            wanted.setdefault(sh, where)
    if not wanted:
        return []
    problems, reported = [], set()
    for rel, data in files.items():
        if b"\0" in data[:4096]:
            continue  # binary
        for sh in shingles(words(data.decode("utf-8", errors="replace"))) & wanted.keys():
            key = (wanted[sh], rel)
            if key in reported:
                continue
            reported.add(key)
            problems.append(f"ground-truth text from {wanted[sh]} appears in {prefix}{rel}: '{' '.join(sh)}'")
    return sorted(problems)


def dockerfile_problems(task: Path) -> list[str]:
    """COPY or ADD of anything but repo/ (other build stages excepted)."""
    df = task / "environment" / "Dockerfile"
    if not df.is_file():
        return []
    text = re.sub(r"\\\r?\n", " ", df.read_text(errors="replace"))
    problems = []
    for n, line in enumerate(text.splitlines(), 1):
        parts = line.strip().split()
        if not parts or parts[0].upper() not in ("COPY", "ADD"):
            continue
        args = parts[1:]
        if any(a.startswith("--from") for a in args):
            continue
        args = [a for a in args if not a.startswith("--")]
        joined = " ".join(args)
        if joined.startswith("["):
            try:
                args = json.loads(joined)
            except ValueError:
                problems.append(f"Dockerfile: cannot parse '{line.strip()}'")
                continue
        for src in args[:-1]:
            if src.rstrip("/").removeprefix("./") != "repo":
                problems.append(f"Dockerfile copies {src} into the image (only repo/ may be copied): "
                                f"'{line.strip()}'")
    return problems


def twin_problems(pos: Path, neg: Path) -> list[str]:
    """environment/ differences between the original positive ``pos`` and its twin."""
    a, b = env_files(pos), env_files(neg)
    try:
        gt = json.loads((pos / "tests" / "ground_truth.json").read_text(encoding="utf-8"))
        allowed = {f"repo/{f}" for f in gt.get("fix_changed_files") or []}
    except (OSError, ValueError) as exc:
        return [f"cannot read positive ground truth: {exc}"]
    problems = []
    differing = sorted(rel for rel in set(a) | set(b) if a.get(rel) != b.get(rel))
    for rel in differing:
        if rel not in allowed:
            problems.append(f"twin differs outside fix_changed_files: environment/{rel}")
        if rel.endswith("security_manifest.json") or "/fixtures/" in f"/{rel}":
            problems.append(f"twin differs in manifest or fixtures: environment/{rel}")
    if not any(rel.endswith("security_manifest.json") for rel in a):
        problems.append("positive has no security_manifest.json under environment/")
    if allowed and not differing:
        problems.append("twins are identical under environment/")
    return problems


def write_qc(task: Path, ok: bool) -> None:
    prov = task / "validation" / "provenance.json"
    if not prov.is_file():
        return
    data = json.loads(prov.read_text(encoding="utf-8"))
    data.setdefault("qc", {})["label_leak_scan"] = "pass" if ok else "fail"
    prov.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n")


def _fix_files(task: Path) -> list[str]:
    try:
        gt = json.loads((task / "tests" / "ground_truth.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    return list(gt.get("fix_changed_files") or [])


def _code_state(task: Path) -> str | None:
    try:
        prov = json.loads((task / "validation" / "provenance.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return (prov.get("lineage") or {}).get("code_state")


def original_positive(a: str, b: str, variants: dict, by_name: dict) -> str | None:
    """Which twin of a pair holds the source-commit code (the side whose fix_changed_files apply).

    1. The twin whose VARIANTS role is positive and whose ground truth lists a
       non-empty ``fix_changed_files``, when only one twin qualifies.
    2. When both qualify (a twin with the upstream fix relabelled as a
       partial-control positive), the one whose ``former_name`` ends in
       ``_positive``, if exactly one does.
    3. Otherwise the one whose provenance ``lineage.code_state`` is
       ``source_commit``, if exactly one is.
    Returns None when the rules do not settle it.
    """
    cands = [x for x in (a, b) if variants[x].get("role") == "positive" and _fix_files(by_name[x])]
    if len(cands) == 1:
        return cands[0]
    if len(cands) != 2:
        return None
    named = [x for x in cands if str(variants[x].get("former_name") or "").endswith("_positive")]
    if len(named) == 1:
        return named[0]
    source = [x for x in cands if _code_state(by_name[x]) == "source_commit"]
    return source[0] if len(source) == 1 else None


def twin_pairs(root: Path, by_name: dict, problems: dict) -> list[tuple[str, str]]:
    """(original positive, its twin) pairs.

    With role-free task ids the pairing comes from the evaluator-only
    ``VARIANTS.json`` next to the tasks ({id: {family, role, twin,
    former_name}}, former_name optional), and ``original_positive`` picks the
    side whose ``fix_changed_files`` define the allowed difference. A pair it
    cannot settle is reported on both tasks. Without the map, folder names
    ``task_<id>_positive`` / ``task_<id>_negative`` are paired.
    """
    pairs = []
    variants_file = root / "VARIANTS.json"
    if variants_file.is_file():
        try:
            variants = json.loads(variants_file.read_text(encoding="utf-8"))
            if not isinstance(variants, dict) or not all(isinstance(v, dict) for v in variants.values()):
                raise ValueError("expected an object of {task id: {family, role, twin, former_name}} objects")
        except (OSError, ValueError) as exc:
            for name in by_name:
                problems[name].append(f"cannot read VARIANTS.json, so no twin was checked: {exc}")
            return []
        seen = set()
        for name, v in variants.items():
            if name not in by_name:
                continue
            twin = v.get("twin")
            if not twin or twin not in by_name or twin not in variants:
                problems[name].append(f"twin {twin} not found")
                continue
            if variants[twin].get("twin") != name:
                problems[name].append(f"twin {twin} does not name {name} as its twin in VARIANTS.json")
                continue
            key = frozenset((name, twin))
            if key in seen:
                continue
            seen.add(key)
            orig = original_positive(name, twin, variants, by_name)
            if orig is None:
                msg = (f"cannot tell which of {name} and {twin} is the original positive (role positive with "
                       "fix_changed_files, then former_name, then provenance lineage.code_state)")
                problems[name].append(msg)
                problems[twin].append(msg)
                continue
            pairs.append((orig, twin if orig == name else name))
        for name in by_name:
            if name not in variants:
                problems[name].append("task missing from VARIANTS.json")
        return pairs
    for name in by_name:
        m = TWIN_RE.match(name)
        if not m:
            continue
        other = f"{m.group(1)}_{'negative' if m.group(2) == 'positive' else 'positive'}"
        if other not in by_name:
            problems[name].append(f"twin {other} not found")
        elif m.group(2) == "positive":
            pairs.append((name, other))
    return pairs


def scan(root: Path) -> dict[str, list[str]]:
    tasks = sorted(d for d in root.iterdir() if is_task(d))
    problems = {t.name: [] for t in tasks}
    vocabulary, vocab_error = load_vocabulary(root)
    for t in tasks:
        if vocab_error:
            problems[t.name].append(vocab_error)
        problems[t.name] += toml_field_problems(t, vocabulary) + metadata_view_problems(t)
        files = env_files(t)
        if not files:
            problems[t.name].append("no files under environment/")
        problems[t.name] += banned_hits(files) + visible_file_hits(t) + evaluator_files(files)
        problems[t.name] += overlap_problems(t, files) + dockerfile_problems(t) + toml_id_problems(t)
    by_name = {t.name: t for t in tasks}
    for pos, neg in twin_pairs(root, by_name, problems):
        a, b = by_name[pos], by_name[neg]
        for p in (twin_problems(a, b) + toml_twin_problems(a, b) + instruction_twin_problems(a, b)
                  + metadata_view_twin_problems(a, b)):
            problems[pos].append(p)
            problems[neg].append(p)
    return problems


# ---------------------------------------------------------------- image mode

IMAGE_ROOT = "/app"
EVALUATOR_DIRS = ("tests", "solution", "validation")
EVALUATOR_NAMES = EVALUATOR_ONLY + [re.compile(p) for p in (r"^grade\.py$", r"^test\.sh$", r"^solve\.sh$",
                                                            r"^findings\.sarif$")]
#: Files this small (an empty __init__.py, a bare "{}") match by chance.
MIN_CONTENT_MATCH_BYTES = 32
BUILD_TIMEOUT_SEC = 1800
DOCKER_TIMEOUT_SEC = 600
TOOLS_ARG_RE = re.compile(r"^\s*ARG\s+SAST_TOOLS_IMAGE\s*=\s*(\S+)\s*$", re.IGNORECASE | re.MULTILINE)


class DockerError(Exception):
    """A docker command failed."""


def docker(args: list[str], timeout: int = DOCKER_TIMEOUT_SEC) -> bytes:
    """Run ``docker <args>`` (list arguments, no shell) and return its stdout."""
    try:
        proc = subprocess.run(["docker", *args], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
    except FileNotFoundError as exc:
        raise DockerError("the docker CLI is not on PATH") from exc
    except subprocess.TimeoutExpired as exc:
        raise DockerError(f"docker {args[0]} did not finish within {timeout} s") from exc
    if proc.returncode != 0:
        err = proc.stderr.decode("utf-8", errors="replace").strip()[-600:]
        raise DockerError(f"docker {args[0]} exited {proc.returncode}: {err}")
    return proc.stdout


def tools_image_default(task: Path) -> str | None:
    """The default of ``ARG SAST_TOOLS_IMAGE=`` in the task's Dockerfile."""
    df = task / "environment" / "Dockerfile"
    if not df.is_file():
        return None
    m = TOOLS_ARG_RE.search(df.read_text(errors="replace"))
    return m.group(1).strip("\"'") if m else None


def build_image(task: Path, tools_image: str | None) -> str:
    """``docker build -q`` of environment/; returns the image id."""
    args = ["build", "-q"]
    value = tools_image or tools_image_default(task)
    if value:
        args += ["--build-arg", f"SAST_TOOLS_IMAGE={value}"]
    out = docker(args + [str(task / "environment")], timeout=BUILD_TIMEOUT_SEC).decode("utf-8", errors="replace")
    lines = [line.strip() for line in out.splitlines() if line.strip()]
    if not lines:
        raise DockerError("docker build -q printed no image id")
    return lines[-1]


def list_image_files(image: str) -> list[str]:
    """Every regular file under /app in the image, as paths relative to /app."""
    out = docker(["run", "--rm", "--entrypoint", "sh", image, "-c", f"find {IMAGE_ROOT} -type f -print0"])
    names = []
    for raw in out.split(b"\0"):
        path = raw.decode("utf-8", errors="replace").strip("\r\n")
        if path.startswith(IMAGE_ROOT + "/"):
            names.append(path[len(IMAGE_ROOT) + 1:])
    return sorted(names)


def read_image_files(image: str) -> dict[str, bytes]:
    """The regular files under /app, read from a created container with ``docker cp ... -``."""
    container = docker(["create", "--entrypoint", "sh", image, "-c", "true"]).decode().strip().splitlines()[-1]
    try:
        archive = docker(["cp", f"{container}:{IMAGE_ROOT}", "-"])
    finally:
        try:
            docker(["rm", "-f", container])
        except DockerError:
            pass
    files = {}
    top = IMAGE_ROOT.strip("/")
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:*") as tar:
        for member in tar.getmembers():
            if not member.isfile():
                continue
            name = member.name.lstrip("./")
            if name != top and not name.startswith(top + "/"):
                continue
            rel = name[len(top) + 1:]
            if rel:
                files[rel] = tar.extractfile(member).read()
    return files


def evaluator_hashes(task: Path) -> dict[str, str]:
    """sha256 -> task-relative path for every file in tests/, solution/ and validation/."""
    found = {}
    for d in EVALUATOR_DIRS:
        folder = task / d
        if not folder.is_dir():
            continue
        for p in sorted(folder.rglob("*")):
            if p.is_file() and p.stat().st_size >= MIN_CONTENT_MATCH_BYTES:
                found.setdefault(hashlib.sha256(p.read_bytes()).hexdigest(), p.relative_to(task).as_posix())
    return found


def image_file_problems(task: Path, listed: list[str], files: dict[str, bytes]) -> list[str]:
    """Checks a to d of image mode on the files read out of the image."""
    where = f"{IMAGE_ROOT}/"
    problems = []
    missing = sorted(set(listed) - set(files))
    if missing:
        problems.append(f"{len(missing)} files listed by find were not in the docker cp archive, "
                        f"for example {where}{missing[0]}")
    for rel in sorted(set(listed) | set(files)):
        parts = rel.split("/")
        if parts[0] in EVALUATOR_DIRS:
            problems.append(f"evaluator folder in the image: {where}{rel}")
        if any(p.match(parts[-1]) for p in EVALUATOR_NAMES):
            problems.append(f"evaluator file name in the image: {where}{rel}")
    hashes = evaluator_hashes(task)
    for rel, data in sorted(files.items()):
        if len(data) < MIN_CONTENT_MATCH_BYTES:
            continue
        source = hashes.get(hashlib.sha256(data).hexdigest())
        if source:
            problems.append(f"{where}{rel} has the same bytes as {source}")
    problems += overlap_problems(task, files, prefix=where)
    return problems


def scan_image(task: Path, tools_image: str | None = None) -> tuple[list[str], int]:
    """Build the task image, run checks a to d, remove the image.

    Returns (problems, number of files under /app)."""
    image = None
    try:
        image = build_image(task, tools_image)
        listed = list_image_files(image)
        files = read_image_files(image)
        if not listed and not files:
            return [f"no files under {IMAGE_ROOT} in the image"], 0
        return image_file_problems(task, listed, files), len(set(listed) | set(files))
    except DockerError as exc:
        return [f"image check could not run: {exc}"], 0
    finally:
        if image:
            try:
                docker(["rmi", "-f", image])
            except DockerError as exc:
                print(f"warning: could not remove image {image}: {exc}", file=sys.stderr)


def main_image(root: Path, only: list[str], tools_image: str | None) -> int:
    tasks = sorted(d for d in root.iterdir() if is_task(d))
    if only:
        unknown = sorted(set(only) - {t.name for t in tasks})
        if unknown:
            print(f"no such task under {root}: {', '.join(unknown)}")
            return 2
        tasks = [t for t in tasks if t.name in only]
    if not tasks:
        print(f"no task folders under {root}")
        return 1
    failed = 0
    for t in tasks:
        items, count = scan_image(t, tools_image)
        failed += bool(items)
        print(f"{t.name}  {'FAIL' if items else 'pass'}  ({count} files under {IMAGE_ROOT})"
              + (f"  ({len(items)} problems)" if items else ""), flush=True)
        for item in items:
            print(f"    {item}")
    print(f"\nimage leak check: {len(tasks) - failed}/{len(tasks)} task images pass "
          f"(a pass is not proof that no label leaks)")
    return 1 if failed else 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("tasks", type=Path, help="the harbor-tasks directory")
    ap.add_argument("--write-qc", action="store_true", help="record pass or fail in validation/provenance.json")
    ap.add_argument("--image", action="store_true", help="build each task image and check what is under /app")
    ap.add_argument("--task", action="append", default=[], metavar="NAME",
                    help="image mode: only this task folder (repeat for more)")
    ap.add_argument("--tools-image", help="image mode: SAST_TOOLS_IMAGE build argument "
                                          "(default: the ARG default in each task's Dockerfile)")
    args = ap.parse_args()
    if args.image:
        if args.write_qc:
            ap.error("--write-qc records the source-tree check and cannot be used with --image")
        return main_image(args.tasks, args.task, args.tools_image)
    if args.task or args.tools_image:
        ap.error("--task and --tools-image need --image")
    problems = scan(args.tasks)
    if not problems:
        print(f"no task folders under {args.tasks}")
        return 1
    for name, items in problems.items():
        print(f"{name}  {'FAIL' if items else 'pass'}" + (f"  ({len(items)} problems)" if items else ""))
        for item in items:
            print(f"    {item}")
        if args.write_qc:
            write_qc(args.tasks / name, not items)
    failed = sum(1 for v in problems.values() if v)
    print(f"\nheuristic leak check: {len(problems) - failed}/{len(problems)} tasks pass "
          f"(a pass is not proof that no label leaks)")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
