#!/usr/bin/env python3
"""Check that no label leaks into what the scanner sees.

    python tools/leak_scan.py <harbor-tasks dir> [--write-qc]

For every task folder (one holding task.toml or environment/):

1. Every file under environment/ (names and text) is searched for banned words
   that would reveal the label (advisory ids, bug-class words, rule ids, CWE ids).
2. Evaluator-only files (ground truth, repro tests, provenance) must not be
   under environment/.
3. For twins ``task_<id>_positive`` / ``task_<id>_negative``: the environment/
   trees may differ only in files listed in the positive ground truth's
   ``fix_changed_files`` (paths relative to environment/repo), and
   security_manifest.json and fixtures/ must be byte-identical.

Prints one line per task and exits 1 when any task has a problem.
``--write-qc`` sets ``qc.label_leak_scan`` to "pass" or "fail" in each task's
validation/provenance.json.

Uses only the standard library.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

BANNED = ["cve-", "ghsa-", "vulnerab", "exploit", "patch", "fixed", "insecure", "bypass", "traversal", "ssrf",
          "injection", "malicious", "LLM02", "LLM03", "CWE-"]
BANNED_RE = re.compile("|".join(re.escape(w) for w in BANNED), re.IGNORECASE)
EVALUATOR_ONLY = [re.compile(p) for p in (r"^ground_truth.*\.json$", r"^repro_test.*\.py$", r"^provenance.*\.json$")]
TWIN_RE = re.compile(r"^(task_.+)_(positive|negative)$")


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


def evaluator_files(files: dict[str, bytes]) -> list[str]:
    return [f"evaluator-only file under environment/: {rel}" for rel in files
            if any(p.match(rel.rsplit("/", 1)[-1]) for p in EVALUATOR_ONLY)]


def twin_problems(pos: Path, neg: Path) -> list[str]:
    a, b = env_files(pos), env_files(neg)
    try:
        gt = json.loads((pos / "tests" / "ground_truth.json").read_text())
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
    data = json.loads(prov.read_text())
    data.setdefault("qc", {})["label_leak_scan"] = "pass" if ok else "fail"
    prov.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n")


def scan(root: Path) -> dict[str, list[str]]:
    tasks = sorted(d for d in root.iterdir() if is_task(d))
    problems = {t.name: [] for t in tasks}
    for t in tasks:
        files = env_files(t)
        if not files:
            problems[t.name].append("no files under environment/")
        problems[t.name] += banned_hits(files) + evaluator_files(files)
    by_name = {t.name: t for t in tasks}
    for name, t in by_name.items():
        m = TWIN_RE.match(name)
        if not m or m.group(2) != "positive":
            continue
        other = f"{m.group(1)}_negative"
        if other not in by_name:
            problems[name].append(f"twin {other} not found")
            continue
        for p in twin_problems(t, by_name[other]):
            problems[name].append(p)
            problems[other].append(p)
    for name in by_name:
        m = TWIN_RE.match(name)
        if m and m.group(2) == "negative" and f"{m.group(1)}_positive" not in by_name:
            problems[name].append(f"twin {m.group(1)}_positive not found")
    return problems


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("tasks", type=Path, help="the harbor-tasks directory")
    ap.add_argument("--write-qc", action="store_true", help="record pass or fail in validation/provenance.json")
    args = ap.parse_args()
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
    print(f"\n{len(problems) - failed}/{len(problems)} tasks pass")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
