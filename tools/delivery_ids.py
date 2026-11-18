#!/usr/bin/env python3
"""Assign sequential delivery ids (D001...) to plan slots and record them everywhere.

    python ng-sast-agent/tools/delivery_ids.py [--dataset tasks] [--task-files] [--quiet-minutes 30]

Delivery ids follow the build order in ``<dataset>/BATCHES.json``:

* ``batch-1`` .. ``batch-10`` slots, in row order of the 250 plan sheet: D001-D250 (batch-N = D(25N-24)-D(25N));
* ``batch-buffer`` slots, in order: D251-D300;
* ``batch-extra`` slots, in order: D301 onwards.

One id per pair: both twins share it. The 500-plan slot (``P###``) is kept beside it as the reference to
``planning/SAST_500_Plan.xlsx``. The script writes:

* ``BATCHES.json``: ``delivery_ids`` (D -> P) and ``slot_delivery_ids`` (P -> D);
* ``VARIANTS.json``: ``delivery_id`` on every entry (under the dataset lock scaffold_pair.py uses);
* each family's ``_work/slot.json``: ``delivery_id``;
* with ``--task-files``, for families whose last QC passed and whose files have not changed for
  ``--quiet-minutes`` (so a pair another builder is still working on is left alone): ``delivery_id`` in both
  twins' ``validation/provenance.json`` (``authoring``, after ``plan_slot``), the README's "Slot P### of" line,
  and the evaluator views regenerated with export_views.py. Nothing scanner-visible changes.

Idempotent: re-run it any time (for example after more pairs are built).
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def lock(path: Path):
    fh = open(path, "a+")
    fh.seek(0)
    if os.name == "nt":
        import msvcrt
        while True:
            try:
                msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, 1)
                return fh
            except OSError:
                time.sleep(1)
    import fcntl
    fcntl.flock(fh, fcntl.LOCK_EX)
    return fh


def unlock(fh) -> None:
    fh.seek(0)
    if os.name == "nt":
        import msvcrt
        msvcrt.locking(fh.fileno(), msvcrt.LK_UNLCK, 1)
    else:
        import fcntl
        fcntl.flock(fh, fcntl.LOCK_UN)
    fh.close()


def write_like(path: Path, raw: str, data) -> bool:
    indent = 2
    m = re.search(r"\n( +)\"", raw)
    if m:
        indent = len(m.group(1))
    new = json.dumps(data, indent=indent, ensure_ascii=raw.isascii()) + ("\n" if raw.endswith("\n") else "")
    if new == raw:
        return False
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(new, encoding="utf-8")
    os.replace(tmp, path)
    return True


def mapping(batches: dict) -> dict[str, str]:
    p2d: dict[str, str] = {}
    n = 0
    for name in sorted(batches["batches"], key=lambda b: int(b.split("-")[1])):
        for slot in batches["batches"][name]["slots"]:
            n += 1
            p2d[slot] = f"D{n:03d}"
    n = 250
    for slot in batches.get("batch-buffer", {}).get("slots", []):
        n += 1
        p2d.setdefault(slot, f"D{n:03d}")
    n = 300
    for slot in batches.get("batch-extra", {}).get("slots", []):
        n += 1
        p2d.setdefault(slot, f"D{n:03d}")
    return p2d


def insert_after(d: dict, after: str, key: str, value) -> dict:
    if d.get(key) == value:
        return d
    out = {}
    for k, v in d.items():
        if k == key:
            continue
        out[k] = v
        if k == after:
            out[key] = value
    if key not in out:
        out[key] = value
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dataset", default="tasks")
    ap.add_argument("--task-files", action="store_true", help="also update provenance, README and views of finished pairs")
    ap.add_argument("--quiet-minutes", type=float, default=30.0)
    args = ap.parse_args()
    root = (ROOT / args.dataset).resolve()

    lk = lock(root / ".VARIANTS.json.lock")
    try:
        braw = (root / "BATCHES.json").read_text(encoding="utf-8")
        batches = json.loads(braw)
        p2d = mapping(batches)
        batches["delivery_ids"] = {d: p for p, d in sorted(p2d.items(), key=lambda kv: kv[1])}
        batches["slot_delivery_ids"] = dict(sorted(p2d.items()))
        write_like(root / "BATCHES.json", braw, batches)
        vraw = (root / "VARIANTS.json").read_text(encoding="utf-8")
        variants = json.loads(vraw)
        for entry in variants.values():
            if isinstance(entry, dict) and entry.get("slot") in p2d:
                entry["delivery_id"] = p2d[entry["slot"]]
        write_like(root / "VARIANTS.json", vraw, variants)
    finally:
        unlock(lk)
    print(f"delivery ids: {len(p2d)} slots; VARIANTS.json and BATCHES.json updated")

    families: dict[str, tuple[Path, str]] = {}
    for entry in variants.values():
        if not isinstance(entry, dict) or entry.get("slot") not in p2d:
            continue
        for bdir in root.glob("batch-*"):
            if (bdir / entry["family"] / "_work").is_dir():
                families[entry["family"]] = (bdir, p2d[entry["slot"]])
    touched, skipped = [], []
    now = time.time()
    for fam, (bdir, did) in sorted(families.items()):
        sj = bdir / fam / "_work" / "slot.json"
        if sj.is_file():
            raw = sj.read_text(encoding="utf-8")
            data = json.loads(raw)
            data = insert_after(data, "slot", "delivery_id", did)
            write_like(sj, raw, data)
        if not args.task_files:
            continue
        qc = bdir / fam / "_work" / "qc.md"
        twins = [bdir / f"{fam}-a", bdir / f"{fam}-b"]
        if not qc.is_file() or "Result: no FAIL" not in qc.read_text(encoding="utf-8", errors="replace") \
                or not all(t.is_dir() for t in twins):
            skipped.append(f"{fam} (no passing QC)")
            continue
        newest = max((p.stat().st_mtime for t in twins + [bdir / fam / "_work"] for p in t.rglob("*")
                      if p.is_file() and p.name not in ("slot.json", "provenance.json", "README.md",
                                                        "evaluator_view.json", "task_metadata.json")),
                     default=0)  # files this script itself writes don't count as builder activity
        if now - newest < args.quiet_minutes * 60:
            skipped.append(f"{fam} (changed in the last {args.quiet_minutes:g} min)")
            continue
        for t in twins:
            prov = t / "validation" / "provenance.json"
            if prov.is_file():
                raw = prov.read_text(encoding="utf-8")
                data = json.loads(raw)
                if isinstance(data.get("authoring"), dict):
                    data["authoring"] = insert_after(data["authoring"], "plan_slot", "delivery_id", did)
                    write_like(prov, raw, data)
            readme = t / "README.md"
            if readme.is_file():
                txt = readme.read_text(encoding="utf-8")
                new = re.sub(r"(?m)^(?:Delivery ID D\d{3}; s|S)lot (P\d{3}) of", rf"Delivery ID {did}; slot \1 of", txt, count=1)
                if new != txt:
                    readme.write_text(new, encoding="utf-8")
        touched.append((bdir, fam))
    if touched:
        py = ROOT / "ng-sast-agent" / ".venv" / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
        by_batch: dict[Path, list[str]] = {}
        for bdir, fam in touched:
            by_batch.setdefault(bdir, []).extend([f"{fam}-a", f"{fam}-b"])
        for bdir, names in by_batch.items():
            cmd = [str(py), str(ROOT / "ng-sast-agent" / "tools" / "export_views.py"), str(bdir)]
            for n in names:
                cmd += ["--task", n]
            r = subprocess.run(cmd, capture_output=True, text=True)
            print(f"{bdir.name}: {(r.stdout.strip().splitlines() or [r.stderr.strip()])[-1][:90]}")
    if args.task_files:
        print(f"task files updated: {len(touched)} pairs; skipped {len(skipped)}")
        for s in skipped:
            print(f"  skipped {s}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
