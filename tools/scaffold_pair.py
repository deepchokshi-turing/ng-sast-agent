#!/usr/bin/env python3
"""Scaffold one benchmark task pair (positive ``<family>-a`` and negative ``<family>-b``) in the v4 format.

    python tools/scaffold_pair.py --slot P001 [--family-name ag2-shell-newline] [--dataset tasks]
                                  [--plan planning/SAST_500_Plan.xlsx] [--force] [--batch NAME] [--flat]

Dataset layout. ``--dataset`` (absolute, or relative to the repository root) names one of:

* the dataset root (default ``tasks``): it holds ``VARIANTS.json``, ``vocabulary.json`` and
  ``BATCHES.json`` (read only), and the families live in batch folders ``<root>/<batch>/``. The
  batch is the key whose ``slots`` list the slot, searched in ``batches.*`` (``batch-1`` ...), then
  ``batch-buffer``, then ``batch-extra``; the family is created in that folder. ``--batch NAME``
  overrides the map (e.g. to place a buffer pair into the batch it replaces) and is required for a
  slot the map does not list.
* a batch folder ``<root>/<batch>``: the same, with ``VARIANTS.json`` and ``BATCHES.json`` in its
  parent. Refused when it is not the slot's batch (from the map, or ``--batch``).
* an old flat dataset (``VARIANTS.json`` and the task folders side by side, e.g.
  ``_poc/harbor-tasks``): detected when the folder has no ``BATCHES.json``, no ``batch-*`` folder,
  and already holds a task folder (one with ``task.toml``), or forced with ``--flat``. The family
  goes in that folder.

Family names are unique across the whole dataset: name allocation and the clash checks look at
``VARIANTS.json`` and at every batch folder. Below, ``<dir>`` is the folder the family goes in
(the batch folder, or the flat dataset).

Concurrency. Parallel scaffolds are safe. Two cross-process locks (an OS byte-range lock on a lock
file: ``msvcrt.locking`` on Windows, ``fcntl.flock`` elsewhere; the OS drops it when the process
dies, so there are no stale locks to clean up; the lock files themselves are left in place):

* ``.cache/repos/<owner>__<name>.lock`` is held while the cached clone is created, fetched into and
  read. ``<owner>__<name>.cloning`` marks a clone in progress; one left behind by an interrupted
  clone makes the next run delete the clone and start again.
* ``<root>/.VARIANTS.json.lock`` is held (a) while the family name and opaque ids are allocated and
  the family's ``_work/`` is created (which reserves the name; ``_work/.scaffold-pending.json``
  reserves the ids until the end), and (b) while ``VARIANTS.json`` is re-read, updated and written
  atomically (temp file + ``os.replace``). The slow work (git, GitHub API, templates) runs between
  the two, outside the lock. If the scaffold fails, the folders it created are removed.

Reads the slot's row from the "Task slots" sheet of the plan workbook and writes

* ``<dir>/<family>/_work/``: the builder's workbench, never shipped. For a slot with a fix
  commit (types A and B upstream fix): ``upstream-positive/`` (the tree at the fix's parent, which
  should equal the plan's Base commit), ``upstream-negative/`` (the tree at the fix commit),
  ``fix.diff``, ``fix_files.txt``. For a designed control (type B without a fix commit):
  ``upstream-positive/`` at the Base commit only. Always: ``slot.json`` (the plan row, advisory
  text from the GitHub API, commit metadata) and ``BUILD_TODO.md`` (the build checklist).
* ``<dir>/<family>-a/`` and ``-b/`` in the v4 layout of ``pilot_v4/`` from the templates in
  ``task_format/templates/v4/``, with every field the plan already decides filled in and the rest
  marked ``TODO``. Paths written into the generated text name the real folder (e.g.
  ``tasks/batch-2/<family>``).
* ``<root>/VARIANTS.json`` (evaluator-only twin map with the opaque ids) and, when missing,
  ``<root>/vocabulary.json`` (a copy of ``ng-sast-agent/task_format/vocabulary.json``).

Third-party code is only fetched and exported (``git clone --filter=blob:none --no-checkout``,
``git fetch``, ``git archive``, ``git diff``); nothing from the repository is installed, built or
run. ``git archive`` runs with attribute overrides (no export-ignore, export-subst, filters or eol
conversion, so LFS pointers stay pointers) and the tar stream is unpacked by Python with path
checks; symlinks and names Windows cannot hold are skipped and listed in BUILD_TODO.md.

Refuses to touch an existing family unless ``--force`` (which keeps the family's opaque ids from
VARIANTS.json and rewrites everything else). Needs git; ``gh`` (authenticated) for the advisory
and licence (without it those fields stay TODO). Reads the workbook with openpyxl when installed,
else with a small stdlib reader.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import zipfile
from pathlib import Path, PurePosixPath
from xml.etree import ElementTree as ET

if os.name == "nt":
    import msvcrt
else:
    import fcntl

TOOLS = Path(__file__).resolve().parent
AGENT_ROOT = TOOLS.parent
ROOT = AGENT_ROOT.parent
TEMPLATES = AGENT_ROOT / "task_format" / "templates" / "v4"
DEFAULT_PLAN = ROOT / "planning" / "SAST_500_Plan.xlsx"
CACHE = ROOT / ".cache" / "repos"
#: The controlled vocabulary shipped with the tooling (a copy of tasks/vocabulary.json).
POC_VOCABULARY = AGENT_ROOT / "task_format" / "vocabulary.json"
SHEET = "Task slots"
BATCHES = "BATCHES.json"
BATCH_DIR = re.compile(r"batch-[a-z0-9]+(-[a-z0-9]+)*")
PENDING = ".scaffold-pending.json"
REPO_LOCK_TIMEOUT = 3 * 3600  # a first clone of a large repository can take a while
DATASET_LOCK_TIMEOUT = 600
COLUMNS = ["Slot", "Source", "Repo", "Language", "Kind", "App type", "Advisory", "Weakness", "Subtype(s)",
           "OWASP", "Linked", "Control", "Negative type", "Negative design", "Base commit", "Fix commit",
           "Excluded paths", "Archived", "Buildability", "Scanner difficulty", "Confidence", "Build notes"]

RULES = {
    "SID.HIGH": "LLM02.SID.HIGH", "SID.MEDIUM": "LLM02.SID.MEDIUM",
    "EA.FUNCTIONALITY": "LLM03.EA.FUNCTIONALITY", "EA.PERMISSIONS": "LLM03.EA.PERMISSIONS",
    "EA.AUTONOMY": "LLM03.EA.AUTONOMY",
}
RULE_NAMES = {
    "LLM02.SID.HIGH": ("SensitiveInformationDisclosureHigh", "Sensitive data can cross an authorisation or trust boundary"),
    "LLM02.SID.MEDIUM": ("SensitiveInformationDisclosureMedium", "Sensitive data reaches model-visible state without controls"),
    "LLM03.EA.FUNCTIONALITY": ("ExcessiveFunctionality", "A tool or tool operation does more than the task needs"),
    "LLM03.EA.PERMISSIONS": ("ExcessivePermissions", "A tool's credential or authorisation scope exceeds its operation"),
    "LLM03.EA.AUTONOMY": ("ExcessiveAutonomy", "A model decision triggers a high-impact action with no gate"),
}
# Labelling policy defaults (_poc/harbor-tasks/README.md, "Labelling policy"). Builders review them.
PARTIAL_CREDIT = {
    "LLM03.EA.FUNCTIONALITY": ["LLM03.EA.PERMISSIONS"],
    "LLM03.EA.PERMISSIONS": ["LLM03.EA.FUNCTIONALITY"],
    "LLM03.EA.AUTONOMY": ["LLM03.EA.FUNCTIONALITY", "LLM03.EA.PERMISSIONS"],
    "LLM02.SID.HIGH": ["LLM02.SID.MEDIUM"],
    "LLM02.SID.MEDIUM": ["LLM02.SID.HIGH"],
}
RECOMMENDATIONS = {
    "LLM03.EA.FUNCTIONALITY": (["REC-NARROW-TYPED-TOOLS", "REC-POLICY-GATE"], ["REC-LEAST-PRIVILEGE", "REC-COMPLETE-MEDIATION"]),
    "LLM03.EA.PERMISSIONS": (["REC-LEAST-PRIVILEGE", "REC-POLICY-GATE"], ["REC-USER-SECURITY-CONTEXT", "REC-COMPLETE-MEDIATION"]),
    "LLM03.EA.AUTONOMY": (["REC-ACTION-BOUND-APPROVAL", "REC-POLICY-GATE"], ["REC-COMPLETE-MEDIATION"]),
    "LLM02.SID.HIGH": (["REC-SINK-SIDE-IFC", "REC-SENSITIVE-DATA-FILTER", "REC-MINIMIZE-CONTEXT"], ["REC-POLICY-GATE"]),
    "LLM02.SID.MEDIUM": (["REC-SINK-SIDE-IFC", "REC-SENSITIVE-DATA-FILTER", "REC-MINIMIZE-CONTEXT"], ["REC-POLICY-GATE"]),
}
SCORING_WEIGHTS = {"detection": 0.35, "classification": 0.05, "path": 0.3, "controls": 0.15, "recommendations": 0.15}
TODO_FILE = "TODO/path/relative/to/environment/repo"
# Words kept out of family names: leak_scan bans them in task.toml (which carries the name) or
# they would say which twin is which.
NAME_BANNED = re.compile(r"cve|ghsa|vulnerab|exploit|patch|fixed|insecure|bypass|traversal|ssrf|injection|malicious"
                         r"|llm0\d|cwe|positive|negative|benign|^(pos|neg|vuln|fix|fixes|safe|unsafe|bad|good)$")
STOPWORDS = set("""a an the in on of to for from by with via and or but not no is are be can its it this that
these those when which while where who whom into onto over under than then so as at any all every each other
only also both same one two use uses using used allow allows allowing enables enabling lets let does do via
without within before after between through across per against""".split())
TEST_PATH = re.compile(r"(^|/)(tests?|__tests__|spec|specs|testdata|test_data|fixtures?/expected)(/|$)|(_test\.go|\.test\.[jt]sx?|\.spec\.[jt]sx?|Tests?\.(java|kt|cs))$|(^|/)test_[^/]*\.py$", re.I)
DOC_PATH = re.compile(r"(^|/)(docs?|website|changelog[^/]*|\.?changes[^/]*|\.?changeset[^/]*|news[^/]*)(/|$)|\.(md|rst|txt|adoc)$", re.I)


class ScaffoldError(Exception):
    pass


def warn(msg: str) -> None:
    print(f"warning: {msg}", file=sys.stderr)


# ---------------------------------------------------------------------------------------------
# Cross-process lock


class FileLock:
    """Exclusive lock on byte 0 of ``path`` (``msvcrt.locking`` / ``fcntl.flock``), polled until
    ``timeout``. The OS releases it when the holder exits or dies, so a crash leaves no stale lock.
    Not re-entrant; the lock file is never deleted (deleting it would race with a waiter)."""

    def __init__(self, path: Path, what: str, timeout: float):
        self.path, self.what, self.timeout = path, what, timeout
        self.fd: int | None = None

    def _try(self) -> bool:
        try:
            if os.name == "nt":
                os.lseek(self.fd, 0, os.SEEK_SET)
                msvcrt.locking(self.fd, msvcrt.LK_NBLCK, 1)
            else:
                fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return True
        except OSError:
            return False

    def __enter__(self) -> "FileLock":
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.fd = os.open(self.path, os.O_RDWR | os.O_CREAT, 0o644)
        deadline = time.monotonic() + self.timeout
        told = False
        while not self._try():
            if time.monotonic() > deadline:
                os.close(self.fd)
                self.fd = None
                raise ScaffoldError(f"timed out after {self.timeout:.0f}s waiting for the {self.what} lock {self.path}")
            if not told:
                print(f"waiting for the {self.what} lock ({self.path})", flush=True)
                told = True
            time.sleep(0.1 + secrets.randbelow(200) / 1000)
        return self

    def __exit__(self, *exc) -> None:
        if self.fd is None:
            return
        try:
            if os.name == "nt":
                os.lseek(self.fd, 0, os.SEEK_SET)
                msvcrt.locking(self.fd, msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(self.fd, fcntl.LOCK_UN)
        finally:
            os.close(self.fd)
            self.fd = None


def repo_lock(owner: str, name: str) -> FileLock:
    return FileLock(CACHE / f"{owner}__{name}.lock", f"repository cache {owner}/{name}", REPO_LOCK_TIMEOUT)


def dataset_lock(root: Path) -> FileLock:
    return FileLock(root / ".VARIANTS.json.lock", "dataset", DATASET_LOCK_TIMEOUT)


# ---------------------------------------------------------------------------------------------
# Dataset layout (batch folders)


def slot_batch(root: Path, slot: str, override: str | None) -> str:
    """Batch folder name for ``slot``: ``--batch`` if given, else the first of ``batches.*.slots``,
    ``batch-buffer.slots``, ``batch-extra.slots`` in ``<root>/BATCHES.json`` that lists it."""
    if override:
        if not BATCH_DIR.fullmatch(override):
            raise ScaffoldError(f"--batch {override!r} must be a batch folder name like batch-3 or batch-buffer")
        return override
    f = root / BATCHES
    if not f.is_file():
        raise ScaffoldError(f"{f} not found: pass --batch NAME, or --flat for a flat dataset")
    data = json.loads(f.read_text(encoding="utf-8"))
    groups = list((data.get("batches") or {}).items()) + [(k, data[k]) for k in ("batch-buffer", "batch-extra")
                                                         if isinstance(data.get(k), dict)]
    want = slot.strip().upper()
    for key, spec in groups:
        if want in {str(s).strip().upper() for s in (spec or {}).get("slots") or []}:
            if not BATCH_DIR.fullmatch(key):
                raise ScaffoldError(f"{f}: batch key {key!r} is not a usable folder name")
            return key
    raise ScaffoldError(f"slot {slot} is in no batch of {display(f)}; pass --batch NAME to place it")


def batch_dirs(root: Path) -> list[Path]:
    if not root.is_dir():
        return []
    return sorted(p for p in root.iterdir() if p.is_dir() and BATCH_DIR.fullmatch(p.name))


def display(p: Path) -> str:
    """``p`` relative to the repository root (POSIX separators) when inside it, else absolute."""
    p = p.resolve()
    try:
        return p.relative_to(ROOT.resolve()).as_posix()
    except ValueError:
        return p.as_posix()


def resolve_layout(arg: str, slot: str, flat: bool, batch: str | None) -> tuple[Path, Path, bool]:
    """Returns (dataset root holding VARIANTS.json, folder the family goes in, flat?)."""
    p = Path(arg)
    p = (p if p.is_absolute() else ROOT / p).resolve()
    if flat:
        if BATCH_DIR.fullmatch(p.name) or batch_dirs(p) or batch:
            raise ScaffoldError(f"--flat, but {p} is or holds batch folders (or --batch was given)")
        return p, p, True
    if BATCH_DIR.fullmatch(p.name) and not (p / "VARIANTS.json").is_file():
        want = slot_batch(p.parent, slot, batch)
        if p.name != want:
            raise ScaffoldError(f"slot {slot} belongs in {want}, not {p.name} (pass the dataset root to place it "
                                "automatically, or --batch to override)")
        return p.parent, p, False
    if (p.is_dir() and not (p / BATCHES).is_file() and not batch_dirs(p) and not batch
            and any((c / "task.toml").is_file() for c in p.iterdir() if c.is_dir())):
        print(f"{display(p)} is a flat dataset (task folders, no {BATCHES}, no batch-* folders): the family goes in it "
              "directly")
        return p, p, True
    return p, p / slot_batch(p, slot, batch), False


def containers(root: Path, flat: bool) -> list[Path]:
    """Every folder that can hold families: the flat dataset, or the root and all its batch folders."""
    return [root] if flat else [root] + batch_dirs(root)


def pending_ids(where: list[Path]) -> tuple[set[str], set[str]]:
    """Opaque ids reserved by scaffolds still in progress (``<family>/_work/.scaffold-pending.json``)."""
    tasks, fams = set(), set()
    for c in where:
        for f in c.glob(f"*/_work/{PENDING}"):
            try:
                d = json.loads(f.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            tasks.update(x for x in (d.get("pos_task"), d.get("neg_task")) if x)
            if d.get("family_id"):
                fams.add(d["family_id"])
    return tasks, fams


# ---------------------------------------------------------------------------------------------
# Plan workbook


def _xlsx_rows_stdlib(path: Path, sheet: str) -> list[list]:
    ns = {"m": "http://schemas.openxmlformats.org/spreadsheetml/2006/main",
          "r": "http://schemas.openxmlformats.org/officeDocument/2006/relationships"}
    with zipfile.ZipFile(path) as z:
        wb = ET.fromstring(z.read("xl/workbook.xml"))
        rid = next((s.get(f"{{{ns['r']}}}id") for s in wb.iter(f"{{{ns['m']}}}sheet") if s.get("name") == sheet), None)
        if rid is None:
            raise ScaffoldError(f"sheet {sheet!r} not found in {path}")
        rels = ET.fromstring(z.read("xl/_rels/workbook.xml.rels"))
        target = next(r.get("Target") for r in rels if r.get("Id") == rid)
        target = target.lstrip("/")
        target = target if target.startswith("xl/") else "xl/" + target
        shared: list[str] = []
        if "xl/sharedStrings.xml" in z.namelist():
            for si in ET.fromstring(z.read("xl/sharedStrings.xml")).iter(f"{{{ns['m']}}}si"):
                shared.append("".join(t.text or "" for t in si.iter(f"{{{ns['m']}}}t")))
        rows = []
        for row in ET.fromstring(z.read(target)).iter(f"{{{ns['m']}}}row"):
            out: list = []
            for c in row.iter(f"{{{ns['m']}}}c"):
                letters = re.match(r"[A-Z]+", c.get("r", "A")).group(0)
                col = 0
                for ch in letters:
                    col = col * 26 + ord(ch) - 64
                while len(out) < col - 1:
                    out.append(None)
                t, v = c.get("t"), c.find("m:v", ns)
                if t == "s" and v is not None:
                    val = shared[int(v.text)]
                elif t == "inlineStr":
                    val = "".join(x.text or "" for x in c.iter(f"{{{ns['m']}}}t"))
                else:
                    val = v.text if v is not None else None
                out.append(val)
            rows.append(out)
        return rows


def read_slot(plan: Path, slot: str) -> dict:
    if not plan.is_file():
        raise ScaffoldError(f"plan workbook not found: {plan}")
    try:
        import openpyxl  # noqa: PLC0415
    except ImportError:
        rows = _xlsx_rows_stdlib(plan, SHEET)
    else:
        wb = openpyxl.load_workbook(plan, read_only=True, data_only=True)
        if SHEET not in wb.sheetnames:
            raise ScaffoldError(f"sheet {SHEET!r} not found in {plan}")
        rows = [list(r) for r in wb[SHEET].iter_rows(values_only=True)]
    header = [str(c).strip() if c is not None else "" for c in rows[0]]
    missing = [c for c in COLUMNS if c not in header]
    if missing:
        raise ScaffoldError(f"plan sheet {SHEET!r} lacks columns {missing}")
    for r in rows[1:]:
        rec = {h: ("" if v is None else str(v).strip()) for h, v in zip(header, r) if h}
        if rec.get("Slot", "").upper() == slot.upper():
            return {c: rec.get(c, "") for c in COLUMNS}
    raise ScaffoldError(f"slot {slot} not found in {plan} sheet {SHEET!r}")


def slot_kind(row: dict) -> str:
    """``fix`` (A, or B with an upstream fix), ``designed`` (B designed control) or ``purpose_built`` (C)."""
    source, repo = row["Source"].lower(), row["Repo"].lower()
    if source.startswith("c") or repo in ("", "purpose-built", "purpose built"):
        return "purpose_built"
    if row["Fix commit"]:
        return "fix"
    if row["Base commit"]:
        return "designed"
    raise ScaffoldError(f"slot {row['Slot']}: source {row['Source']!r} has neither a fix nor a base commit")


def parse_repo(value: str) -> tuple[str, str]:
    v = re.sub(r"^(https?://)?(www\.)?github\.com/", "", value.strip()).removesuffix(".git").strip("/")
    parts = v.split("/")
    if len(parts) != 2 or not all(re.fullmatch(r"[A-Za-z0-9_.-]+", p) for p in parts):
        raise ScaffoldError(f"cannot read the repository {value!r} as owner/name")
    return parts[0], parts[1]


def rule_ids(row: dict) -> list[str]:
    out = []
    for part in re.split(r"[+,;/]| and ", row["Subtype(s)"]):
        key = part.strip().upper()
        if not key:
            continue
        key = key.removeprefix("LLM02.").removeprefix("LLM03.")
        if key not in RULES:
            raise ScaffoldError(f"slot {row['Slot']}: unknown subtype {part.strip()!r} in Subtype(s)")
        out.append(RULES[key])
    if not out:
        raise ScaffoldError(f"slot {row['Slot']}: Subtype(s) is empty")
    # Excessive agency first: a linked pair reads "the action (F1) exposes the data (F2)".
    return sorted(dict.fromkeys(out), key=lambda r: (not r.startswith("LLM03"), r))


def excluded_from_plan(value: str) -> list[str]:
    out = []
    # Split on ';' / newline only outside parentheses, so a note such as
    # "src/*/ (monorepo; scan only the named server)" stays one entry.
    parts, buf, depth = [], [], 0
    for ch in value or "":
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth = max(0, depth - 1)
        if ch in ";\n" and depth == 0:
            parts.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
    parts.append("".join(buf))
    for part in parts:
        p = re.sub(r"\s*\(.*?\)\s*$", "", part.strip()).strip()
        p = p.strip("`'\" ").rstrip("/")
        if p and p.lower() not in ("none", "n/a", "-"):
            out.append(p)
    return list(dict.fromkeys(out))


def load_languages() -> dict:
    return json.loads((TEMPLATES / "languages.json").read_text(encoding="utf-8"))


def language_of(row: dict, languages: dict) -> tuple[str, dict]:
    first = re.split(r"[;,]", row["Language"])[0].strip()
    for key, spec in languages.items():
        if key.startswith("_"):
            continue
        if any(first.lower() == p.lower() for p in spec["plan"]):
            return key, spec
    raise ScaffoldError(f"slot {row['Slot']}: no language template for {row['Language']!r} "
                        f"(add it to {TEMPLATES / 'languages.json'})")


# ---------------------------------------------------------------------------------------------
# Names and ids


def kebab(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")


def derive_family_name(row: dict, taken: set[str]) -> str:
    if slot_kind(row) == "purpose_built":
        prefix = "pb"
    else:
        prefix = kebab(parse_repo(row["Repo"])[1])
        prefix = "-".join(prefix.split("-")[:2])[:20].strip("-") or "repo"
    words = []
    for w in re.findall(r"[A-Za-z][A-Za-z0-9]*", row["Weakness"]):
        lw = w.lower()
        if lw in STOPWORDS or len(lw) < 3 or len(lw) > 16 or NAME_BANNED.search(lw) or lw in prefix.split("-"):
            continue
        if lw not in words:
            words.append(lw)
        if len(words) == 2:
            break
    base = "-".join([prefix] + words) if words else f"{prefix}-{row['Slot'].lower()}"
    name, n = base, 2
    while name in taken:
        name, n = f"{base}-{n}", n + 1
    return name


def check_family_name(name: str) -> None:
    if not re.fullmatch(r"[a-z0-9]+(-[a-z0-9]+)*", name):
        raise ScaffoldError(f"family name {name!r} must be kebab-case (a-z, 0-9, single hyphens)")
    if name == "batch" or name.startswith("batch-"):
        raise ScaffoldError(f"family name {name!r} would look like a batch folder")
    for part in name.split("-"):
        if NAME_BANNED.search(part):
            raise ScaffoldError(f"family name {name!r} contains {part!r}, a word leak_scan bans in task.toml or "
                                "that names a role")


def unique_hex(nbytes: int, prefix: str, taken: set[str]) -> str:
    while True:
        value = prefix + secrets.token_hex(nbytes)
        if value not in taken:
            return value


# ---------------------------------------------------------------------------------------------
# Git (fetch, archive and diff only; nothing from the repository is executed)


def git_env() -> dict:
    env = dict(os.environ)
    env.update({"GIT_TERMINAL_PROMPT": "0", "GIT_LFS_SKIP_SMUDGE": "1", "GIT_CONFIG_NOSYSTEM": "1"})
    return env


GIT_SAFE = ["-c", "core.autocrlf=false", "-c", "core.eol=lf", "-c", "core.quotePath=false",
            "-c", f"core.hooksPath={os.devnull}", "-c", "core.symlinks=false", "-c", "protocol.file.allow=never",
            "-c", "diff.external=", "-c", "advice.detachedHead=false"]


def git(repo: Path | None, *args: str, input_text: str | None = None, check: bool = True,
        no_lazy: bool = False, binary: bool = False):
    cmd = ["git"] + GIT_SAFE + (["-C", str(repo)] if repo else []) + list(args)
    env = git_env()
    if no_lazy:
        env["GIT_NO_LAZY_FETCH"] = "1"
    proc = subprocess.run(cmd, input=input_text.encode() if input_text is not None else None,
                          capture_output=True, env=env)
    if check and proc.returncode != 0:
        raise ScaffoldError(f"git {' '.join(args[:3])} failed: {proc.stderr.decode(errors='replace').strip()[-800:]}")
    if binary:
        return proc
    proc.stdout = proc.stdout.decode("utf-8", errors="replace")
    proc.stderr = proc.stderr.decode("utf-8", errors="replace")
    return proc


def has_commit(repo: Path, sha: str) -> bool:
    return git(repo, "cat-file", "-e", f"{sha}^{{commit}}", check=False, no_lazy=True).returncode == 0


def ensure_repo(owner: str, name: str, commits: list[str]) -> Path:
    """Clone (once) and fetch into the cache. The caller holds ``repo_lock(owner, name)``."""
    repo = CACHE / f"{owner}__{name}"
    # ``<repo>.cloning`` exists while a clone runs; if it is still there, that clone was interrupted.
    # (A marker, not clone-then-rename: Windows often refuses to rename a freshly cloned folder.)
    marker = CACHE / f"{owner}__{name}.cloning"
    if marker.exists() or not (repo / ".git").is_dir():
        CACHE.mkdir(parents=True, exist_ok=True)
        marker.touch()
        rmtree(repo)  # debris of an interrupted clone
        print(f"cloning {owner}/{name} into {repo} (blob:none, no checkout)")
        git(None, "clone", "--filter=blob:none", "--no-checkout", "--quiet",
            f"https://github.com/{owner}/{name}.git", str(repo))
        marker.unlink()
    # Attribute overrides for git archive: keep every file (no export-ignore), no export-subst,
    # no clean/smudge filters (LFS pointers stay pointers), no eol conversion.
    info = repo / ".git" / "info"
    info.mkdir(parents=True, exist_ok=True)
    (info / "attributes").write_text("* -export-ignore -export-subst -filter -text -ident -working-tree-encoding\n",
                                     encoding="utf-8", newline="\n")
    for sha in commits:
        if not has_commit(repo, sha):
            print(f"fetching {sha[:12]} from {owner}/{name}")
            git(repo, "fetch", "--quiet", "--filter=blob:none", "--no-tags", "origin", sha, check=False)
            if not has_commit(repo, sha):
                raise ScaffoldError(f"commit {sha} is not in https://github.com/{owner}/{name} (or not fetchable)")
    return repo


def full_sha(repo: Path, rev: str) -> str:
    return git(repo, "rev-parse", "--verify", f"{rev}^{{commit}}").stdout.strip()


def prefetch_blobs(repo: Path, commit: str) -> list[str]:
    """Fetch every missing blob of ``commit``'s tree in one request. Returns the submodule paths."""
    tree = git(repo, "ls-tree", "-r", "-z", "--full-tree", commit).stdout
    blobs, submodules = [], []
    for entry in filter(None, tree.split("\0")):
        meta, path = entry.split("\t", 1)
        mode, kind, oid = meta.split()
        if kind == "blob":
            blobs.append(oid)
        elif kind == "commit":
            submodules.append(path)
    if blobs:
        check = git(repo, "cat-file", "--batch-check", input_text="\n".join(blobs) + "\n", no_lazy=True, check=False)
        missing = [ln.split()[0] for ln in check.stdout.splitlines() if ln.endswith(" missing")]
        if missing:
            git(repo, "-c", "fetch.negotiationAlgorithm=noop", "fetch", "--quiet", "origin", "--no-tags",
                "--no-write-fetch-head", "--recurse-submodules=no", "--filter=blob:none", "--stdin",
                input_text="\n".join(missing) + "\n")
    return submodules


def _safe_target(dest: Path, name: str) -> Path | None:
    p = PurePosixPath(name)
    if p.is_absolute() or ".." in p.parts or not p.parts:
        return None
    return dest.joinpath(*p.parts)


def export_tree(repo: Path, commit: str, dest: Path) -> list[str]:
    """``git archive`` of ``commit`` unpacked into ``dest``. Returns notes on entries that were skipped."""
    submodules = prefetch_blobs(repo, commit)
    dest.mkdir(parents=True, exist_ok=True)
    cmd = ["git"] + GIT_SAFE + ["-C", str(repo), "archive", "--format=tar", commit]
    errfile = tempfile.TemporaryFile()
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=errfile, env=git_env())
    notes = [f"submodule (not exported): {s}" for s in submodules]
    seen: dict[str, str] = {}
    try:
        _unpack(proc.stdout, dest, notes, seen)
    finally:
        proc.stdout.read()  # drain the tar padding after the end-of-archive marker, or git blocks
        proc.stdout.close()
        code = proc.wait()
    errfile.seek(0)
    err = errfile.read().decode(errors="replace")
    errfile.close()
    if code != 0:
        raise ScaffoldError(f"git archive {commit[:12]} failed: {err.strip()[-500:]}")
    return notes


def _unpack(stream, dest: Path, notes: list[str], seen: dict[str, str]) -> None:
    with tarfile.open(fileobj=stream, mode="r|") as tf:
        for m in tf:
            if m.name in ("pax_global_header",) or m.type == tarfile.XGLTYPE:
                continue
            target = _safe_target(dest, m.name)
            if target is None:
                notes.append(f"unsafe path skipped: {m.name}")
                continue
            if m.issym() or m.islnk():
                notes.append(f"link skipped: {m.name} -> {m.linkname}")
                continue
            low = m.name.rstrip("/").lower()
            if m.isfile() and low in seen and seen[low] != m.name:
                notes.append(f"case collision on Windows, kept the first: {seen[low]} / {m.name}")
                continue
            seen[low] = m.name
            try:
                if m.isdir():
                    target.mkdir(parents=True, exist_ok=True)
                elif m.isfile():
                    target.parent.mkdir(parents=True, exist_ok=True)
                    src = tf.extractfile(m)
                    with open(target, "wb") as out:
                        shutil.copyfileobj(src, out)
                else:
                    notes.append(f"special entry skipped: {m.name}")
            except OSError as exc:
                notes.append(f"cannot write on this file system, skipped: {m.name} ({exc.strerror or exc})")


HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


def diff_hunks(repo: Path, old: str, new: str) -> dict[str, dict]:
    """Per changed file: status and the changed line ranges on each side (zero context, merged when close)."""
    out = git(repo, "diff", "-U0", "--no-color", "--no-ext-diff", "--no-textconv", "-M", old, new).stdout
    files: dict[str, dict] = {}
    cur = None
    old_path = None
    for line in out.splitlines():
        if line.startswith("diff --git "):
            cur, old_path = None, None
        elif line.startswith("--- "):
            old_path = None if line[4:] == "/dev/null" else line[6:].rstrip("	")
        elif line.startswith("+++ "):
            new_path = None if line[4:] == "/dev/null" else line[6:].rstrip("	")
            path = new_path or old_path
            cur = files.setdefault(path, {"old_path": old_path, "new_path": new_path, "old": [], "new": []})
        elif cur is not None and (m := HUNK.match(line)):
            a, b = int(m.group(1)), int(m.group(2) or 1)
            c, d = int(m.group(3)), int(m.group(4) or 1)
            if b > 0:
                cur["old"].append([a, a + b - 1])
            elif a > 0:
                cur["old"].append([a, a])  # pure insertion after old line a
            if d > 0:
                cur["new"].append([c, c + d - 1])
            elif c > 0:
                cur["new"].append([c, c])  # pure deletion after new line c
    for f in files.values():
        for side in ("old", "new"):
            merged: list[list[int]] = []
            for r in sorted(f[side]):
                if merged and r[0] <= merged[-1][1] + 3:
                    merged[-1][1] = max(merged[-1][1], r[1])
                else:
                    merged.append(list(r))
            f[side] = merged
    return files


# ---------------------------------------------------------------------------------------------
# GitHub metadata (data only)


def gh_json(endpoint: str) -> dict | None:
    if shutil.which("gh") is None:
        return None
    proc = subprocess.run(["gh", "api", endpoint], capture_output=True)
    if proc.returncode != 0:
        return None
    try:
        return json.loads(proc.stdout.decode("utf-8", errors="replace"))
    except ValueError:
        return None


def fetch_advisory(advisory: str, owner: str | None, name: str | None) -> dict:
    info: dict = {"id": advisory or None}
    if not advisory:
        return info
    m = re.search(r"GHSA(-[23456789cfghjmpqrvwx]{4}){3}", advisory, re.I)
    cve = re.search(r"CVE-\d{4}-\d{4,}", advisory, re.I)
    if cve:
        info["cve"] = cve.group(0).upper()
    if not m:
        info["url"] = advisory if advisory.startswith("http") else None
        return info
    ghsa = m.group(0)
    info["id"] = ghsa
    data = gh_json(f"advisories/{ghsa}")
    origin = "global"
    if data is None and owner:
        data = gh_json(f"repos/{owner}/{name}/security-advisories/{ghsa}")
        origin = "repository"
    info["url"] = f"https://github.com/advisories/{ghsa}" if origin == "global" else \
        f"https://github.com/{owner}/{name}/security/advisories/{ghsa}"
    if data is None:
        info["fetch_error"] = "gh api returned nothing (not found, gh missing or not authenticated)"
        return info
    info["source"] = f"gh api ({origin} advisory)"
    info["url"] = data.get("html_url") or info["url"]
    for key in ("summary", "description", "severity", "published_at", "updated_at", "withdrawn_at"):
        info[key] = data.get(key)
    info["cve"] = data.get("cve_id") or info.get("cve")
    info["cwes"] = [c.get("cwe_id") for c in data.get("cwes") or [] if c.get("cwe_id")]
    vulns = []
    for v in data.get("vulnerabilities") or []:
        pkg = v.get("package") or {}
        patched = v.get("first_patched_version") or v.get("patched_versions")
        if isinstance(patched, dict):
            patched = patched.get("identifier")
        vulns.append({"package": pkg.get("name"), "ecosystem": pkg.get("ecosystem"),
                      "vulnerable_version_range": v.get("vulnerable_version_range"), "patched": patched})
    info["vulnerabilities"] = vulns
    return info


def fetch_license(owner: str, name: str) -> str | None:
    data = gh_json(f"repos/{owner}/{name}/license")
    spdx = ((data or {}).get("license") or {}).get("spdx_id")
    return spdx if spdx and spdx != "NOASSERTION" else None


def commit_meta(repo: Path, sha: str) -> dict:
    out = git(repo, "log", "-1", "--format=%H%x00%P%x00%cI%x00%an%x00%s", sha).stdout.rstrip("\n").split("\0")
    return {"sha": out[0], "parents": out[1].split(), "date": out[2], "author": out[3], "subject": out[4]}


# ---------------------------------------------------------------------------------------------
# File helpers


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)


def write_json(path: Path, data, indent: int = 2) -> None:
    write_text(path, json.dumps(data, indent=indent, ensure_ascii=False) + "\n")


def write_json_atomic(path: Path, data, indent: int = 2) -> None:
    """Temp file in the same folder, fsync, ``os.replace``: readers see the old or the new file, never half."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(json.dumps(data, indent=indent, ensure_ascii=False) + "\n")
            fh.flush()
            os.fsync(fh.fileno())
        for attempt in range(50):
            try:
                os.replace(tmp, path)
                break
            except PermissionError:  # Windows: a reader has the target open; retry briefly
                if attempt == 49:
                    raise
                time.sleep(0.1)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


SCOPE_PREFIX = "Only these paths under `/app/repo` are in scope: "
SCOPE_TAIL = " The repository may contain"


def scope_sentence(roots: list[str], excluded: list[str]) -> str:
    """The instruction's scope sentence, worded exactly as tools/qc_pair_v4.sh expects it."""
    q = lambda xs: ", ".join(f"`{x}`" for x in xs)
    text = f"{SCOPE_PREFIX}{q(roots)}."
    if excluded:
        text += f" Inside them, {q(excluded)} {'is' if len(excluded) == 1 else 'are'} out of scope."
    return text


def render_instruction(template: str, roots: list[str], excluded: list[str]) -> str:
    """The v4 instruction.md template with only its scope sentence set to these roots and exclusions.

    Everything else stays byte-identical (QC compares it with the template outside that sentence);
    the template's own sentence names the pilot's Python roots, so it comes out unchanged for a
    Python slot with the default roots and no plan exclusions."""
    lines = template.split("\n")
    hits = [i for i, ln in enumerate(lines) if ln.startswith(SCOPE_PREFIX)]
    if len(hits) != 1 or SCOPE_TAIL not in lines[hits[0]]:
        raise ScaffoldError("instruction.md template: expected one scope line starting "
                            f"{SCOPE_PREFIX!r} and containing {SCOPE_TAIL!r}")
    line = lines[hits[0]]
    lines[hits[0]] = scope_sentence(roots, excluded) + line[line.index(SCOPE_TAIL):]
    return "\n".join(lines)


def fill(template: str, values: dict) -> str:
    for k, v in values.items():
        template = template.replace(f"@@{k}@@", v)
    left = re.findall(r"@@[A-Z_]+@@", template)
    if left:
        raise ScaffoldError(f"template placeholders left unfilled: {sorted(set(left))}")
    return template


def toml_str(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)[1:-1]


def toml_list(values: list[str]) -> str:
    return "[" + ", ".join(json.dumps(v, ensure_ascii=False) for v in values) + "]"


def rmtree(path: Path) -> None:
    def onerror(func, p, _exc):
        os.chmod(p, stat.S_IWRITE)
        func(p)
    if path.exists():
        shutil.rmtree(path, onexc=onerror) if sys.version_info >= (3, 12) else shutil.rmtree(path, onerror=onerror)


# ---------------------------------------------------------------------------------------------
# Ground truth, oracle and provenance skeletons


def loc(file: str = TODO_FILE, start: int = 1, end: int | None = None, **extra) -> dict:
    out = {"file": file, "start_line": start, "end_line": end if end is not None else start}
    out.update(extra)
    return out


def source_hunks(hunks: dict[str, dict]) -> list[tuple[str, dict]]:
    return [(p, h) for p, h in hunks.items() if not TEST_PATH.search(p) and not DOC_PATH.search(p)]


def build_findings(rules: list[str], row: dict, ctx: dict) -> list[dict]:
    partial = row["Control"].lower().startswith("partial")
    linked = row["Linked"].lower().startswith("y") and len(rules) > 1
    hints = ctx["hunk_hints"]
    findings = []
    ids = [f"F{i + 1}" for i in range(len(rules))]
    for i, rule in enumerate(rules):
        sid = rule.startswith("LLM02")
        # Hint only: the largest changed range of the fix on the positive side. Every hunk is listed
        # in BUILD_TODO.md; builders add the ones where a fix closes the path as alternatives.
        biggest = max(hints, key=lambda h: h["old"][1] - h["old"][0]) if hints else None
        primary = loc(biggest["file"], *biggest["old"]) if biggest else loc()
        alts: list[dict] = []
        if sid:
            path = [
                {"step": 1, "role": "source", "required": True, **loc(), "note": "TODO(builder): where the protected data originates"},
                {"step": 2, "role": "context_assembly", "required": False, **loc(), "note": "TODO(builder) or delete"},
                {"step": 3, "role": "model_consumption", "required": False, **loc(), "note": "TODO(builder) or delete"},
                {"step": 4, "role": "sink", "required": True, **loc(), "note": "TODO(builder): where the data reaches the unauthorised recipient or channel",
                 "egress": {"kind": "TODO external|internal", "boundary": "tb-TODO"}},
            ]
        else:
            path = [
                {"step": 1, "role": "model_decision", "required": True, **loc(), "note": "TODO(builder): where the model's decision or tool arguments enter"},
                {"step": 2, "role": "root_cause", "required": True, **loc(), "note": "TODO(builder): the missing or incomplete check"},
                {"step": 3, "role": "sink", "required": True, **loc(), "note": "TODO(builder): the consequential action",
                 "egress": {"kind": "TODO external|internal", "boundary": "tb-TODO"}},
            ]
        if partial:
            path.insert(len(path) - 1, {"step": 0, "role": "control_point", "required": False, **loc(),
                                        "note": "TODO(builder): the partial control on the path"})
        for n, step in enumerate(path, 1):
            step["step"] = n
        control = ({"name": "TODO_control_name", "status": "partial", "at": loc(), "note": "TODO(builder): what the control covers and what it misses"}
                   if partial else
                   {"name": "TODO_control_name", "status": "absent", "expected_at": loc()})
        required, acceptable = RECOMMENDATIONS[rule]
        residual = "high"
        f = {
            "id": ids[i],
            "is_vulnerable": True,
            "risk_type": "sensitive_information_disclosure" if sid else "excessive_agency",
            "owasp_id": "LLM02:2026" if sid else "LLM03:2026",
            "rule_id": rule,
            "acceptable_rule_ids": [rule],
            "partial_credit_rule_ids": list(PARTIAL_CREDIT[rule]),
            "severity": ("medium" if rule.endswith("MEDIUM") else "high") if sid else residual,
            "primary_cwe": ctx["cwes"][0] if ctx["cwes"] else "CWE-TODO",
            "acceptable_cwes": list(ctx["cwes"]) or ["CWE-TODO"],
            "primary_location": primary,
            "alternative_primary_locations": alts,
        }
        if linked:
            others = [ids[j] for j, r in enumerate(rules) if j != i and r[:5] != rule[:5]]
            if others:
                f["linked_finding_ids"] = others
                f["link_relation"] = "ea_exposes_sid"
        f.update({
            "path": path,
            "controls": [control],
            "control_status": "partial" if partial else "none",
            "residual_risk": residual,
            "recommendations": {"required_any_of": list(required), "acceptable": list(acceptable),
                                "complete_remediation": "TODO(builder)"},
            "rationale": "TODO(builder): why this is a finding under spec 2.3 and the manifest, and why this subtype",
            "affected_asset": {"fixture_ids": ["fx_TODO"], "data_class": "TODO", "classification": "TODO",
                               "canary_ids": ["CNRY-TODO"]},
        })
        if not sid:
            f["consequence"] = "TODO(builder): one sentence of the rationale"
        f["violates"] = [{"manifest_path": "TODO", "summary": "TODO(builder)"}]
        f["evidence"] = {
            "advisory": ctx["advisory"].get("url"),
            "cve": ctx["advisory"].get("cve"),
            "upstream_fix_commit": ctx.get("fix_commit"),
            "upstream_fix_summary": "TODO(builder)" if ctx.get("fix_commit") else None,
            "repro_test": "validation/repro_test.py::ReproPositive::test_TODO",
            "canary_id": "CNRY-TODO",
            "trigger": "TODO(builder)",
        }
        if ctx["kind"] == "designed":
            f["evidence"]["design"] = row["Negative design"] or None
        findings.append(f)
    return findings


def matching(scanner_roots: list[str], excluded: list[str]) -> dict:
    return {"line_tolerance": 10, "path_line_tolerance": 10, "require_cwe": False,
            "scanner_roots": scanner_roots, "excluded_paths": excluded}


def ground_truths(rules: list[str], row: dict, ctx: dict) -> tuple[dict, dict]:
    fam = ctx["family"]
    a, b = f"{fam}-a", f"{fam}-b"
    pos_var, neg_var = ctx["pos_var"], ctx["neg_var"]
    fam_id = ctx["family_id"]
    findings = build_findings(rules, row, ctx)
    risk_types = sorted({f["risk_type"] for f in findings})
    fixed = ctx["fixed_locations"] or [loc(why="TODO(builder): what the negative changes here")]
    first_fixed = fixed[0]
    todo_common = [
        "Every TODO marker and this _todo list must be gone before QC (qc_pair_v4.sh fails on them).",
        "Paths are relative to environment/repo. Prefilled paths and lines come from the upstream fix diff "
        "(upstream repository layout): remap them if the trimmed repo moves files, and keep upstream line numbers "
        "in the fix files where you can.",
        "partial_credit_rule_ids, recommendations and severity are the labelling-policy defaults "
        "(_poc/harbor-tasks/README.md, 'Labelling policy'); review them.",
        f"Run tools/snippet_ids.py {ctx['dir_display']} --task {a} --task {b} (from ng-sast-agent, dataset path "
        "relative to the repository root) after the lines are final, then check_truth.",
    ]
    pos = {
        "schema_version": "gt-0.2",
        "_todo": todo_common + [
            "Primary location prefilled with the largest changed range of the fix on the positive side (a hint, often "
            "not the root cause). Every fix hunk is listed in _work/BUILD_TODO.md: add those where a fix also closes "
            "the path to alternative_primary_locations (with a 'why').",
            "Add a hard_negative_trap entry to negative_analyses for each safe lookalike in this twin, if any.",
        ],
        "task_id": a,
        "family_id": fam_id,
        "variant_id": pos_var,
        "variant_role": "positive",
        "risk_types_present": risk_types,
        "matching": matching(ctx["scanner_roots"], ctx["excluded_paths"]),
        "fix_changed_files": ctx["fix_changed_files"] or [TODO_FILE],
        "findings": findings,
        "negative_analyses": [{
            "id": "N1", "kind": "minimal_contrast", "contrast_of": "F1", "contrast_task_id": b,
            "contrast_location": {"task_id": b, "file": first_fixed["file"],
                                  "lines": f"{first_fixed['start_line']}-{first_fixed['end_line']}"},
            **{k: v for k, v in findings[0]["primary_location"].items()},
            "rationale": "TODO(builder): what the twin changes and why the same trigger is refused there",
        }],
        "scoring_weights": dict(SCORING_WEIGHTS),
    }
    contrast_note = {
        "fix applied": "the upstream fix (or designed control) closes the path",
    }.get(row["Negative type"].lower(), f"negative type from the plan: {row['Negative type']}")
    neg = {
        "schema_version": "gt-0.2",
        "_todo": todo_common + [
            "fixed_locations prefilled from the fix diff (new side, one per hunk); give each a 'why'.",
            f"Negative type: {row['Negative type'] or 'TODO'} ({contrast_note}). controls[0].at must be one of fixed_locations.",
            "N2 is a hard_negative_trap template: point it at a safe lookalike a scanner would wrongly flag, or delete it.",
        ],
        "task_id": b,
        "family_id": fam_id,
        "variant_id": neg_var,
        "variant_role": "negative",
        "risk_types_present": [],
        "matching": matching(ctx["scanner_roots"], ctx["excluded_paths"]),
        "contrast_rule_ids": list(rules),
        "fixed_locations": fixed,
        "fix_changed_files": ctx["fix_changed_files"] or [TODO_FILE],
        "findings": [],
        "negative_analyses": [
            {"id": "N1", "kind": "minimal_contrast", "contrast_of": "F1",
             **{k: first_fixed[k] for k in ("file", "start_line", "end_line")},
             "rationale": "TODO(builder): the same model decision or data flow, and the control that stops it"},
            {"id": "N2", "kind": "hard_negative_trap", **loc(),
             "trap_rule_prefixes": sorted({r.split(".")[0] for r in rules}),
             "trap_rule_ids": list(rules),
             "why_not_a_finding": "TODO(builder) or delete this entry"},
        ],
        "controls": [{"name": "TODO_control_name", "status": "complete",
                      "at": {k: first_fixed[k] for k in ("file", "start_line", "end_line")},
                      "contrast_of": "F1", "note": "TODO(builder): how the control closes the path"}],
        "control_status": "complete",
        "residual_risk": "low",
        "evidence": {
            "advisory": ctx["advisory"].get("url"),
            "cve": ctx["advisory"].get("cve"),
            "upstream_fix_commit": ctx.get("fix_commit"),
            "upstream_fix_summary": "TODO(builder)" if ctx.get("fix_commit") else None,
        },
        "scoring_weights": dict(SCORING_WEIGHTS),
    }
    if ctx["kind"] == "designed":
        neg["evidence"]["design"] = row["Negative design"] or None
    return pos, neg


def tfl(location: dict, role: str, note: str) -> dict:
    return {"location": {"physicalLocation": {"artifactLocation": {"uri": location["file"]},
                                              "region": {"startLine": location["start_line"],
                                                         "endLine": location["end_line"]}},
                         "message": {"text": note}},
            "properties": {"role": role}}


def oracle(truth: dict, rules: list[str]) -> dict:
    driver_rules = [{"id": r, "name": RULE_NAMES[r][0], "shortDescription": {"text": RULE_NAMES[r][1]},
                     "properties": {"owasp": r.split(".")[0] + ":2026", "tags": ["security", "genai"]}} for r in rules]
    results = []
    if truth["findings"]:
        for f in truth["findings"]:
            p = f["primary_location"]
            results.append({
                "ruleId": f["rule_id"], "level": "error",
                "message": {"text": "TODO(builder): one or two sentences (tools/label_rules/sync_oracle.py rebuilds the flow)"},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": p["file"]},
                                                    "region": {"startLine": p["start_line"], "endLine": p["end_line"]}}}],
                "codeFlows": [{"threadFlows": [{"locations": [tfl(s, s["role"], s["note"]) for s in f["path"]]}]}],
                "properties": {"findingId": f["id"], "cwe": [f["primary_cwe"]], "controlStatus": f["control_status"],
                               "residualRisk": f["residual_risk"],
                               "recommendations": [f["recommendations"]["required_any_of"][0]]},
            })
    else:
        for c in truth["controls"]:
            at = c["at"]
            results.append({
                "ruleId": truth["contrast_rule_ids"][0], "level": "note",
                "message": {"text": "TODO(builder): the complete control and why it closes the path"},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": at["file"]},
                                                    "region": {"startLine": at["start_line"], "endLine": at["end_line"]}}}],
                "properties": {"controlStatus": "complete", "residualRisk": truth["residual_risk"], "control": c["name"],
                               "cwe": [], "recommendations": []},
            })
    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "oracle", "version": "gt-0.2", "rules": driver_rules}},
                      "results": results}]}


def provenance(row: dict, ctx: dict, role: str) -> dict:
    fam = ctx["family"]
    me, twin = (f"{fam}-a", f"{fam}-b") if role == "positive" else (f"{fam}-b", f"{fam}-a")
    var = ctx["pos_var"] if role == "positive" else ctx["neg_var"]
    other = ctx["neg_var"] if role == "positive" else ctx["pos_var"]
    kind = ctx["kind"]
    if kind == "purpose_built":
        code_state = "purpose_built"
    elif role == "positive":
        code_state = "source_commit"
    else:
        code_state = "upstream_fix_applied" if kind == "fix" else "designed_control"
    adv = ctx["advisory"]
    fixed_versions = sorted({v["patched"] for v in adv.get("vulnerabilities") or [] if v.get("patched")})
    return {
        "task_id": me,
        "source_origin": ctx["source_origin"],
        "source_url": ctx.get("source_url"),
        "source_commit": ctx.get("source_commit"),
        "fix_commit": ctx.get("fix_commit"),
        "advisory": adv.get("id"),
        "advisory_url": adv.get("url"),
        "cve": adv.get("cve"),
        "fixed_version": ", ".join(fixed_versions) or None,
        "license": ctx.get("license") or "TODO(builder)",
        "modifications": "TODO(builder): what was extracted, trimmed, stubbed (stand-ins in _compat/) or added, "
                         "and that every other line is upstream.",
        "upstream_files": [{"upstream_path": "TODO", "local_path": "TODO", "kept": "verbatim|adapted"}]
        if kind != "purpose_built" else [],
        "lineage": {
            "repository_id": ctx["repository_id"], "family_id": ctx["family_id"], "variant_id": var,
            "variant_role": role, "related_variant_ids": [f"{ctx['family_id']}:{other}"], "twin_task_id": twin,
            "code_state": code_state,
        },
        "authoring": {"author": "Turing", "created": ctx["date"], "plan_slot": row["Slot"],
                      **({"delivery_id": ctx["delivery_id"]} if ctx.get("delivery_id") else {}),
                      "scaffolded_by": "ng-sast-agent/tools/scaffold_pair.py"},
        "review": {
            "annotator_labels": [],
            "adjudication": None,
            "agreement": {"n_labels": 0, "agree": 0, "rate": None},
            "_how_to_fill": "Each QC reviewer appends {\"reviewer\": name, \"date\": \"YYYY-MM-DD\", \"label\": \"agree\" "
                            "or \"disagree\", \"rule_id\": ..., \"primary_location_ok\": true/false, \"notes\": \"...\"}. "
                            "When labels differ, record the final decision and who made it in adjudication.",
        },
        "qc": {},
        "beyond_upstream_fix": ["TODO(builder): every change beyond the upstream fix, or 'None'"],
        "package_versions": {"task_toml": {}, "this_variant": {},
                             "note": "TODO(builder): task.toml lists the release of the source commit in both twins; "
                                     "this_variant is the release this twin's code matches."},
    }


# ---------------------------------------------------------------------------------------------
# BUILD_TODO.md


def build_todo(row: dict, ctx: dict) -> str:
    fam = ctx["family"]
    kind = ctx["kind"]
    ds = ctx["dir_display"]
    L: list[str] = []
    add = L.append
    add(f"# Build checklist: {fam} (slot {row['Slot']})")
    add("")
    add(f"Generated by `ng-sast-agent/tools/scaffold_pair.py` on {ctx['date']}. Evaluator-only workbench: nothing under `{ds}/{fam}/_work/` ships with the tasks.")
    add("")
    add(f"Folders: `{ds}/{fam}-a/`, `{ds}/{fam}-b/`, `{ds}/{fam}/_work/`; twin map `{ctx['root_display']}/VARIANTS.json`.")
    add("")
    add("## Slot")
    add("")
    add("| Field | Value |")
    add("|---|---|")
    for col in COLUMNS:
        val = (row.get(col) or "").replace("|", "\\|").replace("\n", " ")
        add(f"| {col} | {val} |")
    add("")
    add("## Pair")
    add("")
    add(f"- Positive `{fam}-a` ({ctx['pos_var']}, `{ctx['pos_task_id']}`), negative `{fam}-b` ({ctx['neg_var']}, `{ctx['neg_task_id']}`), family `{ctx['family_id']}`, repository `{ctx['repository_id']}`.")
    add(f"- Planned findings: {', '.join(f'`{r}`' for r in ctx['rules'])}; linked: {row['Linked'] or 'no'}; control on the positive: {row['Control'] or 'TODO'}.")
    add(f"- Negative type: {row['Negative type'] or 'TODO'}.")
    if row["Negative design"]:
        add(f"- Negative design: {row['Negative design']}")
    add(f"- Language template: `{ctx['language']}` (`environment/Dockerfile` from `task_format/templates/v4/dockerfiles/{ctx['lang_spec']['dockerfile']}`).")
    if ctx["advisory"].get("id"):
        adv = ctx["advisory"]
        add(f"- Advisory: [{adv.get('id')}]({adv.get('url')}) {adv.get('cve') or ''} {('CWEs ' + ', '.join(adv.get('cwes') or [])) if adv.get('cwes') else ''}".rstrip())
        if adv.get("fetch_error"):
            add(f"- Advisory fetch: {adv['fetch_error']}")
    if ctx.get("license"):
        add(f"- Licence (GitHub API): {ctx['license']}")
    add("")
    if kind == "fix":
        add("## Upstream trees")
        add("")
        add(f"- `_work/upstream-positive/` = `{ctx['source_commit']}` (parent of the fix). Plan Base commit: `{row['Base commit'] or '-'}`.{' MISMATCH, see warnings.' if ctx['base_mismatch'] else ''}")
        add(f"- `_work/upstream-negative/` = `{ctx['fix_commit']}` (the fix).")
        add("- `_work/fix.diff` is `git diff <positive> <fix>`; `_work/fix_files.txt` lists status, added and deleted lines per file.")
        if ctx["base_mismatch"]:
            add("- `_work/base_to_fix.diff` is `git diff <plan Base commit> <fix>`, kept because the plan's base is not the fix's parent.")
        add("")
        add("### Files the fix touches")
        add("")
        add("| Status | + | - | File | Hint |")
        add("|---|---|---|---|---|")
        for f in ctx["fix_files"]:
            hint = "test" if TEST_PATH.search(f["path"]) else ("docs" if DOC_PATH.search(f["path"]) else "source")
            add(f"| {f['status']} | {f['added']} | {f['deleted']} | `{f['path']}` | {hint} |")
        add("")
        if ctx["hunk_table"]:
            add("### Fix hunks in source files (upstream line numbers)")
            add("")
            add("Positive lines are candidates for `primary_location` / `alternative_primary_locations`; negative lines are prefilled as the negative's `fixed_locations`.")
            add("")
            add("| File | Positive lines (old) | Negative lines (new) |")
            add("|---|---|---|")
            for path, old, new in ctx["hunk_table"]:
                add(f"| `{path}` | {', '.join(f'{a}-{b}' for a, b in old) or '-'} | {', '.join(f'{a}-{b}' for a, b in new) or '-'} |")
            add("")
    elif kind == "designed":
        add("## Upstream tree")
        add("")
        add(f"- `_work/upstream-positive/` = `{ctx['source_commit']}` (plan Base commit). There is no upstream fix: the negative is designed (see Negative design above) and written by hand on a copy of the trimmed positive.")
        add("")
    else:
        add("## Purpose-built")
        add("")
        add(f"- No upstream repository. `environment/repo/` of both twins starts from the `{ctx['language']}` skeleton (`task_format/templates/v4/skeletons/{ctx['lang_spec']['skeleton']}`); the application, fixtures and manifest are written from the slot's Weakness and Negative design.")
        add("")
    if ctx["export_notes"]:
        add("### Export notes (entries not written)")
        add("")
        for n in ctx["export_notes"][:200]:
            add(f"- {n}")
        if len(ctx["export_notes"]) > 200:
            add(f"- ... {len(ctx['export_notes']) - 200} more")
        add("")
    for w in ctx["warnings"]:
        add(f"> WARNING: {w}")
        add("")
    add("## Checklist")
    add("")
    steps = []
    if kind != "purpose_built":
        steps += [
            "Trim: copy into `environment/repo/` of `-a` only what the labelled path needs (the fix files, their callers on the path, config). Keep upstream file paths and line numbers in the fix files where possible. Excluded paths from the plan are already in task.toml `excluded_paths`; generated, vendored and evaluator-only files must stay out of the scanner roots.",
            "Stand-ins: replace third-party imports with small local modules (`_compat/` or the language equivalent) so the code builds and the repro runs offline; record them in provenance `modifications`.",
        ]
        if kind == "fix":
            steps.append("Negative: copy the trimmed positive to `-b` and apply only the fix hunks (from `_work/fix.diff`) to the files you kept; anything beyond the upstream fix goes to provenance `beyond_upstream_fix`. The twin diff of `environment/` must be exactly `fix_changed_files`.")
        else:
            steps.append("Negative: copy the trimmed positive to `-b` and implement the Negative design above, nothing else. Record it in provenance `beyond_upstream_fix` (the whole change is designed).")
    else:
        steps += [
            "Application: write the app in both twins' `environment/repo/` from the skeleton, with a deterministic stub model and no network.",
            "Negative: make `-b` differ from `-a` only in the safety-relevant condition (Negative design); the twin diff must be exactly `fix_changed_files`.",
        ]
    steps += [
        "Manifest and fixtures: fill `environment/repo/security_manifest.json` (identical in both twins) and the synthetic fixtures with canary ids (`fixtures/` identical in both twins).",
        "task.toml (both twins identically, except task_id, variant_id, related_variant_ids): frameworks, package_versions (exact pins), architecture (vocabulary.json), architecture_notes, entrypoint, build_command, test_command, scanner_roots, excluded_paths. Values must be in the dataset's vocabulary.json.",
        "instruction.md is the v4 template with its scope sentence written from this pair's scanner_roots and excluded_paths (task.toml). If you change those in task.toml, change that one sentence the same way in both twins and nothing else in the file (QC compares the rest with the template and the sentence with task.toml).",
        "environment/Dockerfile: build and test commands in the final RUN must match task.toml.",
        f"Ground truth (`tests/ground_truth.json`, both twins): locations, path steps, controls, rationale, affected_asset, violates, evidence; remove `_todo` and every TODO. Then `python tools/snippet_ids.py {ds} --task {fam}-a --task {fam}-b`.",
        f"Oracle: edit `solution/findings.sarif`, then `python tools/label_rules/sync_oracle.py {ds} --task {fam}-a --task {fam}-b`; it must score 1.0 (QC checks).",
        "Repro: `validation/repro_test.py` in each twin must pass on its own code and fail on the twin's (QC runs both with no network).",
        "Provenance and README: `validation/provenance.json` (modifications, upstream_files, beyond_upstream_fix, package_versions) and `README.md`.",
        f"Views: `python tools/export_views.py {ds} --task {fam}-a --task {fam}-b` (writes task_metadata.json and tests/evaluator_view.json).",
        f"QC: `bash ng-sast-agent/tools/qc_pair_v4.sh {ds} {fam}`, then fix until `{ds}/{fam}/_work/qc.md` has no FAIL.",
    ]
    for i, s in enumerate(steps, 1):
        add(f"{i}. [ ] {s}")
    add("")
    for title, col in (("Build notes", "Build notes"), ("Buildability", "Buildability"), ("Scanner difficulty", "Scanner difficulty")):
        if row[col]:
            add(f"## {title}")
            add("")
            add(row[col])
            add("")
    if ctx["excluded_paths_plan"]:
        add("## Excluded paths (plan)")
        add("")
        for p in ctx["excluded_paths_plan"]:
            add(f"- `{p}`")
        add("")
    return "\n".join(L).rstrip() + "\n"


# ---------------------------------------------------------------------------------------------
# Main flow


def load_variants(dataset: Path) -> dict:
    f = dataset / "VARIANTS.json"
    if not f.is_file():
        return {}
    data = json.loads(f.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ScaffoldError(f"{f} is not a JSON object")
    return data


def init_dataset(root: Path) -> None:
    """Caller holds the dataset lock."""
    root.mkdir(parents=True, exist_ok=True)
    if not (root / "VARIANTS.json").is_file():
        write_json_atomic(root / "VARIANTS.json", {})
    if not (root / "vocabulary.json").is_file() and POC_VOCABULARY.is_file():
        shutil.copyfile(POC_VOCABULARY, root / "vocabulary.json")


def allocate(args, row: dict, root: Path, dest: Path, flat: bool) -> dict:
    """Pick the family name and opaque ids and create ``<dest>/<family>/_work`` (the reservation).
    Caller holds the dataset lock. Returns what ``cleanup`` needs to undo it."""
    init_dataset(root)
    variants = load_variants(root)
    where = containers(root, flat)
    names: set[str] = set()
    for c in where:
        for p in c.iterdir():
            if p.is_dir() and not BATCH_DIR.fullmatch(p.name):
                names.add(p.name)
                if p.name[-2:] in ("-a", "-b"):
                    names.add(p.name[:-2])
    families_taken = {v.get("family") for v in variants.values() if isinstance(v, dict)} | names
    # One family per slot: a slot that already has a family is refused (it would otherwise get a "-2" twin family
    # and duplicate a pair another builder already made). Rebuild it with --force --family-name <that family>.
    slot_families = sorted({v.get("family") for v in variants.values()
                            if isinstance(v, dict) and v.get("slot") == row["Slot"]})
    if slot_families and not (args.force and args.family_name in slot_families):
        raise ScaffoldError(f"slot {row['Slot']} already has family {', '.join(slot_families)} in VARIANTS.json; "
                            f"to rebuild it use --force --family-name {slot_families[0]}")
    family = args.family_name or derive_family_name(row, families_taken)
    check_family_name(family)
    a, b = f"{family}-a", f"{family}-b"
    existing = [c / n for c in where for n in (a, b, family) if (c / n).exists()]
    elsewhere = sorted({p.parent for p in existing if p.parent != dest})
    if elsewhere:
        raise ScaffoldError(f"family {family} already exists in {', '.join(display(p) for p in elsewhere)}; slot "
                            f"{row['Slot']} belongs in {display(dest)}. Family names are unique across batches: "
                            "pick another --family-name or move the family")
    other_slot = [n for n in (a, b) if n in variants and variants[n].get("slot") not in (None, row["Slot"])]
    if other_slot:
        raise ScaffoldError(f"{family} belongs to slot {variants[other_slot[0]].get('slot')} in VARIANTS.json")
    registered = [n for n in (a, b) if n in variants and not (dest / n).exists()]
    if (existing or registered) and not args.force:
        raise ScaffoldError(f"family {family} already exists in {display(dest)} "
                            f"({', '.join(sorted({p.name for p in existing} | set(registered)))}); use --force to "
                            "rewrite it")
    if (dest / family / "_work" / PENDING).exists():
        raise ScaffoldError(f"another scaffold of {family} is in progress ({display(dest / family / '_work' / PENDING)}"
                            " exists). If no scaffold is running, a crashed one left it: delete the family's folders "
                            "and rerun")
    targets = [dest / a, dest / b, dest / family]
    for t in targets:
        rmtree(t)

    # Opaque ids: reuse on --force, else new and unique in the dataset (in-flight scaffolds included).
    busy_tasks, busy_fams = pending_ids(where)
    task_ids = {v.get("task_id") for k, v in variants.items() if k not in (a, b)} | busy_tasks
    fam_ids = {v.get("family_id") for k, v in variants.items() if k not in (a, b)} | busy_fams
    old_a, old_b = variants.get(a) or {}, variants.get(b) or {}
    family_id = old_a.get("family_id") or unique_hex(2, "fam_", fam_ids)
    pos_task = old_a.get("task_id") or unique_hex(4, "task_", task_ids)
    neg_task = old_b.get("task_id") or unique_hex(4, "task_", task_ids | {pos_task})
    pos_var = old_a.get("variant_id") or secrets.choice(["var_a", "var_b"])
    neg_var = "var_b" if pos_var == "var_a" else "var_a"

    made_dest = not dest.exists()
    work = dest / family / "_work"
    work.mkdir(parents=True, exist_ok=True)
    ids = {"family": family, "slot": row["Slot"], "family_id": family_id, "pos_task": pos_task, "neg_task": neg_task,
           "pos_var": pos_var, "neg_var": neg_var, "pid": os.getpid()}
    write_json(work / PENDING, ids)
    return {**ids, "targets": targets, "made_dest": made_dest}


def cleanup(res: dict, dest: Path) -> None:
    """Undo a failed scaffold: its folders, and the batch folder when this run created it and it is empty."""
    for t in res["targets"]:
        try:
            rmtree(t)
        except OSError as exc:
            warn(f"could not remove {t}: {exc}")
    if res["made_dest"]:
        try:
            dest.rmdir()  # only succeeds when empty (another scaffold may have put a family there meanwhile)
        except OSError:
            pass


def delivery_ids(dataset: str) -> dict[str, str]:
    """P-slot -> delivery id (D###) from BATCHES.json ``slot_delivery_ids`` (see delivery_ids.py); {} if absent."""
    for base in (ROOT / dataset, (ROOT / dataset).parent):
        f = base / BATCHES
        if f.is_file():
            try:
                return dict(json.loads(f.read_text(encoding="utf-8")).get("slot_delivery_ids") or {})
            except (OSError, ValueError):
                return {}
    return {}


def scaffold(args) -> int:
    languages = load_languages()
    dids = delivery_ids(args.dataset)
    if re.fullmatch(r"[Dd]\d{3}", args.slot):
        by_d = {d: p for p, d in dids.items()}
        if args.slot.upper() not in by_d:
            raise ScaffoldError(f"delivery id {args.slot} not found in BATCHES.json slot_delivery_ids")
        args.slot = by_d[args.slot.upper()]
    row = read_slot(Path(args.plan), args.slot)
    row_did = dids.get(row["Slot"])
    kind = slot_kind(row)
    rules = rule_ids(row)
    lang_key, lang = language_of(row, languages)
    root, dest, flat = resolve_layout(args.dataset, row["Slot"], args.flat, args.batch)
    with dataset_lock(root):
        res = allocate(args, row, root, dest, flat)
    try:
        warnings = build(args, row, kind, rules, lang_key, lang, root, dest, res)
        with dataset_lock(root):
            # VARIANTS.json: re-read under the lock (other scaffolds may have written it meanwhile)
            family, a, b = res["family"], f"{res['family']}-a", f"{res['family']}-b"
            variants = load_variants(root)
            variants[a] = {"family": family, "family_id": res["family_id"], "role": "positive", "twin": b,
                           "task_id": res["pos_task"], "variant_id": res["pos_var"], "slot": row["Slot"], **({"delivery_id": row_did} if row_did else {})}
            variants[b] = {"family": family, "family_id": res["family_id"], "role": "negative", "twin": a,
                           "task_id": res["neg_task"], "variant_id": res["neg_var"], "slot": row["Slot"], **({"delivery_id": row_did} if row_did else {})}
            write_json_atomic(root / "VARIANTS.json", variants)
            (dest / family / "_work" / PENDING).unlink(missing_ok=True)
    except BaseException:
        with dataset_lock(root):
            cleanup(res, dest)
        raise
    family = res["family"]
    print(f"scaffolded {family} (slot {row['Slot']}, {kind}, {lang_key}) in {display(dest)}")
    print(f"  {family}-a: positive {res['pos_var']} {res['pos_task']}; {family}-b: negative {res['neg_var']} "
          f"{res['neg_task']}; family {res['family_id']}")
    print(f"  checklist: {display(dest / family / '_work' / 'BUILD_TODO.md')}")
    for w in warnings:
        warn(w)
    return 0


def build(args, row: dict, kind: str, rules: list[str], lang_key: str, lang: dict, root: Path, dest: Path,
          res: dict) -> list[str]:
    family, family_id = res["family"], res["family_id"]
    pos_task, neg_task, pos_var, neg_var = res["pos_task"], res["neg_task"], res["pos_var"], res["neg_var"]
    a, b = f"{family}-a", f"{family}-b"
    work = dest / family / "_work"
    warnings: list[str] = []
    export_notes: list[str] = []
    owner = name = None
    ctx: dict = {
        "family": family, "kind": kind, "rules": rules, "language": lang_key, "lang_spec": lang,
        "family_id": family_id, "pos_var": pos_var, "neg_var": neg_var, "pos_task_id": pos_task, "neg_task_id": neg_task,
        "date": dt.date.today().isoformat(), "warnings": warnings, "export_notes": export_notes,
        "fix_files": [], "fix_changed_files": [], "fixed_locations": [], "hunk_hints": [], "hunk_table": [], "base_mismatch": False,
        "dir_display": display(dest), "root_display": display(root),
        "delivery_id": delivery_ids(args.dataset).get(row["Slot"]),
    }
    commits: dict = {}
    if kind == "purpose_built":
        ctx.update(source_origin="purpose_built_synthetic", repository_id=f"repo_synthetic_{family.replace('-', '_')}",
                   source_url=None, source_commit=None, fix_commit=None, license=None)
        ctx["advisory"] = fetch_advisory(row["Advisory"], None, None)
    else:
        owner, name = parse_repo(row["Repo"])
        ctx.update(source_origin="adapted_open_source",
                   repository_id="repo_" + re.sub(r"[^a-z0-9]+", "_", f"{owner}_{name}".lower()).strip("_"),
                   source_url=f"https://github.com/{owner}/{name}")
        wanted = [c for c in (row["Base commit"], row["Fix commit"]) if c]
        with repo_lock(owner, name):  # clone, fetch and lazy blob fetches into the shared cache
            repo = ensure_repo(owner, name, wanted)
            if kind == "fix":
                fix = full_sha(repo, row["Fix commit"])
                meta = commit_meta(repo, fix)
                if len(meta["parents"]) != 1:
                    warnings.append(f"fix commit {fix[:12]} has {len(meta['parents'])} parents; the first parent is used")
                if not meta["parents"]:
                    raise ScaffoldError(f"fix commit {fix} has no parent")
                parent = meta["parents"][0]
                base = full_sha(repo, row["Base commit"]) if row["Base commit"] else None
                if base and base != parent:
                    ctx["base_mismatch"] = True
                    anc = git(repo, "merge-base", "--is-ancestor", base, fix, check=False).returncode == 0
                    warnings.append(f"plan Base commit {base[:12]} is not the fix's parent {parent[:12]}"
                                    f" ({'an ancestor of the fix' if anc else 'not an ancestor of the fix'}); "
                                    "the positive tree is the parent. Correct the plan or confirm.")
                ctx.update(source_commit=parent, fix_commit=fix)
                commits = {"positive": commit_meta(repo, parent), "fix": meta}
                if base and base != parent:
                    commits["plan_base"] = commit_meta(repo, base)
                print(f"exporting {parent[:12]} (positive) and {fix[:12]} (negative)")
                export_notes += [f"positive: {n}" for n in export_tree(repo, parent, work / "upstream-positive")]
                export_notes += [f"negative: {n}" for n in export_tree(repo, fix, work / "upstream-negative")]
                diff = git(repo, "diff", "--no-color", "--no-ext-diff", "--no-textconv", "-M", parent, fix).stdout
                write_text(work / "fix.diff", diff)
                if base and base != parent:
                    prefetch_blobs(repo, base)
                    write_text(work / "base_to_fix.diff",
                               git(repo, "diff", "--no-color", "--no-ext-diff", "--no-textconv", "-M", base, fix).stdout)
                status = {}
                for ln in git(repo, "diff", "--name-status", "-M", parent, fix).stdout.splitlines():
                    parts = ln.split("\t")
                    status[parts[-1]] = parts[0] if len(parts) == 2 else f"{parts[0]} from {parts[1]}"
                fix_files = []
                for ln in git(repo, "diff", "--numstat", "-M", parent, fix).stdout.splitlines():
                    added, deleted, path = ln.split("\t", 2)
                    if " => " in path:
                        path = re.sub(r"\{([^{}]*) => ([^{}]*)\}", r"\2", path)
                        path = path.split(" => ")[-1].replace("//", "/")
                    fix_files.append({"status": status.get(path, "?"), "added": added, "deleted": deleted, "path": path})
                ctx["fix_files"] = fix_files
                write_text(work / "fix_files.txt",
                           "".join(f"{f['status']}\t+{f['added']}\t-{f['deleted']}\t{f['path']}\n" for f in fix_files))
                hunks = diff_hunks(repo, parent, fix)
                src = source_hunks(hunks)
                ctx["fix_changed_files"] = [p for p, _ in src]
                ctx["hunk_table"] = [(p, h["old"] if h["old_path"] else [], h["new"] if h["new_path"] else []) for p, h in src]
                for p, h in src:
                    for r in h["new"]:
                        ctx["fixed_locations"].append(loc(p, r[0], r[1], why="TODO(builder): what the fix changes here"))
                    for r in h["old"]:
                        if h["old_path"]:
                            ctx["hunk_hints"].append({"file": h["old_path"], "old": r})
                if not src:
                    warnings.append("the fix touches no source file (only tests or docs); locations are TODO")
            else:
                base = full_sha(repo, row["Base commit"])
                ctx.update(source_commit=base, fix_commit=None)
                commits = {"positive": commit_meta(repo, base)}
                print(f"exporting {base[:12]} (positive; designed negative)")
                export_notes += [f"positive: {n}" for n in export_tree(repo, base, work / "upstream-positive")]
        ctx["license"] = fetch_license(owner, name)
        if ctx["license"] is None:
            warnings.append("licence not found through the GitHub API; fill provenance.license by hand")
        ctx["advisory"] = fetch_advisory(row["Advisory"], owner, name)
        if row["Archived"].lower().startswith("y"):
            warnings.append("the plan marks this repository as archived")
    adv = ctx["advisory"]
    cwes = list(adv.get("cwes") or [])
    for c in re.findall(r"CWE-\d+", row["Weakness"], re.I):
        if c.upper() not in cwes:
            cwes.append(c.upper())
    ctx["cwes"] = cwes
    if row["Advisory"] and adv.get("fetch_error"):
        warnings.append(f"advisory {adv.get('id')}: {adv['fetch_error']}")

    excluded_plan = excluded_from_plan(row["Excluded paths"])
    ctx["excluded_paths_plan"] = excluded_plan
    ctx["scanner_roots"] = list(lang["scanner_roots"])
    ctx["excluded_paths"] = list(dict.fromkeys(lang["excluded_paths"] + excluded_plan))

    # _work/slot.json
    write_json(work / "slot.json", {
        "slot": row["Slot"], **({"delivery_id": ctx.get("delivery_id")} if ctx.get("delivery_id") else {}), "plan_row": row, "plan_file": str(Path(args.plan)), "kind": kind,
        "family": family, "family_id": family_id, "rules": rules, "language_template": lang_key,
        "repository": f"{owner}/{name}" if owner else None, "source_url": ctx.get("source_url"),
        "positive_commit": ctx.get("source_commit"), "fix_commit": ctx.get("fix_commit"), "commits": commits,
        "advisory": adv, "license": ctx.get("license"), "warnings": warnings,
        "dataset_root": ctx["root_display"], "task_dir": ctx["dir_display"],
        "family_dir": f"{ctx['dir_display']}/{family}", "task_folders": [f"{ctx['dir_display']}/{a}", f"{ctx['dir_display']}/{b}"],
        "scaffolded": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    })

    # Task folders
    pos_gt, neg_gt = ground_truths(rules, row, ctx)
    common = TEMPLATES / "common"
    task_toml_t = (TEMPLATES / "task.toml.tmpl").read_text(encoding="utf-8")
    dockerfile_t = (TEMPLATES / "dockerfiles" / lang["dockerfile"]).read_text(encoding="utf-8")
    instruction = render_instruction((common / "instruction.md").read_bytes().decode("utf-8"),
                                     ctx["scanner_roots"], ctx["excluded_paths"])
    manifest_t = (TEMPLATES / "security_manifest.json.tmpl").read_text(encoding="utf-8")
    readme_t = (TEMPLATES / "README.md.tmpl").read_text(encoding="utf-8")
    repro_t = (TEMPLATES / "repro_test.py.tmpl").read_text(encoding="utf-8")
    difficulty = (row["Scanner difficulty"].split(":")[0].strip().lower() or "medium")
    difficulty = re.sub(r"\s*\(.*$", "", difficulty).strip()        # "hard (note...)" -> "hard"
    difficulty = {"high": "hard", "low": "easy"}.get(difficulty, difficulty)
    if difficulty not in ("easy", "medium", "hard"):
        difficulty = "medium"
    app = parse_repo(row["Repo"])[1] if owner else "a purpose-built application"
    description = (f"Static security review of {app} ({row['Language']}) for sensitive information disclosure "
                   "and excessive agency against its security manifest.")
    keywords = ["sast", "security", "static-analysis", "owasp-llm-2026", lang["vocabulary"][0]]
    if owner:
        keywords.append(kebab(name))
    for role, folder, var, other, tid, gt in (("positive", a, pos_var, neg_var, pos_task, pos_gt),
                                              ("negative", b, neg_var, pos_var, neg_task, neg_gt)):
        d = dest / folder
        twin = b if role == "positive" else a
        write_text(d / "task.toml", fill(task_toml_t, {
            "FOLDER": folder, "DESCRIPTION": toml_str(description), "KEYWORDS": toml_list(keywords),
            "DIFFICULTY": difficulty, "TASK_ID": tid, "REPOSITORY_ID": ctx["repository_id"],
            "FAMILY_ID": family_id, "VARIANT_ID": var, "RELATED_VARIANT_ID": f"{family_id}:{other}",
            "SOURCE_ORIGIN": ctx["source_origin"], "LANGUAGES": toml_list(lang["vocabulary"]),
            "ENTRYPOINT": toml_str(lang["entrypoint"]), "BUILD_COMMAND": toml_str(lang["build_command"]),
            "TEST_COMMAND": toml_str(lang["test_command"]), "SCANNER_ROOTS": toml_list(ctx["scanner_roots"]),
            "EXCLUDED_PATHS": toml_list(ctx["excluded_paths"]),
            "BUILD_TIMEOUT": str(lang["build_timeout_sec"]), "MEMORY_MB": str(lang["memory_mb"]),
        }))
        (d / "instruction.md").write_bytes(instruction.encode("utf-8"))
        write_text(d / "environment" / "Dockerfile", fill(dockerfile_t, {
            "BUILD_COMMAND": lang["build_command"], "TEST_COMMAND": lang["test_command"],
            "RUNTIME_NOTE": lang.get("dockerfile_note", "")}))
        repo_dir = d / "environment" / "repo"
        repo_dir.mkdir(parents=True, exist_ok=True)
        if kind == "purpose_built":
            shutil.copytree(TEMPLATES / "skeletons" / lang["skeleton"], repo_dir, dirs_exist_ok=True)
        for rel, src in (lang.get("repo_files") or {}).items():  # build helpers the commands rely on
            (repo_dir / rel).parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(TEMPLATES / src, repo_dir / rel)
        write_text(repo_dir / "security_manifest.json", manifest_t)
        (d / "tests").mkdir(parents=True, exist_ok=True)
        for f in ("Dockerfile", "test.sh", ".dockerignore", ".harborignore"):
            shutil.copyfile(common / "tests" / f, d / "tests" / f)
        write_json(d / "tests" / "ground_truth.json", gt, indent=1)
        write_json(d / "tests" / "evaluator_view.json", {
            "_placeholder": f"Generated file. Run `python tools/export_views.py {ctx['dir_display']} --task {folder}` "
                            "from ng-sast-agent after the build; it rewrites this file and task_metadata.json.",
            "task_id": tid, "task_name": folder, "view": "evaluator_only"})
        (d / "solution").mkdir(parents=True, exist_ok=True)
        for f in ("solve.sh", ".harborignore"):
            shutil.copyfile(common / "solution" / f, d / "solution" / f)
        write_json(d / "solution" / "findings.sarif", oracle(gt, rules), indent=1)
        write_json(d / "validation" / "provenance.json", provenance(row, ctx, role))
        lang_note = ("The code is Python: import it from environment/repo/src." if lang_key == "python" else
                     f"The code is {row['Language']}: drive it through the toolchain in the task image "
                     "(subprocess with list arguments, cwd=REPO, no network), e.g. a test file copied into a "
                     "temp copy of the repo. QC runs this file in the task's own environment image.")
        write_text(d / "validation" / "repro_test.py", fill(repro_t, {
            "FOLDER": folder, "LANGUAGE_NOTE": lang_note,
            "CLASS": "ReproPositive" if role == "positive" else "ReproNegative",
            "ASSERT_HINT": ("The canary must be written, read or sent." if role == "positive" else
                            "The same trigger must be refused and the canary untouched; also keep one positive "
                            "control test (the benign request still works)."),
        }))
        write_text(d / "README.md", fill(readme_t, {
            "FOLDER": folder, "TWIN": twin, "SLOT": (f"Delivery ID {ctx['delivery_id']}; slot {row['Slot']}" if ctx.get("delivery_id") else f"Slot {row['Slot']}"), "DATE": ctx["date"],
            "SOURCE": ctx.get("source_url") or "purpose-built",
            "ROLE_LINE": ("Positive twin (evaluator-only README): TODO(builder) the weakness in two sentences."
                          if role == "positive" else
                          f"Minimal-contrast negative twin of {a} (evaluator-only README): TODO(builder) the control in two sentences."),
        }))

    write_text(work / "BUILD_TODO.md", build_todo(row, ctx))
    return warnings


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--slot", required=True, help="plan slot id, e.g. P001")
    ap.add_argument("--family-name", help="kebab-case family name (default: repo short name + two words of the weakness)")
    ap.add_argument("--dataset", default="tasks",
                    help="dataset root (families go in its batch-N folder for the slot), a batch-N folder, or a flat "
                         "dataset; absolute or relative to the repository root (default: tasks)")
    ap.add_argument("--plan", default=str(DEFAULT_PLAN), help="plan workbook (default: planning/SAST_500_Plan.xlsx)")
    ap.add_argument("--force", action="store_true", help="rewrite an existing family (keeps its opaque ids)")
    ap.add_argument("--batch", metavar="NAME",
                    help="batch folder to use instead of the slot's entry in BATCHES.json (e.g. batch-4 to place a "
                         "buffer pair into the batch it replaces); required for a slot BATCHES.json does not list")
    ap.add_argument("--flat", action="store_true",
                    help="old flat layout: VARIANTS.json and the task folders side by side in --dataset (auto-detected "
                         "when --dataset already holds task folders and no batch-* folder)")
    args = ap.parse_args()
    try:
        return scaffold(args)
    except ScaffoldError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
