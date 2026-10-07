"""Which repo-relative files a scan covers: the task's roots minus its excludes.

Shared by every scanner. Each tool gets the scope in its own syntax (Semgrep:
``--include``/``--exclude``; CodeQL: ``paths``/``paths-ignore``), and every
finding is checked again here, so a difference in a tool's matching rules can
only drop findings, never widen the scope.

Semantics, the same for all tools:
- a root or exclude containing "/" is a path from the repository root;
- an exclude without "/" (``tests``) is that name at any depth, as in .gitignore;
- compiled bytecode is always excluded (:data:`ALWAYS_EXCLUDE`).
"""

from __future__ import annotations

import fnmatch

#: Always skipped: compiled bytecode is a build output, not source. Task images
#: that run tests or compileall at build time are full of it.
ALWAYS_EXCLUDE = ("__pycache__", "*.pyc", "*.pyo")


def repo_path(path: str, repo_dir: str = "/app/repo") -> str:
    """A result path relative to the repository root, "/"-separated."""
    path = path.replace("\\", "/")
    if path.startswith(repo_dir.rstrip("/") + "/"):
        path = path[len(repo_dir.rstrip("/")) + 1:]
    while path.startswith("./"):
        path = path[2:]
    return path.lstrip("/")


def _under(path: str, prefix: str) -> bool:
    prefix = prefix.strip("/")
    return prefix in (".", "") or path == prefix or path.startswith(prefix + "/")


def in_scope(file: str, roots: list[str], excludes: list[str]) -> bool:
    """Whether a repo-relative file is inside the roots and outside the excludes."""
    if not any(_under(file, r) for r in roots):
        return False
    parts = file.split("/")
    for ex in [*excludes, *ALWAYS_EXCLUDE]:
        ex = ex.strip("/")
        if "/" in ex:
            if _under(file, ex):
                return False
        elif any(fnmatch.fnmatchcase(part, ex) for part in parts):
            return False
    return True
