"""Which repo-relative files a scan covers: the task's roots minus its excludes.

Shared by every scanner agent. Each tool is given the scope in its own syntax
(Semgrep ``--include``/``--exclude`` in ``sast.semgrep.agent.scope_args``,
CodeQL ``paths``/``paths-ignore`` in ``sast.codeql.agent.codeql_config``,
SonarQube ``sonar.sources``/``sonar.exclusions``), and every finding is then
checked again with ``in_scope``. A difference in how a tool matches paths can
therefore only drop findings, never widen the scope.

The meaning is the same for every tool:

- a root or an exclude that contains "/" is a path from the repository root
- an exclude without "/" (``tests``) is that name at any depth, as in .gitignore
- compiled bytecode is always excluded (``ALWAYS_EXCLUDE``)
"""

from __future__ import annotations

import fnmatch
from collections.abc import Iterable

from .task_config import repo_relative

REPO_DIR = "/app/repo"

#: Always skipped: compiled bytecode is a build output, not source. Task images
#: that run tests or compileall at build time are full of it, and the Semgrep
#: secrets rules would regex-scan the binaries.
ALWAYS_EXCLUDE = ("__pycache__", "*.pyc", "*.pyo")


def task_scope(roots: Iterable[str], excludes: Iterable[str],
               roots_name: str = "scanner_roots", excludes_name: str = "excluded_paths") -> tuple[list[str], list[str]]:
    """(roots, excludes) as repo-relative paths. No roots means the whole repository ``["."]``.

    Every entry goes through ``task_config.repo_relative``, so an absolute path,
    a ``..`` or a leading "-" is a ScannerError and never reaches a command line.
    """
    checked_roots = [repo_relative(p, roots_name) for p in roots] or ["."]
    checked_excludes = [repo_relative(p, excludes_name) for p in excludes]
    return checked_roots, checked_excludes


def repo_path(path: str, repo_dir: str = REPO_DIR) -> str:
    """A tool's result path relative to the repository root, "/"-separated."""
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
