"""The scanner settings a task declares in its task.toml, read on the host.

Harbor does not hand an agent its task config, but ``environment.environment_dir``
is the host path of the task's ``environment/`` folder (locally and on Daytona),
and the platform writes ``task.toml`` next to it. Only scan configuration is read:
which paths to scan or skip, the sandbox's CPUs and memory, and the agent
timeout. Labels never live in task.toml, and nothing else in it is used.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any

from .errors import ScannerError


@dataclass(frozen=True)
class TaskSettings:
    #: The task.toml that was read, or None when there was none to read.
    source: str | None = None
    scanner_roots: tuple[str, ...] = ()
    excluded_paths: tuple[str, ...] = ()
    cpus: int | None = None
    memory_mb: int | None = None
    agent_timeout_sec: float | None = None
    notes: tuple[str, ...] = field(default=())

    def describe(self) -> dict[str, Any]:
        return {
            "task_toml": self.source,
            "scanner_roots": list(self.scanner_roots),
            "excluded_paths": list(self.excluded_paths),
            "cpus": self.cpus,
            "memory_mb": self.memory_mb,
            "agent_timeout_sec": self.agent_timeout_sec,
            "notes": list(self.notes),
        }


def repo_relative(value: Any, what: str) -> str:
    """A path inside /app/repo, as the scanner will be given it."""
    if not isinstance(value, str) or not value.strip():
        raise ScannerError(f"{what} must be a non-empty string, got {value!r}")
    path = value.strip()
    pure = PurePosixPath(path)
    if pure.is_absolute() or ".." in pure.parts or path.startswith("-"):
        raise ScannerError(f"{what} {value!r} must be a relative path inside the repository")
    return str(pure)


def _paths(raw: Any, what: str) -> tuple[str, ...]:
    if raw is None:
        return ()
    if not isinstance(raw, list):
        raise ScannerError(f"{what} in task.toml must be a list of paths, got {raw!r}")
    return tuple(repo_relative(p, what) for p in raw)


def _positive_number(raw: Any, cast):
    try:
        value = cast(raw)
    except (TypeError, ValueError):
        return None
    return value if value > 0 else None


def load(environment_dir: Path | str | None) -> TaskSettings:
    if environment_dir is None:
        return TaskSettings(notes=("environment has no environment_dir",))
    path = Path(environment_dir).parent / "task.toml"
    if not path.is_file():
        return TaskSettings(notes=(f"no task.toml at {path}",))
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ScannerError(f"cannot read {path}: {exc}") from exc

    metadata = data.get("metadata") or {}
    environment = data.get("environment") or {}
    agent = data.get("agent") or {}
    return TaskSettings(
        source=str(path),
        scanner_roots=_paths(metadata.get("scanner_roots"), "metadata.scanner_roots"),
        excluded_paths=_paths(metadata.get("excluded_paths"), "metadata.excluded_paths"),
        cpus=_positive_number(environment.get("cpus"), int),
        memory_mb=_positive_number(environment.get("memory_mb"), int),
        agent_timeout_sec=_positive_number(agent.get("timeout_sec"), float),
    )
