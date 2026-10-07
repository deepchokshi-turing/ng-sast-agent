"""Operator maintenance helpers (not reachable from the model or any tool)."""

import subprocess


def rotate_logs(command: str) -> int:
    """Run the operator's log-rotation command."""
    return subprocess.run(command, shell=True, check=False).returncode
