"""Everything that decides which Semgrep and which rules a run uses.

Not agent options on purpose: a run cannot quietly use a different engine or rule
set, and changing any value here is a new agent version (bump ``sast.__version__``).

Semgrep and the rules match the earlier SAST sheet (Semgrep OSS 1.179.0,
semgrep/semgrep-rules at a84ff9cc2453, folders python, javascript, typescript, ai
and generic/secrets).
"""

SEMGREP_VERSION = "1.179.0"

# Semgrep's own dependencies are resolved as they were on this date, so a later
# release of a transitive dependency cannot change what gets installed.
EXCLUDE_NEWER = "2026-10-07T00:00:00Z"

# uv brings its own CPython, so the image's Python version does not matter.
PYTHON_VERSION = "3.12"
UV_VERSION = "0.9.29"
UV_SHA256 = {
    "x86_64": "44c93c73e8870e003bda17ab50d433e27d201d0cb28d2bb75351ef1497ffa9db",
    "aarch64": "b1edc94f5d6c36bb28a20f8c8afb400e55a428fcf396b03bf78cb7394f75077c",
}

RULES_REPO = "semgrep/semgrep-rules"
RULES_COMMIT = "a84ff9cc2453ca91d581380de4b8b3f272f6f4be"  # 2026-09-22
RULES_DIRS = ("python", "javascript", "typescript", "ai", "generic/secrets")
# Content hash of the selected rule files (see install.rules_digest): 898 files,
# 949 rules, 790 of them category: security.
RULES_DIGEST = "eeb769187d42c678ef2d8cafd6ed4ea45063352fbd4130c84d30f085f8dcebb7"
RULES_FILE_COUNT = 898


def as_dict() -> dict:
    """The pins as install.py reads them (uploaded as pins.json)."""
    return {
        "semgrep_version": SEMGREP_VERSION,
        "exclude_newer": EXCLUDE_NEWER,
        "python_version": PYTHON_VERSION,
        "uv_version": UV_VERSION,
        "uv_sha256": dict(UV_SHA256),
        "rules_repo": RULES_REPO,
        "rules_commit": RULES_COMMIT,
        "rules_dirs": list(RULES_DIRS),
        "rules_digest": RULES_DIGEST,
        "rules_file_count": RULES_FILE_COUNT,
    }
