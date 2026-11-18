"""Everything that decides which Claude Code, which review tool and which Python
packages a run uses.

Not agent options on purpose. The model and the mode are options (see
options.py), but the code that runs is fixed here, and changing any value is a
new agent version (bump ``sast.__version__``).

- Claude Code: the native CLI binary that npm ships in the platform packages
  ``@anthropic-ai/claude-code-linux-x64`` and ``-linux-arm64`` (the main
  ``@anthropic-ai/claude-code`` package only points at them, so Node is not
  needed). Version 2.1.296, published 2026-10-09. The sha256 values were
  computed from the tarballs downloaded from registry.npmjs.org on 2026-10-12,
  and the sha512 values equal the ``dist.integrity`` npm publishes for them.
- anthropics/claude-code-security-review at commit 0c6a49f (2026-02-11). Only
  the eight library files the driver imports are fetched, each from
  raw.githubusercontent.com at that commit and checked against its sha256
  (computed from a clean checkout of the commit). Upstream tests, evals and the
  GitHub Action wrapper are not installed.
- Python packages: ``requirements.lock`` (anthropic 0.79.0, requests 2.32.5
  and their dependencies, every file hash-pinned), resolved as of the day after
  the upstream commit.
"""

from __future__ import annotations

#: Claude Code CLI version (``claude --version`` prints "<version> (Claude Code)").
CLAUDE_CODE_VERSION = "2.1.296"

#: CPU (platform.machine()) -> npm package, sha256 of its tarball, npm dist.integrity.
CLAUDE_CODE_PACKAGES = {
    "x86_64": (
        "@anthropic-ai/claude-code-linux-x64",
        "eef5a2e2b09a5e7d2ce784d1b3ba335ae7fc6c7f6256c802a0ebf2c21e4fd0e1",
        "sha512-+m01urgelnI+VJxPaKPEK0wixgq42uZ8PeCaUk5tX/8YoDBvSmC/REVQG2jQfJAr8dxunpjJ600FvLrcj1WWTw==",
    ),
    "aarch64": (
        "@anthropic-ai/claude-code-linux-arm64",
        "56abbe1cfc85e5b37afeef5ae8b4856ddc32bbe443b82689a3b5f99992045cd1",
        "sha512-Q6Qh6qFmwuBG9rQFiDR6bY3XkFnwTN9AAPrnnDgBvr9sbg1Ql5wrf0lfoCDiV369EUHOzxI4i5OdHW9Vf2/oeA==",
    ),
}

NPM_REGISTRY = "https://registry.npmjs.org"


def claude_code_tarball_url(arch: str) -> str:
    """registry.npmjs.org/<scope>/<name>/-/<name>-<version>.tgz for a CPU."""
    package = CLAUDE_CODE_PACKAGES[arch][0]
    short = package.split("/", 1)[1]
    return f"{NPM_REGISTRY}/{package}/-/{short}-{CLAUDE_CODE_VERSION}.tgz"


#: The upstream review tool.
CCSR_REPO = "anthropics/claude-code-security-review"
CCSR_COMMIT = "0c6a49f1fa56a1d472575da86a94dbc1edb78eda"
CCSR_COMMIT_DATE = "2026-02-11"
CCSR_RAW_URL = f"https://raw.githubusercontent.com/{CCSR_REPO}/{CCSR_COMMIT}/{{path}}"

#: Upstream files, by path in the repository, and their sha256 at CCSR_COMMIT.
CCSR_FILES = {
    "LICENSE": "a9ac868c004c4cce26430b3117767b46397ba4fa25026b1e5ea6694b463baf4b",
    "claudecode/__init__.py": "abc13e6da18bb8bd2a24856b4be6670bcd3cfbb2bbf2bae21bc694095c16ca08",
    "claudecode/claude_api_client.py": "32b5ca67c3d26b65e2467f289b7df054ff9fea6873e2111bcb7259ab3931d05e",
    "claudecode/constants.py": "3e06e83c0c307be8dffe99ee70902b238ccdef45fd6b50fe710c5a842a290084",
    "claudecode/findings_filter.py": "a18eb6a2112093a547a93bfe351691eb7a9866cfc2ffeee1b5d852da09a63d17",
    "claudecode/github_action_audit.py": "943e1c5afd7a72d6a481faca1e043432854170127e6b0dc309e30a63755be9ea",
    "claudecode/json_parser.py": "1285deac64d815e4b87a2d2b674c271dc50271377c939b3dfde2c844e725693f",
    "claudecode/logger.py": "48002ea6373a388a10011eaeaabd93b8a08d1fe2bbaba3f798e6e6bcb7b12645",
    "claudecode/prompts.py": "a779b599d3badeddff9d01f9a1cbe7828c03a4eb17b4717782131963c825d5d0",
}

#: The upstream default model: ``constants.DEFAULT_CLAUDE_MODEL`` when CLAUDE_MODEL
#: is not set (constants.py:8). Used for the review and for the filter unless the
#: run names another one.
UPSTREAM_DEFAULT_MODEL = "claude-opus-4-1-20250805"

#: The Python packages, hash-pinned (see the file's header).
REQUIREMENTS_FILE = "requirements.lock"
REQUIREMENTS_SHA256 = "d565960b5154a50e0affe734c1b57f4f36972a7e0fa199d689224d355c144707"
ANTHROPIC_VERSION = "0.79.0"
REQUESTS_VERSION = "2.32.5"

#: Where the tools image puts this part: bin/claude, ccsr/, venv/, install.json.
INSTALL_DIR = "/opt/sast/claude-review"


def as_dict() -> dict:
    """The pins as install.py reads them (uploaded as pins.json)."""
    return {
        "claude_code_version": CLAUDE_CODE_VERSION,
        "claude_code_packages": {
            arch: {"package": package, "sha256": sha, "integrity": integrity,
                   "url": claude_code_tarball_url(arch)}
            for arch, (package, sha, integrity) in CLAUDE_CODE_PACKAGES.items()
        },
        "ccsr_repo": CCSR_REPO,
        "ccsr_commit": CCSR_COMMIT,
        "ccsr_raw_url": CCSR_RAW_URL,
        "ccsr_files": dict(CCSR_FILES),
        "upstream_default_model": UPSTREAM_DEFAULT_MODEL,
        "requirements_file": REQUIREMENTS_FILE,
        "requirements_sha256": REQUIREMENTS_SHA256,
        "anthropic_version": ANTHROPIC_VERSION,
        "requests_version": REQUESTS_VERSION,
        "install_dir": INSTALL_DIR,
    }
