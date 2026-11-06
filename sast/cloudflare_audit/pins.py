"""Everything that decides which skill, Claude Code and Node.js a run uses.

Not agent options on purpose: the model, the mode and the profile are options
(options.py), the code that runs is fixed here, and changing any value is a new
agent version.

- The skill: cloudflare/security-audit-skill at commit c1c8a8c (2026-09-14,
  "Clarify guidance and full audit modes"), MIT. Only the files under
  ``skills/security-audit/`` that the skill reads or runs are fetched, each
  from raw.githubusercontent.com at that commit and checked against its sha256
  (computed with ``git show <commit>:<path>`` from a clean clone, and checked
  equal to the raw download on 2026-10-14). The validators' own tests
  (``*.test.cjs``) are not installed. Upstream installs the skill with the
  Skills CLI (``npx skills add``); that installer is not used here, the files
  are put where Claude Code looks for user skills (``~/.claude/skills/``).
- Claude Code: the same pinned native binary as the Claude review
  (``sast.claude_review.pins``: 2.1.296, npm sha256 and sha512 integrity).
- Node.js 24.21.0 (LTS), for the skill's two zero-dependency validators
  (``validate-findings.cjs``, ``validate-coverage-ledger.cjs``). The official
  linux-x64 and linux-arm64 ``.tar.xz`` from nodejs.org, sha256 from
  nodejs.org's SHASUMS256.txt for v24.21.0 (the same pins as the Promptfoo
  agent). Only ``bin/node`` is unpacked.
"""

from __future__ import annotations

from ..claude_review import pins as claude_pins

#: The skill.
SKILL_REPO = "cloudflare/security-audit-skill"
SKILL_COMMIT = "c1c8a8c1471069fb0e188eeaff69b8e8db6564a8"
SKILL_COMMIT_DATE = "2026-09-14"
SKILL_NAME = "security-audit"
SKILL_RAW_URL = f"https://raw.githubusercontent.com/{SKILL_REPO}/{SKILL_COMMIT}/{{path}}"
#: The skill's folder in the repository.
SKILL_PATH = "skills/security-audit"

#: Files by path relative to the skill folder (``LICENSE`` is the repository's), and their sha256.
SKILL_FILES = {
    "AI-AND-LLM.md": "7335a95c43554eadefcf03ece639291bb0e038c398a179299e3887ffe06bd2ef",
    "ATTACK-CLASSES.md": "3ee4f00c6e8c9dcf6dd02dd5ac2a4ceb322e2085f3e9fbe79cf0c6330bc7ef83",
    "CLIENT-SIDE.md": "613f6b98f86083e045525c5b60154ffdab122bac35f1e05eb17488e6e453370c",
    "CLOUD-AND-DEPLOYMENT.md": "3c80f3088be22345e07b057c056d6ed99fe2b0304f794398964f7ccd5a496ca3",
    "DATA-ISOLATION-AND-LIFECYCLE.md": "307dcb3e24d292715c4a041190e7bb135646a37eb6187619ae01d000a634a4ad",
    "DESKTOP-MOBILE-AND-LOCAL-IPC.md": "58eae8ee0ca6a46611c501ec5a3ab47fdff88dd7db0d8d74789bbf8bb19d8cb2",
    "HUNTING.md": "71c121decea1322c47c718f6e110f1a892980bb4266bd7ac55ef043a213ade09",
    "MEMORY-SAFETY-AND-BINARY.md": "7c8b0dccfb35315cca2455509674d49632b2fe37e1f3aac16c1a496a7e9924a7",
    "PROTOCOLS-RPC-AND-MESSAGING.md": "8b73816fa5b3697c9c40977f0c836b40f01d6e81929ff2720fe83ce089e9a619",
    "RECONNAISSANCE.md": "02ca887aca84de8ae137f1891bd2f0a54f28d3fa6da92a27f54734382b3381a2",
    "RESOURCE-EXHAUSTION-AND-AVAILABILITY.md": "4326fab5c92a0b4c420a70196254040105cd794026562130b59bf1a6db3e4baa",
    "SKILL.md": "5e3e96a1e438d8f35fef0a1e38f02d4f00e2bdf910401b7dfe00e6779c6dac85",
    "SUPPLY-CHAIN-AND-RELEASE.md": "f372e919940e335468ba1ae09f99026c3986a345f7fe26f8068f132e199f52a5",
    "VALIDATION-AND-REPORTING.md": "b892470cb89bb31f33403e050d4bdfbe2cdaef940ade1496fa65e32b2e129449",
    "WEB-PROTOCOL-AND-AUTH.md": "4f3066dffa23c5635859187be9b96c32f2aff29a688186b91ff0c63e47d62b5c",
    "report-schema.json": "6575c9de4a62255699ea052ebf9a49ebfb373a32891bcd89af6f55cc84b35519",
    "validate-coverage-ledger.cjs": "2eb280bd2e33c002916f86db9b29f9edfedb6454e5db973c766290465b868ac8",
    "validate-findings.cjs": "e85f232e36bfac0f866f244da50376692d6b45c690beadcb00608b0e6c8b5283",
    "LICENSE": "e598e694aa506650c7192d5ea3be0e50aca0d356ea00551c53429f0b01eb6391",
}

#: Claude Code, as the Claude review pins it.
CLAUDE_CODE_VERSION = claude_pins.CLAUDE_CODE_VERSION

#: Node.js.
NODE_VERSION = "24.21.0"
NODE_DIST_URL = "https://nodejs.org/dist/v{version}/{file}"
NODE_TARBALLS = {
    "x86_64": ("node-v24.21.0-linux-x64.tar.xz", "fd8e59d5a511510f6a298afb548f18c7d2b1be404d8b4a27d94fbe49f56cb2d6"),
    "aarch64": ("node-v24.21.0-linux-arm64.tar.xz", "6ad1325edbdb5649c379b75a237147a666c95d4f9ae8d340fef2d1575d289ad2"),
}

#: The skill names no model. This default is the model the Claude review runs with the same subscription token.
DEFAULT_MODEL = "claude-opus-5-5"

#: Where a tools image would put this part: bin/claude, node/bin/node, skill/, install.json. Not baked yet.
INSTALL_DIR = "/opt/sast/cloudflare-audit"


def skill_url(rel: str) -> str:
    """The raw URL of a pinned file (``LICENSE`` is at the repository root)."""
    path = rel if rel == "LICENSE" else f"{SKILL_PATH}/{rel}"
    return SKILL_RAW_URL.format(path=path)


def as_dict() -> dict:
    """The pins as install.py reads them (uploaded as cf_pins.json)."""
    claude = claude_pins.as_dict()
    return {
        "skill_repo": SKILL_REPO,
        "skill_commit": SKILL_COMMIT,
        "skill_name": SKILL_NAME,
        "skill_files": {rel: {"sha256": sha, "url": skill_url(rel)} for rel, sha in SKILL_FILES.items()},
        "claude_code_version": claude["claude_code_version"],
        "claude_code_packages": claude["claude_code_packages"],
        "node_version": NODE_VERSION,
        "node": {arch: {"file": file, "sha256": sha, "url": NODE_DIST_URL.format(version=NODE_VERSION, file=file),
                        "member": file[:-len(".tar.xz")] + "/bin/node"}
                 for arch, (file, sha) in NODE_TARBALLS.items()},
        "default_model": DEFAULT_MODEL,
        "install_dir": INSTALL_DIR,
    }
