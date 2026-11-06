"""Everything that decides which Codex CLI a run uses.

Not agent options on purpose: the model, the mode and the sandbox are options
(see options.py), but the code that runs is fixed here, and changing any value
is a new agent version.

- The Codex CLI is the native, statically linked (musl) Rust binary that
  OpenAI publishes on the GitHub release ``rust-v0.162.1`` of openai/codex
  (published 2026-10-09; the npm package ``@openai/codex@0.162.1`` ships the
  same binaries in its platform packages, about 450 MB unpacked, so the
  release assets are used instead and Node.js is not needed). Three assets per
  CPU are fetched, each a ``.tar.gz`` holding one executable:

  - ``codex``: the CLI (``codex --version`` prints ``codex-cli 0.162.1``).
  - ``codex-code-mode-host``: the JavaScript tool host. The newer models of the
    bundled catalog (``tool_mode: code_mode_only``, among them the default
    below) get their shell tool through it; without it Codex 0.162.1 says
    "Code Mode is unavailable ... host executable was not found" and fails the
    tool closed. It must sit next to ``codex``.
  - ``bwrap``: the bubblewrap build Codex uses for its Linux sandbox. Codex
    looks for it at ``codex-resources/bwrap`` next to its own executable.

  The tarball sha256 values are the ``digest`` GitHub publishes for each
  release asset; they were checked against the files downloaded on
  2026-10-12, and the sha256 of each extracted executable was computed from
  those files. Both are checked before use.
- The Codex Security CLI (``@openai/codex-security`` 0.2.0 on npm, the product
  formerly called Aardvark) is not used: its docs say scans that use OpenAI
  inference need Codex Security access (and full-repository scans may need
  Trusted Access for Cyber), which a plain API key may not have. See
  docs/codex-security-agent.md.
"""

from __future__ import annotations

#: The Codex CLI version (``codex --version`` prints "codex-cli <version>").
CODEX_VERSION = "0.162.1"
RELEASE_TAG = f"rust-v{CODEX_VERSION}"
RELEASE_DATE = "2026-10-09"
RELEASE_URL = f"https://github.com/openai/codex/releases/download/{RELEASE_TAG}/{{asset}}"

#: CPU (platform.machine(), normalised) -> Rust target of the release assets.
TARGETS = {"x86_64": "x86_64-unknown-linux-musl", "aarch64": "aarch64-unknown-linux-musl"}

#: Where each executable goes, relative to the install part.
INSTALL_PATHS = {
    "codex": "bin/codex",
    "codex-code-mode-host": "bin/codex-code-mode-host",
    "bwrap": "bin/codex-resources/bwrap",
}

#: CPU -> executable -> (tarball sha256, sha256 of the one executable in it).
ASSETS = {
    "x86_64": {
        "codex": ("86f268d81b898f3e144c5ecff2ad2fda2c5802e042d6195b72538fe0fa125057",
                  "628e35487d888a28f0427fc37501da529dd3d81fcbad7a2c3421c1e8670d92e1"),
        "codex-code-mode-host": ("458239ea45c1fc508d89695f180ab352f2834709a8a46929a4466f4f04399ada",
                                 "ec71830690a7c0024916ee0c99fbdc635bc6e747ff665ea4f03a8389bbcb6b30"),
        "bwrap": ("fa78980959466bd7a04643384c6293511f06a3140345c1237cfc75ccde7f3eea",
                  "01fb705f067bd5365b63d8ad2323a61c8d007733ca5e649437e086f3fb9935d8"),
    },
    "aarch64": {
        "codex": ("bf3ca2719f1143b1440fbd85c149379e696c782c50ad7991f8bfcec60b2600c1",
                  "071cbe8d821cf1b02b6d8ba6c8b7991b228fcb8519dcb68a37d31222bb8cabe5"),
        "codex-code-mode-host": ("1395ce9367f8acd280674dff083edf25bf221d908b8351d5bd4f3fdde9181e9a",
                                 "f6477b0357a8cc2291d628962876ecb1a2beb872f71a1e2734363c81ff21700d"),
        "bwrap": ("83377376b697058a1bf6e73d754b027c66ef58b0a0e22527e12110865b33bc9c",
                  "c547cbdc762a70ed216789ffaa4c6c0e7d2beabe32245a498f8e365a9fc8dab4"),
    },
}

#: The default model: the default scan model of OpenAI's own Codex Security CLI
#: (its CLI reference: ``--model``, default ``gpt-5.6-sol``). It is in Codex
#: 0.162.1's bundled model catalog (``codex debug models --bundled``) with
#: ``supported_in_api: true``. OpenAI may retire it; name another with
#: ``--ak model=...``.
DEFAULT_MODEL = "gpt-5.6-sol"

#: Where a tools image would put this part: bin/codex, bin/codex-code-mode-host,
#: bin/codex-resources/bwrap, install.json. Not baked yet (a follow-up).
INSTALL_DIR = "/opt/sast/codex-security"


def asset_name(tool: str, arch: str) -> str:
    """The release asset of ``tool`` for ``arch``, for example codex-x86_64-unknown-linux-musl.tar.gz."""
    return f"{tool}-{TARGETS[arch]}.tar.gz"


def member_name(tool: str, arch: str) -> str:
    """The one file inside that asset."""
    return f"{tool}-{TARGETS[arch]}"


def as_dict() -> dict:
    """The pins as install.py reads them (uploaded as pins.json)."""
    return {
        "codex_version": CODEX_VERSION,
        "release_tag": RELEASE_TAG,
        "assets": {
            arch: {
                tool: {"url": RELEASE_URL.format(asset=asset_name(tool, arch)), "member": member_name(tool, arch),
                       "sha256": tarball, "file_sha256": binary, "path": INSTALL_PATHS[tool]}
                for tool, (tarball, binary) in tools.items()
            }
            for arch, tools in ASSETS.items()
        },
        "default_model": DEFAULT_MODEL,
        "install_dir": INSTALL_DIR,
    }
