"""Everything that decides which datadog-saist binary a run uses.

Not agent options on purpose: the models and the time limits are options
(options.py), but the code that runs is fixed here, and changing any value is a
new agent version.

- datadog-saist ``v0.0.32`` (DataDog/datadog-saist, Apache-2.0, "preview"),
  tag commit ``de91d08561a02e671295a0c1096c88da6ad26477``, released
  2026-09-22. The release assets are goreleaser zips holding one executable
  ``datadog-saist`` (Go, dynamically linked against glibc only) and LICENSE.
  The zip sha256 values are the ``digest`` GitHub publishes for each asset and
  the release's own ``checksums.txt``; the executable's sha256 was computed
  from the files downloaded on 2026-10-14. Both are checked before use.
- The binary has no ``--version`` flag; ``-h`` lists its flags and models and
  the install checks that it runs and names ``-detection-model``.
- Its detection rules are NOT in the binary: by default it downloads them at
  every run from Datadog's public endpoint
  ``https://api.datadoghq.com/api/v2/static-analysis/ai/prompts`` (no key).
  That rule set cannot be pinned; the agent records a digest of the rules the
  run used (from the SARIF's rule descriptors). ``--ak rules=embedded`` uses
  the 12 rules compiled into the binary instead (``--local-prompts``: cmdi,
  sqli, xpathi, xss for Go, Java and Python), which are pinned with the binary
  but cover none of the LLM rules.
"""

from __future__ import annotations

VERSION = "0.0.32"
RELEASE_TAG = f"v{VERSION}"
COMMIT = "de91d08561a02e671295a0c1096c88da6ad26477"
RELEASE_DATE = "2026-09-22"
RELEASE_URL = f"https://github.com/DataDog/datadog-saist/releases/download/{RELEASE_TAG}/{{asset}}"
MEMBER = "datadog-saist"

#: CPU (platform.machine(), normalised) -> (asset, zip sha256, executable sha256).
ASSETS = {
    "x86_64": ("datadog-saist_linux_amd64.zip",
               "6e1c17d4a831f05cad50a95648a594c50c98a82226cc60456cea69aa5e463038",
               "883d840bcb0cc6322ca5d54cc9c9e32dbc708a4d4d394750ae8b2080ccef014c"),
    "aarch64": ("datadog-saist_linux_arm64.zip",
                "581e424ce1dd0bfc2757ed347163d9f9a4ce0816b20b03482020e031fb61ef25",
                "38cf5c479a4e808d1b7cac1cf484f3f1926e10062e3abff378e74460b626cb9d"),
}

#: The binary's model names (``-h``, internal/model/models.go at the tag) -> (provider, API model id).
MODELS = {
    "openai-gpt5-mini": ("openai", "gpt-5-mini"),
    "openai-gpt5.2": ("openai", "gpt-5.2"),
    "openai-gpt5.2-codex": ("openai", "gpt-5.2-codex"),
    "claude-4.5-sonnet": ("anthropic", "claude-sonnet-4-5"),
    "claude-4.5-haiku": ("anthropic", "claude-haiku-4-5"),
    "gemini-2.5-pro": ("google", "gemini-2.5-pro"),
    "gemini-2.5-flash": ("google", "gemini-2.5-flash"),
    "gemini-2.0-flash-lite": ("google", "gemini-2.0-flash-lite-preview"),
    "gemini-3-flash": ("google", "gemini-3-flash-preview"),
}
#: API model id -> the binary's name (for Harbor's -m and --ak model=<API id>).
API_TO_CLI = {api: cli for cli, (_provider, api) in MODELS.items()}
#: The provider -> the host variable that holds its key (the binary reads these names).
KEY_ENVS = {"openai": "OPENAI_API_KEY", "anthropic": "ANTHROPIC_API_KEY", "google": "GOOGLE_API_KEY"}

#: Default detection and validation model. The tool has no default (both flags are
#: required); this is the strongest general OpenAI model it supports, the provider
#: whose key the benchmark has.
DEFAULT_MODEL = "openai-gpt5.2"

#: The public rule endpoint the binary fetches (internal/api/datadog_api.go).
RULES_URL = "https://api.datadoghq.com/api/v2/static-analysis/ai/prompts"
#: Where a tools image would put this part. Not baked yet (a follow-up).
INSTALL_DIR = "/opt/sast/datadog-saist"


def as_dict() -> dict:
    """The pins as install.py reads them (uploaded as datadog_saist_pins.json)."""
    return {
        "version": VERSION,
        "release_tag": RELEASE_TAG,
        "commit": COMMIT,
        "member": MEMBER,
        "assets": {arch: {"url": RELEASE_URL.format(asset=asset), "sha256": zip_sha, "file_sha256": file_sha}
                   for arch, (asset, zip_sha, file_sha) in ASSETS.items()},
        "install_dir": INSTALL_DIR,
    }
