"""Everything that decides which CodeQL and which queries a run uses.

Not agent options on purpose: a run cannot quietly use a different engine or
query suite, and changing any value here is a new agent version (bump
``sast.__version__``).

CodeQL stays at 2.27.1 to match the earlier baseline over the 159 cases. The
bundle (linux64 on amd64, linux-arm64 on arm64) is baked into the tools image at
``INSTALL_DIR``. ``install.py`` uses it when it matches these pins. Otherwise it
downloads the pinned bundle for the CPU, checks its sha256 and unpacks it, all
inside Harbor's 300 s setup limit (about 100 s on a fast link), and fails with a
clear message when the download cannot finish in time.
"""

CODEQL_VERSION = "2.27.1"

BUNDLE_TAG = "codeql-bundle-v2.27.1"
RELEASE_URL = f"https://github.com/github/codeql-action/releases/download/{BUNDLE_TAG}"

#: Docker TARGETARCH -> (release asset, sha256 of that asset). The tools image
#: build fetches the one for its CPU and checks it against this digest.
#: amd64: computed from the download on 2026-10-07 and equal to the digest GitHub
#: publishes for the asset (692285664 bytes).
#: arm64: the digest GitHub publishes for the asset, checked against the GitHub
#: release API by a reviewer on 2026-10-07, the same value PR #2 pins.
BUNDLES = {
    "amd64": ("codeql-bundle-linux64.tar.gz",
              "1d380f79896ededc654c7b21fafb3360136f1aeb678ad4df4df9af3910c6b815"),
    "arm64": ("codeql-bundle-linux-arm64.tar.gz",
              "5f05cc0793971e48824d00e570afe6144a27a325360b43bd823d755aed919817"),
}


def bundle_url(arch: str) -> str:
    """The download URL of the bundle for a Docker TARGETARCH (amd64 or arm64)."""
    return f"{RELEASE_URL}/{BUNDLES[arch][0]}"


#: Where the tools image puts the unpacked bundle; the CLI is INSTALL_DIR/codeql.
INSTALL_DIR = "/opt/sast/codeql"

#: The query pack that ships the Python suites, and its version in this bundle.
PYTHON_QUERIES_PACK = "codeql/python-queries"
PYTHON_QUERIES_VERSION = "1.8.11"

#: The python security-extended suite, relative to the bundle directory.
SUITE_PATH = f"qlpacks/codeql/python-queries/{PYTHON_QUERIES_VERSION}/codeql-suites/python-security-extended.qls"


def as_dict() -> dict:
    """The pins as install.py reads them (uploaded as pins.json)."""
    return {
        "codeql_version": CODEQL_VERSION,
        "bundle_tag": BUNDLE_TAG,
        "bundles": {arch: {"asset": asset, "sha256": sha, "url": bundle_url(arch)}
                    for arch, (asset, sha) in BUNDLES.items()},
        "install_dir": INSTALL_DIR,
        "python_queries_pack": PYTHON_QUERIES_PACK,
        "python_queries_version": PYTHON_QUERIES_VERSION,
        "suite_path": SUITE_PATH,
    }
