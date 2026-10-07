"""Everything that decides which CodeQL and which queries a run uses.

Not agent options on purpose: a run cannot quietly use a different engine or
query set, and changing any value here is a new agent version (bump
``sast.__version__``).

CodeQL CLI 2.27.1 and the ``security-extended`` suites match the earlier SAST
sheet. The query packs ship inside the bundle (``github/codeql`` at
``codeql-cli/v2.27.1``), so nothing is downloaded at scan time.
"""

CODEQL_VERSION = "2.27.1"
BUNDLE_TAG = "codeql-bundle-v2.27.1"
BUNDLE_URL = "https://github.com/github/codeql-action/releases/download/{tag}/codeql-bundle-{platform}.tar.gz"

#: Linux CPU -> (bundle platform, sha256 of the .tar.gz), from the release's
#: published checksum files.
BUNDLES = {
    "x86_64": ("linux64", "1d380f79896ededc654c7b21fafb3360136f1aeb678ad4df4df9af3910c6b815"),
    "aarch64": ("linux-arm64", "5f05cc0793971e48824d00e570afe6144a27a325360b43bd823d755aed919817"),
}

#: CodeQL language -> the bundled query suite run for it.
SUITES = {
    "python": "codeql/python-queries:codeql-suites/python-security-extended.qls",
    "javascript-typescript": "codeql/javascript-queries:codeql-suites/javascript-security-extended.qls",
}

#: Query pack -> version shipped in the pinned bundle. The bundle's sha256 already
#: fixes them; the installer checks them explicitly so a different bundle can
#: never pass silently.
QUERY_PACKS = {
    "codeql/python-queries": "1.8.11",
    "codeql/javascript-queries": "2.4.6",
}

#: CodeQL language -> the folder its database gets inside a --db-cluster.
#: CodeQL stores the javascript-typescript language under its old name.
DATABASE_DIRS = {
    "python": "python",
    "javascript-typescript": "javascript",
}

#: File extensions that make a language present in the scan scope.
LANGUAGE_EXTENSIONS = {
    "python": (".py",),
    "javascript-typescript": (".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"),
}


def as_dict() -> dict:
    """The pins as install.py reads them (uploaded as codeql-pins.json)."""
    return {
        "codeql_version": CODEQL_VERSION,
        "bundle_tag": BUNDLE_TAG,
        "bundle_url": BUNDLE_URL,
        "bundles": {arch: list(v) for arch, v in BUNDLES.items()},
        "suites": dict(SUITES),
        "query_packs": dict(QUERY_PACKS),
    }
