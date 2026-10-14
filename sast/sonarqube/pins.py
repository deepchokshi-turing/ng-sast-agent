"""Which sonar-scanner a run uses, and where the tools image puts it.

The SonarQube server cannot be pinned like a CLI. The user runs it, so every
trial records its version, edition and Python quality profile instead (see
agent.py). Only the scanner CLI, with its bundled JRE, is pinned here.

The version is the release Maven Central listed on 2026-10-07 (8.1.0.6389).
The sha256 values were computed from the downloaded archives
(``Distribution/sonar-scanner-cli/sonar-scanner-cli-<version>-linux-<arch>.zip``
on binaries.sonarsource.com) and match the ``.sha256`` files published next to
them. The tools image build checks them. Changing a value here is a new agent
version (bump ``sast.__version__``).
"""

#: sonar-scanner CLI version.
SONAR_SCANNER_VERSION = "8.1.0.6389"

#: sha256 of the linux zip with the bundled JRE, per CPU architecture. Checked by
#: the tools image build, not in the sandbox (the zip is not kept in the image).
SONAR_SCANNER_SHA256 = {
    "x86_64": "bb8f709f9cb73352f8d1260a3b3c506c0f41146754bc630762c126d795499d0b",   # linux-x64.zip
    "aarch64": "5e1c9328f4e261838de778c9e586ee608cca45ff7f0538108642219214628ba5",  # linux-aarch64.zip
}

#: Where the tools image unpacks the scanner (bin/, lib/, jre/ directly under it).
INSTALL_DIR = "/opt/sast/sonar-scanner"

DOWNLOAD_URL = (
    "https://binaries.sonarsource.com/Distribution/sonar-scanner-cli/"
    "sonar-scanner-cli-{version}-linux-{arch}.zip"
)


def as_dict() -> dict:
    """The pins as install.py reads them (uploaded as pins.json)."""
    return {
        "sonar_scanner_version": SONAR_SCANNER_VERSION,
        "sonar_scanner_sha256": dict(SONAR_SCANNER_SHA256),
        "install_dir": INSTALL_DIR,
    }
