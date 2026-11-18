"""Everything that decides which promptfoo, Node.js and git a run uses.

Not agent options on purpose: the mode and the time limit are options (see
options.py), but the code that runs is fixed here, and changing any value is a
new agent version (bump ``sast.__version__``).

- promptfoo 0.124.1 (published to npm 2026-10-08), the version the owner ran
  ``promptfoo code-scans run`` with on 2026-10-12. Its npm ``dist.integrity`` is
  pinned here and must equal the lock's entry. Every other package comes from
  ``npm/package-lock.json`` with its own sha512 ``integrity``: the lock of
  ``npm/package.json`` (promptfoo plus the filesystem MCP server it launches,
  which promptfoo lists as optional), pruned by ``npm/prune_lock.py`` to the
  packages reachable through required edges plus the glibc libsql binding.
  373 packages, about 270 MB unpacked, instead of the 1.4 GB a full install
  with every optional cloud SDK takes.
- Node.js 24.21.0 (LTS "Krypton", 2026-09-07; promptfoo needs >= 22.22.0), the
  official linux-x64 and linux-arm64 ``.tar.xz`` from nodejs.org. The sha256
  values are those of nodejs.org's SHASUMS256.txt for v24.21.0, and equal the
  sha256 of the tarballs downloaded on 2026-10-12.
- git 2.47.3 (Debian trixie ``git_2.47.3-0+deb13u1``): promptfoo reads the
  change set with the git CLI, and the task images (python:3.12-slim) have no
  git. Only ``/usr/bin/git`` is taken from the .deb; the commands promptfoo
  runs (diff, cat-file, status, branch, rev-parse, log) are built into it, and
  it links only libc, libpcre2-8 and zlib, which the task images have. The
  sha256 values are those of the trixie Packages index (2026-10-12), checked
  against the downloaded files; the sha1 names the file on snapshot.debian.org,
  which keeps it after deb.debian.org drops it.
"""

from __future__ import annotations

#: promptfoo on npm.
PROMPTFOO_VERSION = "0.124.1"
PROMPTFOO_INTEGRITY = "sha512-Y6fq/WGTL7lPvDsirNSmmmcPLhURwRao03iv8fCoLbFq6H1eqg5VVTmXiap5Jl+fiRaQQZXYMHb2N1gQm1tGyQ=="
#: The filesystem MCP server promptfoo starts to let the scan read the repository.
MCP_FILESYSTEM_VERSION = "2026.8.31"
NPM_REGISTRY = "https://registry.npmjs.org/"
#: Next to this file, uploaded with the installer. The sha256 values are of the
#: files with LF line ends (a CRLF checkout is normalised before hashing).
NPM_DIR = "npm"
PACKAGE_JSON = "package.json"
PACKAGE_JSON_SHA256 = "a55faf1773cb56a0af72557bdb479a934a8997d97553b190b0093fc28e20a2d6"
PACKAGE_LOCK = "package-lock.json"
PACKAGE_LOCK_SHA256 = "305a703153a7c283c72f4362cdeed029b34fab6231e47d18c6576f8db096994b"
PACKAGE_LOCK_ENTRIES = 372

#: Node.js.
NODE_VERSION = "24.21.0"
NODE_DIST_URL = "https://nodejs.org/dist/v{version}/{file}"
#: CPU (platform.machine()) -> (tarball, sha256).
NODE_TARBALLS = {
    "x86_64": ("node-v24.21.0-linux-x64.tar.xz", "fd8e59d5a511510f6a298afb548f18c7d2b1be404d8b4a27d94fbe49f56cb2d6"),
    "aarch64": ("node-v24.21.0-linux-arm64.tar.xz", "6ad1325edbdb5649c379b75a237147a666c95d4f9ae8d340fef2d1575d289ad2"),
}
#: npm's name for the CPU, as in the lock's ``cpu`` lists.
NPM_CPU = {"x86_64": "x64", "aarch64": "arm64"}

#: git from Debian trixie.
GIT_VERSION = "2.47.3"
GIT_DEB_VERSION = "2.47.3-0+deb13u1"
#: CPU -> (.deb file name, sha256, sha1).
GIT_DEBS = {
    "x86_64": ("git_2.47.3-0+deb13u1_amd64.deb", "3e35662fd5c46add561703e54031a1d8ad9df45811927689f0a51122b13be722",
               "bb5947667cef07307ce77aeb86fd95c2a3e85472"),
    "aarch64": ("git_2.47.3-0+deb13u1_arm64.deb", "8c6b1e96b226211260d7814472215a8a1ed38ee37400c421d454391c1807cb5a",
                "dac3541a184cbadf9424aba0709c77058bc86b02"),
}
GIT_POOL_URL = "https://deb.debian.org/debian/pool/main/g/git/{file}"
GIT_SNAPSHOT_URL = "https://snapshot.debian.org/file/{sha1}"

#: Where the tools image would put this part (node/, git/, app/, install.json).
INSTALL_DIR = "/opt/sast/promptfoo"
#: Where setup installs it when the image has no baked part.
LOCAL_DIR_NAME = "promptfoo"


def git_urls(arch: str) -> list[str]:
    file, _sha256, sha1 = GIT_DEBS[arch]
    return [GIT_POOL_URL.format(file=file.replace("+", "%2B")), GIT_SNAPSHOT_URL.format(sha1=sha1)]


def as_dict() -> dict:
    """The pins as install.py reads them (uploaded as pins.json)."""
    return {
        "promptfoo_version": PROMPTFOO_VERSION,
        "promptfoo_integrity": PROMPTFOO_INTEGRITY,
        "mcp_filesystem_version": MCP_FILESYSTEM_VERSION,
        "npm_registry": NPM_REGISTRY,
        "package_json_sha256": PACKAGE_JSON_SHA256,
        "package_lock_sha256": PACKAGE_LOCK_SHA256,
        "package_lock_entries": PACKAGE_LOCK_ENTRIES,
        "node_version": NODE_VERSION,
        "node": {arch: {"file": file, "sha256": sha, "url": NODE_DIST_URL.format(version=NODE_VERSION, file=file)}
                 for arch, (file, sha) in NODE_TARBALLS.items()},
        "npm_cpu": dict(NPM_CPU),
        "git_version": GIT_VERSION,
        "git_deb_version": GIT_DEB_VERSION,
        "git": {arch: {"file": file, "sha256": sha256, "urls": git_urls(arch)}
                for arch, (file, sha256, _sha1) in GIT_DEBS.items()},
        "install_dir": INSTALL_DIR,
        "local_dir_name": LOCAL_DIR_NAME,
    }
