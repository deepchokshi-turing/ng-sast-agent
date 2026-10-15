# Pre-built scanner tools for task images. A task's Dockerfile copies them in:
#
#   ARG SAST_TOOLS_IMAGE=<registry>/sast-tools:<version>
#   FROM ${SAST_TOOLS_IMAGE} AS sast-tools
#   FROM <the task's base image>
#   COPY --from=sast-tools /opt/sast /opt/sast
#
# /opt/sast holds four tools:
#   Semgrep        venv, rules and merged rules, with its own CPython (uv-managed),
#                  so it works on any task base image with glibc >= 2.34.
#   CodeQL         /opt/sast/codeql, the full CodeQL bundle (CLI plus query packs),
#                  unpacked as a real folder: codeql-bundle-linux64 on amd64 and
#                  codeql-bundle-linux-arm64 on arm64, each pinned by sha256.
#   sonar-scanner  /opt/sast/sonar-scanner, the CLI with its bundled JRE.
#   claude-review  /opt/sast/claude-review: the Claude Code native binary
#                  (bin/claude, from the npm platform package for the CPU,
#                  checked against its sha256 and npm sha512 integrity), the
#                  pinned files of anthropics/claude-code-security-review
#                  (ccsr/, each checked against its sha256) and a venv with the
#                  hash-pinned anthropic and requests (requirements.lock,
#                  installed with --require-hashes). The venv is built from
#                  the Semgrep part's uv CPython, so it needs that part too.
#
# The CodeQL bundle, sonar-scanner, uv, the Semgrep rules and every file of the
# claude-review part are checked against the sha256 pinned in sast/<tool>/pins.py
# (its wheels against sast/claude_review/requirements.lock). The Semgrep wheel,
# its dependencies and uv's CPython are resolved with --exclude-newer at the
# pinned date but are not hash-checked, so a rebuild could in principle get
# different bytes. The manifest now records what was actually installed, so two
# builds can be compared and a run can say which build it used.
#
# /opt/sast/MANIFEST.json is written by the manifest stage below with
# sast/manifest.py (staged as sast_manifest.py): the tool versions from the
# pins, a sha256 and mode for every file and symlink, one tree digest over the
# sorted (path, sha256, mode) entries, and one tree digest per tool part. Each
# agent's install step records the manifest digest and its tool's tree digest
# in the run metadata. Semgrep and sonar-scanner rehash their own part to check
# it (a few seconds at most). CodeQL records its digest without rehashing,
# since the bundle is about 1.3 GB.
# tools/build_tools_image.sh stages this Dockerfile, the Semgrep installer files
# and fetch_archive.py, and passes the pins as build arguments.
#
# The build stages use python:3.11-slim pinned by its multi-arch index digest
# (from `docker buildx imagetools inspect python:3.11-slim` on 2026-10-08), so
# amd64 and arm64 builds both resolve. Only the build stages use it (the final
# image is FROM scratch and holds /opt/sast alone).
FROM python:3.11-slim@sha256:0dd364ba7e10242f07755449e3a3d0e35f9efd987952737b90def6709ab0c5ce AS semgrep
COPY install.py merge_rules.py pins.json /opt/sast/
# No pipe here: the step's exit status must be the installer's own.
RUN python3 /opt/sast/install.py /opt/sast/pins.json

FROM python:3.11-slim@sha256:0dd364ba7e10242f07755449e3a3d0e35f9efd987952737b90def6709ab0c5ce AS codeql
ARG TARGETARCH
ARG CODEQL_URL_AMD64
ARG CODEQL_SHA256_AMD64
ARG CODEQL_URL_ARM64
ARG CODEQL_SHA256_ARM64
COPY fetch_archive.py /tmp/fetch_archive.py
RUN set -e; \
    case "$TARGETARCH" in \
      amd64) url="$CODEQL_URL_AMD64"; sha="$CODEQL_SHA256_AMD64" ;; \
      arm64) url="$CODEQL_URL_ARM64"; sha="$CODEQL_SHA256_ARM64" ;; \
      *) echo "no CodeQL bundle pinned for linux/$TARGETARCH"; exit 2 ;; \
    esac; \
    mkdir -p /opt/sast; \
    python3 /tmp/fetch_archive.py "$url" "$sha" /opt/sast/codeql --strip-top; \
    /opt/sast/codeql/codeql version --format=terse

FROM python:3.11-slim@sha256:0dd364ba7e10242f07755449e3a3d0e35f9efd987952737b90def6709ab0c5ce AS sonar
ARG TARGETARCH
ARG SONAR_SCANNER_VERSION
ARG SONAR_SCANNER_SHA256_AMD64
ARG SONAR_SCANNER_SHA256_ARM64
COPY fetch_archive.py /tmp/fetch_archive.py
RUN set -e; \
    case "$TARGETARCH" in \
      amd64) arch=x64; sha="$SONAR_SCANNER_SHA256_AMD64" ;; \
      arm64) arch=aarch64; sha="$SONAR_SCANNER_SHA256_ARM64" ;; \
      *) echo "unsupported arch $TARGETARCH"; exit 2 ;; \
    esac; \
    python3 /tmp/fetch_archive.py \
      "https://binaries.sonarsource.com/Distribution/sonar-scanner-cli/sonar-scanner-cli-${SONAR_SCANNER_VERSION}-linux-${arch}.zip" \
      "$sha" /opt/sast/sonar-scanner --strip-top; \
    /opt/sast/sonar-scanner/bin/sonar-scanner -v

# The Claude Code security review. sast/claude_review/install.py, staged as
# claude_review_install.py, downloads and checks everything and builds the venv
# with the Semgrep stage's uv and CPython (copied in, not shipped from here).
FROM python:3.11-slim@sha256:0dd364ba7e10242f07755449e3a3d0e35f9efd987952737b90def6709ab0c5ce AS claude-review
COPY --from=semgrep /opt/sast/python /opt/sast/python
COPY --from=semgrep /opt/sast/bin /opt/sast/bin
COPY claude_review_install.py claude_review_pins.json requirements.lock /tmp/claude-review/
# The installer takes the Semgrep part's CPython 3.12 (/opt/sast/python) first.
RUN python3 /tmp/claude-review/claude_review_install.py /tmp/claude-review/claude_review_pins.json \
      --build --target /opt/sast/claude-review --uv /opt/sast/bin/uv \
      --requirements /tmp/claude-review/requirements.lock

# The four parts together, plus MANIFEST.json over all of them.
FROM python:3.11-slim@sha256:0dd364ba7e10242f07755449e3a3d0e35f9efd987952737b90def6709ab0c5ce AS manifest
COPY --from=semgrep /opt/sast /opt/sast
COPY --from=codeql /opt/sast /opt/sast
COPY --from=sonar /opt/sast /opt/sast
COPY --from=claude-review /opt/sast/claude-review /opt/sast/claude-review
COPY sast_manifest.py manifest_pins.json /tmp/
RUN python3 /tmp/sast_manifest.py write /opt/sast /tmp/manifest_pins.json

FROM scratch
COPY --from=manifest /opt/sast /opt/sast
