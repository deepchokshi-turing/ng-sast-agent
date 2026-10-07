# Pre-built scanner tools for task images. A task's Dockerfile copies them in:
#
#   ARG SAST_TOOLS_IMAGE=<registry>/sast-tools:<version>
#   FROM ${SAST_TOOLS_IMAGE} AS sast-tools
#   FROM <the task's base image>
#   COPY --from=sast-tools /opt/sast /opt/sast
#
# /opt/sast holds three tools:
#   Semgrep        venv, rules and merged rules, with its own CPython (uv-managed),
#                  so it works on any task base image with glibc >= 2.34.
#   CodeQL         /opt/sast/codeql, the full CodeQL bundle (CLI plus query packs),
#                  unpacked as a real folder: codeql-bundle-linux64 on amd64 and
#                  codeql-bundle-linux-arm64 on arm64, each pinned by sha256.
#   sonar-scanner  /opt/sast/sonar-scanner, the CLI with its bundled JRE.
#
# The CodeQL bundle, sonar-scanner, uv and the Semgrep rules are checked against
# the sha256 pinned in sast/<tool>/pins.py. The Semgrep wheel, its dependencies
# and uv's CPython are resolved with --exclude-newer at the pinned date but are
# not hash-checked.
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

FROM scratch
COPY --from=semgrep /opt/sast /opt/sast
COPY --from=codeql /opt/sast /opt/sast
COPY --from=sonar /opt/sast /opt/sast
