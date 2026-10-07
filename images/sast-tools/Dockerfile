# Pre-built scanner tools for task images. A task's Dockerfile copies them in:
#
#   ARG SAST_TOOLS_IMAGE=<registry>/sast-tools:<version>
#   FROM ${SAST_TOOLS_IMAGE} AS sast-tools
#   FROM <the task's base image>
#   COPY --from=sast-tools /opt/sast /opt/sast
#
# /opt/sast holds both tools:
#   - Semgrep in a uv-managed CPython venv, plus the merged rules;
#   - the CodeQL bundle in /opt/sast/codeql (its own Java runtime and query packs).
# It works on any task base image with glibc >= 2.34 (Debian 12+, Ubuntu 22.04+).
# Each agent finds its install, checks it against its pins, and skips the
# download; on an image without it, the agent installs at setup instead (CodeQL's
# bundle is about 650 MB, so that is slow).
#
# Built by tools/build_tools_image.sh, which stages the installers and pins.
# No pipes on the RUN lines: a failed install must fail the build.
FROM python:3.11-slim AS build
COPY install.py merge_rules.py pins.json codeql_install.py codeql-pins.json /opt/sast/
RUN python3 /opt/sast/install.py /opt/sast/pins.json
RUN python3 /opt/sast/codeql_install.py /opt/sast/codeql-pins.json

FROM scratch
COPY --from=build /opt/sast /opt/sast
