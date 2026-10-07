# Pre-built scanner tools for task images. A task's Dockerfile copies them in:
#
#   ARG SAST_TOOLS_IMAGE=<registry>/sast-tools:<version>
#   FROM ${SAST_TOOLS_IMAGE} AS sast-tools
#   FROM <the task's base image>
#   COPY --from=sast-tools /opt/sast /opt/sast
#
# /opt/sast carries its own CPython (uv-managed), so it works on any task base
# image with glibc >= 2.34 (Debian 12+, Ubuntu 22.04+). The agent finds the
# install, checks it against its pins, and skips the download; on an image
# without it, the agent installs as before.
#
# Built by tools/build_tools_image.sh, which stages install.py, merge_rules.py
# and pins.json from sast/semgrep/.
FROM python:3.11-slim AS build
COPY install.py merge_rules.py pins.json /opt/sast/
RUN python3 /opt/sast/install.py /opt/sast/pins.json | tail -1

FROM scratch
COPY --from=build /opt/sast /opt/sast
