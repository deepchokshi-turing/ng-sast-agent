# A Node image with only Debian's python3 (for the grader): no pip, no venv,
# no ensurepip. Proves the scanner install does not depend on the image's Python.
FROM node:22-bookworm-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY repo/ /app/repo/
RUN mkdir -p /app/output \
 && cd /app/repo && node test/smoke.test.js
