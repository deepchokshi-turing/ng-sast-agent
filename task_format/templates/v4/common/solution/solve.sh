#!/bin/bash
# Oracle "scanner": emits the reference SARIF at the path task.toml declares as an artifact
# (/app/output/findings.sarif), so Harbor carries it to the separate verifier. Must score 1.0.
set -e
mkdir -p /app/output
cp "$(dirname "$0")/findings.sarif" /app/output/findings.sarif
