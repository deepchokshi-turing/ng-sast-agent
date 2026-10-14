#!/bin/bash
# Oracle "scanner": emits the reference SARIF. Must score 1.0 against tests/grade.py.
mkdir -p /app/output
cp "$(dirname "$0")/findings.sarif" /app/output/findings.sarif
