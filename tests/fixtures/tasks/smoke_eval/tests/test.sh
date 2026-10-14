#!/bin/bash
# Harbor verifier entrypoint. tests/ is copied in only after the scanner finishes.
mkdir -p /logs/verifier
python3 /tests/grade.py \
  --sarif /app/output/findings.sarif \
  --truth /tests/ground_truth.json \
  --out /logs/verifier || echo 0 > /logs/verifier/reward.txt
