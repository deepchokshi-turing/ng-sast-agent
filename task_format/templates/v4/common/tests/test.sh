#!/bin/bash
# Harbor verifier entrypoint, run in the separate verifier container built from
# tests/Dockerfile. Harbor restores the agent's /app/output/findings.sarif artifact here
# before running this script; no other file from the agent's container is present.
mkdir -p /logs/verifier
/opt/grader/grade \
  --sarif /app/output/findings.sarif \
  --truth /tests/ground_truth.json \
  --out /logs/verifier || echo 0 > /logs/verifier/reward.txt
# A grader that died before writing any reward still scores 0.
[ -s /logs/verifier/reward.txt ] || [ -s /logs/verifier/reward.json ] || echo 0 > /logs/verifier/reward.txt
