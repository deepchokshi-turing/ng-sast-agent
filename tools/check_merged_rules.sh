#!/usr/bin/env bash
# Prove that merging the rule files (install step, see sast/semgrep/merge_rules.py)
# changes no result: scan the pinned rules repo's own test corpus once with the
# original per-file rules and once with the merged files, and compare every
# finding (rule id, path, position, severity, message, metadata).
#
# Run after any change to sast/semgrep/pins.py. Needs Docker and network.
#
#   tools/check_merged_rules.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

PYTHONPATH="$ROOT" python3 -c "import json, sast.semgrep.pins as p; print(json.dumps(p.as_dict()))" > "$WORK/pins.json"
COMMIT="$(python3 -c "import json; print(json.load(open('$WORK/pins.json'))['rules_commit'])")"
cp "$ROOT/sast/semgrep/install.py" "$ROOT/sast/semgrep/merge_rules.py" "$WORK/"

cat > "$WORK/Dockerfile" <<'EOF'
FROM python:3.11-slim
COPY install.py merge_rules.py pins.json /x/
RUN python3 /x/install.py /x/pins.json | tail -1
EOF
docker build -q -t sast-semgrep-check "$WORK" >/dev/null

mkdir -p "$WORK/corpus" "$WORK/out"
curl -fsSL "https://github.com/semgrep/semgrep-rules/archive/$COMMIT.tar.gz" | tar xz -C "$WORK/corpus" --strip-components 1

cat > "$WORK/scan.sh" <<'EOF'
set -e
cd /corpus
ORIG=""; MERGED=""
for d in python javascript typescript ai generic/secrets; do
  ORIG="$ORIG --config /opt/sast/rules/$d"
  MERGED="$MERGED --config /opt/sast/rules-merged/$(echo "$d" | tr / _).yaml"
done
S="/opt/sast/venv/bin/semgrep scan --metrics=off --disable-version-check --no-git-ignore --json --quiet --timeout 30 --jobs 4"
$S $ORIG --output /out/orig.json python javascript typescript ai generic || true
$S --no-rewrite-rule-ids $MERGED --output /out/merged.json python javascript typescript ai generic || true
EOF
docker run --rm -e HOME=/opt/sast/home -v "$WORK/corpus:/corpus:ro" -v "$WORK/out:/out" \
  -v "$WORK/scan.sh:/scan.sh:ro" sast-semgrep-check sh /scan.sh

python3 - "$WORK/out" <<'EOF'
import collections, json, sys
out = sys.argv[1]

def keys(name, prefix):
    doc = json.load(open(f"{out}/{name}.json"))
    found = collections.Counter()
    for r in doc["results"]:
        cid = r["check_id"][len(prefix):] if r["check_id"].startswith(prefix) else r["check_id"]
        e = r["extra"]
        found[(cid, r["path"], r["start"]["line"], r["start"]["col"], r["end"]["line"], r["end"]["col"],
               e["severity"], e["message"], json.dumps(e["metadata"], sort_keys=True))] += 1
    return doc, found

orig_doc, orig = keys("orig", "opt.sast.rules.")
merged_doc, merged = keys("merged", "")
print(f"original: {sum(orig.values())} results, {len(orig_doc['errors'])} errors, "
      f"{len(orig_doc['paths']['scanned'])} files")
print(f"merged:   {sum(merged.values())} results, {len(merged_doc['errors'])} errors, "
      f"{len(merged_doc['paths']['scanned'])} files")
if orig != merged:
    for k in list((orig - merged) + (merged - orig))[:20]:
        print("DIFF", k[:5])
    sys.exit("merged rules do NOT give the same results")
print("identical")
EOF
