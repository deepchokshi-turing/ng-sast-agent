#!/usr/bin/env bash
# Refresh the generated parts of one v4 task pair after a label edit (the explicit write step that
# qc_pair_v4.sh never does in tasker mode).
#
#   bash ng-sast-agent/tools/regen_pair_v4.sh <pair folder> [--check]
#   bash ng-sast-agent/tools/regen_pair_v4.sh <dataset> <family> [--check]
#
# <pair folder> holds <family>-a and <family>-b (a downloaded pair such as my_tasks/<family>); the
# family is the folder's name. On a scratch copy of the pair (with the VARIANTS entries and vocabulary
# qc_pair_v4.sh uses) it runs, in order:
#
#   tools/snippet_ids.py                 snippet_id and snippet_sha256 of every ground-truth location
#   tools/label_rules/sync_oracle.py     solution/findings.sarif follows the ground truth (no --overwrite)
#   tools/export_views.py --task a,b     task_metadata.json and tests/evaluator_view.json
#
# If every step succeeds, each file whose bytes changed is copied back into the pair and listed; nothing
# else in the pair is touched. If a step fails (for example sync_oracle.py needs a human decision), nothing
# is copied back. --check copies nothing and only lists the files that would change (exit 1 when any
# would). Run qc_pair_v4.sh afterwards.
set -uo pipefail

usage() { awk 'NR > 1 && !/^#/ { exit } NR > 1' "$0" | sed 's/^# \{0,1\}//'; exit 2; }
POS=(); CHECK=0
for arg in "$@"; do
  case "$arg" in
    --check) CHECK=1 ;;
    -*) usage ;;
    *) POS+=("$arg") ;;
  esac
done
case ${#POS[@]} in
  1) DATASET_IN="${POS[0]%/}"; FAM="" ;;
  2) DATASET_IN="${POS[0]}"; FAM="${POS[1]}" ;;
  *) usage ;;
esac

HERE="$(cd "$(dirname "$0")" && pwd)"; AG="$(dirname "$HERE")"; ROOT="$(dirname "$AG")"
if [ -d "$DATASET_IN" ]; then DATASET="$(cd "$DATASET_IN" && pwd)"
elif [ -d "$ROOT/$DATASET_IN" ]; then DATASET="$(cd "$ROOT/$DATASET_IN" && pwd)"
else echo "folder not found: $DATASET_IN" >&2; exit 2; fi
[ -n "$FAM" ] || FAM="$(basename "$DATASET")"
if [ -d "$DATASET/$FAM-a" ]; then TASKDIR="$DATASET"
else
  hits=(); for d in "$DATASET"/batch-*/; do [ -d "$d$FAM-a" ] && hits+=("${d%/}"); done
  [ ${#hits[@]} = 1 ] || { echo "family $FAM not found (or found more than once) in $DATASET" >&2; exit 2; }
  TASKDIR="${hits[0]}"
fi
A="$TASKDIR/$FAM-a"; B="$TASKDIR/$FAM-b"
for t in "$A" "$B"; do [ -f "$t/task.toml" ] || { echo "not a task: $t" >&2; exit 2; }; done
PY="$AG/.venv/Scripts/python.exe"; [ -x "$PY" ] || PY="$AG/.venv/bin/python"
[ -x "$PY" ] || { echo "no tooling venv: run 'uv sync' in $AG" >&2; exit 2; }
export PYTHONUTF8=1 PYTHONDONTWRITEBYTECODE=1

shared() { # shared <file name>: path in the pair's folder, else its parent, else empty
  if [ -f "$TASKDIR/$1" ]; then printf '%s' "$TASKDIR/$1"
  elif [ -f "$(dirname "$TASKDIR")/$1" ]; then printf '%s' "$(dirname "$TASKDIR")/$1"; fi
}
VARIANTS_FILE="$(shared VARIANTS.json)"; VOCAB_FILE="$(shared vocabulary.json)"
[ -n "$VOCAB_FILE" ] || VOCAB_FILE="$AG/task_format/vocabulary.json"

WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
S="$WORK/tasks"; mkdir -p "$S"
cp -r "$A" "$B" "$S/"
cp "$VOCAB_FILE" "$S/vocabulary.json"
"$PY" "$HERE/pair_variants.py" "$S" "$FAM" "$VARIANTS_FILE" || exit 2

step() { # step <label> <command...>
  echo "== $1"
  shift
  if ! "$@"; then echo "regen: '$*' failed; nothing was copied back" >&2; exit 1; fi
}
step "snippet ids and hashes" "$PY" "$HERE/snippet_ids.py" "$S" --task "$FAM-a" --task "$FAM-b"
step "oracle (sync_oracle.py)" "$PY" "$HERE/label_rules/sync_oracle.py" "$S" --task "$FAM-a" --task "$FAM-b"
step "views (export_views.py)" "$PY" "$HERE/export_views.py" "$S" --task "$FAM-a" --task "$FAM-b"

CHANGED="$("$PY" - "$S" "$TASKDIR" "$FAM" <<'EOF'
import filecmp, sys
from pathlib import Path
scratch, real, fam = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]
for side in ("a", "b"):
    s = scratch / f"{fam}-{side}"
    for p in sorted(s.rglob("*")):
        if not p.is_file() or "__pycache__" in p.parts:
            continue
        rel = p.relative_to(s)
        r = real / f"{fam}-{side}" / rel
        if not r.is_file() or not filecmp.cmp(p, r, shallow=False):
            print(f"{fam}-{side}/{rel.as_posix()}")
EOF
)"
if [ -z "$CHANGED" ]; then echo "regen: everything is current; nothing to change"; exit 0; fi
if [ "$CHECK" = 1 ]; then
  echo "regen --check: these files would change:"; printf '%s\n' "$CHANGED" | sed 's/^/  /'; exit 1
fi
FAILED=0
while IFS= read -r f; do
  mkdir -p "$(dirname "$TASKDIR/$f")" && cp "$S/$f" "$TASKDIR/$f" && echo "updated $f" || { echo "could not write $f" >&2; FAILED=1; }
done <<< "$CHANGED"
[ "$FAILED" = 0 ] || { echo "regen: some files were not written; fix the cause and rerun" >&2; exit 1; }
echo "regen: done; now run: bash ng-sast-agent/tools/qc_pair_v4.sh ${POS[*]}"
