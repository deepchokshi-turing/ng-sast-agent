#!/usr/bin/env bash
# Mechanical QC of one v4 task pair (port of _poc/SAST_QC/run_mechanical_qc.sh for the v4 layout).
#
#   bash ng-sast-agent/tools/qc_pair_v4.sh <dataset> <family> [--skip-docker] [--skip-harbor] [--clean-build]
#                                          [--no-write-provenance]
#
# <dataset> is the dataset root (tasks/, whose batch-N/ folders hold the families) or one batch
# folder (tasks/batch-N), or an old flat dataset; relative paths are tried from the current
# directory, then from the repository root. The family's folder holding <family>-a (positive),
# <family>-b (negative) and <family>/_work is <dataset>/<family>-a if present, else the one
# <dataset>/batch-*/ that holds it (none or several is an error). VARIANTS.json and
# vocabulary.json are read from that folder, else its parent. Writes <family>/_work/qc.md and
# exits 1 when any check FAILs. Runs in Git Bash on Windows (docker volume paths go through
# cygpath) and in plain bash elsewhere.
#
# Checks: leftover TODO markers; grader image present (registry tag, else local sast-grader:3);
# check_truth in the grader image; snippet ids; oracle reward 1.0 on both; empty SARIF 0 / 1.0;
# twin swap 0; leak scan; export_views --check; twin diff of environment/ against
# fix_changed_files; instruction.md identity (twins, template, scope sentence); harbor lint;
# repro tests own-pass / twin-fail with no network; a local Harbor run of oracle and nop on
# scratch copies whose network policy is forced to public (see the note in the output).
# --clean-build adds tools/check_clean_build.py (build, test and entrypoint in fresh containers).
#
# All checks run on copies in a temp directory. When no check FAILs, the script then records
# the run in the "qc" object of both twins' validation/provenance.json (keys tool, date (UTC
# day), result, report; other qc keys and the rest of the file are kept byte for byte),
# regenerates both twins' views (task_metadata.json, tests/evaluator_view.json, which embed
# provenance) with tools/export_views.py, and re-runs the checks that read provenance or the
# views (TODO markers, leak scan, export_views --check) on fresh copies; their result is part
# of qc.md, and if one fails the three files are restored. Rerunning on an unchanged pair
# changes nothing but the date. --no-write-provenance leaves the task files untouched.
set -uo pipefail

usage() { awk 'NR > 1 && !/^#/ { exit } NR > 1' "$0" | sed 's/^# \{0,1\}//'; exit 2; }
[ $# -ge 2 ] || usage
DATASET_IN="$1"; FAM="$2"; shift 2
SKIP_DOCKER=0; SKIP_HARBOR=0; CLEAN_BUILD=0; WRITE_PROV=1
FLAGS="$*"
for arg in "$@"; do
  case "$arg" in
    --skip-docker) SKIP_DOCKER=1; SKIP_HARBOR=1 ;;
    --skip-harbor) SKIP_HARBOR=1 ;;
    --clean-build) CLEAN_BUILD=1 ;;
    --no-write-provenance) WRITE_PROV=0 ;;
    *) usage ;;
  esac
done

HERE="$(cd "$(dirname "$0")" && pwd)"; AG="$(dirname "$HERE")"; ROOT="$(dirname "$AG")"
if [ -d "$DATASET_IN" ]; then DATASET="$(cd "$DATASET_IN" && pwd)"
elif [ -d "$ROOT/$DATASET_IN" ]; then DATASET="$(cd "$ROOT/$DATASET_IN" && pwd)"
else echo "dataset not found: $DATASET_IN" >&2; exit 2; fi
# The folder that holds the pair: the dataset itself (flat or a batch folder), else one batch-*/.
if [ -d "$DATASET/$FAM-a" ] || [ -d "$DATASET/$FAM-b" ]; then TASKDIR="$DATASET"
else
  hits=(); for d in "$DATASET"/batch-*/; do [ -d "$d$FAM-a" ] && hits+=("${d%/}"); done
  if [ ${#hits[@]} = 0 ]; then echo "family $FAM not found in $DATASET or its batch-*/ folders" >&2; exit 2; fi
  if [ ${#hits[@]} -gt 1 ]; then echo "family $FAM is in several batch folders: ${hits[*]}" >&2; exit 2; fi
  TASKDIR="${hits[0]}"
fi
shared() { # shared <file name>: path in the task folder, else its parent, else empty
  if [ -f "$TASKDIR/$1" ]; then printf '%s' "$TASKDIR/$1"
  elif [ -f "$(dirname "$TASKDIR")/$1" ]; then printf '%s' "$(dirname "$TASKDIR")/$1"; fi
}
VARIANTS_FILE="$(shared VARIANTS.json)"; VOCAB_FILE="$(shared vocabulary.json)"
A="$TASKDIR/$FAM-a"; B="$TASKDIR/$FAM-b"
for t in "$A" "$B"; do [ -f "$t/task.toml" ] || { echo "not a task: $t" >&2; exit 2; }; done
PY="$AG/.venv/Scripts/python.exe"; [ -x "$PY" ] || PY="$AG/.venv/bin/python"
[ -x "$PY" ] || { echo "no tooling venv: run 'uv sync' in $AG" >&2; exit 2; }
export PYTHONUTF8=1 PYTHONDONTWRITEBYTECODE=1
TEMPLATE_INSTRUCTION="$AG/task_format/templates/v4/common/instruction.md"
LANGS_JSON="$AG/task_format/templates/v4/languages.json"
OUTDIR="$TASKDIR/$FAM/_work"; mkdir -p "$OUTDIR"; OUT="$OUTDIR/qc.md"

WORK="$(mktemp -d)"
cleanup() {
  rm -rf "$WORK"
  [ -n "${QC_IMAGES:-}" ] && docker image rm -f $QC_IMAGES >/dev/null 2>&1
  return 0
}
trap cleanup EXIT
winpath() { if command -v cygpath >/dev/null 2>&1; then cygpath -w "$1"; else printf '%s' "$1"; fi; }
drun() { MSYS_NO_PATHCONV=1 docker run --rm "$@"; }

BODY="$WORK/body.md"; : > "$BODY"; SUMMARY="$WORK/summary.tsv"; : > "$SUMMARY"
FAILS=0
section() { printf '\n## %s\n\n' "$1" >> "$BODY"; }
say() { printf '%s\n' "$*" >> "$BODY"; }
block() { { echo '```'; cat; echo '```'; } >> "$BODY"; }
record() { # record STATUS step detail
  printf '%s\t%s\t%s\n' "$1" "$2" "$3" >> "$SUMMARY"
  printf -- '- **%s** %s\n' "$1" "$3" >> "$BODY"
  [ "$1" = FAIL ] && FAILS=$((FAILS + 1))
  return 0
}

# Scratch dataset (flat): the two tasks, a two-entry VARIANTS.json and the vocabulary.
make_scratch() { # make_scratch <dir>
  mkdir -p "$1"
  cp -r "$A" "$B" "$1/"
  if [ -n "$VOCAB_FILE" ]; then cp "$VOCAB_FILE" "$1/"
  elif [ -f "$ROOT/_poc/harbor-tasks/vocabulary.json" ]; then cp "$ROOT/_poc/harbor-tasks/vocabulary.json" "$1/"; fi
  "$PY" - "$1" "$FAM" "$VARIANTS_FILE" <<'EOF'
import json, sys, tomllib
from pathlib import Path
root, fam = Path(sys.argv[1]), sys.argv[2]
names = (f"{fam}-a", f"{fam}-b")
known = {}
f = Path(sys.argv[3]) if sys.argv[3] else None
if f and f.is_file():
    known = json.loads(f.read_text(encoding="utf-8"))
if all(n in known for n in names):
    v = {n: known[n] for n in names}
else:
    v = {}
    for letter, role, twin in (("a", "positive", "b"), ("b", "negative", "a")):
        meta = tomllib.loads((root / f"{fam}-{letter}" / "task.toml").read_text(encoding="utf-8"))["metadata"]
        v[f"{fam}-{letter}"] = {"family": fam, "family_id": meta.get("family_id"), "role": role,
                                "twin": f"{fam}-{twin}", "task_id": meta.get("task_id"),
                                "variant_id": meta.get("variant_id")}
    print("VARIANTS.json has no entries for this pair; synthesised them from task.toml (a = positive)")
(root / "VARIANTS.json").write_text(json.dumps(v, indent=2), encoding="utf-8")
EOF
}
make_scratch "$WORK/tasks"
WA="$WORK/tasks/$FAM-a"; WB="$WORK/tasks/$FAM-b"

# Small JSON readers.
jget() { "$PY" -c "import json,sys;d=json.load(open(sys.argv[1],encoding='utf-8'));print(eval(sys.argv[2],{'d':d}))" "$@" 2>/dev/null; }
reward_of() { [ -f "$1" ] && jget "$1" "d.get('reward')" || echo "missing"; }

GRADER="$(sed -n 's/^FROM[[:space:]]\{1,\}\([^[:space:]]*\).*/\1/p' "$A/tests/Dockerfile" | head -1)"
LANG_KEY="$("$PY" - "$A/task.toml" "$LANGS_JSON" <<'EOF'
import json, sys, tomllib
langs = tomllib.load(open(sys.argv[1], "rb")).get("metadata", {}).get("languages") or []
table = json.load(open(sys.argv[2], encoding="utf-8"))
for key, spec in table.items():
    if not key.startswith("_") and any(l in spec["vocabulary"] for l in langs):
        print(key); break
else:
    print("python")
EOF
)"

# --------------------------------------------------------------------------------------------
todo_hits() { # todo_hits <task dir>...
  "$PY" - "$@" <<'EOF'
import json, sys
from pathlib import Path
files = ["task.toml", "instruction.md", "README.md", "environment/Dockerfile", "environment/repo/security_manifest.json",
         "tests/ground_truth.json", "solution/findings.sarif", "validation/provenance.json", "validation/repro_test.py"]
for t in map(Path, sys.argv[1:]):
    for rel in files:
        p = t / rel
        if not p.is_file():
            continue
        text = p.read_text(encoding="utf-8", errors="replace")
        n = text.count("TODO")
        if rel == "tests/ground_truth.json" and "_todo" in json.loads(text):
            print(f"{t.name}/{rel}: _todo key present")
        if n:
            print(f"{t.name}/{rel}: {n} TODO marker(s)")
EOF
}
section "Builder TODO markers (task files outside environment/repo code)"
TODO_HITS="$(todo_hits "$A" "$B")"
if [ -z "$TODO_HITS" ]; then record PASS todo "no TODO markers or _todo keys left"
else record FAIL todo "TODO markers left (the scaffold's placeholders):"; printf '%s\n' "$TODO_HITS" | block; fi

# --------------------------------------------------------------------------------------------
section "Grader image"
GRADER_OK=0
if [ "$SKIP_DOCKER" = 1 ]; then record SKIP grader-image "--skip-docker"
elif docker image inspect "$GRADER" >/dev/null 2>&1; then
  GRADER_OK=1; record PASS grader-image "\`$GRADER\` present locally ($(docker image inspect -f '{{.Id}}' "$GRADER" | cut -c1-19), version $(drun --network none "$GRADER" cat /opt/grader/VERSION 2>/dev/null))"
elif docker image inspect sast-grader:3 >/dev/null 2>&1; then
  docker tag sast-grader:3 "$GRADER" && GRADER_OK=1
  record PASS grader-image "tagged local \`sast-grader:3\` as \`$GRADER\` (Harbor's build does not pull, so the local tag satisfies FROM)"
elif docker pull -q "$GRADER" >/dev/null 2>&1; then
  GRADER_OK=1; record PASS grader-image "pulled \`$GRADER\`"
else
  record FAIL grader-image "\`$GRADER\` not available (build it with ng-sast-agent/grader_image/build.sh or docker load + tag); grader checks skipped"
fi

grade() { # grade <task dir> <sarif path (host)> <out dir (host)> [truth task dir]
  local task="$1" sarif="$2" out="$3" truth="${4:-$1}"
  mkdir -p "$out"; chmod 777 "$out" 2>/dev/null
  cp "$sarif" "$out/in.sarif"
  drun --network none -v "$(winpath "$truth"):/t:ro" -v "$(winpath "$out"):/o" "$GRADER" \
    /opt/grader/grade --sarif /o/in.sarif --truth /t/tests/ground_truth.json --out /o >/dev/null 2>"$out/stderr.txt"
}

section "check_truth (grader image)"
if [ "$GRADER_OK" = 1 ]; then
  for t in a b; do
    d="$WORK/tasks/$FAM-$t"
    res="$(drun --network none -v "$(winpath "$d"):/t:ro" "$GRADER" /opt/grader/grade --check-truth --truth /t/tests/ground_truth.json --repo /t/environment/repo 2>&1)"; rc=$?
    if [ $rc = 0 ]; then record PASS "check-truth-$t" "$t: $(printf '%s' "$res" | tail -1)"
    else record FAIL "check-truth-$t" "$t: exit $rc"; printf '%s\n' "$res" | tail -25 | block; fi
  done
else record SKIP check-truth "no grader image"; fi

section "Snippet ids and hashes (tools/snippet_ids.py --check)"
res="$("$PY" "$HERE/snippet_ids.py" "$WORK/tasks" --check 2>&1)"; rc=$?
if [ $rc = 0 ]; then record PASS snippet-ids "up to date"; else record FAIL snippet-ids "out of date or unreadable"; fi
printf '%s\n' "$res" | block

section "Oracle SARIF reward (must be 1.0 on both)"
if [ "$GRADER_OK" = 1 ]; then
  for t in a b; do
    d="$WORK/tasks/$FAM-$t"; grade "$d" "$d/solution/findings.sarif" "$WORK/or-$t"
    r="$(reward_of "$WORK/or-$t/reward.json")"
    detail="$(jget "$WORK/or-$t/reward.json" "{k: d.get(k) for k in ('reward','tp','fp','fn','neg.controls','sarif_missing','grader_error') if k in d}")"
    if [ "$r" = "1.0" ] || [ "$r" = "1" ]; then record PASS "oracle-$t" "$t: reward $r $detail"
    else record FAIL "oracle-$t" "$t: reward $r $detail $(tail -3 "$WORK/or-$t/stderr.txt" 2>/dev/null | tr '\n' ' ')"; fi
  done
else record SKIP oracle "no grader image"; fi

section "Empty SARIF (positive must be 0, negative 1.0)"
printf '{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"empty"}},"results":[]}]}' > "$WORK/empty.sarif"
if [ "$GRADER_OK" = 1 ]; then
  grade "$WA" "$WORK/empty.sarif" "$WORK/em-a"; ra="$(reward_of "$WORK/em-a/reward.json")"
  grade "$WB" "$WORK/empty.sarif" "$WORK/em-b"; rb="$(reward_of "$WORK/em-b/reward.json")"
  if { [ "$ra" = "0.0" ] || [ "$ra" = "0" ]; } && { [ "$rb" = "1.0" ] || [ "$rb" = "1" ]; }; then record PASS empty-sarif "a: $ra, b: $rb"
  else record FAIL empty-sarif "a: $ra (want 0), b: $rb (want 1.0)"; fi
else record SKIP empty-sarif "no grader image"; fi

section "Twin swap (positive oracle graded against the negative's truth must be 0)"
if [ "$GRADER_OK" = 1 ]; then
  grade "$WB" "$WA/solution/findings.sarif" "$WORK/sw" "$WB"; r="$(reward_of "$WORK/sw/reward.json")"
  buckets="$(jget "$WORK/sw/reward.json" "{k: v for k, v in d.items() if k.startswith('neg.fail')}")"
  if [ "$r" = "0.0" ] || [ "$r" = "0" ]; then record PASS twin-swap "reward $r, buckets $buckets"
  else record FAIL twin-swap "reward $r (want 0), buckets $buckets"; fi
  grade "$WA" "$WB/solution/findings.sarif" "$WORK/sw2" "$WA"; r2="$(reward_of "$WORK/sw2/reward.json")"
  say "- info: negative oracle graded against the positive's truth: reward $r2 (a complete-control claim matches no finding, so expect 0)"
else record SKIP twin-swap "no grader image"; fi

section "Leak scan (tools/leak_scan.py)"
# Unmodified upstream trees (from scaffold_pair.py): banned words in unchanged upstream code are not hits.
UPSTREAM_ARGS=()
for side in positive negative; do
  u="$OUTDIR/upstream-$side"
  [ -d "$u" ] && UPSTREAM_ARGS+=(--upstream "$FAM-a=$(winpath "$u")" --upstream "$FAM-b=$(winpath "$u")")
done
say "- info: upstream trees for the leak scan: $(( ${#UPSTREAM_ARGS[@]} / 4 )) of 2 found in _work/"
res="$("$PY" "$HERE/leak_scan.py" "$WORK/tasks" "${UPSTREAM_ARGS[@]}" 2>&1)"; rc=$?
if [ $rc = 0 ]; then record PASS leak-scan "no problems"; else record FAIL leak-scan "problems found"; fi
printf '%s\n' "$res" | block

section "Views (tools/export_views.py --check)"
res="$("$PY" "$HERE/export_views.py" "$WORK/tasks" --check 2>&1)"; rc=$?
if [ $rc = 0 ]; then record PASS export-views "views current, proof passes"; else record FAIL export-views "stale view or proof failure (run tools/export_views.py <dataset> --task ...)"; fi
printf '%s\n' "$res" | block

section "Twin diff of environment/ (must be exactly the positive's fix_changed_files)"
res="$("$PY" - "$WA" "$WB" <<'EOF'
import filecmp, json, sys
from pathlib import Path
a, b = Path(sys.argv[1]), Path(sys.argv[2])
def files(root):
    return {p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file() and "__pycache__" not in p.parts}
ea, eb = files(a / "environment"), files(b / "environment")
diff = sorted(p for p in ea | eb if p not in ea or p not in eb or not filecmp.cmp(a / "environment" / p, b / "environment" / p, shallow=False))
fix = set(json.loads((a / "tests" / "ground_truth.json").read_text(encoding="utf-8")).get("fix_changed_files") or [])
in_repo = {p[len("repo/"):] for p in diff if p.startswith("repo/")}
outside = [p for p in diff if not p.startswith("repo/")]
extra = sorted(in_repo - fix)
unchanged = sorted(fix - in_repo)
for p in diff:
    print(f"differs: environment/{p}")
status = "PASS"
if outside or extra or not diff:
    status = "FAIL"
elif unchanged:
    status = "WARN"
print(f"STATUS {status} {len(diff)} file(s) differ; outside repo/: {outside or 'none'}; not in fix_changed_files: {extra or 'none'}; listed but identical: {unchanged or 'none'}")
EOF
)"
line="$(printf '%s\n' "$res" | grep '^STATUS' | tail -1)"; st="$(echo "$line" | awk '{print $2}')"
record "${st:-FAIL}" twin-diff "$(echo "$line" | cut -d' ' -f3-)"
printf '%s\n' "$res" | grep -v '^STATUS' | block

section "instruction.md"
if cmp -s "$A/instruction.md" "$B/instruction.md"; then record PASS instruction-twins "byte-identical in both twins"
else record FAIL instruction-twins "the twins' instruction.md differ"; diff "$A/instruction.md" "$B/instruction.md" | head -20 | block; fi
res="$("$PY" - "$A" "$TEMPLATE_INSTRUCTION" <<'EOF'
import sys, tomllib
from pathlib import Path
task, template = Path(sys.argv[1]), Path(sys.argv[2])
meta = tomllib.loads((task / "task.toml").read_text(encoding="utf-8")).get("metadata", {})
roots, excl = meta.get("scanner_roots") or [], meta.get("excluded_paths") or []
q = lambda xs: ", ".join(f"`{x}`" for x in xs)
expected = f"Only these paths under `/app/repo` are in scope: {q(roots)}."
if excl:
    expected += f" Inside them, {q(excl)} {'is' if len(excl) == 1 else 'are'} out of scope."
mine = (task / "instruction.md").read_text(encoding="utf-8").splitlines()
tmpl = template.read_text(encoding="utf-8").splitlines()
scope_mine = next((l for l in mine if l.startswith("Only these paths under")), "")
other_diff = [i for i, (x, y) in enumerate(zip(mine, tmpl)) if x != y and not x.startswith("Only these paths under")]
if len(mine) != len(tmpl):
    other_diff.append(-1)
identical = mine == tmpl
scope_ok = scope_mine.startswith(expected)
if other_diff:
    print(f"STATUS FAIL differs from the v4 template outside the scope sentence (lines {[i + 1 for i in other_diff if i >= 0]})")
elif not scope_ok:
    print("STATUS WARN the scope sentence does not match task.toml scanner_roots/excluded_paths"
          + (" (it is still the pilot's)" if identical else ""))
    print(f"expected: {expected} ...")
    print(f"actual:   {scope_mine}")
else:
    print("STATUS PASS " + ("identical to the v4 template" if identical else "v4 template with this task's scope sentence"))
EOF
)"
line="$(printf '%s\n' "$res" | grep '^STATUS' | tail -1)"; st="$(echo "$line" | awk '{print $2}')"
record "${st:-FAIL}" instruction-template "$(echo "$line" | cut -d' ' -f3-)"
printf '%s\n' "$res" | grep -v '^STATUS' | sed 's/^/    /' >> "$BODY"

section "harbor lint"
if command -v harbor >/dev/null 2>&1; then
  res="$(harbor lint "$A" "$B" 2>&1)"; rc=$?
  if [ $rc = 0 ]; then record PASS harbor-lint "no findings ($(harbor --version 2>/dev/null))"; else record FAIL harbor-lint "findings (exit $rc)"; fi
  [ -n "$res" ] && printf '%s\n' "$res" | tail -30 | block
else record FAIL harbor-lint "harbor CLI not found (uv tool install harbor==0.26.0)"; fi

# --------------------------------------------------------------------------------------------
section "Repro tests, no network (own code must pass, twin code must fail)"
if [ "$SKIP_DOCKER" = 1 ]; then record SKIP repro "--skip-docker"
else
  RUNNER="$("$PY" -c "import json,sys;print(json.load(open(sys.argv[1]))[sys.argv[2]]['repro_runner'])" "$LANGS_JSON" "$LANG_KEY" 2>/dev/null || echo python:3.12-slim)"
  declare -A IMG
  for t in a b; do
    if [ "$RUNNER" = image ]; then
      IMG[$t]="qc-$FAM-$t:latest"
      if docker build -q -t "${IMG[$t]}" "$WORK/tasks/$FAM-$t/environment" > "$WORK/build-$t.log" 2>&1; then QC_IMAGES="${QC_IMAGES:-} ${IMG[$t]}"
      else IMG[$t]=""; fi
    else IMG[$t]="$RUNNER"; fi
  done
  say "Runner: \`$RUNNER\` (language \`$LANG_KEY\`; \`image\` = each twin's own environment image)."
  say ""
  for t in a b; do
    o=$([ $t = a ] && echo b || echo a)
    for code in $t $o; do
      img="${IMG[$code]}"
      if [ -z "$img" ]; then record FAIL "repro-$t-on-$code" "tests of $t on code of $code: environment image of $code did not build ($(tail -2 "$WORK/build-$code.log" | tr '\n' ' '))"; continue; fi
      rm -rf "$WORK/r"; mkdir -p "$WORK/r/environment"
      cp -r "$WORK/tasks/$FAM-$code/environment/repo" "$WORK/r/environment/repo"
      cp -r "$WORK/tasks/$FAM-$t/validation" "$WORK/r/validation"
      out="$(drun --network none -v "$(winpath "$WORK/r"):/w" -w /w "$img" sh -c "python3 -B validation/repro_test.py 2>&1; echo EXIT=\$?" 2>&1)"
      rc="$(printf '%s\n' "$out" | sed -n 's/^EXIT=//p' | tail -1)"
      tail="$(printf '%s\n' "$out" | grep -v '^EXIT=' | tail -3 | tr '\n' ' ')"
      if [ "$code" = "$t" ]; then
        if [ "$rc" = 0 ]; then record PASS "repro-$t-own" "tests of $t on its own code pass: $tail"
        else record FAIL "repro-$t-own" "tests of $t on its own code fail (exit ${rc:-?}): $tail"; fi
      else
        if [ -n "$rc" ] && [ "$rc" != 0 ]; then record PASS "repro-$t-twin" "tests of $t on the code of $o fail as they must: $tail"
        else record FAIL "repro-$t-twin" "tests of $t on the code of $o pass (exit ${rc:-?}): no contrast. $tail"; fi
      fi
    done
  done
fi

# --------------------------------------------------------------------------------------------
section "Local Harbor run: oracle and nop (network policy forced to public)"
say "This machine's Docker Desktop WSL2 kernel lacks CONFIG_NFT_FIB_INET, so Harbor 0.25's docker environment cannot enforce \`no-network\` or \`allowlist\` and rejects the tasks as written. These runs use scratch copies whose task.toml drops the \`[agent]\` allowlist and sets \`[verifier.environment] network_mode = \"public\"\`; everything else (Dockerfiles, artifacts, separate verifier, grader image) runs as committed. Network isolation itself is therefore NOT verified here (see pilot_v4/README.md)."
say ""
if [ "$SKIP_HARBOR" = 1 ]; then record SKIP harbor-run "--skip-harbor or --skip-docker"
elif ! command -v harbor >/dev/null 2>&1; then record FAIL harbor-run "harbor CLI not found"
else
  H="$WORK/harbor"; mkdir -p "$H/tasks" "$H/jobs"
  cp -r "$WA" "$WB" "$H/tasks/"
  "$PY" - "$H/tasks/$FAM-a/task.toml" "$H/tasks/$FAM-b/task.toml" <<'EOF'
import re, sys
for f in sys.argv[1:]:
    text = open(f, encoding="utf-8").read()
    out, section, skip = [], None, False
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("[") and not s.startswith("[["):
            section = s
        if skip:
            if s.startswith("]"):
                skip = False
            continue
        if section == "[agent]" and re.match(r"(network_mode|allowed_hosts)\s*=", s):
            skip = s.startswith("allowed_hosts") and "]" not in s
            continue
        if section == "[verifier.environment]" and re.match(r"network_mode\s*=", s):
            line = 'network_mode = "public"'
        out.append(line)
    open(f, "w", encoding="utf-8", newline="\n").write("\n".join(out) + "\n")
EOF
  export PROMPTFOO_TOKEN="${PROMPTFOO_TOKEN-}"
  hrun() { # job agent path n
    (cd "$H" && PYTHONUTF8=1 harbor run -y -q -p "$3" -a "$2" -e docker -o jobs --job-name "$1" -n "$4") > "$H/$1.log" 2>&1
  }
  hrun oracle-a oracle "tasks/$FAM-a" 1
  hrun oracle-b oracle "tasks/$FAM-b" 1
  hrun nop-ab nop "tasks" 2
  res="$("$PY" - "$H/jobs" "$FAM" <<'EOF'
import json, sys
from pathlib import Path
jobs, fam = Path(sys.argv[1]), sys.argv[2]
want = {("oracle-a", "a"): 1.0, ("oracle-b", "b"): 1.0, ("nop-ab", "a"): 0.0, ("nop-ab", "b"): 0.0}
got = {}
for res in jobs.glob("*/*/result.json"):
    job = res.parent.parent.name
    d = json.loads(res.read_text(encoding="utf-8"))
    name = str(d.get("task_name") or res.parent.name)
    side = "a" if f"{fam}-a" in name or name.endswith("-a") else "b" if f"{fam}-b" in name or name.endswith("-b") else "?"
    rewards = (d.get("verifier_result") or {}).get("rewards") or {}
    exc = (d.get("exception_info") or {}).get("exception_type")
    got[(job, side)] = (rewards.get("reward"), exc)
ok = True
for key, w in want.items():
    r, exc = got.get(key, (None, "no trial result"))
    good = r is not None and float(r) == w
    ok &= good
    print(f"{'ok ' if good else 'BAD'} {key[0]} {key[1]}: reward {r} (want {w}){' exception ' + exc if exc else ''}")
print("STATUS", "PASS" if ok else "FAIL")
EOF
)"
  line="$(printf '%s\n' "$res" | grep '^STATUS' | tail -1)"; st="$(echo "$line" | awk '{print $2}')"
  record "${st:-FAIL}" harbor-run "oracle a/b must be 1.0, nop a/b 0.0 (nop on the negative is 0: no SARIF is no answer)"
  printf '%s\n' "$res" | grep -v '^STATUS' | block
  if [ "$st" != PASS ]; then for j in oracle-a oracle-b nop-ab; do say "\`$j\` log tail:"; tail -15 "$H/$j.log" | block; done; fi
fi

if [ "$CLEAN_BUILD" = 1 ] && [ "$SKIP_DOCKER" = 0 ]; then
  section "Clean build (tools/check_clean_build.py, no network)"
  res="$("$PY" "$HERE/check_clean_build.py" "$WORK/tasks" --jobs 2 2>&1)"; rc=$?
  if [ $rc = 0 ]; then record PASS clean-build "build, test and entrypoint pass in fresh containers"; else record FAIL clean-build "see output"; fi
  printf '%s\n' "$res" | tail -12 | block
fi

# --------------------------------------------------------------------------------------------
# Record the run in both twins' provenance (only when nothing FAILed), regenerate the views that
# embed provenance, and re-run the checks that read either on fresh copies. The block's result
# counts the checks above only, so it does not depend on itself and a rerun writes the same bytes.
N_CHECKS="$(awk -F'\t' '$1 != "SKIP"' "$SUMMARY" | wc -l | tr -d ' ')"
N_WARN="$(awk -F'\t' '$1 == "WARN"' "$SUMMARY" | wc -l | tr -d ' ')"
N_SKIP="$(awk -F'\t' '$1 == "SKIP"' "$SUMMARY" | wc -l | tr -d ' ')"
QC_RESULT="no FAIL, $([ "$N_WARN" = 0 ] && echo "no WARN" || echo "$N_WARN WARN") ($N_CHECKS checks$([ "$N_SKIP" = 0 ] || echo ", $N_SKIP skipped"))"
QC_TOOL="${HERE#"$ROOT"/}/$(basename "$0")${FLAGS:+ $FLAGS}"
case "$OUT" in "$ROOT"/*) QC_REPORT="${OUT#"$ROOT"/}" ;; *) QC_REPORT="$OUT" ;; esac
QC_DATE="$(date -u +%Y-%m-%d)"
PROV_FILES=(validation/provenance.json task_metadata.json tests/evaluator_view.json)
if [ "$WRITE_PROV" = 0 ]; then PROV_NOTE="not written (--no-write-provenance)"
elif [ "$FAILS" != 0 ]; then PROV_NOTE="not written: the checks above have a FAIL"
else
  section "Provenance qc block (validation/provenance.json of both twins) and re-checks"
  for t in a b; do for f in "${PROV_FILES[@]}"; do
    mkdir -p "$WORK/backup/$t/$(dirname "$f")"
    [ -f "$TASKDIR/$FAM-$t/$f" ] && cp -p "$TASKDIR/$FAM-$t/$f" "$WORK/backup/$t/$f"
  done; done
  restore() {
    for t in a b; do for f in "${PROV_FILES[@]}"; do
      [ -f "$WORK/backup/$t/$f" ] && cp -p "$WORK/backup/$t/$f" "$TASKDIR/$FAM-$t/$f"
    done; done
  }
  res="$("$PY" - "$QC_TOOL" "$QC_DATE" "$QC_RESULT" "$QC_REPORT" "$A/validation/provenance.json" "$B/validation/provenance.json" <<'EOF' 2>&1
import json, sys
from pathlib import Path
tool, date, result, report, *files = sys.argv[1:]
block = {"tool": tool, "date": date, "result": result, "report": report}
def dump_like(raw: str, data) -> str:
    """Serialise data in raw's style (indent, ASCII escaping, trailing newline), as snippet_ids.py does."""
    lines = raw.split("\n")
    indent = len(lines[1]) - len(lines[1].lstrip(" ")) if len(lines) > 1 else 2
    return json.dumps(data, indent=indent or 2, ensure_ascii=raw.isascii()) + ("\n" if raw.endswith("\n") else "")
bad = 0
for f in map(Path, files):
    name = f"{f.parent.parent.name}/{f.parent.name}/{f.name}"
    if not f.is_file():
        print(f"{name}: missing"); bad = 1; continue
    raw = f.read_bytes().decode("utf-8")
    data = json.loads(raw)
    qc = data.setdefault("qc", {})
    if not isinstance(qc, dict):
        print(f"{name}: qc is not an object; left unchanged"); bad = 1; continue
    qc.update(block)  # existing keys keep their place, new ones go last
    new = dump_like(raw, data)
    if new == raw:
        print(f"{name}: qc block already current")
    else:
        f.write_bytes(new.encode("utf-8"))
        print(f"{name}: qc block written")
sys.exit(bad)
EOF
)"; rc=$?
  say "Block: \`$(printf '{"tool": "%s", "date": "%s", "result": "%s", "report": "%s"}' "$QC_TOOL" "$QC_DATE" "$QC_RESULT" "$QC_REPORT")\`"
  say ""
  printf '%s\n' "$res" | block
  if [ $rc != 0 ]; then
    restore; record FAIL provenance-write "could not write the qc block; task files restored"
    PROV_NOTE="not written: writing failed"
  else
    # The views embed provenance: regenerate them on a scratch copy (same VARIANTS entries as the
    # checks above) and copy the two files back, so they match what export_views.py <batch> writes.
    make_scratch "$WORK/regen" >/dev/null
    res="$("$PY" "$HERE/export_views.py" "$WORK/regen" --task "$FAM-a" --task "$FAM-b" 2>&1)"; rc=$?
    if [ $rc = 0 ]; then
      for t in a b; do for f in task_metadata.json tests/evaluator_view.json; do
        cmp -s "$WORK/regen/$FAM-$t/$f" "$TASKDIR/$FAM-$t/$f" || cp "$WORK/regen/$FAM-$t/$f" "$TASKDIR/$FAM-$t/$f"
      done; done
      record PASS post-export-views "views regenerated (tools/export_views.py --task $FAM-a --task $FAM-b)"
    else record FAIL post-export-views "tools/export_views.py could not regenerate the views"; fi
    printf '%s\n' "$res" | block
    # Re-run the checks that read provenance.json or the views, on fresh copies of the task files.
    make_scratch "$WORK/post" >/dev/null
    hits="$(todo_hits "$WORK/post/$FAM-a" "$WORK/post/$FAM-b")"
    if [ -z "$hits" ]; then record PASS post-todo "no TODO markers after the write"
    else record FAIL post-todo "TODO markers after the write"; printf '%s\n' "$hits" | block; fi
    res="$("$PY" "$HERE/leak_scan.py" "$WORK/post" "${UPSTREAM_ARGS[@]}" 2>&1)"; rc=$?
    if [ $rc = 0 ]; then record PASS post-leak-scan "no problems after the write"; else record FAIL post-leak-scan "problems after the write"; printf '%s\n' "$res" | block; fi
    res="$("$PY" "$HERE/export_views.py" "$WORK/post" --check 2>&1)"; rc=$?
    if [ $rc = 0 ]; then record PASS post-export-views-check "views current after the write"; else record FAIL post-export-views-check "views stale or proof failure after the write"; printf '%s\n' "$res" | block; fi
    if [ "$FAILS" != 0 ]; then
      restore; PROV_NOTE="written, then restored (with the views) because a re-check after the write failed"
    else
      PROV_NOTE="qc block (result \"$QC_RESULT\", which counts the checks before the post-* re-checks) written to both twins' validation/provenance.json and their views regenerated; the re-checks pass"
    fi
  fi
fi

# --------------------------------------------------------------------------------------------
{
  echo "# Mechanical QC (v4): $FAM"
  echo
  echo "Run $(date -u +%Y-%m-%dT%H:%MZ) on \`$TASKDIR\` by \`$QC_TOOL\`. Grader image \`$GRADER\`. Language \`$LANG_KEY\`."
  echo
  echo "| Status | Check | Detail |"
  echo "|---|---|---|"
  while IFS=$'\t' read -r st step detail; do
    printf '| %s | %s | %s |\n' "$st" "$step" "$(printf '%s' "$detail" | sed 's/|/\|/g' | cut -c1-220)"
  done < "$SUMMARY"
  echo
  echo "Result: $([ "$FAILS" = 0 ] && echo "no FAIL" || echo "$FAILS FAIL")."
  echo
  echo "Provenance: $PROV_NOTE."
  cat "$BODY"
} > "$OUT"
echo "wrote $OUT ($FAILS FAIL)"
echo "provenance: $PROV_NOTE"
grep -E '^\| (FAIL|WARN|SKIP) ' "$OUT" || true
[ "$FAILS" = 0 ]
