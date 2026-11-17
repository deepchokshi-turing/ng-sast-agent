# Task pair automation (v4)

Three steps turn a slot of the plan workbook into a registered v4 task pair: scaffold, build, QC. Taskers who download a pair from the platform only need [QC of a downloaded pair](#qc-of-a-downloaded-pair-taskers). The tools do the mechanical parts (fetching upstream code, laying out the two task folders, ids, ground-truth and oracle skeletons, every check that can be run); the builder does the creative part (trimming the code, stand-ins for third-party libraries, the manifest and fixtures, labels, repro tests).

The reference for the layout is the pilot pair `pilot_v4/crewai-file-writer-a` / `-b` (see `pilot_v4/README.md`): separate verifier built from `tests/Dockerfile` on the `sast-grader:3` image, `artifacts = ["/app/output"]`, no-network verifier, agent allowlist, `.harborignore` / `.dockerignore`, `[task]` authors and keywords.

## Setup

```bash
cd ng-sast-agent && uv sync            # tooling venv: ng-sast-agent/.venv
uv tool install harbor==0.26.0         # only if `harbor --version` fails
gh auth status                         # advisory text and licence come from the GitHub API
```

`scaffold_pair.py` uses only the standard library plus openpyxl when it is installed (it falls back to a small stdlib reader of the workbook, so the venv's Python works too). `qc_pair_v4.sh` needs Git Bash (or bash), Docker, the venv and the Harbor CLI. Locally, the grader image tag `us-central1-docker.pkg.dev/turing-delivery-rl-gym/daytona/sast-grader:3` and the tools image tag `.../sast-tools:0.5.0` must exist (`grader_image/build.sh`, and `docker load` + `docker tag` of the handoff tarball; see `grader_image/README.md`, "Local fallback").

## 1. Scaffold

```bash
python ng-sast-agent/tools/scaffold_pair.py --slot P001 --family-name ag2-shell-newline --dataset tasks
```

| Option | Meaning |
|---|---|
| `--slot` | Plan slot id (sheet "Task slots" of `planning/SAST_500_Plan.xlsx`) |
| `--family-name` | Kebab-case family name. Default: the repo's short name plus two words of the Weakness (purpose-built slots: `pb-` plus two words), made unique in the dataset. Words that leak_scan bans in task.toml (injection, traversal, bypass, ...) or role words are never used |
| `--dataset` | Dataset directory, relative to the repository root (default `tasks`); created with `VARIANTS.json` and a copy of `ng-sast-agent/task_format/vocabulary.json` if missing. The family goes into the batch folder that `<dataset>/BATCHES.json` gives for the slot (`batch-1` … `batch-10`, `batch-buffer`, `batch-extra`); passing a batch folder such as `tasks/batch-2` also works if it is the slot's batch. A dataset with no `BATCHES.json` and no `batch-*` folders is flat (old layout); `--flat` forces it |
| `--batch` | Put the family in this batch folder instead of the one `BATCHES.json` gives (needed for a slot the map doesn't list, or to move a buffer pair into the batch it replaces) |
| `--plan` | Another workbook |
| `--force` | Rewrite an existing family. Keeps its opaque ids from `VARIANTS.json`; everything else, including `_work/`, is regenerated |

What it writes:

```
<dataset>/
├── VARIANTS.json                  # evaluator-only: folder -> family, family_id, role, twin, task_id, variant_id, slot
├── vocabulary.json                # controlled values (copied once)
├── BATCHES.json                   # slot -> build batch (25 pairs each, from the 250 plan sheet)
└── batch-N/                       # one folder per build batch; every family below lives in one
├── <family>/_work/                # builder's workbench, never shipped
│   ├── upstream-positive/         # tree at the fix's parent (type A / B upstream fix) or at Base commit (B designed)
│   ├── upstream-negative/         # tree at the fix commit (only when the slot has one)
│   ├── fix.diff, fix_files.txt    # git diff <positive> <fix>; status, +/- per file
│   ├── base_to_fix.diff           # only when the plan's Base commit is not the fix's parent
│   ├── slot.json                  # plan row, advisory (gh api), commit metadata, warnings
│   └── BUILD_TODO.md              # checklist generated from the slot
├── <family>-a/                    # positive
└── <family>-b/                    # negative (minimal contrast)
    ├── task.toml                  # v4 + spec 5.2 fields; identical in both twins except task_id, variant_id, related_variant_ids (and [task].name)
    ├── instruction.md             # byte-identical copy of the pilot's
    ├── README.md                  # evaluator-only notes (template)
    ├── environment/Dockerfile     # literal digest-pinned FROM of sast-tools + digest-pinned language base
    ├── environment/repo/          # security_manifest.json skeleton (+ language skeleton for type C)
    ├── tests/                     # Dockerfile, test.sh, .dockerignore, .harborignore (pilot), ground_truth.json (gt-0.2 skeleton), evaluator_view.json (placeholder)
    ├── solution/                  # solve.sh, .harborignore (pilot), findings.sarif (oracle skeleton with findingId)
    └── validation/                # provenance.json, repro_test.py (templates)
```

Per slot type:

- **A real advisory / B upstream fix** (fix commit present): partial clone into `<root>/.cache/repos/<owner>__<repo>` (`git clone --filter=blob:none --no-checkout`, reused, missing commits fetched by sha). The positive tree is the fix's first parent; the tool warns (in its output, `slot.json` and `BUILD_TODO.md`) when that is not the plan's Base commit. Both trees are exported with `git archive` (missing blobs fetched in one batch first) and unpacked by Python: no checkout, no hooks, no filters (LFS files stay pointers), no eol conversion, no export-ignore; symlinks and names Windows cannot hold are skipped and listed under "Export notes". The fix's hunks prefill `fix_changed_files` (source files only, tests and docs are listed but left out), the negative's `fixed_locations` (new side, one per hunk) and a hint for the positive's `primary_location` (the largest changed range); every hunk is tabulated in BUILD_TODO.md.
- **B designed control** (no fix commit): Base commit exported to `upstream-positive/` only; the Negative design goes to BUILD_TODO.md and to the ground truth's `evidence.design`.
- **C purpose-built**: no repository; both twins' `environment/repo/` start from the language skeleton in `task_format/templates/v4/skeletons/<lang>/`.

Filled from the plan: rule ids from Subtype(s) (one finding per subtype, excessive agency first, linked with `ea_exposes_sid` when Linked is yes), risk types, `control_status` (partial or none; a partial control adds a `control_point` path step and a `partial` control), the negative's `contrast_rule_ids`, `controls`, N1 minimal contrast and an N2 trap template, labelling-policy defaults for `partial_credit_rule_ids`, recommendations and severity, CWEs from the advisory (and the Weakness text), excluded paths (plan list, notes in parentheses dropped, plus the language defaults), `source_origin`, `repository_id`, difficulty (Scanner difficulty), licence (GitHub API), advisory id/URL/CVE/fixed versions in provenance. Opaque ids: `task_` + 8 random hex per folder, `fam_` + 4 hex per family, the positive's `var_a` / `var_b` drawn at random.

Language templates (`task_format/templates/v4/languages.json`, `dockerfiles/`, `skeletons/`): Python (the pilot's Dockerfile and python:3.12-slim digest), TypeScript and JavaScript (node:24-bookworm-slim, Node 24.22.2; plan `TypeScript/JavaScript` or `TypeScript` maps to `typescript`, `JavaScript` to `javascript`; TypeScript runs directly through Node 24's type stripping, and `build_command` is `node scripts/check-syntax.mjs src`, a helper the scaffold copies into `environment/repo/scripts/` for every slot kind via the language's `repo_files`, which type-strips each `.ts` file with `stripTypeScriptTypes` and syntax-checks it, because `node --check` does not strip types), Go (golang:1.25-bookworm, Go 1.25.14), Java/Kotlin (eclipse-temurin:21-jdk-noble, plain javac), C# (dotnet/sdk:8.0-bookworm-slim, SDK 8.0.427), Rust (rust:1.90-slim-bookworm, Rust 1.90.0). Every base is pinned by the index digest resolved on 2026-11-06 with `docker buildx imagetools inspect`. Non-Python bases install Debian/Ubuntu `python3` because the scanner agents need it in the task image (apt is not snapshot-pinned: marked TODO in the Dockerfile, noted without a TODO in the Node one). Builds and tests run offline, so dependencies must be stood in or vendored.

## 2. Build (manual)

Follow `<dataset>/<family>/_work/BUILD_TODO.md`. In short: trim the upstream tree into `-a/environment/repo/` keeping upstream paths and line numbers of the fix files, replace third-party imports with small stand-ins, copy to `-b` and apply only the fix hunks (or the designed control), write the manifest and fixtures (identical in both twins), finish task.toml (frameworks, exact package_versions, architecture, commands, roots), the ground truth, the oracle, the repro tests, provenance and README. Then:

```bash
cd ng-sast-agent
python tools/snippet_ids.py ../tasks --task <family>-a --task <family>-b
python tools/label_rules/sync_oracle.py ../tasks --task <family>-a --task <family>-b
python tools/export_views.py ../tasks --task <family>-a --task <family>-b
```

By default `sync_oracle.py` only fills oracle values that are missing or placeholders (plus the parts the ground truth always decides: `findingId`, `codeFlows`, `controlStatus`, `residualRisk`, recommendations cut to the finding's ids, and a location outside `line_tolerance`); a present value that has gone stale after a label edit is kept. Add `--overwrite` to also replace stale values: a `ruleId` that is not the finding's `rule_id` (negative: not in `contrast_rule_ids`), a `level` other than `error` (negative: `note`), a primary location that is not exactly the finding's `primary_location` or an alternative (negative: the control's `at`), CWEs outside `primary_cwe`/`acceptable_cwes`, and bare driver rule entries no result names. Every present value it replaces is printed as `old -> new`; with `--check` it prints them and writes nothing. Message texts are never overwritten. Run `--overwrite --check` first to see what would move.

## 3. QC

```bash
bash ng-sast-agent/tools/qc_pair_v4.sh tasks <family> [--skip-docker] [--skip-harbor] [--clean-build] [--no-write-provenance]
```

This is lead mode: the script picks it when `<batch>/<family>/_work/slot.json` exists (the scaffold writes it). Without that file, or with `--tasker`, it runs in tasker mode (next section). The dataset can be `tasks` (the script finds the batch that holds the family) or a batch folder such as `tasks/batch-2`. Writes `<batch>/<family>/_work/qc.md` (summary table first, details below) and exits 1 on any FAIL. The checks run on copies. When there is no FAIL, the script then writes the `qc` block (tool, date, result, report) into both twins' `validation/provenance.json`, regenerates their views and re-runs the checks that read them (`post-*` rows); if one of those fails, the files are restored. `--no-write-provenance` skips that step.

| Check | Pass condition |
|---|---|
| todo | No `TODO` and no `_todo` left in the task files the scaffold wrote (repo code is not searched) |
| grader-image | The `FROM` of `tests/Dockerfile` exists locally (else `sast-grader:3` is tagged to it, else pulled) |
| check-truth | `/opt/grader/grade --check-truth --repo` in the grader image, no network, both twins |
| snippet-ids | `tools/snippet_ids.py --check` |
| oracle | `solution/findings.sarif` scores 1.0 on both twins (grader image) |
| empty-sarif | An empty SARIF scores 0 on the positive and 1.0 on the negative |
| twin-swap | The positive's oracle scores 0 against the negative's truth |
| leak-scan | `tools/leak_scan.py` on the pair (VARIANTS entries and vocabulary of the dataset; banned words in unchanged upstream code are cleared with the `_work/upstream-*` trees) |
| export-views | `tools/export_views.py --check` |
| twin-diff | `environment/` of the twins differs exactly in the positive's `fix_changed_files` (WARN when a listed file is identical) |
| instruction | Twins byte-identical; identical to the v4 template except the scope sentence, which must match task.toml (WARN otherwise) |
| harbor-lint | `harbor lint` on both, no findings |
| repro | `validation/repro_test.py` of each twin passes on its own code and fails on the twin's, `--network none`, in `python:3.12-slim` (Python) or in the twin's own environment image (other languages) |
| harbor-run | Harbor 0.26 local run: oracle 1.0 on both, nop 0.0 on both (no SARIF is no answer). The script exports `PROMPTFOO_TOKEN` (empty unless already set), which Harbor needs to start a trial |
| clean-build | Optional: `tools/check_clean_build.py` (build, test, entrypoint in fresh no-network containers) |

The Harbor run uses scratch copies whose task.toml drops the `[agent]` allowlist and sets `[verifier.environment] network_mode = "public"`: this machine's Docker Desktop WSL2 kernel lacks `CONFIG_NFT_FIB_INET`, so Harbor's docker environment cannot enforce `no-network` / `allowlist` and rejects the tasks as written. Network isolation is not verified locally; qc.md says so.

The script checks first that Docker is running (`docker info`) and stops with a message if it is not; `--skip-docker` runs only the checks that need no Docker.

## QC of a downloaded pair (taskers)

A pair downloaded from the eval platform is two folders, `<family>-a` and `<family>-b`, with no `_work/`, `VARIANTS.json` or `vocabulary.json`. Put them in a folder named after the family (for example `my_tasks/<family>/<family>-a` and `my_tasks/<family>/<family>-b`), start Docker Desktop, and from the repository root run in Git Bash:

```bash
bash ng-sast-agent/tools/qc_pair_v4.sh my_tasks/<family> --clean-build
```

That is the whole command: nothing has to be copied in and no environment variable has to be set. Prerequisites are the same as for the lead (Setup above): the tooling venv (`uv sync` in `ng-sast-agent`), Harbor 0.26.0, Docker Desktop running and the grader image tag present.

Tasker mode is chosen automatically because the download has no `<family>/_work/slot.json` (`--tasker` forces it). In tasker mode the script:

- never modifies the two task folders: every check runs on copies, no `qc` block is written to `provenance.json`, no view is regenerated, and the last check (`read-only`) compares a SHA-256 of every file in both folders before and after the run and FAILs if anything changed;
- writes its report to `my_tasks/<family>/qc/qc.md` (when the folder holding the pair is not named after the family: `<folder>/qc/<family>/qc.md`); the console shows the FAIL, WARN and SKIP rows;
- reads `vocabulary.json` from the pair's folder or its parent when present, else the copy shipped in `ng-sast-agent/task_format/vocabulary.json`;
- takes the pair's `VARIANTS.json` entries (opaque task ids, roles, twin) from a `VARIANTS.json` in the pair's folder or its parent when it lists both twins, else from each twin's own `tests/evaluator_view.json` (`variant_map_entry`), else from `task.toml` (a = positive); the report's "Mode" line says which;
- runs the leak scan with `--warn-unverified-upstream` (below).

What each row of the report means for a tasker:

| Check | What it tells you | If it is not PASS |
|---|---|---|
| todo | No scaffold placeholder (`TODO`, `_todo`) is left in the task files | Report it: the pair was shipped unfinished |
| grader-image | The grader image named in `tests/Dockerfile` is available locally | Build or load it (`grader_image/README.md`); the grading checks below are skipped until then |
| check-truth | Every ground-truth location points at real lines, and each line hash still matches the code | A label points at the wrong lines, or the code changed under it |
| snippet-ids | Every location's `snippet_id` and `snippet_sha256` are current | After a label edit: run `regen_pair_v4.sh` (below) |
| oracle | The reference answer `solution/findings.sarif` scores 1.0 on both versions | The answer key and the reference answer disagree |
| empty-sarif | No answer scores 0 on -a (vulnerable) and 1.0 on -b (fixed) | The answer keys do not separate the versions |
| twin-swap | -a's reference answer scores 0 against -b's answer key | -b would reward reporting the fixed bug |
| leak-scan | No label text reaches what a scanner can see (banned words, ground-truth prose, evaluator files, twin differences, task.toml ids and vocabulary) | FAIL: a real leak to report. WARN: see below |
| export-views | `task_metadata.json` and `tests/evaluator_view.json` are what `export_views.py` writes from the current files | After a label edit: run `regen_pair_v4.sh` |
| twin-diff | `environment/` of the two versions differs exactly in the fix files the answer key lists | The versions differ in more than the fix (or not at all) |
| instruction-twins / instruction-template | `instruction.md` is identical in both versions and matches the template, scope sentence included | WARN: the scope sentence does not match `scanner_roots` / `excluded_paths` |
| harbor-lint | `harbor lint` finds nothing | Read the findings in the report |
| repro | Each version's `validation/repro_test.py` passes on its own code and fails on the other's, with no network | The repro tests do not show the contrast |
| harbor-run | A local Harbor 0.26 run scores the reference answer 1.0 and an empty agent 0.0 on both versions | Read the log tails in the report |
| clean-build | With `--clean-build`: build, tests and entrypoint pass in fresh no-network containers | The task does not build or run from its own files |
| read-only | The run left both task folders byte for byte as they were | A tooling bug: report it |

**Leak-scan WARN.** The lead's build keeps the unmodified upstream trees in `<family>/_work/`, and the leak scan uses them to clear banned words (`fixed`, `patch`, `bypass`, ...) that sit in unchanged upstream code. A download has no such trees, so with `--warn-unverified-upstream` a banned word in `environment/repo/` code outside comments, or in a repo file path, is a warning instead of a FAIL. Each warning ends with a link to the same file and line at the upstream commit (`source_url` and `source_commit` of `validation/provenance.json`). Open it: if the line is the same upstream, the hit is fine; if the line is task-authored, report it as a leak. Hits in comments, docstrings, prose files and everything outside `environment/repo/` are still a FAIL, exactly as in the lead's run.

**After editing labels.** QC never writes into the pair. When you have edited `tests/ground_truth.json` (or the code under a label), refresh the generated parts explicitly, then run QC again:

```bash
bash ng-sast-agent/tools/regen_pair_v4.sh my_tasks/<family> --check
bash ng-sast-agent/tools/regen_pair_v4.sh my_tasks/<family>
```

`regen_pair_v4.sh` works on a scratch copy and runs `tools/snippet_ids.py` (snippet ids and hashes), `tools/label_rules/sync_oracle.py` (the reference answer follows the answer key; no `--overwrite`) and `tools/export_views.py` (both views). Only when all three succeed does it copy back the files whose bytes changed, and it lists each one; `--check` only lists them and exits 1 when any would change. If a step needs a human decision (for example `sync_oracle.py` cannot fill a value), nothing is copied back.

## 4. Register

Not automated. When qc.md has no FAIL: record the QC outcome in each `validation/provenance.json` (`qc`, `review.annotator_labels`; `tools/leak_scan.py --write-qc` and `tools/check_clean_build.py --write` fill their parts), mark the slot as built in the plan workbook, and commit the two task folders plus the dataset's `VARIANTS.json` entries. `_work/` (upstream trees, diffs, qc.md) is the builder's record and is not part of the published dataset; neither are `VARIANTS.json`, the task READMEs, `tests/`, `solution/` or `validation/` when the set is shown to scanners.

## Automated vs manual

| Automated | Manual |
|---|---|
| Reading the slot, fetching both upstream trees, the fix diff, files and hunks, advisory text, licence, commit metadata | Choosing what to keep, trimming, keeping line numbers, stand-ins for libraries |
| Both task folders in the v4 layout, ids, VARIANTS.json, vocabulary copy | The application around the path (purpose-built slots) and the designed negative (B designed) |
| task.toml with every plan-decided field, language Dockerfile with pinned bases | frameworks, package_versions, architecture, final commands and scanner roots |
| Ground-truth skeleton: findings per subtype, linkage, control status, policy defaults, fix-derived locations; negative contrast, controls, fixed locations | Final locations, path steps, rationale, affected asset, violates, evidence, traps |
| Oracle skeleton (with `findingId`, so `sync_oracle.py` can rebuild it) | Oracle messages; the check that the oracle scores 1.0 is automated |
| Provenance skeleton (source, commits, licence, advisory, lineage, review block) | modifications, upstream_files, beyond_upstream_fix, package_versions |
| Repro-test, README and manifest templates | Their content |
| Every mechanical check (QC) and the local Harbor oracle/nop run | Reviewing qc.md, network-policy verification on the platform, registration |

## Known gaps

- `ng-sast-agent/task_format/vocabulary.json` is a copy of `tasks/vocabulary.json`; when the dataset's vocabulary changes, copy it again (`tests/test_tasker_qc.py` fails while they differ). Java/Kotlin slots get `java` and `TypeScript/JavaScript` slots get `typescript`; change them per task when the code is Kotlin or JavaScript.
- `instruction.md` is the v4 template (`common/instruction.md`, the pilot's text) with its scope sentence written from the language's `scanner_roots` and the merged `excluded_paths`, in the wording QC expects. When the builder changes `scanner_roots` / `excluded_paths` in task.toml (they usually do: upstream layouts rarely match the defaults), they edit that sentence the same way in both twins; QC reports a mismatch as WARN.
- Upstream paths (for example `ag2/tools/...`) rarely match the default `scanner_roots` (`src`, ...). The builder either keeps the upstream layout and changes the roots or re-roots the code and remaps the prefilled locations.
- The default family name is a heuristic; pass `--family-name` for anything that will be kept.
- Repro tests for non-Python twins run inside the twin's environment image, which needs the tools image tag locally; the repro template is Python and drives the language toolchain through subprocess.

## Windows note

When applying `_work/fix.diff` with `git apply` on Windows, git may write CRLF line endings into the patched files. Convert them back to LF (for example with `dos2unix`) before running QC, so the twin diff stays limited to the fix.
