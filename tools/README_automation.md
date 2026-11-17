# Task pair automation (v4)

Three steps turn a slot of the plan workbook into a registered v4 task pair: scaffold, build, QC. The tools do the mechanical parts (fetching upstream code, laying out the two task folders, ids, ground-truth and oracle skeletons, every check that can be run); the builder does the creative part (trimming the code, stand-ins for third-party libraries, the manifest and fixtures, labels, repro tests).

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
| `--dataset` | Dataset directory, relative to the repository root (default `tasks`); created with `VARIANTS.json` and a copy of `_poc/harbor-tasks/vocabulary.json` if missing. The family goes into the batch folder that `<dataset>/BATCHES.json` gives for the slot (`batch-1` … `batch-10`, `batch-buffer`, `batch-extra`); passing a batch folder such as `tasks/batch-2` also works if it is the slot's batch. A dataset with no `BATCHES.json` and no `batch-*` folders is flat (old layout); `--flat` forces it |
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

The dataset can be `tasks` (the script finds the batch that holds the family) or a batch folder such as `tasks/batch-2`. Writes `<batch>/<family>/_work/qc.md` (summary table first, details below) and exits 1 on any FAIL. The checks run on copies. When there is no FAIL, the script then writes the `qc` block (tool, date, result, report) into both twins' `validation/provenance.json`, regenerates their views and re-runs the checks that read them (`post-*` rows); if one of those fails, the files are restored. `--no-write-provenance` skips that step.

| Check | Pass condition |
|---|---|
| todo | No `TODO` and no `_todo` left in the task files the scaffold wrote (repo code is not searched) |
| grader-image | The `FROM` of `tests/Dockerfile` exists locally (else `sast-grader:3` is tagged to it, else pulled) |
| check-truth | `/opt/grader/grade --check-truth --repo` in the grader image, no network, both twins |
| snippet-ids | `tools/snippet_ids.py --check` |
| oracle | `solution/findings.sarif` scores 1.0 on both twins (grader image) |
| empty-sarif | An empty SARIF scores 0 on the positive and 1.0 on the negative |
| twin-swap | The positive's oracle scores 0 against the negative's truth |
| leak-scan | `tools/leak_scan.py` on the pair (VARIANTS entries and vocabulary of the dataset) |
| export-views | `tools/export_views.py --check` |
| twin-diff | `environment/` of the twins differs exactly in the positive's `fix_changed_files` (WARN when a listed file is identical) |
| instruction | Twins byte-identical; identical to the v4 template except the scope sentence, which must match task.toml (WARN otherwise) |
| harbor-lint | `harbor lint` on both, no findings |
| repro | `validation/repro_test.py` of each twin passes on its own code and fails on the twin's, `--network none`, in `python:3.12-slim` (Python) or in the twin's own environment image (other languages) |
| harbor-run | Harbor 0.25 local run: oracle 1.0 on both, nop 0.0 on both (no SARIF is no answer) |
| clean-build | Optional: `tools/check_clean_build.py` (build, test, entrypoint in fresh no-network containers) |

The Harbor run uses scratch copies whose task.toml drops the `[agent]` allowlist and sets `[verifier.environment] network_mode = "public"`: this machine's Docker Desktop WSL2 kernel lacks `CONFIG_NFT_FIB_INET`, so Harbor's docker environment cannot enforce `no-network` / `allowlist` and rejects the tasks as written. Network isolation is not verified locally; qc.md says so.

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

- `vocabulary.json` (copied from the POC) lists only `python` under `languages` and only the POC frameworks. The language templates write `typescript`, `go`, `java`, `csharp` and `rust`, which leak_scan rejects until the dataset's vocabulary.json is extended (a controlled-vocabulary decision, not made by the tool). Java/Kotlin slots get `java` and `TypeScript/JavaScript` slots get `typescript`; change them per task when the code is Kotlin or JavaScript.
- `instruction.md` is the v4 template (`common/instruction.md`, the pilot's text) with its scope sentence written from the language's `scanner_roots` and the merged `excluded_paths`, in the wording QC expects. When the builder changes `scanner_roots` / `excluded_paths` in task.toml (they usually do: upstream layouts rarely match the defaults), they edit that sentence the same way in both twins; QC reports a mismatch as WARN.
- Upstream paths (for example `ag2/tools/...`) rarely match the default `scanner_roots` (`src`, ...). The builder either keeps the upstream layout and changes the roots or re-roots the code and remaps the prefilled locations.
- The default family name is a heuristic; pass `--family-name` for anything that will be kept.
- Repro tests for non-Python twins run inside the twin's environment image, which needs the tools image tag locally; the repro template is Python and drives the language toolchain through subprocess.

## Windows note

When applying `_work/fix.diff` with `git apply` on Windows, git may write CRLF line endings into the patched files. Convert them back to LF (for example with `dos2unix`) before running QC, so the twin diff stays limited to the fix.
