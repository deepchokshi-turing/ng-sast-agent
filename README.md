# sast-agents

Static-analysis scanners as Harbor agents, with no LLM. Each agent installs its
tool inside the task sandbox, scans `/app/repo`, and writes
`/app/output/findings.sarif` in the task's SARIF profile. The task's own verifier
(`tests/grade.py`) then scores it exactly as it scores an LLM agent.

| Agent | Import path | Status |
|---|---|---|
| Semgrep OSS 1.179.0 | `sast.semgrep.agent:SemgrepAgent` | ready |
| CodeQL CLI 2.27.1 | `sast.codeql.agent:CodeQLAgent` | ready: see [docs/codeql-agent.md](docs/codeql-agent.md) |
| SonarQube | `sast.sonarqube.agent:SonarQubeAgent` | planned |

The design, and the red-team review behind it, is in
[docs/semgrep-agent-plan.md](docs/semgrep-agent-plan.md).

## Register on ng-eval-platform

Settings → Agents → add a custom agent:

| Field | Value |
|---|---|
| Name | `semgrep-sast` |
| Display name | `Semgrep OSS 1.179.0` |
| Import path | `sast.semgrep.agent:SemgrepAgent` |
| Source | `git+https://github.com/<org>/<repo>@<commit sha>`. Pin a commit, not a branch |
| Public repository | on if the repo is public, so no token is sent |
| Delivers effort | leave `unknown` |

For CodeQL, add a second agent with name `codeql-sast`, display name
`CodeQL 2.27.1` and import path `sast.codeql.agent:CodeQLAgent`, from the same
source. Its bundle is about 650 MB, so task images should copy it from the
`sast-tools` image (below); installing it at setup takes about 100 s.

The platform fetches the repository at that commit and puts its root on Harbor's
`PYTHONPATH`. It installs nothing, so `sast/` imports only the standard library
and Harbor (`tests/test_imports.py` enforces this).

Every batch run needs a model with a project API key. Pick any enabled model:
the agent records it as `model_ignored` and never calls it.

## Run locally

```bash
uv sync
PYTHONPATH=$PWD .venv/bin/harbor run -y -p dev/tasks -n 4 -a sast.semgrep.agent:SemgrepAgent -o jobs/semgrep
python3 tools/report.py jobs/semgrep --tasks dev/tasks
```

Expected on the sample tasks (agent 0.2.0 checked in Harbor on 2026-10-07; the
0.3.0 figures come from grading the recorded Semgrep output in the unit tests):

| Task | Semgrep | Oracle | Why |
|---|---|---|---|
| `smoke_eval` | 0.40 | 1.0 | finds the `eval()`, so detection and classification score in full. Path, controls and recommendations score 0 by design (see "No dataflow trace" below), which makes 0.40 the scanner's ceiling on a task with full weights. Also checks that `excluded_paths` (`src/calc_agent/thirdparty`, which has its own `eval()`) is honoured, and that an unrelated `shell=True` helper outside `fix_changed_files` is `fp_outside_scope`, not a false positive. Tools pre-baked |
| `smoke_eval_twin` | 1.00 | 1.0 | fixed twin of `smoke_eval` with `fixed_locations`: nothing near the fixed code, the unrelated helper is `fp_outside_scope` (the old grader scored this 0). Tools pre-baked |
| `smoke_eval_node` | 0.40 (graded from the recorded output, not re-run in Harbor) | 1.0 | same, on a Node image whose python3 has no pip or venv (installs at setup) |
| `smoke_empty` | 1.00 | 1.0 | clean code, empty SARIF. Tools pre-baked |
| `task_7f3a91` | 0.00 | 1.0 | Semgrep reports only CSV injection (CWE-1236), outside the task's scope (installs at setup) |

These sample tasks are test fixtures for the agents, not dataset tasks. The
tracked copy lives in `tests/fixtures/tasks/`, and that is what the unit tests
read (a missing folder fails the run, it is never skipped). `dev/tasks/` is an
untracked local working area (in `.gitignore`). To use it, copy the fixtures
there first: `mkdir -p dev/tasks && cp -a tests/fixtures/tasks/. dev/tasks/`.
They use
grader v2 ([task_format/](task_format/README.md)): optional `fixed_locations`
for twins and `fix_changed_files` for positive tasks; without them a task is
graded exactly as by the original `grade.py`.

## Pre-built tools image

Installing at setup takes 40–100 s per trial, more on a slow network. Task
images can carry the tools instead:

```bash
tools/build_tools_image.sh                                  # local: sast-tools:<version>
tools/build_tools_image.sh --save amd64                     # file to hand over (also: arm64)
tools/build_tools_image.sh <region>-docker.pkg.dev/<project>/<repo>/sast-tools   # amd64+arm64, pushed
```

Without a registry, hand over the saved file for the receiver's CPU: `amd64`
for Intel/AMD machines and most Linux servers, `arm64` for Apple-silicon Macs.
They load it once:

```bash
docker load -i sast-tools_0.3.0_amd64.tar.gz    # gives the local tag sast-tools:0.3.0
```

After that, task Dockerfiles with `ARG SAST_TOOLS_IMAGE=sast-tools:0.3.0` build
locally as-is. This covers local `harbor run` only: Daytona can't see a loaded
image, so platform runs still install at setup until the image is in a registry.

Then, in each task's `environment/Dockerfile`:

```dockerfile
ARG SAST_TOOLS_IMAGE=<registry path>/sast-tools:0.3.0
FROM ${SAST_TOOLS_IMAGE} AS sast-tools

FROM python:3.11-slim            # the task's own base image, unchanged
COPY --from=sast-tools /opt/sast /opt/sast
# ... rest of the task's Dockerfile
```

The agent checks the copied install against its pins (`/opt/sast/install.json`,
the venv, the merged rules and `semgrep --version`). If they match it skips the
download, and setup takes seconds. If they don't match, or nothing was copied, it
installs as before. `/opt/sast` brings its own CPython, so it works on any base
image with glibc ≥ 2.34. Daytona must be able to pull the image, so it has to
live in a registry. A local `docker save` only helps local runs. The tag is the
agent version, read from `pyproject.toml` (the script stops if it differs from
`sast.__version__`), so bump both together and rebuild. The sample task
Dockerfiles pin `sast-tools:0.3.0`, and a unit test checks that they match the
agent version.

## What a run does

1. **setup** (inside the sandbox, ≤ 300 s; Harbor allows 360 s): uploads
   `install.py`, `merge_rules.py` and `pins.json` to `/opt/sast` (`/tmp/sast` if
   `/opt` isn't writable). `install.py` then:
   - downloads a pinned, sha256-checked `uv`;
   - creates a Python 3.12 venv with uv's own CPython and installs
     `semgrep==1.179.0`, with dependencies resolved as of 2026-10-07;
   - downloads semgrep-rules at `a84ff9cc2453`, keeps `python`, `javascript`,
     `typescript`, `ai` and `generic/secrets` (898 files, 949 rules), and checks
     their content hash;
   - merges the rule files into one file per folder.

   It needs `python3` (any 3.6+), glibc ≥ 2.34 or musl, and internet access.
   Typical time is 40–100 s, or a few seconds when the task image already
   carries `/opt/sast` (see above).
2. **run**:
   - reads `metadata.scanner_roots`, `metadata.excluded_paths`,
     `environment.cpus`/`memory_mb` and `agent.timeout_sec` from the task's
     `task.toml`;
   - runs one `semgrep scan --json .` from `/app/repo`, with each scan root as
     `--include /<root>` and each excluded path as `--exclude /<path>`. Semgrep
     anchors patterns to the scan target, so they must be anchored at the repo
     root (with root `src`, `--exclude src/x` silently matches nothing). A plain
     name like `tests` still means that name at any depth. Any finding Semgrep
     still reports outside that scope is dropped and counted
     (`findings_out_of_scope`). Semgrep's default `.semgrepignore` still applies
     (tests/, vendor/, node_modules/, ... are skipped), and compiled bytecode
     (`__pycache__/`, `*.pyc`, `*.pyo`) is always skipped: it's a build output,
     and task images that run tests or `compileall` are full of it;
   - runs without `--dataflow-traces` (see "No dataflow trace" below);
   - keeps `category: security` results and maps each one's CWE to a task ruleId
     ([sast/cwe_map.py](sast/cwe_map.py), `cwe-map-3`);
   - writes the SARIF, with the fields below.

### Decisions (all fixed before any results; see the plan for reasons)

- **CWE → ruleId** is assigned by what each CWE means, using the ruleId
  definitions the task format uses, never by task labels.
  - A finding uses its rule's **primary** CWE.
  - LLM02 covers disclosure *flows* only: exposure, logs, errors, sent data, and
    authorisation on data. Hard-coded secrets (CWE-798), weak transport or
    storage, and XXE aren't mapped.
  - Unmapped CWEs (XSS, crypto, CSRF, ...) are outside the five ruleIds and are
    not reported; they're still counted in the metadata.
- **LLM02 severity (cwe-map-3).** The CWE still picks the family. An LLM02
  result is `LLM02.SID.HIGH` when any of its CWEs is CWE-201, 918, 319, 532 or
  359 (weaknesses defined by data leaving its boundary). Otherwise it's
  `LLM02.SID.MEDIUM`. Before 0.3.0 every LLM02 result was HIGH.
- **No dataflow trace, so no `codeFlows`.** Semgrep OSS 1.179.0 gives no
  dataflow trace in its JSON output without a login. Tested on 2026-10-07 with
  an explicit taint rule under `--dataflow-traces`: the JSON had no
  `dataflow_trace` and `extra.lines` read "requires login", the SARIF output had
  no `codeFlows`, and only the plain-text output printed the trace. A code flow
  may only come from a trace the tool reported, and a one-step flow made from
  the match alone would earn path credit through the grader's line tolerance
  with nothing behind it. So the agent emits no `codeFlows`, does not pass
  `--dataflow-traces`, and the path sub-score is 0 for this agent by design.
- **`properties.cwe`** lists every CWE of every rule merged into the result, as
  `"CWE-<n>"`.
- **`controlStatus`, `residualRisk` and `recommendations` are reported apart
  and never scored.** They are heuristics, not semantic analysis
  ([sast/heuristics.py](sast/heuristics.py), `heuristics-1`), so they go under
  `properties.heuristics` (with the table `version`), not in the top-level
  `properties.controlStatus`, `residualRisk` and `recommendations` the grader
  reads. The controls and recommendations sub-scores are therefore 0 for this
  agent by design. A constant that matches the dataset's most common label would
  otherwise raise the score with nothing the tool found. The values, for anyone
  who wants a separate heuristic track:
  - `controlStatus` is always `none`. A taint rule does claim that (it reports a
    finding only when it saw no sanitiser), but a pattern or audit rule makes no
    claim about controls, so there it is only a default.
  - `residualRisk` is the rule's own rating: severity ERROR or `impact: HIGH`
    gives `high`, WARNING gives `medium`, INFO gives `low`. A merged result
    takes the highest.
  - `recommendations` come from a fixed table keyed by the emitted ruleId
    (HIGH: `REC-SINK-SIDE-IFC`, MEDIUM: `REC-SENSITIVE-DATA-FILTER`,
    FUNCTIONALITY: `REC-NARROW-TYPED-TOOLS`, PERMISSIONS: `REC-LEAST-PRIVILEGE`)
    plus a few CWE-specific ids within the same family (authorisation CWEs add
    `REC-AUTHZ-BEFORE-RETRIEVAL`, log/exposure CWEs add
    `REC-SENSITIVE-DATA-FILTER`, CWE-250 adds `REC-USER-SECURITY-CONTEXT`). Only
    ids from the task's catalogue are used. The per-rule pick is the author's
    choice of what fits a pattern finding. It does not follow the order the
    client spec lists the controls in.
  - All three were written before any results and are the same for every task.
- **Merged rule files.** Semgrep starts one `semgrep-core` process to validate
  *each* rule file. On a 1-CPU sandbox that took 244 s with 898 files, and 1.8 s
  with 5 merged files. Rule ids are set to what Semgrep would have reported, so
  results are unchanged: `tools/check_merged_rules.sh` compared all 6,191
  findings on the rules repo's own test corpus and they were identical.
- **Failures are errors, not zeroes.** An install failure, any Semgrep exit
  other than 0, unreadable output, out-of-memory, or a scan over its budget
  raises `ScannerError`. Semgrep writes `"results": []` even when it fails
  (exit 2, 7, ...), so the exit code decides, not the file. Harbor
  then skips the verifier and the platform shows the trial as errored, so it can
  be re-run. The scan budget is the agent timeout minus 120 s, because Harbor
  grades a trial that hits its own timeout as 0.
- **Unknown `--ak` keys are recorded, not rejected.** Harbor validates options
  once per job, so one stray key would fail every trial.

### Options (`--ak key=value`)

| Key | Default |
|---|---|
| `scan_roots` | task's `metadata.scanner_roots`, else the whole repo (comma-separated) |
| `exclude` | task's `metadata.excluded_paths` (comma-separated) |
| `jobs` | the sandbox's CPUs (task `cpus` or a job override), else `nproc` |
| `max_memory_mb` | per job: (sandbox memory − 512) ÷ jobs |
| `per_file_timeout_sec` | 30 |
| `scan_budget_sec` | task's agent timeout − 120 s (3600 s if the task sets none) |

The Semgrep version and the rules are pinned in
[sast/semgrep/pins.py](sast/semgrep/pins.py) and are not options.

## What the platform keeps from a trial

- `result.json` → `agent_result.metadata`: versions, rules digest, CWE map and
  heuristics versions, scan settings, counts (`results_raw`, `findings_security`,
  `findings_mapped`, `results_emitted`, `unmapped_by_cwe`), timings, and
  `findings_compact`. That last one lists every security finding (rule, CWEs,
  file, lines, emitted ruleId or null), capped at 5,000.
- `agent/setup/stdout.txt` holds the install log; `agent/command-1/stdout.txt`
  holds the scan command and its output.
- `artifacts/logs/artifacts/sast/` holds `semgrep.json` (Semgrep's raw output), `findings.sarif`,
  `metadata.json` and `install.log`. They're kept after a failed scan too.
- `verifier/*` holds the grader's reward and match details.

`tools/report.py <job dir> --tasks <tasks dir>` prints a per-trial table and,
as the headline for SAST, **detection pooled across tasks**:

- precision, recall and F1 from the verifier's tp/fp/fn;
- **location recall**: ground-truth findings with any security finding near them,
  mapped or not. This separates "looked at the right code" from "CWE on the other
  OWASP side";
- **location + acceptable-CWE recall**;
- zero-finding tasks with no false positive.

The composite task reward is shown too. For this agent the path, controls and
recommendations sub-scores are 0 by design (no trace, heuristics unscored), so
the reward measures detection and classification only.

## Sizing real tasks

Full langchain at a vulnerable commit (2,000 files), on 1 CPU / 2 GB: **173 s**
scan, **1.58 GB** peak memory, 84 security findings, 31 reported. For full-repo
tasks, give at least `memory_mb = 4096` and keep `agent.timeout_sec` well above
the expected scan time plus 120 s.

## Reading the results

- The real tasks are drawn from cases SAST already missed, so the numbers mean
  "Semgrep on SAST-hard GenAI cases", not a general SAST baseline.
- They aren't comparable with the earlier SAST sheet. That run scanned only the
  files each fix changed and matched by function and CWE family; Harbor scans the
  whole repo and matches by ±10 lines and OWASP prefix.
- On full repos, extra findings lower F1. A zero-finding (fixed-twin) task scores
  1.0 only if the SARIF is completely empty.

## Development

```bash
uv sync
.venv/bin/python -m pytest          # no Docker or Semgrep needed
tools/check_merged_rules.sh         # after changing pins.py; needs Docker
```

To change a pin, edit `pins.py`, recompute `RULES_DIGEST`/`RULES_FILE_COUNT`
when the rules change (`install.read_rules_archive` + `install.rules_digest`),
run both checks above, bump `sast.__version__`, and rebuild the tools image.
