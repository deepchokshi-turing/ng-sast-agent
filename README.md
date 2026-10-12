# sast-agents

Security scanners as Harbor agents. Semgrep, CodeQL and SonarQube are static
analysis with no LLM. The Claude Code security review agent is the exception: it
calls an Anthropic model to do the review. Each agent installs its
tool inside the task sandbox, scans `/app/repo`, and writes
`/app/output/findings.sarif` in the task's SARIF profile. The task's own verifier
(`tests/grade.py`) then scores it exactly as it scores an LLM agent.

| Agent | Import path | Status |
|---|---|---|
| Semgrep OSS 1.179.0 | `sast.semgrep.agent:SemgrepAgent` | ready |
| CodeQL 2.27.1 (research use only) | `sast.codeql.agent:CodeQLAgent` | ready, run with Harbor on the 0.5.0 image (see [CodeQL agent](#codeql-agent)) |
| SonarQube (server you host) | `sast.sonarqube.agent:SonarQubeAgent` | ready, run with Harbor against SonarQube Community Build 26.9 (see [SonarQube agent](#sonarqube-agent)) |
| Claude Code security review (anthropics/claude-code-security-review at 0c6a49f, calls a model) | `sast.claude_review.agent:ClaudeReviewAgent` | unit-tested with fakes, not yet run against the real API (see [Claude Code security review agent](#claude-code-security-review-agent)) |

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

Expected on the sample tasks (agent 0.2.0 checked in Harbor on 2026-10-07. The
other figures come from grading the recorded Semgrep output in the unit tests,
which still pass at 0.4.0):

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
docker load -i sast-tools_0.5.0_amd64.tar.gz    # gives the local tag sast-tools:0.5.0
```

After that, task Dockerfiles with `ARG SAST_TOOLS_IMAGE=sast-tools:0.5.0` build
locally as-is. This covers local `harbor run` only: Daytona can't see a loaded
image, so platform runs still install at setup until the image is in a registry.

Then, in each task's `environment/Dockerfile`:

```dockerfile
ARG SAST_TOOLS_IMAGE=<registry path>/sast-tools:0.5.0
FROM ${SAST_TOOLS_IMAGE} AS sast-tools

FROM python:3.11-slim            # the task's own base image, unchanged
COPY --from=sast-tools /opt/sast /opt/sast
# ... rest of the task's Dockerfile
```

The agent checks the copied install against its pins (`/opt/sast/install.json`,
the venv, the merged rules and `semgrep --version`). If they match it skips the
download, and setup takes seconds. If they don't match, or nothing was copied, it
installs as before. `/opt/sast` brings its own CPython, so it works on any base
image with glibc ≥ 2.34. The image also holds the CodeQL 2.27.1 bundle at
`/opt/sast/codeql` (the linux64 bundle on amd64, the linux-arm64 bundle on
arm64, each checked against its sha256 in `sast/codeql/pins.py` while the image
builds) and sonar-scanner. Daytona must be able to pull the image, so it has to
live in a registry. A local `docker save` only helps local runs. The tag is the
agent version, read from `pyproject.toml` (the script stops if it differs from
`sast.__version__`), so bump both together and rebuild. The sample task
Dockerfiles pin `sast-tools:0.5.0`, and a unit test checks that they match the
agent version.

The image holds `/opt/sast/MANIFEST.json`, written by the last build stage
with [sast/manifest.py](sast/manifest.py). It lists the tool versions from
the pins, a sha256 and mode for every file, one tree digest over all files,
and one tree digest per tool. The CodeQL bundle, sonar-scanner, uv and the
Semgrep rules are checked against pinned hashes during the build. The Semgrep
wheel, its dependencies and uv's CPython are only resolved with
`--exclude-newer`, so the manifest is the record of what was actually
installed. At setup each agent records the manifest's own sha256, the image
tree digest and its tool's tree digest in the run metadata
(`image_manifest`). Semgrep and sonar-scanner hash their own files again and
say whether they match (`status` `verified` or `mismatch`). Measured with a
cold cache, that takes about 1.5 s for Semgrep's venv and CPython (400 MB,
7,400 files) and under 7 s for a full 286 MB JDK, which is more than the
scanner's bundled JRE. CodeQL's bundle (1.3 GB, 35,000 files) took 60 s, so
the CodeQL agent records the digest without hashing again
(`not_recomputed`). A mismatch is recorded, not fatal: the version and pin
checks still decide whether a tool is used.

### Leak check of the built image

`tools/leak_scan.py <harbor-tasks dir>` checks the task sources. With
`--image` it builds each task image and checks what is under `/app` in it:

```bash
python tools/leak_scan.py ../harbor-tasks --image --task task_04d646_positive --task task_04d646_negative
```

It needs only Python and the docker CLI, so the same line works in Windows
PowerShell with Docker Desktop. The tools image named by the Dockerfile's
`ARG SAST_TOOLS_IMAGE=` default (or `--tools-image <image>`) must be present
locally. It removes the images it builds. See the script's docstring for the
checks.

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
     ([sast/cwe_map.py](sast/cwe_map.py), `cwe-map-4`);
   - writes the SARIF, with the fields below.

### Decisions (all fixed before any results; see the plan for reasons)

- **CWE → ruleId** is assigned by what each CWE means, using the ruleId
  definitions the task format uses, never by task labels.
  - A Semgrep finding uses its rule's **primary** CWE, the one the rule's
    author lists first.
  - CodeQL and SonarQube name no primary CWE. CodeQL lists its `external/cwe`
    tags in numeric order and SonarQube's cwe facet is an unordered set, so
    their CWEs are decided as a set (`cwe_map.decide_unordered`, `cwe-map-5`):
    unmapped CWEs are ignored, a generic CWE (200, 284, 668) decides only when
    no specific mapped CWE is present, a set whose deciding CWEs all fall in
    one family is reported under that family, and a set that spans two
    families is dropped as ambiguous and counted. The answer never depends on
    the order.
  - A generic CWE never carries a result that also names clear-text
    transport, credential or storage CWEs (`NOT_DISCLOSURE_CWES`), for any
    tool (`cwe-map-5`). So SonarQube `python:S5332` (CWE-200, CWE-319) is no
    longer reported as `LLM02.SID.HIGH`.
  - LLM02 covers disclosure *flows* only: exposure, logs, errors, sent data, and
    authorisation on data. Hard-coded secrets (CWE-798), weak transport or
    storage, and XXE aren't mapped.
  - Unmapped CWEs (XSS, crypto, CSRF, ...) are outside the five ruleIds and are
    not reported; they're still counted in the metadata.
  - No CWE maps to `LLM03.EA.AUTONOMY`, so no current agent can report it.
    Missing authorisation (CWE-862, and CWE-285, 284 and 863) maps to
    `LLM02.SID.HIGH`, and the Claude review agent goes through the same table.
    A finding labelled `LLM03.EA.AUTONOMY` (for example ec8a82 F1) therefore
    scores 0 for every one of them by construction. A correct report at the
    right lines lands in the LLM02 family and cannot match. This is a property
    of the frozen map, not a miss by the tool.
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

- precision, recall and F1 from the verifier's tp/fp/fn. Precision (and so F1)
  is shown as n/a when the tool reported nothing to take it over;
- **location recall**: ground-truth findings with any security finding near them,
  mapped or not. This separates "looked at the right code" from "CWE on the other
  OWASP side";
- **location + acceptable-CWE recall**;
- zero-finding tasks with no false positive.

When no graded trial of a tool emitted a result (`results_emitted` in the
agent metadata), the report's first line says "no results emitted, scores
equal an empty SARIF". Such a run scores 1.0 on every negative, FPR 0 and an
exact "neither" row by default, so those figures say nothing about the tool.

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
- The grader matches greedily: each result, in file order, takes the first
  unmatched finding near it. A partial-credit result (say `LLM02.SID.MEDIUM`
  one line above) can therefore take a finding that a full-credit result
  further down would have matched, and the full-credit one becomes a false
  positive. Agents merge results of one family on one line, so this needs two
  results on different lines. It was seen in a crafted case only, not in a run.
- On a negative task, a result near the fix marks every contrast category with
  the same risk prefix as detected (`cat.<category>.detected`), the same
  prefix-level match positives use. A `LLM03.EA.PERMISSIONS` result near a
  FUNCTIONALITY fix counts as a false positive for FUNCTIONALITY.

## CodeQL agent

`sast.codeql.agent:CodeQLAgent` (agent name `codeql-sast`) runs the CodeQL
2.27.1 bundle on the task's Python code and writes the same SARIF profile as
the Semgrep agent, graded by the same `tests/grade.py`. CodeQL is used for
research and experimentation only. Its licence terms for commercial use are
revisited if a contract follows, so don't use it in client work until then.

### Run

The normal place for the bundle is the task image at `/opt/sast/codeql`, which
the `sast-tools:0.5.0` image provides for both amd64 and arm64. Setup
(`sast/codeql/install.py`, standard library only) checks it: the CLI must
report 2.27.1, the bundle's `codeql/python-queries` pack must be exactly
1.8.11 and the suite file must be there. When it matches, nothing is
downloaded and setup takes about a second.

When there is no bundle, or one with other versions, setup downloads the
pinned bundle for the CPU (`linux64` on x86_64, `linux-arm64` on aarch64, about
690 MB), checks its sha256 while it streams, refuses any archive entry that
could land or point outside the target (absolute names, `..`, links that
escape directly or through another link), unpacks it into a staging folder,
checks versions and the suite there and only then moves it into place. The
target is `/opt/sast/codeql` when the agent's user can write there, otherwise
`codeql` in the agent's work folder, and the agent runs CodeQL from wherever
setup put it (`install.install_dir` in the metadata). This takes about 100 s on
a fast link. Harbor gives setup 300 s, so the installer stops itself after
270 s, and the download has a hard deadline 90 s before that. A download that
cannot finish in time fails the trial with a message saying so and naming the
tools image, rather than being cut off by Harbor. Setup on Daytona therefore
works without a registry image, at the cost of the download in every trial.

```bash
PYTHONPATH=$PWD .venv/bin/harbor run -y -p <tasks> -n 4 -a sast.codeql.agent:CodeQLAgent -o jobs/codeql
python3 tools/report.py jobs/codeql --tasks <tasks>
```

The only option is `scan_budget_sec`. Unknown keys are accepted and recorded,
as for the Semgrep agent.

### What a run does

1. Reads the scope from `metadata.scanner_roots` and `metadata.excluded_paths`
   through `sast/scope.py` (`task_scope`). A path with a "/" is
   anchored at the repository root, a plain name such as `tests` means that
   name at any depth, and bytecode is always left out.
2. Lists the Python files (`*.py`, `*.pyi`) under the roots and keeps those in
   scope. None at all fails the trial before CodeQL starts, because CodeQL
   would have nothing to analyse.
3. Writes a CodeQL config file from the scope. `paths` holds the folder roots
   and `paths-ignore` the excludes (a plain name is also written as
   `**/<name>`). CodeQL 2.27.1's Python extractor crashes when `paths` names a
   file (tested on `pyproject.toml`), so file roots aren't written. A Python
   file root brings in its folder instead, and other files are skipped.
4. `codeql database create --language=python --build-mode=none
   --source-root=/app/repo` with that config.
5. `codeql database analyze` with the bundle's
   `qlpacks/codeql/python-queries/1.8.11/codeql-suites/python-security-extended.qls`,
   `--format=sarif-latest`. Both steps get `--threads` from the task's cpus and
   `--ram` from its `memory_mb` minus 512, never below 1024.
6. Checks the result (see the failure policy below), turns each result into a
   finding and drops results outside the scope. A finding's CWEs are the rule's
   `external/cwe/cwe-NNN` tags and its location is `locations[0]` relative to
   `/app/repo`. CodeQL has no primary CWE and sorts the tags by number, so the
   first tag means nothing. The tags are decided as a set with the shared table
   (`cwe-map-4`, see "Decisions" above). Under `cwe-map-3` the first tag
   decided, and `py/clear-text-logging-sensitive-data` (CWE-312, 359, 532) and
   `py/clear-text-storage-sensitive-data` (312, 315, 359) could never be
   reported because CWE-312 is unmapped and sorts first. Now both are
   `LLM02.SID.HIGH`. No other rule of the suite changes, and none spans two
   families. A result whose tags did would be dropped and listed in
   `results_cwe_ambiguous`, with the four outcomes counted in
   `results_by_cwe_decision`.

### Failure policy

These fail the trial with `ScannerError`, so it is recorded as errored and never
graded as "found nothing".

- No Python file in the scope, or none of the scan roots exists.
- `database create` or `database analyze` exits non-zero, runs out of time
  (124) or is killed (137). The error text quotes CodeQL's real error lines
  only: its "A fatal error occurred" line, a line tagged `[ERROR]`, and the
  extractor's Python exception line as the cause. A line that merely contains
  the word, such as "0 errors", is never picked.
- A missing or unreadable SARIF file, or a run CodeQL marks with
  `executionSuccessful: false`.
- The `py/summary/lines-of-code` metric is 0. CodeQL then extracted nothing and
  still exits 0, which was checked on a repository with no Python in scope.
- The metric is missing from the SARIF. The suite always reports it, so its
  absence means the run cannot show that any code was analysed.
- An extraction notification at error level that names an in-scope file.

**Extraction problems, and why only error level fails.** Every run's
`toolExecutionNotifications` are read. Notes and level "none" are telemetry and
file lists and are ignored. Errors and warnings are recorded in the metadata
under `codeql_extraction` (counts, the first 50 of each, whether each names an
in-scope file, and `files_not_extracted`). The rule comes from real output.
On all 28 dataset tasks and the three sample tasks CodeQL 2.27.1 reported no
warning or error at all. On a crafted repository with a syntax error in one
file and a non-UTF-8 byte in another, it skipped both files and said so with
`py/diagnostics/syntax-error` and `py/diagnostics/extraction-warnings` at
warning level, analysed the rest and exited 0. So an unparseable file is a
warning, recorded with its path in `files_not_extracted`. It does not fail the
trial: it is a property of the code that a re-run cannot change, and the rest
of the scope was analysed. If no file could be read at all, lines of code is 0
and the trial fails anyway. An error-level notification never appeared. One
that names an in-scope file would mean CodeQL itself failed on code it should
have analysed, so it fails the trial. One outside the scope is only recorded.

### What it emits

- **`codeFlows` are real CodeQL paths.** When a path query reports a dataflow
  path, its first thread flow becomes the result's `codeFlows`. The first step
  is marked `source`, the last `sink`, and the steps in between get no role.
  A plain problem query has no path and gets no `codeFlows`. With the default
  (remote) threat model, CodeQL found no path result on any of the 28 twin
  tasks, so in practice the path sub-score is 0 on them for now. The
  `smoke_web_eval` sample task shows the other side: an HTTP query parameter
  reaches `eval`, CodeQL reports the 12-step path, and the task's grader gives
  0.70 (detection, classification and path) where the same finding without its
  path gets 0.40.
- `residualRisk` (heuristic only, under `properties.heuristics`, never scored)
  comes from the rule's `security-severity`: 7.0 and above is high, 4.0 to 6.9
  medium, lower low.
- Artifacts, kept after a failed scan too: `codeql-config.json` (the scope file
  CodeQL was given), `codeql.sarif` (CodeQL's own output), `codeql-logs.tar.gz`
  (the database's `log` and `diagnostic` folders, packed in a `finally` block),
  and the usual `findings.sarif`, `metadata.json` and `install.log`. Packing the
  logs is best effort. Its outcome is `codeql_logs_packed` in the metadata, and
  a failure there never fails a good scan.

### Measured on the real tasks (2026-10-08)

The agent's two CodeQL commands, with its scope file and the tasks' own limits
(1 CPU, so `--threads=1`, and 2048 MB, so `--ram=1536`), were run on all 28
harbor tasks with the 2.27.1 bundle, each under `/usr/bin/time -v`. The
process-tree figure is the largest sum of resident memory over CodeQL and all
its child processes, sampled every 0.1 s, which is closer to what the sandbox's
memory limit counts. The host had 2 CPUs and 8 GB and ran nothing else heavy.

| | Result |
|---|---|
| Runs that completed | 28 of 28 (both steps exit 0, `executionSuccessful` true) |
| `database create` | 6.4 to 7.5 s, median 7.1 s |
| `database analyze` | 20.0 to 27.2 s, median 22.0 s |
| Both steps | 26.5 to 34.2 s, median 29.0 s, against a scan budget of 780 s |
| Peak memory, largest process (`time -v`) | create 147 to 178 MB, analyze 827 to 947 MB |
| Peak memory, process tree | create 281 to 325 MB, analyze 831 to 950 MB, against 2048 MB |
| Lines of Python extracted | 249 to 1725, median 751 |
| Warning or error notifications | none |
| Tasks with any result | 6, both twins of `4da5ab`, `795c39` and `dc4b7a` |

The six results are `py/insecure-protocol` (CWE-327) in `4da5ab`'s HTTP shim
and `py/incomplete-url-substring-sanitization` (CWE-20) in `data_types.py` in
`795c39` and `dc4b7a`. They are the same in both twins of each pair and are not
the labelled bugs. Neither CWE is in the shared table, so nothing is reported.
The tasks' 2 GB and 900 s leave a wide margin, so no task change is needed for
CodeQL.

Recorded output (CodeQL 2.27.1, graded by each task's own grader in
`tests/test_codeql_normalise.py`):

| Task | CodeQL results | Reported | Reward |
|---|---|---|---|
| `task_7f3a91` | 0 | 0 | 0.00 |
| `smoke_eval` | 0 (the `eval` input is model output, not a CodeQL source) | 0 | 0.00 |
| `smoke_web_eval` | 1 (`py/code-injection`, CWE-94, with its path) | 1 | 0.70 |
| `task_3920a8_positive` / `_negative` | 0 / 0 | 0 / 0 | 0.00 / 1.00 |
| `task_4da5ab_positive` / `_negative` | 1 / 1 (`py/insecure-protocol`, CWE-327) | 0 / 0 | 0.00 / 1.00 |
| `task_bd9abf_positive` / `_negative` | 0 / 0 | 0 / 0 | 0.00 / 1.00 |
| `task_dc4b7a_positive` / `_negative` | 1 / 1 (`py/incomplete-url-substring-sanitization`, CWE-20) | 0 / 0 | 0.00 / 1.00 |

Where each recording came from is in `tests/fixtures/README.md`. The tests that
run the real CLI look for it at `$CODEQL_BIN` (the `codeql` launcher of an
unpacked bundle) or `/opt/sast/codeql/codeql`, and skip with that reason when
neither exists. Every other test reads only files inside this repository.

## SonarQube agent

SonarQube is a server, not a CLI, so this agent needs one you run yourself.
The agent runs `sonar-scanner` inside the task sandbox against that server,
reads the results back through the web API (also from inside the sandbox), and
writes the same SARIF as the Semgrep agent. It keeps both issues of type
VULNERABILITY and Security Hotspots, but on the server version used here
(Community Build 26.9.0.129388) a hotspot can never appear, because that
server has no hotspot rules at all (see "No Security Hotspots on Community
Build 26.9" below). The design is in
[docs/superpowers/specs/2026-10-07-codeql-sonarqube-agents-design.md](docs/superpowers/specs/2026-10-07-codeql-sonarqube-agents-design.md).

### 1. Start the server

```bash
docker run -d --name sonarqube -p 9000:9000 sonarqube:26.9.0.129388-community
```

This is the Community Build the agent was checked against, so use this exact
tag and every run talks to the same server. Wait until
`curl -s localhost:9000/api/system/status` says `"status":"UP"` (a minute or
two on first start), then log in at http://localhost:9000 as `admin`/`admin`
and set a new password.

### 2. Create a token

In the UI, open My Account, then Security, and generate a **user token**. The
user needs the global permissions Execute Analysis and Create Projects, and
Administer on the projects it creates so the agent can delete them afterwards.
The `admin` user has all of these. A project or global analysis token is not
enough, because the agent also deletes the project.

### 3. Tell the agent where the server is

Both variables are read on the host when the scan starts. A missing one fails
the trial before anything runs.

```bash
export SONAR_HOST_URL=http://host.docker.internal:9000
export SONAR_TOKEN=<the token>
```

`SONAR_HOST_URL` is the server **as the sandbox sees it**, not as your shell
sees it. It must not hold a user name or password (`http://user:pass@host`),
because the URL goes into the exec env and the metadata. Such a URL is
refused without being echoed. Inside a Docker sandbox on Docker Desktop (macOS, Windows) that is
`http://host.docker.internal:9000`. On Linux, either add
`--add-host=host.docker.internal:host-gateway` to the sandbox or use the
bridge address (usually `http://172.17.0.1:9000`). The agent checks the server
from inside the sandbox before it scans, so a wrong address fails fast with a
clear message.

How the token reaches the sandbox: Harbor turns the environment of an exec
call into command-line arguments (`docker compose exec -e NAME=value`, and
`env NAME=value` on Daytona), which any process listing shows. So the agent
never passes the token that way. It uploads the token as a file into a
directory under its work dir that only the sandbox user can open, makes the
file mode 600, and points `fetch.py` at it with `SONAR_TOKEN_FILE`. The scanner
gets the token from the sandbox shell, as
`SONAR_TOKEN="$(cat <file>)" exec sonar-scanner ...`, so it is in the scanner's
own environment but in no command line Harbor builds. Writing the file is
inside the same `try`/`finally` as the scan, so the file is deleted when the
scan ends, also after a failure in the upload or in making it private, and the
metadata records `token_file_removed`. The token is never in a log, an artifact or the run
metadata, and the command output that is kept is scrubbed of it in case a tool
prints it. The unit tests check all of this.

### 4. Run

The task image must carry the scanner, so build it from the tools image
`sast-tools:0.5.0` (see "Pre-built tools image" above). The scanner is not
downloaded at setup.

```bash
PYTHONPATH=$PWD .venv/bin/harbor run -y -p dev/tasks -n 2 -a sast.sonarqube.agent:SonarQubeAgent -o jobs/sonarqube
```

Keep `-n` small: every trial is analysed by the same server, which handles one
background task at a time on the Community Build.

To record a run that has results, use the sample task
`tests/fixtures/tasks/smoke_sonar` (`-p tests/fixtures/tasks -i smoke_sonar`).
Its tiny notes helper has clear-text HTTP, which the Community Build reports as
a VULNERABILITY (`python:S5332`), and a shell command, a formatted SQL query
and a world-writable folder. Older servers report those three as Security
Hotspots. Community Build 26.9 has no hotspot rules, so there they can only
come back as VULNERABILITY issues from the former-hotspot rules, or not at
all.

### What a run does

1. **setup**: `install.py` checks `/opt/sast/sonar-scanner` (the scanner and its
   bundled JRE, pinned in [sast/sonarqube/pins.py](sast/sonarqube/pins.py)) and
   runs `sonar-scanner -v`.
2. **run**:
   - The token file is written as described above.
   - One deadline, the scan budget, covers the check, the scanner, the
     background task, the measures, the paging and the rule lookups.
     `sonar-scanner` and every `fetch.py` call run under
     `timeout -k 10 <seconds>` inside the sandbox, so they stop there even when
     Harbor only kills its own `docker compose exec` client.
   - `fetch.py check` asks the server for its status (must be `UP`), checks the
     token, and records the server version, the edition and the default Python
     quality profile.
   - `sonar-scanner` analyses `/app/repo` as a throwaway project
     `sast-<12 random hex>` (the agent never sees the task id), with
     `sonar.sources` from the task's `scanner_roots`, `sonar.exclusions` from
     its `excluded_paths` (a path with a slash, like `src/vendor`, is that
     path from the repo root, and a plain name, like `tests`, is that name at
     any depth, as for Semgrep), `sonar.python.version=3` and
     `sonar.scm.disabled=true`. Its working files go under the agent's work
     directory, so a read-only repository is fine.
   - `fetch.py collect` waits for the server's background task to reach
     `SUCCESS`, reads what was analysed (`api/measures/component` with
     `files`, `ncloc` and `ncloc_language_distribution`), pages through the
     vulnerabilities (`types=VULNERABILITY`) and the hotspots, and looks up
     each rule once. Every search must yield exactly as many items as its
     `paging.total`. `api/rules/show` gives a rule's name and type, and
     `api/rules/search?rule_key=<key>&facets=cwe&ps=1` gives its CWEs as the
     `cwe` facet. Community Build 26.9 does not return `securityStandards`
     from `api/rules/show`, so the facet is the only CWE source. The rule
     description's resources section is a hand-written reference list, not a
     primary CWE (`python:S4423` lists only CWE-327 there while its facet holds
     295, 326 and 327), so it is not used. Any rule lookup error stops the
     run, and so does a search that does not return exactly that one rule
     (`paging.total == 1` and the same key), because a rule without its CWEs
     would silently drop its results. Then it reads the project's Python
     quality profile (the server's default one when the project has none)
     and deletes the project. The delete gets its own short time slice, also
     when the deadline has passed. A delete that fails does not fail the run,
     and the metadata says the project was left.
   - **A scan that looked at nothing is an error.** The agent counts the `.py`
     files in the task's scope before scanning. After the collection it
     raises `ScannerError` when SonarQube analysed 0 files, when the scope has
     Python files but `ncloc_language_distribution` has no Python, or when the
     Python quality profile has no active rule (`activeRuleCount` 0). The
     background task's `warnings` and any "Unable to parse file" lines of the
     scanner output go into the metadata (`ce_task.warnings`,
     `files_not_parsed`).
   - Only `fetch_format` 2 output (with the cwe facet) is read. The older
     format 1 has no CWE and would report nothing without saying so.
   - Each issue's own `type` is checked again, and anything other than
     `VULNERABILITY` is skipped and counted (`issues_not_vulnerability`).
   - The CWEs are mapped with the same table as Semgrep (`cwe-map-5`), with
     the rule below.
3. **Failures are errors**: a server that is down, a refused token (HTTP 401)
   or missing permission (403), a scanner error, a background task that ends
   `FAILED` or `CANCELED`, a rule lookup error, an incomplete page, an
   analysis of nothing, or running out of budget raises `ScannerError`. The
   project is deleted on every exit path once the scanner has started,
   including a timeout and a budget that runs out between steps.

#### How a rule's CWE set is mapped

The cwe facet is an unordered set and Sonar names no primary CWE, so the
agent uses `cwe_map.decide_unordered` (`cwe-map-5`, the same rule as the
CodeQL agent). Unmapped CWEs are ignored, and a generic CWE (200, 284, 668)
gives way to a specific mapped one. When the deciding CWEs all fall in one
family, that family is reported, and the CWEs are passed on with that family's
CWEs first, so the SARIF ruleId is that family and `task_rule` still sees
every CWE when it picks HIGH or MEDIUM. When they fall in more than one
family, the result is dropped as ambiguous and listed in
`results_cwe_ambiguous`. When no CWE is mapped, the result is counted as
unmapped and not reported. `results_by_cwe_decision` counts the four outcomes
(`none`, `unmapped`, `mapped`, `ambiguous`). For example `python:S4423`
(CWE-295, 326, 327) is unmapped, `python:S5332` (CWE-200 and CWE-319) is
unmapped because clear-text transport is not disclosure, and
`docker:S6471` (CWE-250 and CWE-284) is `LLM03.EA.PERMISSIONS` through the
specific CWE-250.

An honest note on that example. The rule the agent used before (drop a result
when any of its CWEs is unmapped) was chosen after `python:S5332`'s CWEs
{200, 319} were already known, and it happened to drop S5332. `cwe-map-4`
ignores unmapped CWEs instead, so S5332 is now reported. On the dc4b7a twins
it fires in shared code, so it is a false positive there and lowers
precision. The rule is kept because it is the principled one, not because of
that outcome.

`cwe-map-5` (2026-10-12) changes that outcome on purpose, after the QC review
against spec sections 2.3 and 3: a disclosure finding needs protected data to
reach an unauthorised recipient, and clear-text transport describes the
channel, not the recipient. S5332 was SonarQube's only cause of failed
negatives (454a7f and dc4b7a). Regrading the v0.4.0 SARIFs with S5332 removed
and S6471 added turns both negatives from 0.0 to 1.0 and changes nothing else.
The SonarQube job has to be run again for the published numbers to reflect
`cwe-map-5`. See the `sast/cwe_map.py` docstring for the full decision,
including why Semgrep's CWE-939 stays unmapped.

#### No Security Hotspots on Community Build 26.9

SonarQube Community Build 26.9.0.129388, the server this agent was checked
against, has no Security Hotspot rules. `api/rules/search?types=SECURITY_HOTSPOT`
returns `total` 0 for every language, and 35 of the 61 active Python
VULNERABILITY rules carry the tag `former-hotspot`, so the old hotspot checks
were turned into vulnerability rules. A scan on this server therefore never
yields a hotspot, and the `SECURITY_HOTSPOT` count in the metadata is always 0
there. That is a property of the server, not a fault of the agent. The agent
still pages `api/hotspots/search` and maps hotspots, because older servers do
have hotspot rules.

So that every run shows this, `fetch.py collect` also asks
`api/rules/search?types=SECURITY_HOTSPOT&ps=1` (server-wide) and
`api/rules/search?types=SECURITY_HOTSPOT&languages=py&activation=true&qprofile=<key>&ps=1`
(the Python profile used) and records the two totals as
`hotspot_rules_total` and `hotspot_rules_active`, with the profile key in
`hotspot_rules_qprofile`. Both are expected to be 0 on 26.9. The counts are
informational: if the call fails, the error is kept in `hotspot_rules_error`
and the run goes on.

#### No traces

SonarQube results never carry a trace (no `codeFlows`). The Community Build
has no taint engine, so its issues come with empty `flows`, and the order of a
flow's locations was never checked against a real taint flow. The metadata
still counts `flows_raw` and `issues_with_flows`, so a server that does return
flows is noticed.

Options (`--ak key=value`): `scan_roots`, `exclude` and `scan_budget_sec` as for
Semgrep, and `keep_project=true` to leave the project on the server so you can
look at it in the UI.

The metadata records, under `sonarqube`: the host URL, server version, edition,
quality profile (with `activeRuleCount`), project key, whether it was deleted
(also after a timeout), the background task with its `warnings`, what was
analysed (`analysis`: files, ncloc, ncloc per language, Python files in
scope, active Python rules), the Security Hotspot rule counts
(`hotspot_rules_total` on the server, `hotspot_rules_active` in the Python
profile, and `hotspot_rules_qprofile`, `hotspot_rules_error`),
`files_not_parsed`, the token file's path and
whether it was removed, and the kept findings per `sonarType`. At the top
level it records the counts above (`rule_cwe_source`, `rules_without_cwe`,
`results_by_cwe_decision`, `results_cwe_ambiguous`,
`issues_not_vulnerability`, `flows_raw`). The raw API responses are in the
trial artifacts as `sonarqube.json`, next to `sonar-scanner.log`.

The tests replay responses recorded from real runs (server 26.9.0.129388
Community, scanner 8.1.0.6389), unedited, in
`tests/fixtures/sonarqube_26.9-f2_<task>.json` (2026-10-08, with the cwe
facet). The HTTP stub in `tests/test_sonarqube_fetch.py` and the fake sandbox
in `tests/test_sonarqube_agent.py` serve those responses. The measures answer
is written in its documented shape, because the recordings predate that
call, and tests of error paths no recording shows (401, 404, a FAILED task, a
timeout) say so. The older `sonarqube_26.9_<task>.json` (format 1, no CWE) are
kept to check that the normaliser refuses them. No recording holds a Security
Hotspot, and none can on 26.9 (see above). The recordings also predate the
hotspot rule count, so its tests use a stubbed answer. The real values (0 and
0) will come from the next recording.

## Claude Code security review agent

This agent runs Anthropic's open-source
[claude-code-security-review](https://github.com/anthropics/claude-code-security-review)
(pinned at commit `0c6a49f`, 2026-02-11) on a task. Unlike the other agents it
calls a model: the Claude Code CLI (2.1.296, pinned) does the review, and the
upstream false-positive filter calls the Anthropic API once per finding. It
needs an Anthropic API key and HTTPS access to `api.anthropic.com` from the
task container. The design and what was and was not verified are in
[docs/claude-review-agent.md](docs/claude-review-agent.md).

The upstream tool reviews a GitHub pull request. The agent uses its library
code without GitHub: the in-scope files (the task's `scanner_roots` minus
`excluded_paths`) become one pull request that adds them all, against an empty
base. Our own driver (`sast/claude_review/driver.py`) builds the upstream
prompt, runs the CLI, runs the upstream filter and checks every step.

### 1. Build the tools image

The CLI binary, the upstream files and a Python venv with `anthropic` 0.79.0
and `requests` 2.32.5 come with the tools image, in `/opt/sast/claude-review`.
Every file is checked against a pinned hash while the image builds: the CLI
tarball against its sha256 and npm integrity, each upstream file against its
sha256, and every wheel through `requirements.lock` (`--require-hashes`).

```bash
uv sync
tools/build_tools_image.sh                 # sast-tools:0.5.0, now with the claude-review part
```

See [Pre-built tools image](#pre-built-tools-image) for `--save` and registry builds.

The image grows by about 260 MB (the CLI is a 257 MB native binary). The venv
is built from the Semgrep part's CPython, so the task image must copy all of
`/opt/sast`, as the sample task Dockerfiles do. Without the baked part, setup
installs it into the work directory instead. That needs the sandbox to reach
registry.npmjs.org, raw.githubusercontent.com and pypi.org, a glibc Linux on
x86_64 or aarch64, and Python 3.9 or newer.

### 2. Set the key

```bash
export ANTHROPIC_API_KEY=<key>
```

The key must be enabled for the Claude API and for Claude Code. It is read on
the host where Harbor runs. A missing key stops the job before any trial
starts. Do not pass it with `--ae`, since Harbor writes agent env values into
the job config.

How the key reaches the sandbox: the same way as SonarQube's token. It is
uploaded as a file into a mode 700 directory under the work dir, copied under
umask 077 into a mode 600 file, and the whole directory is removed when the
review ends, also after a failure. The driver reads it in-process. The CLI gets
it through an `apiKeyHelper` (`cat <key file>`) in a private settings file, so
the key is in no command line and in no process environment. The key is never
in a log, an artifact or the run metadata, and all output that is kept is
scrubbed of it. The unit tests check all of this.

### 3. Run

The agent uses the upstream tool's default model, `claude-opus-4-1-20250805`,
unless you name another one with `--ak model=<model id>` or the host variable
`CLAUDE_REVIEW_MODEL`. Anthropic may retire that model, and your key may not
have it enabled, so naming the model is usually the safer choice. The examples
below use `claude-opus-5-5`. Use any model your key can use.

The agent checks the model at run time, not from a fixed list. The driver
sends one tiny request per model before the review, so a retired or unknown
model fails in seconds. Then it reads the CLI's first message, which names the
model the CLI will really use. If that is not the requested model, the CLI is
stopped before the review spends anything and the trial fails with an error
that says to pass `--ak model=<model id>`.

```bash
PYTHONPATH=$PWD .venv/bin/harbor run -y --force-build -p dev/tasks -n 2 \
  -a sast.claude_review.agent:ClaudeReviewAgent -o jobs/claude-review \
  --include-task-name smoke_eval \
  --agent-timeout-multiplier 3 \
  --ak model=claude-opus-5-5 --ak timeout_sec=2400
```

The same with the benchmark's scope added to the prompt, three attempts per
task:

```bash
PYTHONPATH=$PWD .venv/bin/harbor run -y --force-build -p dev/tasks -n 2 -k 3 \
  -a sast.claude_review.agent:ClaudeReviewAgent -o jobs/claude-review-scoped \
  --include-task-name smoke_eval \
  --agent-timeout-multiplier 3 \
  --ak model=claude-opus-5-5 --ak mode=scoped --ak timeout_sec=2400
```

The sample tasks give the agent 900 s, which is often too short for a model
review. `timeout_sec` is the agent's own limit for the whole review, and
Harbor's limit (task timeout times `--agent-timeout-multiplier`) must stay at
least 120 s above it, or Harbor stops the agent first and grades a missing
SARIF as 0. Without `timeout_sec` the agent uses the task's timeout minus
120 s, as the other agents do. Harbor does not tell an agent its multiplied
limit (0.23 and 0.24 pass it only to the oracle agent), so the agent cannot
check it. When `timeout_sec` is longer than the task's timeout allows, the
metadata gets a `budget_note` and `harbor_limit_needed_sec` as a reminder. It
is not an error, and with the multiplier above it is expected.

The task environment must allow outbound HTTPS to `api.anthropic.com`. The
driver checks that first and fails with a clear message if it cannot connect.

### Options

Every option is `--ak key=value` or the host variable `CLAUDE_REVIEW_<KEY>`
(for example `CLAUDE_REVIEW_MODEL`). `--ak` wins.

| Option | Default | Meaning |
|---|---|---|
| `model` | upstream default, `claude-opus-4-1-20250805` (may be retired, see above) | model for the review and, unless `filter_model` is set, the filter. Harbor's `-m` is recorded and not used |
| `filter_model` | `model` | model for the per-finding filter |
| `mode` | `stock` | `stock`: upstream prompts and filter unchanged. `scoped`: adds the benchmark's LLM02/LLM03 scope and a pointer to `security_manifest.json` through the upstream custom instructions, asks for a CWE list per finding, and uses the upstream filter text without exclusions 7 ("lack of hardening") and 14 ("user content in AI prompts is not a vulnerability") |
| `filter` | `claude` | `claude`: the upstream regex rules plus the per-finding API check. `hard_rules`: the regex rules only |
| `max_turns` | none | Claude Code `--max-turns` |
| `max_budget_usd` | none | Claude Code `--max-budget-usd` for the review (the filter is not counted) |
| `timeout_sec` | task timeout minus 120 s | wall-clock limit for the whole review |
| `cli_share` | 0.6 | share of that limit the CLI may use, the filter gets the rest |
| `cli_attempts` | 3 | CLI attempts, as upstream |
| `cli_auth` | `api_key_helper` | `env` puts the key into the CLI process's own environment instead (a fallback, never a command line) |
| `scan_roots`, `exclude` | the task's | as for the other agents |

### What a run does

1. **setup**: `install.py` checks `/opt/sast/claude-review` (CLI version, every
   upstream file's sha256, the venv's `anthropic` and `requests` versions, and
   that it imports the upstream package) and rehashes the part against the
   image's `MANIFEST.json`. If the part is missing or wrong, it installs it
   into the work dir.
2. **run**: the agent lists the in-scope files, uploads a request (no secret in
   it) and the key file, and runs the driver under `timeout -k 10 <seconds>`.
   The driver:
   - removes every `ANTHROPIC_*` and `CLAUDE_CODE_*` variable from its own
     environment, gives the CLI only an allow-list of variables (PATH, locale,
     temp dir, CA bundles and proxies, plus HOME and Claude Code's switches
     that turn off telemetry), so no host setting such as
     `CLAUDE_CODE_PROVIDER_MANAGED_BY_HOST` can choose the model, checks that `api.anthropic.com` answers, and sends one tiny
     request per model, so a bad key, a retired model or a blocked network
     fails in seconds.
   - builds the pull request (a file whose diff holds `@generated` is left
     out, as upstream does, and so are binary files) and the upstream prompt.
   - runs the CLI in `/app/repo` with the upstream command line plus `-p`,
     `--output-format stream-json --verbose` (the last line is the same result
     object as upstream's `json` output), `--settings` and `--setting-sources
     user` (the repository's own `.claude` settings are not loaded),
     `--strict-mcp-config` and `--no-session-persistence`. The settings deny
     Bash, WebFetch, WebSearch, Edit, MultiEdit, Write and NotebookEdit, and
     reads of the key and the CLI home folders. The CLI's first message is
     checked before the review spends anything: it must use the requested
     model, take its key from the apiKeyHelper, and offer none of the denied
     tools, or the CLI is stopped at once.
   - retries a failed attempt (3 in all) and, when the prompt is too long,
     runs once more with the file list only, as upstream does.
   - runs the upstream `FindingsFilter`. Its API access check uses the
     filter's own model instead of the hard-coded `claude-3-5-haiku-20241022`,
     which is retired.
   - writes one JSON result, scrubbed of the key.
3. The agent maps the kept findings and writes the SARIF.

**Failures are errors, never a clean scan.** The upstream code treats several
failures as "no findings". The agent raises `ScannerError` instead when the key
is missing, the API cannot be reached or refuses the key, the model is not
available, the CLI would use another model or credential, a CLI result is not
JSON, says `is_error` or a subtype other than `success` (including
`error_max_turns`), holds no findings JSON, says `review_completed` false or
`files_reviewed` 0, when the filter cannot reach the API (upstream silently
falls back to the regex rules), when any per-finding filter call fails
(upstream keeps that finding at confidence 10), and when the time runs out.

### Mapping

- **CWE, stock mode**: the review gives a free-text `category` and no CWE. A
  frozen table (`sast/claude_review/category_map.py`, version
  `ccsr-category-map-1`) maps the normalised category to one CWE, for example
  `sql_injection` to CWE-89, `command_injection` to CWE-78 and
  `sensitive_data_logging` to CWE-532. A category that is not in the table is
  counted in `unmapped_by_category` and not reported.
- **CWE, scoped mode**: the model's own `cwe` list is used when at least one
  entry is a well-formed id on the agent's allow-list, else the table. Rejected
  values are counted in `cwes_rejected`, and each finding's `cweSource` says
  which was used.
- The CWEs then go through `cwe_map.decide_unordered` and `task_rule`, like
  CodeQL and SonarQube results, so the ruleId follows the same frozen CWE
  table as every scanner. `LLM03.EA.AUTONOMY` has no CWE and is never reported,
  and missing authorisation (CWE-862) becomes `LLM02.SID.HIGH`, so findings
  labelled with the Autonomy subtype score 0 for this agent by construction, as
  for the other agents.
- **Location**: the finding's `file` must be one of the in-scope text files
  and its `line` a positive integer within the file. Anything else is dropped
  and counted (`dropped_bad_location`, `dropped_out_of_scope`).
- **Level and residual risk**: HIGH gives `error` and `high`, MEDIUM `warning`
  and `medium`, LOW `note` and `low`.
- **No codeFlows.** The review describes the exploit in prose and gives no
  path, so no trace is made up.
- **Control status and recommendations** come from the fixed heuristics, under
  `properties.heuristics`, and are never scored. The review's own
  recommendation text, category, severity, confidences and exploit scenario
  are kept under `toolProperties`.

### What the metadata records

Under `claude_review`: mode, model and filter model, the upstream commit, the
pinned and reported Claude Code version, the `anthropic`, `requests` and Python
versions, the exact CLI command line, the CLI settings, the CLI's init message
(model, key source, tools), the sha256 of the prompt, the request and the
scoped instruction texts, every attempt with its outcome, `total_cost_usd`,
`num_turns`, `usage` and `modelUsage` from the CLI, token counts of the direct
API calls per model, the filter's summary and every excluded finding with its
reason. At the top level: `model`, `filter_model`, `mode`, `filter_mode`,
`harbor_model_name_ignored`, and the mapping counts above. Harbor's agent info
names the model the review used. The driver's full result is kept as the
artifact `claude_review.json`.

### Cost, time and caveats

- No run against the real API has been made with this agent yet, so these are
  estimates. Claude Code's own system prompt is about 15,000 tokens, read again
  (mostly from cache) on every turn. A review of a small repository with an
  Opus-class model takes a few minutes to about 15 minutes and roughly $0.50 to
  $5, and each finding that reaches the filter costs one more call that holds
  the whole file. `total_cost_usd` in the metadata covers the CLI only, and the
  filter's tokens are recorded separately.
- **Run it 3 times per task.** Neither the CLI nor the upstream filter sets a
  temperature, so results vary between runs. Use `-k 3` and report the spread.
- **The stock prompts leave out some risks in scope.** They exclude rate
  limiting and resource exhaustion, ask for at least 80% confidence and HIGH or
  MEDIUM findings only, and their categories do not name LLM risks. The
  default filter drops "lack of hardening measures" and "user-controlled
  content in AI prompts", and its regex rules drop findings that mention
  unbounded loops or missing rate limits. Expect low recall on LLM02 and on
  excessive permissions and autonomy in stock mode. Scoped mode addresses part
  of this and is a different scanner, so report the two modes separately.
- The upstream prompt is framed as a pull request review ("focus only on
  security implications newly added by this PR"). Since every file is new in
  the synthetic pull request, the whole scope counts as new.
- Findings in `.md` files are always dropped by the upstream regex rules.
- The upstream README says the tool is not hardened against prompt injection.
  The key cannot be reached by the review's tools (no Bash, no web, reads of
  the key folder denied), but the review's findings can still be steered by
  repository content.

## Development

```bash
uv sync
.venv/bin/python -m pytest -rs      # no Docker or Semgrep needed, -rs lists skips
tools/check_merged_rules.sh         # after changing pins.py; needs Docker
```

To change a pin, edit `pins.py`, recompute `RULES_DIGEST`/`RULES_FILE_COUNT`
when the rules change (`install.read_rules_archive` + `install.rules_digest`),
run both checks above, bump `sast.__version__`, and rebuild the tools image.
