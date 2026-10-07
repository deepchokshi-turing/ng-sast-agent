# CodeQL and SonarQube scanner agents: design

Date: 2026-10-07. Status: approved in chat, waiting for review of this file.
Builds on agent 0.3.0 with the audit fixes (branch `agent-v0.3.0-audit-fixes`).

## 1. Goal

Add two scanner agents next to the Semgrep agent so the same 28 twin tasks
(and later tasks) can be run with CodeQL and with SonarQube. Every agent emits
the same five OWASP ruleIds through the same SARIF writer and is graded by the
same `tests/grade.py`, so results are comparable across tools.

Agreed in chat:

- SonarQube runs as a server the user hosts (Docker locally today, any
  reachable URL later, Daytona included). The agent gets the URL and token
  from environment variables.
- SonarQube results cover both issues of type VULNERABILITY and Security
  Hotspots.
- CodeQL runs the `security-extended` suite.
- One tools image, `sast-tools:0.4.0`, holds Semgrep, CodeQL and
  sonar-scanner.
- CodeQL use is research and experimentation only for now. Licensing is
  revisited if a contract follows.

Assumptions: Python only for now (all 28 tasks are Python). CodeQL stays at
2.27.1 to match the earlier baseline over the 159 cases.

## 2. Rules carried over from the audit

These hold for all three agents and are tested for each.

1. ruleId comes only from the shared CWE table `cwe-map-3`, by the rule's
   primary CWE. No tool-specific mapping and no tuning after results.
2. `controlStatus`, `residualRisk` and `recommendations` stay under
   `properties.heuristics` and are never scored.
3. `codeFlows` are written only from a real trace the tool produced. No
   one-step flows made from the match location.
4. Unit tests use recorded real tool output, never hand-made fixtures. A
   fixture says which tool version and which task produced it.
5. Anything that makes a result untrustworthy raises `ScannerError`, so the
   trial is recorded as errored and never graded as "found nothing".
6. Raw tool output is saved in the trial artifacts.

## 3. Structure

```
sast/
  base.py            unchanged lifecycle, budget, artifacts, error policy
  findings.py        Finding gains an optional trace (see 3.1)
  sarif.py           writes codeFlows only when a Finding has a trace
  cwe_map.py         shared, unchanged
  heuristics.py      shared, unchanged
  semgrep/           unchanged apart from the image build
  codeql/
    pins.py          CodeQL bundle version, URL and sha256 per arch, suite
    install.py       checks /opt/sast/codeql against the pins
    normalise.py     CodeQL SARIF -> Finding
    agent.py         CodeQLAgent
  sonarqube/
    pins.py          sonar-scanner version, URL and sha256 per arch
    install.py       checks /opt/sast/sonar-scanner against the pins
    fetch.py         runs in the sandbox: waits for the server, pages the API
    normalise.py     SonarQube API JSON -> Finding
    agent.py         SonarQubeAgent
```

Harbor entry points: `sast.codeql.agent:CodeQLAgent` and
`sast.sonarqube.agent:SonarQubeAgent`. Each agent reports
`<agent version>+<tool>-<tool version>` like the Semgrep agent.

### 3.1 Finding trace

`Finding` gains `trace: tuple[TraceStep, ...] = ()`, where a `TraceStep` has
file, start_line, end_line and role. The normalisers fill it only from the
tool's own flow data. `sarif.py` writes `codeFlows` only when `trace` is not
empty. The first step gets role `source`, the last gets role `sink`, and the
steps in between are written without a role, because no tool tells us which
of them is a `root_cause` or a `context_assembly` step.

## 4. CodeQL agent

Install: the bundle is in the image at `/opt/sast/codeql`. `install.py`
checks `codeql version` and the bundle's `python-queries` pack version against
the pins. If it is missing it fails with a clear message, because the bundle
download does not fit in the 300 s setup limit.

Scan, inside the sandbox:

1. Write a CodeQL config file with `paths` = `scanner_roots` and
   `paths-ignore` = `excluded_paths`.
2. `codeql database create <db> --language=python --build-mode=none
   --source-root=/app/repo --codescanning-config=<config> --threads=<cpus>
   --ram=<memory budget>`.
3. `codeql database analyze <db> <python security-extended suite from the
   bundle> --format=sarif-latest --output=<out>/codeql.sarif
   --threads=<cpus> --ram=<memory budget>`.
4. Any non-zero exit, a missing output file or unreadable SARIF is a
   `ScannerError`.

Normalise: for each result, the CWEs are the rule's `external/cwe/cwe-NNN`
tags in order. The location is `locations[0]`, made relative to `/app/repo`.
When the result has `codeFlows`, the first thread flow becomes the trace.
`residualRisk` (heuristic only) comes from the rule's `security-severity`
property: 7.0 and above is high, 4.0 to 6.9 medium, lower is low. Results
outside the task scope are dropped, as in the Semgrep agent.

Memory budget: the sandbox memory from the task settings minus 512 MB for the
OS and the agent, never below 1024 MB.

Artifacts: `codeql.sarif` and the CodeQL log directory, plus the usual
`findings.sarif`, `metadata.json` and `install.log`.

## 5. SonarQube agent

Configuration, read on the host from environment variables at the start of
`run()`:

- `SONAR_HOST_URL`, required. The server as the sandbox sees it, for example
  `http://host.docker.internal:9000` for a local Docker server.
- `SONAR_TOKEN`, required. A user token with permission to create and delete
  projects and to browse issues and hotspots.

A missing variable is a `ScannerError` before anything runs. The token is
passed only through the `env` of the sandbox commands that need it. It is
never written to a file, a log, the command line or the metadata, and a test
checks that it does not appear in any saved artifact.

Scan, inside the sandbox:

1. Check the server: `GET api/system/status` must say `UP`. Record
   `api/server/version` and the quality profile used for Python in the
   metadata.
2. Run `sonar-scanner` (bundled JRE, from `/opt/sast/sonar-scanner`) with a
   unique project key `sast-<random 12-hex id>` (the agent never sees the
   task id, by design),
   `sonar.sources` = `scanner_roots`, `sonar.exclusions` built from
   `excluded_paths`, `sonar.python.version=3`, and
   `sonar.scm.disabled=true`.
3. `fetch.py`, run with the Python in `/opt/sast`, reads the background task
   id from the scanner's report file and polls `api/ce/task` until it is
   `SUCCESS`. `FAILED`, `CANCELED` or running out of budget is a
   `ScannerError`.
4. It pages through `api/issues/search` with `types=VULNERABILITY` and
   `api/hotspots/search`, then calls `api/rules/show` once per rule to read
   its security standards (`cwe:NNN`). Raw responses go to
   `sonarqube.json`.
5. It deletes the project (`api/projects/delete`). If deleting fails, the run
   still succeeds and the metadata says the project was left behind.

Normalise: CWEs come from the rule's security standards in the order the
server returns them. A vulnerability's `flows`, when present, become the
trace. Hotspots have no flows. Each result records `sonarType`
(`VULNERABILITY` or `SECURITY_HOTSPOT`) in its properties so the report can
split them later. `residualRisk` (heuristic only) comes from the issue
severity or the hotspot's vulnerability probability.

Reproducibility: the server cannot be pinned the way a CLI can. The metadata
records the server version, the edition and the quality profile name and key
for every trial, and the report shows them.

Network: all API calls run from the sandbox, so they use the same route as
the scanner. The task needs outbound network to the server, and the agent
checks that before scanning.

## 6. Tools image 0.4.0

`images/sast-tools/Dockerfile` gains two install steps, each checking a
pinned sha256:

- CodeQL bundle 2.27.1 for linux64 into `/opt/sast/codeql`.
- sonar-scanner CLI with its bundled JRE for linux-x64 into
  `/opt/sast/sonar-scanner`. The exact version and hash are taken from
  binaries.sonarsource.com during implementation and written into
  `sast/sonarqube/pins.py`.

`sast.__version__` and `pyproject.toml` move to 0.4.0, and
`build_tools_image.sh` tags `sast-tools:0.4.0`. All 28 task Dockerfiles
and the sample task fixtures move to `sast-tools:0.4.0`. This is a real
content change, so the image is rebuilt, not retagged.

## 7. Testing and verification

Unit tests, all on recorded real output:

- CodeQL: run CodeQL 2.27.1 in the build sandbox on `task_7f3a91` and on two
  twin pairs, save the SARIF as fixtures, and test the normaliser, scope
  filtering, CWE extraction, trace to `codeFlows`, and that the heuristics
  stay unscored.
- SonarQube: start `sonarqube:<pinned community tag>` in Docker on the user's
  machine (only with the user's go-ahead), scan the same tasks, and save the
  API responses as fixtures. Until then the SonarQube tests that need them
  are not written. They are not replaced with invented data.
- Shared: token never in artifacts, missing configuration fails clearly, a
  non-`SUCCESS` background task fails clearly.

End to end, before calling it done: Harbor runs of both agents on two twin
pairs, graded by the tasks' own grader, with every trial status `ok` and
the raw output saved.

## 8. Out of scope

Languages other than Python, Daytona runs, CodeQL licensing for commercial
use, custom CodeQL queries or Sonar quality profiles tuned to the dataset.
