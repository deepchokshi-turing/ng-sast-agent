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

1. ruleId comes only from the shared CWE table, now `cwe-map-4`. Semgrep maps
   by the rule's primary CWE. CodeQL and SonarQube name no primary CWE, so
   their CWEs are decided as an unordered set with
   `cwe_map.decide_unordered` (revised 2026-10-08, see section 4). No
   tool-specific mapping and no tuning after results.
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
  base.py            lifecycle, budget, artifacts, error policy, and the root
                     and CPU checks every agent uses
  scope.py           the task scope every agent shares: repo-relative roots
                     and excludes, in_scope (added 2026-10-08, from PR #2)
  findings.py        Finding gains an optional trace (see 3.1)
  sarif.py           writes codeFlows only when a Finding has a trace
  cwe_map.py         shared, cwe-map-4 adds decide_unordered (2026-10-08)
  heuristics.py      shared, unchanged
  semgrep/           unchanged apart from the image build and using scope.py
                     (it still re-exports in_scope for older imports)
  codeql/
    pins.py          CodeQL bundle version, URL and sha256 per arch, suite
    install.py       uses /opt/sast/codeql when it matches the pins, else
                     downloads the pinned bundle (revised 2026-10-08)
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
checks `codeql version`, the bundle's `python-queries` pack version and the
suite file against the pins. The first version failed when the bundle was
missing, on the view that the download does not fit in the 300 s setup limit.
A teammate's review and PR #2 showed that it does (about 100 s), and that
without a registry image every Daytona trial would fail at setup. So since
2026-10-08 a missing or different bundle is downloaded for the CPU, its sha256
is checked, the archive entries are checked against escapes (including chained
symlinks), it is unpacked into a staging folder, checked there and moved into
`/opt/sast/codeql`, or into the work folder when that is not writable. The
installer stops itself at 270 s and the download has a hard deadline 90 s
before that, so a slow link fails with a clear message instead of being cut off
by Harbor.

Scan, inside the sandbox:

1. List the Python files under the roots and keep those in scope. None is a
   `ScannerError` before CodeQL runs.
2. Write a CodeQL config file with `paths` = the folder roots of
   `scanner_roots` and `paths-ignore` = `excluded_paths`.
3. `codeql database create <db> --language=python --build-mode=none
   --source-root=/app/repo --codescanning-config=<config> --threads=<cpus>
   --ram=<memory budget>`.
4. `codeql database analyze <db> <python security-extended suite from the
   bundle> --format=sarif-latest --output=<out>/codeql.sarif
   --threads=<cpus> --ram=<memory budget>`.
5. Any non-zero exit, a missing output file, unreadable SARIF or
   `executionSuccessful: false` is a `ScannerError`. So is a
   `py/summary/lines-of-code` metric of 0 or a SARIF without that metric
   (added 2026-10-08, after CodeQL was seen to exit 0 with nothing extracted).
6. Extraction notifications (`toolExecutionNotifications`) at warning and
   error level are recorded in the metadata. Only an error-level one that names
   an in-scope file is a `ScannerError`. On the 28 dataset tasks there were
   none, and files CodeQL could not parse (syntax error, bad encoding) come out
   at warning level with the rest analysed, so they are recorded, not fatal.
   The README gives the evidence.

Normalise: for each result, the CWEs are the rule's `external/cwe/cwe-NNN`
tags. CodeQL defines no primary CWE and lists the tags in numeric order, so
taking the first tag (the first version) silently dropped
`py/clear-text-logging-sensitive-data` (312, 359, 532) through the unmapped
CWE-312 (audit 0.4.0, M1). The tags now go through
`cwe_map.decide_unordered`: unmapped CWEs are ignored, one family is reported,
two families are dropped as ambiguous and counted
(`results_by_cwe_decision`, `results_cwe_ambiguous`). The location is `locations[0]`, made relative to `/app/repo`.
When the result has `codeFlows`, the first thread flow becomes the trace.
`residualRisk` (heuristic only) comes from the rule's `security-severity`
property: 7.0 and above is high, 4.0 to 6.9 medium, lower is low. Results
outside the task scope are dropped, as in the Semgrep agent.

Memory budget: the sandbox memory from the task settings minus 512 MB for the
OS and the agent, never below 1024 MB.

Artifacts: the config file, `codeql.sarif` and the database's `log` and
`diagnostic` folders packed as `codeql-logs.tar.gz`, plus the usual
`findings.sarif`, `metadata.json` and `install.log`. All are kept after a
failed scan too, and packing the logs can never fail a good scan.

## 5. SonarQube agent

Configuration, read on the host from environment variables at the start of
`run()`:

- `SONAR_HOST_URL`, required. The server as the sandbox sees it, for example
  `http://host.docker.internal:9000` for a local Docker server.
- `SONAR_TOKEN`, required. A user token with permission to create and delete
  projects and to browse issues and hotspots.

A missing variable, or a `SONAR_HOST_URL` with a user name or password in it,
is a `ScannerError` before anything runs. Harbor puts exec
environment variables on the command line (`docker compose exec -e`, and
`env NAME=value` on Daytona), so the token never goes through exec env. The
agent uploads it to a mode 600 file in a mode 700 folder under the work
directory. `fetch.py` reads it from that file, and the scanner runs as
`SONAR_TOKEN="$(cat <file>)" exec sonar-scanner ...`, so the token is in the
scanner's environment but in no command line Harbor builds. Writing the file
is inside the same `try` whose `finally` removes it, and the return code of
every step that writes it is checked, so a failed upload or protect step
leaves nothing behind (revised 2026-10-08 after a teammate reproduced the
leak). Tests check that the token appears in no exec
command, exec env, log, metadata, artifact or file left in the sandbox.
(Revised 2026-10-08 after review. The first version passed the token through
exec env.)

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
4. It reads `api/measures/component` (`files`, `ncloc`,
   `ncloc_language_distribution`), then pages through `api/issues/search`
   with `types=VULNERABILITY` and `api/hotspots/search`, and the items read
   must equal each search's `paging.total`. Per rule it calls
   `api/rules/show` (name, type) and `api/rules/search?rule_key=<key>&facets=cwe`,
   because SonarQube 26.9's rules/show does not return security standards.
   The cwe facet is the only place the rule's CWEs appear, as an unordered
   set. The description's resources section is a hand-written reference list
   (S5332 lists 200 and 319, but S4423 lists only 327 while its facet holds
   295, 326 and 327), so it is not a primary CWE and is not used. Every rule
   lookup error is fatal, and the search must answer `paging.total == 1` with
   `rules[0].key` equal to the rule. Raw responses go to `sonarqube.json`.
5. It reads the project's Python quality profile, or the default one, and
   deletes the project (`api/projects/delete`). If deleting fails, the run
   still succeeds and the metadata says the project was left behind.
6. The agent raises `ScannerError` when the analysis looked at nothing: 0
   files, no Python in the language distribution although the scope holds
   `.py` files (counted in the sandbox before the scan), or a Python profile
   with `activeRuleCount` 0. The background task's warnings and the scanner's
   "Unable to parse file" lines are kept in the metadata.

Time: one deadline, the scan budget, covers the check, the scan, the
background task, the measures, the paging and the rule lookups. sonar-scanner
and fetch.py run under `timeout -k 10 <seconds>` inside the sandbox, so a
Harbor timeout that only kills the local `docker compose exec` client cannot
leave the scanner running with the token. Once the scanner has started, the
project is deleted on every exit path, including a timeout and a budget that
runs out between steps, and that cleanup gets a short fixed slice even when
the deadline has passed.

Normalise: only `fetch_format` 2 output is read (format 1 has no CWE and
would report nothing silently). SonarQube gives a rule's CWEs as an unordered
set with no primary CWE, so the decision is `cwe_map.decide_unordered`
(cwe-map-4, shared with CodeQL): unmapped CWEs are ignored, mapped CWEs in one
family give that family, mapped CWEs in several families make the result
ambiguous (dropped and counted), and no mapped CWE means unmapped. Example:
python:S5332 (CWE-200, CWE-319) is LLM02.SID.HIGH. Honest note: the earlier
rule (drop when any CWE is unmapped) was chosen after S5332's CWEs were known,
and it dropped S5332. Under cwe-map-4 S5332 is a false positive in the shared
code of the dc4b7a twins, which lowers precision. The rule is kept because it
is the principled one, not because of that outcome. No trace is ever
emitted from SonarQube: the Community Build has no taint engine, the recorded
issues carry no flows, and the flow order was never verified. Raw flow counts
are kept in the metadata. Each result records `sonarType`
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

- CodeQL bundle 2.27.1 into `/opt/sast/codeql`, the linux64 asset on amd64
  and the linux-arm64 asset on arm64 (arm64 added 2026-10-08, sha256 from the
  GitHub release, as PR #2 pins it). Setup downloads the same pinned bundle
  only when the image does not have it (revised 2026-10-08, see section 4).
- sonar-scanner CLI with its bundled JRE (linux-x64 on amd64, linux-aarch64
  on arm64) into
  `/opt/sast/sonar-scanner`. The exact version and hash are taken from
  binaries.sonarsource.com during implementation and written into
  `sast/sonarqube/pins.py`.

The Semgrep step runs the installer without a pipe, so a failed install fails
the build (audit 0.4.0, L1). The build stages use `python:3.11-slim` by tag,
because no digest for it is recorded here, and the Dockerfile says how to pin
one. `fetch_archive.py` checks tar entries for chained symlink escapes before
unpacking (audit 0.4.0, L2).

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
