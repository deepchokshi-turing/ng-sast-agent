# CodeQL agent

`sast.codeql.agent:CodeQLAgent` runs GitHub CodeQL as a Harbor agent, with no LLM.
It uses the same base as the Semgrep agent (`sast/base.py`): the same lifecycle,
failure policy, artifacts, CWE table, SARIF writer, grader and reports. Only
installing and scanning differ.

## Decisions (2026-10-07)

| Decision | Choice | Why |
|---|---|---|
| Licence | open-source use only | CodeQL is free for open-source code and research; the tasks are adapted open source plus synthetic code |
| Version | CodeQL CLI **2.27.1** (bundle `codeql-bundle-v2.27.1`) | the version the earlier SAST sheet used; 2.27.2 came out the same day and is not used |
| Queries | bundled `python-security-extended` / `javascript-security-extended` suites | stock queries only, as in the earlier sheet; no custom queries, no extra source models |
| Install | **baked into `sast-tools`** (`/opt/sast/codeql`), install at setup as fallback | the bundle is about 650 MB; installing in the sandbox takes about 100 s and is network-bound |
| Build mode | `--build-mode=none` | Python and JS/TS need no build, so no task changes |
| Scope | CodeQL `paths` / `paths-ignore` (`--codescanning-config`), plus the shared post-filter | same semantics as Semgrep (`sast/scope.py`): "/" anchors at the repo root, a bare name matches at any depth, bytecode always skipped |
| CWEs | the query's own `external/cwe/cwe-NNN` tags, first tag = primary | then the same frozen `cwe_map` as Semgrep |
| Paths | CodeQL's `codeFlows`, passed through as-is | the tool's own dataflow path; source and sink marked, middle steps unlabelled |
| Judgment fields | under `properties.heuristics`, unscored | same as Semgrep |

## What a run does

1. **setup:** upload `codeql_install.py` and `codeql-pins.json` (own names, so the
   Semgrep installer in the same `/opt/sast` is never overwritten). The
   installer reuses `/opt/sast/codeql` if `install.json` matches the pins and
   `codeql version` agrees. Otherwise it downloads the pinned bundle for the CPU
   (linux64 or linux-arm64), checks its sha256, extracts it, and checks two
   things: that the pinned query packs are there (`codeql/python-queries`
   1.8.11, `codeql/javascript-queries` 2.4.6), and that both suites resolve
   (52 Python and 105 JS/TS queries).
2. **run:**
   - read the scope and limits (`scanner_roots`, `excluded_paths`, CPUs, memory,
     timeout);
   - list the source files and keep the languages with at least one file in scope;
   - write the `paths`/`paths-ignore` config;
   - `codeql database create --db-cluster --language=... --build-mode=none`
     (log: `agent/command-1/stdout.txt`);
   - `codeql database analyze` once per language with its suite, SARIF output
     (logs: `command-2`, `command-3`);
   - normalise, map CWEs, write `findings.sarif`;
   - keep as artifacts: CodeQL's raw SARIF per language, the config, and
     CodeQL's own log folders (`codeql-logs.tar.gz`). The logs are packed after a
     failed step too.
3. **Limits:** `--threads` = the sandbox's CPUs, `--ram` = memory − 512 MB. All
   steps share one scan budget (agent timeout − 120 s).

## Failure policy (errored, never graded 0)

- install failed: no python3, download or sha256 failure, or more than 300 s
  (a bake avoids this);
- no Python or JS/TS file in the scope;
- `database create` or `analyze` exits non-zero, out of memory (137), or runs
  out of time (124);
- CodeQL's own "lines of code" metric is 0 for a language (nothing extracted);
- unreadable SARIF.

## What to expect

CodeQL tracks data from the sources its libraries model: HTTP requests, files,
environment variables, command-line arguments. **Model output is not one of
them.** A flow that starts at an LLM reply (model output → tool → `eval`) is
invisible to the stock queries. This is by design: adding "LLM output is a
source" models would be building a detector, not measuring CodeQL.

The two sample tasks show both sides:

| Task | What flows into `eval` | CodeQL | Semgrep |
|---|---|---|---|
| `smoke_web_eval` | an HTTP query parameter | found, with a 12-step path from the request to `eval`: reward **0.70** (detection 0.35 + classification 0.05 + path 0.30) | found, no path: 0.40 |
| `smoke_eval` | the model's reply | nothing (not a modelled source) | found by the `eval` pattern: 0.40 |

## Measured on the real tasks (2026-10-07)

How it was run:
- CodeQL 2.27.1, exactly as the agent runs it (same scope config, threads and
  RAM);
- on all 28 dataset tasks plus `sample_task_7f3a91`;
- each under the task's own limits: 1 CPU, 2048 MB, agent timeout 900 s
  (scan budget 780 s).

| | Result |
|---|---|
| Runs that completed | **29 / 29** (database create and analyze both exit 0) |
| Time per task (create + analyze) | 33–47 s, median 39 s (create 7–11 s, analyze 25–38 s) |
| Peak memory | 1135–1254 MB, median 1215 MB, against a 2048 MB limit |
| Lines of Python extracted | 166–1719 per task |
| Tasks with any result | 6 (both twins of `4da5ab`, `795c39`, `dc4b7a`) |
| Known bugs detected | **0 of 14** positive tasks |

**What the 6 results are:**
- `py/insecure-protocol` (CWE-327) in `4da5ab`'s HTTP shim;
- `py/incomplete-url-substring-sanitization` (CWE-20) in `data_types.py` in
  `795c39` and `dc4b7a`.

They are identical in both twins and not related to the labelled bugs. Their
CWEs are outside the OWASP mapping, so they are not reported, and no reward
changes.

**Conclusion:** no task change is needed for CodeQL. The tasks' 2 GB and 900 s
are enough, with about 40% memory headroom and about 95% time headroom. The
result matches the earlier SAST sheet (CodeQL caught 1 of 26) and the reason
given above: these bugs start at model output, which CodeQL does not treat as
untrusted input.

**A bug this run caught:** with the tasks' `scanner_roots`, which include
`security_manifest.json` and `pyproject.toml`, the first attempt failed on every
task. CodeQL's Python extractor raises `NotADirectoryError` for a file in
`paths`. `codescanning_config` now lists only directory roots, and a test
covers it.
