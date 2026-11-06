# Test fixtures

Everything the tests read lives in this folder, so a fresh clone runs the whole
suite with nothing skipped for a missing sibling folder. Tool output here is
recorded from the real tool and never written by hand. The file name says which
tool and version produced it and on which task.

## CodeQL 2.27.1

All CodeQL files come from the CodeQL CLI 2.27.1 bundle (`codeql/python-queries`
1.8.11, suite `python-security-extended.qls`). They were made with the agent's
own command lines (`sast.codeql.agent.create_command` and `analyze_command`) and
its scope file (`codeql_config`), with `--threads=1 --ram=1536` as the tasks'
1 CPU and 2048 MB give, on the task's `environment/repo` mounted at
`/app/repo`. The SARIF is unedited. It still names the local bundle folder in
`tool.extensions[].locations`, which nothing reads.

| File | Recorded on | When |
|---|---|---|
| `codeql_2.27.1_task_7f3a91.json` | `tasks/task_7f3a91` | 2026-10-07 |
| `codeql_2.27.1_task_{3920a8,4da5ab,dc4b7a}_{positive,negative}.json` | the harbor-tasks twins of those ids | 2026-10-07 |
| `codeql_2.27.1_threat-model-local_task_{3920a8,4da5ab}_positive.json` | the same positives with `--threat-model=local` added to `database analyze` | 2026-10-07 |
| `codeql_2.27.1_task_bd9abf_{positive,negative}.json` | the harbor-tasks twins `task_bd9abf_*` | 2026-10-08 |
| `codeql_2.27.1_smoke_eval.json` | `tasks/smoke_eval` | 2026-10-08 |
| `codeql_2.27.1_smoke_web_eval.json` | `tasks/smoke_web_eval` | 2026-10-08 |
| `codeql_2.27.1_crafted_unparseable_files.json` | a crafted repo, see below | 2026-10-08 |
| `codeql_2.27.1_crafted_no_python.json` | a crafted repo, see below | 2026-10-08 |
| `codeql_2.27.1_create_failure_file_in_paths.txt` | a failed `database create`, see below | 2026-10-08 |

The agent does not use `--threat-model=local`. Those two files exist only
because the default (remote) threat model found no path result on any of the 28
twin tasks, and the trace parsing needs real CodeQL code flows.

On 2026-10-08 all 28 harbor tasks and the three sample tasks were scanned again
with the same commands (the measurement in the README). For the seven tasks
recorded on 2026-10-07 with the default threat model, the fresh results, rules,
metrics and file lists equal the recordings above. Only the
order of the `artifacts` array differs between runs.

PR #2 recorded the same tasks with its own commands (`sample_task_7f3a91`,
`smoke_eval`, `smoke_web_eval`, `task_4da5ab_positive`, `task_bd9abf_*`,
`task_dc4b7a_*`). Its results equal our fresh runs on all eight, and so do the
lines-of-code metrics except on `smoke_eval` (15 there, 13 here), because PR #2
extracts the excluded `src/calc_agent/thirdparty` folder and filters afterwards.
The files kept here are therefore our own recordings, which match the agent's
commands exactly.

The crafted repos are not tracked, so here is what they held. Both had a
task.toml with `scanner_roots = ["src"]`, `excluded_paths = ["tests"]`, 1 CPU
and 2048 MB.

- `crafted_unparseable_files`: `src/pkg/ok.py` (a Flask route that passes
  `request.args["q"]` to `eval`), `src/pkg/bad_syntax.py` (`def broken(:` and
  `x = = 2`), `src/pkg/bad_enc.py` (a Latin-1 `é` byte with no coding line),
  `src/pkg/py2.py` (`print "hello"` and `exec "x=1"`) and an empty
  `src/pkg/__init__.py`. CodeQL exited 0, reported lines of code 10, found the
  `eval`, and reported the two unreadable files with
  `py/diagnostics/extraction-warnings` and `py/diagnostics/syntax-error`
  notifications at warning level. The Python 2 file was extracted.
- `crafted_no_python`: only `src/data.json`. CodeQL exited 0 for both steps and
  reported lines of code 0.
- `create_failure_file_in_paths.txt`: the last 25 lines of `database create`
  with `paths: ["src", "p.toml"]`, where `p.toml` is a file. It exits 2 with
  `NotADirectoryError`. The line echoing this machine's `JAVA_TOOL_OPTIONS`
  (proxy settings) was removed. Nothing else was changed.

## Semgrep 1.179.0

`semgrep_1.179.0_<task>.json` is the output of the Semgrep agent's scan command
with the pinned, merged rules on `tasks/<task>`.

## SonarQube

See `sonarqube_26.9_PROVENANCE.txt`.

## Tasks

`tasks/` holds two kinds of folders.

- Full sample tasks (`smoke_empty`, `smoke_eval`, `smoke_eval_node`,
  `smoke_eval_twin`, `smoke_web_eval`, `task_7f3a91`) that the agent tests run
  against and that `harbor run` can use. `smoke_web_eval` comes from PR #2
  unchanged. Its eval input is an HTTP query parameter, a source CodeQL models,
  so it is the one sample where CodeQL reports a dataflow path.
- Grading-only copies of eight harbor-tasks twins (`task_3920a8_*`,
  `task_4da5ab_*`, `task_bd9abf_*`, `task_dc4b7a_*`). Each holds only the
  task's `task.toml`, `tests/grade.py` and `tests/ground_truth.json`, copied
  unchanged on 2026-10-08, which is all the CodeQL grading tests read. They are
  not runnable tasks.
