# Test fixtures

Every tool-output fixture here is **recorded real output**, never hand-made. The
file name says which tool and version produced it and on which task.

| Fixture | Tool | Produced on | How |
|---|---|---|---|
| `semgrep_1.179.0_<task>.json` | Semgrep OSS 1.179.0, pinned rules | `tasks/<task>` here | the agent's scan command, merged rules |
| `codeql_2.27.1_smoke_web_eval.sarif`, `codeql_2.27.1_smoke_eval.sarif` | CodeQL CLI 2.27.1 bundle, `python-security-extended` | `tasks/smoke_web_eval`, `tasks/smoke_eval` here | `database create --build-mode=none` + `database analyze`, scope `paths: [src]` |
| `codeql_2.27.1_sample_task_7f3a91.sarif`, `codeql_2.27.1_task_<id>_<role>.sarif` | same | the v3 task set (`harbor-tasks`, 2026-10-07): `sample_task_7f3a91`, `task_bd9abf_*`, `task_dc4b7a_*`, `task_4da5ab_positive` | the agent's exact commands and scope config (`sast.codeql.agent.codescanning_config`), under each task's limits (1 CPU, 2048 MB), during the 28-task measurement in `docs/codeql-agent.md` |
| `tasks/` | | | sample tasks the tests grade against (tracked copy; see the README) |

The one exception, `crafted_semgrep_dataflow_trace.json`, was removed in the
v0.3.0 audit fixes.
