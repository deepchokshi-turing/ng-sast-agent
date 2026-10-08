#!/usr/bin/env python3
"""Compile several Harbor scanner jobs into one comparative eval report.

    python tools/eval_report.py <job dir> [<job dir> ...] [--tasks <tasks dir>] [--out <dir>]

Each <job dir> is a Harbor job (holding trial folders) or a jobs folder such as
harbor-jobs/semgrep-v040-all, in which case its latest job is used. One job per
tool is expected; the tool name comes from the agent metadata.

The per-tool numbers are the ones tools/report.py computes (it is imported, so
both reports always agree). On top of them this script adds:

- a headline table with one column per tool,
- OWASP category and risk-type tables side by side,
- a task matrix (each task pair, every tool),
- the result funnel per tool: raw tool results, security results, results
  mapped to an OWASP rule, results written to the SARIF, and the CWEs that
  were dropped because no OWASP rule covers them,
- every false positive and every true positive, with rule and location, read
  from each trial's verifier/grading_detail.json.

With --out it writes eval_report.md, eval_report.json, eval_report.html and
trials.csv there. The HTML is tools/eval_report.html with the JSON embedded,
laid out along the client's four measurements (risk detection, reachability and
path tracing, mitigation detection, mitigation recommendation), with the
ambiguous negatives, the per-family results and the scanner output after them.
The Markdown is always printed. Standard library only.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import report  # noqa: E402  (tools/report.py)

fmt = report.fmt


def read_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def resolve_job(path: Path) -> Path:
    """A job dir, or the latest job inside a jobs dir."""
    if report.trial_results(path):
        return path
    nested = sorted(p for p in path.iterdir() if p.is_dir() and report.trial_results(p))
    if not nested:
        sys.exit(f"eval_report: no Harbor trials found under {path}")
    return nested[-1]


def sarif_results(trial_dir: Path) -> list:
    """The results of the SARIF the verifier graded (the agent's own copy)."""
    for candidate in (trial_dir / "agent" / "findings.sarif",
                      trial_dir / "artifacts" / "logs" / "artifacts" / "sast" / "findings.sarif"):
        data = read_json(candidate)
        if isinstance(data, dict):
            return [r for run in data.get("runs") or [] for r in run.get("results") or []]
    return []


def result_at(results: list, index) -> dict:
    return results[index] if isinstance(index, int) and 0 <= index < len(results) else {}


def res_location(res: dict) -> list:
    try:
        phys = res["locations"][0]["physicalLocation"]
        region = phys.get("region") or {}
        return [phys["artifactLocation"]["uri"], region.get("startLine"), region.get("endLine")]
    except (KeyError, IndexError, TypeError):
        return []


def mean(values):
    values = [v for v in values if v is not None]
    return sum(values) / len(values) if values else None


def task_id(task: str) -> tuple[str, str]:
    """task_3c67f1_positive -> ("3c67f1", "positive")."""
    name = task.split("/")[-1]
    parts = name.split("_")
    if len(parts) >= 3 and parts[-1] in ("positive", "negative"):
        return "_".join(parts[1:-1]), parts[-1]
    return name, ""


# ---- per job ---------------------------------------------------------------------------

def collect(job: Path, tasks_dir: Path | None) -> dict:
    rows = report.rows_for(job, tasks_dir)
    summary = report.summarise(rows)
    trials = []
    funnel = Counter()
    unmapped = Counter()
    by_rule = Counter()
    versions = Counter()
    manifest = Counter()
    hits = []
    false_positives = []
    for result_file, trial in report.trial_results(job):
        trial_dir = result_file.parent
        meta = (trial.get("agent_result") or {}).get("metadata") or {}
        task = str(trial.get("task_name") or trial_dir.name).split("/")[-1]
        detail = read_json(trial_dir / "verifier" / "grading_detail.json") or {}
        for key in ("results_raw", "findings_security", "findings_mapped", "results_emitted"):
            funnel[key] += meta.get(key) or 0
        unmapped.update(meta.get("unmapped_by_cwe") or {})
        by_rule.update(meta.get("results_by_rule") or {})
        versions[meta.get("agent_version") or meta.get("tool_version") or "?"] += 1
        im = meta.get("image_manifest") or {}
        if im.get("manifest_sha256"):
            manifest[im["manifest_sha256"][:12]] += 1
        results = sarif_results(trial_dir)
        for f in detail.get("per_finding") or []:
            if f.get("matched"):
                res = result_at(results, f.get("result_index"))
                hits.append({"task": task, "finding": f.get("finding"), "rule": f.get("ruleId", ""),
                             "location": res_location(res), "cwe_ok": f.get("cwe_ok"),
                             "scores": f.get("scores") or {}})
        # On a positive, trap_hits only tag results already listed as unmatched.
        traps_by_index: dict = {}
        for th in detail.get("trap_hits") or []:
            if "result_index" in th:
                traps_by_index.setdefault(th["result_index"], []).append(th.get("trap", ""))
        for kind, key in (("unmatched", "unmatched_results"), ("trap", "trap_hits"),
                          ("near_fix", "results_near_fixed_code")):
            for res in detail.get(key) or []:
                if kind == "trap" and "result_index" in res:
                    continue
                traps = list(res.get("traps") or []) + traps_by_index.get(res.get("index"), [])
                false_positives.append({"task": task, "kind": kind, "rule": res.get("ruleId", ""),
                                        "location": res.get("location") or "",
                                        "traps": ",".join(traps)})
        trials.append({"task": task, "detail": detail})
    tool = next((r["tool"] for r in rows if r.get("tool")), job.parent.name)
    return {
        "tool": tool, "job": str(job), "rows": rows, "summary": summary,
        "funnel": dict(funnel), "unmapped_by_cwe": dict(unmapped.most_common()),
        "results_by_rule": dict(by_rule.most_common()), "agent_versions": dict(versions),
        "image_manifests": dict(manifest), "hits": hits, "false_positives": false_positives,
        "job_result": read_json(job / "result.json") or {},
    }


# ---- rendering -------------------------------------------------------------------------

def headline(jobs: list[dict]) -> list[list]:
    def row(label, fn):
        return [label] + [fn(j) for j in jobs]

    def det(j, key):
        d = j["summary"]["pooled_detection"] or {}
        return d.get(key)

    def role(j, r, key):
        return j["summary"]["reward_by_role"][r].get(key)

    def cat(j, key):
        return j["summary"]["categories"]["overall"].get(key)

    def errored(j):
        return sum(1 for r in j["rows"] if r["status"] != "ok")

    def scan(j):
        return mean([r.get("scan_s") for r in j["rows"]])

    def setup(j):
        return mean([r.get("setup_s") for r in j["rows"]])

    def emitted_trials(j):
        return sum(1 for r in j["rows"] if (r.get("emitted") or 0) > 0)

    neg_clean = lambda j: "{}/{}".format(*j["summary"]["zero_finding_tasks_clean"])  # noqa: E731
    return [
        row("Trials (ok / not ok)", lambda j: f"{len(j['rows']) - errored(j)} / {errored(j)}"),
        row("Results written to SARIF (trials with any)",
            lambda j: f"{j['funnel'].get('results_emitted', 0)} ({emitted_trials(j)})"),
        row("Ground-truth findings (positives)", lambda j: det(j, "gt")),
        row("True positives", lambda j: det(j, "tp")),
        row("False positives on positives", lambda j: det(j, "fp")),
        row("False negatives", lambda j: det(j, "fn")),
        row("Precision", lambda j: fmt(det(j, "precision")) or "n/a"),
        row("Recall", lambda j: fmt(det(j, "recall"))),
        row("F1", lambda j: fmt(det(j, "F1")) or "n/a"),
        row("Negatives clean", neg_clean),
        row("Negatives failed on a trap / near the fix",
            lambda j: f"{role(j, 'negative', 'failed_trap')} / {role(j, 'negative', 'failed_near_fix')}"),
        row("Mean reward, positives", lambda j: fmt(role(j, "positive", "mean_reward"))),
        row("Mean reward, negatives", lambda j: fmt(role(j, "negative", "mean_reward"))),
        row("OWASP mean TPR", lambda j: fmt(cat(j, "mean_TPR"))),
        row("OWASP mean FPR", lambda j: fmt(cat(j, "mean_FPR"))),
        row("OWASP score (TPR minus FPR)", lambda j: fmt(cat(j, "score"))),
        row("Results outside scope (not scored)", lambda j: j["summary"]["fp_outside_scope"]),
        row("Mean setup seconds", lambda j: f"{setup(j):.1f}" if setup(j) is not None else ""),
        row("Mean scan seconds", lambda j: f"{scan(j):.1f}" if scan(j) is not None else ""),
    ]


def category_rows(jobs: list[dict]) -> list[list]:
    cats = sorted({c for j in jobs for c in j["summary"]["categories"]["per_category"]})
    out = []
    for c in cats:
        line = [c]
        for j in jobs:
            v = j["summary"]["categories"]["per_category"].get(c)
            line.append("" if not v else
                        f"TPR {fmt(v['TPR'])}, FPR {fmt(v['FPR'])} ({v['TP']}/{v['TP'] + v['FN']} hit, "
                        f"{v['FP']}/{v['FP'] + v['TN']} false)")
        out.append(line)
    return out


def risk_rows(jobs: list[dict], key: str) -> list[list]:
    out = []
    for risk in report.RISKS.values():
        line = [risk]
        for j in jobs:
            v = j["summary"][key][risk]
            line.append(f"TPR {fmt(v['TPR'])}, FPR {fmt(v['FPR'])} (TP {v['TP']}, FP {v['FP']})")
        out.append(line)
    exact = sorted({k for j in jobs for k in j["summary"][key]["by_truth_set"]})
    for k in exact:
        line = [f"exact risk set, {k}"]
        for j in jobs:
            v = j["summary"][key]["by_truth_set"].get(k)
            line.append(f"{v['exact']}/{v['tasks']}" if v else "")
        out.append(line)
    return out


def matrix_rows(jobs: list[dict]) -> list[list]:
    cells: dict[str, dict] = {}
    for idx, j in enumerate(jobs):
        for r in j["rows"]:
            tid, role = task_id(r["task"])
            entry = cells.setdefault(tid, {})
            if r["reward"] is None:
                text = r["status"]
            elif role == "positive":
                text = f"{r['tp'] or 0}/{r['gt'] or 0} found" + (f", {r['fp']} FP" if r.get("fp") else "")
            else:
                text = "clean" if (r["fp"] or 0) == 0 else f"FAIL ({r['fp']} FP)"
            entry[(idx, role)] = text
    out = []
    for tid in sorted(cells):
        line = [tid]
        for idx in range(len(jobs)):
            line.append(cells[tid].get((idx, "positive"), ""))
            line.append(cells[tid].get((idx, "negative"), ""))
        out.append(line)
    return out


def funnel_rows(jobs: list[dict]) -> list[list]:
    labels = [("results_raw", "Raw tool results"), ("findings_security", "Security results"),
              ("findings_mapped", "Mapped to an OWASP rule"), ("results_emitted", "Written to the SARIF")]
    rows = [[label] + [j["funnel"].get(key, 0) for j in jobs] for key, label in labels]
    rows.append(["Top dropped CWEs (no OWASP rule)"] +
                [", ".join(f"{k} x{v}" for k, v in list(j["unmapped_by_cwe"].items())[:6]) for j in jobs])
    rows.append(["Emitted by OWASP rule"] +
                [", ".join(f"{k} x{v}" for k, v in j["results_by_rule"].items()) for j in jobs])
    return rows


def loc(v) -> str:
    if isinstance(v, (list, tuple)) and v:
        return f"{v[0]}:{v[1]}" if len(v) > 1 else str(v[0])
    if isinstance(v, dict):
        return f"{v.get('file', '')}:{v.get('start_line', '')}"
    return str(v or "")


def observations(jobs: list[dict]) -> list[str]:
    notes = []
    for j in jobs:
        s = j["summary"]
        det = s["pooled_detection"] or {}
        if s["no_results_emitted"]:
            notes.append(f"{j['tool']} wrote no result on any task, so its negatives pass by default and its "
                         f"scores say nothing about the tool.")
        if det and not det.get("tp"):
            raw = j["funnel"].get("results_raw", 0)
            notes.append(f"{j['tool']} found none of the {det.get('gt')} ground-truth findings. It produced "
                         f"{raw} raw results, of which {j['funnel'].get('results_emitted', 0)} reached the SARIF.")
        fails = s["reward_by_role"]["negative"]["failed"]
        if fails:
            notes.append(f"{j['tool']} failed {fails} of {s['reward_by_role']['negative']['tasks']} negatives "
                         f"(the fixed code), so it would flag safe code as vulnerable there.")
    tps = {j["tool"]: (j["summary"]["pooled_detection"] or {}).get("tp") or 0 for j in jobs}
    if tps and max(tps.values()) == 0:
        notes.append("No tool detected any ground-truth finding. The OWASP scores below are therefore driven only "
                     "by false positives on negatives.")
    return notes


def render(jobs: list[dict], tasks_dir: Path | None) -> str:
    t = report.md_table
    tools = [j["tool"] for j in jobs]
    out = ["# SAST scanner eval report", "",
           f"Generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} from "
           f"{len(jobs)} Harbor jobs. Ground truth from {tasks_dir or 'the paths recorded in the trials'}.", ""]
    for j in jobs:
        versions = ", ".join(j["agent_versions"])
        manifests = ", ".join(j["image_manifests"]) or "not recorded"
        out.append(f"- **{j['tool']}**: agent {versions}, image manifest {manifests}, job `{j['job']}`")
    notes = observations(jobs)
    if notes:
        out += ["", "## Key observations", ""] + [f"- {n}" for n in notes]
    out += ["", "## Headline", ""]
    out.append("Positive tasks hold the vulnerable code, negative tasks the fixed twin. Rewards are never "
               "averaged over both, since an empty SARIF scores 1.0 on every negative.")
    out += t(["Measure"] + tools, headline(jobs))
    out += ["", "## OWASP categories", "",
            "One test case per task and category (OWASP Benchmark style). A category hit means a matched result "
            "on a positive, and a false hit means a result on a negative that fails it."]
    out += t(["Category"] + tools, category_rows(jobs))
    out += ["", "## Risk types (task level)", ""]
    out += t(["Risk type"] + tools, risk_rows(jobs, "risk_types"))
    out += ["", "## Result funnel", "",
            "Where each tool's results went. Results whose CWEs no OWASP LLM02/LLM03 rule covers are dropped "
            "before the SARIF is written."]
    out += t(["Stage"] + tools, funnel_rows(jobs))
    out += ["", "## Task matrix", ""]
    header = ["Task"] + [f"{tool} {role}" for tool in tools for role in ("positive", "negative")]
    out += t(header, matrix_rows(jobs))
    out += ["", "## True positives", ""]
    hits = [[j["tool"], h["task"], h["finding"], h["rule"], loc(h["location"]), h["cwe_ok"],
             h["scores"].get("detection"), h["scores"].get("classification")] for j in jobs for h in j["hits"]]
    out += (t(["Tool", "Task", "Finding", "Rule", "Location", "CWE ok", "Detection", "Classification"], hits)
            if hits else ["None. No tool matched any ground-truth finding."])
    out += ["", "## False positives", "",
            "`unmatched` is a result near no finding on a positive (Traps names a decoy it landed on), `trap` a "
            "result on a negative's decoy, `near_fix` a result on a negative next to the fixed code."]
    fps = [[j["tool"], f["task"], f["kind"], f["rule"], loc(f["location"]), f["traps"]]
           for j in jobs for f in j["false_positives"]]
    out += t(["Tool", "Task", "Kind", "Rule", "Location", "Traps"], fps) if fps else ["None."]
    errors = [[j["tool"], r["task"], r["status"], r["error"]] for j in jobs for r in j["rows"] if r["status"] != "ok"]
    if errors:
        out += ["", "## Trials that did not finish cleanly", ""]
        out += t(["Tool", "Task", "Status", "Error"], errors)
    out += ["", "## Note", "", report.HARBOR_MEAN_WARNING, ""]
    return "\n".join(out)


HTML_TEMPLATE = Path(__file__).resolve().parent / "eval_report.html"
DATA_MARKER = '<script id="report-data" type="application/json">null</script>'


def build_payload(jobs: list[dict], tasks_dir: Path | None) -> dict:
    """What eval_report.json holds and the HTML view reads."""
    return {
        "schema": "sast-eval-report/1",
        "generated": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "tasks_dir": str(tasks_dir) if tasks_dir else None,
        "observations": observations(jobs),
        "harbor_mean_warning": report.HARBOR_MEAN_WARNING,
        "tools": [{k: v for k, v in j.items() if k != "rows"} | {"trials": j["rows"]} for j in jobs],
    }


def render_html(payload: dict) -> str:
    """tools/eval_report.html with the report embedded, so the file opens on its own.

    The template also works without embedded data: served next to an
    eval_report.json it fetches it, and opened from disk it offers a file picker.
    """
    template = HTML_TEMPLATE.read_text(encoding="utf-8")
    if DATA_MARKER not in template:
        raise SystemExit(f"eval_report: {HTML_TEMPLATE} has no data placeholder")
    # "<" escaped so no string in the data can close the script element.
    data = json.dumps(payload, default=str).replace("<", "\\u003c")
    return template.replace(DATA_MARKER, DATA_MARKER.replace(">null<", ">" + data + "<"), 1)


CSV_COLUMNS = ["tool", "task", "status", "reward", "tp", "fp", "fn", "gt", "fp_out", "raw", "security",
               "emitted", "setup_s", "scan_s", "detection", "classification", "path", "controls",
               "recommendations", "neg_fail_trap", "neg_fail_near_fix", "error"]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("jobs", type=Path, nargs="+", help="Harbor job dirs or jobs folders, one per tool")
    parser.add_argument("--tasks", type=Path, help="folder holding the task directories, for ground truth")
    parser.add_argument("--out", type=Path, help="write eval_report.md, eval_report.json and trials.csv here")
    args = parser.parse_args()

    jobs = [collect(resolve_job(p), args.tasks) for p in args.jobs]
    markdown = render(jobs, args.tasks)
    if args.out:
        args.out.mkdir(parents=True, exist_ok=True)
        (args.out / "eval_report.md").write_text(markdown, encoding="utf-8")
        payload = build_payload(jobs, args.tasks)
        (args.out / "eval_report.json").write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
        (args.out / "eval_report.html").write_text(render_html(payload), encoding="utf-8")
        with open(args.out / "trials.csv", "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=CSV_COLUMNS, extrasaction="ignore")
            writer.writeheader()
            for j in jobs:
                for r in j["rows"]:
                    writer.writerow({**r, "tool": j["tool"]})
    sys.stdout.reconfigure(encoding="utf-8")
    print(markdown)


if __name__ == "__main__":
    main()
