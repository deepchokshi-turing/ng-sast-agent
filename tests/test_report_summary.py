"""The plain-English summary at the top of eval_report.md and eval_report.html: it comes first,
uses no scanner-testing terms, its counts are the scoreboard's, the three measurement cells read
a percent, "not provided by this tool" or "nothing to judge" in the right cases, and every old
section is still there under "Details for reviewers"."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import eval_report  # noqa: E402
from tests.test_eval_report import (  # noqa: E402
    GT_NEG, GT_POS, add, job_dir, make_tasks, neg_rewards, pos_rewards, result, run, standard_pair)

BANNED = ["TPR", "FPR", "F1", "precision", "recall", "SARIF", "CWE", "ruleId", "ground truth", "positive",
          "positives", "negative", "negatives", "OWASP", "decoy", "decoys", "trial", "trials", "funnel",
          "codeFlows"]

OLD_SECTIONS = ["Key observations", "Versions and run configuration", "Dataset", "Scoreboard",
                "Measurement 1: risk detection", "Measurement 1, loose rule (secondary view)",
                "Measurements 2 to 4: path, controls and recommendations", "OWASP categories", "Result funnel",
                "Task matrix", "True positives", "False positives", "Results outside scope (not scored)", "Method",
                "Note"]

CLAUDE_META = {"tool": "claude-code-security-review", "model": "claude-opus-5-5", "mode": "stock", "auth": "oauth",
               "category_map": "ccsr-category-map-1", "findings_unmapped": 2,
               "unmapped_by_category": {"prompt_injection_data_exfiltration": 2},
               "claude_review": {"mode": "stock", "auth": "oauth", "filter_mode": "hard_rules",
                                 "results_label": "stock CLI + hard-rule filter", "model": "claude-opus-5-5"}}


def build(tmp_path, monkeypatch, capsys):
    """Four tools: one that matched nothing (plain), one that wrote nothing (codeql), one that matched
    a finding with a path and recommendations but no control status (rich), and a stock-mode Claude
    review that matched a finding with none of the three fields and failed the fixed app."""
    tasks = make_tasks(tmp_path, {"task_fam1_positive": GT_POS, "task_fam1_negative": GT_NEG})
    plain = job_dir(tmp_path, "semgrep")
    standard_pair(plain, "semgrep")
    quiet = job_dir(tmp_path, "codeql")
    standard_pair(quiet, "codeql", emit=False)
    rich = job_dir(tmp_path, "sonarqube")
    flow = {"codeFlows": [{"threadFlows": [{"locations": []}]}], "properties": {"recommendations": ["r1"]}}
    add(rich, "task_fam1_positive", "sonarqube", pos_rewards(hit=True, path=0.25, recommendations=0.5),
        {"per_finding": [{"finding": "F1", "matched": True, "result_index": 0, "ruleId": "LLM02.SID.HIGH",
                          "cwe_ok": True, "scores": {"path": 0.5}}], "unmatched_results": [], "trap_hits": []},
        [{**result("LLM02.SID.HIGH", "src/app.py", 10), **flow}], {"results_emitted": 1})
    add(rich, "task_fam1_negative", "sonarqube", neg_rewards(), {"negative": True}, [], {"results_emitted": 0})
    claude = job_dir(tmp_path, "claude")
    add(claude, "task_fam1_positive", "claude-code-security-review",
        pos_rewards(hit=True, tp=1, fp=1, reward=0.204),
        {"per_finding": [{"finding": "F1", "matched": True, "result_index": 0, "ruleId": "LLM02.SID.MEDIUM",
                          "cwe_ok": True, "scores": {}}],
         "unmatched_results": [{"index": 1, "ruleId": "LLM03.EA.FUNCTIONALITY", "location": ["src/tool.py", 40, 40]}],
         "trap_hits": []},
        [result("LLM02.SID.MEDIUM", "src/app.py", 10), result("LLM03.EA.FUNCTIONALITY", "src/tool.py", 40)],
        {**CLAUDE_META, "results_emitted": 2})
    add(claude, "task_fam1_negative", "claude-code-security-review", neg_rewards(fail=True),
        {"negative": True, "trap_hits": [], "results_near_fixed_code": [
            {"index": 0, "ruleId": "LLM02.SID.MEDIUM", "location": ["src/app.py", 20, 20]}]},
        [result("LLM02.SID.MEDIUM", "src/app.py", 20)], {**CLAUDE_META, "results_emitted": 1})
    return run(monkeypatch, capsys, plain.parent, quiet.parent, rich.parent, claude.parent, "--tasks", tasks,
               "--out", tmp_path / "o")


def summary_part(md: str) -> str:
    return md.split("\n## Details for reviewers")[0]


def texts(value):
    """Every string in the payload's summary block, except the tool keys (identifiers, not prose)."""
    if isinstance(value, dict):
        return [s for k, v in value.items() if k != "key" for s in texts(v)]
    if isinstance(value, list):
        return [s for v in value for s in texts(v)]
    return [value] if isinstance(value, str) else []


def test_summary_comes_first_and_details_follow(tmp_path, monkeypatch, capsys):
    md, payload, html = build(tmp_path, monkeypatch, capsys)
    lines = md.splitlines()
    assert lines[0] == "# Scanner evaluation: summary"
    assert re.fullmatch(r"\d{1,2} [A-Z][a-z]+ \d{4}\. 2 apps: 1 vulnerable, 1 fixed copy\. 2 known issues in the "
                        r"vulnerable apps\.", lines[2]), lines[2]
    order = [lines.index(h) for h in ("## What was tested", "## Results at a glance", "## Results by risk type",
                                      "## What this means", "## Words used in this report",
                                      "## Details for reviewers")]
    assert order == sorted(order)
    details = md.split("\n## Details for reviewers\n")[1]
    assert details.lstrip().startswith(eval_report.DETAILS_INTRO)
    # The old header block (generated date, jobs, versions) is in the details part, not at the top.
    assert "Generated " in details and "Generated " not in summary_part(md)
    assert "image manifest" in details and "# SAST scanner eval report" not in md
    # Every old section is still there, one level down, and nothing else is at level 2 below the details.
    for title in OLD_SECTIONS:
        assert f"\n### {title}\n" in details, title
    assert not re.search(r"^## ", details, re.M)
    # The HTML reads the same block and folds the old views away.
    assert payload["summary"]["title"] == "Scanner evaluation: summary"
    assert "renderSummary" in html and '"details-body"' in html and "Show details" in html
    for key in ("schema", "generated", "tasks_dir", "dataset", "coverage_note", "warnings", "observations",
                "scoreboard", "measurement_rows", "versions", "method", "not_supported", "no_results_measure",
                "no_results_badge", "harbor_mean_warning", "tools"):
        assert key in payload, key


def test_summary_uses_no_jargon(tmp_path, monkeypatch, capsys):
    md, payload, _ = build(tmp_path, monkeypatch, capsys)
    for text in [summary_part(md)] + texts(payload["summary"]):
        for word in BANNED:
            assert not re.search(rf"\b{re.escape(word)}\b", text, re.I), (word, text)
        assert "—" not in text and ";" not in text, text
    # Counts are "x of y" and percentages whole numbers, never decimals.
    assert not re.search(r"\d\.\d", summary_part(md).replace("Opus 5.5", ""))


def test_summary_counts_match_the_scoreboard(tmp_path, monkeypatch, capsys):
    md, payload, _ = build(tmp_path, monkeypatch, capsys)
    board = {r[0]: r[1:] for r in payload["scoreboard"]["rows"]}
    glance = {r[0]: r[1:] for r in payload["summary"]["at_a_glance"]["rows"]}
    gts = [str(v) for v in board["Ground-truth findings on scored positives"]]
    tps = [str(v) for v in board["True positives (findings matched)"]]
    assert glance["Known issues found"] == [f"{tp} of {gt}" for tp, gt in zip(tps, gts)]
    assert glance["False alarms on the vulnerable apps"] == [str(v) for v in board["False positives on positives"]]
    clean = [v.split("/") for v in board["Negatives clean"]]
    assert glance["Fixed apps wrongly flagged"] == [f"{int(n) - int(c)} of {n}" for c, n in clean]
    rewards = [float(v) for v in board["Mean reward, positives"]]
    assert glance["Average score on vulnerable apps (0–100)"] == [str(eval_report.whole_percent(r)) for r in rewards]
    assert glance["Known issues found"] == ["0 of 2", "0 of 2", "1 of 2", "1 of 2"]
    assert glance["Fixed apps wrongly flagged"] == ["0 of 1", "0 of 1", "0 of 1", "1 of 1"]
    assert glance["Average score on vulnerable apps (0–100)"][3] == "20"
    # By risk type, the issues add up to the known issues found, over the same totals.
    risk = {r[0]: r[1:] for r in payload["summary"]["by_risk"]["rows"]}
    assert risk["Data disclosure issues found"] == ["0 of 1", "0 of 1", "1 of 1", "1 of 1"]
    assert risk["Excessive agency issues found"] == ["0 of 1"] * 4
    # Short tool names from the agent metadata, the same in both tables and in the Markdown.
    names = ["Semgrep", "CodeQL", "SonarQube", "Claude (Opus 5.5, stock)"]
    assert payload["summary"]["at_a_glance"]["columns"] == [""] + names
    assert "|  | Semgrep | CodeQL | SonarQube | Claude (Opus 5.5, stock) |" in md
    assert "| Known issues found | 0 of 2 | 0 of 2 | 1 of 2 | 1 of 2 |" in md


def test_measurement_cells_read_a_percent_not_provided_or_nothing_to_judge(tmp_path, monkeypatch, capsys):
    md, payload, _ = build(tmp_path, monkeypatch, capsys)
    glance = {r[0]: r[1:] for r in payload["summary"]["at_a_glance"]["rows"]}
    nothing, absent = eval_report.NOTHING_TO_JUDGE, eval_report.NOT_PROVIDED
    # semgrep and codeql matched nothing, sonarqube matched with a path and recommendations, Claude matched
    # with none of the three fields.
    assert glance["Described how the issue is reached"] == [nothing, nothing, "25%", absent]
    assert glance["Judged existing protections"] == [nothing, nothing, absent, absent]
    assert glance["Suggested fixes"] == [nothing, nothing, "50%", absent]
    assert f"| Suggested fixes | {nothing} | {nothing} | 50% | {absent} |" in md


def test_what_this_means_sentences_and_caveats(tmp_path, monkeypatch, capsys):
    md, payload, _ = build(tmp_path, monkeypatch, capsys)
    tools = {t["name"]: t for t in payload["summary"]["tools"]}
    assert tools["Semgrep"]["tested"] == "Semgrep: a pattern-matching code scanner."
    assert tools["CodeQL"]["tested"] == "CodeQL: a code-analysis scanner from GitHub."
    assert "Opus 5.5 model" in tools["Claude (Opus 5.5, stock)"]["tested"]
    assert "ran as shipped (stock mode)" in tools["Claude (Opus 5.5, stock)"]["tested"]
    semgrep = " ".join(tools["Semgrep"]["meaning"])
    assert semgrep.startswith("Semgrep found 0 of 2 known issues and raised no alarm on the fixed apps.")
    assert "nothing to judge for paths, protections or fixes" in semgrep
    codeql = " ".join(tools["CodeQL"]["meaning"])
    assert "CodeQL reported nothing, so its clean results on fixed apps say nothing about it." in codeql
    sonar = " ".join(tools["SonarQube"]["meaning"])
    assert "It scored 25% on describing how the issue is reached and 50% on suggesting fixes." in sonar
    assert "It did not describe protections in a form that can be scored." in sonar
    claude = " ".join(tools["Claude (Opus 5.5, stock)"]["meaning"])
    assert claude.startswith("Claude (Opus 5.5, stock) found 1 of 2 known issues, raised 1 false alarm on the vulnerable "
                             "apps and wrongly flagged 1 of 1 fixed apps.")
    assert "It did not describe paths, protections or fixes in a form that can be scored." in claude
    assert "category names are not in our fixed list. 4 findings were dropped here." in claude  # 2 per run
    assert "without the extra AI check that normally removes false alarms" in claude
    assert "Each tool ran once per app" in " ".join(payload["summary"]["notes"])
    terms = [g["term"] for g in payload["summary"]["glossary"]]
    assert 5 <= len(terms) <= 8 and {"Known issue", "False alarm", "Fixed app", "Data disclosure",
                                     "Excessive agency"} <= set(terms)
    assert "## What this means" in md and claude in md


def test_markdown_and_payload_share_one_summary(tmp_path, monkeypatch, capsys):
    md, payload, html = build(tmp_path, monkeypatch, capsys)
    assert summary_part(md).rstrip("\n") == "\n".join(eval_report.summary_markdown(payload["summary"]))
    start = html.index('<script id="report-data" type="application/json">') + len(
        '<script id="report-data" type="application/json">')
    assert json.loads(html[start:html.index("</script>", start)])["summary"] == payload["summary"]


def test_model_names_read_plainly():
    assert eval_report.model_name("claude-opus-5-5") == "Opus 5.5"
    assert eval_report.model_name("claude-sonnet-4-5-20250929") == "Sonnet 4.5"
    assert eval_report.whole_percent(0.204) == 20 and eval_report.whole_percent(0.125) == 13
