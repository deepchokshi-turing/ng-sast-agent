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
    GT_NEG, GT_POS, add, job_dir, make_tasks, neg_rewards, pos_rewards, result, run, standard_pair, write)

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
    assert re.fullmatch(r"\d{1,2} [A-Z][a-z]+ \d{4}\. All 2 apps \(1 app family\) in the set were run: 1 "
                        r"vulnerable, 1 fixed copy, with 2 known issues in the vulnerable apps\.", lines[2]), lines[2]
    order = [lines.index(h) for h in ("## Read this first", "## What was tested", "## Results at a glance",
                                      "## Results by risk type",
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
    nothing, absent, free = eval_report.NOTHING_TO_JUDGE, eval_report.NOT_PROVIDED, eval_report.FREE_TEXT
    # semgrep and codeql matched nothing, sonarqube matched with a path and recommendations, Claude matched
    # with none of the three fields. A stock Claude review writes its exploit scenario and recommendation
    # as free text, so those two read "free text", and protections (which it never gives) "not provided".
    assert glance["Described how the issue is reached"] == [nothing, nothing, "25%", free]
    assert glance["Judged existing protections"] == [nothing, nothing, absent, absent]
    assert glance["Suggested fixes"] == [nothing, nothing, "50%", free]
    assert f"| Suggested fixes | {nothing} | {nothing} | 50% | {free} |" in md


def test_what_this_means_sentences_and_caveats(tmp_path, monkeypatch, capsys):
    md, payload, _ = build(tmp_path, monkeypatch, capsys)
    tools = {t["name"]: t for t in payload["summary"]["tools"]}
    assert tools["Semgrep"]["tested"] == "Semgrep: a pattern-matching code scanner."
    assert tools["CodeQL"]["tested"] == "CodeQL: a code-analysis scanner from GitHub."
    assert "Opus 5.5 model" in tools["Claude (Opus 5.5, stock)"]["tested"]
    assert tools["Claude (Opus 5.5, stock)"]["tested"].endswith(eval_report.STOCK_HOW)
    assert "as shipped" not in tools["Claude (Opus 5.5, stock)"]["tested"]
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
    assert ("It wrote how each issue is reached and its suggested fixes as free text, which our checker cannot "
            "score. It did not describe protections in a form that can be scored.") in claude
    assert "category names are not in our fixed list. 4 findings were dropped here." in claude  # 2 per run
    assert "without the extra AI check that normally removes false alarms" in claude
    assert "pointed at" not in claude  # its unmatched result is nowhere near the other known issue
    terms = [g["term"] for g in payload["summary"]["glossary"]]
    assert 5 <= len(terms) <= 10 and {"Known issue", "False alarm", "Fixed app", "Data disclosure",
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


def test_read_this_first_lists_the_caveats_that_apply(tmp_path, monkeypatch, capsys):
    md, payload, html = build(tmp_path, monkeypatch, capsys)
    first = payload["summary"]["read_first"]
    assert first[0] == ("Each tool ran once per app, so differences of one or two issues between tools are not "
                        "meaningful.")
    assert ("Claude (Opus 5.5, stock) was run on a subscription token, so the reviewer's second AI check that "
            "removes false alarms was off") in first[1]
    # No scoped run here, so no scoped caveat.
    assert not any("scoped" in r for r in first)
    # The known issues are one high-severity disclosure and one permission issue.
    assert first[2] == ("Data disclosure issues of medium severity and excessive-agency extra-feature and approval "
                        "issues are not in this set, so no tool is tested on them. Data disclosure issues of high "
                        "severity and excessive-agency permission issues have only one example each, so one hit or "
                        "miss swings the result.")
    # semgrep and sonarqube wrote one result each, codeql none.
    assert first[3] == ("Semgrep, CodeQL and SonarQube reported almost nothing (Semgrep wrote 1 result, CodeQL wrote "
                        "no results and SonarQube wrote 1 result across all apps), so their few false alarms say "
                        "little about them.")
    lines = md.splitlines()
    start = lines.index("## Read this first")
    assert lines[start - 2] == payload["summary"]["intro"]
    assert lines[start + 2:start + 2 + len(first)] == [f"- {r}" for r in first]
    assert '"Read this first"' in html


def test_scoped_mode_partial_coverage_free_text_and_wrong_risk_type(tmp_path, monkeypatch, capsys):
    """A task set larger than the run, a scoped Claude review with its false-alarm check on that pointed
    at the excessive-agency issue under the disclosure risk type, and a scanner whose matched result
    carries an exploit scenario only as free text."""
    tasks = make_tasks(tmp_path, {"task_fam1_positive": GT_POS, "task_fam1_negative": GT_NEG,
                                  "task_fam2_positive": GT_POS, "task_fam2_negative": GT_NEG})
    write(tasks / "VARIANTS.json", {
        "task_fam1_positive": {"family": "fam1", "role": "positive"},
        "task_fam1_negative": {"family": "fam1", "role": "negative"},
        "task_fam2_positive": {"family": "fam2", "role": "positive"},
        "task_fam2_negative": {"family": "fam2", "role": "negative"}})
    meta = {"tool": "claude-code-security-review", "model": "claude-opus-5-5", "mode": "scoped", "auth": "api_key",
            "claude_review": {"mode": "scoped", "auth": "api_key", "filter_mode": "claude",
                              "model": "claude-opus-5-5"}}
    scoped = job_dir(tmp_path, "scoped")
    add(scoped, "task_fam1_positive", "claude-code-security-review", pos_rewards(hit=True, tp=1, fp=1),
        {"per_finding": [{"finding": "F1", "matched": True, "result_index": 0, "ruleId": "LLM02.SID.HIGH",
                          "cwe_ok": True, "scores": {}}, {"finding": "F2", "matched": False}],
         "unmatched_results": [{"index": 1, "ruleId": "LLM02.SID.HIGH", "location": ["src/tool.py", 7, 7]}],
         "trap_hits": [], "some_new_field": {"x": 1}},
        [result("LLM02.SID.HIGH", "src/app.py", 10), result("LLM02.SID.HIGH", "src/tool.py", 7)],
        {**meta, "results_emitted": 2})
    add(scoped, "task_fam1_negative", "claude-code-security-review", neg_rewards(), {"negative": True}, [],
        {**meta, "results_emitted": 0})
    prose = job_dir(tmp_path, "prose")
    told = {**result("LLM02.SID.HIGH", "src/app.py", 10),
            "properties": {"toolProperties": {"exploitScenario": "An attacker asks the agent to read the log."}}}
    add(prose, "task_fam1_positive", "prose", pos_rewards(hit=True),
        {"per_finding": [{"finding": "F1", "matched": True, "result_index": 0, "ruleId": "LLM02.SID.HIGH",
                          "cwe_ok": True, "scores": {}}], "unmatched_results": [], "trap_hits": []},
        [told, result("LLM03.EA.PERMISSIONS", "src/other.py", 90), result("LLM03.EA.PERMISSIONS", "src/x.py", 1)],
        {"results_emitted": 3})
    add(prose, "task_fam1_negative", "prose", neg_rewards(), {"negative": True}, [], {"results_emitted": 0})
    md, payload, _ = run(monkeypatch, capsys, scoped.parent, prose.parent, "--tasks", tasks, "--out", tmp_path / "o")
    s = payload["summary"]
    assert ". 2 of 4 apps (1 of 2 app families) were run: 1 vulnerable, 1 fixed copy" in s["intro"]
    assert s["coverage"] == {"apps_run": 2, "families_run": 1, "apps_total": 4, "families_total": 2}
    tools = {t["name"]: t for t in s["tools"]}
    claude = tools["Claude (Opus 5.5, scoped)"]
    assert claude["tested"].endswith(eval_report.SCOPED_HOW)
    assert "told the answer format our checker scores" in claude["tested"]
    assert "not like-for-like" in claude["tested"]
    meaning = " ".join(claude["meaning"])
    assert "It pointed at 1 more known issue but under the wrong risk type, so it was not counted." in meaning
    assert "subscription token" not in meaning and not any("subscription" in r for r in s["read_first"])
    assert any(r.startswith("In scoped mode the AI reviewer was told the answer format our checker scores")
               for r in s["read_first"])
    gloss = {g["term"]: g["text"] for g in s["glossary"]}
    assert "as shipped" not in gloss["Stock and scoped mode"]
    assert "answer format our checker scores" in gloss["Stock and scoped mode"]
    # The scanner's exploit scenario is prose, so path tracing reads free text. It gave no fix at all.
    prose_tool = tools["prose"]
    assert prose_tool["path"]["text"] == eval_report.FREE_TEXT
    assert prose_tool["recommendations"]["text"] == eval_report.NOT_PROVIDED
    assert ("It wrote how each issue is reached as free text, which our checker cannot score."
            in " ".join(prose_tool["meaning"]))
    assert "pointed at" not in " ".join(prose_tool["meaning"])  # its excessive-agency results are far away
    assert "Free text, not scorable" in gloss
    for text in [summary_part(md)] + texts(s):
        for word in BANNED:
            assert not re.search(rf"\b{re.escape(word)}\b", text, re.I), (word, text)


def test_coverage_line_reads_the_whole_set():
    data = {"positives": 5, "negatives": 5, "families": 5}
    assert eval_report.coverage_line(data, {"tasks": 30, "families": 15}) == (
        "10 of 30 apps (5 of 15 app families) were run")
    assert eval_report.coverage_line(data, {"tasks": 10, "families": 5}) == (
        "All 10 apps (5 app families) in the set were run")
    assert eval_report.coverage_line(data, {"tasks": 30, "families": None}) == "10 of 30 apps were run"
    assert eval_report.coverage_line(data, None) == "10 apps (5 app families) were run"


def test_measurement_captions_say_how_the_average_is_taken(tmp_path, monkeypatch, capsys):
    _, payload, _ = build(tmp_path, monkeypatch, capsys)
    for c in payload["summary"]["charts"][2:]:
        assert c["caption"].endswith("averaged over the vulnerable apps. An app's score counts each of its known "
                                     "issues, and a missed issue counts as zero. Longer bars are better.")
