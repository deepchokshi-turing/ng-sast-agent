"""The "Measurements at a glance" charts: five standalone SVG files next to eval_report.md, linked from
its summary with a caption each, drawn from the same summary block as the HTML. Their values are the
summary's, a missing measurement is written in its row instead of drawn as a bar, the files are valid
XML, use no scanner-testing terms and are the same bytes for the same input."""

from __future__ import annotations

import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import eval_report  # noqa: E402
from tests.test_report_summary import BANNED, build, summary_part  # noqa: E402

NS = {"s": "http://www.w3.org/2000/svg"}
FILES = ["m1-issues-found", "m1-fixed-flagged", "m2-path", "m3-protections", "m4-fixes"]
NAMES = ["Semgrep", "CodeQL", "SonarQube", "Claude (Opus 5.5, stock)"]


def charts(payload) -> dict:
    return {c["id"]: c for c in payload["summary"]["charts"]}


def rows_of(svg: ET.Element) -> dict:
    """Per drawn row: its tooltip title -> the row group."""
    return {g.find("s:title", NS).text: g for g in svg.iter(f"{{{NS['s']}}}g")}


def visible_text(svg: ET.Element) -> list[str]:
    return [t for el in svg.iter() if el.tag != f"{{{NS['s']}}}style" for t in [el.text, el.tail] if t and t.strip()]


def test_svgs_are_written_and_linked_from_the_markdown_summary(tmp_path, monkeypatch, capsys):
    md, payload, _ = build(tmp_path, monkeypatch, capsys)
    out = tmp_path / "o"
    summary = summary_part(md)
    lines = summary.splitlines()
    order = [lines.index(h) for h in ("## Results by risk type", "## Measurements at a glance", "## What this means")]
    assert order == sorted(order)
    section = summary.split("## Measurements at a glance\n")[1].split("\n## ")[0]
    assert [c["id"] for c in payload["summary"]["charts"]] == FILES
    for c in payload["summary"]["charts"]:
        assert c["file"] == f"charts/{c['id']}.svg"
        assert (out / c["file"]).is_file()
        # A relative image link, then its one-line caption.
        assert f"![{c['title']}]({c['file']})\n\n{c['caption']}\n" in section
        assert "\n" not in c["caption"]
    assert payload["summary"]["charts_intro"] in section


def test_svgs_are_valid_xml_with_a_title_description_and_dark_mode(tmp_path, monkeypatch, capsys):
    build(tmp_path, monkeypatch, capsys)
    for name in FILES:
        text = (tmp_path / "o" / "charts" / f"{name}.svg").read_text(encoding="utf-8")
        svg = ET.fromstring(text)
        assert svg.tag == f"{{{NS['s']}}}svg" and svg.get("role") == "img"
        assert svg.find("s:title", NS).text and svg.find("s:desc", NS).text
        style = svg.find("s:style", NS).text
        assert "@media (prefers-color-scheme: dark)" in style
        # Self-contained: no external references, no scripts.
        assert "href" not in text and "<script" not in text and "\r" not in text


def test_svgs_are_deterministic(tmp_path, monkeypatch, capsys):
    _, payload, _ = build(tmp_path / "a", monkeypatch, capsys)
    build(tmp_path / "b", monkeypatch, capsys)
    for name in FILES:
        a = (tmp_path / "a" / "o" / "charts" / f"{name}.svg").read_bytes()
        assert a == (tmp_path / "b" / "o" / "charts" / f"{name}.svg").read_bytes(), name
        assert a == eval_report.chart_svg(charts(payload)[name]).encode("utf-8")


def test_chart_values_match_the_summary_tables(tmp_path, monkeypatch, capsys):
    _, payload, _ = build(tmp_path, monkeypatch, capsys)
    s = payload["summary"]
    glance = {r[0]: r[1:] for r in s["at_a_glance"]["rows"]}
    risk = {r[0]: r[1:] for r in s["by_risk"]["rows"]}
    c = charts(payload)
    disclosure, agency = c["m1-issues-found"]["facets"]
    assert [disclosure["title"], agency["title"]] == ["Data disclosure", "Excessive agency"]
    assert [r["tool"] for r in disclosure["rows"]] == NAMES
    # "x of y (n%)": the table's "x of y" with its whole percent.
    assert [r["text"] for r in disclosure["rows"]] == ["0 of 1 (0%)", "0 of 1 (0%)", "1 of 1 (100%)", "1 of 1 (100%)"]
    assert [r["text"].split(" (")[0] for r in disclosure["rows"]] == risk["Data disclosure issues found"]
    assert [r["text"].split(" (")[0] for r in agency["rows"]] == risk["Excessive agency issues found"]
    flagged = c["m1-fixed-flagged"]["facets"][0]["rows"]
    assert [r["text"].split(" (")[0] for r in flagged] == glance["Fixed apps wrongly flagged"]
    assert [r["value"] for r in flagged] == [0, 0, 0, 1]
    for name, label in [("m2-path", "Described how the issue is reached"), ("m3-protections", "Judged existing protections"),
                        ("m4-fixes", "Suggested fixes")]:
        assert [r["text"] for r in c[name]["facets"][0]["rows"]] == glance[label], name
    assert c["m2-path"]["facets"][0]["rows"][2]["value"] == 0.25
    assert c["m4-fixes"]["facets"][0]["rows"][2]["value"] == 0.5
    # The SVG says the same: every row's tooltip and the description carry the text.
    for name in FILES:
        svg = ET.parse(tmp_path / "o" / "charts" / f"{name}.svg").getroot()
        desc = svg.find("s:desc", NS).text
        titles = rows_of(svg)
        for facet in c[name]["facets"]:
            for r in facet["rows"]:
                assert f"{r['tool']}: {r['text']}" in titles
                assert f"{r['tool']}: {r['text']}." in desc


def test_missing_measurements_are_written_not_drawn_as_zero(tmp_path, monkeypatch, capsys):
    _, payload, _ = build(tmp_path, monkeypatch, capsys)
    nothing, absent = eval_report.NOTHING_TO_JUDGE, eval_report.NOT_PROVIDED
    path = rows_of(ET.parse(tmp_path / "o" / "charts" / "m2-path.svg").getroot())
    bars = lambda g: g.findall("s:path", NS) + g.findall("s:rect", NS)  # noqa: E731
    for title in (f"Semgrep: {nothing}", f"CodeQL: {nothing}", f"Claude (Opus 5.5, stock): {absent}"):
        g = path[title]
        assert bars(g) == [], title
        state = [t for t in g.findall("s:text", NS) if "state" in t.get("class")]
        assert [t.text for t in state] == [title.split(": ")[1]]
    scored = path["SonarQube: 25%"]
    assert len(scored.findall("s:path", NS)) == 1 and not [t for t in scored.findall("s:text", NS)
                                                           if "state" in t.get("class")]
    # A real zero is drawn: a 2px stub on the baseline with its value, not a state text.
    zero = rows_of(ET.parse(tmp_path / "o" / "charts" / "m1-issues-found.svg").getroot())["Semgrep: 0 of 1 (0%)"]
    assert [r.get("width") for r in zero.findall("s:rect", NS)] == ["2"]


def test_unknown_totals_and_empty_denominators_are_text():
    t = {"key": "x", "name": "Tool"}
    assert eval_report.count_row(t, 2, None, "none") == {
        "key": "x", "tool": "Tool", "state": "not_known", "value": None, "text": "2 found, total not known"}
    assert eval_report.count_row(t, 0, 0, "no fixed apps tested")["text"] == "no fixed apps tested"
    assert eval_report.count_row(t, 4, 9, "")["text"] == "4 of 9 (44%)"
    chart = {"id": "c", "group": "Measurement 1: risk detection", "title": "T", "caption": "C.", "file": "charts/c.svg",
             "facets": [{"title": None, "rows": [eval_report.count_row(t, 2, None, ""),
                                                 eval_report.count_row({"key": "y", "name": "Other tool with a much "
                                                                        "longer name than fits"}, 4, 9, "")]}]}
    svg = ET.fromstring(eval_report.chart_svg(chart))
    rows = rows_of(svg)
    assert not rows["Tool: 2 found, total not known"].findall("s:path", NS)
    long_row = rows["Other tool with a much longer name than fits: 4 of 9 (44%)"]
    assert len(long_row.findall("s:path", NS)) == 1
    assert len(long_row.find("s:text", NS).findall("s:tspan", NS)) == 2  # a long name wraps, it is not cut


def test_chart_text_uses_no_jargon(tmp_path, monkeypatch, capsys):
    md, payload, html = build(tmp_path, monkeypatch, capsys)
    section = summary_part(md).split("## Measurements at a glance\n")[1].split("\n## ")[0]
    texts = [section]
    for name in FILES:
        texts += visible_text(ET.parse(tmp_path / "o" / "charts" / f"{name}.svg").getroot())
    for text in texts:
        for word in BANNED:
            assert not re.search(rf"\b{re.escape(word)}\b", text, re.I), (word, text)
        assert "—" not in text and ";" not in text, text
    # The HTML draws the same specs from the payload in its summary.
    assert "renderMeasureCharts" in html and '"measures"' in html
