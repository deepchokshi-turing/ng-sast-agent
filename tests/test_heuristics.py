import pytest

from sast import heuristics


@pytest.mark.parametrize("code, kind", [
    ("requests.post(url, json=body)", "network"),
    ("await fetch(hookUrl, {method: 'POST'})", "network"),
    ("httpx.AsyncClient().send(req)", "network"),
    ("smtp.send_message(msg)", "email"),
    ("send_email(to, body)", "email"),
    ("transporter.sendMail(opts)", "email"),
    ("fh.write(record)", "file_write"),
    ("Path(out).write_text(text)", "file_write"),
    ("fs.writeFileSync(p, data)", "file_write"),
    ("logger.info('prompt %s', prompt)", "logging"),
    ("logging.debug(completion)", "logging"),
    ("console.log(user)", "logging"),
    ("system = f'...{profile}'", None),
    ("client.chat.completions.create(messages=m)", None),
    ("fetch_rows(q)", None),
    ("", None),
])
def test_boundary_sink_kind(code, kind):
    assert heuristics.boundary_sink_kind(code) == kind


def test_control_status_is_none():
    assert heuristics.CONTROL_STATUS == "none"


def test_recommendations_are_deterministic_and_ordered():
    a = heuristics.recommendations("LLM02.SID.HIGH", ["CWE-532", "CWE-862"])
    b = heuristics.recommendations("LLM02.SID.HIGH", ["CWE-862", "CWE-532"])
    assert a == b == ["REC-AUTHZ-BEFORE-RETRIEVAL", "REC-SENSITIVE-DATA-FILTER", "REC-SINK-SIDE-IFC"]
    assert heuristics.recommendations("LLM03.EA.PERMISSIONS", ["CWE-250"]) == [
        "REC-LEAST-PRIVILEGE", "REC-USER-SECURITY-CONTEXT"]
    assert heuristics.recommendations("UNKNOWN", ["CWE-1"]) == []
