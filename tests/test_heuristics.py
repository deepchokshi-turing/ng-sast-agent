from sast import heuristics


def test_control_status_is_none():
    assert heuristics.CONTROL_STATUS == "none"


def test_recommendations_are_deterministic_and_ordered():
    a = heuristics.recommendations("LLM02.SID.HIGH", ["CWE-532", "CWE-862"])
    b = heuristics.recommendations("LLM02.SID.HIGH", ["CWE-862", "CWE-532"])
    assert a == b == ["REC-AUTHZ-BEFORE-RETRIEVAL", "REC-SENSITIVE-DATA-FILTER", "REC-SINK-SIDE-IFC"]
    assert heuristics.recommendations("LLM03.EA.PERMISSIONS", ["CWE-250"]) == [
        "REC-LEAST-PRIVILEGE", "REC-USER-SECURITY-CONTEXT"]
    assert heuristics.recommendations("UNKNOWN", ["CWE-1"]) == []
