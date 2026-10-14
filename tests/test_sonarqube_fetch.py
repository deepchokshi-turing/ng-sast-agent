"""fetch.py against a local HTTP stub: token file, auth header, HTTP errors, task states, paging, rule lookups.

Where a real answer exists, the stub replays it: ``replay_routes`` serves the
responses recorded from SonarQube 26.9 in tests/fixtures/sonarqube_26.9-f2_*.json
(background task, issues, hotspots, rules/show, the rules/search cwe facet,
quality profile, server version). Two kinds of answer are written here
instead. The ``api/measures/component`` answer, because the recordings predate
that call (``measures_response``, in the documented shape). And error paths no
recording can show (401, 403, 404, 5xx, a FAILED or CANCELED task, a server
that is not UP, a short page, a deadline), which use minimal JSON and say so in
their docstrings or names.
"""

from __future__ import annotations

import copy
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from sast.sonarqube.normalise import normalise
from tests.conftest import FIXTURES, ROOT

FETCH = ROOT / "sast" / "sonarqube" / "fetch.py"
TOKEN = "squ_fedcba9876543210fedcba9876543210fedcba98"
PROJECT = "sast-0123456789ab"


class Stub:
    """routes: path -> (status, body) or a function(query) -> (status, body)."""

    def __init__(self, routes):
        self.routes = routes
        self.requests: list[dict] = []
        stub = self

        class Handler(BaseHTTPRequestHandler):
            def _answer(self, method):
                parsed = urllib.parse.urlparse(self.path)
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length).decode() if length else ""
                query = dict(urllib.parse.parse_qsl(parsed.query))
                stub.requests.append({"method": method, "path": parsed.path.lstrip("/"), "query": query,
                                      "auth": self.headers.get("Authorization"), "body": body})
                route = stub.routes.get(parsed.path.lstrip("/"), (404, {"errors": [{"msg": "Unknown url"}]}))
                status, payload = route(query) if callable(route) else route
                data = payload.encode() if isinstance(payload, str) else json.dumps(payload).encode()
                self.send_response(status)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                self._answer("GET")

            def do_POST(self):
                self._answer("POST")

            def log_message(self, *args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()

    def calls(self, path, method=None):
        return [r for r in self.requests if r["path"] == path and (method is None or r["method"] == method)]

    def close(self):
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def stub():
    servers = []

    def make(routes):
        server = Stub(routes)
        servers.append(server)
        return server

    yield make
    for server in servers:
        server.close()


def run_fetch(args, host, token=TOKEN, cwd=None, via="env", extra_env=None):
    """fetch.py with the token in a file, named by SONAR_TOKEN_FILE (via="env") or --token-file (via="arg")."""
    env = {k: v for k, v in os.environ.items() if not k.startswith("SONAR_")}
    env.pop("HTTP_PROXY", None), env.pop("http_proxy", None)
    if host is not None:
        env["SONAR_HOST_URL"] = host
    env["NO_PROXY"] = env["no_proxy"] = "127.0.0.1,localhost"
    env.update(extra_env or {})
    with tempfile.TemporaryDirectory() as tmp:
        prefix = []
        if token is not None:
            token_file = os.path.join(tmp, "sonar-token")
            with open(token_file, "w") as f:
                f.write(token + "\n")
            if via == "env":
                env["SONAR_TOKEN_FILE"] = token_file
            else:
                prefix = ["--token-file", token_file]
        command = [sys.executable, str(FETCH), *prefix, *args]
        assert all(TOKEN not in part for part in command)
        if extra_env is None:
            assert all(TOKEN not in value for key, value in env.items() if key.startswith("SONAR_"))
        proc = subprocess.run(command, env=env, capture_output=True, text=True, timeout=60, cwd=cwd)
    assert TOKEN not in proc.stdout and TOKEN not in proc.stderr
    return proc


def result_line(stdout, prefix):
    return json.loads([line for line in stdout.splitlines() if line.startswith(prefix + " ")][-1][len(prefix) + 1:])


UP = (200, {"id": "server-1", "version": "26.9.0.129388", "status": "UP"})
EMPTY_ISSUES = (200, {"issues": [], "paging": {"pageIndex": 1, "pageSize": 500, "total": 0}})
EMPTY_HOTSPOTS = (200, {"hotspots": [], "paging": {"pageIndex": 1, "pageSize": 500, "total": 0}})


def check_routes(**overrides):
    routes = {
        "api/system/status": UP,
        "api/authentication/validate": (200, {"valid": True}),
        "api/server/version": (200, "26.9.0.129388"),
        "api/navigation/global": (200, {"edition": "community"}),
        "api/qualityprofiles/search": (200, {"profiles": [{"name": "Sonar way", "key": "py-1"}]}),
    }
    routes.update(overrides)
    return routes


def measures_response(files=34, ncloc=1500, distribution="py=1500"):
    """api/measures/component in its documented shape. Not recorded: the recordings predate this call."""
    return {"component": {"key": PROJECT, "qualifier": "TRK", "measures": [
        {"metric": "files", "value": str(files)}, {"metric": "ncloc", "value": str(ncloc)},
        {"metric": "ncloc_language_distribution", "value": distribution}]}}


def collect_routes(ce_status="SUCCESS", **overrides):
    """Minimal answers for error-path tests (no findings content)."""
    routes = {
        "api/ce/task": (200, {"task": {"id": "task-1", "status": ce_status, "errorMessage": "analysis crashed"}}),
        "api/server/version": (200, "26.9.0.129388"),
        "api/measures/component": (200, measures_response()),
        "api/issues/search": EMPTY_ISSUES,
        "api/hotspots/search": EMPTY_HOTSPOTS,
        "api/qualityprofiles/search": (200, {"profiles": [{"name": "Sonar way", "key": "py-1", "language": "py",
                                                           "activeRuleCount": 398}]}),
        "api/projects/delete": (204, ""),
    }
    routes.update(overrides)
    return routes


def recorded_f2(task):
    return json.loads((FIXTURES / f"sonarqube_26.9-f2_{task}.json").read_text())


def _paged(pages):
    def answer(query):
        index = int(query.get("p", 1)) - 1
        return (200, pages[index]) if index < len(pages) else (200, {**pages[-1], "issues": [], "hotspots": []})
    return answer


def hotspot_rule_search(total=0, active=0):
    """api/rules/search?types=SECURITY_HOTSPOT in its documented shape (ps=1).
    Stub only: the recordings predate this call. The real values (0 and 0 on
    Community Build 26.9.0.129388) will come from the next recording."""
    def answer(query):
        n = active if query.get("activation") == "true" else total
        return 200, {"total": n, "p": 1, "ps": 1, "paging": {"pageIndex": 1, "pageSize": 1, "total": n},
                     "rules": [{"key": "python:S4507", "type": "SECURITY_HOTSPOT"}] if n else []}
    return answer


def rules_search(facets, hotspots=None):
    """The recorded cwe facet for a rule_key query, else the hotspot rule count stub."""
    hotspots = hotspots or hotspot_rule_search()

    def answer(query):
        if "rule_key" in query:
            return 200, facets[query["rule_key"]]
        return hotspots(query)
    return answer


def replay_routes(document, **overrides):
    """A stub that answers with the responses of one real recorded run
    (the hotspot rule count excepted, see ``hotspot_rule_search``)."""
    rules, facets = document["rules"], document["rule_facets"]
    routes = {
        "api/ce/task": (200, {"task": document["ce_task"]}),
        "api/server/version": (200, document["server"]["version"]),
        "api/measures/component": (200, measures_response()),
        "api/issues/search": _paged(document["issues_pages"]),
        "api/hotspots/search": _paged(document["hotspots_pages"]),
        "api/rules/show": lambda q: (200, rules[q["key"]]) if q["key"] in rules else (404, {"errors": [{"msg": "x"}]}),
        "api/rules/search": rules_search(facets),
        "api/qualityprofiles/search": (200, document["quality_profiles"]),
        "api/projects/delete": (204, ""),
    }
    routes.update(overrides)
    return routes


def report_for(tmp_path, project):
    path = tmp_path / "report-task.txt"
    path.write_text(f"projectKey={project}\nceTaskId=task-1\n")
    return path


@pytest.fixture
def report(tmp_path):
    path = tmp_path / "report-task.txt"
    path.write_text(f"projectKey={PROJECT}\nserverUrl=http://elsewhere:9000\nceTaskId=task-1\n"
                    "ceTaskUrl=http://elsewhere:9000/api/ce/task?id=task-1\n")
    return path


def collect_args(report, tmp_path, *extra, deadline="10"):
    return ["collect", "--report", str(report), "--project", PROJECT, "--out", str(tmp_path / "sonarqube.json"),
            "--deadline", deadline, "--poll-interval", "0.05", *extra]


# ---------------------------------------------------------------- check


def test_check_reports_version_edition_and_profile(stub):
    server = stub(check_routes())
    proc = run_fetch(["check"], server.url)
    assert proc.returncode == 0, proc.stdout
    assert result_line(proc.stdout, "CHECK_RESULT") == {
        "status": "UP", "server_version": "26.9.0.129388", "server_id": "server-1", "edition": "community",
        "default_python_profile": {"name": "Sonar way", "key": "py-1"},
    }
    assert server.requests and all(r["auth"] == f"Bearer {TOKEN}" for r in server.requests)
    assert all(TOKEN not in json.dumps(r["query"]) for r in server.requests)


def test_check_needs_status_up(stub):
    server = stub(check_routes(**{"api/system/status": (200, {"status": "STARTING"})}))
    proc = run_fetch(["check"], server.url)
    assert proc.returncode == 3 and "status is STARTING, not UP" in proc.stdout


def test_check_rejects_an_invalid_token(stub):
    server = stub(check_routes(**{"api/authentication/validate": (200, {"valid": False})}))
    proc = run_fetch(["check"], server.url)
    assert proc.returncode == 3 and "did not accept SONAR_TOKEN" in proc.stdout


@pytest.mark.parametrize("status, message", [
    (401, "did not accept SONAR_TOKEN (wrong, expired or revoked token)"),
    (403, "SONAR_TOKEN lacks a permission"),
    (404, "not found"),
    (500, "HTTP 500"),
    (503, "HTTP 503"),
])
def test_http_errors_have_clear_messages(stub, status, message):
    server = stub(check_routes(**{"api/authentication/validate": (status, {"errors": [{"msg": "nope"}]})}))
    proc = run_fetch(["check"], server.url)
    assert proc.returncode == 3
    assert "ERROR: GET api/authentication/validate failed" in proc.stdout
    assert message in proc.stdout and "(server said: nope)" in proc.stdout
    if status >= 500:  # retried before giving up
        assert len(server.calls("api/authentication/validate")) == 3
    else:
        assert len(server.calls("api/authentication/validate")) == 1


def test_server_error_text_echoing_the_token_is_scrubbed(stub):
    server = stub(check_routes(**{"api/authentication/validate": (401, f"bad token {TOKEN}")}))
    proc = run_fetch(["check"], server.url)  # run_fetch asserts the token is not printed
    assert proc.returncode == 3 and "bad token ***" in proc.stdout


def test_unreachable_server():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    proc = run_fetch(["check"], f"http://127.0.0.1:{port}")
    assert proc.returncode == 3 and f"cannot reach SONAR_HOST_URL http://127.0.0.1:{port}" in proc.stdout


@pytest.mark.parametrize("host, token, message", [
    (None, TOKEN, "SONAR_HOST_URL is not set"),
    ("http://127.0.0.1:9", None, "no token file: pass --token-file or set SONAR_TOKEN_FILE"),
    ("http://127.0.0.1:9", "  ", "is empty"),
    ("127.0.0.1:9000", TOKEN, "must start with http"),
])
def test_missing_configuration(host, token, message):
    proc = run_fetch(["check"], host, token=token)
    assert proc.returncode == 2 and message in proc.stdout


def test_token_in_the_environment_is_not_read():
    """Only a token file is accepted: SONAR_TOKEN on its own is a configuration error."""
    proc = run_fetch(["check"], "http://127.0.0.1:9", token=None, extra_env={"SONAR_TOKEN": TOKEN})
    assert proc.returncode == 2 and "no token file" in proc.stdout


def test_unreadable_token_file(tmp_path):
    proc = run_fetch(["--token-file", str(tmp_path / "missing"), "check"], "http://127.0.0.1:9", token=None)
    assert proc.returncode == 2 and "cannot read the token file" in proc.stdout


def test_token_file_argument(stub):
    server = stub(check_routes())
    proc = run_fetch(["check"], server.url, via="arg")
    assert proc.returncode == 0, proc.stdout
    assert all(r["auth"] == f"Bearer {TOKEN}" for r in server.requests)


# ---------------------------------------------------------------- collect


@pytest.mark.parametrize("task", ["task_4da5ab_negative", "task_4da5ab_positive", "task_dc4b7a_negative",
                                  "task_dc4b7a_positive"])
def test_collect_replays_a_recorded_run(stub, tmp_path, task):
    """fetch.py collect against the real responses of one recorded run gives the same document and findings."""
    recording = recorded_f2(task)
    project = recording["project_key"]
    server = stub(replay_routes(recording))
    out = tmp_path / "sonarqube.json"
    proc = run_fetch(["collect", "--report", str(report_for(tmp_path, project)), "--project", project,
                      "--out", str(out), "--deadline", "30", "--poll-interval", "0.05"], server.url)
    assert proc.returncode == 0, proc.stdout
    document = json.loads(out.read_text())
    for key in ("ce_task", "issues_pages", "hotspots_pages", "rules", "rule_facets", "quality_profiles"):
        assert document[key] == recording[key], key
    assert document["fetch_format"] == 2 and document["rule_errors"] == {} and document["deleted"] is True
    assert document["measures"] == measures_response() and document["default_quality_profiles"] is None
    assert document["server"]["version"] == "26.9.0.129388"
    assert normalise(document) == normalise(recording)

    first = server.calls("api/issues/search")[0]["query"]
    assert first["componentKeys"] == project and first["types"] == "VULNERABILITY" and first["ps"] == "500"
    assert server.calls("api/hotspots/search")[0]["query"]["projectKey"] == project
    assert server.calls("api/measures/component")[0]["query"] == {
        "component": project, "metricKeys": "files,ncloc,ncloc_language_distribution"}
    (search,) = [c for c in server.calls("api/rules/search") if "rule_key" in c["query"]]
    assert search["query"] == {"rule_key": next(iter(recording["rules"])), "facets": "cwe", "ps": "1"}
    assert document["hotspot_rules_total"] == 0 and document["hotspot_rules_active"] == 0
    assert server.calls("api/qualityprofiles/search")[0]["query"] == {"project": project, "language": "py"}
    assert server.calls("api/ce/task")[0]["query"] == {"id": "task-1"}
    (delete,) = server.calls("api/projects/delete", "POST")
    assert urllib.parse.parse_qs(delete["body"]) == {"project": [project]}
    assert all(r["auth"] == f"Bearer {TOKEN}" for r in server.requests)
    assert TOKEN not in out.read_text()


def test_collect_pages_until_the_total_is_read(stub, tmp_path, report):
    """501 results over two pages, made of copies of a recorded issue (no recording has that many)."""
    issue = recorded_f2("task_dc4b7a_negative")["issues_pages"][0]["issues"][0]

    def issues(query):
        page = int(query["p"])
        items = []
        for n in range(500 if page == 1 else 1):
            item = copy.deepcopy(issue)
            item["key"] = f"i{page}-{n}"
            items.append(item)
        return 200, {"issues": items, "paging": {"pageIndex": page, "pageSize": 500, "total": 501}}

    recording = recorded_f2("task_dc4b7a_negative")
    server = stub(replay_routes(recording, **{"api/issues/search": issues}))
    proc = run_fetch(collect_args(report, tmp_path), server.url)
    assert proc.returncode == 0, proc.stdout
    assert result_line(proc.stdout, "COLLECT_RESULT") == {
        "issues": 501, "hotspots": 0, "rules": 1, "deleted": True, "kept": False, "delete_error": None}
    assert [c["query"]["p"] for c in server.calls("api/issues/search")] == ["1", "2"]
    assert len(server.calls("api/rules/show")) == 1  # each rule once


def test_a_short_page_is_an_error(stub, tmp_path, report):
    """Stub only: the server reports 3 results but serves 2 (no recording can show it)."""
    pages = copy.deepcopy(recorded_f2("task_dc4b7a_negative")["issues_pages"])
    pages[0]["paging"]["total"] = 3
    server = stub(replay_routes(recorded_f2("task_dc4b7a_negative"), **{"api/issues/search": _paged(pages)}))
    proc = run_fetch(collect_args(report, tmp_path), server.url)
    assert proc.returncode == 6 and "reported 3 results but 2 were read" in proc.stdout
    assert server.calls("api/projects/delete", "POST")


def test_a_page_without_total_is_an_error(stub, tmp_path, report):
    """Stub only: a search answer with no paging total."""
    server = stub(collect_routes(**{"api/hotspots/search": (200, {"hotspots": []})}))
    proc = run_fetch(collect_args(report, tmp_path), server.url)
    assert proc.returncode == 6 and "no paging total" in proc.stdout


def test_hotspot_rule_counts_are_recorded(stub, tmp_path, report):
    """Server-wide and active-in-the-Python-profile Security Hotspot rule totals.

    Stub only (``hotspot_rule_search``): the recordings predate this call. The
    numbers here are made non-zero on purpose so the two queries cannot be
    confused. On the user's SonarQube Community Build 26.9.0.129388 both are 0
    (checked by hand with api/rules/search), and the real values (0) will come
    from the next recording."""
    server = stub(collect_routes(**{"api/rules/search": hotspot_rule_search(total=7, active=3)}))
    proc = run_fetch(collect_args(report, tmp_path), server.url)
    assert proc.returncode == 0, proc.stdout
    document = json.loads((tmp_path / "sonarqube.json").read_text())
    assert document["hotspot_rules_total"] == 7 and document["hotspot_rules_active"] == 3
    assert document["hotspot_rules_qprofile"] == "py-1" and document["hotspot_rules_error"] is None
    server_wide, active = [c["query"] for c in server.calls("api/rules/search")]
    assert server_wide == {"types": "SECURITY_HOTSPOT", "ps": "1"}
    assert active == {"types": "SECURITY_HOTSPOT", "languages": "py", "activation": "true", "qprofile": "py-1",
                      "ps": "1"}
    # The hotspot paging still runs: older servers have hotspot rules.
    assert server.calls("api/hotspots/search")


def test_a_failed_hotspot_rule_count_does_not_stop_the_collection(stub, tmp_path, report):
    """Stub only: the count is informational, so an error is recorded and the run goes on."""
    server = stub(collect_routes(**{"api/rules/search": (403, {"errors": [{"msg": "Insufficient privileges"}]})}))
    proc = run_fetch(collect_args(report, tmp_path), server.url)
    assert proc.returncode == 0, proc.stdout
    document = json.loads((tmp_path / "sonarqube.json").read_text())
    assert document["hotspot_rules_total"] is None and document["hotspot_rules_active"] is None
    assert "api/rules/search" in document["hotspot_rules_error"] and document["deleted"] is True


def test_default_profile_when_the_project_has_none(stub, tmp_path, report):
    """Stub only: the project search returns no profile, so the default Python profile is read."""
    def profiles(query):
        if query.get("project"):
            return 200, {"profiles": []}
        return 200, {"profiles": [{"name": "Sonar way", "key": "py-1", "language": "py", "activeRuleCount": 398}]}

    server = stub(collect_routes(**{"api/qualityprofiles/search": profiles}))
    proc = run_fetch(collect_args(report, tmp_path), server.url)
    assert proc.returncode == 0, proc.stdout
    document = json.loads((tmp_path / "sonarqube.json").read_text())
    assert document["default_quality_profiles"]["profiles"][0]["activeRuleCount"] == 398
    assert server.calls("api/qualityprofiles/search")[1]["query"] == {"language": "py", "defaults": "true"}


def test_the_deadline_covers_the_whole_collection(stub, tmp_path, report):
    """Stub only: the task succeeds at once, then a hanging search runs past the deadline. The delete still runs."""
    import time

    def slow(query):
        time.sleep(1.5)
        return EMPTY_ISSUES

    server = stub(collect_routes(**{"api/issues/search": slow}))
    started = time.monotonic()
    proc = run_fetch(collect_args(report, tmp_path, deadline="0.5"), server.url)
    assert proc.returncode == 5 and "deadline passed" in proc.stdout
    assert time.monotonic() - started < 10
    assert server.calls("api/projects/delete", "POST")
    assert json.loads((tmp_path / "sonarqube.json").read_text())["deleted"] is True


def test_keep_leaves_the_project(stub, tmp_path, report):
    server = stub(collect_routes())
    proc = run_fetch(collect_args(report, tmp_path, "--keep"), server.url)
    assert proc.returncode == 0
    assert not server.calls("api/projects/delete")
    document = json.loads((tmp_path / "sonarqube.json").read_text())
    assert document["deleted"] is False and document["kept"] is True


def test_a_failed_delete_does_not_fail_the_run(stub, tmp_path, report):
    server = stub(collect_routes(**{"api/projects/delete": (403, {"errors": [{"msg": "Insufficient privileges"}]})}))
    proc = run_fetch(collect_args(report, tmp_path), server.url)
    assert proc.returncode == 0
    outcome = result_line(proc.stdout, "COLLECT_RESULT")
    assert outcome["deleted"] is False and "Insufficient privileges" in outcome["delete_error"]
    assert f"project {PROJECT} was left on the server" in proc.stdout


@pytest.mark.parametrize("status", ["FAILED", "CANCELED"])
def test_background_task_failed_or_canceled(stub, tmp_path, report, status):
    server = stub(collect_routes(ce_status=status))
    proc = run_fetch(collect_args(report, tmp_path), server.url)
    assert proc.returncode == 4
    assert f"the background task task-1 ended {status}: analysis crashed" in proc.stdout
    assert not server.calls("api/issues/search")
    assert server.calls("api/projects/delete", "POST")  # cleaned up anyway
    document = json.loads((tmp_path / "sonarqube.json").read_text())
    assert document["ce_task"]["status"] == status and document["deleted"] is True
    assert "analysis crashed" in document["error"]


def test_background_task_past_the_deadline(stub, tmp_path, report):
    server = stub(collect_routes(ce_status="IN_PROGRESS"))
    proc = run_fetch(collect_args(report, tmp_path, deadline="0.3"), server.url)
    assert proc.returncode == 5 and "still IN_PROGRESS when the deadline passed" in proc.stdout
    assert len(server.calls("api/ce/task")) >= 2
    assert server.calls("api/projects/delete", "POST")


def test_http_error_while_collecting_still_cleans_up(stub, tmp_path, report):
    server = stub(collect_routes(**{"api/hotspots/search": (403, {"errors": [{"msg": "Insufficient privileges"}]})}))
    proc = run_fetch(collect_args(report, tmp_path), server.url)
    assert proc.returncode == 3
    assert "GET api/hotspots/search failed: SONAR_TOKEN lacks a permission" in proc.stdout
    assert server.calls("api/projects/delete", "POST")
    assert json.loads((tmp_path / "sonarqube.json").read_text())["error"].startswith("GET api/hotspots/search")


def test_more_results_than_can_be_paged_is_an_error(stub, tmp_path, report):
    server = stub(collect_routes(**{"api/issues/search": (200, {"issues": [{"rule": "python:S1"}],
                                                                "paging": {"pageIndex": 1, "total": 10001}})}))
    proc = run_fetch(collect_args(report, tmp_path), server.url)
    assert proc.returncode == 6 and "would be incomplete" in proc.stdout


def test_report_for_another_project_is_refused(stub, tmp_path):
    report = tmp_path / "report-task.txt"
    report.write_text("projectKey=sast-other\nceTaskId=task-1\n")
    server = stub(collect_routes())
    proc = run_fetch(collect_args(report, tmp_path), server.url)
    assert proc.returncode == 2 and "is for project 'sast-other'" in proc.stdout
    assert not server.calls("api/ce/task")


def test_missing_report_file(stub, tmp_path):
    server = stub(collect_routes())
    proc = run_fetch(collect_args(tmp_path / "nope.txt", tmp_path), server.url)
    assert proc.returncode == 2 and "cannot read sonar-scanner's report file" in proc.stdout


def test_delete_subcommand(stub):
    server = stub(collect_routes())
    proc = run_fetch(["delete", "--project", PROJECT], server.url)
    assert proc.returncode == 0
    assert result_line(proc.stdout, "DELETE_RESULT") == {"project_key": PROJECT, "deleted": True, "error": None}


def one_issue_routes(**overrides):
    """The recorded dc4b7a positive run, with its rule lookups overridden for an error path."""
    return replay_routes(recorded_f2("task_dc4b7a_positive"), **overrides)


S5332 = "python:S5332"


@pytest.mark.parametrize("routes, message", [
    ({"api/rules/show": (404, {"errors": [{"msg": "Rule not found"}]})}, "GET api/rules/show failed: not found"),
    ({"api/rules/search": (404, {"errors": [{"msg": "Rule not found"}]})}, "GET api/rules/search failed: not found"),
    ({"api/rules/search": (200, {"total": 0, "paging": {"total": 0}, "rules": [], "facets": []})},
     "did not return exactly that rule"),
    ({"api/rules/search": (200, {"paging": {"total": 1}, "rules": [{"key": "python:S9999"}], "facets": []})},
     "did not return exactly that rule"),
    ({"api/rules/search": (200, {"paging": {"total": 2}, "rules": [{"key": S5332}, {"key": "python:S1"}],
                                 "facets": []})},
     "did not return exactly that rule"),
    ({"api/rules/search": (403, {"errors": [{"msg": "Insufficient privileges"}]})}, "GET api/rules/search failed"),
])
def test_every_rule_lookup_error_is_fatal(stub, tmp_path, routes, message):
    """Stub only: no recording has a failed rule lookup. A rule without its CWEs must not drop results silently."""
    project = recorded_f2("task_dc4b7a_positive")["project_key"]
    server = stub(one_issue_routes(**routes))
    out = tmp_path / "sonarqube.json"
    proc = run_fetch(["collect", "--report", str(report_for(tmp_path, project)), "--project", project,
                      "--out", str(out), "--deadline", "10", "--poll-interval", "0.05"], server.url)
    assert proc.returncode in (3, 6) and message in proc.stdout, proc.stdout
    document = json.loads(out.read_text())
    assert document["error"] and document["deleted"] is True
    assert server.calls("api/projects/delete", "POST")


def test_host_url_with_user_info_is_refused():
    proc = run_fetch(["check"], "http://admin:hunter2@127.0.0.1:9")
    assert proc.returncode == 2 and "must not contain a user name or password" in proc.stdout
    assert "hunter2" not in proc.stdout
