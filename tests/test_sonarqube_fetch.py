"""fetch.py against a local HTTP stub: token file, auth header, HTTP errors, task states, paging, rule lookups.

The stub answers with status codes and minimal JSON shapes (no findings
content), so it tests how fetch.py talks to a server, not what a real
SonarQube reports. Real output is in test_sonarqube_normalise.py.
"""

from __future__ import annotations

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

from tests.conftest import ROOT

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


UP = (200, {"id": "server-1", "version": "26.9.test", "status": "UP"})
EMPTY_ISSUES = (200, {"issues": [], "paging": {"pageIndex": 1, "pageSize": 500, "total": 0}})
EMPTY_HOTSPOTS = (200, {"hotspots": [], "paging": {"pageIndex": 1, "pageSize": 500, "total": 0}})


def check_routes(**overrides):
    routes = {
        "api/system/status": UP,
        "api/authentication/validate": (200, {"valid": True}),
        "api/server/version": (200, "26.9.test"),
        "api/navigation/global": (200, {"edition": "community"}),
        "api/qualityprofiles/search": (200, {"profiles": [{"name": "Sonar way", "key": "py-1"}]}),
    }
    routes.update(overrides)
    return routes


def collect_routes(ce_status="SUCCESS", **overrides):
    routes = {
        "api/ce/task": (200, {"task": {"id": "task-1", "status": ce_status, "errorMessage": "analysis crashed"}}),
        "api/server/version": (200, "26.9.test"),
        "api/issues/search": EMPTY_ISSUES,
        "api/hotspots/search": EMPTY_HOTSPOTS,
        "api/qualityprofiles/search": (200, {"profiles": [{"name": "Sonar way", "key": "py-1", "language": "py"}]}),
        "api/projects/delete": (204, ""),
    }
    routes.update(overrides)
    return routes


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
        "status": "UP", "server_version": "26.9.test", "server_id": "server-1", "edition": "community",
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


def test_collect_pages_reads_each_rule_once_and_deletes(stub, tmp_path, report):
    def issues(query):
        page = int(query["p"])
        items = [{"key": f"i{page}-{n}", "rule": f"python:S{n % 2}"} for n in range(500 if page == 1 else 1)]
        return 200, {"issues": items, "paging": {"pageIndex": page, "pageSize": 500, "total": 501}}

    routes = collect_routes(**{
        "api/issues/search": issues,
        "api/hotspots/search": (200, {"hotspots": [{"key": "h1", "ruleKey": "python:S5"}],
                                      "paging": {"pageIndex": 1, "pageSize": 500, "total": 1}}),
        "api/rules/show": lambda q: (200, {"rule": {"key": q["key"]}}),
        "api/rules/search": lambda q: (200, {"total": 1, "rules": [{"key": q["rule_key"]}], "facets": [
            {"property": "cwe", "values": [{"val": "200", "count": 1}]}]}),
    })
    server = stub(routes)
    proc = run_fetch(collect_args(report, tmp_path), server.url)
    assert proc.returncode == 0, proc.stdout
    assert result_line(proc.stdout, "COLLECT_RESULT") == {
        "issues": 501, "hotspots": 1, "rules": 3, "rule_errors": 0, "deleted": True, "kept": False,
        "delete_error": None}

    assert [c["query"]["p"] for c in server.calls("api/issues/search")] == ["1", "2"]
    first = server.calls("api/issues/search")[0]["query"]
    assert first["componentKeys"] == PROJECT and first["types"] == "VULNERABILITY" and first["ps"] == "500"
    assert server.calls("api/hotspots/search")[0]["query"]["projectKey"] == PROJECT
    assert sorted(c["query"]["key"] for c in server.calls("api/rules/show")) == ["python:S0", "python:S1",
                                                                                  "python:S5"]
    searches = server.calls("api/rules/search")
    assert sorted(c["query"]["rule_key"] for c in searches) == ["python:S0", "python:S1", "python:S5"]
    assert all(c["query"]["facets"] == "cwe" and c["query"]["ps"] == "1" for c in searches)
    assert server.calls("api/qualityprofiles/search")[0]["query"] == {"project": PROJECT, "language": "py"}
    # The task is polled at SONAR_HOST_URL, never at the serverUrl in the report file.
    assert server.calls("api/ce/task")[0]["query"] == {"id": "task-1"}
    (delete,) = server.calls("api/projects/delete", "POST")
    assert urllib.parse.parse_qs(delete["body"]) == {"project": [PROJECT]}

    document = json.loads((tmp_path / "sonarqube.json").read_text())
    assert document["deleted"] is True and document["error"] is None and document["project_key"] == PROJECT
    assert len(document["issues_pages"]) == 2 and set(document["rules"]) == {"python:S0", "python:S1", "python:S5"}
    assert document["fetch_format"] == 2 and document["rule_errors"] == {}
    assert set(document["rule_facets"]) == {"python:S0", "python:S1", "python:S5"}
    assert document["server"] == {"host_url": server.url, "version": "26.9.test"}
    assert TOKEN not in (tmp_path / "sonarqube.json").read_text()


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
    issues = (200, {"issues": [{"key": "i1", "rule": "python:S9", "type": "VULNERABILITY"}],
                    "paging": {"pageIndex": 1, "pageSize": 500, "total": 1}})
    return collect_routes(**{"api/issues/search": issues, **overrides})


@pytest.mark.parametrize("routes, recorded_error", [
    ({"api/rules/show": (404, {"errors": [{"msg": "Rule not found"}]}),
      "api/rules/search": (404, {"errors": [{"msg": "Rule not found"}]})}, "not found"),
    ({"api/rules/show": (200, {"rule": {"key": "python:S9"}}),
      "api/rules/search": (200, {"total": 0, "rules": [], "facets": [{"property": "cwe", "values": []}]})},
     "found no rule python:S9"),
])
def test_a_rule_without_cwe_does_not_fail_collect(stub, tmp_path, report, routes, recorded_error):
    server = stub(one_issue_routes(**routes))
    proc = run_fetch(collect_args(report, tmp_path), server.url)
    assert proc.returncode == 0, proc.stdout
    assert result_line(proc.stdout, "COLLECT_RESULT")["rule_errors"] == 1
    document = json.loads((tmp_path / "sonarqube.json").read_text())
    assert recorded_error in document["rule_errors"]["python:S9"]
    assert document["deleted"] is True and document["error"] is None


def test_other_rule_lookup_errors_still_fail(stub, tmp_path, report):
    server = stub(one_issue_routes(**{"api/rules/show": (200, {"rule": {"key": "python:S9"}}),
                                      "api/rules/search": (403, {"errors": [{"msg": "Insufficient privileges"}]})}))
    proc = run_fetch(collect_args(report, tmp_path), server.url)
    assert proc.returncode == 3 and "GET api/rules/search failed" in proc.stdout
    assert server.calls("api/projects/delete", "POST")
