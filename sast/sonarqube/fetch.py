#!/usr/bin/env python3
"""Talk to the SonarQube server from inside the sandbox.

Uploaded by ``SonarQubeAgent.setup`` and run with the same Python as
install.py. All API calls run here, not on the host, so they take the same
network route as sonar-scanner. Standard library only, any Python 3.6+.

The server comes from ``SONAR_HOST_URL``. The token is read from a file, named
by ``--token-file`` or else ``SONAR_TOKEN_FILE``, that the agent uploads with
mode 600 and deletes after the scan. The token is never passed on a command
line or through an exec environment, because Harbor turns both into process
arguments. It goes only into the ``Authorization: Bearer`` header. It is never
printed, written anywhere or put in a URL, and every line this script prints
is scrubbed of it as well.

Subcommands:

``check``
    The server is UP, the token is accepted, and its version, edition and
    default Python quality profile. Last line ``CHECK_RESULT {json}``.
``collect --report FILE --project KEY --out FILE --deadline SEC [--keep]``
    Reads the background task id from sonar-scanner's report file, polls
    ``api/ce/task`` until SUCCESS (FAILED, CANCELED or the deadline is an
    error), pages ``api/issues/search`` (VULNERABILITY) and
    ``api/hotspots/search``, then for each rule once calls ``api/rules/show``
    (name and type) and ``api/rules/search?rule_key=<key>&facets=cwe``, whose
    ``cwe`` facet is the rule's CWE set (26.9 has no securityStandards in
    rules/show). A 404 or an empty answer for one rule is recorded under
    ``rule_errors`` and does not stop the collection. Then it reads the
    project's Python quality profile and deletes the project unless
    ``--keep``. Writes every raw response to ``--out`` with a ``deleted`` flag,
    also after a failure. Last line ``COLLECT_RESULT {json}``.
``delete --project KEY``
    Best-effort cleanup after a failed scan.

Exit status: 0 ok, 2 bad configuration or arguments, 3 the server refused or
could not be reached, 4 the background task FAILED or was CANCELED, 5 the
deadline passed, 6 the results cannot be read completely.
"""

import argparse
import json
import os
import socket
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

PAGE_SIZE = 500
#: Elasticsearch behind the issues and hotspots APIs serves at most this many
#: results per query. More cannot be paged, so the result would be incomplete.
MAX_RESULTS = 10000
HTTP_TIMEOUT_SEC = 60
GET_ATTEMPTS = 3

EXIT_CONFIG, EXIT_HTTP, EXIT_TASK, EXIT_TIMEOUT, EXIT_INCOMPLETE = 2, 3, 4, 5, 6


class Failure(Exception):
    def __init__(self, message, code, http_status=None):
        Exception.__init__(self, message)
        self.code = code
        self.http_status = http_status


class Sonar(object):
    def __init__(self, host, token):
        self.host = host.rstrip("/")
        self.token = token

    def scrub(self, text):
        text = str(text)
        return text.replace(self.token, "***") if self.token else text

    def _describe(self, code, method, path, body):
        detail = ""
        try:
            errors = json.loads(body.decode("utf-8", "replace")).get("errors") or []
            detail = "; ".join(str(e.get("msg", "")) for e in errors if isinstance(e, dict))
        except (ValueError, AttributeError):
            detail = body.decode("utf-8", "replace").strip()[:300]
        where = "{} {}".format(method, path)
        if code == 401:
            why = "the server did not accept SONAR_TOKEN (wrong, expired or revoked token)"
        elif code == 403:
            why = ("SONAR_TOKEN lacks a permission this call needs (it needs Execute Analysis, Create Projects, "
                   "Browse on the project and Administer to delete it)")
        elif code == 404:
            why = "not found (wrong SONAR_HOST_URL path, or the project or task does not exist)"
        else:
            why = "HTTP {}".format(code)
        message = "{} failed: {}".format(where, why)
        if detail:
            message += " (server said: {})".format(detail)
        return self.scrub(message)

    def call(self, method, path, params=None, form=None, raw=False):
        url = self.host + "/" + path
        if params:
            url += "?" + urllib.parse.urlencode(params)
        data = urllib.parse.urlencode(form).encode("utf-8") if form is not None else None
        headers = {"Authorization": "Bearer " + self.token, "Accept": "application/json",
                   "User-Agent": "sast-agents-fetch"}
        attempts = GET_ATTEMPTS if method == "GET" else 1
        for attempt in range(1, attempts + 1):
            request = urllib.request.Request(url, data=data, headers=headers, method=method)
            try:
                with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT_SEC) as response:
                    body = response.read()
                break
            except urllib.error.HTTPError as exc:
                body = exc.read() or b""
                if exc.code >= 500 and attempt < attempts:
                    time.sleep(0.5 * attempt)
                    continue
                raise Failure(self._describe(exc.code, method, path, body), EXIT_HTTP, exc.code)
            except (urllib.error.URLError, socket.timeout, ConnectionError) as exc:
                if attempt < attempts:
                    time.sleep(0.5 * attempt)
                    continue
                reason = getattr(exc, "reason", exc)
                raise Failure(self.scrub("cannot reach SONAR_HOST_URL {} for {} {}: {}".format(
                    self.host, method, path, reason)), EXIT_HTTP)
        if raw:
            return body.decode("utf-8", "replace")
        if not body:
            return None
        try:
            return json.loads(body.decode("utf-8"))
        except ValueError:
            raise Failure("{} {} returned something that is not JSON: {}".format(
                method, path, self.scrub(body[:200].decode("utf-8", "replace"))), EXIT_HTTP)

    def get(self, path, **params):
        return self.call("GET", path, params=params or None)


def say(sonar, line):
    print(sonar.scrub(line) if sonar else line, flush=True)


def read_token(path):
    if not path:
        raise Failure("no token file: pass --token-file or set SONAR_TOKEN_FILE", EXIT_CONFIG)
    try:
        with open(path) as f:
            token = f.read().strip()
    except OSError as exc:
        raise Failure("cannot read the token file {}: {}".format(path, exc.strerror or exc), EXIT_CONFIG)
    if not token:
        raise Failure("the token file {} is empty".format(path), EXIT_CONFIG)
    return token


def connect(token_file=None):
    host = os.environ.get("SONAR_HOST_URL", "").strip()
    if not host:
        raise Failure("SONAR_HOST_URL is not set", EXIT_CONFIG)
    token = read_token(token_file or os.environ.get("SONAR_TOKEN_FILE", "").strip())
    if not host.startswith(("http://", "https://")):
        raise Failure("SONAR_HOST_URL must start with http:// or https://, got {!r}".format(host), EXIT_CONFIG)
    return Sonar(host, token)


# ---------------------------------------------------------------- check

def check(sonar, args):
    status = sonar.get("api/system/status") or {}
    if status.get("status") != "UP":
        raise Failure("the server status is {}, not UP".format(status.get("status")), EXIT_HTTP)
    valid = sonar.get("api/authentication/validate") or {}
    if valid.get("valid") is not True:
        raise Failure("the server did not accept SONAR_TOKEN (api/authentication/validate says not valid)",
                      EXIT_HTTP)
    version = sonar.call("GET", "api/server/version", raw=True).strip()
    result = {"status": "UP", "server_version": version, "server_id": status.get("id"),
              "edition": None, "default_python_profile": None}
    try:
        result["edition"] = (sonar.get("api/navigation/global") or {}).get("edition")
    except Failure as exc:
        say(sonar, "[fetch] edition not available: {}".format(exc))
    try:
        profiles = (sonar.get("api/qualityprofiles/search", language="py", defaults="true") or {}).get("profiles")
        if profiles:
            result["default_python_profile"] = {k: profiles[0].get(k) for k in ("name", "key")}
    except Failure as exc:
        say(sonar, "[fetch] default Python profile not available: {}".format(exc))
    say(sonar, "CHECK_RESULT " + json.dumps(result))


# ---------------------------------------------------------------- collect

def read_report(path):
    """key=value lines of sonar-scanner's report-task.txt."""
    try:
        with open(path) as f:
            lines = f.read().splitlines()
    except OSError as exc:
        raise Failure("cannot read sonar-scanner's report file {}: {}".format(path, exc), EXIT_CONFIG)
    values = {}
    for line in lines:
        if "=" in line and not line.lstrip().startswith("#"):
            key, value = line.split("=", 1)
            values[key.strip()] = value.strip()
    return values


def wait_for_task(sonar, task_id, deadline, interval, document):
    while True:
        task = (sonar.get("api/ce/task", id=task_id) or {}).get("task") or {}
        document["ce_task"] = task
        status = task.get("status")
        if status == "SUCCESS":
            return task
        if status in ("FAILED", "CANCELED"):
            raise Failure("the background task {} ended {}: {}".format(
                task_id, status, task.get("errorMessage") or "no error message"), EXIT_TASK)
        if time.time() + interval > deadline:
            raise Failure("the background task {} was still {} when the deadline passed".format(
                task_id, status), EXIT_TIMEOUT)
        time.sleep(interval)


def pages(sonar, path, items_key, params):
    """Every page of a search, raw. Stops when all results are read."""
    collected, page, total = [], 1, None
    while True:
        response = sonar.get(path, p=page, ps=PAGE_SIZE, **params) or {}
        collected.append(response)
        paging = response.get("paging") or {}
        total = paging.get("total", response.get("total"))
        if total is not None and int(total) > MAX_RESULTS:
            raise Failure("{} reports {} results but only {} can be paged, so the result would be incomplete".format(
                path, total, MAX_RESULTS), EXIT_INCOMPLETE)
        items = response.get(items_key) or []
        if not items or total is None or page * PAGE_SIZE >= int(total):
            return collected
        page += 1


def search_issues(sonar, project):
    params = {"componentKeys": project, "types": "VULNERABILITY"}
    try:
        return pages(sonar, "api/issues/search", "issues", params)
    except Failure as exc:
        # componentKeys is deprecated in favour of components since 10.2.
        if exc.code != EXIT_HTTP or "componentKeys" not in str(exc):
            raise
        params = {"components": project, "types": "VULNERABILITY"}
        return pages(sonar, "api/issues/search", "issues", params)


def lookup_rule(sonar, key, document):
    """rules/show and the rules/search cwe facet of one rule, raw.

    A rule the server does not know (404) or a search that finds nothing is
    recorded in ``rule_errors`` and leaves the rule with no CWE. Any other
    error stops the collection as usual.
    """
    errors = []
    try:
        document["rules"][key] = sonar.get("api/rules/show", key=key)
    except Failure as exc:
        if exc.http_status != 404:
            raise
        document["rules"][key] = None
        errors.append(str(exc))
    try:
        search = sonar.get("api/rules/search", rule_key=key, facets="cwe", ps=1)
    except Failure as exc:
        if exc.http_status != 404:
            raise
        search = None
        errors.append(str(exc))
    document["rule_facets"][key] = search
    if search is not None and not (search.get("rules") or search.get("total")):
        errors.append("api/rules/search found no rule {}".format(key))
    if errors:
        document["rule_errors"][key] = "; ".join(errors)


def delete_project(sonar, project):
    """(deleted, error)."""
    try:
        sonar.call("POST", "api/projects/delete", form={"project": project})
        return True, None
    except Failure as exc:
        return False, str(exc)


def write_json(path, document):
    tmp = path + ".part"
    with open(tmp, "w") as f:
        json.dump(document, f, indent=1, sort_keys=True)
    os.replace(tmp, path)


def collect(sonar, args):
    document = {
        "fetch_format": 2,
        "server": {"host_url": sonar.host},
        "project_key": args.project,
        "report_task": None,
        "ce_task": None,
        "issues_pages": [],
        "hotspots_pages": [],
        "rules": {},
        "rule_facets": {},
        "rule_errors": {},
        "quality_profiles": None,
        "deleted": False,
        "delete_error": None,
        "kept": bool(args.keep),
        "error": None,
    }
    deadline = time.time() + float(args.deadline)
    failure = None
    try:
        report = read_report(args.report)
        document["report_task"] = {k: report.get(k) for k in ("projectKey", "ceTaskId", "ceTaskUrl")}
        if report.get("projectKey") != args.project:
            raise Failure("the report file is for project {!r}, expected {!r}".format(
                report.get("projectKey"), args.project), EXIT_CONFIG)
        task_id = report.get("ceTaskId")
        if not task_id:
            raise Failure("the report file {} has no ceTaskId".format(args.report), EXIT_CONFIG)

        wait_for_task(sonar, task_id, deadline, float(args.poll_interval), document)
        try:
            document["server"]["version"] = sonar.call("GET", "api/server/version", raw=True).strip()
        except Failure as exc:
            say(sonar, "[fetch] server version not available: {}".format(exc))
        document["issues_pages"] = search_issues(sonar, args.project)
        document["hotspots_pages"] = pages(sonar, "api/hotspots/search", "hotspots", {"projectKey": args.project})

        keys = set()
        for page in document["issues_pages"]:
            keys.update(i.get("rule") for i in page.get("issues") or [] if i.get("rule"))
        for page in document["hotspots_pages"]:
            keys.update(h.get("ruleKey") for h in page.get("hotspots") or [] if h.get("ruleKey"))
        for key in sorted(keys):
            lookup_rule(sonar, key, document)
        document["quality_profiles"] = sonar.get("api/qualityprofiles/search", project=args.project, language="py")
    except Failure as exc:
        failure = exc
        document["error"] = str(exc)

    if not args.keep:
        document["deleted"], document["delete_error"] = delete_project(sonar, args.project)
        if document["delete_error"]:
            say(sonar, "[fetch] project {} was left on the server: {}".format(args.project, document["delete_error"]))
    write_json(args.out, document)
    if failure is not None:
        raise failure

    issues = sum(len(p.get("issues") or []) for p in document["issues_pages"])
    hotspots = sum(len(p.get("hotspots") or []) for p in document["hotspots_pages"])
    say(sonar, "COLLECT_RESULT " + json.dumps({
        "issues": issues, "hotspots": hotspots, "rules": len(document["rules"]),
        "rule_errors": len(document["rule_errors"]),
        "deleted": document["deleted"], "kept": document["kept"], "delete_error": document["delete_error"],
    }))


def delete(sonar, args):
    deleted, error = delete_project(sonar, args.project)
    say(sonar, "DELETE_RESULT " + json.dumps({"project_key": args.project, "deleted": deleted, "error": error}))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--token-file", help="file holding the token (default: $SONAR_TOKEN_FILE)")
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("check")
    p = sub.add_parser("collect")
    p.add_argument("--report", required=True)
    p.add_argument("--project", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--deadline", required=True, type=float, help="seconds to wait for the background task")
    p.add_argument("--poll-interval", default=2.0, type=float)
    p.add_argument("--keep", action="store_true", help="do not delete the project")
    p = sub.add_parser("delete")
    p.add_argument("--project", required=True)
    args = parser.parse_args(argv)
    if args.command is None:
        parser.error("a subcommand is required")

    sonar = None
    try:
        sonar = connect(args.token_file)
        {"check": check, "collect": collect, "delete": delete}[args.command](sonar, args)
    except Failure as exc:
        say(sonar, "[fetch] ERROR: {}".format(exc))
        return exc.code
    return 0


if __name__ == "__main__":
    sys.exit(main())
