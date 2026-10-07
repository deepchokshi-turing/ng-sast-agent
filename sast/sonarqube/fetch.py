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
    error), reads what was analysed (``api/measures/component``: files, ncloc,
    ncloc_language_distribution), pages ``api/issues/search`` (VULNERABILITY)
    and ``api/hotspots/search``, then for each rule once calls
    ``api/rules/show`` (name and type) and
    ``api/rules/search?rule_key=<key>&facets=cwe``, whose ``cwe`` facet is the
    rule's CWE set (26.9 has no securityStandards in rules/show). Any error in
    a rule lookup stops the collection, and so does a search that does not
    find exactly that one rule. Then it reads the project's Python quality
    profile (the default one when the project has none), counts the Security
    Hotspot rules (``api/rules/search?types=SECURITY_HOTSPOT``, server-wide and
    active in that profile, see ``hotspot_rule_counts``) and deletes the
    project unless ``--keep``. ``--deadline`` bounds every one of these calls
    together. The delete still gets a short fixed slice after it. Writes every
    raw response to ``--out`` with a ``deleted`` flag, also after a failure.
    Last line ``COLLECT_RESULT {json}``.
``delete --project KEY``
    Best-effort cleanup after a failed scan, within a short fixed time.

Exit status: 0 ok, 2 bad configuration or arguments, 3 the server refused or
could not be reached, 4 the background task FAILED or was CANCELED, 5 the
deadline passed, 6 the results cannot be read completely (paging, rule CWEs).

The agent also runs this script under ``timeout -k 10 <seconds>``, so it
cannot outlive its step even if a call hangs.
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
#: Seconds the project delete may take, also when the collect deadline has passed.
DELETE_SLICE_SEC = 20
#: The analysis measures read after the background task succeeds.
MEASURE_KEYS = "files,ncloc,ncloc_language_distribution"

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
        #: time.time() after which no call starts, or None for no limit.
        self.deadline = None

    def _time_left(self, method, path):
        if self.deadline is None:
            return float(HTTP_TIMEOUT_SEC)
        left = self.deadline - time.time()
        if left <= 0:
            raise Failure("the deadline passed before {} {}".format(method, path), EXIT_TIMEOUT)
        return min(float(HTTP_TIMEOUT_SEC), left)

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
            timeout = self._time_left(method, path)
            request = urllib.request.Request(url, data=data, headers=headers, method=method)
            try:
                with urllib.request.urlopen(request, timeout=timeout) as response:
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


def has_user_info(url):
    """Whether a URL carries a user name or password (``http://user:pass@host``)."""
    netloc = urllib.parse.urlsplit(url).netloc
    return "@" in netloc


def connect(token_file=None):
    host = os.environ.get("SONAR_HOST_URL", "").strip()
    if not host:
        raise Failure("SONAR_HOST_URL is not set", EXIT_CONFIG)
    if has_user_info(host):
        # Not echoed: it holds a credential.
        raise Failure("SONAR_HOST_URL must not contain a user name or password (user:pass@host)", EXIT_CONFIG)
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
    """Every page of a search, raw. The number of items read must equal the reported total."""
    collected, page, count = [], 1, 0
    while True:
        response = sonar.get(path, p=page, ps=PAGE_SIZE, **params) or {}
        collected.append(response)
        paging = response.get("paging") or {}
        total = paging.get("total", response.get("total"))
        if total is None:
            raise Failure("{} gave no paging total, so completeness cannot be checked".format(path), EXIT_INCOMPLETE)
        total = int(total)
        if total > MAX_RESULTS:
            raise Failure("{} reports {} results but only {} can be paged, so the result would be incomplete".format(
                path, total, MAX_RESULTS), EXIT_INCOMPLETE)
        items = response.get(items_key) or []
        count += len(items)
        if not items or page * PAGE_SIZE >= total:
            break
        page += 1
    if count != total:
        raise Failure("{} reported {} results but {} were read".format(path, total, count), EXIT_INCOMPLETE)
    return collected


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


def facet_found_rule(search, key):
    """Whether an api/rules/search answer is exactly the one rule ``key``."""
    search = search or {}
    total = (search.get("paging") or {}).get("total", search.get("total"))
    rules = search.get("rules") or []
    return total is not None and int(total) == 1 and len(rules) == 1 and (rules[0] or {}).get("key") == key


def lookup_rule(sonar, key, document):
    """rules/show and the rules/search cwe facet of one rule, raw.

    Every error is fatal: a rule without its CWEs would silently drop its
    results. The search must report exactly one rule, the one asked for.
    """
    document["rules"][key] = sonar.get("api/rules/show", key=key)
    search = sonar.get("api/rules/search", rule_key=key, facets="cwe", ps=1)
    document["rule_facets"][key] = search
    if not facet_found_rule(search, key):
        raise Failure("api/rules/search?rule_key={} did not return exactly that rule, so its CWEs are "
                      "unknown".format(key), EXIT_INCOMPLETE)


def python_profile_key(document):
    """Key of the project's Python quality profile, else of the default one."""
    for name in ("quality_profiles", "default_quality_profiles"):
        for profile in (document.get(name) or {}).get("profiles") or []:
            if isinstance(profile, dict) and profile.get("language", "py") == "py" and profile.get("key"):
                return profile["key"]
    return None


def search_total(answer):
    """The ``total`` of an api/rules/search answer (top level, or under paging)."""
    answer = answer or {}
    total = answer.get("total")
    if total is None:
        total = (answer.get("paging") or {}).get("total")
    if total is None:
        raise Failure("api/rules/search returned no total", EXIT_INCOMPLETE)
    return int(total)


def hotspot_rule_counts(sonar, document):
    """How many Security Hotspot rules the server has, and how many are active
    in the Python profile used.

    SonarQube Community Build 26.9.0.129388 has none at all (the server-wide
    total is 0 for every language, and 35 of its 61 active Python
    VULNERABILITY rules carry the tag former-hotspot), so a scan on it can
    never raise a hotspot. Older servers do, which is why the hotspot paging
    stays. Recorded as ``hotspot_rules_total`` and ``hotspot_rules_active``.
    Informational: an error here is recorded in ``hotspot_rules_error`` and
    does not stop the collection.
    """
    try:
        document["hotspot_rules_total"] = search_total(
            sonar.get("api/rules/search", types="SECURITY_HOTSPOT", ps=1))
        key = python_profile_key(document)
        document["hotspot_rules_qprofile"] = key
        if key is None:
            document["hotspot_rules_error"] = "no Python quality profile to count active hotspot rules in"
            return
        document["hotspot_rules_active"] = search_total(
            sonar.get("api/rules/search", types="SECURITY_HOTSPOT", languages="py", activation="true",
                      qprofile=key, ps=1))
    except (Failure, ValueError, TypeError, AttributeError) as exc:
        document["hotspot_rules_error"] = str(exc)
        say(sonar, "[fetch] hotspot rule count not available: {}".format(exc))


def delete_project(sonar, project):
    """(deleted, error). Gets its own short time slice, also after the deadline."""
    sonar.deadline = time.time() + DELETE_SLICE_SEC
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
        "measures": None,
        "quality_profiles": None,
        "default_quality_profiles": None,
        "hotspot_rules_total": None,
        "hotspot_rules_active": None,
        "hotspot_rules_qprofile": None,
        "hotspot_rules_error": None,
        "deleted": False,
        "delete_error": None,
        "kept": bool(args.keep),
        "error": None,
    }
    deadline = time.time() + float(args.deadline)
    sonar.deadline = deadline
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
        document["measures"] = sonar.get("api/measures/component", component=args.project,
                                         metricKeys=MEASURE_KEYS)
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
        if not (document["quality_profiles"] or {}).get("profiles"):
            document["default_quality_profiles"] = sonar.get("api/qualityprofiles/search", language="py",
                                                             defaults="true")
        hotspot_rule_counts(sonar, document)
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
