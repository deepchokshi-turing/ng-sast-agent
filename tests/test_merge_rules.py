"""merge_rules.py: same rules, ids as Semgrep would have written them.

The full equivalence check (every finding identical on the rules repo's own test
corpus) is tools/check_merged_rules.sh, run once per pin change.
"""

import json
import subprocess
import sys

import pytest

from tests.conftest import ROOT

SCRIPT = ROOT / "sast" / "semgrep" / "merge_rules.py"


def write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def merge(rules, out, *folders):
    return subprocess.run([sys.executable, str(SCRIPT), str(rules), str(out), *folders],
                          capture_output=True, text=True)


def test_ids_carry_the_folder_path_and_content_is_kept(tmp_path):
    rules = tmp_path / "rules"
    write(rules / "python/lang/security/audit/eval.yaml",
          "rules:\n- id: eval-detected\n  pattern: eval(...)\n  message: m\n  languages: [python]\n"
          "  severity: WARNING\n  metadata:\n    cwe: ['CWE-95: x']\n    category: security\n")
    write(rules / "generic/secrets/gitleaks/a.yml",
          "rules:\n- id: a\n  pattern-regex: 'on'\n  message: yes\n  languages: [generic]\n  severity: INFO\n")
    result = merge(rules, tmp_path / "out", "python", "generic/secrets")
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout.split("MERGED ", 1)[1]) == {"python": 1, "generic/secrets": 1}

    python = json.loads((tmp_path / "out" / "python.yaml").read_text())["rules"]
    assert python[0]["id"] == "python.lang.security.audit.eval-detected"
    assert python[0]["pattern"] == "eval(...)" and python[0]["metadata"]["cwe"] == ["CWE-95: x"]
    secrets = json.loads((tmp_path / "out" / "generic_secrets.yaml").read_text())["rules"]
    # YAML 1.2: 'on' and yes stay strings, as Semgrep reads them.
    assert secrets[0]["id"] == "generic.secrets.gitleaks.a"
    assert secrets[0]["pattern-regex"] == "on" and secrets[0]["message"] == "yes"


def test_duplicate_ids_fail_the_install(tmp_path):
    rules = tmp_path / "rules"
    body = "rules:\n- id: same\n  pattern: x\n  message: m\n  languages: [python]\n  severity: INFO\n"
    write(rules / "python/a.yaml", body)
    write(rules / "python/b.yaml", body)
    result = merge(rules, tmp_path / "out", "python")
    assert result.returncode != 0 and "duplicate rule id" in result.stderr
