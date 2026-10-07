"""Merge the pinned rule files into one config file per rules folder.

Run by install.py with the Semgrep venv's Python (ruamel.yaml comes with Semgrep).

Why: Semgrep validates every rule *file* in a separate ``semgrep-core`` process.
With 898 files on a 1-CPU sandbox that alone takes about four minutes, before a
single target is scanned. Five merged files take seconds.

Nothing about matching changes. Every rule keeps its content; only its ``id`` is
set to what Semgrep itself would have reported for the original file (the
file's folder, dotted, then the id: ``python/lang/security/audit/eval-detected.yaml``
rule ``eval-detected`` -> ``python.lang.security.audit.eval-detected``), and the
scan runs with ``--no-rewrite-rule-ids`` so Semgrep keeps those ids as written.
The output is JSON, which is valid YAML.

    python merge_rules.py <rules dir> <output dir> <folder> [<folder> ...]
"""

import json
import os
import sys

from ruamel.yaml import YAML


def merged_rules(rules_dir, folder):
    yaml = YAML(typ="safe", pure=True)
    rules = []
    root = os.path.join(rules_dir, folder)
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        for name in sorted(filenames):
            if not name.endswith((".yaml", ".yml")):
                continue
            path = os.path.join(dirpath, name)
            with open(path, encoding="utf-8") as f:
                document = yaml.load(f)
            if not isinstance(document, dict) or not isinstance(document.get("rules"), list):
                raise SystemExit("not a rules file: " + path)
            prefix = os.path.relpath(dirpath, rules_dir).replace(os.sep, ".")
            for rule in document["rules"]:
                rule["id"] = prefix + "." + str(rule["id"])
                rules.append(rule)
    return rules


def main():
    rules_dir, out_dir, folders = sys.argv[1], sys.argv[2], sys.argv[3:]
    os.makedirs(out_dir, exist_ok=True)
    summary = {}
    seen = set()
    for folder in folders:
        rules = merged_rules(rules_dir, folder)
        for rule in rules:
            if rule["id"] in seen:
                raise SystemExit("duplicate rule id after merging: " + rule["id"])
            seen.add(rule["id"])
        target = os.path.join(out_dir, folder.replace("/", "_") + ".yaml")
        with open(target, "w", encoding="utf-8") as f:
            json.dump({"rules": rules}, f)
        summary[folder] = len(rules)
    print("MERGED " + json.dumps(summary))


if __name__ == "__main__":
    main()
