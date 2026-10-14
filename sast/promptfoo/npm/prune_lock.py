#!/usr/bin/env python3
"""Prune a full ``npm install --package-lock-only`` lock to what the agent installs.

Maintenance tool, run by hand when the pins change (see docs/promptfoo-agent.md):

    python prune_lock.py full-package-lock.json package-lock.json

promptfoo 0.124.1 lists 27 optional dependencies (cloud SDKs, sharp, the
Claude agent SDK, ...) that a full ``npm ci`` installs: 1.4 GB. Code Scanning
needs none of them, but ``--omit=optional`` would also drop the native SQLite
binding promptfoo loads at start-up. So the lock keeps every package reachable
from the root through required edges (``dependencies`` and non-optional
``peerDependencies``), plus the optional packages named in ``KEEP_OPTIONAL``.
``npm ci`` then installs exactly that, with every tarball checked against the
lock's ``integrity``. No entry is edited, only left out.
"""

import json
import sys

#: Optional packages promptfoo needs on glibc Linux: the libsql binding it loads at start-up.
KEEP_OPTIONAL = frozenset(("@libsql/linux-x64-gnu", "@libsql/linux-arm64-gnu"))


def resolve(packages, from_path, name):
    """The lock path npm resolves ``name`` to from the package at ``from_path``."""
    base = from_path
    while True:
        candidate = (base + "/node_modules/" if base else "node_modules/") + name
        if candidate in packages:
            return candidate
        if not base:
            return None
        index = base.rfind("/node_modules/")
        base = base[:index] if index >= 0 else ""


def prune(lock):
    packages = lock["packages"]
    keep, todo = {""}, [""]
    while todo:
        path = todo.pop()
        entry = packages[path]
        optional_peers = {k for k, v in (entry.get("peerDependenciesMeta") or {}).items() if v.get("optional")}
        edges = list((entry.get("dependencies") or {}).keys())
        edges += [n for n in (entry.get("peerDependencies") or {}) if n not in optional_peers]
        edges += [n for n in (entry.get("optionalDependencies") or {}) if n in KEEP_OPTIONAL]
        for name in edges:
            target = resolve(packages, path, name)
            if target is None:
                if name in (entry.get("dependencies") or {}):
                    raise SystemExit("unresolved required dependency {} of {!r}".format(name, path))
                continue
            if target not in keep:
                keep.add(target)
                todo.append(target)
    pruned = dict(lock)
    pruned["packages"] = {k: v for k, v in packages.items() if k in keep}
    return pruned


def main(argv):
    source, target = argv[1], argv[2]
    with open(source) as f:
        lock = json.load(f)
    pruned = prune(lock)
    with open(target, "w", newline="\n") as f:
        json.dump(pruned, f, indent=2)
        f.write("\n")
    print("{} of {} lock entries kept".format(len(pruned["packages"]), len(lock["packages"])))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
