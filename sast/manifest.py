#!/usr/bin/env python3
"""Content manifest of the tools image: /opt/sast/MANIFEST.json (audit L6).

Writer, run once by the last build stage of images/sast-tools/Dockerfile::

    python3 sast_manifest.py write /opt/sast manifest_pins.json

It records the tool versions from the pins, a sha256 and mode for every file
and symlink under /opt/sast, one tree digest over all of them, and one tree
digest per tool part (see ``PARTS``). A tree digest is the sha256 of the sorted
lines ``<path>\\0<sha256>\\0<mode>\\n``. The path is relative to /opt/sast, the
mode is the octal ``st_mode`` from ``lstat`` (so a symlink and a file differ),
and a symlink's sha256 is that of its target string. Folders are not listed.

Reader, used by each agent's install or check step in the sandbox. Each agent
uploads this file as ``sast_manifest.py`` next to its installer, which calls
``check(tool, recompute=...)`` and puts the result in its INSTALL_RESULT, so it
lands in the run metadata under ``install.image_manifest``. When asked to
recompute, the reader hashes that tool's part again and compares it with the
recorded tree digest, and stops (recording "not_recomputed") once
``max_seconds`` have passed. A mismatch is recorded, not raised: the installers
still run their own version and pin checks.

Standard library only, and written for any Python 3.6+, because the reader runs
with whatever Python the task image has.
"""

import hashlib
import json
import os
import stat
import sys
import time

MANIFEST_NAME = "MANIFEST.json"
FORMAT = 1
#: The image's /opt/sast. Tests point it elsewhere with SAST_MANIFEST_ROOT.
DEFAULT_ROOT = "/opt/sast"

#: What belongs to each tool, as paths relative to /opt/sast (a folder covers
#: everything below it). Loose files the agents upload at setup (install.py,
#: pins.json, fetch.py) and the scratch folders home/ and out/ are left out on
#: purpose: they change in every sandbox.
PARTS = {
    "semgrep": ("bin", "venv", "python", "rules", "rules-merged", "install.json"),
    "codeql": ("codeql",),
    "sonar-scanner": ("sonar-scanner",),
}

#: Which pins key holds each tool's version.
VERSION_KEYS = {
    "semgrep": "semgrep_version",
    "codeql": "codeql_version",
    "sonar-scanner": "sonar_scanner_version",
}


class Timeout(Exception):
    """Recomputing took longer than allowed."""


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def entry(path):
    """(sha256, mode, size) of one file or symlink."""
    st = os.lstat(path)
    if stat.S_ISLNK(st.st_mode):
        return hashlib.sha256(os.readlink(path).encode("utf-8", "surrogateescape")).hexdigest(), \
            "{:o}".format(st.st_mode), 0
    return sha256_file(path), "{:o}".format(st.st_mode), st.st_size


def walk(root, prefixes=None, deadline=None):
    """{relative path: (sha256, mode, size)} for every file and symlink under
    ``root`` (only below ``prefixes`` when given), without MANIFEST.json."""
    found = {}
    starts = [os.path.join(root, p) for p in prefixes] if prefixes else [root]
    for start in starts:
        if os.path.islink(start) or os.path.isfile(start):
            rel = os.path.relpath(start, root).replace(os.sep, "/")
            found[rel] = entry(start)
            continue
        for current, dirs, files in os.walk(start):
            dirs.sort()
            # os.walk lists a symlink to a folder under dirs and does not follow it.
            for name in sorted(files) + [d for d in dirs if os.path.islink(os.path.join(current, d))]:
                if deadline is not None and time.monotonic() > deadline:
                    raise Timeout()
                path = os.path.join(current, name)
                rel = os.path.relpath(path, root).replace(os.sep, "/")
                if rel == MANIFEST_NAME:
                    continue
                found[rel] = entry(path)
    return found


def tree_digest(entries):
    """sha256 over sorted "<path>\\0<sha256>\\0<mode>\\n" lines."""
    lines = sorted("{}\0{}\0{}\n".format(rel, value[0], value[1]) for rel, value in entries.items())
    return hashlib.sha256("".join(lines).encode("utf-8", "surrogateescape")).hexdigest()


def in_part(rel, part):
    return any(rel == p or rel.startswith(p + "/") for p in PARTS[part])


def build(root, pins):
    """The manifest document for the tree at ``root``."""
    entries = walk(root)
    parts = {}
    for part in PARTS:
        mine = {rel: v for rel, v in entries.items() if in_part(rel, part)}
        parts[part] = {"paths": list(PARTS[part]), "files": len(mine),
                       "bytes": sum(v[2] for v in mine.values()), "tree_digest": tree_digest(mine)}
    tools = {}
    for tool, key in VERSION_KEYS.items():
        tool_pins = pins.get(tool) or {}
        tools[tool] = {"version": tool_pins.get(key), "pins": tool_pins}
    return {
        "format": FORMAT,
        "root": root,
        "tools": tools,
        "parts": parts,
        "file_count": len(entries),
        "total_bytes": sum(v[2] for v in entries.values()),
        "tree_digest": tree_digest(entries),
        "files": {rel: {"sha256": v[0], "mode": v[1], "size": v[2]} for rel, v in sorted(entries.items())},
    }


def write(root, pins_path):
    with open(pins_path) as f:
        pins = json.load(f)
    missing = [tool for tool, key in VERSION_KEYS.items() if not (pins.get(tool) or {}).get(key)]
    if missing:
        print("ERROR: no version pinned for " + ", ".join(missing), flush=True)
        return 2
    document = build(root, pins)
    with open(os.path.join(root, MANIFEST_NAME), "w") as f:
        json.dump(document, f, indent=1, sort_keys=True)
        f.write("\n")
    print("MANIFEST {} files, {} bytes, tree {}".format(
        document["file_count"], document["total_bytes"], document["tree_digest"]), flush=True)
    for part, info in document["parts"].items():
        print("  {} {} files, {} bytes, tree {}".format(part, info["files"], info["bytes"], info["tree_digest"]),
              flush=True)
    return 0


def check(tool, root=None, recompute=True, max_seconds=30.0):
    """What the run metadata records about the image manifest for one tool.

    Keys: ``present``, and when present also ``path``, ``manifest_sha256`` (of the
    file), ``tree_digest`` (whole image, as recorded), ``tool_version`` (from
    the pins in the manifest), ``tool_tree_digest`` (as recorded), ``status``
    and ``verified``. Status is "verified" (recomputed and equal), "mismatch"
    (recomputed and different, with ``recomputed_tree_digest``),
    "not_recomputed" (with ``reason``) or "unreadable". ``recompute`` is
    True to rehash the tool's part, or a string saying why not.
    """
    root = root or os.environ.get("SAST_MANIFEST_ROOT") or DEFAULT_ROOT
    path = os.path.join(root, MANIFEST_NAME)
    if not os.path.isfile(path):
        return {"present": False, "path": path, "verified": False, "status": "absent"}
    try:
        with open(path, "rb") as f:
            raw = f.read()
        document = json.loads(raw.decode("utf-8"))
        part = document["parts"][tool]
        result = {
            "present": True,
            "path": path,
            "format": document.get("format"),
            "manifest_sha256": hashlib.sha256(raw).hexdigest(),
            "tree_digest": document["tree_digest"],
            "tool": tool,
            "tool_version": ((document.get("tools") or {}).get(tool) or {}).get("version"),
            "tool_tree_digest": part["tree_digest"],
            "tool_files": part.get("files"),
            "tool_bytes": part.get("bytes"),
        }
    except (OSError, ValueError, KeyError, TypeError) as exc:
        return {"present": True, "path": path, "verified": False, "status": "unreadable",
                "reason": "{}: {}".format(type(exc).__name__, exc)}
    if recompute is not True:
        # A string says why not, for the record.
        result.update(verified=False, status="not_recomputed",
                      reason=recompute if isinstance(recompute, str) and recompute else "not asked to recompute")
        return result
    started = time.monotonic()
    try:
        entries = walk(root, PARTS[tool], deadline=started + max_seconds)
    except Timeout:
        result.update(verified=False, status="not_recomputed",
                      reason="stopped after {} s".format(max_seconds))
        return result
    except OSError as exc:
        result.update(verified=False, status="not_recomputed", reason="cannot read: {}".format(exc))
        return result
    digest = tree_digest(entries)
    result["recompute_seconds"] = round(time.monotonic() - started, 2)
    if digest == part["tree_digest"]:
        result.update(verified=True, status="verified")
    else:
        result.update(verified=False, status="mismatch", recomputed_tree_digest=digest,
                      recomputed_files=len(entries))
    return result


def main(argv):
    if len(argv) == 3 and argv[0] == "write":
        return write(argv[1], argv[2])
    if len(argv) in (2, 3) and argv[0] == "check":
        print(json.dumps(check(argv[1], argv[2] if len(argv) == 3 else None)))
        return 0
    print("usage: sast_manifest.py write <root> <pins.json> | check <tool> [<root>]")
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
