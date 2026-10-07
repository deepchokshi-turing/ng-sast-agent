"""The platform puts this repo on Harbor's PYTHONPATH and installs nothing.

So loading the agent may only import the standard library, harbor, and what
harbor itself depends on. This is the failure the BrowseComp agent needed a patch
for ("No module named 'PIL'").
"""

import json
import re
import subprocess
import sys
from importlib import metadata

from tests.conftest import ROOT


def _closure(dist: str) -> set[str]:
    seen: set[str] = set()
    todo = [dist]
    while todo:
        name = re.split(r"[\s<>=!~;\[(]", todo.pop(), maxsplit=1)[0].lower().replace("_", "-")
        if name in seen:
            continue
        try:
            requires = metadata.requires(name) or []
        except metadata.PackageNotFoundError:
            continue
        seen.add(name)
        todo += [r for r in requires if "extra ==" not in r]
    return seen


def test_agent_imports_only_stdlib_and_harbor():
    code = (
        "import json, sys; import sast.semgrep.agent, sast.codeql.agent; "
        "print(json.dumps(sorted({m.split('.')[0] for m in sys.modules})))"
    )
    out = subprocess.run([sys.executable, "-c", code], cwd=ROOT, check=True, capture_output=True, text=True)
    top_level = set(json.loads(out.stdout))

    allowed_dists = _closure("harbor")
    providers = metadata.packages_distributions()
    offenders = []
    # sitecustomize/usercustomize: Debian and Ubuntu Pythons load their own at startup.
    for module in top_level - set(sys.stdlib_module_names) - {"sast", "harbor", "sitecustomize", "usercustomize"}:
        if module.startswith("_"):
            continue
        dists = {d.lower().replace("_", "-") for d in providers.get(module, [])}
        if not dists & allowed_dists:
            offenders.append((module, sorted(dists)))
    assert offenders == []
