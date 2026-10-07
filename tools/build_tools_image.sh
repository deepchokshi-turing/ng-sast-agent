#!/usr/bin/env bash
# Build the sast-tools image (see images/sast-tools/Dockerfile).
#
#   tools/build_tools_image.sh                        # local, this machine's arch: sast-tools:<version>
#   tools/build_tools_image.sh --save amd64|arm64     # a file to hand over: handoff/sast-tools_<version>_<arch>.tar.gz
#   tools/build_tools_image.sh <registry>/sast-tools  # multi-arch (amd64 + arm64), pushed
#
# A saved file is loaded with `docker load -i <file>` and gives the same local tag
# (sast-tools:<version>) that the task Dockerfiles copy from. It must match the
# CPU of the machine that runs Harbor. It only helps local runs: Daytona pulls
# images from a registry.
#
# The tag is the agent version from pyproject.toml (it must equal
# sast.__version__), so a task image always copies tools that match the agent
# version that will check them. Task Dockerfiles pin the same tag, for example
# ARG SAST_TOOLS_IMAGE=sast-tools:0.4.0.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERSION="$(python3 -c 'import sys, tomllib; print(tomllib.load(open(sys.argv[1], "rb"))["project"]["version"])' "$ROOT/pyproject.toml")"
PKG_VERSION="$(PYTHONPATH="$ROOT" python3 -c 'import sast; print(sast.__version__)')"
if [[ "$VERSION" != "$PKG_VERSION" ]]; then
  echo "pyproject.toml says $VERSION but sast.__version__ is $PKG_VERSION: make them equal first" >&2
  exit 1
fi
CONTEXT="$(mktemp -d)"
trap 'rm -rf "$CONTEXT"' EXIT

cp "$ROOT/images/sast-tools/Dockerfile" "$ROOT/images/sast-tools/fetch_archive.py" \
   "$ROOT/sast/semgrep/install.py" "$ROOT/sast/semgrep/merge_rules.py" "$CONTEXT/"
PYTHONPATH="$ROOT" python3 -c "import json, sast.semgrep.pins as p; print(json.dumps(p.as_dict()))" > "$CONTEXT/pins.json"
# The manifest writer and every tool's pins, for /opt/sast/MANIFEST.json.
cp "$ROOT/sast/manifest.py" "$CONTEXT/sast_manifest.py"
PYTHONPATH="$ROOT" python3 -c "import json, sast.semgrep.pins as s, sast.codeql.pins as c, sast.sonarqube.pins as q; print(json.dumps({'semgrep': s.as_dict(), 'codeql': c.as_dict(), 'sonar-scanner': q.as_dict()}))" > "$CONTEXT/manifest_pins.json"

# CodeQL and sonar-scanner pins, passed as build arguments. A missing sha256 stops here.
PYTHONPATH="$ROOT" python3 - > "$CONTEXT/build-args.txt" <<'PY'
import sast.codeql.pins as c, sast.sonarqube.pins as s
values = {
    "CODEQL_URL_AMD64": c.bundle_url("amd64"),
    "CODEQL_SHA256_AMD64": c.BUNDLES["amd64"][1],
    "CODEQL_URL_ARM64": c.bundle_url("arm64"),
    "CODEQL_SHA256_ARM64": c.BUNDLES["arm64"][1],
    "SONAR_SCANNER_VERSION": s.SONAR_SCANNER_VERSION,
    "SONAR_SCANNER_SHA256_AMD64": s.SONAR_SCANNER_SHA256["x86_64"],
    "SONAR_SCANNER_SHA256_ARM64": s.SONAR_SCANNER_SHA256["aarch64"],
}
missing = [k for k, v in values.items() if not v]
if missing:
    raise SystemExit("missing pins: " + ", ".join(missing))
for k, v in values.items():
    print("--build-arg")
    print(f"{k}={v}")
PY
TOOL_ARGS=()
while IFS= read -r line; do TOOL_ARGS+=("$line"); done < "$CONTEXT/build-args.txt"
if [[ ${#TOOL_ARGS[@]} -ne 14 ]]; then
  echo "could not read the CodeQL and sonar-scanner pins" >&2
  exit 1
fi

if [[ $# -eq 0 ]]; then
  docker build "${TOOL_ARGS[@]}" -t "sast-tools:$VERSION" "$CONTEXT"
  echo "built sast-tools:$VERSION"
elif [[ "$1" == "--save" ]]; then
  ARCH="${2:?usage: --save amd64|arm64}"
  OUT="$ROOT/handoff/sast-tools_${VERSION}_${ARCH}.tar"
  mkdir -p "$ROOT/handoff"
  docker build "${TOOL_ARGS[@]}" --platform "linux/$ARCH" -t "sast-tools:$VERSION" "$CONTEXT"
  docker save "sast-tools:$VERSION" | gzip > "$OUT.gz"
  # Put this machine's own build back under the tag (cached, so quick).
  docker build "${TOOL_ARGS[@]}" -t "sast-tools:$VERSION" "$CONTEXT" >/dev/null
  echo "saved $OUT.gz (load with: docker load -i $(basename "$OUT").gz)"
else
  docker buildx build "${TOOL_ARGS[@]}" --platform linux/amd64,linux/arm64 -t "$1:$VERSION" --push "$CONTEXT"
  echo "pushed $1:$VERSION"
fi
