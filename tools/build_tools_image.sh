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
# The tag is sast.__version__, so a task image always copies tools that match
# the agent version that will check them.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERSION="$(PYTHONPATH="$ROOT" python3 -c 'import sast; print(sast.__version__)')"
CONTEXT="$(mktemp -d)"
trap 'rm -rf "$CONTEXT"' EXIT

cp "$ROOT/images/sast-tools/Dockerfile" "$ROOT/sast/semgrep/install.py" "$ROOT/sast/semgrep/merge_rules.py" "$CONTEXT/"
PYTHONPATH="$ROOT" python3 -c "import json, sast.semgrep.pins as p; print(json.dumps(p.as_dict()))" > "$CONTEXT/pins.json"

if [[ $# -eq 0 ]]; then
  docker build -t "sast-tools:$VERSION" "$CONTEXT"
  echo "built sast-tools:$VERSION"
elif [[ "$1" == "--save" ]]; then
  ARCH="${2:?usage: --save amd64|arm64}"
  OUT="$ROOT/handoff/sast-tools_${VERSION}_${ARCH}.tar"
  mkdir -p "$ROOT/handoff"
  docker build --platform "linux/$ARCH" -t "sast-tools:$VERSION" "$CONTEXT"
  docker save "sast-tools:$VERSION" | gzip > "$OUT.gz"
  # Put this machine's own build back under the tag (cached, so quick).
  docker build -t "sast-tools:$VERSION" "$CONTEXT" >/dev/null
  echo "saved $OUT.gz (load with: docker load -i $(basename "$OUT").gz)"
else
  docker buildx build --platform linux/amd64,linux/arm64 -t "$1:$VERSION" --push "$CONTEXT"
  echo "pushed $1:$VERSION"
fi
