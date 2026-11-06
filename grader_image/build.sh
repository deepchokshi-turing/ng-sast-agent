#!/usr/bin/env bash
# Build the sast-grader image locally and tag it for the registry and for local use.
#
#   grader_image/build.sh            # from ng-sast-agent/ (any cwd works)
#
# Tags produced (VERSION = contents of grader_image/VERSION, e.g. 3.3.0, MAJOR = 3):
#   us-central1-docker.pkg.dev/turing-delivery-rl-gym/daytona/sast-grader:MAJOR    (moving)
#   us-central1-docker.pkg.dev/turing-delivery-rl-gym/daytona/sast-grader:VERSION  (fixed)
#   sast-grader:MAJOR                                                             (local alias)
#
# Task tests/Dockerfiles say FROM <registry>/sast-grader:MAJOR. Harbor's docker build does
# not pass --pull, so the locally built registry tag satisfies that FROM without registry
# credentials. Push with grader_image/push.sh.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
REGISTRY_REPO="${REGISTRY_REPO:-us-central1-docker.pkg.dev/turing-delivery-rl-gym/daytona/sast-grader}"
LOCAL_REPO="${LOCAL_REPO:-sast-grader}"

VERSION="$(tr -d '[:space:]' < "$HERE/VERSION")"
MAJOR="${VERSION%%.*}"
MAJOR_MINOR="$(echo "$VERSION" | cut -d. -f1,2)"

# grade.py's GRADER_VERSION (e.g. v3.3) must agree with VERSION's major.minor.
GRADER_VERSION="$(sed -n 's/^GRADER_VERSION = "\(.*\)"$/\1/p' "$ROOT/task_format/grade.py")"
if [ "$GRADER_VERSION" != "v$MAJOR_MINOR" ]; then
  echo "build.sh: grade.py GRADER_VERSION=$GRADER_VERSION does not match VERSION=$VERSION" >&2
  exit 1
fi

# Stage a minimal build context: the Dockerfile, the wrapper, VERSION and grade.py.
CTX="$(mktemp -d)"
trap 'rm -rf "$CTX"' EXIT
cp "$HERE/Dockerfile" "$HERE/grade" "$HERE/VERSION" "$CTX/"
cp "$ROOT/task_format/grade.py" "$CTX/grade.py"

docker build \
  --platform linux/amd64 \
  --build-arg "GRADER_IMAGE=$REGISTRY_REPO:$MAJOR" \
  --build-arg "GRADER_IMAGE_VERSION=$VERSION" \
  -t "$REGISTRY_REPO:$MAJOR" \
  -t "$REGISTRY_REPO:$VERSION" \
  -t "$LOCAL_REPO:$MAJOR" \
  "$CTX"

# Smoke test: no network, a missing SARIF must grade 0 and carry the version stamp.
docker run --rm --network none --entrypoint sh "$REGISTRY_REPO:$MAJOR" -c '
  set -e
  printf "%s" "{\"schema_version\":\"gt-0.2\",\"variant_role\":\"positive\",\"matching\":{\"line_tolerance\":3,\"path_line_tolerance\":3},\"scoring_weights\":{\"detection\":1},\"findings\":[],\"negative_analyses\":[]}" > /tmp/truth.json
  /opt/grader/grade --sarif /tmp/none.sarif --truth /tmp/truth.json --out /tmp/out > /dev/null
  grep -q "\"grader_image_version\": \"'"$VERSION"'\"" /tmp/out/grading_detail.json
  grep -q "\"grader_version_major\": '"$MAJOR"'" /tmp/out/reward.json
' && echo "build.sh: smoke test ok"

echo "built $REGISTRY_REPO:$MAJOR, $REGISTRY_REPO:$VERSION and $LOCAL_REPO:$MAJOR"
docker image inspect "$REGISTRY_REPO:$MAJOR" --format 'image id {{.Id}}'
