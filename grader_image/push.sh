#!/usr/bin/env bash
# Push the sast-grader image built by build.sh to the project registry.
#
#   grader_image/build.sh && grader_image/push.sh
#
# Needs gcloud logged in with write access to the Artifact Registry repository. Pushes the
# fixed VERSION tag first, then moves the MAJOR tag to the same image, and prints the digest
# so it can be recorded (README.md, "Tag policy").
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REGISTRY_HOST="us-central1-docker.pkg.dev"
REGISTRY_REPO="${REGISTRY_REPO:-$REGISTRY_HOST/turing-delivery-rl-gym/daytona/sast-grader}"

VERSION="$(tr -d '[:space:]' < "$HERE/VERSION")"
MAJOR="${VERSION%%.*}"

for tag in "$MAJOR" "$VERSION"; do
  docker image inspect "$REGISTRY_REPO:$tag" > /dev/null \
    || { echo "push.sh: $REGISTRY_REPO:$tag not found locally; run build.sh first" >&2; exit 1; }
done

gcloud auth configure-docker "$REGISTRY_HOST" --quiet

docker push "$REGISTRY_REPO:$VERSION"
docker push "$REGISTRY_REPO:$MAJOR"

echo "pushed $REGISTRY_REPO:$VERSION and :$MAJOR"
docker image inspect "$REGISTRY_REPO:$MAJOR" --format '{{range .RepoDigests}}{{println .}}{{end}}'
