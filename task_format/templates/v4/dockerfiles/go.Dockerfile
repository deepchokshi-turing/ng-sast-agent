# Scanner tools pre-installed from the sast-tools image (sast_agents/tools/build_tools_image.sh).
# Pulled from the project registry, pinned by digest. A literal FROM, not a build ARG:
# Daytona's builder fails on FROM ${ARG} (checked 2026-10-14). Local Docker needs registry
# access (gcloud auth configure-docker us-central1-docker.pkg.dev), or the local tag from
# `docker load -i ng-sast-agent/handoff/sast-tools_0.5.0_amd64.tar.gz` + `docker tag` (see
# ng-sast-agent/grader_image/README.md, "Local fallback").
FROM us-central1-docker.pkg.dev/turing-delivery-rl-gym/daytona/sast-tools:0.5.0@sha256:1cfbcb335b43f54999e6fe20c139737ca8bd88552a832130b1f39d9057999fef AS sast-tools

# golang:1.25-bookworm pinned by digest (Go 1.25.14; digest resolved 2026-11-06 with
# docker buildx imagetools inspect). Modules must be vendored (go mod vendor): the build runs with GOPROXY=off.
FROM golang:1.25-bookworm@sha256:3b4a11519ad929d1e1d261a12cff056f0c85b735253d7d861346b9c6f8b36437
COPY --from=sast-tools /opt/sast /opt/sast
# The scanner agents need python3 (any 3.6+) and glibc >= 2.34 in the task image; /opt/sast
# brings its own CPython for the tools themselves. TODO(builder): for a byte-reproducible image,
# pin apt to snapshot.debian.org (or drop this if the base already ships python3).
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 ca-certificates \
 && rm -rf /var/lib/apt/lists/*

ENV GOPROXY=off GOTOOLCHAIN=local GOTELEMETRY=off CGO_ENABLED=0

WORKDIR /app
COPY repo/ /app/repo/
# TODO(builder): keep this in sync with build_command and test_command in task.toml.
RUN mkdir -p /app/output \
 && cd /app/repo && @@BUILD_COMMAND@@ \
 && @@TEST_COMMAND@@
