# Scanner tools pre-installed from the sast-tools image (sast_agents/tools/build_tools_image.sh).
# Pulled from the project registry, pinned by digest. A literal FROM, not a build ARG:
# Daytona's builder fails on FROM ${ARG} (checked 2026-10-14). Local Docker needs registry
# access (gcloud auth configure-docker us-central1-docker.pkg.dev), or the local tag from
# `docker load -i ng-sast-agent/handoff/sast-tools_0.5.0_amd64.tar.gz` + `docker tag` (see
# ng-sast-agent/grader_image/README.md, "Local fallback").
FROM us-central1-docker.pkg.dev/turing-delivery-rl-gym/daytona/sast-tools:0.5.0@sha256:1cfbcb335b43f54999e6fe20c139737ca8bd88552a832130b1f39d9057999fef AS sast-tools

# node:24-bookworm-slim pinned by digest (Node.js 24.22.2; digest resolved 2026-11-06 with
# docker buildx imagetools inspect).
# @@RUNTIME_NOTE@@
FROM node:24-bookworm-slim@sha256:01d566e8d94d8c619591d78652babfccd3c6992a3dffa9ed5ab39e11cf6c70e9
COPY --from=sast-tools /opt/sast /opt/sast
# The scanner agents need python3 (any 3.6+) and glibc >= 2.34 in the task image; /opt/sast
# brings its own CPython for the tools themselves. The repro test (validation/repro_test.py) also
# runs on this python3. apt is not snapshot-pinned (snapshot.debian.org would make it reproducible).
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY repo/ /app/repo/
# Keep in sync with build_command and test_command in task.toml (the scaffold fills both from
# task_format/templates/v4/languages.json).
RUN mkdir -p /app/output \
 && cd /app/repo && @@BUILD_COMMAND@@ \
 && @@TEST_COMMAND@@

ENV NODE_ENV=production
