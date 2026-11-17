# Scanner tools pre-installed from the sast-tools image (sast_agents/tools/build_tools_image.sh).
# Pulled from the project registry, pinned by digest. A literal FROM, not a build ARG:
# Daytona's builder fails on FROM ${ARG} (checked 2026-10-14). Local Docker needs registry
# access (gcloud auth configure-docker us-central1-docker.pkg.dev), or the local tag from
# `docker load -i ng-sast-agent/handoff/sast-tools_0.5.0_amd64.tar.gz` + `docker tag` (see
# ng-sast-agent/grader_image/README.md, "Local fallback").
FROM us-central1-docker.pkg.dev/turing-delivery-rl-gym/daytona/sast-tools:0.5.0@sha256:1cfbcb335b43f54999e6fe20c139737ca8bd88552a832130b1f39d9057999fef AS sast-tools

# python:3.12-slim pinned by digest (Python 3.12.15), the same base as the pilot tasks.
FROM python:3.12-slim@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1
COPY --from=sast-tools /opt/sast /opt/sast

WORKDIR /app
COPY repo/ /app/repo/
# TODO(builder): keep this in sync with build_command and test_command in task.toml.
RUN mkdir -p /app/output \
 && cd /app/repo && @@BUILD_COMMAND@@ \
 && @@TEST_COMMAND@@

ENV PYTHONPATH=/app/repo/src
