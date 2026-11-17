# Scanner tools pre-installed from the sast-tools image (sast_agents/tools/build_tools_image.sh).
# Pulled from the project registry, pinned by digest. A literal FROM, not a build ARG:
# Daytona's builder fails on FROM ${ARG} (checked 2026-10-14). Local Docker needs registry
# access (gcloud auth configure-docker us-central1-docker.pkg.dev), or the local tag from
# `docker load -i ng-sast-agent/handoff/sast-tools_0.5.0_amd64.tar.gz` + `docker tag` (see
# ng-sast-agent/grader_image/README.md, "Local fallback").
FROM us-central1-docker.pkg.dev/turing-delivery-rl-gym/daytona/sast-tools:0.5.0@sha256:1cfbcb335b43f54999e6fe20c139737ca8bd88552a832130b1f39d9057999fef AS sast-tools

# mcr.microsoft.com/dotnet/sdk:8.0-bookworm-slim pinned by digest (SDK 8.0.427; digest resolved
# 2026-11-06 with docker buildx imagetools inspect). No NuGet package references: restore runs offline.
FROM mcr.microsoft.com/dotnet/sdk:8.0-bookworm-slim@sha256:341aa6e8bbaceb1194732328ca27c15bfa9c531687db83a66af3c0c1833f5534
COPY --from=sast-tools /opt/sast /opt/sast
# The scanner agents need python3 (any 3.6+) and glibc >= 2.34 in the task image; /opt/sast
# brings its own CPython for the tools themselves. TODO(builder): for a byte-reproducible image,
# pin apt to snapshot.debian.org (or drop this if the base already ships python3).
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 ca-certificates \
 && rm -rf /var/lib/apt/lists/*

ENV DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1 DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1

WORKDIR /app
COPY repo/ /app/repo/
# TODO(builder): keep this in sync with build_command and test_command in task.toml.
RUN mkdir -p /app/output \
 && cd /app/repo && @@BUILD_COMMAND@@ \
 && @@TEST_COMMAND@@
