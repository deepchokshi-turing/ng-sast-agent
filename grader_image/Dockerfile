# sast-grader: the task grader (task_format/grade.py) baked into a verifier base image.
# Task verifiers build FROM this image (tests/Dockerfile) and add only test.sh and the
# task's ground truth. Build with grader_image/build.sh, which stages grade.py next to
# this file; a plain `docker build` of this folder fails for lack of grade.py.
#
# Runtime needs no network and no packages beyond the standard library.

# python:3.12-slim pinned by digest (Python 3.12.15), the same base as the task images.
FROM python:3.12-slim@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1

ARG GRADER_IMAGE=us-central1-docker.pkg.dev/turing-delivery-rl-gym/daytona/sast-grader:3
ARG GRADER_IMAGE_VERSION=unknown

LABEL org.opencontainers.image.title="sast-grader" \
      org.opencontainers.image.description="SAST benchmark task grader (grade.py) for Harbor separate verifiers" \
      org.opencontainers.image.vendor="Turing" \
      org.opencontainers.image.version="${GRADER_IMAGE_VERSION}" \
      org.opencontainers.image.ref.name="${GRADER_IMAGE}"

ENV GRADER_IMAGE=${GRADER_IMAGE} \
    GRADER_IMAGE_VERSION=${GRADER_IMAGE_VERSION} \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

COPY grade.py grade VERSION /opt/grader/

# Read-only grader owned by root; a non-root user runs it. /logs/verifier and /app/output
# exist so the grader can write its output and Harbor can restore the SARIF artifact.
RUN groupadd --gid 10001 grader \
 && useradd --uid 10001 --gid grader --home-dir /home/grader --create-home --shell /usr/sbin/nologin grader \
 && chmod 0755 /opt/grader /opt/grader/grade \
 && chmod 0644 /opt/grader/grade.py /opt/grader/VERSION \
 && mkdir -p /tests /app/output /logs/verifier \
 && chown grader:grader /logs/verifier \
 && python3 /opt/grader/grade --help > /dev/null

WORKDIR /tests
USER grader
