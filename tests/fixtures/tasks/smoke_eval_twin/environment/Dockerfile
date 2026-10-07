# Scanner tools pre-installed from the sast-tools image (tools/build_tools_image.sh).
# On the platform, set the default to the registry path Daytona pulls from.
ARG SAST_TOOLS_IMAGE=sast-tools:0.3.0
FROM ${SAST_TOOLS_IMAGE} AS sast-tools

FROM python:3.11-slim
COPY --from=sast-tools /opt/sast /opt/sast

WORKDIR /app
COPY repo/ /app/repo/
RUN mkdir -p /app/output \
 && cd /app/repo && python -m unittest discover -s tests -q
