FROM python:3.11-slim

WORKDIR /app
COPY repo/ /app/repo/
RUN mkdir -p /app/output \
 && cd /app/repo && python -m compileall -q src \
 && python -m unittest discover -s tests -q

ENV PYTHONPATH=/app/repo/src
