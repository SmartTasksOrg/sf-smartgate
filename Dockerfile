# SmartGate server image, built from this repository (nothing is downloaded from PyPI except the
# optional redis client). Pin the base image by digest for production:
#   docker buildx imagetools inspect python:3.12-slim   -> use python:3.12-slim@sha256:<digest>
FROM python:3.12-slim

RUN useradd --create-home --uid 10001 smartgate && mkdir -p /data && chown smartgate /data
WORKDIR /src
COPY pyproject.toml README.md LICENSE NOTICE ./
COPY src ./src
RUN python -m pip install --no-cache-dir ".[redis]" && rm -rf /src

USER smartgate
WORKDIR /data
EXPOSE 8711
# Tokens come from the environment (SMARTGATE_AGENT_TOKEN, SMARTGATE_OPERATOR_TOKEN); the server
# refuses to start without them.
HEALTHCHECK --interval=10s --timeout=2s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8711/healthz', timeout=2)"
ENTRYPOINT ["sf-smartgate", "serve", "--host", "0.0.0.0", "--port", "8711", "--audit", "/data/audit.jsonl"]
