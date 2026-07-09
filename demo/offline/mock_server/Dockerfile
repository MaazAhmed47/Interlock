# Mock MCP server for the offline Interlock demo. Stdlib only — the image is
# just Python plus one file, and never talks to anything outside the compose
# network.
FROM python:3.12-slim

RUN groupadd -r mock && useradd -r -g mock -u 1000 mock
WORKDIR /app
COPY server.py .
USER mock

EXPOSE 9100
HEALTHCHECK --interval=10s --timeout=3s --start-period=3s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:9100/health', timeout=2)"

CMD ["python", "server.py"]
