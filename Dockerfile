# ============================================================================
# Production Multi-Stage Dockerfile — Vendor Risk & Compliance Multi-Agent
# ============================================================================

FROM python:3.11-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /build

COPY requirements.txt .
RUN pip install --upgrade pip && \
    pip install --prefix=/install -r requirements.txt

FROM python:3.11-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8000 \
    HOST=0.0.0.0 \
    OTEL_ENABLED=true \
    OTEL_SERVICE_NAME=vendor-risk-compliance-multi-agent \
    SQLITE_DB_PATH=/var/lib/vendor-sessions/vendor_sessions.db

# Create non-root user and persistent data directory
RUN groupadd -g 10001 appgroup && \
    useradd -u 10001 -g appgroup -m -s /usr/sbin/nologin appuser && \
    mkdir -p /var/lib/vendor-sessions && \
    chown -R appuser:appgroup /var/lib/vendor-sessions

WORKDIR /app

COPY --from=builder /install /usr/local
COPY --chown=appuser:appgroup app ./app
COPY --chown=appuser:appgroup cli.py ./cli.py

USER appuser

EXPOSE 8000

HEALTHCHECK --interval=15s --timeout=5s --start-period=5s --retries=3 \
    CMD python3 -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/health')" || exit 1

CMD ["python3", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
