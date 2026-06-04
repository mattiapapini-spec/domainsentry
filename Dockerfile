FROM python:3.12-slim

LABEL maintainer="Domain Intelligence Project"
LABEL version="4.0.0"
LABEL description="Domain Intelligence Platform — Microservices"

ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app

# Sistema
RUN apt-get update && apt-get install -y --no-install-recommends \
    dnsutils \
    whois \
    ca-certificates \
    curl \
    gcc \
    g++ \
    libfuzzy-dev \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Python packages
COPY requirements.txt /tmp/
RUN pip install --no-cache-dir -r /tmp/requirements.txt

# Non-root user
RUN useradd -m -s /bin/bash -u 1000 sentry

# Codice
WORKDIR /app
COPY shared/ /app/shared/
COPY services/ /app/services/
COPY run_service.py /app/
COPY unified.py /app/

# Data directory con permessi per non-root
RUN mkdir -p /data/feed/whitelists /data/events /data/baselines && \
    chown -R sentry:sentry /data /app

USER sentry

# Health check generico (ogni servizio risponde su /health)
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -sf http://localhost:${SERVICE_PORT:-8000}/health || exit 1

ENTRYPOINT ["python3", "run_service.py"]
