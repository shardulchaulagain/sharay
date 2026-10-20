# SHARAY Production Multi-Stage Hardened Container Image
FROM python:3.13-slim AS base

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    iptables \
    nftables \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd -g 10001 sharay && \
    useradd -u 10001 -g sharay -s /bin/bash -m sharay

WORKDIR /app
COPY requirements.txt requirements-dev.txt pyproject.toml ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN chown -R sharay:sharay /app

USER sharay
EXPOSE 8000
HEALTHCHECK --interval=15s --timeout=3s --retries=3 \
    CMD curl -f http://localhost:8000/api/v1/overview || exit 1

ENTRYPOINT ["python", "-m", "aegis"]
CMD ["serve", "--port", "8000", "--host", "0.0.0.0"]
