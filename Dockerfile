# ============================================================
#  NetGuard IDS — Multi-stage Dockerfile
#  Stage 1 (builder) : install Python deps into a venv
#  Stage 2 (runtime) : slim image; copies venv + source
# ============================================================

# ---- builder stage ----
FROM python:3.11-slim AS builder

WORKDIR /build

# System deps needed at install time (e.g. npcap headers on Linux are skipped)
RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc \
        libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt pyproject.toml ./

# Install all Python deps into a virtual environment
RUN python -m venv /opt/venv && \
    /opt/venv/bin/pip install --upgrade pip && \
    /opt/venv/bin/pip install \
        fastapi>=0.100.0 \
        "uvicorn[standard]>=0.23.0" \
        pydantic>=2.0.0 \
        websockets>=11.0.0 \
        psutil>=5.9 \
        pyyaml>=6.0 \
        python-dotenv>=1.0 \
        requests>=2.28 \
        schedule>=1.2 \
        scikit-learn>=1.3 \
        joblib>=1.3 \
        numpy>=1.24 \
        rich>=13.0 \
        typer>=0.9.0 \
    && /opt/venv/bin/pip install --no-deps . 2>/dev/null || true

# ---- runtime stage ----
FROM python:3.11-slim AS runtime

LABEL org.opencontainers.image.title="NetGuard IDS"
LABEL org.opencontainers.image.description="Firewall & Intrusion Detection System (headless)"
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.source="https://github.com/Armanrbu/Firewall-Configuration-and-Basic-Intrusion-Detection-System"

# Non-root user for security
RUN groupadd -r netguard && useradd -r -g netguard netguard

WORKDIR /app

# Copy venv from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
ENV PYTHONPATH="/app"
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Copy source (no GUI deps needed in headless container)
COPY --chown=netguard:netguard . /app/

# Ensure data dirs exist and are writable
RUN mkdir -p /app/data /app/logs && \
    chown -R netguard:netguard /app/data /app/logs

USER netguard

# Health check: the API server exposes /status
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5000/status').read()" \
    || exit 1

# Expose the FastAPI port
EXPOSE 5000

# Default: run headless engine + REST API
CMD ["python", "main.py", "--headless"]
