# Multi-stage Dockerfile for BlindVault Control Plane
FROM python:3.12-slim AS builder

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml .
COPY src/ src/
RUN pip install --no-cache-dir --upgrade pip && \
    pip wheel --no-cache-dir --wheel-dir /build/wheels .

# Final runtime image
FROM python:3.12-slim AS runner

WORKDIR /app

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    BLINDVAULT_HOST=0.0.0.0 \
    BLINDVAULT_PORT=8000 \
    BLINDVAULT_UDP_HOST=0.0.0.0 \
    BLINDVAULT_UDP_PORT=3478

# Install runtime utilities (curl for healthcheck)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create unprivileged service user
RUN groupadd -g 10001 blindvault && \
    useradd -u 10001 -g blindvault -s /bin/false -m blindvault

# Copy and install prebuilt wheels from builder stage
COPY --from=builder /build/wheels /wheels
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir /wheels/*.whl && \
    rm -rf /wheels

USER blindvault:blindvault

EXPOSE 8000/tcp
EXPOSE 3478/udp

HEALTHCHECK --interval=15s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/ready || exit 1

ENTRYPOINT ["blindvault-control"]
