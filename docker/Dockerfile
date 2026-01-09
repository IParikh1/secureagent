# SecureAgent - AI & Cloud Security Platform
# Multi-stage Dockerfile for optimized builds

# Stage 1: Build stage
FROM python:3.11-slim as builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    git \
    && rm -rf /var/lib/apt/lists/*

# Copy project files
COPY pyproject.toml README.md ./
COPY src/ ./src/

# Install poetry and build wheel
RUN pip install --no-cache-dir poetry && \
    poetry config virtualenvs.create false && \
    poetry build -f wheel

# Stage 2: Runtime stage
FROM python:3.11-slim as runtime

LABEL maintainer="SecureAgent Team"
LABEL description="AI & Cloud Security Platform"
LABEL version="1.0.2"

WORKDIR /app

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -u 1000 secureagent

# Copy wheel from builder
COPY --from=builder /app/dist/*.whl /tmp/

# Install SecureAgent with pinned Typer/Click versions to avoid CLI compatibility issues
RUN pip install --no-cache-dir 'typer>=0.9.0,<0.12.0' 'click>=8.0.0,<8.2.0' && \
    pip install --no-cache-dir /tmp/*.whl && \
    rm /tmp/*.whl

# Switch to non-root user
USER secureagent

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV SECUREAGENT_CONFIG_DIR=/app/config

# Default entrypoint
ENTRYPOINT ["secureagent"]
CMD ["--help"]

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD secureagent --version || exit 1

# ---
# Build instructions:
#   docker build -t secureagent:latest -f docker/Dockerfile .
#
# Run examples:
#   docker run --rm secureagent scan /path/to/config
#   docker run --rm -v $(pwd):/workspace secureagent scan /workspace
#   docker run --rm -e AWS_ACCESS_KEY_ID -e AWS_SECRET_ACCESS_KEY secureagent cloud scan --provider aws
# ---
