# SPDX-FileCopyrightText: 2025 system-under-test contributors
# SPDX-License-Identifier: Apache-2.0

# ============================================================================
# Builder Stage: Installs dependencies, including build-time tools.
# ============================================================================
FROM python:3.14.0rc3-slim-bookworm AS builder

# Install build tools required for some Python packages with C extensions.
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        g++ \
        make \
        libc6-dev && \
    rm -rf /var/lib/apt/lists/*

# Install pinned Python dependencies into the user's local directory.
RUN pip install --no-cache-dir --user \
    "opentelemetry-sdk==1.37.0" \
    "opentelemetry-exporter-otlp-proto-grpc==1.37.0" \
    "paho-mqtt==2.1.0"

# ============================================================================
# Final Stage: Creates the lightweight, secure production image.
# ============================================================================
FROM python:3.14.0rc3-slim-bookworm

# Create a non-root user to run the application.
RUN useradd --create-home --shell /bin/bash appuser

# Copy installed Python packages from the builder stage.
COPY --from=builder /root/.local /home/appuser/.local

# Ensure the appuser owns the installed packages.
RUN chown -R appuser:appuser /home/appuser/.local

# Switch to the non-root user.
USER appuser

# Set the working directory.
WORKDIR /home/appuser/app

# Add the local bin to the PATH for any executables from pip.
ENV PATH="/home/appuser/.local/bin:${PATH}"

# Copy application source code and set correct ownership.
COPY --chown=appuser:appuser src/ ./

# Define the entrypoint to run the application.
ENTRYPOINT ["python", "system-under-test/test_mqtt.py"]
