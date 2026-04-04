# SPDX-FileCopyrightText: 2025 technical descent
# SPDX-License-Identifier: Apache-2.0
# -----------------------------------------------------------
# Multi-stage build on Debian slim.  Debian provides
# manylinux-compatible wheels when available and faster
# compilation from source when not (glibc vs musl).
#
# The build context is the project root.  A .dockerignore
# file restricts what is sent to the daemon (only
# pyproject.toml and src/platteklip/).
# -----------------------------------------------------------

# ============================================================
# Stage 1: Builder
# ============================================================
FROM python:3.15.0a7-slim-bookworm AS builder

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
    build-essential \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY pyproject.toml ./
COPY src/platteklip/ ./src/platteklip/

RUN pip install --no-cache-dir --no-compile \
      --disable-pip-version-check \
      --prefix=/install \
      ".[observability]"

# ============================================================
# Stage 2: Runtime
# ============================================================
FROM python:3.15.0a7-slim-bookworm AS base

# ---- OS hardening -----------------------------------------
# Strip SUID/SGID bits from all binaries (CIS Docker 4.8).
RUN set -eu; \
    paths=""; \
    for p in \
      /bin /sbin /usr/bin /usr/sbin \
      /usr/local/bin /usr/local/sbin; \
    do \
      [ -d "$p" ] && paths="$paths $p"; \
    done; \
    [ -n "$paths" ]; \
    find $paths -xdev -type f -perm /6000 \
      -print -exec chmod a-s {} +; \
    test -z "$( \
      find $paths -xdev -type f -perm /6000 -print \
    )"

# ---- Non-root user ----------------------------------------
RUN useradd -r -m -u 1000 \
      -d /home/appuser -s /usr/sbin/nologin appuser \
 && mkdir -p /home/appuser/app \
 && chown -R appuser:appuser /home/appuser

# ---- Copy installed packages from builder -----------------
COPY --from=builder /install /usr/local

# ---- Application code -------------------------------------
WORKDIR /home/appuser/app
COPY --chown=appuser:appuser pyproject.toml ./
COPY --chown=appuser:appuser \
  src/platteklip/ ./src/platteklip/

# Install the package itself (deps already present)
RUN pip install --no-cache-dir --no-compile \
      --disable-pip-version-check \
      --no-deps \
      "." \
 && pip cache purge 2>/dev/null || true

# ---- Runtime ----------------------------------------------
USER appuser

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH="/home/appuser/app/src"

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD ["python", "-c", \
    "from platteklip.health import is_healthy; \
     raise SystemExit(0 if is_healthy() else 1)"]

ENTRYPOINT ["python", "-m", "platteklip.mqtt_producer"]
