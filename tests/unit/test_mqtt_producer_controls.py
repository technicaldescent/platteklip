# SPDX-FileCopyrightText: 2025 technical descent
# SPDX-License-Identifier: Apache-2.0

"""Pytest tests annotated with control markers.

Each ``@pytest.mark.control`` links the test to one or
more Gemara Layer 2 assessment requirement IDs.  The
conftest fixture injects these as JUnit XML properties
for evidence collection.
"""

import ssl
from typing import Any

import pytest

from platteklip.mqtt_producer import (
    MQTTConnectionConfig,
)


@pytest.mark.control("PK-DC-01.02")
class TestMQTTTLSVersion:
    """MQTTConnectionConfig constrains TLS to 1.3."""

    def test_min_version_is_tls_1_3(self) -> None:
        """Enforce TLS 1.3 as the minimum version."""
        config = MQTTConnectionConfig()
        assert config.tls_min_version == ssl.TLSVersion.TLSv1_3

    def test_max_version_is_tls_1_3(self) -> None:
        """Enforce TLS 1.3 as the maximum version."""
        config = MQTTConnectionConfig()
        assert config.tls_max_version == ssl.TLSVersion.TLSv1_3


@pytest.mark.control("PK-IA-01.01")
def test_default_cert_paths_are_secrets() -> None:
    """Default certificate paths use /run/secrets/."""
    config = MQTTConnectionConfig()
    assert config.ca_file.startswith(
        "/run/secrets/",
    )
    assert config.cert_file.startswith(
        "/run/secrets/",
    )


@pytest.mark.control("PK-IA-01.01", "PK-DC-01.02")
def test_tls_enabled_by_default() -> None:
    """Enable TLS by default."""
    config = MQTTConnectionConfig()
    assert config.use_tls is True


@pytest.mark.control("PK-RA-02.01")
def test_memory_limiter_first_in_pipeline(
    otel_collector_config: dict[str, Any],
) -> None:
    """Place memory_limiter first in every pipeline."""
    service: dict[str, Any] = otel_collector_config.get("service", {})
    pipelines: dict[str, Any] = service.get(
        "pipelines",
        {},
    )
    for name, pipe in pipelines.items():
        procs: list[str] = pipe.get(
            "processors",
            [],
        )
        assert procs, f"Pipeline {name} has no processors"
        assert "memory_limiter" in procs[0], (
            f"Pipeline {name}: first processor"
            f" is {procs[0]},"
            f" expected memory_limiter"
        )
