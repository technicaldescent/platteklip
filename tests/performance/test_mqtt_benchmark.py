# SPDX-FileCopyrightText: 2025 technical descent
# SPDX-License-Identifier: Apache-2.0

"""MQTT publish throughput benchmark.

This is a pytest-style test so it can be selected via
``-m performance``, emit JUnit XML, and use normal
assertion reporting.  It is environment-gated to avoid
failing when no broker is available.
"""

import asyncio
import os

import pytest

from platteklip.mqtt_load_harness import (
    LoadProfile,
    run_harness,
)
from platteklip.mqtt_producer import MQTTConnectionConfig

pytestmark = pytest.mark.performance


def test_mqtt_publish_throughput_smoke() -> None:
    """Gate on PERF_MQTT_HOST; skip when unset."""
    host = os.getenv("PERF_MQTT_HOST")
    if not host:
        pytest.skip(
            "Set PERF_MQTT_HOST to enable" " throughput benchmarks",
        )

    port = int(os.getenv("PERF_MQTT_PORT", "1883"))
    use_tls = os.getenv(
        "PERF_MQTT_USE_TLS",
        "false",
    ).strip().lower() in {"1", "true", "yes", "on"}

    connection = MQTTConnectionConfig(
        host=host,
        port=port,
        use_tls=use_tls,
        ca_file=os.getenv(
            "PERF_MQTT_CA_FILE",
            "/run/secrets/ca.crt",
        ),
        cert_file=os.getenv(
            "PERF_MQTT_CERT_FILE",
            "/run/secrets/tls_certificate.crt",
        ),
        key_file=os.getenv(
            "PERF_MQTT_KEY_FILE",
            "/run/secrets/tls_private_key.key",
        ),
        tls_check_hostname=os.getenv(
            "PERF_MQTT_TLS_CHECK_HOSTNAME",
            "true",
        )
        .strip()
        .lower()
        in {"1", "true", "yes", "on"},
        connect_timeout_seconds=float(
            os.getenv(
                "PERF_MQTT_CONNECT_TIMEOUT",
                "10",
            ),
        ),
    )

    profile = LoadProfile(
        client_count=int(
            os.getenv("PERF_CLIENT_COUNT", "1"),
        ),
        duration_seconds=float(
            os.getenv("PERF_DURATION_SECONDS", "5"),
        ),
        messages_per_second_per_client=float(
            os.getenv("PERF_MPS_PER_CLIENT", "50"),
        ),
        qos=int(os.getenv("PERF_QOS", "1")),
        topic_prefix=os.getenv(
            "PERF_TOPIC_PREFIX",
            "perf/test",
        ),
        message_size_bytes=int(
            os.getenv(
                "PERF_MESSAGE_SIZE_BYTES",
                "128",
            ),
        ),
        log_interval_seconds=0.0,
    )

    result = asyncio.run(
        run_harness(connection, profile),
    )

    expected_min = int(
        profile.client_count
        * profile.messages_per_second_per_client
        * profile.duration_seconds
        * 0.5
    )
    assert result.total_published_accepted >= expected_min, (
        f"Throughput below threshold:"
        f" accepted="
        f"{result.total_published_accepted}"
        f" expected_min={expected_min}"
        f" failures="
        f"{result.total_publish_failures}"
    )
    assert result.total_publish_failures == 0, (
        f"Publish failures:" f" {result.total_publish_failures}"
    )
