# SPDX-FileCopyrightText: 2025 technical descent
# SPDX-License-Identifier: Apache-2.0

"""MQTT load harness for benchmarking and soak testing.

Composes :class:`~platteklip.mqtt_producer.MQTTProducer`
instances to generate sustained load at a configurable
rate.  The harness uses a token-bucket pacer per client
and collects per-client publish counters.

The ``__main__`` block provides an environment-variable-
driven entry point suitable for container deployments.

Configuration
-------------
:class:`LoadProfile` is the single source of truth for
all test defaults.  The container entry point reads
environment variables and only overrides fields that
are explicitly set.

The precedence chain is::

    LoadProfile dataclass default
      <- overridden by environment variable (if set)
        <- overridden by compose .env

Testability
-----------
The module exposes :data:`_monotonic` and :data:`_sleep`
as module-level indirections so that tests can replace
them without patching :func:`time.monotonic` (which
would disrupt the asyncio event loop itself).

Policy
------
QoS **must** be 1 or 2.  QoS 0 is rejected at
validation time.
"""

import asyncio
import json
import logging
import os
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any, Final

from platteklip.mqtt_producer import (
    MQTTConnectionConfig,
    MQTTProducer,
    MQTTProducerStats,
)

logger: Final[logging.Logger] = logging.getLogger(
    __name__,
)

# Local indirections for testability.  Do NOT patch
# time.monotonic or asyncio.sleep globally — doing so
# destabilises the event loop.
_monotonic: Callable[[], float] = time.monotonic
_sleep: Callable[[float], Awaitable[None]] = asyncio.sleep


# ------------------------------------------------------------------
# Configuration and result data classes
# ------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class LoadProfile:
    """Parameters that define the load pattern.

    Parameters
    ----------
    client_count
        Number of concurrent producer clients.
    duration_seconds
        Total harness run time.
    messages_per_second_per_client
        Target publish rate per client.
    qos
        MQTT QoS level (1 or 2 only).
    topic_prefix
        Base topic; each client appends its ID.
    message_size_bytes
        Target MQTT application payload size.
    burst_cap_seconds
        Maximum token-bucket depth expressed as
        seconds of burst capacity.
    log_interval_seconds
        Interval between per-client progress logs.
    stagger_every
        Insert a delay after launching this many
        clients.
    stagger_delay_seconds
        Duration of the stagger pause.
    """

    client_count: int = 1
    duration_seconds: float = 1800.0
    messages_per_second_per_client: float = 2.0
    qos: int = 2
    topic_prefix: str = "scada/telemetry/stress"
    message_size_bytes: int = 1024
    burst_cap_seconds: float = 2.0
    log_interval_seconds: float = 5.0
    stagger_every: int = 5
    stagger_delay_seconds: float = 0.05


@dataclass(frozen=True, slots=True)
class LoadResult:
    """Aggregated results from a harness run.

    Parameters
    ----------
    started_monotonic
        Monotonic timestamp when the run began.
    finished_monotonic
        Monotonic timestamp when the run completed.
    total_published_accepted
        Sum of accepted publishes across all clients.
    total_publish_failures
        Sum of failed publishes across all clients.
    total_queue_full
        Sum of queue-full rejections across all clients.
    per_client
        Per-client stats keyed by client identifier.
    """

    started_monotonic: float
    finished_monotonic: float
    total_published_accepted: int
    total_publish_failures: int
    total_queue_full: int
    per_client: dict[str, MQTTProducerStats]


# ------------------------------------------------------------------
# Producer factory
# ------------------------------------------------------------------

ProducerFactory = Callable[[MQTTConnectionConfig, str], MQTTProducer]


def _build_producer(
    config: MQTTConnectionConfig,
    client_id: str,
) -> MQTTProducer:
    """Create a producer with default settings."""
    return MQTTProducer(config, client_id=client_id)


# ------------------------------------------------------------------
# Payload builder
# ------------------------------------------------------------------

_PAYLOAD_SEPARATORS: Final[tuple[str, str]] = (
    ",",
    ":",
)


def _build_payload(
    client_id: str,
    message_size_bytes: int,
) -> bytes:
    """Build a deterministic JSON payload of exact size.

    The size target covers the MQTT application payload
    only, excluding protocol framing.

    Parameters
    ----------
    client_id
        Identifier embedded in the JSON body.
    message_size_bytes
        Exact byte length of the returned payload.

    Raises
    ------
    ValueError
        If *message_size_bytes* is too small to contain
        the minimum JSON envelope, or if the constructed
        payload does not match the requested size.
    """
    base_obj: dict[str, str] = {
        "id": client_id,
        "ts": "",
        "data": "",
    }
    base_bytes = json.dumps(
        base_obj,
        separators=_PAYLOAD_SEPARATORS,
        ensure_ascii=False,
    ).encode("utf-8")

    if message_size_bytes < len(base_bytes):
        raise ValueError(
            f"message_size_bytes="
            f"{message_size_bytes}"
            f" is too small; minimum is"
            f" {len(base_bytes)}.",
        )

    pad_len = message_size_bytes - len(base_bytes)
    base_obj["data"] = "x" * pad_len

    payload = json.dumps(
        base_obj,
        separators=_PAYLOAD_SEPARATORS,
        ensure_ascii=False,
    ).encode("utf-8")

    if len(payload) != message_size_bytes:
        raise ValueError(
            f"Payload sizing invariant failed:"
            f" got {len(payload)} bytes,"
            f" expected {message_size_bytes}.",
        )

    return payload


# ------------------------------------------------------------------
# Profile validation
# ------------------------------------------------------------------

_FIELD_BOUNDS: Final[list[tuple[str, Callable[[LoadProfile], bool], str]]] = [
    (
        "client_count",
        lambda p: p.client_count >= 1,
        "must be >= 1",
    ),
    (
        "duration_seconds",
        lambda p: p.duration_seconds >= 0.0,
        "must be >= 0",
    ),
    (
        "messages_per_second_per_client",
        lambda p: p.messages_per_second_per_client >= 0.0,
        "must be >= 0",
    ),
    (
        "qos",
        lambda p: p.qos in (1, 2),
        "must be 1 or 2 (policy)",
    ),
    (
        "message_size_bytes",
        lambda p: p.message_size_bytes >= 1,
        "must be >= 1",
    ),
    (
        "burst_cap_seconds",
        lambda p: p.burst_cap_seconds >= 0.0,
        "must be >= 0",
    ),
    (
        "log_interval_seconds",
        lambda p: p.log_interval_seconds >= 0.0,
        "must be >= 0",
    ),
]


def _check_bounds(lp: LoadProfile) -> None:
    """Check that every field in *lp* is within bounds.

    Raises
    ------
    ValueError
        On the first out-of-range field.
    """
    for field, predicate, msg in _FIELD_BOUNDS:
        if not predicate(lp):
            raise ValueError(f"{field} {msg}.")


# ------------------------------------------------------------------
# Token-bucket burst helper
# ------------------------------------------------------------------


async def _drain_tokens(
    *,
    producer: MQTTProducer,
    tokens: float,
    topic: str,
    payload: bytes,
    qos: int,
    stop_event: asyncio.Event,
) -> tuple[float, int]:
    """Publish messages until tokens are exhausted.

    Returns
    -------
    tuple[float, int]
        Remaining tokens and number of messages sent.
    """
    sent = 0
    while tokens >= 1.0 and not stop_event.is_set() and producer.is_connected:
        accepted = producer.publish(
            topic,
            payload,
            qos=qos,
        )
        tokens -= 1.0
        sent += 1

        if not accepted:
            await _sleep(0.002)
            break

        if sent % 200 == 0:
            await _sleep(0)

    return tokens, sent


# ------------------------------------------------------------------
# Per-client coroutine
# ------------------------------------------------------------------


async def _client_task(
    *,
    index: int,
    connection: MQTTConnectionConfig,
    profile: LoadProfile,
    factory: ProducerFactory,
    client_id_prefix: str,
    stop_event: asyncio.Event,
    end_t: float,
    per_client_stats: dict[str, MQTTProducerStats],
    log: logging.Logger,
) -> None:
    """Run a single producer for the load test duration.

    Connects, publishes at the configured rate using a
    token-bucket pacer, and records stats on teardown.

    Parameters
    ----------
    index
        Zero-based client index.
    connection
        Broker connection configuration.
    profile
        Load profile governing rate and payload.
    factory
        Callable that creates a producer instance.
    client_id_prefix
        Prefix for the generated client identifier.
    stop_event
        Cooperative cancellation signal.
    end_t
        Monotonic deadline for the run.
    per_client_stats
        Shared dict to deposit stats into on teardown.
    log
        Logger instance.
    """
    client_id = f"{client_id_prefix}_{index:04d}"
    producer = factory(connection, client_id)

    payload = _build_payload(
        client_id,
        profile.message_size_bytes,
    )
    topic = f"{profile.topic_prefix.rstrip('/')}" f"/{client_id}/data"

    log_ctx: dict[str, str | int] = {
        "messaging.client.id": client_id,
        "messaging.destination.name": topic,
    }

    await producer.connect()

    tokens = 0.0
    last_t = _monotonic()
    last_log_t = last_t

    try:
        while _monotonic() < end_t and not stop_event.is_set():
            now = _monotonic()

            if not producer.is_connected:
                await _sleep(0.25)
                last_t = _monotonic()
                continue

            rate = float(
                profile.messages_per_second_per_client,
            )
            if rate <= 0.0:
                await _sleep(0.5)
                continue

            dt = max(0.0, now - last_t)
            last_t = now

            cap = rate * float(
                profile.burst_cap_seconds,
            )
            tokens = min(
                tokens + rate * dt,
                max(0.0, cap),
            )

            tokens, _sent = await _drain_tokens(
                producer=producer,
                tokens=tokens,
                topic=topic,
                payload=payload,
                qos=profile.qos,
                stop_event=stop_event,
            )

            _maybe_log_progress(
                producer=producer,
                now=now,
                last_log_t=last_log_t,
                interval=profile.log_interval_seconds,
                log=log,
                log_ctx=log_ctx,
            )
            if (
                profile.log_interval_seconds > 0.0
                and (now - last_log_t) >= profile.log_interval_seconds
            ):
                last_log_t = now

            await _sleep(0.001)
    finally:
        producer.stop()
        per_client_stats[producer.client_id] = producer.stats


def _maybe_log_progress(
    *,
    producer: MQTTProducer,
    now: float,
    last_log_t: float,
    interval: float,
    log: logging.Logger,
    log_ctx: dict[str, str | int],
) -> None:
    """Emit a progress log line if the interval has elapsed."""
    if interval <= 0.0:
        return
    if (now - last_log_t) < interval:
        return
    s = producer.stats
    log.info(
        "ok=%d fail=%d qfull=%d",
        s.published_accepted,
        s.publish_failures,
        s.queue_full,
        extra={
            **log_ctx,
            "published_accepted": s.published_accepted,
            "publish_failures": s.publish_failures,
            "queue_full": s.queue_full,
        },
    )


# ------------------------------------------------------------------
# Result aggregation
# ------------------------------------------------------------------


def _aggregate_results(
    started: float,
    finished: float,
    per_client: dict[str, MQTTProducerStats],
) -> LoadResult:
    """Build a LoadResult from per-client stats."""
    return LoadResult(
        started_monotonic=started,
        finished_monotonic=finished,
        total_published_accepted=sum(s.published_accepted for s in per_client.values()),
        total_publish_failures=sum(s.publish_failures for s in per_client.values()),
        total_queue_full=sum(s.queue_full for s in per_client.values()),
        per_client=per_client,
    )


# ------------------------------------------------------------------
# Orchestrator
# ------------------------------------------------------------------


async def run_harness(
    connection: MQTTConnectionConfig,
    profile: LoadProfile,
    *,
    producer_factory: ProducerFactory | None = None,
    client_id_prefix: str = "client",
    stop_event: asyncio.Event | None = None,
    log: logging.Logger | None = None,
) -> LoadResult:
    """Execute a load profile and return aggregated metrics.

    Creates *profile.client_count* producers, connects
    them with optional staggering, and publishes at the
    configured rate until the duration elapses or
    *stop_event* is set.

    Parameters
    ----------
    connection
        Broker connection configuration.
    profile
        Load shaping parameters.
    producer_factory
        Override the default producer constructor
        (useful for injecting test doubles).
    client_id_prefix
        Prefix for generated client identifiers.
    stop_event
        Cooperative cancellation signal.
    log
        Override the module-level logger.

    Raises
    ------
    ValueError
        If *profile* contains out-of-range values.
    """
    _check_bounds(profile)

    _log = log or logger
    factory = producer_factory or _build_producer
    stop = stop_event or asyncio.Event()

    per_client_stats: dict[str, MQTTProducerStats] = {}
    producers: list[MQTTProducer] = []

    started = _monotonic()
    end_t = started + float(
        profile.duration_seconds,
    )

    def _tracking_factory(
        cfg: MQTTConnectionConfig,
        cid: str,
    ) -> MQTTProducer:
        """Create and register a producer."""
        producer = factory(cfg, cid)
        producers.append(producer)
        return producer

    try:
        async with asyncio.TaskGroup() as tg:
            for i in range(profile.client_count):
                tg.create_task(
                    _client_task(
                        index=i,
                        connection=connection,
                        profile=profile,
                        factory=_tracking_factory,
                        client_id_prefix=(client_id_prefix),
                        stop_event=stop,
                        end_t=end_t,
                        per_client_stats=(per_client_stats),
                        log=_log,
                    ),
                    name=(f"{client_id_prefix}" f"_{i:04d}"),
                )

                if _is_stagger_due(
                    i,
                    profile.stagger_every,
                ):
                    await _sleep(
                        profile.stagger_delay_seconds,
                    )
    except asyncio.CancelledError:
        stop.set()
        raise
    finally:
        for p in producers:
            p.stop()

    return _aggregate_results(
        started,
        _monotonic(),
        per_client_stats,
    )


def _is_stagger_due(
    index: int,
    stagger_every: int,
) -> bool:
    """Return True if a stagger pause is due."""
    return stagger_every > 0 and index > 0 and index % stagger_every == 0


# ------------------------------------------------------------------
# Environment -> LoadProfile mapping
# ------------------------------------------------------------------

_PROFILE_ENV_MAP: Final[dict[str, tuple[str, Callable[[str], Any]]]] = {
    "TEST_TYPE": (
        "topic_prefix",
        lambda v: f"scada/telemetry/{v.lower()}",
    ),
    "STRESS_CLIENT_COUNT": ("client_count", int),
    "LOAD_CLIENT_COUNT": ("client_count", int),
    "TEST_DURATION_MINUTES": (
        "duration_seconds",
        lambda v: float(v) * 60,
    ),
    "SOAK_DURATION_HOURS": (
        "duration_seconds",
        lambda v: float(v) * 3600,
    ),
    "MESSAGES_PER_SECOND": (
        "messages_per_second_per_client",
        float,
    ),
    "SOAK_MESSAGE_RATE": (
        "messages_per_second_per_client",
        float,
    ),
    "QOS_LEVEL": ("qos", int),
}


def _profile_from_env() -> LoadProfile:
    """Build a LoadProfile from environment variables.

    Starts with the dataclass defaults and overrides
    only the fields for which an environment variable
    is explicitly set.

    Returns
    -------
    LoadProfile
        Profile with defaults overridden by env vars.

    Raises
    ------
    SystemExit
        If an env var is set but cannot be parsed.
    """
    test_type = os.getenv(
        "TEST_TYPE",
        "stress",
    ).lower()

    active_vars = _active_env_vars(test_type)
    overrides: dict[str, Any] = {}

    for env_name in active_vars:
        raw = os.getenv(env_name)
        if raw is None:
            continue
        field_name, parser = _PROFILE_ENV_MAP[env_name]
        try:
            overrides[field_name] = parser(raw)
        except (ValueError, TypeError) as exc:
            raise SystemExit(
                f"Invalid value for" f" {env_name}={raw!r}: {exc}",
            ) from exc

    return LoadProfile(**overrides)


def _active_env_vars(
    test_type: str,
) -> set[str]:
    """Return the env var names for the given test type."""
    common = {"TEST_TYPE", "QOS_LEVEL"}
    if test_type == "soak":
        return common | {
            "LOAD_CLIENT_COUNT",
            "SOAK_DURATION_HOURS",
            "SOAK_MESSAGE_RATE",
        }
    return common | {
        "STRESS_CLIENT_COUNT",
        "TEST_DURATION_MINUTES",
        "MESSAGES_PER_SECOND",
    }


# ------------------------------------------------------------------
# Container entry point
# ------------------------------------------------------------------


async def _entry_main() -> None:
    """Run the harness from environment variables.

    Reads test type, broker coordinates, and load
    parameters from the process environment, then runs
    a single harness invocation.
    """
    from platteklip.instrumentation.setup import (  # noqa: PLC0415
        configure_telemetry,
        shutdown_telemetry,
    )

    configure_telemetry()

    test_type = os.getenv(
        "TEST_TYPE",
        "stress",
    ).lower()

    connection_config = MQTTConnectionConfig(
        host=os.getenv(
            "MQTT_HOST",
            "mqtt-broker",
        ),
        port=int(
            os.getenv("MQTT_PORT", "8883"),
        ),
        use_tls=(
            os.getenv(
                "MQTT_USE_TLS",
                "true",
            ).lower()
            == "true"
        ),
        ca_file=os.getenv(
            "MQTT_CA_FILE",
            "/run/secrets/ca.crt",
        ),
        cert_file=os.getenv(
            "MQTT_CERT_FILE",
            "/run/secrets/tls_certificate.crt",
        ),
        key_file=os.getenv(
            "MQTT_KEY_FILE",
            "/run/secrets/tls_private_key.key",
        ),
        tls_check_hostname=(
            os.getenv(
                "MQTT_TLS_CHECK_HOSTNAME",
                "true",
            ).lower()
            == "true"
        ),
    )

    harness_profile = _profile_from_env()

    harness_ctx: dict[str, str | int | float] = {
        "test.type": test_type,
        "test.client_count": harness_profile.client_count,
        "test.rate_per_client": harness_profile.messages_per_second_per_client,
        "test.duration_seconds": harness_profile.duration_seconds,
        "server.address": connection_config.host,
        "server.port": connection_config.port,
    }

    logger.info(
        "Running %s test: %d clients," " %.1f msg/s/client, %.0fs",
        test_type.upper(),
        harness_profile.client_count,
        harness_profile.messages_per_second_per_client,
        harness_profile.duration_seconds,
        extra=harness_ctx,
    )

    try:
        result = await run_harness(
            connection=connection_config,
            profile=harness_profile,
            client_id_prefix=(f"scada_{test_type}"),
        )
        logger.info(
            "Complete: accepted=%d failures=%d" " queue_full=%d",
            result.total_published_accepted,
            result.total_publish_failures,
            result.total_queue_full,
            extra={
                **harness_ctx,
                "total_published_accepted": result.total_published_accepted,
                "total_publish_failures": result.total_publish_failures,
                "total_queue_full": result.total_queue_full,
            },
        )
    except asyncio.CancelledError:
        logger.warning(
            "Test cancelled.",
            extra=harness_ctx,
        )
    except (ValueError, OSError) as exc:
        logger.error(
            "Test failed: %s",
            exc,
            extra=harness_ctx,
            exc_info=True,
        )
    finally:
        shutdown_telemetry()


if __name__ == "__main__":
    import sys

    logging.basicConfig(
        level=logging.INFO,
        format=(
            "%(asctime)s [%(levelname)s]"
            " %(name)s"
            " [trace=%(otelTraceID)s"
            " span=%(otelSpanID)s]: %(message)s"
        ),
        stream=sys.stdout,
    )

    try:
        asyncio.run(_entry_main())
    except KeyboardInterrupt:
        logger.info("Interrupted by user.")
