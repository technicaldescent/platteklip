# SPDX-FileCopyrightText: 2025 technical descent
# SPDX-License-Identifier: Apache-2.0

"""MQTT v5 producer with strict mTLS and QoS enforcement.

Provides connection lifecycle management, thread-to-asyncio
state bridging, and a publish primitive with per-producer
counters.  TLS configuration enforces TLS 1.3 only, with
mutual authentication and hostname verification enabled by
default.

Edge telemetry instruments are created from the
Weaver-generated semantic convention module.  Metric names,
units, and descriptions are derived from the edge registry
and stay in sync with the OTel Collector transform rules.

The :func:`main` entry point runs a simulated edge
telemetry loop.  On each tick, synthetic register values
are generated for every metric in the registry, recorded
as OTel gauge values, and published as structured JSON
payloads over MQTT to per-subsystem topics under
``edge/telemetry/``.
"""

import asyncio
import json
import logging
import os
import secrets
import ssl
import time
from dataclasses import asdict, dataclass
from typing import Any, Final, Self

from opentelemetry import metrics, trace

import platteklip.mqtt.client as mqtt
from platteklip.health import (
    HealthConfig,
    HealthServer,
)
from platteklip.instrumentation.edge_semconv import (
    EDGE_SOURCE_ID,
    EDGE_SOURCE_TYPE,
    EDGE_VEHICLE_ID,
    METRICS_BY_NAME,
)
from platteklip.mqtt.enums import CallbackAPIVersion
from platteklip.mqtt.packettypes import PacketTypes
from platteklip.mqtt.properties import Properties
from platteklip.signal_generator import (
    SignalGenerator,
)

logger: Final[logging.Logger] = logging.getLogger(
    __name__,
)

_ALLOWED_QOS: Final[frozenset[int]] = frozenset(
    {1, 2},
)
_OTEL_SCOPE: Final[str] = "platteklip.mqtt_producer"

_SEM_MESSAGING_SYSTEM: Final[str] = "messaging.system"
_SEM_MESSAGING_OP: Final[str] = "messaging.operation.type"
_SEM_MESSAGING_DEST: Final[str] = "messaging.destination.name"
_SEM_MESSAGING_BODY_SIZE: Final[str] = "messaging.message.body.size"
_SEM_MESSAGING_CLIENT_ID: Final[str] = "messaging.client.id"
_SEM_SERVER_ADDR: Final[str] = "server.address"
_SEM_SERVER_PORT: Final[str] = "server.port"
_SEM_NET_PROTO_NAME: Final[str] = "network.protocol.name"
_SEM_NET_PROTO_VER: Final[str] = "network.protocol.version"


class MQTTProducerError(RuntimeError):
    """Base exception for MQTT producer failures."""


class TLSConfigurationError(MQTTProducerError):
    """The TLS context cannot be constructed."""


class ConnectionTimeoutError(MQTTProducerError):
    """The broker did not respond within the timeout."""


class ConnectionRejectedError(MQTTProducerError):
    """The broker rejected the CONNECT packet."""


@dataclass(frozen=True, slots=True)
class MQTTConnectionConfig:
    """Connection and client tuning for a producer.

    Parameters
    ----------
    host
        Broker hostname or IP address.
    port
        Broker TLS port.
    keepalive
        MQTT keep-alive interval in seconds.
    connect_timeout_seconds
        Maximum wait for an initial CONNACK.
    disconnect_timeout_seconds
        Maximum wait for a graceful DISCONNECT.
    receive_maximum
        MQTT v5 flow-control hint sent to the broker.
    max_inflight_messages
        Client-side cap on in-flight QoS > 0 messages.
    max_queued_messages
        Client-side outgoing queue depth.
    reconnect_min_delay_seconds
        Floor for the exponential backoff delay.
    reconnect_max_delay_seconds
        Ceiling for the exponential backoff delay.
    use_tls
        Enable TLS (mTLS) transport.
    ca_file
        Path to the CA certificate bundle.
    cert_file
        Path to the client certificate.
    key_file
        Path to the client private key.
    tls_check_hostname
        Verify the broker certificate SAN/CN.
    tls_min_version
        Minimum TLS protocol version.
    tls_max_version
        Maximum TLS protocol version.
    """

    host: str = "mqtt-broker"
    port: int = 8883
    keepalive: int = 60
    connect_timeout_seconds: float = 10.0
    disconnect_timeout_seconds: float = 5.0
    receive_maximum: int = 65_535
    max_inflight_messages: int = 2048
    max_queued_messages: int = 10_000
    reconnect_min_delay_seconds: int = 1
    reconnect_max_delay_seconds: int = 30
    use_tls: bool = True
    ca_file: str = "/run/secrets/ca.crt"
    cert_file: str = "/run/secrets/tls_certificate.crt"
    key_file: str = "/run/secrets/tls_private_key.key"
    tls_check_hostname: bool = True
    tls_min_version: ssl.TLSVersion = ssl.TLSVersion.TLSv1_3
    tls_max_version: ssl.TLSVersion = ssl.TLSVersion.TLSv1_3


@dataclass(slots=True)
class MQTTProducerStats:
    """Publish counters for a single producer.

    Parameters
    ----------
    published_accepted
        Messages accepted into the outgoing queue.
    publish_failures
        Total failed publish attempts.
    queue_full
        Rejections due to queue exhaustion.
    not_connected
        Rejections due to no active connection.
    rejected_qos
        Rejections due to disallowed QoS level.
    """

    published_accepted: int = 0
    publish_failures: int = 0
    queue_full: int = 0
    not_connected: int = 0
    rejected_qos: int = 0


def create_edge_instruments(
    meter: metrics.Meter,
) -> dict[str, Any]:
    """Create OTel gauge instruments from the Weaver registry.

    Parameters
    ----------
    meter
        OTel meter scoped to the producer.

    Returns
    -------
    dict[str, Any]
        Gauges keyed by fully qualified metric name.
    """
    gauges: dict[str, Any] = {}
    for name, conv in METRICS_BY_NAME.items():
        gauges[name] = meter.create_gauge(
            name=conv.name,
            description=conv.description,
            unit=conv.unit,
        )
    return gauges


class MQTTProducer:
    """MQTT v5 producer with mTLS and QoS enforcement.

    Parameters
    ----------
    config
        Connection and tuning parameters.
    client_id
        Override the auto-generated client identifier.
    mqtt_client
        Inject a pre-built MQTT client (for testing).
    log
        Override the module-level logger.

    Raises
    ------
    MQTTProducerError
        If *mqtt_client* is not configured for v5.
    TLSConfigurationError
        If TLS context construction fails.
    """

    def __init__(
        self,
        config: MQTTConnectionConfig,
        *,
        client_id: str | None = None,
        mqtt_client: mqtt.Client | None = None,
        log: logging.Logger | None = None,
    ) -> None:
        """Initialise the producer and configure TLS."""
        self._config: MQTTConnectionConfig = config
        self._log: logging.Logger = log or logger
        self._client_id: str = client_id or f"client_{secrets.randbelow(10_000):04d}"

        self._loop: asyncio.AbstractEventLoop | None = None
        self._running: bool = False

        self._connected_event: asyncio.Event = asyncio.Event()
        self._connect_future: asyncio.Future[None] | None = None
        self._disconnect_future: asyncio.Future[None] | None = None

        self._stats: MQTTProducerStats = MQTTProducerStats()

        self._mqtt_client: mqtt.Client = mqtt_client or mqtt.Client(
            callback_api_version=(CallbackAPIVersion.VERSION2),
            client_id=self._client_id,
            protocol=mqtt.MQTTv5,
        )

        if self._mqtt_client.protocol != mqtt.MQTTv5:
            raise MQTTProducerError(
                "MQTT v5 is required; client is" " misconfigured.",
            )

        try:
            self._mqtt_client.enable_logger(
                self._log,
            )
        except AttributeError, TypeError:
            self._log.debug(
                "[%s] enable_logger unavailable",
                self._client_id,
                exc_info=True,
            )

        self._mqtt_client.max_inflight_messages_set(
            self._config.max_inflight_messages,
        )
        self._mqtt_client.max_queued_messages_set(
            self._config.max_queued_messages,
        )
        self._mqtt_client.reconnect_delay_set(
            min_delay=(self._config.reconnect_min_delay_seconds),
            max_delay=(self._config.reconnect_max_delay_seconds),
        )

        self._mqtt_client.on_connect = self._on_connect
        self._mqtt_client.on_disconnect = self._on_disconnect
        self._mqtt_client.on_publish = self._on_publish

        if self._config.use_tls:
            self._configure_tls()

        self._tracer: trace.Tracer = trace.get_tracer(
            _OTEL_SCOPE,
        )
        meter: metrics.Meter = metrics.get_meter(
            _OTEL_SCOPE,
        )

        self._base_attrs: dict[str, str | int] = {
            _SEM_MESSAGING_SYSTEM: "mqtt",
            _SEM_NET_PROTO_NAME: "mqtt",
            _SEM_NET_PROTO_VER: "5",
            _SEM_MESSAGING_CLIENT_ID: self._client_id,
            _SEM_SERVER_ADDR: self._config.host,
            _SEM_SERVER_PORT: self._config.port,
        }

        self._log_ctx: dict[str, str | int] = {
            _SEM_MESSAGING_SYSTEM: "mqtt",
            _SEM_MESSAGING_CLIENT_ID: self._client_id,
            _SEM_SERVER_ADDR: self._config.host,
            _SEM_SERVER_PORT: self._config.port,
        }

        self._publish_counter: metrics.Counter = meter.create_counter(
            name="messaging.publish.messages",
            description=("Number of messages offered to" " the MQTT client library."),
            unit="{message}",
        )
        self._publish_duration: metrics.Histogram = meter.create_histogram(
            name="messaging.publish.duration",
            description=("Time to submit a message to" " the client library."),
            unit="s",
        )

        self._edge_gauges: dict[str, Any] = create_edge_instruments(meter)

    @property
    def client_id(self) -> str:
        """Return the MQTT client identifier."""
        return self._client_id

    @property
    def stats(self) -> MQTTProducerStats:
        """Return the producer's publish counters."""
        return self._stats

    @property
    def is_connected(self) -> bool:
        """Return ``True`` if the broker connection is active."""
        return self._connected_event.is_set()

    def record_edge_metric(
        self,
        metric_name: str,
        value: float,
        attributes: dict[str, str | int] | None = None,
    ) -> None:
        """Record a value for a Weaver-registered metric.

        Parameters
        ----------
        metric_name
            Fully qualified name from the registry.
        value
            The observed value.
        attributes
            Additional OTel attributes to attach.
        """
        gauge = self._edge_gauges.get(metric_name)
        if gauge is None:
            self._log.warning(
                "Unknown edge metric: %s",
                metric_name,
                extra=self._log_ctx,
            )
            return
        gauge.set(
            value,
            attributes=attributes or {},
        )

    def _configure_tls(self) -> None:
        """Build and apply a strict TLS 1.3 mTLS context.

        Raises
        ------
        TLSConfigurationError
            If certificate files are missing or the
            context cannot be initialised.
        """
        try:
            ctx = ssl.create_default_context(
                ssl.Purpose.SERVER_AUTH,
            )
            ctx.check_hostname = self._config.tls_check_hostname
            ctx.verify_mode = ssl.CERT_REQUIRED
            ctx.minimum_version = self._config.tls_min_version
            ctx.maximum_version = self._config.tls_max_version
            ctx.verify_flags |= ssl.VERIFY_X509_STRICT

            ctx.load_verify_locations(
                cafile=self._config.ca_file,
            )
            ctx.load_cert_chain(
                certfile=self._config.cert_file,
                keyfile=self._config.key_file,
            )

            self._mqtt_client.tls_set_context(ctx)

        except FileNotFoundError as exc:
            raise TLSConfigurationError(
                f"TLS file not found for client" f" {self._client_id}: {exc}",
            ) from exc
        except ssl.SSLError as exc:
            raise TLSConfigurationError(
                f"TLS context failed for client" f" {self._client_id}: {exc}",
            ) from exc
        except (OSError, ValueError) as exc:
            raise TLSConfigurationError(
                f"Unexpected TLS error for client" f" {self._client_id}: {exc}",
            ) from exc

    def _on_connect(
        self,
        client: mqtt.Client,
        userdata: Any,
        connect_flags: Any,
        reason_code: Any,
        properties: Properties | None = None,
    ) -> None:
        """Handle CONNACK from the broker."""
        rc = int(reason_code) if reason_code is not None else 1

        if rc == 0:
            self._log.info(
                "Connected to broker",
                extra=self._log_ctx,
            )
            self._threadsafe_connected(connected=True)
            self._threadsafe_resolve_connect(
                ok=True,
                error=None,
            )
            return

        err = ConnectionRejectedError(
            f"[{self._client_id}] CONNECT rejected" f" (reason_code={rc})",
        )
        self._log.error(
            "CONNECT rejected (reason_code=%s)",
            rc,
            extra={
                **self._log_ctx,
                "mqtt.reason_code": rc,
            },
        )
        self._threadsafe_connected(connected=False)
        self._threadsafe_resolve_connect(
            ok=False,
            error=err,
        )

    def _on_disconnect(
        self,
        client: mqtt.Client,
        userdata: Any,
        disconnect_flags: Any,
        reason_code: Any,
        properties: Properties | None = None,
    ) -> None:
        """Handle DISCONNECT or connection loss."""
        rc = int(reason_code) if reason_code is not None else 0
        self._threadsafe_connected(connected=False)

        if rc != 0:
            self._log.warning(
                "Unexpected disconnect" " (reason_code=%s)",
                rc,
                extra={
                    **self._log_ctx,
                    "mqtt.reason_code": rc,
                },
            )
        else:
            self._log.info(
                "Disconnected cleanly",
                extra=self._log_ctx,
            )

        self._threadsafe_resolve_disconnect()

    def _on_publish(
        self,
        client: mqtt.Client,
        userdata: Any,
        mid: int,
        reason_code: Any | None = None,
        properties: Properties | None = None,
    ) -> None:
        """Handle PUBACK/PUBCOMP for QoS > 0 messages."""

    def _threadsafe_connected(
        self,
        *,
        connected: bool,
    ) -> None:
        """Set or clear the connected event from the network thread."""
        loop = self._loop
        if loop is None:
            return

        def _apply() -> None:
            """Toggle the connected event."""
            if connected:
                self._connected_event.set()
            else:
                self._connected_event.clear()

        loop.call_soon_threadsafe(_apply)

    def _threadsafe_resolve_connect(
        self,
        *,
        ok: bool,
        error: Exception | None,
    ) -> None:
        """Resolve the connect future from the network thread."""
        loop = self._loop
        if loop is None:
            return

        def _apply() -> None:
            """Resolve or reject the connect future."""
            fut = self._connect_future
            if fut is None or fut.done():
                return
            if ok:
                fut.set_result(None)
            else:
                fut.set_exception(
                    error
                    or ConnectionRejectedError(
                        "CONNECT rejected",
                    ),
                )

        loop.call_soon_threadsafe(_apply)

    def _threadsafe_resolve_disconnect(
        self,
    ) -> None:
        """Resolve the disconnect future from the network thread."""
        loop = self._loop
        if loop is None:
            return

        def _apply() -> None:
            """Resolve the disconnect future."""
            fut = self._disconnect_future
            if fut is None or fut.done():
                return
            fut.set_result(None)

        loop.call_soon_threadsafe(_apply)

    async def connect(self) -> None:
        """Start the network loop and await CONNACK.

        Raises
        ------
        MQTTProducerError
            If *receive_maximum* is out of range or
            the client cannot be started.
        ConnectionTimeoutError
            If no CONNACK arrives within the timeout.
        """
        if self._running and self.is_connected:
            return

        self._loop = asyncio.get_running_loop()
        self._connected_event.clear()

        if not (1 <= self._config.receive_maximum <= 65_535):
            raise MQTTProducerError(
                "receive_maximum must be in" " [1, 65535].",
            )

        self._connect_future = self._loop.create_future()

        props = Properties(PacketTypes.CONNECT)
        props.ReceiveMaximum = self._config.receive_maximum

        try:
            self._mqtt_client.connect_async(
                self._config.host,
                self._config.port,
                keepalive=self._config.keepalive,
                properties=props,
            )
            self._mqtt_client.loop_start()
            self._running = True
        except OSError as exc:
            self._running = False
            raise MQTTProducerError(
                f"[{self._client_id}] Failed to" f" start MQTT client: {exc}",
            ) from exc

        try:
            await asyncio.wait_for(
                self._connect_future,
                timeout=float(
                    self._config.connect_timeout_seconds,
                ),
            )
        except TimeoutError as exc:
            self.stop()
            timeout = self._config.connect_timeout_seconds
            raise ConnectionTimeoutError(
                f"[{self._client_id}] Connection" f" timed out after {timeout}s",
            ) from exc

    async def disconnect(self) -> None:
        """Send a graceful shutdown request (best-effort).

        Sends DISCONNECT and waits up to
        *disconnect_timeout_seconds*.  Falls back to
        a hard stop if the timeout expires.
        """
        if not self._running:
            return

        loop = asyncio.get_running_loop()
        self._disconnect_future = loop.create_future()

        try:
            self._mqtt_client.disconnect()
        except OSError:
            self._log.debug(
                "disconnect call failed",
                extra=self._log_ctx,
                exc_info=True,
            )

        try:
            await asyncio.wait_for(
                self._disconnect_future,
                timeout=float(
                    self._config.disconnect_timeout_seconds,
                ),
            )
        except TimeoutError:
            self._log.debug(
                "disconnect wait timed out",
                extra=self._log_ctx,
            )

        self.stop()

    def publish(  # noqa: FNE005
        self,
        topic: str,
        payload: str | bytes,
        *,
        qos: int = 1,
        retain: bool = False,
    ) -> bool:
        """Publish a single message.

        Returns ``True`` when the message is accepted
        into the outgoing queue.  Never raises; failures
        are reflected in :attr:`stats` and the OTel
        counter.

        Parameters
        ----------
        topic
            MQTT topic string.
        payload
            Message body.
        qos
            Quality of Service level (1 or 2 only).
        retain
            Set the MQTT retain flag.

        Returns
        -------
        bool
            ``True`` if the message was queued.
        """
        pub_ctx: dict[str, str | int] = {
            **self._log_ctx,
            _SEM_MESSAGING_DEST: topic,
            _SEM_MESSAGING_OP: "publish",
        }

        if qos not in _ALLOWED_QOS:
            self._stats.rejected_qos += 1
            self._publish_counter.add(
                1,
                {
                    **self._base_attrs,
                    _SEM_MESSAGING_DEST: topic,
                    _SEM_MESSAGING_OP: "publish",
                    "outcome": "rejected_qos",
                },
            )
            self._log.error(
                "QoS=%d rejected (policy: 1/2)",
                qos,
                extra={
                    **pub_ctx,
                    "outcome": "rejected_qos",
                },
            )
            return False

        if not self.is_connected:
            self._stats.not_connected += 1
            self._stats.publish_failures += 1
            self._publish_counter.add(
                1,
                {
                    **self._base_attrs,
                    _SEM_MESSAGING_DEST: topic,
                    _SEM_MESSAGING_OP: "publish",
                    "outcome": "not_connected",
                },
            )
            return False

        body_size = (
            len(payload) if isinstance(payload, bytes) else len(payload.encode("utf-8"))
        )

        span_attrs: dict[str, str | int] = {
            **self._base_attrs,
            _SEM_MESSAGING_OP: "publish",
            _SEM_MESSAGING_DEST: topic,
            _SEM_MESSAGING_BODY_SIZE: body_size,
        }

        with self._tracer.start_as_current_span(
            f"{topic} publish",
            kind=trace.SpanKind.PRODUCER,
            attributes=span_attrs,
        ) as span:
            t0 = time.monotonic()

            try:
                info = self._mqtt_client.publish(
                    topic,
                    payload,
                    qos=qos,
                    retain=retain,
                )
            except (OSError, ValueError) as exc:
                self._stats.publish_failures += 1
                span.set_status(
                    trace.StatusCode.ERROR,
                    str(exc),
                )
                span.record_exception(exc)
                self._log.error(
                    "Publish raised: %s",
                    exc,
                    extra={
                        **pub_ctx,
                        "outcome": "error",
                    },
                )
                self._record_publish_metric(
                    topic,
                    t0,
                    "error",
                )
                return False

            if info.rc == mqtt.MQTT_ERR_SUCCESS:
                self._stats.published_accepted += 1
                span.set_attribute(
                    "messaging.message.id",
                    info.mid,
                )
                self._record_publish_metric(
                    topic,
                    t0,
                    "accepted",
                )
                return True

            if info.rc == mqtt.MQTT_ERR_QUEUE_SIZE:
                self._stats.queue_full += 1
                self._stats.publish_failures += 1
                span.set_status(
                    trace.StatusCode.ERROR,
                    "queue_full",
                )
                self._log.warning(
                    "Outgoing queue full",
                    extra={
                        **pub_ctx,
                        "outcome": "queue_full",
                    },
                )
                self._record_publish_metric(
                    topic,
                    t0,
                    "queue_full",
                )
                return False

            self._stats.publish_failures += 1
            span.set_status(
                trace.StatusCode.ERROR,
                f"rc={info.rc}",
            )
            self._log.warning(
                "Publish rejected (rc=%s)",
                info.rc,
                extra={
                    **pub_ctx,
                    "outcome": "rejected",
                    "mqtt.rc": info.rc,
                },
            )
            self._record_publish_metric(
                topic,
                t0,
                "rejected",
            )
            return False

    def _record_publish_metric(
        self,
        topic: str,
        t0: float,
        outcome: str,
    ) -> None:
        """Record counter and histogram for a publish."""
        elapsed = time.monotonic() - t0
        attrs: dict[str, str | int] = {
            **self._base_attrs,
            _SEM_MESSAGING_DEST: topic,
            _SEM_MESSAGING_OP: "publish",
            "outcome": outcome,
        }
        self._publish_counter.add(1, attrs)
        self._publish_duration.record(elapsed, attrs)

    def stop(self) -> None:
        """Stop the network loop (idempotent)."""
        if not self._running:
            return

        self._running = False
        self._connected_event.clear()

        try:
            self._mqtt_client.loop_stop()
        except OSError:
            self._log.debug(
                "loop_stop failed",
                exc_info=True,
            )

    @classmethod
    def with_client_id_prefix(
        cls,
        config: MQTTConnectionConfig,
        *,
        prefix: str,
        index: int,
    ) -> Self:
        """Create a producer with a deterministic ID.

        Parameters
        ----------
        config
            Connection and tuning parameters.
        prefix
            Prefix string for the client ID.
        index
            Numeric suffix for the client ID.

        Returns
        -------
        Self
            A new producer instance.
        """
        return cls(
            config,
            client_id=f"{prefix}_{index:04d}",
        )


def _parse_env_int(
    name: str,
    default: str,
) -> int:
    """Read an integer from the environment.

    Parameters
    ----------
    name
        Environment variable name.
    default
        Fallback value if the variable is unset.

    Returns
    -------
    int
        The parsed integer.

    Raises
    ------
    SystemExit
        If the value is not a valid integer.
    """
    raw = os.getenv(name, default)
    try:
        return int(raw)
    except ValueError as exc:
        raise SystemExit(
            f"Invalid integer for {name}={raw!r}:" f" {exc}",
        ) from exc


_JSON_SEPARATORS: Final[tuple[str, str]] = (",", ":")


async def main() -> None:
    """Run a simulated edge telemetry producer.

    Generates synthetic SCADA register values, records
    each as an OTel gauge, and publishes structured JSON
    payloads over MQTT to per-subsystem topics under
    ``edge/telemetry/{vehicle_id}/{subsystem}``.
    """
    host = os.getenv("MQTT_HOST", "mqtt-broker")
    port = _parse_env_int("MQTT_PORT", "8883")
    use_tls = os.getenv("MQTT_USE_TLS", "true").lower() == "true"
    check_hostname = (
        os.getenv(
            "MQTT_TLS_CHECK_HOSTNAME",
            "true",
        ).lower()
        == "true"
    )
    ca_file = os.getenv(
        "MQTT_CA_FILE",
        "/run/secrets/ca.crt",
    )
    cert_file = os.getenv(
        "MQTT_CERT_FILE",
        "/run/secrets/tls_certificate.crt",
    )
    key_file = os.getenv(
        "MQTT_KEY_FILE",
        "/run/secrets/tls_private_key.key",
    )

    mps = _parse_env_int(
        "MESSAGES_PER_SECOND",
        "2",
    )
    sleep_interval = 1.0 / mps if mps > 0 else 1.0
    health_port = _parse_env_int(
        "HEALTH_PORT",
        "8080",
    )

    vehicle_id = os.getenv(
        "VEHICLE_ID",
        "vehicle_001",
    )
    source_id = os.getenv(
        "SOURCE_ID",
        "sim_001",
    )

    from platteklip.instrumentation.setup import (  # noqa: PLC0415
        configure_telemetry,
        shutdown_telemetry,
    )

    configure_telemetry()

    config = MQTTConnectionConfig(
        host=host,
        port=port,
        use_tls=use_tls,
        ca_file=ca_file,
        cert_file=cert_file,
        key_file=key_file,
        tls_check_hostname=check_hostname,
    )

    producer = MQTTProducer(
        config,
        client_id="edge_telemetry_producer",
    )

    generator = SignalGenerator()

    edge_attrs: dict[str, str | int] = {
        EDGE_VEHICLE_ID: vehicle_id,
        EDGE_SOURCE_ID: source_id,
        EDGE_SOURCE_TYPE: "simulation",
    }

    def _health_status() -> dict[str, object]:
        """Build health payload from producer state."""
        return {
            "healthy": producer.is_connected,
            "client_id": producer.client_id,
            "connected": producer.is_connected,
            **asdict(producer.stats),
        }

    health = HealthServer(
        status_fn=_health_status,
        config=HealthConfig(port=health_port),
    )
    health.start()

    logger.info(
        "Initialising edge telemetry producer",
        extra={
            "server.address": host,
            "server.port": port,
            EDGE_VEHICLE_ID: vehicle_id,
            EDGE_SOURCE_ID: source_id,
        },
    )

    logger.info(
        "Registered %d edge metric instruments" " from semantic convention registry",
        len(METRICS_BY_NAME),
    )

    try:
        await producer.connect()
        logger.info(
            "Connected to %s:%d via mTLS",
            host,
            port,
            extra={
                "server.address": host,
                "server.port": port,
            },
        )

        while True:
            samples = generator.tick_by_subsystem()

            for subsystem, signals in samples.items():
                for name, value in signals.items():
                    producer.record_edge_metric(
                        name,
                        value,
                        attributes=edge_attrs,
                    )

                topic = f"edge/telemetry" f"/{vehicle_id}" f"/{subsystem}"
                payload = json.dumps(
                    {
                        "vehicle_id": vehicle_id,
                        "source_id": source_id,
                        "source_type": "simulation",
                        "timestamp_ns": time.time_ns(),
                        "signals": signals,
                    },
                    separators=_JSON_SEPARATORS,
                ).encode("utf-8")

                producer.publish(
                    topic,
                    payload,
                    qos=1,
                )

            await asyncio.sleep(sleep_interval)

    except asyncio.CancelledError:
        logger.info("Producer loop cancelled.")
    except MQTTProducerError as exc:
        logger.error(
            "Producer encountered a fatal" " error: %s",
            exc,
        )
    finally:
        logger.info("Disconnecting")
        health.stop()
        await producer.disconnect()
        shutdown_telemetry()


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format=(
            "%(asctime)s [%(levelname)s]"
            " %(name)s"
            " [trace=%(otelTraceID)s"
            " span=%(otelSpanID)s]: %(message)s"
        ),
    )

    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Interrupted by user.")
