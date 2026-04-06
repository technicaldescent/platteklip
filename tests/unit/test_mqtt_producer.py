# SPDX-FileCopyrightText: 2025 technical descent
# SPDX-License-Identifier: Apache-2.0

"""Tests for the MQTT v5 producer.

Covers initialisation guards, TLS error wrapping,
publish paths (success, queue full, rejected QoS,
not connected, exception, other rc), edge metric
recording, connection lifecycle (connect, disconnect,
timeout, early return), thread-to-asyncio state
bridges, callback dispatch, stop idempotency, and
the factory classmethod.
"""

import asyncio
import ssl
import unittest
from unittest.mock import MagicMock, patch

import platteklip.mqtt.client as mqtt
from platteklip.mqtt_producer import (
    ConnectionTimeoutError,
    MQTTConnectionConfig,
    MQTTProducer,
    MQTTProducerError,
    TLSConfigurationError,
)


def _make_v5_mock(**kwargs: object) -> MagicMock:
    """Build a MagicMock with protocol set to MQTTv5."""
    m = MagicMock(**kwargs)
    m.protocol = mqtt.MQTTv5
    return m


# ==================================================================
# Initialisation guards
# ==================================================================


class TestMQTTProducerInit(unittest.TestCase):
    """Verify __init__ validation and setup."""

    def test_protocol_mismatch_raises(self) -> None:
        """Reject a client not configured for v5."""
        m = MagicMock()
        m.protocol = 3  # MQTTv3
        with self.assertRaises(MQTTProducerError):
            MQTTProducer(
                MQTTConnectionConfig(use_tls=False),
                mqtt_client=m,
            )

    def test_enable_logger_attribute_error(
        self,
    ) -> None:
        """Swallow AttributeError from enable_logger."""
        m = _make_v5_mock()
        m.enable_logger.side_effect = AttributeError("no logger")
        log = MagicMock()

        p = MQTTProducer(
            MQTTConnectionConfig(use_tls=False),
            mqtt_client=m,
            log=log,
        )

        self.assertTrue(log.debug.called)
        self.assertIsNotNone(p)

    def test_enable_logger_type_error(
        self,
    ) -> None:
        """Swallow TypeError from enable_logger."""
        m = _make_v5_mock()
        m.enable_logger.side_effect = TypeError(
            "bad arg",
        )
        log = MagicMock()

        p = MQTTProducer(
            MQTTConnectionConfig(use_tls=False),
            mqtt_client=m,
            log=log,
        )

        self.assertTrue(log.debug.called)
        self.assertIsNotNone(p)


# ==================================================================
# Properties
# ==================================================================


class TestMQTTProducerProperties(unittest.TestCase):
    """Verify public properties."""

    def test_client_id_returns_string(self) -> None:
        """Return the assigned client identifier."""
        p = MQTTProducer(
            MQTTConnectionConfig(use_tls=False),
            mqtt_client=_make_v5_mock(),
            client_id="test_id",
        )
        self.assertEqual(p.client_id, "test_id")

    def test_stats_returns_dataclass(self) -> None:
        """Return the MQTTProducerStats instance."""
        p = MQTTProducer(
            MQTTConnectionConfig(use_tls=False),
            mqtt_client=_make_v5_mock(),
        )
        self.assertEqual(
            p.stats.published_accepted,
            0,
        )

    def test_is_connected_default_false(
        self,
    ) -> None:
        """Start in a disconnected state."""
        p = MQTTProducer(
            MQTTConnectionConfig(use_tls=False),
            mqtt_client=_make_v5_mock(),
        )
        self.assertFalse(p.is_connected)


# ==================================================================
# TLS configuration
# ==================================================================


class TestMQTTProducerTLS(unittest.TestCase):
    """Verify TLS error wrapping."""

    def test_tls_file_not_found_is_wrapped(
        self,
    ) -> None:
        """Wrap FileNotFoundError as TLSConfigurationError."""
        config = MQTTConnectionConfig(
            host="localhost",
            port=8883,
            use_tls=True,
            ca_file="/missing/ca",
            cert_file="/missing/cert",
            key_file="/missing/key",
        )
        ctx = MagicMock()
        ctx.load_cert_chain.side_effect = FileNotFoundError("nope")

        with patch(
            "platteklip.mqtt_producer" ".ssl.create_default_context",
            return_value=ctx,
        ):
            with self.assertRaises(
                TLSConfigurationError,
            ):
                MQTTProducer(
                    config,
                    mqtt_client=_make_v5_mock(),
                )

    def test_tls_ssl_error_is_wrapped(
        self,
    ) -> None:
        """Wrap SSLError as TLSConfigurationError."""
        config = MQTTConnectionConfig(
            host="localhost",
            port=8883,
            use_tls=True,
        )
        with patch(
            "platteklip.mqtt_producer" ".ssl.create_default_context",
            side_effect=ssl.SSLError("bad"),
        ):
            with self.assertRaises(
                TLSConfigurationError,
            ):
                MQTTProducer(
                    config,
                    mqtt_client=_make_v5_mock(),
                )

    def test_tls_generic_error_is_wrapped(
        self,
    ) -> None:
        """Wrap ValueError as TLSConfigurationError."""
        config = MQTTConnectionConfig(
            host="localhost",
            port=8883,
            use_tls=True,
        )
        ctx = MagicMock()
        ctx.load_cert_chain.side_effect = ValueError(
            "boom",
        )

        with patch(
            "platteklip.mqtt_producer" ".ssl.create_default_context",
            return_value=ctx,
        ):
            with self.assertRaisesRegex(
                TLSConfigurationError,
                "Unexpected TLS error",
            ):
                MQTTProducer(
                    config,
                    mqtt_client=_make_v5_mock(),
                )


# ==================================================================
# Edge metric recording
# ==================================================================


class TestMQTTProducerEdgeMetrics(unittest.TestCase):
    """Verify edge metric recording."""

    def test_record_known_metric(self) -> None:
        """Set a gauge for a known metric name."""
        p = MQTTProducer(
            MQTTConnectionConfig(use_tls=False),
            mqtt_client=_make_v5_mock(),
        )
        # Pick the first gauge from the registry
        name = next(iter(p._edge_gauges))
        gauge = MagicMock()
        p._edge_gauges[name] = gauge

        p.record_edge_metric(
            name,
            42.0,
            attributes={"k": "v"},
        )

        gauge.set.assert_called_once_with(
            42.0,
            attributes={"k": "v"},
        )

    def test_record_unknown_metric_warns(
        self,
    ) -> None:
        """Log a warning for an unregistered metric."""
        log = MagicMock()
        p = MQTTProducer(
            MQTTConnectionConfig(use_tls=False),
            mqtt_client=_make_v5_mock(),
            log=log,
        )

        p.record_edge_metric(
            "edge.nonexistent.metric",
            1.0,
        )

        self.assertTrue(log.warning.called)

    def test_record_none_attributes_defaults(
        self,
    ) -> None:
        """Pass empty dict when attributes is None."""
        p = MQTTProducer(
            MQTTConnectionConfig(use_tls=False),
            mqtt_client=_make_v5_mock(),
        )
        name = next(iter(p._edge_gauges))
        gauge = MagicMock()
        p._edge_gauges[name] = gauge

        p.record_edge_metric(name, 1.0)

        gauge.set.assert_called_once_with(
            1.0,
            attributes={},
        )


# ==================================================================
# Publish paths
# ==================================================================


class TestMQTTProducerPublishing(unittest.TestCase):
    """Verify all publish outcome paths."""

    def test_publish_success_increments(
        self,
    ) -> None:
        """Increment published_accepted on success."""
        m = _make_v5_mock()
        info = MagicMock()
        info.rc = mqtt.MQTT_ERR_SUCCESS
        m.publish.return_value = info

        p = MQTTProducer(
            MQTTConnectionConfig(use_tls=False),
            mqtt_client=m,
        )
        p._connected_event.set()
        ok = p.publish("t", "payload", qos=1)

        self.assertTrue(ok)
        self.assertEqual(
            p.stats.published_accepted,
            1,
        )
        self.assertEqual(
            p.stats.publish_failures,
            0,
        )
        self.assertEqual(p.stats.queue_full, 0)

    def test_publish_queue_full_counts(
        self,
    ) -> None:
        """Increment queue_full and publish_failures."""
        m = _make_v5_mock()
        info = MagicMock()
        info.rc = mqtt.MQTT_ERR_QUEUE_SIZE
        m.publish.return_value = info

        p = MQTTProducer(
            MQTTConnectionConfig(use_tls=False),
            mqtt_client=m,
        )
        p._connected_event.set()
        ok = p.publish("t", "payload", qos=1)

        self.assertFalse(ok)
        self.assertEqual(p.stats.queue_full, 1)
        self.assertEqual(
            p.stats.publish_failures,
            1,
        )

    def test_publish_other_rc_counts_failure(
        self,
    ) -> None:
        """Increment publish_failures for unknown rc."""
        m = _make_v5_mock()
        info = MagicMock()
        info.rc = 12345
        m.publish.return_value = info

        p = MQTTProducer(
            MQTTConnectionConfig(use_tls=False),
            mqtt_client=m,
        )
        p._connected_event.set()
        ok = p.publish("t", "payload")

        self.assertFalse(ok)
        self.assertEqual(
            p.stats.publish_failures,
            1,
        )

    def test_publish_raises_counts_failure(
        self,
    ) -> None:
        """Increment publish_failures on OSError."""
        m = _make_v5_mock()
        m.publish.side_effect = OSError("net down")

        p = MQTTProducer(
            MQTTConnectionConfig(use_tls=False),
            mqtt_client=m,
        )
        p._connected_event.set()
        ok = p.publish("t", "payload")

        self.assertFalse(ok)
        self.assertEqual(
            p.stats.publish_failures,
            1,
        )

    def test_publish_not_connected(self) -> None:
        """Increment not_connected when disconnected."""
        m = _make_v5_mock()
        p = MQTTProducer(
            MQTTConnectionConfig(use_tls=False),
            mqtt_client=m,
        )
        # Do not set _connected_event
        ok = p.publish("t", "payload", qos=1)

        self.assertFalse(ok)
        self.assertEqual(p.stats.not_connected, 1)
        self.assertEqual(
            p.stats.publish_failures,
            1,
        )

    def test_publish_rejected_qos(self) -> None:
        """Increment rejected_qos for QoS 0."""
        m = _make_v5_mock()
        p = MQTTProducer(
            MQTTConnectionConfig(use_tls=False),
            mqtt_client=m,
        )
        p._connected_event.set()
        ok = p.publish("t", "payload", qos=0)

        self.assertFalse(ok)
        self.assertEqual(p.stats.rejected_qos, 1)

    def test_publish_bytes_payload(self) -> None:
        """Accept bytes payload without encoding."""
        m = _make_v5_mock()
        info = MagicMock()
        info.rc = mqtt.MQTT_ERR_SUCCESS
        m.publish.return_value = info

        p = MQTTProducer(
            MQTTConnectionConfig(use_tls=False),
            mqtt_client=m,
        )
        p._connected_event.set()
        ok = p.publish("t", b"\x00\x01", qos=1)

        self.assertTrue(ok)


# ==================================================================
# Connection lifecycle
# ==================================================================


class TestMQTTProducerLifecycle(
    unittest.IsolatedAsyncioTestCase,
):
    """Verify async connection lifecycle."""

    async def test_connect_success_path(
        self,
    ) -> None:
        """Connect and resolve the future on CONNACK."""
        m = _make_v5_mock()
        p = MQTTProducer(
            MQTTConnectionConfig(
                use_tls=False,
                connect_timeout_seconds=1.0,
            ),
            mqtt_client=m,
        )

        def _resolve(
            *a: object,
            **kw: object,
        ) -> None:
            """Simulate immediate CONNACK."""
            fut = p._connect_future
            if fut and not fut.done():
                fut.set_result(None)

        m.connect_async.side_effect = _resolve

        await p.connect()

        self.assertTrue(m.connect_async.called)
        self.assertTrue(m.loop_start.called)

    async def test_connect_timeout_raises(
        self,
    ) -> None:
        """Raise ConnectionTimeoutError on timeout."""
        m = _make_v5_mock()
        p = MQTTProducer(
            MQTTConnectionConfig(
                use_tls=False,
                connect_timeout_seconds=0.01,
            ),
            mqtt_client=m,
        )

        with self.assertRaises(
            ConnectionTimeoutError,
        ):
            await p.connect()

        self.assertTrue(m.loop_stop.called)

    async def test_connect_start_failure(
        self,
    ) -> None:
        """Wrap OSError from connect_async."""
        m = _make_v5_mock()
        m.connect_async.side_effect = OSError(
            "boom",
        )

        p = MQTTProducer(
            MQTTConnectionConfig(use_tls=False),
            mqtt_client=m,
        )

        with self.assertRaises(MQTTProducerError):
            await p.connect()

    async def test_connect_early_return(
        self,
    ) -> None:
        """Skip connect when already running."""
        m = _make_v5_mock()
        p = MQTTProducer(
            MQTTConnectionConfig(use_tls=False),
            mqtt_client=m,
        )

        p._running = True
        p._connected_event.set()
        await p.connect()

        self.assertFalse(m.connect_async.called)

    async def test_disconnect_success(
        self,
    ) -> None:
        """Complete a graceful disconnect."""
        m = _make_v5_mock()
        p = MQTTProducer(
            MQTTConnectionConfig(
                use_tls=False,
                disconnect_timeout_seconds=0.1,
            ),
            mqtt_client=m,
        )
        p._running = True
        p._loop = asyncio.get_running_loop()

        # Resolve the disconnect future immediately
        def _resolve_disconnect(
            *a: object,
            **kw: object,
        ) -> None:
            """Simulate broker DISCONNECT ack."""
            fut = p._disconnect_future
            if fut and not fut.done():
                fut.set_result(None)

        m.disconnect.side_effect = _resolve_disconnect

        await p.disconnect()

        self.assertFalse(p._running)

    async def test_disconnect_not_running(
        self,
    ) -> None:
        """Return immediately when not running."""
        m = _make_v5_mock()
        p = MQTTProducer(
            MQTTConnectionConfig(use_tls=False),
            mqtt_client=m,
        )

        await p.disconnect()

        self.assertFalse(m.disconnect.called)

    async def test_disconnect_timeout(
        self,
    ) -> None:
        """Fall back to stop() on disconnect timeout."""
        m = _make_v5_mock()
        p = MQTTProducer(
            MQTTConnectionConfig(
                use_tls=False,
                disconnect_timeout_seconds=0.01,
            ),
            mqtt_client=m,
        )
        p._running = True

        await p.disconnect()

        self.assertFalse(p._running)
        self.assertTrue(m.loop_stop.called)

    async def test_disconnect_os_error_swallowed(
        self,
    ) -> None:
        """Swallow OSError from the disconnect call."""
        m = _make_v5_mock()
        m.disconnect.side_effect = OSError(
            "socket gone",
        )
        log = MagicMock()

        p = MQTTProducer(
            MQTTConnectionConfig(
                use_tls=False,
                disconnect_timeout_seconds=0.01,
            ),
            mqtt_client=m,
            log=log,
        )
        p._running = True

        await p.disconnect()

        self.assertTrue(log.debug.called)
        self.assertFalse(p._running)


# ==================================================================
# Thread-safe state bridges
# ==================================================================


class TestMQTTProducerThreadSafe(
    unittest.IsolatedAsyncioTestCase,
):
    """Verify thread-to-asyncio state bridges."""

    async def test_threadsafe_connected_no_loop(
        self,
    ) -> None:
        """Do nothing when no event loop is set."""
        p = MQTTProducer(
            MQTTConnectionConfig(use_tls=False),
            mqtt_client=_make_v5_mock(),
        )
        p._loop = None
        p._threadsafe_connected(connected=True)
        p._threadsafe_connected(connected=False)

    async def test_threadsafe_connected_with_loop(
        self,
    ) -> None:
        """Set the connected event via the loop."""
        p = MQTTProducer(
            MQTTConnectionConfig(use_tls=False),
            mqtt_client=_make_v5_mock(),
        )
        p._loop = asyncio.get_running_loop()

        p._threadsafe_connected(connected=True)
        await asyncio.sleep(0)
        self.assertTrue(p.is_connected)

        p._threadsafe_connected(connected=False)
        await asyncio.sleep(0)
        self.assertFalse(p.is_connected)

    async def test_resolve_connect_success(
        self,
    ) -> None:
        """Resolve the connect future on success."""
        p = MQTTProducer(
            MQTTConnectionConfig(use_tls=False),
            mqtt_client=_make_v5_mock(),
        )
        p._loop = asyncio.get_running_loop()
        p._connect_future = p._loop.create_future()

        p._threadsafe_resolve_connect(
            ok=True,
            error=None,
        )
        await asyncio.sleep(0)

        self.assertTrue(p._connect_future.done())
        self.assertIsNone(p._connect_future.result())

    async def test_resolve_connect_failure(
        self,
    ) -> None:
        """Reject the connect future on failure."""
        p = MQTTProducer(
            MQTTConnectionConfig(use_tls=False),
            mqtt_client=_make_v5_mock(),
        )
        p._loop = asyncio.get_running_loop()
        p._connect_future = p._loop.create_future()

        err = MQTTProducerError("test")
        p._threadsafe_resolve_connect(
            ok=False,
            error=err,
        )
        await asyncio.sleep(0)

        self.assertTrue(p._connect_future.done())
        with self.assertRaises(MQTTProducerError):
            p._connect_future.result()

    async def test_resolve_connect_already_done(
        self,
    ) -> None:
        """Skip resolution when future is done."""
        p = MQTTProducer(
            MQTTConnectionConfig(use_tls=False),
            mqtt_client=_make_v5_mock(),
        )
        p._loop = asyncio.get_running_loop()
        p._connect_future = p._loop.create_future()
        p._connect_future.set_result(None)

        # Should not raise
        p._threadsafe_resolve_connect(
            ok=True,
            error=None,
        )
        await asyncio.sleep(0)

    async def test_resolve_connect_no_loop(
        self,
    ) -> None:
        """Do nothing when no event loop is set."""
        p = MQTTProducer(
            MQTTConnectionConfig(use_tls=False),
            mqtt_client=_make_v5_mock(),
        )
        p._loop = None
        p._threadsafe_resolve_connect(
            ok=True,
            error=None,
        )

    async def test_resolve_disconnect_success(
        self,
    ) -> None:
        """Resolve the disconnect future."""
        p = MQTTProducer(
            MQTTConnectionConfig(use_tls=False),
            mqtt_client=_make_v5_mock(),
        )
        p._loop = asyncio.get_running_loop()
        p._disconnect_future = p._loop.create_future()

        p._threadsafe_resolve_disconnect()
        await asyncio.sleep(0)

        self.assertTrue(
            p._disconnect_future.done(),
        )

    async def test_resolve_disconnect_no_loop(
        self,
    ) -> None:
        """Do nothing when no event loop is set."""
        p = MQTTProducer(
            MQTTConnectionConfig(use_tls=False),
            mqtt_client=_make_v5_mock(),
        )
        p._loop = None
        p._threadsafe_resolve_disconnect()

    async def test_resolve_disconnect_already_done(
        self,
    ) -> None:
        """Skip resolution when future is done."""
        p = MQTTProducer(
            MQTTConnectionConfig(use_tls=False),
            mqtt_client=_make_v5_mock(),
        )
        p._loop = asyncio.get_running_loop()
        p._disconnect_future = p._loop.create_future()
        p._disconnect_future.set_result(None)

        p._threadsafe_resolve_disconnect()
        await asyncio.sleep(0)


# ==================================================================
# Callback dispatch
# ==================================================================


class TestMQTTProducerCallbacks(
    unittest.IsolatedAsyncioTestCase,
):
    """Verify callback dispatch from the network thread."""

    async def test_on_connect_success(self) -> None:
        """Set connected on rc=0."""
        m = _make_v5_mock()
        p = MQTTProducer(
            MQTTConnectionConfig(use_tls=False),
            mqtt_client=m,
        )
        p._loop = asyncio.get_running_loop()

        p._on_connect(m, None, {}, reason_code=0)
        await asyncio.sleep(0)

        self.assertTrue(p.is_connected)

    async def test_on_connect_failure(self) -> None:
        """Clear connected on rc != 0."""
        m = _make_v5_mock()
        p = MQTTProducer(
            MQTTConnectionConfig(use_tls=False),
            mqtt_client=m,
        )
        p._loop = asyncio.get_running_loop()

        p._on_connect(m, None, {}, reason_code=1)
        await asyncio.sleep(0)

        self.assertFalse(p.is_connected)

    async def test_on_disconnect_clean(
        self,
    ) -> None:
        """Clear connected on clean disconnect."""
        m = _make_v5_mock()
        p = MQTTProducer(
            MQTTConnectionConfig(use_tls=False),
            mqtt_client=m,
        )
        p._loop = asyncio.get_running_loop()
        p._threadsafe_connected(connected=True)
        await asyncio.sleep(0)

        p._on_disconnect(
            m,
            None,
            {},
            reason_code=0,
        )
        await asyncio.sleep(0)

        self.assertFalse(p.is_connected)

    async def test_on_disconnect_unclean(
        self,
    ) -> None:
        """Clear connected and warn on unclean disconnect."""
        m = _make_v5_mock()
        log = MagicMock()
        p = MQTTProducer(
            MQTTConnectionConfig(use_tls=False),
            mqtt_client=m,
            log=log,
        )
        p._loop = asyncio.get_running_loop()
        p._threadsafe_connected(connected=True)
        await asyncio.sleep(0)

        p._on_disconnect(
            m,
            None,
            {},
            reason_code=1,
        )
        await asyncio.sleep(0)

        self.assertFalse(p.is_connected)
        self.assertTrue(log.warning.called)

    async def test_on_publish_is_noop(
        self,
    ) -> None:
        """Complete without raising."""
        m = _make_v5_mock()
        p = MQTTProducer(
            MQTTConnectionConfig(use_tls=False),
            mqtt_client=m,
        )
        p._on_publish(m, None, 1)  # must not raise


# ==================================================================
# Stop
# ==================================================================


class TestMQTTProducerStop(unittest.TestCase):
    """Verify stop idempotency and error handling."""

    def test_stop_when_not_running(self) -> None:
        """Return early without calling loop_stop."""
        m = _make_v5_mock()
        p = MQTTProducer(
            MQTTConnectionConfig(use_tls=False),
            mqtt_client=m,
        )
        p.stop()
        self.assertFalse(m.loop_stop.called)

    def test_stop_calls_loop_stop(self) -> None:
        """Call loop_stop when running."""
        m = _make_v5_mock()
        p = MQTTProducer(
            MQTTConnectionConfig(use_tls=False),
            mqtt_client=m,
        )
        p._running = True
        p.stop()
        self.assertTrue(m.loop_stop.called)
        self.assertFalse(p._running)

    def test_stop_swallows_os_error(self) -> None:
        """Swallow OSError from loop_stop."""
        m = _make_v5_mock()
        m.loop_stop.side_effect = OSError("fail")
        log = MagicMock()

        p = MQTTProducer(
            MQTTConnectionConfig(use_tls=False),
            mqtt_client=m,
            log=log,
        )
        p._running = True
        p.stop()

        self.assertTrue(log.debug.called)
        self.assertFalse(p._running)


# ==================================================================
# Factory
# ==================================================================


class TestMQTTProducerFactory(unittest.TestCase):
    """Verify the factory classmethod."""

    def test_with_client_id_prefix(self) -> None:
        """Format client_id as prefix_NNNN."""
        p = MQTTProducer.with_client_id_prefix(
            MQTTConnectionConfig(use_tls=False),
            prefix="prefix",
            index=7,
        )
        self.assertEqual(
            p.client_id,
            "prefix_0007",
        )

    def test_with_client_id_prefix_zero(
        self,
    ) -> None:
        """Handle index zero correctly."""
        p = MQTTProducer.with_client_id_prefix(
            MQTTConnectionConfig(use_tls=False),
            prefix="edge",
            index=0,
        )
        self.assertEqual(
            p.client_id,
            "edge_0000",
        )


if __name__ == "__main__":
    unittest.main()
