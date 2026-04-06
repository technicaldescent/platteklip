# SPDX-FileCopyrightText: 2025 technical descent
# SPDX-License-Identifier: Apache-2.0

"""Tests for the mqtt_producer entry point.

Covers :func:`_parse_env_int` and the :func:`main`
simulation loop, including environment variable handling,
signal generation, edge metric recording, MQTT publishing,
topic structure, payload schema, TLS configuration paths,
and exception-path teardown.
"""

import asyncio
import json
import types
import unittest
from unittest.mock import (
    AsyncMock,
    MagicMock,
    patch,
)

from platteklip.instrumentation.edge_semconv import (
    EDGE_SOURCE_ID,
    EDGE_SOURCE_TYPE,
    EDGE_VEHICLE_ID,
)
from platteklip.mqtt_producer import (
    MQTTProducerError,
    _parse_env_int,
    main,
)

# ----------------------------------------------------------
# _parse_env_int
# ----------------------------------------------------------


class TestParseEnvInt(unittest.TestCase):
    """Verify the _parse_env_int helper."""

    def test_returns_default_when_unset(
        self,
    ) -> None:
        """Fall back to the default string value."""
        with patch.dict(
            "os.environ",
            {},
            clear=True,
        ):
            result = _parse_env_int(
                "NONEXISTENT_VAR",
                "42",
            )
        self.assertEqual(result, 42)

    def test_returns_env_value_when_set(
        self,
    ) -> None:
        """Prefer the environment variable over default."""
        with patch.dict(
            "os.environ",
            {"MY_PORT": "9999"},
        ):
            result = _parse_env_int(
                "MY_PORT",
                "1234",
            )
        self.assertEqual(result, 9999)

    def test_raises_system_exit_on_invalid(
        self,
    ) -> None:
        """Exit on non-integer environment values."""
        with patch.dict(
            "os.environ",
            {"BAD_VAR": "notanint"},
        ):
            with self.assertRaises(SystemExit):
                _parse_env_int("BAD_VAR", "0")


# ----------------------------------------------------------
# Helpers for main() tests
# ----------------------------------------------------------

_MAIN_ENV: dict[str, str] = {
    "MQTT_HOST": "test-broker",
    "MQTT_PORT": "1883",
    "MQTT_USE_TLS": "false",
    "MESSAGES_PER_SECOND": "10",
    "HEALTH_PORT": "18080",
    "VEHICLE_ID": "test_vehicle",
    "SOURCE_ID": "test_source",
}

_TLS_ENV: dict[str, str] = {
    **_MAIN_ENV,
    "MQTT_USE_TLS": "true",
    "MQTT_TLS_CHECK_HOSTNAME": "false",
    "MQTT_CA_FILE": "/test/ca.crt",
    "MQTT_CERT_FILE": "/test/cert.crt",
    "MQTT_KEY_FILE": "/test/key.key",
}


class _PatchMainDeps:
    """Combined patch context for main().

    Stubs out MQTTProducer, SignalGenerator,
    HealthServer, configure_telemetry, and
    shutdown_telemetry so that main() can run
    without real infrastructure.
    """

    def __enter__(self) -> dict[str, MagicMock]:
        """Activate all patches and return the mocks."""
        self._patches = {
            "MQTTProducer": patch(
                "platteklip.mqtt_producer" ".MQTTProducer",
            ),
            "SignalGenerator": patch(
                "platteklip.mqtt_producer" ".SignalGenerator",
            ),
            "HealthServer": patch(
                "platteklip.mqtt_producer" ".HealthServer",
            ),
            "configure_telemetry": patch(
                "platteklip.instrumentation" ".setup.configure_telemetry",
            ),
            "shutdown_telemetry": patch(
                "platteklip.instrumentation" ".setup.shutdown_telemetry",
            ),
        }
        self._mocks = {name: p.__enter__() for name, p in self._patches.items()}
        return self._mocks

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: types.TracebackType | None,
    ) -> None:
        """Deactivate all patches."""
        for p in reversed(self._patches.values()):
            p.__exit__(exc_type, exc_val, exc_tb)


def _patch_main_deps() -> _PatchMainDeps:
    """Return a combined patch context for main()."""
    return _PatchMainDeps()


def _build_mock_producer() -> MagicMock:
    """Build a MQTTProducer mock with async methods."""
    producer = MagicMock()
    producer.connect = AsyncMock()
    producer.disconnect = AsyncMock()
    producer.is_connected = True
    producer.client_id = "edge_telemetry_producer"
    producer.stats = MagicMock(
        published_accepted=0,
        publish_failures=0,
        queue_full=0,
        not_connected=0,
        rejected_qos=0,
    )
    producer.publish.return_value = True
    producer.record_edge_metric = MagicMock()
    return producer


def _build_mock_generator(
    tick_count: int = 1,
) -> MagicMock:
    """Build a SignalGenerator mock.

    Return *tick_count* subsystem dicts, then raise
    ``CancelledError`` to break the loop.
    """
    sample: dict[str, dict[str, float]] = {
        "conveyor": {
            "edge.conveyor.frequency": 2.5,
            "edge.conveyor.running": 1.0,
        },
        "vehicle": {
            "edge.vehicle.speed": 0.0,
        },
    }
    gen = MagicMock()
    gen.tick_by_subsystem = MagicMock(
        side_effect=([sample] * tick_count + [asyncio.CancelledError()]),
    )
    return gen


# ----------------------------------------------------------
# Environment variable propagation
# ----------------------------------------------------------


class TestMainEnvDefaults(
    unittest.IsolatedAsyncioTestCase,
):
    """Verify environment variable propagation."""

    async def test_vehicle_id_from_env(self) -> None:
        """Pass VEHICLE_ID into edge attributes."""
        producer = _build_mock_producer()
        gen = _build_mock_generator()

        with (
            patch.dict("os.environ", _MAIN_ENV),
            _patch_main_deps() as mocks,
        ):
            mocks["MQTTProducer"].return_value = producer
            mocks["SignalGenerator"].return_value = gen
            await main()

        record_calls = producer.record_edge_metric.call_args_list
        self.assertTrue(len(record_calls) > 0)
        attrs = record_calls[0][1].get(
            "attributes",
            (record_calls[0][0][2] if len(record_calls[0][0]) > 2 else {}),
        )
        self.assertEqual(
            attrs[EDGE_VEHICLE_ID],
            "test_vehicle",
        )
        self.assertEqual(
            attrs[EDGE_SOURCE_ID],
            "test_source",
        )
        self.assertEqual(
            attrs[EDGE_SOURCE_TYPE],
            "simulation",
        )

    async def test_tls_disabled_via_env(
        self,
    ) -> None:
        """Set use_tls=False when MQTT_USE_TLS=false."""
        producer = _build_mock_producer()
        gen = _build_mock_generator()

        with (
            patch.dict("os.environ", _MAIN_ENV),
            _patch_main_deps() as mocks,
        ):
            mocks["MQTTProducer"].return_value = producer
            mocks["SignalGenerator"].return_value = gen
            await main()

        config_call = mocks["MQTTProducer"].call_args
        config = config_call[0][0]
        self.assertFalse(config.use_tls)

    async def test_tls_enabled_via_env(
        self,
    ) -> None:
        """Set use_tls=True and propagate cert paths."""
        producer = _build_mock_producer()
        gen = _build_mock_generator()

        with (
            patch.dict("os.environ", _TLS_ENV),
            _patch_main_deps() as mocks,
        ):
            mocks["MQTTProducer"].return_value = producer
            mocks["SignalGenerator"].return_value = gen
            await main()

        config_call = mocks["MQTTProducer"].call_args
        config = config_call[0][0]
        self.assertTrue(config.use_tls)
        self.assertFalse(config.tls_check_hostname)
        self.assertEqual(
            config.ca_file,
            "/test/ca.crt",
        )
        self.assertEqual(
            config.cert_file,
            "/test/cert.crt",
        )
        self.assertEqual(
            config.key_file,
            "/test/key.key",
        )

    async def test_default_check_hostname(
        self,
    ) -> None:
        """Default MQTT_TLS_CHECK_HOSTNAME to true."""
        producer = _build_mock_producer()
        gen = _build_mock_generator()

        env = {
            **_MAIN_ENV,
            "MQTT_USE_TLS": "true",
        }

        with (
            patch.dict("os.environ", env),
            _patch_main_deps() as mocks,
        ):
            mocks["MQTTProducer"].return_value = producer
            mocks["SignalGenerator"].return_value = gen
            await main()

        config_call = mocks["MQTTProducer"].call_args
        config = config_call[0][0]
        self.assertTrue(config.tls_check_hostname)


# ----------------------------------------------------------
# Simulation loop behaviour
# ----------------------------------------------------------


class TestMainSimulationLoop(
    unittest.IsolatedAsyncioTestCase,
):
    """Verify the core simulation loop."""

    async def test_record_edge_metric_called(
        self,
    ) -> None:
        """Record every signal on each tick."""
        producer = _build_mock_producer()
        gen = _build_mock_generator(tick_count=1)

        with (
            patch.dict("os.environ", _MAIN_ENV),
            _patch_main_deps() as mocks,
        ):
            mocks["MQTTProducer"].return_value = producer
            mocks["SignalGenerator"].return_value = gen
            await main()

        # 3 signals across 2 subsystems = 3 calls.
        self.assertEqual(
            producer.record_edge_metric.call_count,
            3,
        )

    async def test_publish_called_per_subsystem(
        self,
    ) -> None:
        """Publish one message per subsystem per tick."""
        producer = _build_mock_producer()
        gen = _build_mock_generator(tick_count=1)

        with (
            patch.dict("os.environ", _MAIN_ENV),
            _patch_main_deps() as mocks,
        ):
            mocks["MQTTProducer"].return_value = producer
            mocks["SignalGenerator"].return_value = gen
            await main()

        self.assertEqual(
            producer.publish.call_count,
            2,
        )

    async def test_topic_structure(self) -> None:
        """Format topics as edge/telemetry/{vid}/{sub}."""
        producer = _build_mock_producer()
        gen = _build_mock_generator(tick_count=1)

        with (
            patch.dict("os.environ", _MAIN_ENV),
            _patch_main_deps() as mocks,
        ):
            mocks["MQTTProducer"].return_value = producer
            mocks["SignalGenerator"].return_value = gen
            await main()

        topics = [c[0][0] for c in producer.publish.call_args_list]
        for topic in topics:
            self.assertTrue(
                topic.startswith(
                    "edge/telemetry/test_vehicle/",
                ),
                f"Bad topic: {topic}",
            )

        subsystems = [t.split("/")[-1] for t in topics]
        self.assertIn("conveyor", subsystems)
        self.assertIn("vehicle", subsystems)

    async def test_payload_schema(self) -> None:
        """Include required keys in JSON payloads."""
        producer = _build_mock_producer()
        gen = _build_mock_generator(tick_count=1)

        with (
            patch.dict("os.environ", _MAIN_ENV),
            _patch_main_deps() as mocks,
        ):
            mocks["MQTTProducer"].return_value = producer
            mocks["SignalGenerator"].return_value = gen
            await main()

        raw = producer.publish.call_args_list[0]
        payload = json.loads(raw[0][1])

        self.assertEqual(
            payload["vehicle_id"],
            "test_vehicle",
        )
        self.assertEqual(
            payload["source_id"],
            "test_source",
        )
        self.assertEqual(
            payload["source_type"],
            "simulation",
        )
        self.assertIn("timestamp_ns", payload)
        self.assertIsInstance(
            payload["timestamp_ns"],
            int,
        )
        self.assertIn("signals", payload)
        self.assertIsInstance(
            payload["signals"],
            dict,
        )

    async def test_publish_qos_is_one(self) -> None:
        """Publish all messages at QoS 1."""
        producer = _build_mock_producer()
        gen = _build_mock_generator(tick_count=1)

        with (
            patch.dict("os.environ", _MAIN_ENV),
            _patch_main_deps() as mocks,
        ):
            mocks["MQTTProducer"].return_value = producer
            mocks["SignalGenerator"].return_value = gen
            await main()

        for c in producer.publish.call_args_list:
            self.assertEqual(c[1].get("qos"), 1)


# ----------------------------------------------------------
# Multiple ticks
# ----------------------------------------------------------


class TestMainMultipleTicks(
    unittest.IsolatedAsyncioTestCase,
):
    """Verify correct scaling over multiple ticks."""

    async def test_three_ticks_triple_calls(
        self,
    ) -> None:
        """Scale publish and record calls linearly."""
        producer = _build_mock_producer()
        gen = _build_mock_generator(tick_count=3)

        with (
            patch.dict("os.environ", _MAIN_ENV),
            _patch_main_deps() as mocks,
        ):
            mocks["MQTTProducer"].return_value = producer
            mocks["SignalGenerator"].return_value = gen
            await main()

        # 3 ticks x 2 subsystems = 6 publishes
        self.assertEqual(
            producer.publish.call_count,
            6,
        )
        # 3 ticks x 3 signals = 9 recordings
        self.assertEqual(
            producer.record_edge_metric.call_count,
            9,
        )


# ----------------------------------------------------------
# Exception paths and teardown
# ----------------------------------------------------------


class TestMainExceptionPaths(
    unittest.IsolatedAsyncioTestCase,
):
    """Verify cleanup on all exit paths."""

    async def test_cancelled_error_triggers_cleanup(
        self,
    ) -> None:
        """Disconnect and shut down on cancellation."""
        producer = _build_mock_producer()
        gen = _build_mock_generator(tick_count=0)

        with (
            patch.dict("os.environ", _MAIN_ENV),
            _patch_main_deps() as mocks,
        ):
            mocks["MQTTProducer"].return_value = producer
            mocks["SignalGenerator"].return_value = gen
            await main()

        producer.disconnect.assert_awaited_once()
        mocks["shutdown_telemetry"].assert_called()

    async def test_producer_error_triggers_cleanup(
        self,
    ) -> None:
        """Disconnect and shut down on producer error."""
        producer = _build_mock_producer()
        producer.connect = AsyncMock(
            side_effect=MQTTProducerError("boom"),
        )

        with (
            patch.dict("os.environ", _MAIN_ENV),
            _patch_main_deps() as mocks,
        ):
            mocks["MQTTProducer"].return_value = producer
            await main()

        producer.disconnect.assert_awaited_once()
        mocks["shutdown_telemetry"].assert_called()

    async def test_health_server_stopped_on_exit(
        self,
    ) -> None:
        """Start and stop the health server."""
        producer = _build_mock_producer()
        gen = _build_mock_generator(tick_count=0)
        health = MagicMock()

        with (
            patch.dict("os.environ", _MAIN_ENV),
            _patch_main_deps() as mocks,
        ):
            mocks["MQTTProducer"].return_value = producer
            mocks["SignalGenerator"].return_value = gen
            mocks["HealthServer"].return_value = health
            await main()

        health.start.assert_called_once()
        health.stop.assert_called_once()

    async def test_configure_and_shutdown_called(
        self,
    ) -> None:
        """Invoke telemetry setup and teardown."""
        producer = _build_mock_producer()
        gen = _build_mock_generator(tick_count=0)

        with (
            patch.dict("os.environ", _MAIN_ENV),
            _patch_main_deps() as mocks,
        ):
            mocks["MQTTProducer"].return_value = producer
            mocks["SignalGenerator"].return_value = gen
            await main()

        mocks["configure_telemetry"].assert_called_once()
        mocks["shutdown_telemetry"].assert_called_once()


# ----------------------------------------------------------
# Sleep interval
# ----------------------------------------------------------


class TestMainSleepInterval(
    unittest.IsolatedAsyncioTestCase,
):
    """Verify sleep interval from MESSAGES_PER_SECOND."""

    async def test_zero_mps_uses_one_second(
        self,
    ) -> None:
        """Fall back to 1.0s when rate is zero."""
        producer = _build_mock_producer()
        gen = _build_mock_generator(tick_count=1)

        env = {
            **_MAIN_ENV,
            "MESSAGES_PER_SECOND": "0",
        }

        with (
            patch.dict("os.environ", env),
            _patch_main_deps() as mocks,
            patch(
                "platteklip.mqtt_producer" ".asyncio.sleep",
                new_callable=AsyncMock,
            ) as mock_sleep,
        ):
            mocks["MQTTProducer"].return_value = producer
            mocks["SignalGenerator"].return_value = gen
            await main()

        first_sleep = mock_sleep.call_args_list[0]
        self.assertEqual(first_sleep[0][0], 1.0)

    async def test_custom_mps_sets_interval(
        self,
    ) -> None:
        """Compute 1/mps as the sleep interval."""
        producer = _build_mock_producer()
        gen = _build_mock_generator(tick_count=1)

        env = {
            **_MAIN_ENV,
            "MESSAGES_PER_SECOND": "5",
        }

        with (
            patch.dict("os.environ", env),
            _patch_main_deps() as mocks,
            patch(
                "platteklip.mqtt_producer" ".asyncio.sleep",
                new_callable=AsyncMock,
            ) as mock_sleep,
        ):
            mocks["MQTTProducer"].return_value = producer
            mocks["SignalGenerator"].return_value = gen
            await main()

        first_sleep = mock_sleep.call_args_list[0]
        self.assertAlmostEqual(
            first_sleep[0][0],
            0.2,
        )


if __name__ == "__main__":
    unittest.main()
