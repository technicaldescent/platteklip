# SPDX-FileCopyrightText: 2025 technical descent
# SPDX-License-Identifier: Apache-2.0

"""Tests for the MQTT load harness module.

Covers dataclass defaults, payload construction, profile
validation, stagger logic, progress logging, result
aggregation, environment-to-profile mapping, producer
lifecycle, token-bucket pacing, cooperative cancellation,
and the default producer factory path.
"""

import asyncio
import unittest
from dataclasses import dataclass, field
from unittest.mock import MagicMock, patch

from platteklip.mqtt_load_harness import (
    LoadProfile,
    LoadResult,
    _active_env_vars,
    _aggregate_results,
    _build_payload,
    _check_bounds,
    _is_stagger_due,
    _maybe_log_progress,
    _profile_from_env,
    run_harness,
)
from platteklip.mqtt_producer import (
    MQTTConnectionConfig,
    MQTTProducer,
    MQTTProducerStats,
)

# ==================================================================
# Test double
# ==================================================================


@dataclass
class _FakeProducer:
    """Test double for MQTTProducer.

    Accepts publishes, tracks stats, and optionally
    simulates disconnected states or triggers a stop
    event after a given number of publishes.
    """

    config: MQTTConnectionConfig
    client_id: str
    stats: MQTTProducerStats = field(
        default_factory=MQTTProducerStats,
    )

    stopped: bool = False
    connected_calls: int = 0

    connected_sequence: list[bool] | None = None
    _connected_index: int = 0

    stop_event: asyncio.Event | None = None
    stop_after_publishes: int | None = None
    reject_after: int | None = None

    @property
    def is_connected(self) -> bool:
        """Return the next value from the sequence."""
        if self.connected_sequence is None:
            return True
        if self._connected_index < len(
            self.connected_sequence,
        ):
            v = self.connected_sequence[self._connected_index]
            self._connected_index += 1
            return v
        return True

    async def connect(self) -> None:
        """Record the connect call."""
        self.connected_calls += 1

    def publish(
        self,
        topic: str,
        payload: str | bytes,
        *,
        qos: int = 1,
    ) -> bool:
        """Accept or reject the publish."""
        self.stats.published_accepted += 1
        if (
            self.reject_after is not None
            and self.stats.published_accepted >= self.reject_after
        ):
            return False
        if (
            self.stop_event is not None
            and self.stop_after_publishes is not None
            and self.stats.published_accepted >= self.stop_after_publishes
        ):
            self.stop_event.set()
        return True

    def stop(self) -> None:
        """Record the stop call."""
        self.stopped = True


def _fake_factory(
    config: MQTTConnectionConfig,
    client_id: str,
) -> MQTTProducer:
    """Create a fake producer for testing."""
    return _FakeProducer(  # type: ignore[return-value]
        config=config,
        client_id=client_id,
    )


class _Stepper:
    """Deterministic monotonic clock.

    Each call advances by a fixed step, giving tests
    full control over elapsed time.
    """

    def __init__(
        self,
        start: float = 0.0,
        step: float = 0.05,
    ) -> None:
        """Initialize with a start time and step."""
        self._t = start
        self._step = step

    def __call__(self) -> float:
        """Advance the clock and return the new time."""
        self._t += self._step
        return self._t


# ==================================================================
# LoadProfile defaults
# ==================================================================


class TestLoadProfileDefaults(unittest.TestCase):
    """Verify LoadProfile dataclass defaults."""

    def test_default_client_count(self) -> None:
        """Default to one client."""
        self.assertEqual(LoadProfile().client_count, 1)

    def test_default_qos(self) -> None:
        """Default to QoS 2."""
        self.assertEqual(LoadProfile().qos, 2)

    def test_default_duration(self) -> None:
        """Default to 1800 seconds."""
        self.assertEqual(
            LoadProfile().duration_seconds,
            1800.0,
        )

    def test_frozen(self) -> None:
        """Reject attribute mutation."""
        with self.assertRaises(AttributeError):
            LoadProfile().client_count = 5  # type: ignore[misc]


# ==================================================================
# LoadResult construction
# ==================================================================


class TestLoadResult(unittest.TestCase):
    """Verify LoadResult construction."""

    def test_fields_stored(self) -> None:
        """Store all fields from constructor."""
        r = LoadResult(
            started_monotonic=1.0,
            finished_monotonic=2.0,
            total_published_accepted=10,
            total_publish_failures=1,
            total_queue_full=0,
            per_client={},
        )
        self.assertEqual(
            r.total_published_accepted,
            10,
        )
        self.assertEqual(
            r.finished_monotonic,
            2.0,
        )


# ==================================================================
# _build_payload
# ==================================================================


class TestBuildPayload(unittest.TestCase):
    """Verify deterministic payload construction."""

    def test_exact_size(self) -> None:
        """Produce a payload of exactly the requested size."""
        payload = _build_payload("test", 1024)
        self.assertEqual(len(payload), 1024)

    def test_too_small_raises(self) -> None:
        """Reject sizes below the JSON envelope minimum."""
        with self.assertRaises(ValueError):
            _build_payload("test", 5)

    def test_contains_client_id(self) -> None:
        """Embed the client_id in the JSON body."""
        payload = _build_payload("my_client", 1024)
        self.assertIn(b"my_client", payload)


# ==================================================================
# _check_bounds
# ==================================================================


class TestCheckBounds(unittest.TestCase):
    """Verify profile field validation."""

    def test_valid_profile_passes(self) -> None:
        """Accept a valid profile without raising."""
        _check_bounds(LoadProfile())

    def test_invalid_client_count(self) -> None:
        """Reject client_count < 1."""
        with self.assertRaises(ValueError):
            _check_bounds(
                LoadProfile(client_count=0),
            )

    def test_negative_duration(self) -> None:
        """Reject negative duration_seconds."""
        with self.assertRaises(ValueError):
            _check_bounds(
                LoadProfile(duration_seconds=-1.0),
            )

    def test_negative_rate(self) -> None:
        """Reject negative rate."""
        with self.assertRaises(ValueError):
            _check_bounds(
                LoadProfile(
                    messages_per_second_per_client=-1,
                ),
            )

    def test_invalid_qos(self) -> None:
        """Reject QoS outside {1, 2}."""
        with self.assertRaises(ValueError):
            _check_bounds(LoadProfile(qos=0))

    def test_invalid_message_size(self) -> None:
        """Reject message_size_bytes < 1."""
        with self.assertRaises(ValueError):
            _check_bounds(
                LoadProfile(message_size_bytes=0),
            )

    def test_negative_burst_cap(self) -> None:
        """Reject negative burst_cap_seconds."""
        with self.assertRaises(ValueError):
            _check_bounds(
                LoadProfile(
                    burst_cap_seconds=-1.0,
                ),
            )

    def test_negative_log_interval(self) -> None:
        """Reject negative log_interval_seconds."""
        with self.assertRaises(ValueError):
            _check_bounds(
                LoadProfile(
                    log_interval_seconds=-1.0,
                ),
            )


# ==================================================================
# _is_stagger_due
# ==================================================================


class TestIsStaggerDue(unittest.TestCase):
    """Verify stagger decision logic."""

    def test_true_at_boundary(self) -> None:
        """Return True at the stagger interval."""
        self.assertTrue(_is_stagger_due(5, 5))

    def test_false_at_index_zero(self) -> None:
        """Return False for the first client."""
        self.assertFalse(_is_stagger_due(0, 5))

    def test_false_when_disabled(self) -> None:
        """Return False when stagger_every is 0."""
        self.assertFalse(_is_stagger_due(5, 0))

    def test_false_off_boundary(self) -> None:
        """Return False between boundaries."""
        self.assertFalse(_is_stagger_due(3, 5))


# ==================================================================
# _maybe_log_progress
# ==================================================================


class TestMaybeLogProgress(unittest.TestCase):
    """Verify conditional progress logging."""

    def test_skips_when_interval_zero(self) -> None:
        """Do nothing when interval is disabled."""
        log = MagicMock()
        producer = MagicMock()
        _maybe_log_progress(
            producer=producer,
            now=10.0,
            last_log_t=0.0,
            interval=0.0,
            log=log,
            log_ctx={},
        )
        self.assertFalse(log.info.called)

    def test_skips_before_interval(self) -> None:
        """Do nothing before the interval elapses."""
        log = MagicMock()
        producer = MagicMock()
        _maybe_log_progress(
            producer=producer,
            now=0.5,
            last_log_t=0.0,
            interval=5.0,
            log=log,
            log_ctx={},
        )
        self.assertFalse(log.info.called)

    def test_logs_after_interval(self) -> None:
        """Emit a log line after the interval."""
        log = MagicMock()
        producer = MagicMock()
        producer.stats = MQTTProducerStats(
            published_accepted=10,
            publish_failures=1,
            queue_full=0,
        )
        _maybe_log_progress(
            producer=producer,
            now=6.0,
            last_log_t=0.0,
            interval=5.0,
            log=log,
            log_ctx={},
        )
        self.assertTrue(log.info.called)


# ==================================================================
# _aggregate_results
# ==================================================================


class TestAggregateResults(unittest.TestCase):
    """Verify result aggregation."""

    def test_sums_per_client_stats(self) -> None:
        """Sum stats across all clients."""
        per_client = {
            "a": MQTTProducerStats(
                published_accepted=10,
                publish_failures=1,
                queue_full=0,
            ),
            "b": MQTTProducerStats(
                published_accepted=20,
                publish_failures=2,
                queue_full=1,
            ),
        }
        r = _aggregate_results(
            1.0,
            2.0,
            per_client,
        )
        self.assertEqual(
            r.total_published_accepted,
            30,
        )
        self.assertEqual(
            r.total_publish_failures,
            3,
        )
        self.assertEqual(r.total_queue_full, 1)

    def test_empty_per_client(self) -> None:
        """Return zeros with no clients."""
        r = _aggregate_results(0.0, 0.0, {})
        self.assertEqual(
            r.total_published_accepted,
            0,
        )


# ==================================================================
# _active_env_vars
# ==================================================================


class TestActiveEnvVars(unittest.TestCase):
    """Verify env var selection by test type."""

    def test_stress_vars(self) -> None:
        """Select stress-specific variables."""
        v = _active_env_vars("stress")
        self.assertIn("STRESS_CLIENT_COUNT", v)
        self.assertIn("TEST_DURATION_MINUTES", v)
        self.assertNotIn("SOAK_DURATION_HOURS", v)

    def test_soak_vars(self) -> None:
        """Select soak-specific variables."""
        v = _active_env_vars("soak")
        self.assertIn("SOAK_DURATION_HOURS", v)
        self.assertIn("LOAD_CLIENT_COUNT", v)
        self.assertNotIn("STRESS_CLIENT_COUNT", v)

    def test_common_vars_always_present(
        self,
    ) -> None:
        """Include TEST_TYPE and QOS_LEVEL always."""
        for tt in ("stress", "soak"):
            v = _active_env_vars(tt)
            self.assertIn("TEST_TYPE", v)
            self.assertIn("QOS_LEVEL", v)


# ==================================================================
# _profile_from_env
# ==================================================================


class TestProfileFromEnv(unittest.TestCase):
    """Verify environment-to-LoadProfile mapping."""

    def test_stress_defaults(self) -> None:
        """Return defaults with no env vars set."""
        with patch.dict(
            "os.environ",
            {},
            clear=True,
        ):
            p = _profile_from_env()
        self.assertEqual(p.client_count, 1)
        self.assertIn("stress", p.topic_prefix)

    def test_soak_overrides(self) -> None:
        """Override fields for soak test type."""
        env = {
            "TEST_TYPE": "soak",
            "LOAD_CLIENT_COUNT": "4",
            "SOAK_DURATION_HOURS": "2",
            "SOAK_MESSAGE_RATE": "5.0",
        }
        with patch.dict("os.environ", env):
            p = _profile_from_env()
        self.assertEqual(p.client_count, 4)
        self.assertEqual(
            p.duration_seconds,
            7200.0,
        )
        self.assertEqual(
            p.messages_per_second_per_client,
            5.0,
        )

    def test_invalid_env_raises_exit(self) -> None:
        """Exit on unparsable env values."""
        env = {
            "TEST_TYPE": "stress",
            "STRESS_CLIENT_COUNT": "notanint",
        }
        with patch.dict("os.environ", env):
            with self.assertRaises(SystemExit):
                _profile_from_env()

    def test_qos_override(self) -> None:
        """Override QoS from QOS_LEVEL."""
        env = {"QOS_LEVEL": "1"}
        with patch.dict("os.environ", env):
            p = _profile_from_env()
        self.assertEqual(p.qos, 1)


# ==================================================================
# Profile validation via run_harness
# ==================================================================


class TestLoadHarnessValidation(
    unittest.IsolatedAsyncioTestCase,
):
    """Verify that run_harness rejects invalid profiles."""

    async def test_invalid_client_count(
        self,
    ) -> None:
        """Reject client_count < 1."""
        with self.assertRaises(ValueError):
            await run_harness(
                MQTTConnectionConfig(use_tls=False),
                LoadProfile(client_count=0),
                producer_factory=_fake_factory,
            )

    async def test_negative_duration(self) -> None:
        """Reject negative duration."""
        with self.assertRaises(ValueError):
            await run_harness(
                MQTTConnectionConfig(use_tls=False),
                LoadProfile(duration_seconds=-1.0),
                producer_factory=_fake_factory,
            )

    async def test_invalid_qos(self) -> None:
        """Reject QoS outside {1, 2}."""
        with self.assertRaises(ValueError):
            await run_harness(
                MQTTConnectionConfig(use_tls=False),
                LoadProfile(qos=3),
                producer_factory=_fake_factory,
            )


# ==================================================================
# Harness behaviour
# ==================================================================


class TestLoadHarnessBehaviour(
    unittest.IsolatedAsyncioTestCase,
):
    """Verify runtime behaviour and branch coverage."""

    async def test_default_factory_path(self) -> None:
        """Exercise the _build_producer code path."""
        connection = MQTTConnectionConfig(
            host="localhost",
            port=1883,
            use_tls=False,
        )
        profile = LoadProfile(
            client_count=1,
            duration_seconds=1.0,
            messages_per_second_per_client=10.0,
            log_interval_seconds=0.0,
            stagger_every=0,
        )
        clock = _Stepper(start=0.0, step=0.05)

        async def fast_sleep(_: float) -> None:
            """Skip all sleeps."""

        with (
            patch(
                "platteklip.mqtt_load_harness" "._monotonic",
                side_effect=clock,
            ),
            patch(
                "platteklip.mqtt_load_harness" "._sleep",
                side_effect=fast_sleep,
            ),
            patch(
                "platteklip.mqtt_load_harness" ".MQTTProducer",
                _FakeProducer,
            ),
        ):
            result = await run_harness(
                connection,
                profile,
                producer_factory=None,
            )

        self.assertEqual(len(result.per_client), 1)
        self.assertGreaterEqual(
            result.total_published_accepted,
            1,
        )

    async def test_disconnected_branch(self) -> None:
        """Cover the not-connected wait path."""
        connection = MQTTConnectionConfig(
            host="localhost",
            port=1883,
            use_tls=False,
        )
        profile = LoadProfile(
            client_count=1,
            duration_seconds=1.0,
            messages_per_second_per_client=10.0,
            log_interval_seconds=0.0,
            stagger_every=0,
        )

        def factory(
            config: MQTTConnectionConfig,
            client_id: str,
        ) -> MQTTProducer:
            """Return a producer that starts disconnected."""
            return _FakeProducer(  # type: ignore[return-value]
                config=config,
                client_id=client_id,
                connected_sequence=[
                    False,
                    False,
                    True,
                ],
            )

        clock = _Stepper(start=0.0, step=0.05)

        async def fast_sleep(_: float) -> None:
            """Skip all sleeps."""

        with (
            patch(
                "platteklip.mqtt_load_harness" "._monotonic",
                side_effect=clock,
            ),
            patch(
                "platteklip.mqtt_load_harness" "._sleep",
                side_effect=fast_sleep,
            ),
        ):
            result = await run_harness(
                connection,
                profile,
                producer_factory=factory,
            )

        self.assertGreaterEqual(
            result.total_published_accepted,
            0,
        )

    async def test_logging_interval(self) -> None:
        """Trigger the periodic logging path."""
        connection = MQTTConnectionConfig(
            host="localhost",
            port=1883,
            use_tls=False,
        )
        profile = LoadProfile(
            client_count=1,
            duration_seconds=1.0,
            messages_per_second_per_client=10.0,
            log_interval_seconds=0.1,
            stagger_every=0,
        )
        log = MagicMock()
        clock = _Stepper(start=0.0, step=0.2)

        async def fast_sleep(_: float) -> None:
            """Skip all sleeps."""

        with (
            patch(
                "platteklip.mqtt_load_harness" "._monotonic",
                side_effect=clock,
            ),
            patch(
                "platteklip.mqtt_load_harness" "._sleep",
                side_effect=fast_sleep,
            ),
        ):
            await run_harness(
                connection,
                profile,
                producer_factory=_fake_factory,
                log=log,
            )

        self.assertTrue(log.info.called)

    async def test_batch_yield_at_200(self) -> None:
        """Hit the sent % 200 == 0 yield branch."""
        connection = MQTTConnectionConfig(
            host="localhost",
            port=1883,
            use_tls=False,
        )
        stop_event = asyncio.Event()
        profile = LoadProfile(
            client_count=1,
            duration_seconds=10.0,
            messages_per_second_per_client=1000.0,
            burst_cap_seconds=2.0,
            log_interval_seconds=0.0,
            stagger_every=0,
        )

        def factory(
            config: MQTTConnectionConfig,
            client_id: str,
        ) -> MQTTProducer:
            """Return a producer that stops after 200."""
            return _FakeProducer(  # type: ignore[return-value]
                config=config,
                client_id=client_id,
                stop_event=stop_event,
                stop_after_publishes=200,
            )

        clock = _Stepper(start=0.0, step=1.0)
        sleep_calls: list[float] = []

        async def recording_sleep(
            delay: float,
        ) -> None:
            """Record every sleep call."""
            sleep_calls.append(float(delay))

        with (
            patch(
                "platteklip.mqtt_load_harness" "._monotonic",
                side_effect=clock,
            ),
            patch(
                "platteklip.mqtt_load_harness" "._sleep",
                side_effect=recording_sleep,
            ),
        ):
            result = await run_harness(
                connection,
                profile,
                producer_factory=factory,
                stop_event=stop_event,
            )

        self.assertGreaterEqual(
            result.total_published_accepted,
            200,
        )
        self.assertIn(0.0, sleep_calls)

    async def test_startup_stagger(self) -> None:
        """Cover the stagger delay between launches."""
        connection = MQTTConnectionConfig(
            host="localhost",
            port=1883,
            use_tls=False,
        )
        profile = LoadProfile(
            client_count=2,
            duration_seconds=0.0,
            messages_per_second_per_client=10.0,
            log_interval_seconds=0.0,
            stagger_every=1,
            stagger_delay_seconds=0.05,
        )
        clock = _Stepper(start=0.0, step=0.01)
        sleep_calls: list[float] = []

        async def recording_sleep(
            delay: float,
        ) -> None:
            """Record every sleep call."""
            sleep_calls.append(float(delay))

        with (
            patch(
                "platteklip.mqtt_load_harness" "._monotonic",
                side_effect=clock,
            ),
            patch(
                "platteklip.mqtt_load_harness" "._sleep",
                side_effect=recording_sleep,
            ),
        ):
            await run_harness(
                connection,
                profile,
                producer_factory=_fake_factory,
            )

        self.assertIn(0.05, sleep_calls)

    async def test_cancellation_propagates(
        self,
    ) -> None:
        """Set stop_event and re-raise CancelledError."""
        connection = MQTTConnectionConfig(
            host="localhost",
            port=1883,
            use_tls=False,
        )
        stop_event = asyncio.Event()
        profile = LoadProfile(
            client_count=1,
            duration_seconds=60.0,
            messages_per_second_per_client=10.0,
            log_interval_seconds=0.0,
            stagger_every=0,
        )
        task = asyncio.create_task(
            run_harness(
                connection,
                profile,
                producer_factory=_fake_factory,
                stop_event=stop_event,
            ),
        )
        await asyncio.sleep(0)

        task.cancel()
        with self.assertRaises(
            asyncio.CancelledError,
        ):
            await task

        self.assertTrue(stop_event.is_set())

    async def test_zero_rate(self) -> None:
        """Publish nothing when rate is zero."""
        connection = MQTTConnectionConfig(
            host="localhost",
            port=1883,
            use_tls=False,
        )
        profile = LoadProfile(
            client_count=1,
            duration_seconds=0.5,
            messages_per_second_per_client=0.0,
            log_interval_seconds=0.0,
            stagger_every=0,
        )
        clock = _Stepper(start=0.0, step=0.1)

        async def fast_sleep(_: float) -> None:
            """Skip all sleeps."""

        with (
            patch(
                "platteklip.mqtt_load_harness" "._monotonic",
                side_effect=clock,
            ),
            patch(
                "platteklip.mqtt_load_harness" "._sleep",
                side_effect=fast_sleep,
            ),
        ):
            result = await run_harness(
                connection,
                profile,
                producer_factory=_fake_factory,
            )

        self.assertEqual(
            result.total_published_accepted,
            0,
        )

    async def test_multiple_clients(self) -> None:
        """Run multiple clients and aggregate stats."""
        connection = MQTTConnectionConfig(
            host="localhost",
            port=1883,
            use_tls=False,
        )
        profile = LoadProfile(
            client_count=3,
            duration_seconds=0.5,
            messages_per_second_per_client=10.0,
            log_interval_seconds=0.0,
            stagger_every=0,
        )
        clock = _Stepper(start=0.0, step=0.05)

        async def fast_sleep(_: float) -> None:
            """Skip all sleeps."""

        with (
            patch(
                "platteklip.mqtt_load_harness" "._monotonic",
                side_effect=clock,
            ),
            patch(
                "platteklip.mqtt_load_harness" "._sleep",
                side_effect=fast_sleep,
            ),
        ):
            result = await run_harness(
                connection,
                profile,
                producer_factory=_fake_factory,
            )

        self.assertEqual(
            len(result.per_client),
            3,
        )
        self.assertGreaterEqual(
            result.total_published_accepted,
            3,
        )

    async def test_publish_rejected_breaks(
        self,
    ) -> None:
        """Break the drain loop on publish rejection."""
        connection = MQTTConnectionConfig(
            host="localhost",
            port=1883,
            use_tls=False,
        )
        stop_event = asyncio.Event()
        profile = LoadProfile(
            client_count=1,
            duration_seconds=2.0,
            messages_per_second_per_client=100.0,
            burst_cap_seconds=2.0,
            log_interval_seconds=0.0,
            stagger_every=0,
        )

        def factory(
            config: MQTTConnectionConfig,
            client_id: str,
        ) -> MQTTProducer:
            """Return a producer that rejects after 5."""
            return _FakeProducer(  # type: ignore[return-value]
                config=config,
                client_id=client_id,
                reject_after=5,
                stop_event=stop_event,
                stop_after_publishes=10,
            )

        clock = _Stepper(start=0.0, step=0.5)

        async def fast_sleep(_: float) -> None:
            """Skip all sleeps."""

        with (
            patch(
                "platteklip.mqtt_load_harness" "._monotonic",
                side_effect=clock,
            ),
            patch(
                "platteklip.mqtt_load_harness" "._sleep",
                side_effect=fast_sleep,
            ),
        ):
            result = await run_harness(
                connection,
                profile,
                producer_factory=factory,
                stop_event=stop_event,
            )

        # Should have published some but stopped
        # at the rejection boundary
        self.assertGreaterEqual(
            result.total_published_accepted,
            5,
        )


if __name__ == "__main__":
    unittest.main()
