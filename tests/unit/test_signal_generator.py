# SPDX-FileCopyrightText: 2025 technical descent
# SPDX-License-Identifier: Apache-2.0

"""Tests for the synthetic signal generator.

Covers subsystem extraction, profile-to-registry
alignment, deterministic seeding, per-profile-type
invariants, subsystem grouping, and anomalous signal
profile parameters.
"""

import unittest
from unittest.mock import patch

from platteklip.instrumentation.edge_semconv import (
    METRICS_BY_NAME,
)
from platteklip.signal_generator import (
    _PROFILES,
    BinarySignal,
    BitmaskSignal,
    ContinuousSignal,
    FixedSignal,
    SignalGenerator,
    subsystem_of,
)

# A fixed seed with 256 bits of entropy for reproducible
# tests.  Generated once via secrets.randbits(256).
_TEST_SEED: int = int(
    "7A3F1E2D4C5B6A890F1E2D3C4B5A6978" "8796A5B4C3D2E1F00F1E2D3C4B5A6978",
    16,
)


class TestSubsystemOf(unittest.TestCase):
    """Verify subsystem extraction from metric names."""

    def test_extracts_conveyor(self) -> None:
        """Parse conveyor from edge.conveyor.*."""
        self.assertEqual(
            subsystem_of("edge.conveyor.frequency"),
            "conveyor",
        )

    def test_extracts_controls(self) -> None:
        """Parse controls from edge.controls.*."""
        self.assertEqual(
            subsystem_of(
                "edge.controls.tram.pedal.position",
            ),
            "controls",
        )

    def test_extracts_traction(self) -> None:
        """Parse traction from edge.traction.*."""
        self.assertEqual(
            subsystem_of(
                "edge.traction.left.frequency",
            ),
            "traction",
        )

    def test_extracts_pump(self) -> None:
        """Parse pump from edge.pump.*."""
        self.assertEqual(
            subsystem_of("edge.pump.running"),
            "pump",
        )

    def test_extracts_plc(self) -> None:
        """Parse plc from edge.plc.*."""
        self.assertEqual(
            subsystem_of("edge.plc.input.status"),
            "plc",
        )

    def test_extracts_vehicle(self) -> None:
        """Parse vehicle from edge.vehicle.*."""
        self.assertEqual(
            subsystem_of("edge.vehicle.speed"),
            "vehicle",
        )

    def test_single_segment_returns_unknown(
        self,
    ) -> None:
        """Fall back to unknown for single-segment names."""
        self.assertEqual(
            subsystem_of("edge"),
            "unknown",
        )

    def test_empty_string_returns_unknown(
        self,
    ) -> None:
        """Fall back to unknown for empty strings."""
        self.assertEqual(
            subsystem_of(""),
            "unknown",
        )


class TestProfileRegistryCoverage(unittest.TestCase):
    """Verify bidirectional profile-registry alignment."""

    def test_all_registry_metrics_have_profiles(
        self,
    ) -> None:
        """Reject registry metrics without profiles."""
        missing = METRICS_BY_NAME.keys() - _PROFILES.keys()
        self.assertEqual(
            missing,
            set(),
            f"Registry metrics without signal" f" profiles: {sorted(missing)}",
        )

    def test_all_profiles_have_registry_metrics(
        self,
    ) -> None:
        """Reject profiles without registry metrics."""
        extra = _PROFILES.keys() - METRICS_BY_NAME.keys()
        self.assertEqual(
            extra,
            set(),
            f"Signal profiles without registry" f" metrics: {sorted(extra)}",
        )

    def test_profile_count_matches_registry(
        self,
    ) -> None:
        """Verify equal profile and registry counts."""
        self.assertEqual(
            len(_PROFILES),
            len(METRICS_BY_NAME),
        )


class TestSignalGeneratorInit(unittest.TestCase):
    """Verify construction and initial state."""

    def test_deterministic_seed_produces_same_state(
        self,
    ) -> None:
        """Produce identical output from the same seed."""
        g1 = SignalGenerator(seed=_TEST_SEED)
        g2 = SignalGenerator(seed=_TEST_SEED)

        self.assertEqual(g1.tick(), g2.tick())

    def test_default_seed_uses_entropy(self) -> None:
        """Produce distinct output without a seed."""
        g1 = SignalGenerator()
        g2 = SignalGenerator()

        # Astronomically unlikely to collide with
        # 256 bits of entropy.
        self.assertNotEqual(g1.tick(), g2.tick())

    def test_all_states_initialised(self) -> None:
        """Initialize a state for every profiled metric."""
        g = SignalGenerator(seed=_TEST_SEED)
        values = g.tick()

        for name in _PROFILES:
            if name in METRICS_BY_NAME:
                self.assertIn(
                    name,
                    values,
                    f"Missing state for {name}",
                )

    def test_warns_on_profile_without_registry(
        self,
    ) -> None:
        """Log a warning for orphaned profiles."""
        fake_profiles = {
            **_PROFILES,
            "edge.fake.metric": ContinuousSignal(
                0.0,
                100.0,
                1.0,
            ),
        }
        with patch.dict(
            "platteklip.signal_generator._PROFILES",
            fake_profiles,
        ):
            with self.assertLogs(
                "platteklip.signal_generator",
                level="WARNING",
            ) as cm:
                SignalGenerator(seed=_TEST_SEED)

        self.assertTrue(
            any("edge.fake.metric" in msg for msg in cm.output),
        )


class TestContinuousSignal(unittest.TestCase):
    """Verify ContinuousSignal invariants."""

    def test_values_stay_within_bounds(self) -> None:
        """Clamp values to [low, high] over many ticks."""
        g = SignalGenerator(seed=_TEST_SEED)

        for _ in range(500):
            values = g.tick()
            for name, profile in _PROFILES.items():
                if (
                    not isinstance(
                        profile,
                        ContinuousSignal,
                    )
                    or name not in values
                ):
                    continue
                self.assertGreaterEqual(
                    values[name],
                    profile.low,
                    f"{name} below lower bound",
                )
                self.assertLessEqual(
                    values[name],
                    profile.high,
                    f"{name} above upper bound",
                )

    def test_wrap_mode_stays_within_bounds(
        self,
    ) -> None:
        """Keep wrapped values in [low, high)."""
        g = SignalGenerator(seed=_TEST_SEED)

        for _ in range(500):
            values = g.tick()
            orientation = values.get(
                "edge.vehicle.orientation",
            )
            if orientation is not None:
                self.assertGreaterEqual(
                    orientation,
                    0.0,
                )
                self.assertLess(orientation, 360.0)

    def test_explicit_initial_value_used(
        self,
    ) -> None:
        """Honour the initial field in the profile."""
        profile = _PROFILES["edge.conveyor.frequency.reference"]
        assert isinstance(profile, ContinuousSignal)
        self.assertEqual(profile.initial, 25.0)

    def test_values_change_over_ticks(self) -> None:
        """Observe at least one change after a tick."""
        g = SignalGenerator(seed=_TEST_SEED)

        v1 = g.tick()
        v2 = g.tick()

        changed = any(
            v1[k] != v2[k]
            for k in v1
            if isinstance(
                _PROFILES.get(k),
                ContinuousSignal,
            )
        )
        self.assertTrue(
            changed,
            "No continuous signal changed" " after a tick",
        )


class TestBinarySignal(unittest.TestCase):
    """Verify BinarySignal invariants."""

    def test_values_are_zero_or_one(self) -> None:
        """Constrain values to {0.0, 1.0}."""
        g = SignalGenerator(seed=_TEST_SEED)

        for _ in range(500):
            values = g.tick()
            for name, profile in _PROFILES.items():
                if (
                    not isinstance(
                        profile,
                        BinarySignal,
                    )
                    or name not in values
                ):
                    continue
                self.assertIn(
                    values[name],
                    (0.0, 1.0),
                    f"{name} not binary",
                )

    def test_toggle_occurs_over_many_ticks(
        self,
    ) -> None:
        """Observe both states within 2000 ticks."""
        g = SignalGenerator(seed=_TEST_SEED)
        name = "edge.conveyor.running"

        seen: set[float] = set()
        for _ in range(2000):
            values = g.tick()
            seen.add(values[name])
            if len(seen) == 2:
                break

        self.assertEqual(
            seen,
            {0.0, 1.0},
            f"{name} never toggled in 2000 ticks",
        )


class TestBitmaskSignal(unittest.TestCase):
    """Verify BitmaskSignal invariants."""

    def test_values_within_bit_range(self) -> None:
        """Constrain mask to [0, 2^bits - 1]."""
        g = SignalGenerator(seed=_TEST_SEED)

        for _ in range(500):
            values = g.tick()
            for name, profile in _PROFILES.items():
                if (
                    not isinstance(
                        profile,
                        BitmaskSignal,
                    )
                    or name not in values
                ):
                    continue
                mask = int(values[name])
                max_val = (1 << profile.bits) - 1
                self.assertGreaterEqual(
                    mask,
                    0,
                    f"{name} negative",
                )
                self.assertLessEqual(
                    mask,
                    max_val,
                    f"{name} exceeds" f" {profile.bits}-bit range",
                )

    def test_bits_flip_over_many_ticks(
        self,
    ) -> None:
        """Observe at least two distinct values."""
        g = SignalGenerator(seed=_TEST_SEED)
        name = "edge.plc.input.status"

        values_seen: set[int] = set()
        for _ in range(2000):
            values = g.tick()
            values_seen.add(int(values[name]))
            if len(values_seen) > 1:
                break

        self.assertGreater(
            len(values_seen),
            1,
            f"{name} never changed in 2000 ticks",
        )


class TestFixedSignal(unittest.TestCase):
    """Verify FixedSignal invariants."""

    def test_value_never_changes(self) -> None:
        """Hold the fixed value across all ticks."""
        g = SignalGenerator(seed=_TEST_SEED)

        for _ in range(100):
            values = g.tick()
            for name, profile in _PROFILES.items():
                if (
                    not isinstance(
                        profile,
                        FixedSignal,
                    )
                    or name not in values
                ):
                    continue
                self.assertEqual(
                    values[name],
                    profile.value,
                    f"{name} deviated from" f" fixed value",
                )

    def test_stuck_sensors_are_zero(self) -> None:
        """Verify known stuck sensors output 0.0."""
        stuck = [
            "edge.conveyor.temperature",
            "edge.pump.temperature",
        ]
        g = SignalGenerator(seed=_TEST_SEED)
        values = g.tick()

        for name in stuck:
            self.assertEqual(
                values[name],
                0.0,
                f"{name} should be stuck at zero",
            )


class TestTickBySubsystem(unittest.TestCase):
    """Verify tick_by_subsystem grouping."""

    def test_returns_expected_subsystems(
        self,
    ) -> None:
        """Return all six subsystem groups."""
        g = SignalGenerator(seed=_TEST_SEED)
        groups = g.tick_by_subsystem()

        expected = {
            "controls",
            "conveyor",
            "plc",
            "pump",
            "traction",
            "vehicle",
        }
        self.assertEqual(
            set(groups.keys()),
            expected,
        )

    def test_all_metrics_present_across_groups(
        self,
    ) -> None:
        """Include every profiled metric in some group."""
        g = SignalGenerator(seed=_TEST_SEED)
        groups = g.tick_by_subsystem()

        all_names: set[str] = set()
        for signals in groups.values():
            all_names.update(signals.keys())

        for name in _PROFILES:
            if name in METRICS_BY_NAME:
                self.assertIn(
                    name,
                    all_names,
                    f"{name} missing from" f" grouped output",
                )

    def test_grouping_matches_flat_tick(
        self,
    ) -> None:
        """Produce identical values to tick()."""
        g1 = SignalGenerator(seed=_TEST_SEED)
        g2 = SignalGenerator(seed=_TEST_SEED)

        flat = g1.tick()
        grouped = g2.tick_by_subsystem()

        reassembled: dict[str, float] = {}
        for signals in grouped.values():
            reassembled.update(signals)

        self.assertEqual(flat, reassembled)

    def test_no_metric_appears_in_multiple_groups(
        self,
    ) -> None:
        """Assign each metric to exactly one group."""
        g = SignalGenerator(seed=_TEST_SEED)
        groups = g.tick_by_subsystem()

        seen: set[str] = set()
        for signals in groups.values():
            overlap = seen & signals.keys()
            self.assertEqual(
                overlap,
                set(),
                f"Metrics in multiple groups:" f" {overlap}",
            )
            seen.update(signals.keys())


class TestAnomalousProfiles(unittest.TestCase):
    """Verify anomalous signal profile parameters."""

    def test_conveyor_frequency_range(self) -> None:
        """Match the documented anomalous range."""
        profile = _PROFILES["edge.conveyor.frequency"]
        assert isinstance(profile, ContinuousSignal)
        self.assertEqual(profile.low, -5.0)
        self.assertEqual(profile.high, 5.0)

    def test_switch_position_range(self) -> None:
        """Match the documented position range."""
        profile = _PROFILES["edge.controls.conveyor.switch.position"]
        assert isinstance(profile, ContinuousSignal)
        self.assertEqual(profile.low, 10.0)
        self.assertEqual(profile.high, 72.0)

    def test_vehicle_speed_is_binary(self) -> None:
        """Confirm speed uses a binary profile."""
        profile = _PROFILES["edge.vehicle.speed"]
        assert isinstance(profile, BinarySignal)

    def test_vehicle_orientation_wraps(self) -> None:
        """Confirm orientation uses wrap mode."""
        profile = _PROFILES["edge.vehicle.orientation"]
        assert isinstance(profile, ContinuousSignal)
        self.assertTrue(profile.wrap)


if __name__ == "__main__":
    unittest.main()
