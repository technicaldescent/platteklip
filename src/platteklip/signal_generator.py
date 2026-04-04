# SPDX-FileCopyrightText: 2025 technical descent
# SPDX-License-Identifier: Apache-2.0

"""Synthetic signal generator for edge telemetry.

Produces simulated register values for every metric
in the Weaver-generated semantic convention registry.
Signal profiles encode the documented ranges, anomalies,
and correlations so that dashboards display realistic
behaviour without a physical data source.

The generator is deterministic given a fixed seed but
uses :func:`secrets.randbits` with 256 bits of entropy
by default.
"""

import logging
import random
import secrets
from dataclasses import dataclass
from typing import Final

from platteklip.instrumentation.edge_semconv import (
    METRICS_BY_NAME,
)

_log: Final[logging.Logger] = logging.getLogger(
    __name__,
)


# ------------------------------------------------------------------
# Signal profile types
# ------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ContinuousSignal:
    """Random-walk gauge within fixed bounds.

    Parameters
    ----------
    low
        Minimum simulated value.
    high
        Maximum simulated value.
    step
        Maximum absolute change per tick.
    initial
        Starting value; ``None`` picks a random point
        within *[low, high]*.
    wrap
        Wrap around instead of clamping (e.g. heading
        in degrees).
    """

    low: float
    high: float
    step: float
    initial: float | None = None
    wrap: bool = False


@dataclass(frozen=True, slots=True)
class BinarySignal:
    """Binary indicator that toggles stochastically.

    Parameters
    ----------
    toggle_prob
        Probability of flipping per tick.
    initial
        Starting value (0 or 1).
    """

    toggle_prob: float = 0.02
    initial: int = 0


@dataclass(frozen=True, slots=True)
class BitmaskSignal:
    """Integer bitmask with stochastic bit flips.

    Parameters
    ----------
    bits
        Number of significant bits.
    flip_prob
        Per-bit flip probability per tick.
    initial
        Starting bitmask value.
    """

    bits: int = 8
    flip_prob: float = 0.005
    initial: int = 0


@dataclass(frozen=True, slots=True)
class FixedSignal:
    """Constant value (stuck or broken sensor).

    Parameters
    ----------
    value
        The fixed output.
    """

    value: float = 0.0


SignalProfile = ContinuousSignal | BinarySignal | BitmaskSignal | FixedSignal


# ------------------------------------------------------------------
# Per-metric profiles
#
# Ranges and anomalies are taken directly from the
# descriptions in the Weaver-generated registry.
# ------------------------------------------------------------------

_PROFILES: Final[dict[str, SignalProfile]] = {
    # -- Controls --
    "edge.controls.conveyor.switch.position": ContinuousSignal(10.0, 72.0, 3.0),
    "edge.controls.conveyor.switch.reverse": BinarySignal(0.02, 0),
    "edge.controls.tram.pedal.position": ContinuousSignal(0.0, 100.0, 5.0),
    "edge.controls.tram.pedal.reverse": BinarySignal(0.01, 0),
    "edge.controls.tram.torque.reference": ContinuousSignal(
        0.0,
        32767.0,
        500.0,
        8000.0,
    ),
    # -- Conveyor --
    "edge.conveyor.frequency": ContinuousSignal(-5.0, 5.0, 0.5),
    "edge.conveyor.frequency.reference": ContinuousSignal(0.0, 50.0, 2.0, 25.0),
    "edge.conveyor.motor.current": ContinuousSignal(0.0, 80.0, 3.0, 15.0),
    "edge.conveyor.motor.voltage": ContinuousSignal(360.0, 420.0, 2.0, 400.0),
    "edge.conveyor.running": BinarySignal(0.01, 1),
    "edge.conveyor.temperature": FixedSignal(0.0),
    # -- PLC --
    "edge.plc.input.status": BitmaskSignal(16, 0.005, 0x00FF),
    "edge.plc.operational.status": BitmaskSignal(8, 0.002, 0x07),
    "edge.plc.output.status": BitmaskSignal(16, 0.005, 0x003F),
    # -- Pump --
    "edge.pump.dcbus.voltage": ContinuousSignal(540.0, 620.0, 3.0, 580.0),
    "edge.pump.motor.current": ContinuousSignal(0.0, 60.0, 2.0, 12.0),
    "edge.pump.motor.voltage": ContinuousSignal(360.0, 420.0, 2.0, 400.0),
    "edge.pump.running": BinarySignal(0.01, 1),
    "edge.pump.temperature": FixedSignal(0.0),
    # -- Traction left --
    "edge.traction.left.frequency": ContinuousSignal(0.0, 50.0, 2.0, 20.0),
    "edge.traction.left.motor.current": ContinuousSignal(0.0, 120.0, 5.0, 30.0),
    "edge.traction.left.motor.voltage": ContinuousSignal(360.0, 420.0, 2.0, 400.0),
    "edge.traction.left.running": BinarySignal(0.01, 1),
    "edge.traction.left.temperature": ContinuousSignal(25.0, 85.0, 1.0, 40.0),
    # -- Traction right --
    "edge.traction.right.frequency": ContinuousSignal(0.0, 50.0, 2.0, 20.0),
    "edge.traction.right.motor.current": ContinuousSignal(0.0, 120.0, 5.0, 30.0),
    "edge.traction.right.motor.voltage": ContinuousSignal(360.0, 420.0, 2.0, 400.0),
    "edge.traction.right.running": BinarySignal(0.01, 1),
    "edge.traction.right.temperature": ContinuousSignal(25.0, 85.0, 1.0, 40.0),
    # -- Vehicle --
    "edge.vehicle.orientation": ContinuousSignal(0.0, 360.0, 5.0, wrap=True),
    "edge.vehicle.speed": BinarySignal(0.05, 0),
    "edge.vehicle.steering.angle": ContinuousSignal(-45.0, 45.0, 3.0, 0.0),
}


# ------------------------------------------------------------------
# Subsystem grouping
# ------------------------------------------------------------------


def subsystem_of(metric_name: str) -> str:
    """Extract the subsystem from a metric name.

    ``edge.conveyor.frequency`` -> ``conveyor``
    ``edge.controls.tram.pedal.position`` -> ``controls``

    Return ``unknown`` if the name has fewer than two
    dot-separated segments.
    """
    parts = metric_name.split(".")
    if len(parts) >= 2:
        return parts[1]
    return "unknown"


# ------------------------------------------------------------------
# Per-profile step functions
# ------------------------------------------------------------------


def _step_continuous(
    rng: random.Random,
    current: float,
    profile: ContinuousSignal,
) -> float:
    """Advance a continuous random-walk signal."""
    delta = rng.uniform(-profile.step, profile.step)
    new = current + delta
    if profile.wrap:
        span = profile.high - profile.low
        return profile.low + ((new - profile.low) % span)
    return max(profile.low, min(profile.high, new))


def _step_binary(
    rng: random.Random,
    current: float,
    profile: BinarySignal,
) -> float:
    """Advance a binary toggle signal."""
    if rng.random() < profile.toggle_prob:
        return 0.0 if current != 0.0 else 1.0
    return current


def _step_bitmask(
    rng: random.Random,
    current: float,
    profile: BitmaskSignal,
) -> float:
    """Advance a bitmask signal with random bit flips."""
    mask = int(current)
    for bit in range(profile.bits):
        if rng.random() < profile.flip_prob:
            mask ^= 1 << bit
    return float(mask)


def _initial_value(
    rng: random.Random,
    profile: SignalProfile,
) -> float:
    """Compute the initial state for a signal profile."""
    match profile:
        case ContinuousSignal(
            initial=init,
            low=lo,
            high=hi,
        ):
            return init if init is not None else rng.uniform(lo, hi)
        case BinarySignal(initial=init):
            return float(init)
        case BitmaskSignal(initial=init):
            return float(init)
        case FixedSignal(value=val):
            return val


# ------------------------------------------------------------------
# Generator
# ------------------------------------------------------------------


class SignalGenerator:
    """Synthetic signal source for the edge registry.

    On each call to :meth:`tick` or
    :meth:`tick_by_subsystem`, every metric in the
    registry is advanced by one step according to its
    signal profile.

    Parameters
    ----------
    seed
        Explicit RNG seed.  If ``None``,
        :func:`secrets.randbits` provides 256 bits
        of entropy.
    """

    def __init__(
        self,
        *,
        seed: int | None = None,
    ) -> None:
        """Initialise signal states from profiles."""
        if seed is None:
            seed = secrets.randbits(256)
        self._rng = random.Random(seed)  # nosec B311
        self._states: dict[str, float] = {}

        for name, profile in _PROFILES.items():
            if name not in METRICS_BY_NAME:
                _log.warning(
                    "Profile for %s has no registry" " entry — skipped",
                    name,
                )
                continue
            self._states[name] = _initial_value(
                self._rng,
                profile,
            )

        unmatched = METRICS_BY_NAME.keys() - _PROFILES.keys()
        for name in sorted(unmatched):
            _log.warning(
                "No signal profile for registry" " metric: %s",
                name,
            )

    def tick(self) -> dict[str, float]:
        """Advance all signals by one step.

        Returns
        -------
        dict[str, float]
            Current values keyed by fully qualified
            metric name.
        """
        for name in self._states:
            profile = _PROFILES[name]
            current = self._states[name]

            match profile:
                case ContinuousSignal():
                    self._states[name] = _step_continuous(
                        self._rng,
                        current,
                        profile,
                    )
                case BinarySignal():
                    self._states[name] = _step_binary(
                        self._rng,
                        current,
                        profile,
                    )
                case BitmaskSignal():
                    self._states[name] = _step_bitmask(
                        self._rng,
                        current,
                        profile,
                    )
                case FixedSignal():
                    pass

        return dict(self._states)

    def tick_by_subsystem(
        self,
    ) -> dict[str, dict[str, float]]:
        """Advance all signals, grouped by subsystem.

        Returns
        -------
        dict[str, dict[str, float]]
            Outer key is the subsystem name; inner dict
            maps metric names to current values.
        """
        values = self.tick()
        groups: dict[str, dict[str, float]] = {}
        for name, value in values.items():
            sub = subsystem_of(name)
            if sub not in groups:
                groups[sub] = {}
            groups[sub][name] = value
        return groups
