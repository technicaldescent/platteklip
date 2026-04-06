# SPDX-FileCopyrightText: 2025 technical descent
# SPDX-License-Identifier: Apache-2.0

"""Shared fixtures for unit tests."""

import pathlib
from typing import Any

import pytest
import yaml  # type: ignore[import-untyped]

_PROJECT_ROOT: pathlib.Path = pathlib.Path(__file__).resolve().parents[2]


@pytest.fixture
def otel_collector_config() -> dict[str, Any]:
    """Load the OTel Collector configuration."""
    config_path = _PROJECT_ROOT / "services" / "otel-collector" / "config.yaml"
    with config_path.open() as fh:
        config: dict[str, Any] = yaml.safe_load(fh)
        return config
