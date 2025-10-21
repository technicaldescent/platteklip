# SPDX-FileCopyrightText: 2025 system-under-test contributors
# SPDX-License-Identifier: Apache-2.0

"""
Message queue instrumentation module.

This module provides OpenTelemetry instrumentation utilities for message
queue systems, including configuration and initialisation of telemetry
exporters for traces, metrics, and logs.
"""

from .utils import setup_telemetry

__all__ = ["setup_telemetry"]
