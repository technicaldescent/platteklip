# SPDX-FileCopyrightText: 2025 technical descent
# SPDX-License-Identifier: Apache-2.0

"""MQTT v5 client library.

This package provides a vendored MQTT v5 client with
strict protocol enforcement, structured error handling,
and OpenTelemetry-compatible callback signatures.

Modules
-------
client
    MQTT v5 client with mTLS, QoS, and callback support.
enums
    Callback API version enumeration.
packettypes
    MQTT v5 packet type constants.
properties
    MQTT v5 property identifiers and metadata.
reasoncodes
    MQTT v5 reason code constants and lookup.
"""

__all__: list[str] = ["MQTTException"]


class MQTTException(Exception):
    """Base exception for MQTT client errors."""
