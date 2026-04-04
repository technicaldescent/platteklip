# SPDX-FileCopyrightText: 2025 technical descent
# SPDX-License-Identifier: Apache-2.0

"""Constants and enumerations for the MQTT v5 client.

Defines the callback API version, protocol version,
and client-side error codes used throughout
the MQTT client library.
"""

import enum


class CallbackAPIVersion(enum.IntEnum):
    """User callback API version.

    Only ``VERSION2`` is supported in this codebase.
    Version 2 callbacks receive a :class:`ReasonCode`
    object rather than a bare integer.
    """

    VERSION2 = 2


class MQTTProtocolVersion(enum.IntEnum):
    """MQTT protocol version identifiers.

    Only MQTT v5 is supported.  The numeric value
    matches the protocol level byte in the CONNECT
    packet variable header.
    """

    MQTTv5 = 5


class MQTTErrorCode(enum.IntEnum):
    """Client-side status codes (internal).

    These codes are returned by the client library
    to indicate the outcome of local operations
    (publish, subscribe, connect).  They are not
    MQTT protocol reason codes.
    """

    MQTT_ERR_SUCCESS = 0
    MQTT_ERR_INVAL = 2
    MQTT_ERR_PROTOCOL = 3
    MQTT_ERR_NO_CONN = 4
    MQTT_ERR_CONN_LOST = 7
    MQTT_ERR_UNKNOWN = 14
    MQTT_ERR_QUEUE_SIZE = 15
