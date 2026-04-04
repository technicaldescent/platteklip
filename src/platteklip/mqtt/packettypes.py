# SPDX-FileCopyrightText: 2025 technical descent
# SPDX-License-Identifier: Apache-2.0

"""MQTT v5 control packet type constants.

Each MQTT control packet has a fixed header whose first
four bits encode the packet type.  This module maps the
14 packet types defined in MQTT v5.0 section 2.1.2 to
named integer constants.

Reference
---------
MQTT v5.0 specification, section 2.1.2:
    https://docs.oasis-open.org/mqtt/mqtt/v5.0/
"""

import enum


class PacketTypes(enum.IntEnum):
    """MQTT v5 control packet types (1–15)."""

    CONNECT = 1
    CONNACK = 2
    PUBLISH = 3
    PUBACK = 4
    PUBREC = 5
    PUBREL = 6
    PUBCOMP = 7
    SUBSCRIBE = 8
    SUBACK = 9
    UNSUBSCRIBE = 10
    UNSUBACK = 11
    PINGREQ = 12
    PINGRESP = 13
    DISCONNECT = 14
    AUTH = 15
