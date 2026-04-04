# SPDX-FileCopyrightText: 2025 technical descent
# SPDX-License-Identifier: Apache-2.0

"""MQTT v5 property encoding and decoding.

Implements the variable-length integer (varint) wire
format and the property set defined in MQTT v5.0
section 2.2.2.  Only the properties required by the
producer are materialised as typed fields; all others
are safely skipped during unpacking based on their
data type.

Supported properties
--------------------
Receive Maximum (0x21)
    Two-byte integer.  Used in CONNECT to limit the
    number of in-flight QoS 1/2 messages.

Reference
---------
MQTT v5.0 specification, section 2.2.2:
    https://docs.oasis-open.org/mqtt/mqtt/v5.0/
"""

import struct
from dataclasses import dataclass

from .packettypes import PacketTypes

# Property identifier constants for MQTT v5 data types.
# Used during unpacking to determine how many bytes to
# skip for unsupported properties.
_ONE_BYTE_IDS: frozenset[int] = frozenset(
    {0x01, 0x17, 0x19, 0x24, 0x25, 0x28, 0x29, 0x2A},
)
_TWO_BYTE_IDS: frozenset[int] = frozenset(
    {0x13, 0x22, 0x23},
)
_FOUR_BYTE_IDS: frozenset[int] = frozenset(
    {0x02, 0x11, 0x18, 0x27},
)
_STRING_IDS: frozenset[int] = frozenset(
    {0x03, 0x08, 0x09, 0x12, 0x15, 0x16, 0x1A, 0x1C, 0x1F},
)
_USER_PROPERTY_ID: int = 0x26
_SUBSCRIPTION_ID: int = 0x0B
_RECEIVE_MAXIMUM_ID: int = 0x21


def _encode_varint(value: int) -> bytes:
    """Encode an integer as an MQTT variable-length integer.

    Parameters
    ----------
    value
        A non-negative integer in the range
        [0, 268 435 455].

    Returns
    -------
    bytes
        The varint-encoded representation (1–4 bytes).

    Raises
    ------
    ValueError
        If *value* is outside the permitted range.
    """
    if value < 0 or value > 268_435_455:
        raise ValueError("MQTT varint out of range")
    out = bytearray()
    while True:
        b = value % 128
        value //= 128
        if value:
            b |= 0x80
        out.append(b)
        if not value:
            return bytes(out)


def _decode_varint(
    data: bytes,
    offset: int = 0,
) -> tuple[int, int]:
    """Decode an MQTT variable-length integer.

    Parameters
    ----------
    data
        The byte buffer to read from.
    offset
        The position in *data* to begin decoding.

    Returns
    -------
    tuple[int, int]
        A tuple of the decoded value and the number
        of bytes consumed.

    Raises
    ------
    ValueError
        If the buffer is too short or the varint
        encoding is malformed (more than 4 bytes).
    """
    multiplier = 1
    value = 0
    for consumed in range(4):
        if offset + consumed >= len(data):
            raise ValueError(
                "Insufficient data for varint",
            )
        b = data[offset + consumed]
        value += (b & 0x7F) * multiplier
        if (b & 0x80) == 0:
            return value, consumed + 1
        multiplier *= 128
    raise ValueError("Malformed varint")


def _read_utf8_len(
    data: bytes,
    pos: int,
    end: int,
    label: str,
) -> int:
    """Read a two-byte UTF-8 string length prefix.

    Returns the total bytes to skip (2 + string length).

    Raises
    ------
    ValueError
        If the buffer is too short for the length prefix.
    """
    if pos + 2 > end:
        raise ValueError(f"Truncated {label}")
    (slen,) = struct.unpack("!H", data[pos : pos + 2])
    return 2 + int(slen)


def _skip_property(
    prop_id: int,
    data: bytes,
    pos: int,
    end: int,
) -> int:
    """Return the number of bytes to skip for *prop_id*.

    Raises
    ------
    ValueError
        If the property identifier is unknown or the
        payload is truncated.
    """
    if prop_id in _ONE_BYTE_IDS:
        return 1
    if prop_id in _TWO_BYTE_IDS:
        return 2
    if prop_id in _FOUR_BYTE_IDS:
        return 4
    if prop_id in _STRING_IDS:
        return _read_utf8_len(
            data,
            pos,
            end,
            f"string prop 0x{prop_id:02x}",
        )
    if prop_id == _USER_PROPERTY_ID:
        key_skip = _read_utf8_len(
            data,
            pos,
            end,
            "User Property key",
        )
        val_skip = _read_utf8_len(
            data,
            pos + key_skip,
            end,
            "User Property value",
        )
        return key_skip + val_skip
    if prop_id == _SUBSCRIPTION_ID:
        _, consumed = _decode_varint(data, pos)
        return consumed
    raise ValueError(
        f"Unsupported and unknown property " f"id: 0x{prop_id:02x}",
    )


@dataclass(slots=True)
class Properties:
    """MQTT v5 property set for a given packet type.

    Properties are serialised as a varint-prefixed byte
    sequence.  Each property is identified by a single
    byte and followed by a type-specific payload.

    Only :attr:`ReceiveMaximum` is materialised as a
    typed field.  All other property identifiers are
    safely skipped during :meth:`unpack` based on their
    MQTT v5 data type.

    Parameters
    ----------
    packet_type
        The MQTT control packet type this property
        set belongs to.
    ReceiveMaximum
        The Receive Maximum value (1–65 535), or
        ``None`` if not set.
    """

    packet_type: PacketTypes

    ReceiveMaximum: int | None = None  # noqa: N815

    def pack(self) -> bytes:
        """Serialise properties to wire format.

        Returns
        -------
        bytes
            A varint length prefix followed by the
            encoded property bytes.  If no properties
            are set, returns a single zero byte
            (varint-encoded zero length).

        Raises
        ------
        ValueError
            If :attr:`ReceiveMaximum` is outside the
            range [1, 65 535].
        """
        props = bytearray()

        if self.ReceiveMaximum is not None:
            if not (1 <= self.ReceiveMaximum <= 65_535):
                raise ValueError(
                    "ReceiveMaximum must be in " "[1, 65535]",
                )
            props.append(_RECEIVE_MAXIMUM_ID)
            props.extend(
                struct.pack("!H", self.ReceiveMaximum),
            )

        return _encode_varint(len(props)) + props

    def unpack(
        self,
        data: bytes,
        offset: int = 0,
    ) -> int:
        """Deserialise properties from a byte buffer.

        Reads the varint length prefix at *offset*,
        then iterates over each property identifier
        in the payload.  Supported properties are
        stored on the instance; unsupported properties
        are skipped based on their MQTT v5 data type.

        Parameters
        ----------
        data
            The byte buffer to read from.
        offset
            The position in *data* to begin reading.

        Returns
        -------
        int
            The total number of bytes consumed from
            *offset*, including the length varint.

        Raises
        ------
        ValueError
            If the buffer is truncated, a property
            payload is incomplete, or an unknown
            property identifier is encountered.
        """
        length, n = _decode_varint(data, offset)
        start = offset + n
        end = start + length
        if end > len(data):
            raise ValueError(
                "Properties length exceeds " "available data",
            )

        i = start
        while i < end:
            prop_id = data[i]
            i += 1

            # Receive Maximum (0x21): two-byte integer
            if prop_id == _RECEIVE_MAXIMUM_ID:
                if i + 2 > end:
                    raise ValueError(
                        "Truncated ReceiveMaximum",
                    )
                (value,) = struct.unpack(
                    "!H",
                    data[i : i + 2],
                )
                i += 2
                self.ReceiveMaximum = int(value)
                continue

            # Skip unsupported properties by type
            i += _skip_property(
                prop_id,
                data,
                i,
                end,
            )

        return n + length
