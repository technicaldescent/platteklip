# SPDX-FileCopyrightText: 2025 technical descent
# SPDX-License-Identifier: Apache-2.0

"""MQTT v5 reason code representation.

Each MQTT v5 control packet carries a reason code that
indicates the outcome of the operation.  This module
provides a frozen dataclass for type-safe reason code
handling with pack/unpack support for wire-format
serialisation.

Reference
---------
MQTT v5.0 specification, section 2.4:
    https://docs.oasis-open.org/mqtt/mqtt/v5.0/
"""

from dataclasses import dataclass

from .packettypes import PacketTypes


@dataclass(frozen=True, slots=True)
class ReasonCode:
    """An MQTT v5 reason code bound to a packet type.

    Parameters
    ----------
    packet_type
        The MQTT control packet type this reason code
        belongs to.
    identifier
        The numeric reason code value (0–255).
        Defaults to 0 (Success).
    """

    packet_type: PacketTypes
    identifier: int = 0

    def __int__(self) -> int:
        """Return the numeric reason code value."""
        return int(self.identifier)

    def pack(self) -> bytes:
        """Serialise the reason code to a single byte.

        Returns
        -------
        bytes
            A single-byte representation of the reason
            code, masked to the low 8 bits.
        """
        return bytes([self.identifier & 0xFF])

    @classmethod
    def unpack_from(
        cls,
        packet_type: PacketTypes,
        data: bytes,
        offset: int = 0,
    ) -> tuple[ReasonCode, int]:
        """Deserialise a reason code from a byte buffer.

        Parameters
        ----------
        packet_type
            The packet type context for the reason code.
        data
            The byte buffer to read from.
        offset
            The position in *data* to read the reason
            code byte.  Defaults to 0.

        Returns
        -------
        tuple[ReasonCode, int]
            A tuple of the deserialised reason code and
            the number of bytes consumed (always 1).

        Raises
        ------
        ValueError
            If *offset* is beyond the end of *data*.
        """
        if offset >= len(data):
            raise ValueError(
                "Insufficient data for ReasonCode",
            )
        return (
            cls(
                packet_type=packet_type,
                identifier=data[offset],
            ),
            1,
        )
