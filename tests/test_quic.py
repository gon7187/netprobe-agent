from __future__ import annotations

import struct

import pytest

from netprobe.quic import build_version_negotiation_probe, parse_version_negotiation


def test_build_quic_probe_is_1200_bytes_and_uses_unsupported_version() -> None:
    packet = build_version_negotiation_probe(b"12345678", b"abcdefgh")

    assert len(packet) == 1200
    assert packet[0] & 0x80
    assert packet[1:5] == struct.pack("!I", 0x0A0A0A0A)
    assert packet[5:14] == b"\x0812345678"


def test_parse_version_negotiation_validates_connection_ids() -> None:
    # Server swaps the client's source/destination connection IDs.
    response = (
        b"\xc0"
        + b"\x00\x00\x00\x00"
        + b"\x08abcdefgh"
        + b"\x0812345678"
        + struct.pack("!II", 1, 0x6B3343CF)
    )
    versions = parse_version_negotiation(
        response,
        original_dcid=b"12345678",
        original_scid=b"abcdefgh",
    )
    assert versions == (1, 0x6B3343CF)

    with pytest.raises(ValueError, match="connection ID"):
        parse_version_negotiation(
            response,
            original_dcid=b"XXXXXXXX",
            original_scid=b"abcdefgh",
        )
