from __future__ import annotations

import ipaddress
import struct

import pytest

from netprobe.dns_wire import (
    DNSProtocolError,
    build_query,
    encode_qname,
    parse_response,
)


def _response(*answers: bytes, flags: int = 0x8180, qtype: int = 1) -> bytes:
    question = encode_qname("example.com") + struct.pack("!HH", qtype, 1)
    header = struct.pack("!HHHHHH", 0x1234, flags, 1, len(answers), 0, 0)
    return header + question + b"".join(answers)


def _rr(rr_type: int, ttl: int, payload: bytes) -> bytes:
    return b"\xc0\x0c" + struct.pack("!HHIH", rr_type, 1, ttl, len(payload)) + payload


def test_encode_qname_and_build_query() -> None:
    assert encode_qname("example.com") == b"\x07example\x03com\x00"
    assert encode_qname("example.com.") == b"\x07example\x03com\x00"
    assert encode_qname("пример.рф") == encode_qname("xn--e1afmkfd.xn--p1ai")

    query = build_query("example.com", qtype=28, transaction_id=0x1234)
    assert query[:12] == struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    assert query[-4:] == struct.pack("!HH", 28, 1)


@pytest.mark.parametrize(
    "name",
    ["bad..name", "a" * 64 + ".example", "x\x00.example", "x\r.example"],
)
def test_encode_qname_rejects_malformed_names(name: str) -> None:
    with pytest.raises(DNSProtocolError):
        encode_qname(name)


def test_parse_compressed_a_and_aaaa_answers() -> None:
    a_packet = _response(_rr(1, 120, ipaddress.ip_address("192.0.2.1").packed))
    a = parse_response(a_packet, expected_id=0x1234, expected_name="example.com", expected_qtype=1)
    assert a.rcode == 0
    assert a.addresses == ("192.0.2.1",)
    assert a.records[0].ttl == 120

    aaaa_packet = _response(_rr(28, 60, ipaddress.ip_address("2001:db8::1").packed), qtype=28)
    aaaa = parse_response(
        aaaa_packet,
        expected_id=0x1234,
        expected_name="example.com",
        expected_qtype=28,
    )
    assert aaaa.addresses == ("2001:db8::1",)


@pytest.mark.parametrize(("rcode", "name"), [(2, "SERVFAIL"), (3, "NXDOMAIN"), (5, "REFUSED")])
def test_parse_rcode_and_truncated_flag(rcode: int, name: str) -> None:
    message = parse_response(
        _response(flags=0x8380 | rcode),
        expected_id=0x1234,
        expected_name="example.com",
        expected_qtype=1,
    )
    assert message.rcode_name == name
    assert message.truncated is True


def test_parse_rejects_transaction_or_question_mismatch() -> None:
    packet = _response()
    with pytest.raises(DNSProtocolError, match="transaction"):
        parse_response(packet, expected_id=1, expected_name="example.com", expected_qtype=1)
    with pytest.raises(DNSProtocolError, match="question"):
        parse_response(packet, expected_id=0x1234, expected_name="other.example", expected_qtype=1)


@pytest.mark.parametrize(
    "packet",
    [
        b"\x00" * 5,
        struct.pack("!HHHHHH", 0x1234, 0x8180, 500, 0, 0, 0),
        struct.pack("!HHHHHH", 0x1234, 0x8180, 1, 0, 0, 0) + b"\xc0\x0c",
        struct.pack("!HHHHHH", 0x1234, 0x8180, 1, 0, 0, 0) + b"\xc0\xff",
    ],
)
def test_parse_rejects_malformed_packets(packet: bytes) -> None:
    with pytest.raises(DNSProtocolError):
        parse_response(packet, expected_id=0x1234, expected_name="example.com", expected_qtype=1)
