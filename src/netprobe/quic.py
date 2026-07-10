"""Dependency-free QUIC version-negotiation reachability probe.

This does not claim that a timeout means QUIC blocking.  A valid Version
Negotiation response only proves that UDP/443 and a QUIC-speaking endpoint are
reachable; direct-vs-VPN comparison supplies the useful differential evidence.
"""

from __future__ import annotations

import ipaddress
import secrets
import socket
import struct
import time

from netprobe.models import Outcome, ProbeResult
from netprobe.probes import family_name, normalize_exception

_UNSUPPORTED_GREASE_VERSION = 0x0A0A0A0A
_MIN_INITIAL_SIZE = 1200


def _validate_connection_id(value: bytes, name: str) -> bytes:
    if not isinstance(value, bytes) or not 1 <= len(value) <= 20:
        raise ValueError(f"{name} must contain 1..20 bytes")
    return value


def build_version_negotiation_probe(dcid: bytes, scid: bytes) -> bytes:
    """Build a padded long-header packet carrying an intentionally unknown version."""

    destination = _validate_connection_id(dcid, "dcid")
    source = _validate_connection_id(scid, "scid")
    header = (
        b"\xc0"
        + struct.pack("!I", _UNSUPPORTED_GREASE_VERSION)
        + bytes([len(destination)])
        + destination
        + bytes([len(source)])
        + source
    )
    return header + secrets.token_bytes(_MIN_INITIAL_SIZE - len(header))


def parse_version_negotiation(
    packet: bytes,
    *,
    original_dcid: bytes,
    original_scid: bytes,
) -> tuple[int, ...]:
    """Validate and extract versions from an RFC 9000 Version Negotiation packet."""

    destination = _validate_connection_id(original_dcid, "original_dcid")
    source = _validate_connection_id(original_scid, "original_scid")
    if len(packet) < 7 or not packet[0] & 0x80:
        raise ValueError("not a QUIC long-header packet")
    if packet[1:5] != b"\x00\x00\x00\x00":
        raise ValueError("packet is not QUIC Version Negotiation")
    offset = 5
    destination_length = packet[offset]
    offset += 1
    if destination_length > 20 or offset + destination_length + 1 > len(packet):
        raise ValueError("invalid destination connection ID")
    response_dcid = packet[offset : offset + destination_length]
    offset += destination_length
    source_length = packet[offset]
    offset += 1
    if source_length > 20 or offset + source_length > len(packet):
        raise ValueError("invalid source connection ID")
    response_scid = packet[offset : offset + source_length]
    offset += source_length
    if response_dcid != source or response_scid != destination:
        raise ValueError("Version Negotiation connection ID mismatch")
    remainder = packet[offset:]
    if not remainder or len(remainder) % 4:
        raise ValueError("invalid QUIC version list")
    versions = tuple(struct.unpack(f"!{len(remainder) // 4}I", remainder))
    if 0 in versions:
        raise ValueError("Version Negotiation list contains reserved zero version")
    return versions


def probe_quic_version_negotiation(
    probe_id: str,
    address: str,
    *,
    port: int = 443,
    timeout: float = 2.5,
) -> ProbeResult:
    """Ask a pinned IP for QUIC versions without a third-party QUIC library."""

    started = time.perf_counter()
    parsed = ipaddress.ip_address(address)
    family = socket.AF_INET6 if parsed.version == 6 else socket.AF_INET
    endpoint: tuple[object, ...] = (address, port, 0, 0) if parsed.version == 6 else (address, port)
    dcid = secrets.token_bytes(8)
    scid = secrets.token_bytes(8)
    evidence: dict[str, object] = {
        "variant": "quic_version_negotiation",
        "probe_version": f"0x{_UNSUPPORTED_GREASE_VERSION:08x}",
        "response_versions": [],
    }
    try:
        with socket.socket(family, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.connect(endpoint)
            sock.send(build_version_negotiation_probe(dcid, scid))
            response = sock.recv(2048)
        versions = parse_version_negotiation(
            response,
            original_dcid=dcid,
            original_scid=scid,
        )
        evidence["response_versions"] = [f"0x{version:08x}" for version in versions]
        outcome, error = Outcome.SUCCESS, None
    except (OSError, TimeoutError, ValueError) as exc:
        outcome, error = normalize_exception(exc, stage="quic_version_negotiation")
    return ProbeResult(
        id=probe_id,
        probe_type="udp_quic",
        stage="udp",
        outcome=outcome,
        duration_ms=(time.perf_counter() - started) * 1000,
        family=family_name(address),
        endpoint_ip=address,
        endpoint_port=port,
        evidence=evidence,
        error=error,
    )
