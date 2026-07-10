"""Pinned-IP TCP, TLS/SNI, and HTTP probes."""

from __future__ import annotations

import errno
import hashlib
import ipaddress
import re
import socket
import ssl
import time
from collections.abc import Callable
from contextlib import closing, suppress
from typing import Any

from netprobe.models import Outcome, ProbeError, ProbeResult

_RESET_CODES = {errno.ECONNRESET, errno.EPIPE, 10054, 10053}
_REFUSED_CODES = {errno.ECONNREFUSED, 10061}
_UNREACHABLE_CODES = {
    errno.ENETUNREACH,
    errno.EHOSTUNREACH,
    errno.ENETDOWN,
    errno.EADDRNOTAVAIL,
    10051,
    10065,
    10049,
}
_TIMEOUT_CODES = {errno.ETIMEDOUT, 10060}
_STATUS_LINE = re.compile(rb"^HTTP/\d(?:\.\d)?\s+(\d{3})(?:\s|$)")
_BLOCKPAGE_PATTERNS: tuple[tuple[str, tuple[str, ...]], ...] = (
    (
        "rkn_registry",
        (
            "eais.rkn.gov.ru",
            "единый реестр доменных имен",
            "доступ к информационному ресурсу ограничен",
        ),
    ),
    (
        "isp_restriction_notice",
        (
            "access to the requested resource has been restricted",
            "access to this resource is restricted",
        ),
    ),
)


def family_name(address: str) -> str:
    return "ipv6" if ipaddress.ip_address(address).version == 6 else "ipv4"


def _family(address: str) -> socket.AddressFamily:
    return socket.AF_INET6 if ipaddress.ip_address(address).version == 6 else socket.AF_INET


def _endpoint(address: str, port: int) -> tuple[Any, ...]:
    return (address, port, 0, 0) if _family(address) == socket.AF_INET6 else (address, port)


def _error_code(exc: BaseException) -> int | None:
    if isinstance(exc, OSError):
        return exc.winerror if getattr(exc, "winerror", None) is not None else exc.errno
    return None


def normalize_exception(exc: BaseException, *, stage: str) -> tuple[Outcome, ProbeError]:
    """Normalize platform-specific socket/TLS errors without relying on localized text."""

    code = _error_code(exc)
    if isinstance(exc, ssl.SSLCertVerificationError):
        outcome, category = Outcome.CERTIFICATE_ERROR, "certificate_verification"
    elif isinstance(exc, (socket.timeout, TimeoutError)) or code in _TIMEOUT_CODES:
        outcome, category = Outcome.TIMEOUT, "timeout"
    elif isinstance(exc, ConnectionRefusedError) or code in _REFUSED_CODES:
        outcome, category = Outcome.REFUSED, "connection_refused"
    elif isinstance(exc, (ConnectionResetError, BrokenPipeError)) or code in _RESET_CODES:
        outcome, category = Outcome.RESET, "connection_reset"
    elif code in _UNREACHABLE_CODES:
        outcome, category = Outcome.UNREACHABLE, "network_unreachable"
    elif isinstance(exc, ssl.SSLError):
        outcome, category = Outcome.TLS_ALERT, "tls_error"
    else:
        outcome, category = Outcome.ERROR, type(exc).__name__.lower()
    message = " ".join(str(exc).split())[:300]
    return outcome, ProbeError(category=category, message=message, stage=stage, code=code)


def _open_socket(address: str, port: int, timeout: float) -> socket.socket:
    sock = socket.socket(_family(address), socket.SOCK_STREAM)
    try:
        sock.settimeout(timeout)
        sock.connect(_endpoint(address, port))
    except BaseException:
        sock.close()
        raise
    return sock


def probe_tcp(
    probe_id: str,
    address: str,
    port: int,
    *,
    timeout: float,
    probe_type: str = "tcp",
    attempt: int = 1,
) -> ProbeResult:
    started = time.perf_counter()
    try:
        with closing(_open_socket(address, port, timeout)):
            outcome, error = Outcome.SUCCESS, None
    except (OSError, TimeoutError) as exc:
        outcome, error = normalize_exception(exc, stage="connect")
    return ProbeResult(
        id=probe_id,
        probe_type=probe_type,
        stage="tcp",
        outcome=outcome,
        duration_ms=(time.perf_counter() - started) * 1000,
        attempt=attempt,
        family=family_name(address),
        endpoint_ip=address,
        endpoint_port=port,
        error=error,
    )


def _read_bio(bio: ssl.MemoryBIO) -> bytes:
    chunks: list[bytes] = []
    while bio.pending:
        chunks.append(bio.read())
    return b"".join(chunks)


def _send_first_flight(
    sock: socket.socket,
    payload: bytes,
    *,
    hostname: str | None,
    fragment_sni: bool,
    fragment_delay: float,
) -> int | None:
    if not fragment_sni or not hostname:
        sock.sendall(payload)
        return None
    needle = hostname.encode("ascii")
    position = payload.find(needle)
    if position < 0:
        raise RuntimeError("SNI hostname was not found in generated ClientHello")
    split_offset = position + max(1, len(needle) // 2)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    sock.sendall(payload[:split_offset])
    time.sleep(fragment_delay)
    sock.sendall(payload[split_offset:])
    return split_offset


def _memory_bio_handshake(
    address: str,
    port: int,
    *,
    hostname: str | None,
    timeout: float,
    verify: bool,
    fragment_sni: bool,
    fragment_delay: float,
    forced_version: str | None,
) -> dict[str, Any]:
    if verify:
        context = ssl.create_default_context()
        context.check_hostname = hostname is not None
    else:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    if forced_version == "1.2":
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.maximum_version = ssl.TLSVersion.TLSv1_2
    elif forced_version == "1.3":
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.maximum_version = ssl.TLSVersion.TLSv1_3
    elif forced_version is not None:
        raise ValueError("forced_version must be 1.2, 1.3, or None")
    context.set_alpn_protocols(["h2", "http/1.1"])
    incoming = ssl.MemoryBIO()
    outgoing = ssl.MemoryBIO()
    tls = context.wrap_bio(incoming, outgoing, server_side=False, server_hostname=hostname)
    deadline = time.monotonic() + timeout
    first_flight = True
    split_offset: int | None = None

    with closing(_open_socket(address, port, timeout)) as sock:
        while True:
            try:
                tls.do_handshake()
                pending = _read_bio(outgoing)
                if pending:
                    sock.sendall(pending)
                break
            except ssl.SSLWantReadError:
                pending = _read_bio(outgoing)
                if pending:
                    if first_flight:
                        split_offset = _send_first_flight(
                            sock,
                            pending,
                            hostname=hostname,
                            fragment_sni=fragment_sni,
                            fragment_delay=fragment_delay,
                        )
                        first_flight = False
                    else:
                        sock.sendall(pending)
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("TLS handshake deadline exceeded") from None
                sock.settimeout(remaining)
                data = sock.recv(65536)
                if not data:
                    raise ConnectionResetError("peer closed during TLS handshake") from None
                incoming.write(data)
            except ssl.SSLWantWriteError:
                pending = _read_bio(outgoing)
                if pending:
                    sock.sendall(pending)

        certificate = tls.getpeercert(binary_form=True)
        cipher = tls.cipher()
        return {
            "tls_version": tls.version(),
            "cipher": cipher[0] if cipher else None,
            "alpn": tls.selected_alpn_protocol(),
            "peer_certificate_sha256": hashlib.sha256(certificate).hexdigest()
            if certificate
            else None,
            "client_hello_fragment_offset": split_offset,
            "diagnostic_unverified": not verify,
        }


def probe_tls(
    probe_id: str,
    address: str,
    port: int,
    *,
    hostname: str | None,
    timeout: float,
    variant: str,
    verify: bool = False,
    fragment_sni: bool = False,
    fragment_delay: float = 0.05,
    forced_version: str | None = None,
    attempt: int = 1,
) -> ProbeResult:
    started = time.perf_counter()
    evidence: dict[str, Any] = {
        "variant": variant,
        "sni": hostname,
        "fragmented": fragment_sni,
        "verified": verify,
        "forced_tls_version": forced_version,
    }
    try:
        evidence.update(
            _memory_bio_handshake(
                address,
                port,
                hostname=hostname,
                timeout=timeout,
                verify=verify,
                fragment_sni=fragment_sni,
                fragment_delay=fragment_delay,
                forced_version=forced_version,
            )
        )
        outcome, error = Outcome.SUCCESS, None
    except (OSError, ssl.SSLError, TimeoutError, RuntimeError) as exc:
        outcome, error = normalize_exception(exc, stage="tls_handshake")
    return ProbeResult(
        id=probe_id,
        probe_type="tls",
        stage="tls",
        outcome=outcome,
        duration_ms=(time.perf_counter() - started) * 1000,
        attempt=attempt,
        family=family_name(address),
        endpoint_ip=address,
        endpoint_port=port,
        hostname=hostname,
        evidence=evidence,
        error=error,
    )


def _decode_blockpage(data: bytes) -> str | None:
    texts = [data.decode("utf-8", errors="ignore").lower()]
    with suppress(LookupError):
        texts.append(data.decode("cp1251", errors="ignore").lower())
    for label, patterns in _BLOCKPAGE_PATTERNS:
        if any(pattern in text for text in texts for pattern in patterns):
            return label
    return None


def _parse_http_response(data: bytes) -> dict[str, Any]:
    head, _, body = data.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    match = _STATUS_LINE.match(lines[0]) if lines else None
    if match is None:
        raise ValueError("peer response does not start with an HTTP status line")
    headers: dict[str, str] = {}
    for line in lines[1:]:
        name, separator, value = line.partition(b":")
        if not separator:
            continue
        key = name.decode("ascii", errors="ignore").strip().lower()
        if key in {"content-type", "location", "server", "via"}:
            headers[key] = value.decode("iso-8859-1", errors="replace").strip()[:500]
    return {
        "status_code": int(match.group(1)),
        "headers": headers,
        "body_bytes_captured": len(body),
        "body_sha256": hashlib.sha256(body).hexdigest(),
        "blockpage_fingerprint": _decode_blockpage(body),
    }


def _send_http_request(
    sock: socket.socket,
    request: bytes,
    *,
    host_bytes: bytes,
    fragment_host: bool,
    fragment_delay: float,
) -> None:
    if not fragment_host:
        sock.sendall(request)
        return
    position = request.find(host_bytes)
    if position < 0:
        raise RuntimeError("Host header was not found in HTTP request")
    split_offset = position + max(1, len(host_bytes) // 2)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    sock.sendall(request[:split_offset])
    time.sleep(fragment_delay)
    sock.sendall(request[split_offset:])


def probe_http(
    probe_id: str,
    address: str,
    port: int,
    *,
    hostname: str,
    request_target: str,
    timeout: float,
    use_tls: bool,
    variant: str,
    fragment_host: bool = False,
    verify_tls: bool = True,
    fragment_delay: float = 0.05,
    max_response_bytes: int = 65536,
    attempt: int = 1,
) -> ProbeResult:
    started = time.perf_counter()
    evidence: dict[str, Any] = {
        "variant": variant,
        "scheme": "https" if use_tls else "http",
        "host_header": hostname,
        "fragmented": fragment_host,
    }
    stage = "connect"
    sock: socket.socket | ssl.SSLSocket | None = None
    try:
        raw = _open_socket(address, port, timeout)
        sock = raw
        if use_tls:
            stage = "tls_handshake"
            if verify_tls:
                context = ssl.create_default_context()
            else:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
            sock = context.wrap_socket(raw, server_hostname=hostname)
        stage = "http_write"
        host_bytes = hostname.encode("ascii")
        target_bytes = request_target.encode("ascii", errors="strict")
        request = (
            b"GET "
            + target_bytes
            + b" HTTP/1.1\r\nHost: "
            + host_bytes
            + b"\r\nUser-Agent: netprobe-agent/0.1\r\nAccept: */*\r\nConnection: close\r\n\r\n"
        )
        _send_http_request(
            sock,
            request,
            host_bytes=host_bytes,
            fragment_host=fragment_host,
            fragment_delay=fragment_delay,
        )
        stage = "http_read"
        chunks: list[bytes] = []
        total = 0
        while total < max_response_bytes:
            try:
                chunk = sock.recv(min(16384, max_response_bytes - total))
            except TimeoutError:
                if chunks:
                    break
                raise
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if b"\r\n\r\n" in b"".join(chunks) and total >= 32768:
                break
        evidence.update(_parse_http_response(b"".join(chunks)))
        outcome, error = Outcome.HTTP_RESPONSE, None
    except (OSError, ssl.SSLError, TimeoutError, UnicodeError, RuntimeError, ValueError) as exc:
        outcome, error = normalize_exception(exc, stage=stage)
    finally:
        if sock is not None:
            sock.close()
    return ProbeResult(
        id=probe_id,
        probe_type="http",
        stage="http",
        outcome=outcome,
        duration_ms=(time.perf_counter() - started) * 1000,
        attempt=attempt,
        family=family_name(address),
        endpoint_ip=address,
        endpoint_port=port,
        hostname=hostname,
        evidence=evidence,
        error=error,
    )


ProbeCallable = Callable[[], ProbeResult]
