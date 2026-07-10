"""Small, dependency-free DNS wire codec and transport helpers.

The module deliberately implements only the record data needed by the network
diagnostic tool (A, AAAA and CNAME).  Other record types are retained as raw
bytes so a response can still be inspected without accepting unbounded or
recursive parser work.
"""

from __future__ import annotations

import base64
import ipaddress
import math
import secrets
import socket
import ssl
import struct
import time
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final
from urllib import parse as urllib_parse
from urllib import request as urllib_request

__all__ = [
    "QTYPE_NAMES",
    "RCODE_NAMES",
    "DNSMessage",
    "DNSProtocolError",
    "DNSQuestion",
    "DNSRecord",
    "build_query",
    "decode_name",
    "dns_query_doh",
    "dns_query_tcp",
    "dns_query_udp",
    "doh_query",
    "encode_qname",
    "parse_response",
    "query_doh",
    "query_tcp",
    "query_udp",
    "rcode_name",
    "tcp_query",
    "udp_query",
]


_DNS_HEADER = struct.Struct("!HHHHHH")
_QUESTION_TAIL = struct.Struct("!HH")
_RECORD_HEADER = struct.Struct("!HHIH")

_MAX_MESSAGE_SIZE: Final = 65_535
_MAX_QUESTIONS: Final = 64
_MAX_RECORDS: Final = 4_096
_MAX_POINTER_JUMPS: Final = 128
_MAX_LABELS: Final = 127

_TYPE_A: Final = 1
_TYPE_CNAME: Final = 5
_TYPE_AAAA: Final = 28
_TYPE_OPT: Final = 41
_CLASS_IN: Final = 1

QTYPE_NAMES: Final[dict[int, str]] = {
    _TYPE_A: "A",
    _TYPE_CNAME: "CNAME",
    _TYPE_AAAA: "AAAA",
    _TYPE_OPT: "OPT",
}
_QTYPES_BY_NAME: Final = {name: code for code, name in QTYPE_NAMES.items()}

# Header RCODEs plus currently assigned extended RCODEs.  Extended values are
# recovered from an OPT pseudo-record when one is present.
RCODE_NAMES: Final[dict[int, str]] = {
    0: "NOERROR",
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMP",
    5: "REFUSED",
    6: "YXDOMAIN",
    7: "YXRRSET",
    8: "NXRRSET",
    9: "NOTAUTH",
    10: "NOTZONE",
    11: "DSOTYPENI",
    16: "BADVERS",
    17: "BADKEY",
    18: "BADTIME",
    19: "BADMODE",
    20: "BADNAME",
    21: "BADALG",
    22: "BADTRUNC",
    23: "BADCOOKIE",
}


class DNSProtocolError(ValueError):
    """Raised when a DNS message is malformed or does not match its query."""


@dataclass(frozen=True, slots=True)
class DNSQuestion:
    """A decoded DNS question."""

    name: str
    qtype: int
    qclass: int

    @property
    def type(self) -> int:
        """Return the numeric query type."""

        return self.qtype

    @property
    def type_name(self) -> str:
        """Return the mnemonic for the question type when it is known."""

        return QTYPE_NAMES.get(self.qtype, f"TYPE{self.qtype}")


@dataclass(frozen=True, slots=True)
class DNSRecord:
    """A decoded DNS resource record.

    ``data`` is a presentation-format string for A, AAAA and CNAME records and
    raw bytes for other types.  ``raw_data`` always contains the original RDATA.
    """

    name: str
    rtype: int
    rclass: int
    ttl: int
    data: str | bytes
    raw_data: bytes

    @property
    def type(self) -> int:
        """Return the numeric resource-record type."""

        return self.rtype

    @property
    def record_type(self) -> int:
        """Alias useful to callers that prefer a descriptive field name."""

        return self.rtype

    @property
    def record_class(self) -> int:
        """Alias useful to callers that prefer a descriptive field name."""

        return self.rclass

    @property
    def type_name(self) -> str:
        """Return the mnemonic for the record type when it is known."""

        return QTYPE_NAMES.get(self.rtype, f"TYPE{self.rtype}")

    @property
    def value(self) -> str | bytes:
        """Alias for decoded ``data``."""

        return self.data


@dataclass(frozen=True, slots=True)
class DNSMessage:
    """A validated DNS response and its decoded sections."""

    transaction_id: int
    flags: int
    questions: tuple[DNSQuestion, ...]
    answers: tuple[DNSRecord, ...]
    authorities: tuple[DNSRecord, ...]
    additionals: tuple[DNSRecord, ...]
    rcode: int

    @property
    def id(self) -> int:
        """Return the DNS transaction identifier."""

        return self.transaction_id

    @property
    def records(self) -> tuple[DNSRecord, ...]:
        """Return answer records (the primary records for a lookup)."""

        return self.answers

    @property
    def all_records(self) -> tuple[DNSRecord, ...]:
        """Return answer, authority and additional records in wire order."""

        return self.answers + self.authorities + self.additionals

    @property
    def rcode_name(self) -> str:
        """Return the standard mnemonic for the response code."""

        return rcode_name(self.rcode)

    @property
    def truncated(self) -> bool:
        """Whether the DNS TC flag is set."""

        return bool(self.flags & 0x0200)

    @property
    def authoritative(self) -> bool:
        """Whether the DNS AA flag is set."""

        return bool(self.flags & 0x0400)

    @property
    def recursion_available(self) -> bool:
        """Whether the resolver advertised recursion availability."""

        return bool(self.flags & 0x0080)

    @property
    def addresses(self) -> tuple[str, ...]:
        """Return A and AAAA values from the answer section."""

        return tuple(
            record.data
            for record in self.answers
            if record.rtype in {_TYPE_A, _TYPE_AAAA} and isinstance(record.data, str)
        )

    @property
    def cnames(self) -> tuple[str, ...]:
        """Return CNAME targets from the answer section."""

        return tuple(
            record.data
            for record in self.answers
            if record.rtype == _TYPE_CNAME and isinstance(record.data, str)
        )


def rcode_name(code: int) -> str:
    """Return a stable presentation name for a DNS response code."""

    return RCODE_NAMES.get(code, f"RCODE{code}")


def _qtype_code(qtype: int | str) -> int:
    if isinstance(qtype, str):
        try:
            return _QTYPES_BY_NAME[qtype.strip().upper()]
        except KeyError as exc:
            raise DNSProtocolError(f"unsupported DNS query type: {qtype!r}") from exc
    if isinstance(qtype, bool) or not isinstance(qtype, int) or not 0 <= qtype <= 0xFFFF:
        raise DNSProtocolError(f"DNS query type is outside uint16: {qtype!r}")
    return qtype


def _uint16(value: int, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 0xFFFF:
        raise DNSProtocolError(f"{field} is outside uint16: {value!r}")
    return value


def encode_qname(name: str) -> bytes:
    """Encode a Unicode or ASCII domain name into DNS question wire format.

    Unicode labels are converted with Python's built-in IDNA codec.  A single
    trailing dot is accepted.  Empty labels, control characters, labels longer
    than 63 octets and names longer than the DNS 255-octet limit are rejected.
    """

    if not isinstance(name, str):
        raise DNSProtocolError("DNS name must be a string")
    if name == ".":
        return b"\x00"
    if not name:
        raise DNSProtocolError("DNS name must not be empty")

    without_root = name[:-1] if name.endswith(".") else name
    if not without_root:
        return b"\x00"

    output = bytearray()
    for label in without_root.split("."):
        if not label:
            raise DNSProtocolError("DNS name contains an empty label")
        if any(ord(character) <= 0x20 or ord(character) == 0x7F for character in label):
            raise DNSProtocolError("DNS name contains a control or whitespace character")
        try:
            encoded = label.encode("idna")
        except UnicodeError as exc:
            raise DNSProtocolError(f"DNS label cannot be encoded with IDNA: {label!r}") from exc
        if not encoded or len(encoded) > 63:
            raise DNSProtocolError(f"DNS label exceeds 63 octets: {label!r}")
        # IDNA operates on labels.  A dot appearing after conversion would
        # otherwise smuggle an extra wire label into the query.
        if b"." in encoded or any(byte <= 0x20 or byte == 0x7F for byte in encoded):
            raise DNSProtocolError(f"DNS label has an invalid encoded form: {label!r}")
        output.append(len(encoded))
        output.extend(encoded)

    output.append(0)
    if len(output) > 255:
        raise DNSProtocolError("encoded DNS name exceeds 255 octets")
    return bytes(output)


def _canonical_name(name: str) -> str:
    wire = encode_qname(name)
    if wire == b"\x00":
        return "."
    labels: list[str] = []
    offset = 0
    while wire[offset]:
        length = wire[offset]
        offset += 1
        labels.append(wire[offset : offset + length].decode("ascii").lower())
        offset += length
    return ".".join(labels)


def build_query(
    name: str,
    qtype: int | str = _TYPE_A,
    *,
    transaction_id: int | None = None,
    qclass: int = _CLASS_IN,
    recursion_desired: bool = True,
    checking_disabled: bool = False,
) -> bytes:
    """Build a one-question DNS query.

    When ``transaction_id`` is omitted a cryptographically strong random
    16-bit identifier is used.  Supplying it is useful for deterministic tests
    and for callers that need to correlate the response themselves.
    """

    resolved_qtype = _qtype_code(qtype)
    resolved_qclass = _uint16(qclass, "DNS query class")
    resolved_id = (
        secrets.randbits(16)
        if transaction_id is None
        else _uint16(transaction_id, "DNS transaction ID")
    )
    flags = (0x0100 if recursion_desired else 0) | (0x0010 if checking_disabled else 0)
    return (
        _DNS_HEADER.pack(resolved_id, flags, 1, 0, 0, 0)
        + encode_qname(name)
        + _QUESTION_TAIL.pack(resolved_qtype, resolved_qclass)
    )


def _decode_label(label: bytes) -> str:
    try:
        decoded = label.decode("ascii")
    except UnicodeDecodeError as exc:
        raise DNSProtocolError("DNS name label is not ASCII/IDNA wire data") from exc
    if any(ord(character) <= 0x20 or ord(character) == 0x7F for character in decoded):
        raise DNSProtocolError("DNS name label contains control or whitespace data")
    if "." in decoded:
        raise DNSProtocolError("DNS name label contains an unescaped dot")
    return decoded


def _decode_name(message: bytes, offset: int) -> tuple[str, int]:
    """Decode one possibly compressed name and return its following offset."""

    if not 0 <= offset < len(message):
        raise DNSProtocolError("DNS name starts outside the message")

    labels: list[str] = []
    cursor = offset
    following_offset: int | None = None
    pointer_targets: set[int] = set()
    pointer_jumps = 0
    expanded_length = 1  # terminating root label

    while True:
        if cursor >= len(message):
            raise DNSProtocolError("truncated DNS name")
        length = message[cursor]

        if length & 0xC0 == 0xC0:
            if cursor + 1 >= len(message):
                raise DNSProtocolError("truncated DNS compression pointer")
            target = ((length & 0x3F) << 8) | message[cursor + 1]
            if target >= len(message):
                raise DNSProtocolError("DNS compression pointer is outside the message")
            # RFC 1035 compression pointers refer to a prior occurrence.  This
            # restriction also makes pointer cycles impossible by construction.
            if target >= cursor:
                raise DNSProtocolError("DNS compression pointer does not point backwards")
            if target in pointer_targets:
                raise DNSProtocolError("DNS compression pointer loop detected")
            pointer_targets.add(target)
            pointer_jumps += 1
            if pointer_jumps > _MAX_POINTER_JUMPS:
                raise DNSProtocolError("too many DNS compression pointer jumps")
            if following_offset is None:
                following_offset = cursor + 2
            cursor = target
            continue

        if length & 0xC0:
            raise DNSProtocolError("unsupported DNS extended label type")
        cursor += 1
        if length == 0:
            if following_offset is None:
                following_offset = cursor
            break
        if length > 63:
            raise DNSProtocolError("DNS label exceeds 63 octets")
        label_end = cursor + length
        if label_end > len(message):
            raise DNSProtocolError("truncated DNS label")
        expanded_length += length + 1
        if expanded_length > 255:
            raise DNSProtocolError("expanded DNS name exceeds 255 octets")
        labels.append(_decode_label(message[cursor:label_end]))
        if len(labels) > _MAX_LABELS:
            raise DNSProtocolError("DNS name contains too many labels")
        cursor = label_end

    if following_offset is None:  # Defensive: the terminating label always sets it.
        raise DNSProtocolError("DNS name has no terminating root label")
    return (".".join(labels) if labels else "."), following_offset


def decode_name(message: bytes | bytearray | memoryview, offset: int) -> tuple[str, int]:
    """Public bounded decoder for a name embedded in a DNS message."""

    return _decode_name(bytes(message), offset)


def _parse_question(message: bytes, offset: int) -> tuple[DNSQuestion, int]:
    name, offset = _decode_name(message, offset)
    if offset + _QUESTION_TAIL.size > len(message):
        raise DNSProtocolError("truncated DNS question")
    qtype, qclass = _QUESTION_TAIL.unpack_from(message, offset)
    return DNSQuestion(name=name, qtype=qtype, qclass=qclass), offset + _QUESTION_TAIL.size


def _parse_record(message: bytes, offset: int) -> tuple[DNSRecord, int]:
    name, offset = _decode_name(message, offset)
    if offset + _RECORD_HEADER.size > len(message):
        raise DNSProtocolError("truncated DNS resource record header")
    rtype, rclass, ttl, data_length = _RECORD_HEADER.unpack_from(message, offset)
    data_offset = offset + _RECORD_HEADER.size
    data_end = data_offset + data_length
    if data_end > len(message):
        raise DNSProtocolError("truncated DNS resource record data")
    raw_data = message[data_offset:data_end]

    if rtype == _TYPE_A:
        if data_length != 4:
            raise DNSProtocolError("A record RDATA must be exactly 4 octets")
        data: str | bytes = str(ipaddress.IPv4Address(raw_data))
    elif rtype == _TYPE_AAAA:
        if data_length != 16:
            raise DNSProtocolError("AAAA record RDATA must be exactly 16 octets")
        data = str(ipaddress.IPv6Address(raw_data))
    elif rtype == _TYPE_CNAME:
        data, cname_end = _decode_name(message, data_offset)
        if cname_end != data_end:
            raise DNSProtocolError("CNAME RDATA length does not match its encoded name")
    else:
        data = raw_data

    return (
        DNSRecord(
            name=name,
            rtype=rtype,
            rclass=rclass,
            ttl=ttl,
            data=data,
            raw_data=raw_data,
        ),
        data_end,
    )


def parse_response(
    packet: bytes | bytearray | memoryview,
    *,
    expected_id: int | None = None,
    expected_name: str | None = None,
    expected_qtype: int | str | None = None,
    expected_qclass: int = _CLASS_IN,
) -> DNSMessage:
    """Parse and validate a DNS response.

    Expected values should be supplied for network responses.  Name comparison
    is case-insensitive and IDNA-aware.  Every section is consumed exactly; a
    packet with trailing bytes or impossible section counts is rejected.
    """

    message = bytes(packet)
    if len(message) < _DNS_HEADER.size:
        raise DNSProtocolError("DNS response is shorter than its header")
    if len(message) > _MAX_MESSAGE_SIZE:
        raise DNSProtocolError("DNS response exceeds 65535 octets")

    transaction_id, flags, qdcount, ancount, nscount, arcount = _DNS_HEADER.unpack_from(message)
    if not flags & 0x8000:
        raise DNSProtocolError("DNS packet is not a response")
    if flags & 0x7800:
        raise DNSProtocolError("unsupported non-zero DNS opcode")
    if flags & 0x0040:
        raise DNSProtocolError("reserved DNS header flag is set")
    if qdcount > _MAX_QUESTIONS:
        raise DNSProtocolError("DNS response contains too many questions")
    record_count = ancount + nscount + arcount
    if record_count > _MAX_RECORDS:
        raise DNSProtocolError("DNS response contains too many resource records")
    # A root question needs 5 bytes; a root owner plus fixed RR header needs 11.
    # This cheap bound rejects hostile counts before entering parser loops.
    if _DNS_HEADER.size + qdcount * 5 + record_count * 11 > len(message):
        raise DNSProtocolError("DNS section counts cannot fit in the response")

    if expected_id is not None:
        resolved_expected_id = _uint16(expected_id, "expected DNS transaction ID")
        if transaction_id != resolved_expected_id:
            raise DNSProtocolError(
                "DNS transaction ID mismatch: "
                f"expected {resolved_expected_id:#06x}, received {transaction_id:#06x}"
            )

    offset = _DNS_HEADER.size
    questions: list[DNSQuestion] = []
    for _ in range(qdcount):
        question, offset = _parse_question(message, offset)
        questions.append(question)

    question_expectation = expected_name is not None or expected_qtype is not None
    if question_expectation:
        if len(questions) != 1:
            raise DNSProtocolError(
                f"DNS question count mismatch: expected 1, received {len(questions)}"
            )
        question = questions[0]
        if expected_name is not None and question.name.lower() != _canonical_name(expected_name):
            raise DNSProtocolError(
                "DNS question name mismatch: "
                f"expected {expected_name!r}, received {question.name!r}"
            )
        if expected_qtype is not None and question.qtype != _qtype_code(expected_qtype):
            raise DNSProtocolError(
                "DNS question type mismatch: "
                f"expected {_qtype_code(expected_qtype)}, received {question.qtype}"
            )
        resolved_qclass = _uint16(expected_qclass, "expected DNS question class")
        if question.qclass != resolved_qclass:
            raise DNSProtocolError(
                "DNS question class mismatch: "
                f"expected {resolved_qclass}, received {question.qclass}"
            )

    def parse_records(count: int) -> tuple[DNSRecord, ...]:
        nonlocal offset
        records: list[DNSRecord] = []
        for _ in range(count):
            record, offset = _parse_record(message, offset)
            records.append(record)
        return tuple(records)

    answers = parse_records(ancount)
    authorities = parse_records(nscount)
    additionals = parse_records(arcount)
    if offset != len(message):
        raise DNSProtocolError("DNS response has trailing bytes after its declared sections")

    opt_records = [record for record in additionals if record.rtype == _TYPE_OPT]
    if len(opt_records) > 1:
        raise DNSProtocolError("DNS response contains more than one OPT record")
    extended_rcode = 0
    if opt_records:
        opt_record = opt_records[0]
        if opt_record.name != ".":
            raise DNSProtocolError("OPT record owner name must be the DNS root")
        extended_rcode = (opt_record.ttl >> 24) & 0xFF
    response_code = (extended_rcode << 4) | (flags & 0x000F)

    return DNSMessage(
        transaction_id=transaction_id,
        flags=flags,
        questions=tuple(questions),
        answers=answers,
        authorities=authorities,
        additionals=additionals,
        rcode=response_code,
    )


def _validate_timeout(timeout: float) -> float:
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
        raise ValueError("DNS timeout must be a positive finite number")
    resolved = float(timeout)
    if not math.isfinite(resolved) or resolved <= 0:
        raise ValueError("DNS timeout must be a positive finite number")
    return resolved


def _validate_port(port: int) -> int:
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65_535:
        raise ValueError("DNS port must be between 1 and 65535")
    return port


def _server_host(server: str) -> str:
    if not isinstance(server, str) or not server.strip():
        raise ValueError("DNS server must be a non-empty hostname or address")
    host = server.strip()
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    return host


def _remaining(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("DNS query timed out")
    return remaining


def query_udp(
    server: str,
    name: str,
    qtype: int | str = _TYPE_A,
    *,
    port: int = 53,
    timeout: float = 3.0,
    transaction_id: int | None = None,
    family: int = socket.AF_UNSPEC,
    source: str | None = None,
) -> DNSMessage:
    """Send one DNS query over UDP and return a validated response.

    The socket is connected, so the operating system discards datagrams from a
    different source endpoint.  Truncated responses are returned with
    ``message.truncated`` set; callers can explicitly compare them with TCP.
    """

    host = _server_host(server)
    resolved_port = _validate_port(port)
    resolved_timeout = _validate_timeout(timeout)
    resolved_qtype = _qtype_code(qtype)
    query_id = (
        secrets.randbits(16)
        if transaction_id is None
        else _uint16(transaction_id, "DNS transaction ID")
    )
    query = build_query(name, resolved_qtype, transaction_id=query_id)
    endpoints = socket.getaddrinfo(host, resolved_port, family, socket.SOCK_DGRAM)
    deadline = time.monotonic() + resolved_timeout
    last_error: OSError | None = None

    for address_family, socket_type, protocol, _, sockaddr in endpoints:
        sock = socket.socket(address_family, socket_type, protocol)
        try:
            sock.settimeout(_remaining(deadline))
            if source is not None:
                sock.bind((source, 0))
            sock.connect(sockaddr)
            sock.sendall(query)
            sock.settimeout(_remaining(deadline))
            response = sock.recv(_MAX_MESSAGE_SIZE)
            return parse_response(
                response,
                expected_id=query_id,
                expected_name=name,
                expected_qtype=resolved_qtype,
            )
        except OSError as exc:
            last_error = exc
        finally:
            sock.close()

    if last_error is not None:
        raise last_error
    raise OSError(f"no usable address found for DNS server {host!r}")


def _recv_exact(sock: socket.socket, count: int, deadline: float) -> bytes:
    chunks: list[bytes] = []
    remaining_bytes = count
    while remaining_bytes:
        sock.settimeout(_remaining(deadline))
        chunk = sock.recv(remaining_bytes)
        if not chunk:
            raise DNSProtocolError("TCP DNS response ended before its declared length")
        chunks.append(chunk)
        remaining_bytes -= len(chunk)
    return b"".join(chunks)


def query_tcp(
    server: str,
    name: str,
    qtype: int | str = _TYPE_A,
    *,
    port: int = 53,
    timeout: float = 3.0,
    transaction_id: int | None = None,
    family: int = socket.AF_UNSPEC,
    source: str | None = None,
) -> DNSMessage:
    """Send one length-prefixed DNS query over TCP and validate its response."""

    host = _server_host(server)
    resolved_port = _validate_port(port)
    resolved_timeout = _validate_timeout(timeout)
    resolved_qtype = _qtype_code(qtype)
    query_id = (
        secrets.randbits(16)
        if transaction_id is None
        else _uint16(transaction_id, "DNS transaction ID")
    )
    query = build_query(name, resolved_qtype, transaction_id=query_id)
    endpoints = socket.getaddrinfo(host, resolved_port, family, socket.SOCK_STREAM)
    deadline = time.monotonic() + resolved_timeout
    last_error: OSError | None = None

    for address_family, socket_type, protocol, _, sockaddr in endpoints:
        sock = socket.socket(address_family, socket_type, protocol)
        try:
            sock.settimeout(_remaining(deadline))
            if source is not None:
                sock.bind((source, 0))
            sock.connect(sockaddr)
            sock.sendall(struct.pack("!H", len(query)) + query)
            response_length = struct.unpack("!H", _recv_exact(sock, 2, deadline))[0]
            if response_length < _DNS_HEADER.size:
                raise DNSProtocolError("TCP DNS response length is shorter than its header")
            response = _recv_exact(sock, response_length, deadline)
            return parse_response(
                response,
                expected_id=query_id,
                expected_name=name,
                expected_qtype=resolved_qtype,
            )
        except OSError as exc:
            last_error = exc
        finally:
            sock.close()

    if last_error is not None:
        raise last_error
    raise OSError(f"no usable address found for DNS server {host!r}")


def query_doh(
    url: str,
    name: str,
    qtype: int | str = _TYPE_A,
    *,
    timeout: float = 5.0,
    transaction_id: int | None = None,
    method: str = "POST",
    headers: Mapping[str, str] | None = None,
    ssl_context: ssl.SSLContext | None = None,
    allow_insecure_http: bool = False,
) -> DNSMessage:
    """Send a DNS-over-HTTPS query using only the Python standard library.

    RFC 8484 POST and GET encodings are supported.  HTTPS is required unless
    ``allow_insecure_http`` is explicitly enabled for a controlled test server.
    """

    resolved_timeout = _validate_timeout(timeout)
    parsed_url = urllib_parse.urlsplit(url)
    if parsed_url.scheme not in {"http", "https"} or not parsed_url.netloc:
        raise ValueError("DoH URL must be an absolute HTTP(S) URL")
    if parsed_url.scheme != "https" and not allow_insecure_http:
        raise ValueError("DoH requires HTTPS; enable allow_insecure_http only for local tests")

    resolved_qtype = _qtype_code(qtype)
    query_id = (
        secrets.randbits(16)
        if transaction_id is None
        else _uint16(transaction_id, "DNS transaction ID")
    )
    query = build_query(name, resolved_qtype, transaction_id=query_id)
    resolved_method = method.upper()
    request_headers = {
        "Accept": "application/dns-message",
        "User-Agent": "netprobe-agent/0.1",
    }
    if headers is not None:
        request_headers.update(headers)

    if resolved_method == "POST":
        request_headers["Content-Type"] = "application/dns-message"
        request_url = url
        request_data: bytes | None = query
    elif resolved_method == "GET":
        encoded_query = base64.urlsafe_b64encode(query).rstrip(b"=").decode("ascii")
        query_items = urllib_parse.parse_qsl(parsed_url.query, keep_blank_values=True)
        query_items.append(("dns", encoded_query))
        request_url = urllib_parse.urlunsplit(
            parsed_url._replace(query=urllib_parse.urlencode(query_items))
        )
        request_data = None
    else:
        raise ValueError("DoH method must be POST or GET")

    http_request = urllib_request.Request(
        request_url,
        data=request_data,
        headers=request_headers,
        method=resolved_method,
    )
    with urllib_request.urlopen(
        http_request,
        timeout=resolved_timeout,
        context=ssl_context,
    ) as response:
        content_length = response.headers.get("Content-Length")
        if content_length is not None:
            try:
                declared_length = int(content_length)
            except ValueError as exc:
                raise DNSProtocolError("DoH response has an invalid Content-Length") from exc
            if declared_length > _MAX_MESSAGE_SIZE:
                raise DNSProtocolError("DoH response exceeds 65535 octets")

        content_type = response.headers.get("Content-Type")
        if content_type is not None and content_type.split(";", 1)[0].strip().lower() != (
            "application/dns-message"
        ):
            raise DNSProtocolError(f"unexpected DoH response Content-Type: {content_type!r}")
        response_data = response.read(_MAX_MESSAGE_SIZE + 1)

    if len(response_data) > _MAX_MESSAGE_SIZE:
        raise DNSProtocolError("DoH response exceeds 65535 octets")
    return parse_response(
        response_data,
        expected_id=query_id,
        expected_name=name,
        expected_qtype=resolved_qtype,
    )


# Both word orders are exported because codebases commonly use either spelling.
udp_query = query_udp
tcp_query = query_tcp
doh_query = query_doh
dns_query_udp = query_udp
dns_query_tcp = query_tcp
dns_query_doh = query_doh
