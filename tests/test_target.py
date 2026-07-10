from __future__ import annotations

import pytest

from netprobe.target import TargetError, parse_target


@pytest.mark.parametrize(
    ("raw", "scheme", "host", "host_idna", "port", "path"),
    [
        ("example.com", "https", "example.com", "example.com", 443, "/"),
        ("203.0.113.7:8443", "https", "203.0.113.7", "203.0.113.7", 8443, "/"),
        (
            "https://Example.COM:8443/a?q=1",
            "https",
            "example.com",
            "example.com",
            8443,
            "/a?q=1",
        ),
        (
            "http://[2001:db8::1]:8080/x",
            "http",
            "2001:db8::1",
            "2001:db8::1",
            8080,
            "/x",
        ),
        ("пример.рф", "https", "пример.рф", "xn--e1afmkfd.xn--p1ai", 443, "/"),
    ],
)
def test_parse_target_matrix(
    raw: str,
    scheme: str,
    host: str,
    host_idna: str,
    port: int,
    path: str,
) -> None:
    target = parse_target(raw)

    assert target.scheme == scheme
    assert target.hostname == host
    assert target.hostname_idna == host_idna
    assert target.port == port
    assert target.request_target == path


@pytest.mark.parametrize(
    "raw",
    [
        "file:///etc/passwd",
        "ftp://example.com",
        "https://user:pass@example.com",
        "https://",
        "https://example.com:0",
        "https://example.com:65536",
        "http://[2001:db8::1",
        "https://bad..example",
        "https://example.com\x00/",
        "https://example.com\r\nX-Test: yes",
        "example.com & calc.exe",
        "https://" + "a" * 64 + ".example",
        "https://" + "a" * 2050 + ".example",
    ],
)
def test_reject_unsafe_targets(raw: str) -> None:
    with pytest.raises(TargetError):
        parse_target(raw)
