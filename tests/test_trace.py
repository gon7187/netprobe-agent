from __future__ import annotations

import pytest

from netprobe.trace import build_trace_command, parse_traceroute

WINDOWS = """
Tracing route to 1.1.1.1 over a maximum of 5 hops
  1    <1 ms    <1 ms     1 ms  192.168.1.1
  2     *        *        *     Request timed out.
  3    10 ms    11 ms    12 ms  1.1.1.1
Trace complete.
"""

WINDOWS_RU = """
Трассировка маршрута к 2606:4700:4700::1111
  1     1 мс     2 мс     1 мс  2001:db8::1
  2     *        *        *     Превышен интервал ожидания для запроса.
"""

LINUX = """
traceroute to 1.1.1.1 (1.1.1.1), 5 hops max
 1  192.168.1.1  0.500 ms
 2  *
 3  10.0.0.1  1.2 ms  10.0.0.2  1.4 ms
 4  1.1.1.1  10.2 ms
"""


def test_parse_windows_and_ignore_header_target() -> None:
    result = parse_traceroute(WINDOWS, target_ip="1.1.1.1", platform_name="windows")
    assert result.reached is True
    assert [hop.ttl for hop in result.hops] == [1, 2, 3]
    assert result.hops[1].timed_out is True
    assert result.hops[0].responders[0].ip == "192.168.1.1"
    assert result.hops[0].responders[0].rtt_ms == 0.5


def test_parse_localized_ipv6_timeout() -> None:
    result = parse_traceroute(
        WINDOWS_RU,
        target_ip="2606:4700:4700::1111",
        platform_name="windows",
    )
    assert result.reached is False
    assert result.hops[0].responders[0].ip == "2001:db8::1"
    assert result.hops[1].timed_out is True


def test_parse_linux_multiple_responders() -> None:
    result = parse_traceroute(LINUX, target_ip="1.1.1.1", platform_name="linux")
    assert result.reached is True
    assert [item.ip for item in result.hops[2].responders] == ["10.0.0.1", "10.0.0.2"]


def test_build_trace_command_validates_numeric_ip() -> None:
    command = build_trace_command(
        "1.1.1.1",
        max_hops=5,
        wait_ms=500,
        platform_name="windows",
        executable="tracert.exe",
    )
    assert command == ["tracert.exe", "-d", "-4", "-h", "5", "-w", "500", "1.1.1.1"]

    with pytest.raises(ValueError):
        build_trace_command(
            "1.1.1.1 & calc.exe",
            max_hops=5,
            wait_ms=500,
            platform_name="windows",
        )
