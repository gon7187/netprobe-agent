"""Cross-platform traceroute execution and output parsing.

The command builder deliberately accepts only a numeric destination address.  Host
name resolution belongs to the DNS probes, and keeping a validated address as one
argv element also makes the subprocess boundary unambiguous.
"""

from __future__ import annotations

import ipaddress
import locale
import math
import platform
import re
import subprocess
from dataclasses import dataclass
from numbers import Integral, Real
from typing import Any

_HOP_LINE = re.compile(r"^\s*(?P<ttl>[0-9]{1,3})(?=\s)")
_TOKEN = re.compile(r"\S+")
_RTT = re.compile(
    r"(?P<less_than><)?\s*(?P<value>[0-9]+(?:[.,][0-9]+)?)\s*"
    r"(?:ms|msec|msecs|millisecond|milliseconds|мс|мсек|毫秒)\b",
    re.IGNORECASE,
)
_TOKEN_EDGE_CHARS = "()[]{}<>,;\"'"


@dataclass(frozen=True, slots=True)
class TraceResponder:
    """One distinct address that answered for a hop."""

    ip: str
    rtt_ms: float | None = None

    def to_dict(self) -> dict[str, str | float | None]:
        """Return JSON-friendly primitive values."""

        return {"ip": self.ip, "rtt_ms": self.rtt_ms}


@dataclass(frozen=True, slots=True)
class TraceHop:
    """Parsed responses for one TTL value."""

    ttl: int
    responders: tuple[TraceResponder, ...] = ()
    timed_out: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Return JSON-friendly primitive values."""

        return {
            "ttl": self.ttl,
            "responders": [responder.to_dict() for responder in self.responders],
            "timed_out": self.timed_out,
        }


@dataclass(frozen=True, slots=True)
class TraceResult:
    """A parsed trace and, when executed locally, its process metadata."""

    target_ip: str
    platform_name: str
    hops: tuple[TraceHop, ...]
    reached: bool
    command: tuple[str, ...] = ()
    return_code: int | None = None
    raw_output: str = ""
    error: str | None = None
    timed_out: bool = False

    @property
    def platform(self) -> str:
        """Canonical platform name, retained as a convenient short alias."""

        return self.platform_name

    def to_dict(self) -> dict[str, Any]:
        """Return a stable mapping containing only JSON-friendly values."""

        return {
            "target_ip": self.target_ip,
            "platform_name": self.platform_name,
            "hops": [hop.to_dict() for hop in self.hops],
            "reached": self.reached,
            "command": list(self.command),
            "return_code": self.return_code,
            "raw_output": self.raw_output,
            "error": self.error,
            "timed_out": self.timed_out,
        }


def _numeric_ip(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError("target_ip must be a numeric IPv4 or IPv6 address")

    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise ValueError("target_ip must be a numeric IPv4 or IPv6 address") from exc

    # A scope identifier is useful for local socket APIs but is not a numeric IP
    # destination suitable for portable traceroute argv.
    if isinstance(address, ipaddress.IPv6Address) and address.scope_id is not None:
        raise ValueError("target_ip must not contain an IPv6 scope identifier")
    return address


def _platform_name(value: str | None) -> str:
    name = platform.system() if value is None else value
    if not isinstance(name, str):
        raise ValueError("platform_name must identify Windows, Linux, or macOS")

    normalized = name.strip().lower()
    if normalized.startswith("win"):
        return "windows"
    if normalized.startswith("linux"):
        return "linux"
    if normalized in {"darwin", "mac", "macos", "mac os", "osx"}:
        return "darwin"
    raise ValueError(f"unsupported traceroute platform: {name!r}")


def _positive_int(value: int, *, name: str, maximum: int | None = None) -> int:
    if isinstance(value, bool) or not isinstance(value, Integral):
        raise ValueError(f"{name} must be a positive integer")
    result = int(value)
    if result <= 0 or (maximum is not None and result > maximum):
        suffix = f" no greater than {maximum}" if maximum is not None else ""
        message = f"{name} must be positive and{suffix}" if suffix else f"{name} must be positive"
        raise ValueError(message)
    return result


def _executable(value: str | None, *, default: str) -> str:
    if value is None:
        return default
    if not isinstance(value, str) or not value.strip() or "\x00" in value:
        raise ValueError("executable must be a non-empty path or program name")
    return value


def _seconds_argument(wait_ms: int) -> str:
    seconds = wait_ms / 1000
    return f"{seconds:.3f}".rstrip("0").rstrip(".")


def build_trace_command(
    target_ip: str,
    *,
    max_hops: int = 30,
    wait_ms: int = 1_000,
    platform_name: str | None = None,
    executable: str | None = None,
) -> list[str]:
    """Build a native traceroute argv list for a validated numeric address.

    No part of the returned value is shell syntax.  It is intended to be passed
    directly to :func:`subprocess.run` with ``shell=False``.
    """

    address = _numeric_ip(target_ip)
    hops = _positive_int(max_hops, name="max_hops", maximum=255)
    wait = _positive_int(wait_ms, name="wait_ms")
    system = _platform_name(platform_name)
    family = "-4" if address.version == 4 else "-6"

    if system == "windows":
        program = _executable(executable, default="tracert.exe")
        return [program, "-d", family, "-h", str(hops), "-w", str(wait), str(address)]

    if system == "linux":
        program = _executable(executable, default="traceroute")
        return [
            program,
            "-n",
            family,
            "-m",
            str(hops),
            "-w",
            _seconds_argument(wait),
            str(address),
        ]

    # The native macOS tools use separate executables for IPv4 and IPv6 rather
    # than GNU traceroute's -4/-6 switches.
    default_program = "traceroute" if address.version == 4 else "traceroute6"
    program = _executable(executable, default=default_program)
    return [
        program,
        "-n",
        "-m",
        str(hops),
        "-w",
        _seconds_argument(wait),
        str(address),
    ]


@dataclass(frozen=True, slots=True)
class _AddressOccurrence:
    start: int
    end: int
    ip: str


def _address_occurrences(text: str) -> list[_AddressOccurrence]:
    occurrences: list[_AddressOccurrence] = []
    for match in _TOKEN.finditer(text):
        candidate = match.group(0).strip(_TOKEN_EDGE_CHARS)
        if "." not in candidate and ":" not in candidate:
            continue
        try:
            address = ipaddress.ip_address(candidate)
        except ValueError:
            continue
        occurrences.append(_AddressOccurrence(match.start(), match.end(), str(address)))
    return occurrences


def _rtt_value(match: re.Match[str]) -> float:
    value = float(match.group("value").replace(",", "."))
    # A measured "<1 ms" is not literally zero.  Recording half of the stated
    # resolution preserves that useful distinction while remaining conservative.
    return value / 2 if match.group("less_than") else value


def _responders(text: str) -> tuple[TraceResponder, ...]:
    addresses = _address_occurrences(text)
    if not addresses:
        return ()

    rtts = list(_RTT.finditer(text))
    ordered_ips: list[str] = []
    rtt_by_ip: dict[str, float | None] = {}

    for index, occurrence in enumerate(addresses):
        segment_end = addresses[index + 1].start if index + 1 < len(addresses) else len(text)
        matching_rtts = [match for match in rtts if occurrence.end <= match.start() < segment_end]
        rtt = _rtt_value(matching_rtts[0]) if matching_rtts else None

        if occurrence.ip not in rtt_by_ip:
            ordered_ips.append(occurrence.ip)
            rtt_by_ip[occurrence.ip] = rtt
        elif rtt_by_ip[occurrence.ip] is None and rtt is not None:
            # Non-numeric output may print "hostname (address) RTT"; in that form
            # the useful RTT follows the second occurrence of the same address.
            rtt_by_ip[occurrence.ip] = rtt

    if len(ordered_ips) == 1 and rtt_by_ip[ordered_ips[0]] is None and rtts:
        # Windows tracert prints its three RTT samples before the hop address.
        rtt_by_ip[ordered_ips[0]] = _rtt_value(rtts[0])

    return tuple(TraceResponder(ip=ip, rtt_ms=rtt_by_ip[ip]) for ip in ordered_ips)


def _same_address(left: str, right: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    try:
        return ipaddress.ip_address(left) == right
    except ValueError:
        return False


def parse_traceroute(
    output: str,
    *,
    target_ip: str,
    platform_name: str | None = None,
    command: tuple[str, ...] | list[str] = (),
    return_code: int | None = None,
    error: str | None = None,
    timed_out: bool = False,
) -> TraceResult:
    """Parse Windows, Linux, or macOS traceroute text without localized labels."""

    if not isinstance(output, str):
        raise TypeError("output must be text")
    address = _numeric_ip(target_ip)
    system = _platform_name(platform_name)

    hops: list[TraceHop] = []
    for line in output.splitlines():
        match = _HOP_LINE.match(line)
        if match is None:
            continue
        ttl = int(match.group("ttl"))
        if not 1 <= ttl <= 255:
            continue
        responders = _responders(line[match.end() :])
        hops.append(TraceHop(ttl=ttl, responders=responders, timed_out=not responders))

    reached = any(
        _same_address(responder.ip, address) for hop in hops for responder in hop.responders
    )
    return TraceResult(
        target_ip=str(address),
        platform_name=system,
        hops=tuple(hops),
        reached=reached,
        command=tuple(command),
        return_code=return_code,
        raw_output=output,
        error=error,
        timed_out=timed_out,
    )


def _decode_output(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value

    encodings = ["utf-8", locale.getpreferredencoding(False), "cp866", "cp1251"]
    for encoding in dict.fromkeys(encodings):
        try:
            return value.decode(encoding)
        except (LookupError, UnicodeDecodeError):
            continue
    return value.decode("utf-8", errors="replace")


def _combined_output(stdout: str | bytes | None, stderr: str | bytes | None) -> str:
    parts = [part for item in (stdout, stderr) if (part := _decode_output(item)).strip()]
    return "\n".join(parts)


def _timeout_value(
    timeout_s: float | None,
    *,
    max_hops: int,
    wait_ms: int,
) -> float:
    if timeout_s is None:
        # Native tools normally issue three probes per TTL.  A little process
        # overhead is included without permitting an unbounded child process.
        return max_hops * wait_ms * 3 / 1000 + 5
    if isinstance(timeout_s, bool) or not isinstance(timeout_s, Real):
        raise ValueError("timeout_s must be a positive finite number")
    result = float(timeout_s)
    if result <= 0 or not math.isfinite(result):
        raise ValueError("timeout_s must be a positive finite number")
    return result


def run_traceroute(
    target_ip: str,
    *,
    max_hops: int = 30,
    wait_ms: int = 1_000,
    platform_name: str | None = None,
    executable: str | None = None,
    timeout_s: float | None = None,
) -> TraceResult:
    """Run the platform traceroute safely and return its parsed result.

    Missing executables, OS launch errors, and overall timeouts are represented in
    ``TraceResult.error`` so a larger diagnostic run can continue with other probes.
    """

    command = build_trace_command(
        target_ip,
        max_hops=max_hops,
        wait_ms=wait_ms,
        platform_name=platform_name,
        executable=executable,
    )
    system = _platform_name(platform_name)
    hops = _positive_int(max_hops, name="max_hops", maximum=255)
    wait = _positive_int(wait_ms, name="wait_ms")
    process_timeout = _timeout_value(timeout_s, max_hops=hops, wait_ms=wait)

    try:
        completed = subprocess.run(
            command,
            shell=False,
            capture_output=True,
            timeout=process_timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        output = _combined_output(exc.stdout, exc.stderr)
        return parse_traceroute(
            output,
            target_ip=target_ip,
            platform_name=system,
            command=command,
            error=f"traceroute timed out after {process_timeout:g} seconds",
            timed_out=True,
        )
    except OSError as exc:
        return parse_traceroute(
            "",
            target_ip=target_ip,
            platform_name=system,
            command=command,
            error=f"unable to run {command[0]!r}: {exc}",
        )

    output = _combined_output(completed.stdout, completed.stderr)
    error = None
    if completed.returncode != 0:
        error = f"traceroute exited with status {completed.returncode}"
    return parse_traceroute(
        output,
        target_ip=target_ip,
        platform_name=system,
        command=command,
        return_code=completed.returncode,
        error=error,
    )


# Friendly aliases for callers that use generic hop/responder terminology.
HopResponder = TraceResponder
TracerouteResult = TraceResult

__all__ = [
    "HopResponder",
    "TraceHop",
    "TraceResponder",
    "TraceResult",
    "TracerouteResult",
    "build_trace_command",
    "parse_traceroute",
    "run_traceroute",
]
