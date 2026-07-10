"""Safe parsing and normalization of diagnostic targets."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import SplitResult, urlsplit, urlunsplit

_MAX_INPUT_LENGTH = 2048
_MAX_HOST_LENGTH = 253
_CONTROL_OR_SPACE = re.compile(r"[\x00-\x20\x7f]")
_ALLOWED_SCHEMES = {"http": 80, "https": 443}


class TargetError(ValueError):
    """Raised when a target is ambiguous, unsupported, or unsafe."""


@dataclass(frozen=True, slots=True)
class Target:
    """Normalized network target."""

    input: str
    scheme: str
    hostname: str
    hostname_idna: str
    port: int
    request_target: str
    explicit_port: bool
    is_ip: bool

    @property
    def authority(self) -> str:
        host = f"[{self.hostname_idna}]" if ":" in self.hostname_idna else self.hostname_idna
        default_port = _ALLOWED_SCHEMES[self.scheme]
        return f"{host}:{self.port}" if self.port != default_port else host

    @property
    def normalized_url(self) -> str:
        path, separator, query = self.request_target.partition("?")
        return urlunsplit((self.scheme, self.authority, path, query if separator else "", ""))

    def to_dict(self) -> dict[str, object]:
        return {
            "input": self.input,
            "normalized_url": self.normalized_url,
            "scheme": self.scheme,
            "hostname": self.hostname,
            "hostname_idna": self.hostname_idna,
            "port": self.port,
            "request_target": self.request_target,
            "explicit_port": self.explicit_port,
            "is_ip": self.is_ip,
        }


def _ensure_safe_input(raw: str) -> str:
    if not isinstance(raw, str):
        raise TargetError("target must be text")
    if not raw or len(raw) > _MAX_INPUT_LENGTH:
        raise TargetError(f"target length must be between 1 and {_MAX_INPUT_LENGTH} characters")
    if _CONTROL_OR_SPACE.search(raw):
        raise TargetError("target must not contain spaces or control characters")
    return raw


def _split_target(raw: str) -> SplitResult:
    # A raw IPv6 literal is unambiguous without urlsplit's host:port heuristics.
    try:
        address = ipaddress.ip_address(raw.rstrip("."))
    except ValueError:
        address = None
    if address is not None:
        bracketed = f"[{address.compressed}]" if address.version == 6 else address.compressed
        return urlsplit(f"https://{bracketed}")

    value = raw if "://" in raw else f"https://{raw}"
    try:
        return urlsplit(value)
    except ValueError as exc:
        raise TargetError(f"invalid target: {exc}") from exc


def _normalize_hostname(hostname: str) -> tuple[str, str, bool]:
    host = hostname.rstrip(".").lower()
    if not host:
        raise TargetError("target has no hostname")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None
    if address is not None:
        compressed = address.compressed
        return compressed, compressed, True

    if ".." in host or host.startswith("."):
        raise TargetError("hostname contains an empty label")
    try:
        idna = host.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise TargetError("hostname is not valid IDNA") from exc
    if len(idna) > _MAX_HOST_LENGTH:
        raise TargetError("hostname is too long")
    labels = idna.split(".")
    if any(not label or len(label) > 63 for label in labels):
        raise TargetError("hostname contains an invalid DNS label")
    if any(label.startswith("-") or label.endswith("-") for label in labels):
        raise TargetError("hostname labels must not start or end with '-'")
    return host, idna, False


def parse_target(raw: str) -> Target:
    """Parse a URL, hostname, or numeric address without shell interpretation."""

    original = _ensure_safe_input(raw)
    parts = _split_target(original)
    scheme = parts.scheme.lower()
    if scheme not in _ALLOWED_SCHEMES:
        raise TargetError("only http:// and https:// targets are supported")
    if parts.username is not None or parts.password is not None:
        raise TargetError("credentials in target URLs are not accepted")
    if not parts.hostname:
        raise TargetError("target has no hostname")
    try:
        parsed_port = parts.port
    except ValueError as exc:
        raise TargetError(f"invalid port: {exc}") from exc
    port = parsed_port if parsed_port is not None else _ALLOWED_SCHEMES[scheme]
    if not 1 <= port <= 65535:
        raise TargetError("port must be between 1 and 65535")
    if parts.fragment:
        # URL fragments never travel over the network and tend to confuse reports.
        raise TargetError("URL fragments are not diagnostic targets")

    hostname, hostname_idna, is_ip = _normalize_hostname(parts.hostname)
    path = parts.path or "/"
    request_target = f"{path}?{parts.query}" if parts.query else path
    return Target(
        input=original,
        scheme=scheme,
        hostname=hostname,
        hostname_idna=hostname_idna,
        port=port,
        request_target=request_target,
        explicit_port=parsed_port is not None,
        is_ip=is_ip,
    )
