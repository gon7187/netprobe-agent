"""Strict JSON conversion and secret redaction."""

from __future__ import annotations

import dataclasses
import ipaddress
import json
import math
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from netprobe.target import Target

_SECRET_KEYS = {
    "access_token",
    "api_key",
    "apikey",
    "auth",
    "authorization",
    "key",
    "password",
    "secret",
    "signature",
    "token",
}


def redact_url(value: str) -> str:
    """Remove userinfo and common query secrets while retaining useful routing data."""

    try:
        parts = urlsplit(value)
    except ValueError:
        return value[:512]
    hostname = parts.hostname or ""
    if ":" in hostname and not hostname.startswith("["):
        hostname = f"[{hostname}]"
    try:
        port = parts.port
    except ValueError:
        port = None
    netloc = f"{hostname}:{port}" if port is not None else hostname
    query = urlencode(
        [
            (key, "REDACTED" if key.lower() in _SECRET_KEYS else item)
            for key, item in parse_qsl(parts.query, keep_blank_values=True)
        ]
    )
    return urlunsplit((parts.scheme, netloc, parts.path, query, ""))[:2048]


def _datetime_to_iso(value: datetime) -> str:
    aware = value if value.tzinfo is not None else value.replace(tzinfo=UTC)
    normalized = aware.astimezone(UTC).isoformat().replace("+00:00", "Z")
    return normalized


def to_primitive(value: Any) -> Any:
    """Recursively convert supported report values to JSON primitives."""

    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("report contains a non-finite number")
        return value
    if isinstance(value, Enum):
        return to_primitive(value.value)
    if isinstance(value, datetime):
        return _datetime_to_iso(value)
    if isinstance(value, (ipaddress.IPv4Address, ipaddress.IPv6Address, Path)):
        return str(value)
    if isinstance(value, Target):
        redacted = redact_url(value.normalized_url)
        parts = urlsplit(redacted)
        request_target = parts.path or "/"
        if parts.query:
            request_target = f"{request_target}?{parts.query}"
        result = value.to_dict()
        result["input"] = redacted
        result["normalized_url"] = redacted
        result["request_target"] = request_target
        return result
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return {
            field.name: to_primitive(getattr(value, field.name))
            for field in dataclasses.fields(value)
        }
    to_dict_method = getattr(value, "to_dict", None)
    if callable(to_dict_method):
        return to_primitive(to_dict_method())
    if isinstance(value, dict):
        return {str(key): to_primitive(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [to_primitive(item) for item in value]
    raise TypeError(f"unsupported JSON value: {type(value).__name__}")


def dumps_json(value: Any, *, pretty: bool = True) -> str:
    kwargs: dict[str, Any] = {
        "ensure_ascii": False,
        "allow_nan": False,
        "sort_keys": True,
    }
    if pretty:
        kwargs["indent"] = 2
    else:
        kwargs["separators"] = (",", ":")
    return json.dumps(to_primitive(value), **kwargs)
