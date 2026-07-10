"""Stable report models shared by probes, renderers, and agents."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any

from netprobe.target import Target


class Outcome(StrEnum):
    SUCCESS = "success"
    HTTP_RESPONSE = "http_response"
    TIMEOUT = "timeout"
    REFUSED = "refused"
    RESET = "reset"
    UNREACHABLE = "unreachable"
    DNS_ERROR = "dns_error"
    TLS_ALERT = "tls_alert"
    CERTIFICATE_ERROR = "certificate_error"
    ERROR = "error"
    SKIPPED = "skipped"


@dataclass(slots=True)
class ProbeError:
    category: str
    message: str
    stage: str
    code: int | str | None = None


@dataclass(slots=True)
class ProbeResult:
    id: str
    probe_type: str
    stage: str
    outcome: Outcome
    duration_ms: float
    attempt: int = 1
    family: str | None = None
    endpoint_ip: str | None = None
    endpoint_port: int | None = None
    hostname: str | None = None
    evidence: dict[str, Any] = field(default_factory=dict)
    error: ProbeError | None = None

    @property
    def reached_transport(self) -> bool:
        return self.outcome in {
            Outcome.SUCCESS,
            Outcome.HTTP_RESPONSE,
            Outcome.REFUSED,
            Outcome.CERTIFICATE_ERROR,
            Outcome.TLS_ALERT,
        }


@dataclass(slots=True)
class Finding:
    code: str
    layer: str
    verdict: str
    confidence: str
    summary: str
    evidence_probe_ids: tuple[str, ...] = ()
    alternatives: tuple[str, ...] = ()
    recommendation: str | None = None


@dataclass(slots=True)
class DiagnosticReport:
    run_id: str
    target: Target
    started_at: datetime
    context: dict[str, Any]
    probes: list[ProbeResult]
    findings: list[Finding] = field(default_factory=list)
    traces: list[Any] = field(default_factory=list)
    route_recommendation: dict[str, Any] = field(default_factory=dict)
    completed_at: datetime | None = None
    schema_version: str = "1.0"
