from __future__ import annotations

import json
from datetime import UTC, datetime

from netprobe.models import DiagnosticReport, Outcome, ProbeResult
from netprobe.serialization import dumps_json, redact_url
from netprobe.target import parse_target


def test_report_serializes_to_stable_json_primitives() -> None:
    report = DiagnosticReport(
        run_id="run-1",
        target=parse_target("https://пример.рф/a?token=secret&x=1"),
        started_at=datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC),
        context={"язык": "русский"},
        probes=[
            ProbeResult(
                id="dns-1",
                probe_type="dns",
                stage="dns",
                outcome=Outcome.SUCCESS,
                duration_ms=1.25,
                evidence={"addresses": ["8.8.8.8"]},
            )
        ],
    )
    document = dumps_json(report)
    payload = json.loads(document)

    assert payload["schema_version"] == "1.0"
    assert payload["target"]["hostname_idna"] == "xn--e1afmkfd.xn--p1ai"
    assert payload["started_at"] == "2026-01-02T03:04:05Z"
    assert payload["probes"][0]["outcome"] == "success"
    assert payload["context"]["язык"] == "русский"
    assert "secret" not in document
    assert "token=REDACTED" in payload["target"]["input"]


def test_redact_url_hides_common_secrets() -> None:
    value = redact_url("https://u:p@example.com/a?token=abc&api_key=def&safe=yes")
    assert "abc" not in value
    assert "def" not in value
    assert "u:p" not in value
    assert "safe=yes" in value
