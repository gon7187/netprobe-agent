from __future__ import annotations

from netprobe.classify import classify_probes
from netprobe.models import Outcome, ProbeResult


def probe(
    probe_id: str,
    probe_type: str,
    outcome: Outcome,
    *,
    ip: str | None = None,
    port: int | None = None,
    variant: str | None = None,
    addresses: list[str] | None = None,
    rcode: int | None = None,
) -> ProbeResult:
    evidence: dict[str, object] = {}
    if variant:
        evidence["variant"] = variant
    if addresses is not None:
        evidence["addresses"] = addresses
    if rcode is not None:
        evidence["rcode"] = rcode
    return ProbeResult(
        id=probe_id,
        probe_type=probe_type,
        stage=probe_type,
        outcome=outcome,
        duration_ms=1.0,
        endpoint_ip=ip,
        endpoint_port=port,
        evidence=evidence,
    )


def codes(probes: list[ProbeResult]) -> set[str]:
    return {finding.code for finding in classify_probes(probes)}


def test_dns_interference_requires_working_alternate_answer() -> None:
    findings = codes(
        [
            probe("dns-system", "dns", Outcome.DNS_ERROR, variant="system", rcode=3),
            probe(
                "dns-doh",
                "dns",
                Outcome.SUCCESS,
                variant="doh",
                addresses=["93.184.216.34"],
            ),
            probe(
                "tcp-pinned",
                "tcp",
                Outcome.SUCCESS,
                ip="93.184.216.34",
                port=443,
            ),
        ]
    )
    assert "dns_interference_suspected" in findings


def test_refused_port_is_not_classified_as_ip_block() -> None:
    findings = codes(
        [
            probe("target", "tcp", Outcome.REFUSED, ip="203.0.113.7", port=443),
            probe("control", "control_tcp", Outcome.SUCCESS, ip="1.1.1.1", port=443),
        ]
    )
    assert "service_refused" in findings
    assert "tcp_ip_interference_suspected" not in findings


def test_sni_fragment_differential_is_probable_sni_filtering() -> None:
    findings = classify_probes(
        [
            probe("tcp", "tcp", Outcome.SUCCESS, ip="203.0.113.7", port=443),
            probe(
                "tls-normal",
                "tls",
                Outcome.RESET,
                ip="203.0.113.7",
                port=443,
                variant="sni_normal",
            ),
            probe(
                "tls-fragmented",
                "tls",
                Outcome.SUCCESS,
                ip="203.0.113.7",
                port=443,
                variant="sni_fragmented",
            ),
        ]
    )
    finding = next(item for item in findings if item.code == "tls_sni_filtering_suspected")
    assert finding.confidence == "high"
    assert set(finding.evidence_probe_ids) == {"tls-normal", "tls-fragmented", "tcp"}


def test_certificate_failure_is_not_sni_block() -> None:
    findings = codes(
        [
            probe("tcp", "tcp", Outcome.SUCCESS, ip="203.0.113.7", port=443),
            probe(
                "tls",
                "tls",
                Outcome.CERTIFICATE_ERROR,
                ip="203.0.113.7",
                port=443,
                variant="verified",
            ),
        ]
    )
    assert "tls_certificate_error" in findings
    assert "tls_sni_filtering_suspected" not in findings


def test_http_status_is_reachable_not_automatic_dpi() -> None:
    findings = codes(
        [
            probe("tcp", "tcp", Outcome.SUCCESS, ip="203.0.113.7", port=80),
            ProbeResult(
                id="http",
                probe_type="http",
                stage="http",
                outcome=Outcome.HTTP_RESPONSE,
                duration_ms=2,
                endpoint_ip="203.0.113.7",
                endpoint_port=80,
                evidence={"variant": "host_normal", "status_code": 451},
            ),
        ]
    )
    assert "http_policy_response" in findings
    assert "http_host_filtering_suspected" not in findings


def test_ipv6_failure_is_reported_as_reachability_not_dpi() -> None:
    findings = codes(
        [
            probe("v4", "tcp", Outcome.SUCCESS, ip="8.8.8.8", port=443),
            probe("v6", "tcp", Outcome.UNREACHABLE, ip="2001:4860:4860::8888", port=443),
        ]
    )
    assert "ipv6_reachability_problem" in findings
    assert "tcp_ip_interference_suspected" not in findings


def test_quic_timeout_is_inconclusive_even_when_tcp_works() -> None:
    findings = codes(
        [
            probe("tcp", "tcp", Outcome.SUCCESS, ip="8.8.8.8", port=443),
            probe("quic", "udp_quic", Outcome.TIMEOUT, ip="8.8.8.8", port=443),
        ]
    )
    assert "quic_reachability_inconclusive" in findings
    assert "tcp_ip_interference_suspected" not in findings
