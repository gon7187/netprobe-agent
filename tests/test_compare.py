from __future__ import annotations

from netprobe.compare import compare_reports


def _report(path_label: str, probes: list[dict[str, object]]) -> dict[str, object]:
    return {
        "schema_version": "1.0",
        "run_id": path_label,
        "target": {"hostname_idna": "blocked.example", "port": 443},
        "context": {"path_label": path_label},
        "probes": probes,
    }


def test_compare_exact_ip_distinguishes_tcp_interference() -> None:
    direct = _report(
        "direct",
        [
            {
                "id": "tcp-direct",
                "probe_type": "tcp",
                "outcome": "timeout",
                "endpoint_ip": "203.0.113.10",
                "endpoint_port": 443,
                "evidence": {},
            }
        ],
    )
    vpn = _report(
        "vpn",
        [
            {
                "id": "tcp-vpn",
                "probe_type": "tcp",
                "outcome": "success",
                "endpoint_ip": "203.0.113.10",
                "endpoint_port": 443,
                "evidence": {},
            }
        ],
    )

    result = compare_reports(direct, vpn)

    assert result["same_target"] is True
    assert result["findings"][0]["code"] == "tcp_path_interference_likely"
    assert result["findings"][0]["confidence"] == "high"


def test_compare_does_not_match_different_cdn_ips() -> None:
    direct = _report(
        "direct",
        [
            {
                "id": "tls-direct",
                "probe_type": "tls",
                "outcome": "reset",
                "endpoint_ip": "203.0.113.10",
                "endpoint_port": 443,
                "evidence": {"variant": "sni_normal"},
            }
        ],
    )
    vpn = _report(
        "vpn",
        [
            {
                "id": "tls-vpn",
                "probe_type": "tls",
                "outcome": "success",
                "endpoint_ip": "203.0.113.11",
                "endpoint_port": 443,
                "evidence": {"variant": "sni_normal"},
            }
        ],
    )

    result = compare_reports(direct, vpn)

    assert result["exact_comparisons"] == []
    assert result["findings"][0]["code"] == "no_exact_endpoint_overlap"


def test_compare_tls_failure_with_direct_tcp_success_points_to_sni_layer() -> None:
    direct = _report(
        "direct",
        [
            {
                "id": "tcp-direct",
                "probe_type": "tcp",
                "outcome": "success",
                "endpoint_ip": "203.0.113.10",
                "endpoint_port": 443,
                "evidence": {},
            },
            {
                "id": "tls-direct",
                "probe_type": "tls",
                "outcome": "reset",
                "endpoint_ip": "203.0.113.10",
                "endpoint_port": 443,
                "evidence": {"variant": "sni_normal"},
            },
        ],
    )
    vpn = _report(
        "vpn",
        [
            {
                "id": "tcp-vpn",
                "probe_type": "tcp",
                "outcome": "success",
                "endpoint_ip": "203.0.113.10",
                "endpoint_port": 443,
                "evidence": {},
            },
            {
                "id": "tls-vpn",
                "probe_type": "tls",
                "outcome": "success",
                "endpoint_ip": "203.0.113.10",
                "endpoint_port": 443,
                "evidence": {"variant": "sni_normal"},
            },
        ],
    )

    result = compare_reports(direct, vpn)

    assert any(item["code"] == "tls_sni_path_interference_likely" for item in result["findings"])
