"""Compare direct and VPN reports on identical endpoints."""

from __future__ import annotations

from typing import Any

_SUCCESS = {"success", "http_response"}
_FAILURE = {
    "timeout",
    "reset",
    "unreachable",
    "tls_alert",
    "certificate_error",
    "dns_error",
    "error",
}


def _validate_report(report: dict[str, Any], label: str) -> None:
    if not isinstance(report, dict):
        raise ValueError(f"{label} report must be a JSON object")
    if report.get("schema_version") != "1.0":
        raise ValueError(f"{label} report uses an unsupported schema_version")
    if not isinstance(report.get("target"), dict) or not isinstance(report.get("probes"), list):
        raise ValueError(f"{label} report is missing target or probes")


def _probe_key(probe: dict[str, Any]) -> tuple[object, ...] | None:
    probe_type = probe.get("probe_type")
    address = probe.get("endpoint_ip")
    port = probe.get("endpoint_port")
    raw_evidence = probe.get("evidence")
    evidence: dict[str, Any] = raw_evidence if isinstance(raw_evidence, dict) else {}
    if not probe_type or address is None or port is None:
        return None
    return (
        probe_type,
        address,
        port,
        evidence.get("variant"),
        evidence.get("qtype"),
    )


def _index(report: dict[str, Any]) -> dict[tuple[object, ...], dict[str, Any]]:
    result: dict[tuple[object, ...], dict[str, Any]] = {}
    for item in report["probes"]:
        if not isinstance(item, dict):
            continue
        key = _probe_key(item)
        if key is not None:
            result[key] = item
    return result


def _target_key(report: dict[str, Any]) -> tuple[object, object]:
    target = report["target"]
    return target.get("hostname_idna"), target.get("port")


def _direct_tcp_worked(
    direct_index: dict[tuple[object, ...], dict[str, Any]], address: object, port: object
) -> bool:
    return any(
        key[0] == "tcp"
        and key[1] == address
        and key[2] == port
        and probe.get("outcome") == "success"
        for key, probe in direct_index.items()
    )


def compare_reports(direct: dict[str, Any], vpn: dict[str, Any]) -> dict[str, Any]:
    """Compare exact IP:port probes; different CDN answers are never treated as controls."""

    _validate_report(direct, "direct")
    _validate_report(vpn, "vpn")
    direct_index = _index(direct)
    vpn_index = _index(vpn)
    overlaps = sorted(
        set(direct_index) & set(vpn_index), key=lambda item: tuple(str(x) for x in item)
    )
    comparisons: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []

    for key in overlaps:
        direct_probe = direct_index[key]
        vpn_probe = vpn_index[key]
        item = {
            "probe_type": key[0],
            "endpoint_ip": key[1],
            "endpoint_port": key[2],
            "variant": key[3],
            "direct_outcome": direct_probe.get("outcome"),
            "vpn_outcome": vpn_probe.get("outcome"),
            "direct_probe_id": direct_probe.get("id"),
            "vpn_probe_id": vpn_probe.get("id"),
        }
        comparisons.append(item)
        direct_failed = direct_probe.get("outcome") in _FAILURE
        vpn_worked = vpn_probe.get("outcome") in _SUCCESS
        if not (direct_failed and vpn_worked):
            continue
        evidence = [direct_probe.get("id"), vpn_probe.get("id")]
        if key[0] == "tcp":
            findings.append(
                {
                    "code": "tcp_path_interference_likely",
                    "layer": "tcp_ip",
                    "verdict": "suspected",
                    "confidence": "high",
                    "summary": "Тот же exact IP:port не работает напрямую и работает через VPN.",
                    "evidence_probe_ids": evidence,
                }
            )
        elif (
            key[0] == "tls"
            and key[3] == "sni_normal"
            and _direct_tcp_worked(direct_index, key[1], key[2])
        ):
            findings.append(
                {
                    "code": "tls_sni_path_interference_likely",
                    "layer": "tls_sni",
                    "verdict": "suspected",
                    "confidence": "high",
                    "summary": (
                        "TCP напрямую проходит, но TLS с тем же SNI на exact IP:port проходит "
                        "только через VPN."
                    ),
                    "evidence_probe_ids": evidence,
                }
            )
        elif key[0] == "tls" and direct_probe.get("outcome") == "certificate_error":
            findings.append(
                {
                    "code": "tls_interception_path_difference",
                    "layer": "tls_certificate",
                    "verdict": "suspected",
                    "confidence": "high",
                    "summary": "Проверка сертификата падает напрямую и проходит на том же IP через VPN.",
                    "evidence_probe_ids": evidence,
                }
            )
        elif key[0] == "http":
            findings.append(
                {
                    "code": "http_path_interference_likely",
                    "layer": "http",
                    "verdict": "suspected",
                    "confidence": "high",
                    "summary": "Тот же HTTP-вариант на exact IP:port отвечает только через VPN.",
                    "evidence_probe_ids": evidence,
                }
            )
        elif key[0] == "udp_quic":
            findings.append(
                {
                    "code": "udp_quic_path_interference_likely",
                    "layer": "udp_quic",
                    "verdict": "suspected",
                    "confidence": "high",
                    "summary": "QUIC version-negotiation на exact IP:443 отвечает только через VPN.",
                    "evidence_probe_ids": evidence,
                }
            )

    if not overlaps:
        findings.append(
            {
                "code": "no_exact_endpoint_overlap",
                "layer": "comparison",
                "verdict": "inconclusive",
                "confidence": "low",
                "summary": (
                    "Отчёты не содержат одинаковых IP:port+variant; разные CDN IP нельзя считать "
                    "контрольной парой."
                ),
                "evidence_probe_ids": [],
            }
        )
    elif not findings:
        findings.append(
            {
                "code": "no_path_differential_detected",
                "layer": "comparison",
                "verdict": "normal",
                "confidence": "medium",
                "summary": "На сопоставимых exact endpoint не найдено варианта direct-fail/VPN-success.",
                "evidence_probe_ids": [],
            }
        )
    return {
        "schema_version": "1.0",
        "direct_run_id": direct.get("run_id"),
        "vpn_run_id": vpn.get("run_id"),
        "same_target": _target_key(direct) == _target_key(vpn),
        "target": direct.get("target"),
        "exact_comparisons": comparisons,
        "findings": findings,
        "warning": "Высокая уверенность всё равно требует воспроизводимости минимум в 2 из 3 запусков.",
    }
