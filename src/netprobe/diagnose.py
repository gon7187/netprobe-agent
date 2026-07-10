"""End-to-end diagnostic orchestration."""

from __future__ import annotations

import ipaddress
import os
import platform
import sys
import time
import uuid
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from netprobe.classify import classify_probes
from netprobe.models import DiagnosticReport, Finding, Outcome, ProbeResult
from netprobe.probes import ProbeCallable, probe_http, probe_tcp, probe_tls
from netprobe.quic import probe_quic_version_negotiation
from netprobe.resolve import (
    DEFAULT_DOH_ENDPOINTS,
    DEFAULT_RESOLVERS,
    ResolutionSummary,
    resolve_all,
    select_route_addresses,
)
from netprobe.routes import destination_networks
from netprobe.target import Target
from netprobe.trace import TraceResult, run_traceroute

Progress = Callable[[str], None]


@dataclass(frozen=True, slots=True)
class DiagnosticConfig:
    timeout: float = 2.5
    resolvers: tuple[str, ...] = DEFAULT_RESOLVERS
    doh_endpoints: tuple[str, ...] = DEFAULT_DOH_ENDPOINTS
    include_dns_tcp: bool = True
    trace: bool = True
    trace_max_hops: int = 12
    trace_wait_ms: int = 500
    max_addresses_per_family: int = 2
    extended_ports: bool = True
    extended_tls: bool = True
    path_label: str = "direct"

    def validate(self) -> None:
        if not 0.1 <= self.timeout <= 60:
            raise ValueError("timeout must be between 0.1 and 60 seconds")
        if not 1 <= self.trace_max_hops <= 64:
            raise ValueError("trace_max_hops must be between 1 and 64")
        if not 50 <= self.trace_wait_ms <= 60_000:
            raise ValueError("trace_wait_ms must be between 50 and 60000")
        if not 1 <= self.max_addresses_per_family <= 8:
            raise ValueError("max_addresses_per_family must be between 1 and 8")
        if self.path_label not in {"direct", "vpn", "proxy"}:
            raise ValueError("path_label must be direct, vpn, or proxy")


def _notify(callback: Progress | None, message: str) -> None:
    if callback is not None:
        callback(message)


def _address_sort_key(address: str) -> tuple[int, int]:
    parsed = ipaddress.ip_address(address)
    return parsed.version, int(parsed)


def select_candidate_addresses(
    resolution: ResolutionSummary, *, maximum_per_family: int
) -> tuple[str, ...]:
    """Prioritize system/DoH answers while retaining differential candidates."""

    source_groups = [
        ("system:system",),
        tuple(key for key in resolution.addresses_by_source if key.startswith("doh:")),
        tuple(key for key in resolution.addresses_by_source if key.startswith("dns_tcp:")),
        tuple(key for key in resolution.addresses_by_source if key.startswith("dns_udp:")),
    ]
    grouped_addresses = [
        sorted(
            {
                address
                for source in sources
                for address in resolution.addresses_by_source.get(source, ())
            },
            key=_address_sort_key,
        )
        for sources in source_groups
    ]
    selected: list[str] = []
    for version in (4, 6):
        while (
            sum(ipaddress.ip_address(item).version == version for item in selected)
            < maximum_per_family
        ):
            made_progress = False
            for addresses in grouped_addresses:
                candidate = next(
                    (
                        address
                        for address in addresses
                        if ipaddress.ip_address(address).version == version
                        and address not in selected
                    ),
                    None,
                )
                if candidate is None:
                    continue
                selected.append(candidate)
                made_progress = True
                if (
                    sum(ipaddress.ip_address(item).version == version for item in selected)
                    >= maximum_per_family
                ):
                    break
            if not made_progress:
                break
    return tuple(selected)


def _run_probe_calls(calls: list[ProbeCallable], *, maximum_workers: int = 12) -> list[ProbeResult]:
    if not calls:
        return []
    results: list[ProbeResult] = []
    with ThreadPoolExecutor(
        max_workers=min(maximum_workers, len(calls)), thread_name_prefix="netprobe"
    ) as pool:
        futures = [pool.submit(call) for call in calls]
        for future in as_completed(futures):
            results.append(future.result())
    return sorted(results, key=lambda item: item.id)


def _tcp_probes(
    target: Target,
    addresses: tuple[str, ...],
    config: DiagnosticConfig,
) -> list[ProbeResult]:
    ports = {target.port}
    if config.extended_ports:
        ports.update({80, 443})
    calls: list[ProbeCallable] = []
    for address_index, address in enumerate(addresses, start=1):
        for port in sorted(ports):
            probe_id = f"tcp-{address_index}-{port}"
            calls.append(
                lambda probe_id=probe_id, address=address, port=port: probe_tcp(
                    probe_id,
                    address,
                    port,
                    timeout=config.timeout,
                )
            )
    # Independent connectivity controls keep a total local outage from looking target-specific.
    calls.extend(
        [
            lambda: probe_tcp(
                "control-tcp-cloudflare",
                "1.1.1.1",
                443,
                timeout=config.timeout,
                probe_type="control_tcp",
            ),
            lambda: probe_tcp(
                "control-tcp-google",
                "8.8.8.8",
                443,
                timeout=config.timeout,
                probe_type="control_tcp",
            ),
        ]
    )
    return _run_probe_calls(calls)


def _successful_tcp_endpoints(probes: list[ProbeResult]) -> set[tuple[str, int]]:
    return {
        (probe.endpoint_ip, probe.endpoint_port)
        for probe in probes
        if probe.probe_type == "tcp"
        and probe.outcome == Outcome.SUCCESS
        and probe.endpoint_ip is not None
        and probe.endpoint_port is not None
    }


def _tls_probes(
    target: Target,
    addresses: tuple[str, ...],
    tcp_results: list[ProbeResult],
    config: DiagnosticConfig,
) -> list[ProbeResult]:
    working = _successful_tcp_endpoints(tcp_results)
    tls_ports = {target.port} if target.scheme == "https" else set()
    if config.extended_ports:
        tls_ports.add(443)
    hostname = None if target.is_ip else target.hostname_idna
    calls: list[ProbeCallable] = []
    counter = 0
    for address in addresses:
        for port in sorted(tls_ports):
            if (address, port) not in working:
                continue
            counter += 1
            prefix = f"tls-{counter}"
            calls.append(
                lambda prefix=prefix, address=address, port=port: probe_tls(
                    f"{prefix}-normal",
                    address,
                    port,
                    hostname=hostname,
                    timeout=config.timeout,
                    variant="sni_normal",
                )
            )
            if hostname is not None:
                calls.append(
                    lambda prefix=prefix, address=address, port=port: probe_tls(
                        f"{prefix}-fragmented",
                        address,
                        port,
                        hostname=hostname,
                        timeout=config.timeout,
                        variant="sni_fragmented",
                        fragment_sni=True,
                    )
                )
                calls.append(
                    lambda prefix=prefix, address=address, port=port: probe_tls(
                        f"{prefix}-verified",
                        address,
                        port,
                        hostname=hostname,
                        timeout=config.timeout,
                        variant="verified",
                        verify=True,
                    )
                )
                if config.extended_tls:
                    calls.extend(
                        [
                            lambda prefix=prefix, address=address, port=port: probe_tls(
                                f"{prefix}-no-sni",
                                address,
                                port,
                                hostname=None,
                                timeout=config.timeout,
                                variant="no_sni",
                            ),
                            lambda prefix=prefix, address=address, port=port: probe_tls(
                                f"{prefix}-tls12",
                                address,
                                port,
                                hostname=hostname,
                                timeout=config.timeout,
                                variant="tls12",
                                forced_version="1.2",
                            ),
                            lambda prefix=prefix, address=address, port=port: probe_tls(
                                f"{prefix}-tls13",
                                address,
                                port,
                                hostname=hostname,
                                timeout=config.timeout,
                                variant="tls13",
                                forced_version="1.3",
                            ),
                        ]
                    )
    return _run_probe_calls(calls)


def _quic_probes(
    addresses: tuple[str, ...],
    config: DiagnosticConfig,
) -> list[ProbeResult]:
    if not config.extended_ports:
        return []
    calls: list[ProbeCallable] = [
        lambda address=address, index=index: probe_quic_version_negotiation(
            f"quic-{index}",
            address,
            timeout=config.timeout,
        )
        for index, address in enumerate(addresses, start=1)
    ]
    return _run_probe_calls(calls)


def _http_probes(
    target: Target,
    addresses: tuple[str, ...],
    tcp_results: list[ProbeResult],
    config: DiagnosticConfig,
) -> list[ProbeResult]:
    working = _successful_tcp_endpoints(tcp_results)
    hostname = target.hostname_idna
    calls: list[ProbeCallable] = []
    counter = 0
    plain_ports = {target.port} if target.scheme == "http" else set()
    if config.extended_ports:
        plain_ports.add(80)
    for address in addresses:
        for port in sorted(plain_ports):
            if (address, port) not in working:
                continue
            counter += 1
            prefix = f"http-{counter}"
            request_target = target.request_target if target.scheme == "http" else "/"
            calls.append(
                lambda prefix=prefix, address=address, port=port, request_target=request_target: (
                    probe_http(
                        f"{prefix}-normal",
                        address,
                        port,
                        hostname=hostname,
                        request_target=request_target,
                        timeout=config.timeout,
                        use_tls=False,
                        variant="host_normal",
                    )
                )
            )
            calls.append(
                lambda prefix=prefix, address=address, port=port, request_target=request_target: (
                    probe_http(
                        f"{prefix}-fragmented",
                        address,
                        port,
                        hostname=hostname,
                        request_target=request_target,
                        timeout=config.timeout,
                        use_tls=False,
                        variant="host_fragmented",
                        fragment_host=True,
                    )
                )
            )

    if target.scheme == "https":
        for address in addresses:
            if (address, target.port) not in working:
                continue
            counter += 1
            prefix = f"https-{counter}"
            calls.append(
                lambda prefix=prefix, address=address: probe_http(
                    prefix,
                    address,
                    target.port,
                    hostname=hostname,
                    request_target=target.request_target,
                    timeout=config.timeout,
                    use_tls=True,
                    variant="https_pinned",
                )
            )
    return _run_probe_calls(calls)


def _trace_addresses(addresses: tuple[str, ...]) -> tuple[str, ...]:
    selected: list[str] = []
    seen_families: set[int] = set()
    for address in addresses:
        version = ipaddress.ip_address(address).version
        if version not in seen_families:
            selected.append(address)
            seen_families.add(version)
    return tuple(selected)


def _run_traces(addresses: tuple[str, ...], config: DiagnosticConfig) -> list[TraceResult]:
    if not config.trace:
        return []
    traces: list[TraceResult] = []
    for address in _trace_addresses(addresses):
        traces.append(
            run_traceroute(
                address,
                max_hops=config.trace_max_hops,
                wait_ms=config.trace_wait_ms,
            )
        )
    return traces


def _context(config: DiagnosticConfig) -> dict[str, Any]:
    proxy_names = [
        name
        for name in ("ALL_PROXY", "HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY")
        if os.environ.get(name) or os.environ.get(name.lower())
    ]
    return {
        "platform": platform.platform(),
        "python": sys.version.split()[0],
        "path_label": config.path_label,
        "proxy_environment_variables_present": proxy_names,
        "timeout_seconds": config.timeout,
        "classification_note": (
            "Без идентичного контрольного запуска через VPN большинство сетевых сбоев остаются "
            "подозрениями, а не подтверждённым DPI."
        ),
    }


def _route_recommendation(
    resolution: ResolutionSummary, probes: list[ProbeResult]
) -> dict[str, Any]:
    verified_addresses = {
        item.endpoint_ip
        for item in probes
        if item.probe_type == "tls"
        and item.outcome == Outcome.SUCCESS
        and item.evidence.get("variant") == "verified"
        and item.endpoint_ip is not None
    }
    addresses, source_warnings = select_route_addresses(
        resolution,
        verified_addresses=verified_addresses,
    )
    networks, excluded = destination_networks(addresses)
    warnings = list(source_warnings)
    if any(ipaddress.ip_address(item).version == 6 for item in addresses):
        warnings.append(
            "Есть IPv6: добавьте /128 и убедитесь, что VPN маршрутизирует IPv6, иначе возможен обход /32."
        )
    warnings.extend(
        [
            "Маршруты traceroute сюда не входят: промежуточные роутеры не являются адресами сервиса.",
            "CDN-адреса меняются; статический список нужно периодически синхронизировать.",
            "Редиректы, API и CDN на других доменах требуют отдельных целей.",
        ]
    )
    return {
        "addresses": list(addresses),
        "routes": networks,
        "excluded": excluded,
        "warnings": warnings,
    }


def run_diagnostics(
    target: Target,
    config: DiagnosticConfig | None = None,
    *,
    progress: Progress | None = None,
) -> DiagnosticReport:
    """Run the full staged diagnostic and always return a structured report."""

    settings = config or DiagnosticConfig()
    settings.validate()
    started = datetime.now(UTC)
    _notify(progress, "DNS: системный, UDP, TCP и DoH")
    resolution = resolve_all(
        target.hostname_idna,
        timeout=settings.timeout,
        resolvers=settings.resolvers,
        doh_endpoints=settings.doh_endpoints,
        include_tcp=settings.include_dns_tcp,
    )
    addresses = select_candidate_addresses(
        resolution,
        maximum_per_family=settings.max_addresses_per_family,
    )
    _notify(progress, f"TCP: {len(addresses)} конечных IP")
    tcp = _tcp_probes(target, addresses, settings)
    _notify(progress, "TLS: обычный, фрагментированный SNI и проверка сертификата")
    tls = _tls_probes(target, addresses, tcp, settings)
    _notify(progress, "UDP/443: QUIC Version Negotiation")
    quic = _quic_probes(addresses, settings)
    _notify(progress, "HTTP: обычный и фрагментированный Host")
    http = _http_probes(target, addresses, tcp, settings)
    probes = [*resolution.probes, *tcp, *tls, *quic, *http]
    findings = classify_probes(probes)
    if not findings:
        findings = [
            Finding(
                code="diagnostic_inconclusive",
                layer="summary",
                verdict="inconclusive",
                confidence="low",
                summary="Недостаточно успешных сравнительных проб для вывода.",
                evidence_probe_ids=tuple(item.id for item in probes),
                alternatives=("локальная потеря связи", "таймаут", "недоступность цели"),
            )
        ]
    _notify(progress, "Traceroute: по одному адресу каждого семейства")
    traces = _run_traces(addresses, settings)
    report = DiagnosticReport(
        run_id=str(uuid.uuid4()),
        target=target,
        started_at=started,
        context=_context(settings),
        probes=probes,
        findings=findings,
        traces=traces,
        route_recommendation=_route_recommendation(resolution, probes),
        completed_at=datetime.now(UTC),
    )
    _notify(progress, f"Готово за {(time.time() - started.timestamp()):.1f} с")
    return report
