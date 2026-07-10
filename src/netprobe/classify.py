"""Evidence-based classification that avoids categorical DPI claims."""

from __future__ import annotations

import ipaddress
from collections import defaultdict
from collections.abc import Iterable

from netprobe.models import Finding, Outcome, ProbeResult

_NETWORK_FAILURES = {Outcome.TIMEOUT, Outcome.RESET, Outcome.UNREACHABLE}
_TLS_FAILURES = _NETWORK_FAILURES | {Outcome.TLS_ALERT, Outcome.ERROR}


def _variant(probe: ProbeResult) -> str:
    return str(probe.evidence.get("variant", ""))


def _addresses(probe: ProbeResult) -> set[str]:
    values = probe.evidence.get("addresses", [])
    return {str(value) for value in values} if isinstance(values, list | tuple | set) else set()


def _endpoint(probe: ProbeResult) -> tuple[str | None, int | None]:
    return probe.endpoint_ip, probe.endpoint_port


def _special_addresses(addresses: Iterable[str]) -> set[str]:
    result: set[str] = set()
    for address in addresses:
        try:
            parsed = ipaddress.ip_address(address)
        except ValueError:
            continue
        if not parsed.is_global:
            result.add(parsed.compressed)
    return result


def _classify_dns(probes: list[ProbeResult]) -> list[Finding]:
    findings: list[Finding] = []
    dns = [probe for probe in probes if probe.probe_type == "dns"]
    system = [probe for probe in dns if _variant(probe) == "system"]
    alternates = [probe for probe in dns if _variant(probe) in {"doh", "dns_udp", "dns_tcp"}]
    system_addresses = set().union(*(_addresses(item) for item in system)) if system else set()
    alternate_addresses = (
        set().union(*(_addresses(item) for item in alternates)) if alternates else set()
    )
    doh = [probe for probe in alternates if _variant(probe) == "doh"]
    doh_addresses = set().union(*(_addresses(item) for item in doh)) if doh else set()
    comparison_addresses = doh_addresses or alternate_addresses
    system_failed = bool(system) and all(
        item.outcome in {Outcome.DNS_ERROR, Outcome.TIMEOUT, Outcome.ERROR} or not _addresses(item)
        for item in system
    )
    alternate_worked = any(
        item.outcome == Outcome.SUCCESS and _addresses(item) for item in alternates
    )
    pinned_worked = any(
        item.probe_type in {"tcp", "tls", "http"}
        and item.endpoint_ip in alternate_addresses
        and item.reached_transport
        for item in probes
    )
    if system_failed and alternate_worked and pinned_worked:
        evidence = tuple(item.id for item in system + alternates if item.outcome != Outcome.SKIPPED)
        findings.append(
            Finding(
                code="dns_interference_suspected",
                layer="dns",
                verdict="suspected",
                confidence="high",
                summary=(
                    "Системный DNS не дал пригодного ответа, тогда как независимый резолвер дал "
                    "IP и соединение с этим IP состоялось."
                ),
                evidence_probe_ids=evidence
                + tuple(
                    item.id
                    for item in probes
                    if item.endpoint_ip in alternate_addresses and item.reached_transport
                ),
                alternatives=("ошибка локального DNS-сервера", "политика корпоративной сети"),
                recommendation="Сравнить тот же запуск напрямую и через VPN.",
            )
        )

    special_system = _special_addresses(system_addresses)
    special_alternate = _special_addresses(comparison_addresses)
    if special_system and comparison_addresses and not special_alternate:
        findings.append(
            Finding(
                code="dns_forged_address_suspected",
                layer="dns",
                verdict="suspected",
                confidence="high",
                summary="Системный DNS вернул special-use IP, а независимые ответы — глобальные адреса.",
                evidence_probe_ids=tuple(item.id for item in system + alternates),
                alternatives=("split-horizon DNS", "локальная тестовая зона"),
            )
        )
    elif (
        system_addresses
        and comparison_addresses
        and system_addresses.isdisjoint(comparison_addresses)
    ):
        findings.append(
            Finding(
                code="dns_answer_mismatch",
                layer="dns",
                verdict="inconclusive",
                confidence="low",
                summary="Системный и независимые DNS вернули разные наборы адресов.",
                evidence_probe_ids=tuple(item.id for item in system + alternates),
                alternatives=("CDN/GeoDNS", "разные точки anycast", "DNS-кэш"),
                recommendation="Различие адресов само по себе не доказывает подмену DNS.",
            )
        )

    udp = [item for item in alternates if _variant(item) == "dns_udp"]
    tcp_or_doh = [item for item in alternates if _variant(item) in {"dns_tcp", "doh"}]
    if udp and all(
        item.outcome in _NETWORK_FAILURES | {Outcome.DNS_ERROR, Outcome.ERROR} for item in udp
    ):
        working = [
            item for item in tcp_or_doh if item.outcome == Outcome.SUCCESS and _addresses(item)
        ]
        if working:
            findings.append(
                Finding(
                    code="dns_udp_transport_interference_suspected",
                    layer="dns",
                    verdict="suspected",
                    confidence="medium",
                    summary="DNS по UDP/53 не работает, но TCP/DoH даёт ответы.",
                    evidence_probe_ids=tuple(item.id for item in udp + working),
                    alternatives=("роутер запрещает внешние DNS", "межсетевой экран организации"),
                )
            )
    return findings


def _classify_tcp(probes: list[ProbeResult]) -> list[Finding]:
    findings: list[Finding] = []
    tcp = [probe for probe in probes if probe.probe_type == "tcp"]
    controls = [probe for probe in probes if probe.probe_type == "control_tcp"]
    control_works = any(item.outcome == Outcome.SUCCESS for item in controls)
    refused = [item for item in tcp if item.outcome == Outcome.REFUSED]
    if refused:
        findings.append(
            Finding(
                code="service_refused",
                layer="tcp",
                verdict="observed",
                confidence="high",
                summary="Удалённый узел явно отказал в TCP-соединении: IP достижим, порт закрыт.",
                evidence_probe_ids=tuple(item.id for item in refused),
                alternatives=("служба не запущена", "порт закрыт сервером"),
            )
        )

    failed = [item for item in tcp if item.outcome in _NETWORK_FAILURES]
    if failed and control_works and not any(item.outcome == Outcome.SUCCESS for item in tcp):
        findings.append(
            Finding(
                code="tcp_ip_interference_suspected",
                layer="tcp",
                verdict="suspected",
                confidence="low",
                summary="Контрольный интернет-узел доступен, но TCP к целевым адресам не устанавливается.",
                evidence_probe_ids=tuple(
                    item.id for item in failed + controls if item.outcome == Outcome.SUCCESS
                ),
                alternatives=("сервер недоступен", "маршрутизация", "порт фильтруется сервером"),
                recommendation=(
                    "Для высокой уверенности нужен тот же exact IP:port через VPN в двух из трёх попыток."
                ),
            )
        )

    by_ip: dict[str, list[ProbeResult]] = defaultdict(list)
    for item in tcp:
        if item.endpoint_ip:
            by_ip[item.endpoint_ip].append(item)
    for ip, items in by_ip.items():
        good = [item for item in items if item.outcome == Outcome.SUCCESS]
        bad = [item for item in items if item.outcome in _NETWORK_FAILURES]
        if good and bad:
            findings.append(
                Finding(
                    code="port_specific_reachability_anomaly",
                    layer="tcp",
                    verdict="suspected",
                    confidence="low",
                    summary=f"Один порт на {ip} доступен, другой не отвечает.",
                    evidence_probe_ids=tuple(item.id for item in good + bad),
                    alternatives=("служба не слушает порт", "фильтр сервера", "сетевой фильтр"),
                )
            )
    by_port: dict[int, list[ProbeResult]] = defaultdict(list)
    for item in tcp:
        if item.endpoint_port is not None and item.endpoint_ip is not None:
            by_port[item.endpoint_port].append(item)
    for port, items in by_port.items():
        ipv4 = [
            item for item in items if item.family == "ipv4" or ":" not in (item.endpoint_ip or "")
        ]
        ipv6 = [item for item in items if item.family == "ipv6" or ":" in (item.endpoint_ip or "")]
        if (
            ipv4
            and ipv6
            and any(item.outcome == Outcome.SUCCESS for item in ipv4)
            and all(item.outcome in _NETWORK_FAILURES for item in ipv6)
        ):
            findings.append(
                Finding(
                    code="ipv6_reachability_problem",
                    layer="tcp_ipv6",
                    verdict="observed",
                    confidence="high",
                    summary=f"IPv4 на порту {port} работает, а все проверенные IPv6 недоступны.",
                    evidence_probe_ids=tuple(item.id for item in ipv4 + ipv6),
                    alternatives=("нет IPv6-маршрута", "IPv6 отключён у VPN/провайдера"),
                    recommendation="Не считать это DPI без target-specific сравнения через VPN.",
                )
            )
        elif (
            ipv4
            and ipv6
            and any(item.outcome == Outcome.SUCCESS for item in ipv6)
            and all(item.outcome in _NETWORK_FAILURES for item in ipv4)
        ):
            findings.append(
                Finding(
                    code="ipv4_reachability_problem",
                    layer="tcp_ipv4",
                    verdict="observed",
                    confidence="high",
                    summary=f"IPv6 на порту {port} работает, а все проверенные IPv4 недоступны.",
                    evidence_probe_ids=tuple(item.id for item in ipv4 + ipv6),
                    alternatives=("нет IPv4-маршрута", "семейство адресов фильтруется локально"),
                )
            )
    return findings


def _classify_tls(probes: list[ProbeResult]) -> list[Finding]:
    findings: list[Finding] = []
    tls = [probe for probe in probes if probe.probe_type == "tls"]
    tcp_by_endpoint = {
        _endpoint(item): item
        for item in probes
        if item.probe_type == "tcp" and item.outcome == Outcome.SUCCESS
    }
    cert_errors = [item for item in tls if item.outcome == Outcome.CERTIFICATE_ERROR]
    if cert_errors:
        findings.append(
            Finding(
                code="tls_certificate_error",
                layer="tls",
                verdict="observed",
                confidence="high",
                summary="TLS-транспорт достигнут, но стандартная проверка сертификата не прошла.",
                evidence_probe_ids=tuple(item.id for item in cert_errors),
                alternatives=(
                    "ошибка конфигурации сайта",
                    "неверное системное время",
                    "корпоративный TLS-прокси/антивирус",
                ),
            )
        )

    grouped: dict[tuple[str | None, int | None], dict[str, list[ProbeResult]]] = defaultdict(
        lambda: defaultdict(list)
    )
    for item in tls:
        grouped[_endpoint(item)][_variant(item)].append(item)
    for endpoint, variants in grouped.items():
        normal = variants.get("sni_normal", [])
        fragmented = variants.get("sni_fragmented", [])
        no_sni = variants.get("no_sni", [])
        normal_failed = [item for item in normal if item.outcome in _TLS_FAILURES]
        fragmented_ok = [item for item in fragmented if item.outcome == Outcome.SUCCESS]
        tcp = tcp_by_endpoint.get(endpoint)
        if normal_failed and fragmented_ok and tcp is not None:
            findings.append(
                Finding(
                    code="tls_sni_filtering_suspected",
                    layer="tls_sni",
                    verdict="suspected",
                    confidence="high",
                    summary=(
                        "На том же IP:port обычный ClientHello с SNI сбоит, а ClientHello с SNI, "
                        "разделённым между TCP-сегментами, проходит."
                    ),
                    evidence_probe_ids=tuple(
                        [
                            *(item.id for item in normal_failed),
                            *(item.id for item in fragmented_ok),
                            tcp.id,
                        ]
                    ),
                    alternatives=("редкая несовместимость сетевого оборудования",),
                    recommendation="Повторить сравнение 2–3 раза и через VPN.",
                )
            )
        elif (
            normal_failed
            and any(item.outcome == Outcome.SUCCESS for item in no_sni)
            and tcp is not None
        ):
            findings.append(
                Finding(
                    code="tls_sni_behavior_difference",
                    layer="tls_sni",
                    verdict="inconclusive",
                    confidence="medium",
                    summary="TLS с целевым SNI сбоит, а без SNI на том же IP:port проходит.",
                    evidence_probe_ids=tuple(
                        [
                            *(item.id for item in normal_failed),
                            *(item.id for item in no_sni),
                            tcp.id,
                        ]
                    ),
                    alternatives=(
                        "обычная конфигурация виртуального хостинга",
                        "разные политики TLS на default vhost",
                    ),
                    recommendation="Само по себе отличие no-SNI не доказывает DPI; нужен VPN-контроль.",
                )
            )
    return findings


def _classify_http(probes: list[ProbeResult]) -> list[Finding]:
    findings: list[Finding] = []
    http = [probe for probe in probes if probe.probe_type == "http"]
    grouped: dict[tuple[str | None, int | None], dict[str, list[ProbeResult]]] = defaultdict(
        lambda: defaultdict(list)
    )
    for item in http:
        grouped[_endpoint(item)][_variant(item)].append(item)
    for variants in grouped.values():
        normal = variants.get("host_normal", [])
        fragmented = variants.get("host_fragmented", [])
        normal_failed = [item for item in normal if item.outcome in _NETWORK_FAILURES]
        fragmented_ok = [item for item in fragmented if item.outcome == Outcome.HTTP_RESPONSE]
        if normal_failed and fragmented_ok:
            findings.append(
                Finding(
                    code="http_host_filtering_suspected",
                    layer="http_host",
                    verdict="suspected",
                    confidence="high",
                    summary=(
                        "Обычный HTTP Host сбоит, а тот же Host, разделённый между TCP-сегментами, "
                        "получает ответ."
                    ),
                    evidence_probe_ids=tuple(item.id for item in normal_failed + fragmented_ok),
                    alternatives=("нестандартный reverse proxy",),
                    recommendation="Повторить на том же IP через VPN.",
                )
            )

    policy = [
        item
        for item in http
        if item.outcome == Outcome.HTTP_RESPONSE and item.evidence.get("status_code") == 451
    ]
    if policy:
        findings.append(
            Finding(
                code="http_policy_response",
                layer="http",
                verdict="observed",
                confidence="high",
                summary="Сервер вернул HTTP 451; это ответ уровня приложения, а не доказательство DPI.",
                evidence_probe_ids=tuple(item.id for item in policy),
                alternatives=("политика origin/CDN", "географическое ограничение"),
            )
        )
    blockpages = [
        item
        for item in http
        if item.outcome == Outcome.HTTP_RESPONSE and item.evidence.get("blockpage_fingerprint")
    ]
    if blockpages:
        findings.append(
            Finding(
                code="explicit_blockpage_detected",
                layer="http",
                verdict="confirmed",
                confidence="high",
                summary="Ответ совпал с поддерживаемым явным fingerprint страницы блокировки.",
                evidence_probe_ids=tuple(item.id for item in blockpages),
            )
        )
    return findings


def _classify_quic(probes: list[ProbeResult]) -> list[Finding]:
    tcp_working = {
        _endpoint(item)
        for item in probes
        if item.probe_type == "tcp" and item.outcome == Outcome.SUCCESS
    }
    failed = [
        item
        for item in probes
        if item.probe_type == "udp_quic"
        and item.outcome in _NETWORK_FAILURES | {Outcome.ERROR}
        and _endpoint(item) in tcp_working
    ]
    if not failed:
        return []
    return [
        Finding(
            code="quic_reachability_inconclusive",
            layer="udp_quic",
            verdict="inconclusive",
            confidence="low",
            summary="TCP/443 работает, но QUIC Version Negotiation по UDP/443 не ответил.",
            evidence_probe_ids=tuple(item.id for item in failed),
            alternatives=(
                "endpoint не поддерживает QUIC",
                "сервер игнорирует неизвестную версию",
                "UDP фильтруется",
            ),
            recommendation="Только direct-fail/VPN-success на exact IP:443 усиливает вывод.",
        )
    ]


def classify_probes(probes: Iterable[ProbeResult]) -> list[Finding]:
    """Return ordered, explainable findings for a probe collection."""

    values = list(probes)
    findings = [
        *_classify_dns(values),
        *_classify_tcp(values),
        *_classify_tls(values),
        *_classify_quic(values),
        *_classify_http(values),
    ]
    if not findings and any(
        item.outcome in {Outcome.SUCCESS, Outcome.HTTP_RESPONSE} for item in values
    ):
        findings.append(
            Finding(
                code="no_interference_detected",
                layer="summary",
                verdict="normal",
                confidence="medium",
                summary="Проверенные этапы доступны; явных признаков вмешательства не найдено.",
                evidence_probe_ids=tuple(
                    item.id
                    for item in values
                    if item.outcome in {Outcome.SUCCESS, Outcome.HTTP_RESPONSE}
                ),
                recommendation="Отсутствие признаков в одном запуске не исключает выборочную фильтрацию.",
            )
        )
    return findings
