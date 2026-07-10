"""System and independent DNS resolution orchestration."""

from __future__ import annotations

import ipaddress
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Any

from netprobe.dns_wire import DNSMessage, query_doh, query_tcp, query_udp
from netprobe.models import Outcome, ProbeError, ProbeResult
from netprobe.probes import normalize_exception

DEFAULT_RESOLVERS: tuple[str, ...] = ("1.1.1.1", "8.8.8.8")
DEFAULT_DOH_ENDPOINTS: tuple[str, ...] = (
    "https://cloudflare-dns.com/dns-query",
    "https://dns.google/dns-query",
)


@dataclass(frozen=True, slots=True)
class ResolutionSummary:
    probes: tuple[ProbeResult, ...]
    addresses_by_source: dict[str, tuple[str, ...]]

    @property
    def all_addresses(self) -> tuple[str, ...]:
        values = {
            address for addresses in self.addresses_by_source.values() for address in addresses
        }
        return tuple(
            sorted(
                values,
                key=lambda value: (
                    ipaddress.ip_address(value).version,
                    int(ipaddress.ip_address(value)),
                ),
            )
        )


def _sort_addresses(addresses: set[str]) -> list[str]:
    return sorted(
        addresses,
        key=lambda value: (ipaddress.ip_address(value).version, int(ipaddress.ip_address(value))),
    )


def resolve_system(hostname: str, *, probe_id: str = "dns-system") -> ProbeResult:
    started = time.perf_counter()
    evidence: dict[str, Any] = {"variant": "system", "resolver": "system", "transport": "system"}
    try:
        try:
            numeric = ipaddress.ip_address(hostname)
        except ValueError:
            numeric = None
        if numeric is not None:
            addresses = [numeric.compressed]
        else:
            info = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
            addresses = _sort_addresses({str(item[4][0]).split("%", 1)[0] for item in info})
        evidence["addresses"] = addresses
        outcome = Outcome.SUCCESS if addresses else Outcome.DNS_ERROR
        error = (
            None
            if addresses
            else ProbeError("empty_answer", "system DNS returned no addresses", "resolve")
        )
    except (socket.gaierror, OSError) as exc:
        outcome, normalized = normalize_exception(exc, stage="resolve")
        outcome = Outcome.TIMEOUT if outcome == Outcome.TIMEOUT else Outcome.DNS_ERROR
        error = normalized
        evidence["addresses"] = []
        if isinstance(exc, socket.gaierror):
            evidence["gaierror"] = exc.errno
    return ProbeResult(
        id=probe_id,
        probe_type="dns",
        stage="dns",
        outcome=outcome,
        duration_ms=(time.perf_counter() - started) * 1000,
        hostname=hostname,
        evidence=evidence,
        error=error,
    )


def _dns_probe(
    probe_id: str,
    hostname: str,
    qtype: int,
    *,
    variant: str,
    resolver: str,
    timeout: float,
) -> ProbeResult:
    started = time.perf_counter()
    evidence: dict[str, Any] = {
        "variant": variant,
        "resolver": resolver,
        "transport": {"dns_udp": "udp", "dns_tcp": "tcp", "doh": "https"}[variant],
        "qtype": "A" if qtype == 1 else "AAAA",
    }
    try:
        message: DNSMessage
        if variant == "dns_udp":
            message = query_udp(resolver, hostname, qtype=qtype, timeout=timeout)
        elif variant == "dns_tcp":
            message = query_tcp(resolver, hostname, qtype=qtype, timeout=timeout)
        else:
            message = query_doh(resolver, hostname, qtype=qtype, timeout=timeout)
        evidence.update(
            {
                "rcode": message.rcode,
                "rcode_name": message.rcode_name,
                "truncated": message.truncated,
                "addresses": list(message.addresses),
                "cnames": list(message.cnames),
                "records": [
                    {
                        "name": item.name,
                        "type": item.type,
                        "ttl": item.ttl,
                        "value": item.value.hex() if isinstance(item.value, bytes) else item.value,
                    }
                    for item in message.records
                ],
            }
        )
        if message.rcode == 0:
            outcome = Outcome.SUCCESS
            error = None
        else:
            outcome = Outcome.DNS_ERROR
            error = ProbeError(
                category="dns_rcode",
                message=message.rcode_name,
                stage="resolve",
                code=message.rcode,
            )
    except Exception as exc:
        outcome, error = normalize_exception(exc, stage="resolve")
        if outcome not in {Outcome.TIMEOUT, Outcome.UNREACHABLE, Outcome.RESET}:
            outcome = Outcome.DNS_ERROR
        evidence["addresses"] = []
    return ProbeResult(
        id=probe_id,
        probe_type="dns",
        stage="dns",
        outcome=outcome,
        duration_ms=(time.perf_counter() - started) * 1000,
        hostname=hostname,
        evidence=evidence,
        error=error,
    )


def resolve_all(
    hostname: str,
    *,
    timeout: float,
    resolvers: tuple[str, ...] = DEFAULT_RESOLVERS,
    doh_endpoints: tuple[str, ...] = DEFAULT_DOH_ENDPOINTS,
    include_tcp: bool = True,
) -> ResolutionSummary:
    """Resolve through system DNS, UDP/TCP DNS, and DNS-over-HTTPS in parallel."""

    system = resolve_system(hostname)
    jobs: list[tuple[str, str, int, str]] = []
    for resolver_index, resolver in enumerate(resolvers, start=1):
        for qtype in (1, 28):
            suffix = "a" if qtype == 1 else "aaaa"
            jobs.append((f"dns-udp-{resolver_index}-{suffix}", "dns_udp", qtype, resolver))
            if include_tcp:
                jobs.append((f"dns-tcp-{resolver_index}-{suffix}", "dns_tcp", qtype, resolver))
    for endpoint_index, endpoint in enumerate(doh_endpoints, start=1):
        for qtype in (1, 28):
            suffix = "a" if qtype == 1 else "aaaa"
            jobs.append((f"dns-doh-{endpoint_index}-{suffix}", "doh", qtype, endpoint))

    probes: list[ProbeResult] = [system]
    if jobs:
        with ThreadPoolExecutor(
            max_workers=min(12, len(jobs)), thread_name_prefix="netprobe-dns"
        ) as pool:
            futures = {
                pool.submit(
                    _dns_probe,
                    probe_id,
                    hostname,
                    qtype,
                    variant=variant,
                    resolver=resolver,
                    timeout=timeout,
                ): probe_id
                for probe_id, variant, qtype, resolver in jobs
            }
            completed = [future.result() for future in as_completed(futures)]
        probes.extend(sorted(completed, key=lambda item: item.id))

    by_source: dict[str, set[str]] = {}
    for probe in probes:
        source = f"{probe.evidence.get('variant')}:{probe.evidence.get('resolver')}"
        by_source.setdefault(source, set()).update(
            str(item) for item in probe.evidence.get("addresses", [])
        )
    return ResolutionSummary(
        probes=tuple(probes),
        addresses_by_source={
            key: tuple(_sort_addresses(value)) for key, value in by_source.items()
        },
    )


def trusted_route_addresses(summary: ResolutionSummary) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Prefer encrypted answers, then DNS/TCP, then system resolution."""

    warnings: list[str] = []
    groups: tuple[tuple[str, ...], ...] = (
        tuple(key for key in summary.addresses_by_source if key.startswith("doh:")),
        tuple(key for key in summary.addresses_by_source if key.startswith("dns_tcp:")),
        ("system:system",),
    )
    selected: set[str] = set()
    selected_group = ""
    for keys in groups:
        selected = {address for key in keys for address in summary.addresses_by_source.get(key, ())}
        if selected:
            selected_group = keys[0].split(":", 1)[0]
            break
    if selected_group != "doh":
        warnings.append("DoH не дал адресов; использован менее защищённый источник DNS.")
    system = set(summary.addresses_by_source.get("system:system", ()))
    if system and selected and system.isdisjoint(selected):
        warnings.append("Системный DNS и выбранный доверенный источник дали непересекающиеся IP.")
    return tuple(_sort_addresses(selected)), tuple(warnings)


def select_route_addresses(
    summary: ResolutionSummary,
    *,
    verified_addresses: set[str] | frozenset[str] = frozenset(),
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Combine encrypted DNS answers with system-only IPs proven by hostname TLS."""

    selected, source_warnings = trusted_route_addresses(summary)
    warnings = list(source_warnings)
    selected_set = set(selected)
    system = set(summary.addresses_by_source.get("system:system", ()))
    has_doh = any(
        summary.addresses_by_source.get(key)
        for key in summary.addresses_by_source
        if key.startswith("doh:")
    )
    if has_doh:
        selected_set.update(system & set(verified_addresses))
        excluded_system = system - selected_set
        if excluded_system:
            values = ", ".join(_sort_addresses(excluded_system))
            warnings.append(f"System-only IP без успешной TLS-проверки не добавлены: {values}.")
    return tuple(_sort_addresses(selected_set)), tuple(warnings)
