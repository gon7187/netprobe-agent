"""Command-line interface with stable JSON output for AI agents."""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import platform
import shutil
import socket
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

from netprobe import __version__
from netprobe.compare import compare_reports
from netprobe.diagnose import DiagnosticConfig, run_diagnostics
from netprobe.models import Outcome
from netprobe.probes import probe_tls
from netprobe.render import render_report
from netprobe.resolve import (
    DEFAULT_DOH_ENDPOINTS,
    DEFAULT_RESOLVERS,
    resolve_all,
    resolve_system,
    select_route_addresses,
)
from netprobe.routes import ManagedRouteFile, RouteFileError, destination_networks
from netprobe.serialization import dumps_json, to_primitive
from netprobe.target import TargetError, parse_target
from netprobe.trace import run_traceroute


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="netprobe",
        description="Диагностика DNS → TCP/IP → TLS/SNI → HTTP Host → traceroute.",
    )
    parser.add_argument("--version", action="version", version=f"netprobe {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    doctor = subparsers.add_parser("doctor", help="проверить локальные возможности")
    doctor.add_argument("--json", action="store_true", help="один JSON-документ в stdout")

    diagnose = subparsers.add_parser("diagnose", help="полная послойная диагностика")
    diagnose.add_argument("target", help="URL, домен или IP")
    diagnose.add_argument("--timeout", type=float, default=2.5, help="таймаут одной пробы, сек")
    diagnose.add_argument("--resolver", action="append", dest="resolvers", help="IP DNS-сервера")
    diagnose.add_argument("--doh", action="append", dest="doh_endpoints", help="HTTPS URL DoH")
    diagnose.add_argument(
        "--quick", action="store_true", help="по одному контролю и адресу семейства"
    )
    diagnose.add_argument("--no-dns-tcp", action="store_true", help="не проверять DNS/TCP")
    diagnose.add_argument("--no-trace", action="store_true", help="не запускать traceroute")
    diagnose.add_argument("--trace-max-hops", type=int, default=12)
    diagnose.add_argument("--trace-wait-ms", type=int, default=500)
    diagnose.add_argument("--no-extended-ports", action="store_true", help="только порт цели")
    diagnose.add_argument("--path-label", choices=("direct", "vpn", "proxy"), default="direct")
    diagnose.add_argument("--json", action="store_true", help="один JSON-документ в stdout")
    diagnose.add_argument("--json-out", type=Path, help="также атомарно сохранить JSON")
    diagnose.add_argument(
        "--fail-on-suspected",
        action="store_true",
        help="код 1 при suspected/confirmed (без флага завершённый отчёт = 0)",
    )

    trace = subparsers.add_parser("trace", help="traceroute к зафиксированным IP цели")
    trace.add_argument("target")
    trace.add_argument("--family", choices=("both", "4", "6"), default="both")
    trace.add_argument("--all-addresses", action="store_true")
    trace.add_argument("--max-hops", type=int, default=20)
    trace.add_argument("--wait-ms", type=int, default=500)
    trace.add_argument("--json", action="store_true")

    compare = subparsers.add_parser(
        "compare", help="сравнить отчёты direct и VPN только на exact IP:port"
    )
    compare.add_argument("direct_report", type=Path)
    compare.add_argument("vpn_report", type=Path)
    compare.add_argument("--json", action="store_true")

    routes = subparsers.add_parser("routes", help="кандидаты и managed-файл VPN маршрутов")
    route_subparsers = routes.add_subparsers(dest="route_command", required=True)
    suggest = route_subparsers.add_parser("suggest", help="только показать /32 и /128")
    _add_route_resolution_arguments(suggest)
    sync = route_subparsers.add_parser("sync", help="добавить/обновить адреса цели в файле")
    _add_route_resolution_arguments(sync)
    sync.add_argument("--file", required=True, type=Path)
    remove = route_subparsers.add_parser("remove", help="удалить только принадлежащие цели записи")
    remove.add_argument("target")
    remove.add_argument("--file", required=True, type=Path)
    remove.add_argument("--json", action="store_true")
    validate = route_subparsers.add_parser("validate", help="проверить файл без изменения")
    validate.add_argument("--file", required=True, type=Path)
    validate.add_argument("--json", action="store_true")
    return parser


def _add_route_resolution_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("target")
    parser.add_argument("--timeout", type=float, default=2.5)
    parser.add_argument("--allow-non-global", action="store_true")
    parser.add_argument(
        "--include-system-unverified",
        action="store_true",
        help="включить system-only IP без успешной TLS-проверки",
    )
    parser.add_argument("--json", action="store_true")


def _atomic_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary_path = Path(temporary)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(content)
            if not content.endswith("\n"):
                handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, path)
    finally:
        temporary_path.unlink(missing_ok=True)


def _doctor_payload() -> dict[str, Any]:
    if platform.system().lower().startswith("win"):
        trace_tools = [shutil.which("tracert.exe")]
    elif platform.system().lower() == "darwin":
        trace_tools = [shutil.which("traceroute"), shutil.which("traceroute6")]
    else:
        trace_tools = [shutil.which("traceroute"), shutil.which("tracepath")]
    return {
        "schema_version": "1.0",
        "netprobe": __version__,
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "ipv6_supported": socket.has_ipv6,
        "traceroute_tools": [item for item in trace_tools if item],
        "runtime_dependencies": [],
    }


def _print_doctor(arguments: argparse.Namespace) -> int:
    payload = _doctor_payload()
    if arguments.json:
        print(dumps_json(payload))
    else:
        print(f"netprobe {payload['netprobe']} | Python {payload['python']}")
        print(f"Платформа: {payload['platform']}")
        print(f"IPv6: {'да' if payload['ipv6_supported'] else 'нет'}")
        tools = payload["traceroute_tools"]
        print(f"Traceroute: {', '.join(tools) if tools else 'не найден'}")
        print("Runtime dependencies: нет (stdlib-only)")
    return 0


def _diagnostic_config(arguments: argparse.Namespace) -> DiagnosticConfig:
    resolvers = tuple(arguments.resolvers or DEFAULT_RESOLVERS)
    doh = tuple(arguments.doh_endpoints or DEFAULT_DOH_ENDPOINTS)
    if arguments.quick:
        resolvers = resolvers[:1]
        doh = doh[:1]
    return DiagnosticConfig(
        timeout=arguments.timeout,
        resolvers=resolvers,
        doh_endpoints=doh,
        include_dns_tcp=not arguments.no_dns_tcp and not arguments.quick,
        trace=not arguments.no_trace,
        trace_max_hops=arguments.trace_max_hops,
        trace_wait_ms=arguments.trace_wait_ms,
        max_addresses_per_family=1 if arguments.quick else 2,
        extended_ports=not arguments.no_extended_ports,
        extended_tls=not arguments.quick,
        path_label=arguments.path_label,
    )


def _run_diagnose(arguments: argparse.Namespace) -> int:
    target = parse_target(arguments.target)
    json_mode = bool(arguments.json)

    def progress(message: str) -> None:
        if not json_mode:
            print(f"→ {message}", file=sys.stderr, flush=True)
        elif arguments.json_out:
            print(f"netprobe: {message}", file=sys.stderr, flush=True)

    report = run_diagnostics(target, _diagnostic_config(arguments), progress=progress)
    document = dumps_json(report)
    if arguments.json_out:
        _atomic_write(arguments.json_out, document)
    if json_mode:
        print(document)
    else:
        print(render_report(report))
        if arguments.json_out:
            print(f"\nJSON: {arguments.json_out}")
    has_suspected = any(item.verdict in {"suspected", "confirmed"} for item in report.findings)
    return 1 if arguments.fail_on_suspected and has_suspected else 0


def _filter_family(addresses: list[str], family: str) -> list[str]:
    if family == "both":
        return addresses
    version = int(family)
    return [item for item in addresses if ipaddress.ip_address(item).version == version]


def _run_trace(arguments: argparse.Namespace) -> int:
    target = parse_target(arguments.target)
    resolution = resolve_system(target.hostname_idna)
    addresses = _filter_family(list(resolution.evidence.get("addresses", [])), arguments.family)
    if not arguments.all_addresses:
        primary: list[str] = []
        seen: set[int] = set()
        for address in addresses:
            version = ipaddress.ip_address(address).version
            if version not in seen:
                primary.append(address)
                seen.add(version)
        addresses = primary
    results = [
        run_traceroute(address, max_hops=arguments.max_hops, wait_ms=arguments.wait_ms)
        for address in addresses
    ]
    payload = {
        "schema_version": "1.0",
        "target": to_primitive(target),
        "resolved_addresses": addresses,
        "traces": results,
        "warning": "Промежуточные hops нельзя добавлять в VPN route-файл.",
    }
    if arguments.json:
        print(dumps_json(payload))
    else:
        print(f"Цель: {target.hostname_idna} -> {', '.join(addresses) or 'нет IP'}")
        for result in results:
            print(
                f"{result.target_ip}: {'reached' if result.reached else 'partial'}, hops={len(result.hops)}"
            )
            for hop in result.hops:
                responders = ", ".join(item.ip for item in hop.responders) or "*"
                print(f"  {hop.ttl:>2}  {responders}")
            if result.error:
                print(f"  ! {result.error}")
        print("Важно: hops — роутеры пути, а не адреса назначения; в VPN-файл их не добавляют.")
    return 0


def _load_report(path: Path) -> dict[str, Any]:
    try:
        if path.stat().st_size > 32 * 1024 * 1024:
            raise ValueError(f"report is too large: {path}")
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read report {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"report must contain a JSON object: {path}")
    return value


def _run_compare(arguments: argparse.Namespace) -> int:
    result = compare_reports(
        _load_report(arguments.direct_report),
        _load_report(arguments.vpn_report),
    )
    if arguments.json:
        print(dumps_json(result))
    else:
        print(f"Exact comparisons: {len(result['exact_comparisons'])}")
        for finding in result["findings"]:
            print(
                f"[{finding['confidence']}/{finding['verdict']}] "
                f"{finding['code']}: {finding['summary']}"
            )
        print(f"! {result['warning']}")
    return 0


def _route_plan(arguments: argparse.Namespace) -> tuple[str, dict[str, Any]]:
    target = parse_target(arguments.target)
    resolution = resolve_all(
        target.hostname_idna,
        timeout=arguments.timeout,
        resolvers=DEFAULT_RESOLVERS,
        doh_endpoints=DEFAULT_DOH_ENDPOINTS,
        include_tcp=True,
    )
    all_candidates = sorted(
        {
            address
            for source_addresses in resolution.addresses_by_source.values()
            for address in source_addresses
        },
        key=lambda value: (ipaddress.ip_address(value).version, int(ipaddress.ip_address(value))),
    )[:32]
    validation_results = []
    if not target.is_ip and all_candidates:
        port = target.port if target.scheme == "https" else 443
        with ThreadPoolExecutor(
            max_workers=min(12, len(all_candidates)), thread_name_prefix="netprobe-routes"
        ) as pool:
            futures = [
                pool.submit(
                    probe_tls,
                    f"route-tls-{index}",
                    address,
                    port,
                    hostname=target.hostname_idna,
                    timeout=arguments.timeout,
                    variant="verified",
                    verify=True,
                )
                for index, address in enumerate(all_candidates, start=1)
            ]
            validation_results = [future.result() for future in as_completed(futures)]
    verified = {
        result.endpoint_ip
        for result in validation_results
        if result.outcome == Outcome.SUCCESS and result.endpoint_ip is not None
    }
    if arguments.include_system_unverified:
        verified.update(resolution.addresses_by_source.get("system:system", ()))
    addresses, warnings = select_route_addresses(
        resolution,
        verified_addresses=verified,
    )
    networks, excluded = destination_networks(
        addresses,
        include_non_global=arguments.allow_non_global,
    )
    payload = {
        "schema_version": "1.0",
        "target": to_primitive(target),
        "selected_addresses": list(addresses),
        "routes": networks,
        "excluded": excluded,
        "warnings": [
            *warnings,
            "Только конечные /32 и /128; hops traceroute намеренно исключены.",
            "CDN IP меняются — используйте routes sync повторно.",
        ],
        "tls_validation": [
            {
                "address": result.endpoint_ip,
                "outcome": result.outcome,
                "error": result.error,
            }
            for result in sorted(validation_results, key=lambda item: item.endpoint_ip or "")
        ],
    }
    return target.hostname_idna, payload


def _run_routes(arguments: argparse.Namespace) -> int:
    if arguments.route_command in {"suggest", "sync"}:
        target, payload = _route_plan(arguments)
        if arguments.route_command == "sync":
            result = ManagedRouteFile(arguments.file).sync(target, payload["routes"])
            payload["route_file"] = {
                "path": str(arguments.file.absolute()),
                "state_path": str(
                    arguments.file.with_name(f"{arguments.file.name}.netprobe.json").absolute()
                ),
                "added": list(result.added),
                "removed": list(result.removed),
                "unchanged": sorted(set(result.routes) - set(result.added)),
            }
        if arguments.json:
            print(dumps_json(payload))
        else:
            print(f"Цель: {target}")
            print("Маршруты:")
            for route in payload["routes"]:
                print(route)
            for warning in payload["warnings"]:
                print(f"! {warning}")
            if "route_file" in payload:
                print(f"Файл: {payload['route_file']['path']}")
        return 0

    if arguments.route_command == "remove":
        target = parse_target(arguments.target).hostname_idna
        result = ManagedRouteFile(arguments.file).remove(target)
        payload = {
            "schema_version": "1.0",
            "target": target,
            "file": str(arguments.file.absolute()),
            "removed": list(result.removed),
        }
        print(
            dumps_json(payload)
            if arguments.json
            else f"Удалено: {', '.join(result.removed) or 'ничего'}"
        )
        return 0

    return _validate_route_file(arguments)


def _validate_route_file(arguments: argparse.Namespace) -> int:
    path: Path = arguments.file
    errors: list[dict[str, Any]] = []
    routes: list[str] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise RouteFileError(str(exc)) from exc
    for number, line in enumerate(lines, start=1):
        value = line.strip()
        if not value or value.startswith("#"):
            continue
        try:
            networks, _excluded = destination_networks(
                [value.split("/", 1)[0]], include_non_global=True
            )
            if not networks or value not in networks:
                raise ValueError("must be canonical /32 or /128")
            routes.append(value)
        except ValueError as exc:
            errors.append({"line": number, "value": value[:200], "error": str(exc)})
    payload = {
        "schema_version": "1.0",
        "file": str(path.absolute()),
        "valid": not errors,
        "routes": routes,
        "errors": errors,
    }
    if arguments.json:
        print(dumps_json(payload))
    else:
        print(f"{path}: {'OK' if not errors else 'ошибки'}; routes={len(routes)}")
        for item in errors:
            print(f"  line {item['line']}: {item['error']}")
    return 0 if not errors else 1


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    try:
        try:
            arguments = parser.parse_args(argv)
        except SystemExit as exc:
            return int(exc.code or 0)
        if arguments.command == "doctor":
            return _print_doctor(arguments)
        if arguments.command == "diagnose":
            return _run_diagnose(arguments)
        if arguments.command == "trace":
            return _run_trace(arguments)
        if arguments.command == "compare":
            return _run_compare(arguments)
        if arguments.command == "routes":
            return _run_routes(arguments)
        parser.error("unknown command")
    except KeyboardInterrupt:
        print("netprobe: прервано пользователем", file=sys.stderr)
        return 130
    except (TargetError, RouteFileError, ValueError) as exc:
        print(f"netprobe: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:  # pragma: no cover - last-resort CLI boundary
        print(
            f"netprobe: локальная ошибка инструмента: {type(exc).__name__}: {exc}", file=sys.stderr
        )
        return 3
    return 3


if __name__ == "__main__":
    raise SystemExit(main())
