"""Compact Russian human-readable output; JSON remains the agent contract."""

from __future__ import annotations

from collections import Counter

from netprobe.models import DiagnosticReport


def render_report(report: DiagnosticReport) -> str:
    lines = [
        f"Цель: {report.target.normalized_url}",
        f"Run ID: {report.run_id}",
        "",
        "Этапы:",
    ]
    by_stage: dict[str, Counter[str]] = {}
    for probe in report.probes:
        by_stage.setdefault(probe.stage, Counter())[probe.outcome.value] += 1
    for stage, outcomes in by_stage.items():
        details = ", ".join(f"{name}={count}" for name, count in sorted(outcomes.items()))
        lines.append(f"  {stage:<8} {details}")

    lines.extend(["", "Выводы:"])
    for finding in report.findings:
        lines.append(
            f"  [{finding.confidence}/{finding.verdict}] {finding.code}: {finding.summary}"
        )
        if finding.alternatives:
            lines.append(f"    Другие объяснения: {', '.join(finding.alternatives)}")
        if finding.recommendation:
            lines.append(f"    Дальше: {finding.recommendation}")

    lines.extend(["", "Traceroute:"])
    if not report.traces:
        lines.append("  отключён или нет адресов")
    for trace in report.traces:
        status = "достигнут" if trace.reached else "не достигнут/ICMP фильтруется"
        lines.append(f"  {trace.target_ip}: {status}, hops={len(trace.hops)}")
        if trace.error:
            lines.append(f"    {trace.error}")

    routes = report.route_recommendation.get("routes", [])
    lines.extend(["", "Кандидаты для VPN (только конечные адреса):"])
    lines.extend(f"  {route}" for route in routes)
    if not routes:
        lines.append("  нет безопасных глобальных адресов")
    for warning in report.route_recommendation.get("warnings", []):
        lines.append(f"  ! {warning}")
    return "\n".join(lines)
