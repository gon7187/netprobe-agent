from __future__ import annotations

from netprobe.diagnose import select_candidate_addresses
from netprobe.resolve import ResolutionSummary, select_route_addresses


def test_candidate_selection_keeps_system_and_doh_per_family() -> None:
    summary = ResolutionSummary(
        probes=(),
        addresses_by_source={
            "system:system": ("8.6.112.0", "8.47.69.0"),
            "doh:https://one": (
                "104.20.23.154",
                "172.66.147.243",
                "2606:4700:10::1",
                "2606:4700:10::2",
            ),
            "dns_tcp:1.1.1.1": ("8.6.112.0", "8.47.69.0"),
        },
    )

    selected = select_candidate_addresses(summary, maximum_per_family=2)

    assert selected[:2] == ("8.6.112.0", "104.20.23.154")
    assert selected[2:] == ("2606:4700:10::1", "2606:4700:10::2")


def test_route_selection_adds_only_tls_verified_system_only_addresses() -> None:
    summary = ResolutionSummary(
        probes=(),
        addresses_by_source={
            "system:system": ("8.6.112.0", "8.47.69.0"),
            "doh:https://one": ("104.20.23.154", "2606:4700:10::1"),
        },
    )

    addresses, warnings = select_route_addresses(summary, verified_addresses={"8.6.112.0"})

    assert addresses == ("8.6.112.0", "104.20.23.154", "2606:4700:10::1")
    assert any("8.47.69.0" in warning for warning in warnings)
