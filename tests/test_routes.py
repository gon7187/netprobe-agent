from __future__ import annotations

import json

from netprobe.routes import ManagedRouteFile, destination_networks


def test_destination_networks_are_exact_sorted_and_exclude_hops() -> None:
    networks, excluded = destination_networks(
        ["2001:4860:4860::8888", "8.8.8.8", "8.8.8.8", "192.168.1.1"]
    )
    assert networks == ["8.8.8.8/32", "2001:4860:4860::8888/128"]
    assert excluded == [{"address": "192.168.1.1", "reason": "non_global"}]


def test_managed_route_file_sync_is_idempotent_and_preserves_manual_entries(tmp_path) -> None:
    route_file = tmp_path / "vpn-routes.txt"
    route_file.write_text("# manual\n9.9.9.9/32\n", encoding="utf-8")
    manager = ManagedRouteFile(route_file)

    first = manager.sync("example.com", ["8.8.8.8/32", "2001:4860:4860::8888/128"])
    second = manager.sync("example.com", ["8.8.8.8/32", "2001:4860:4860::8888/128"])

    assert first.added == ("8.8.8.8/32", "2001:4860:4860::8888/128")
    assert second.added == ()
    assert "# manual" in route_file.read_text(encoding="utf-8")
    assert "9.9.9.9/32" in route_file.read_text(encoding="utf-8")

    state = json.loads((tmp_path / "vpn-routes.txt.netprobe.json").read_text(encoding="utf-8"))
    assert state["targets"]["example.com"]["routes"] == [
        "8.8.8.8/32",
        "2001:4860:4860::8888/128",
    ]


def test_sync_removes_only_stale_owned_route(tmp_path) -> None:
    route_file = tmp_path / "routes.txt"
    route_file.write_text("9.9.9.9/32\n", encoding="utf-8")
    manager = ManagedRouteFile(route_file)
    manager.sync("example.com", ["8.8.8.8/32"])

    result = manager.sync("example.com", ["1.1.1.1/32"])

    content = route_file.read_text(encoding="utf-8")
    assert result.removed == ("8.8.8.8/32",)
    assert "8.8.8.8/32" not in content
    assert "1.1.1.1/32" in content
    assert "9.9.9.9/32" in content


def test_shared_route_is_kept_until_last_target_removed(tmp_path) -> None:
    route_file = tmp_path / "routes.txt"
    manager = ManagedRouteFile(route_file)
    manager.sync("one.example", ["8.8.8.8/32"])
    manager.sync("two.example", ["8.8.8.8/32"])

    manager.remove("one.example")
    assert "8.8.8.8/32" in route_file.read_text(encoding="utf-8")
    manager.remove("two.example")
    assert "8.8.8.8/32" not in route_file.read_text(encoding="utf-8")
