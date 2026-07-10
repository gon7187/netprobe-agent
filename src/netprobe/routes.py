"""Safe exact-route suggestions and management of a plain-text route file.

The route file may contain arbitrary user-maintained lines.  Netprobe records the
routes it actually inserted in a JSON sidecar, so a later sync never has to guess
which existing entries belong to the user.
"""

from __future__ import annotations

import ipaddress
import json
import os
import stat
import tempfile
import threading
from collections.abc import Iterable
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

_STATE_VERSION = 1
_MAX_ROUTE_FILE_BYTES = 16 * 1024 * 1024
_MAX_STATE_FILE_BYTES = 4 * 1024 * 1024
_MAX_TARGETS = 10_000
_MAX_ROUTES = 100_000
_PATH_LOCKS: dict[str, threading.RLock] = {}
_PATH_LOCKS_GUARD = threading.Lock()


class RouteFileError(ValueError):
    """Base class for invalid or unsafe route-file operations."""


class UnsafeRoutePathError(RouteFileError):
    """Raised when a managed path is a symlink or not a regular file."""


class RouteStateError(RouteFileError):
    """Raised when the ownership sidecar is malformed or unsupported."""


@dataclass(frozen=True, slots=True)
class RouteSyncResult:
    """Changes made by :class:`ManagedRouteFile` for one target."""

    target: str
    routes: tuple[str, ...]
    added: tuple[str, ...] = ()
    removed: tuple[str, ...] = ()


@dataclass(slots=True)
class _RouteState:
    targets: dict[str, set[str]]
    owned_routes: set[str]


def _route_sort_key(route: str) -> tuple[int, int]:
    network = ipaddress.ip_network(route, strict=True)
    return network.version, int(network.network_address)


def _sorted_routes(routes: Iterable[str]) -> list[str]:
    return sorted(routes, key=_route_sort_key)


def _canonical_exact_route(value: object) -> str:
    if not isinstance(value, str):
        raise RouteFileError("route entries must be strings")
    candidate = value.strip()
    if not candidate or "/" not in candidate:
        raise RouteFileError(f"route must be an exact CIDR: {value!r}")
    try:
        network = ipaddress.ip_network(candidate, strict=True)
    except ValueError as exc:
        raise RouteFileError(f"invalid route: {value!r}") from exc
    if network.prefixlen != network.max_prefixlen:
        expected = 32 if network.version == 4 else 128
        raise RouteFileError(f"route must use /{expected}: {value!r}")
    return network.with_prefixlen


def _canonical_route_set(values: Iterable[object]) -> set[str]:
    routes: set[str] = set()
    for count, value in enumerate(values, start=1):
        if count > _MAX_ROUTES:
            raise RouteFileError(f"too many routes (maximum {_MAX_ROUTES})")
        route = _canonical_exact_route(value)
        routes.add(route)
    return routes


def destination_networks(
    addresses: Iterable[str | IPAddress], *, include_non_global: bool = False
) -> tuple[list[str], list[dict[str, str]]]:
    """Convert destination addresses to deterministic exact host networks.

    Private, loopback, link-local, multicast, reserved, and otherwise non-global
    addresses are excluded by default.  Invalid values are reported alongside
    excluded addresses rather than making traceroute-derived suggestions fail.
    """

    accepted: set[str] = set()
    excluded: dict[tuple[str, str], dict[str, str]] = {}

    for value in addresses:
        raw = str(value).strip()
        try:
            address = ipaddress.ip_address(raw)
        except ValueError:
            item = {"address": raw, "reason": "invalid_address"}
            excluded[(raw, item["reason"])] = item
            continue

        # Scoped IPv6 literals are meaningful only with their interface and are
        # not safe as portable VPN route-file entries.
        if isinstance(address, ipaddress.IPv6Address) and address.scope_id is not None:
            item = {"address": str(address), "reason": "invalid_address"}
            excluded[(item["address"], item["reason"])] = item
            continue

        canonical = str(address)
        if not include_non_global and not address.is_global:
            item = {"address": canonical, "reason": "non_global"}
            excluded[(canonical, item["reason"])] = item
            continue

        accepted.add(f"{canonical}/{address.max_prefixlen}")

    def excluded_sort_key(item: dict[str, str]) -> tuple[int, int | str, str]:
        try:
            address = ipaddress.ip_address(item["address"])
        except ValueError:
            return 3, item["address"].casefold(), item["reason"]
        return address.version, int(address), item["reason"]

    return _sorted_routes(accepted), sorted(excluded.values(), key=excluded_sort_key)


def _validate_target(target: object) -> str:
    if not isinstance(target, str):
        raise RouteFileError("target must be a string")
    if not target or target != target.strip():
        raise RouteFileError("target must be non-empty and have no surrounding whitespace")
    if len(target) > 1024 or any(ord(character) < 32 for character in target):
        raise RouteFileError("target contains invalid characters")
    return target


def _absolute_without_resolving(path: Path) -> Path:
    return Path(os.path.abspath(os.fspath(path)))


def _path_lock(path: Path) -> threading.RLock:
    key = os.path.normcase(os.fspath(_absolute_without_resolving(path)))
    with _PATH_LOCKS_GUARD:
        return _PATH_LOCKS.setdefault(key, threading.RLock())


def _reject_symlink_components(path: Path) -> None:
    current = _absolute_without_resolving(path)
    while True:
        try:
            metadata = os.lstat(current)
        except FileNotFoundError:
            pass
        else:
            if stat.S_ISLNK(metadata.st_mode):
                raise UnsafeRoutePathError(f"symlinks are not allowed: {current}")
        parent = current.parent
        if parent == current:
            return
        current = parent


def _read_regular_text(path: Path, *, maximum_bytes: int) -> str | None:
    _reject_symlink_components(path)
    try:
        before = os.lstat(path)
    except FileNotFoundError:
        return None
    if stat.S_ISLNK(before.st_mode):
        raise UnsafeRoutePathError(f"symlinks are not allowed: {path}")
    if not stat.S_ISREG(before.st_mode):
        raise UnsafeRoutePathError(f"path is not a regular file: {path}")
    if before.st_size > maximum_bytes:
        raise RouteFileError(f"file is too large: {path}")

    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        # Some platforms report ELOOP for O_NOFOLLOW; present it as the stable
        # public error rather than exposing platform-specific errno behavior.
        if path.is_symlink():
            raise UnsafeRoutePathError(f"symlinks are not allowed: {path}") from exc
        raise

    with os.fdopen(descriptor, "rb") as handle:
        opened = os.fstat(handle.fileno())
        if not stat.S_ISREG(opened.st_mode):
            raise UnsafeRoutePathError(f"path is not a regular file: {path}")
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise UnsafeRoutePathError(f"path changed while it was being opened: {path}")
        data = handle.read(maximum_bytes + 1)

    if len(data) > maximum_bytes:
        raise RouteFileError(f"file is too large: {path}")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise RouteFileError(f"file is not valid UTF-8: {path}") from exc


def _fsync_directory(directory: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    try:
        descriptor = os.open(directory, flags)
    except OSError:
        return
    try:
        os.fsync(descriptor)
    except OSError:
        # Directory fsync is unavailable on Windows and some filesystems.
        pass
    finally:
        os.close(descriptor)


def _atomic_write_text(path: Path, content: str) -> None:
    _reject_symlink_components(path)
    parent = path.parent
    try:
        parent_metadata = os.lstat(parent)
    except FileNotFoundError as exc:
        raise RouteFileError(f"parent directory does not exist: {parent}") from exc
    if not stat.S_ISDIR(parent_metadata.st_mode):
        raise RouteFileError(f"parent path is not a directory: {parent}")

    existing_mode: int | None = None
    try:
        destination_metadata = os.lstat(path)
    except FileNotFoundError:
        pass
    else:
        if stat.S_ISLNK(destination_metadata.st_mode):
            raise UnsafeRoutePathError(f"symlinks are not allowed: {path}")
        if not stat.S_ISREG(destination_metadata.st_mode):
            raise UnsafeRoutePathError(f"path is not a regular file: {path}")
        existing_mode = stat.S_IMODE(destination_metadata.st_mode)

    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=parent
    )
    temporary_path = Path(temporary_name)
    try:
        if existing_mode is not None:
            os.chmod(temporary_path, existing_mode)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as handle:
            descriptor = -1
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())

        _reject_symlink_components(path)
        try:
            destination_metadata = os.lstat(path)
        except FileNotFoundError:
            pass
        else:
            if stat.S_ISLNK(destination_metadata.st_mode):
                raise UnsafeRoutePathError(f"symlinks are not allowed: {path}")
            if not stat.S_ISREG(destination_metadata.st_mode):
                raise UnsafeRoutePathError(f"path is not a regular file: {path}")

        os.replace(temporary_path, path)
        _fsync_directory(parent)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        with suppress(FileNotFoundError):
            temporary_path.unlink()


def _json_object_without_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise RouteStateError(f"duplicate key in route state: {key!r}")
        result[key] = value
    return result


def _load_state(text: str | None) -> _RouteState:
    if text is None:
        return _RouteState(targets={}, owned_routes=set())
    try:
        document = json.loads(text, object_pairs_hook=_json_object_without_duplicate_keys)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise RouteStateError("route state is not valid JSON") from exc
    if not isinstance(document, dict):
        raise RouteStateError("route state must be a JSON object")

    version = document.get("version", _STATE_VERSION)
    if type(version) is not int or version != _STATE_VERSION:
        raise RouteStateError(f"unsupported route state version: {version!r}")

    raw_targets = document.get("targets")
    if not isinstance(raw_targets, dict):
        raise RouteStateError("route state targets must be an object")
    if len(raw_targets) > _MAX_TARGETS:
        raise RouteStateError(f"too many route targets (maximum {_MAX_TARGETS})")

    targets: dict[str, set[str]] = {}
    for raw_target, raw_entry in raw_targets.items():
        try:
            target = _validate_target(raw_target)
        except RouteFileError as exc:
            raise RouteStateError(f"invalid target in route state: {raw_target!r}") from exc
        if not isinstance(raw_entry, dict) or not isinstance(raw_entry.get("routes"), list):
            raise RouteStateError(f"invalid route state entry for target {target!r}")
        raw_routes = raw_entry["routes"]
        try:
            routes = _canonical_route_set(raw_routes)
        except RouteFileError as exc:
            raise RouteStateError(f"invalid route for target {target!r}") from exc
        if len(routes) != len(raw_routes):
            raise RouteStateError(f"duplicate routes for target {target!r}")
        targets[target] = routes

    raw_owned = document.get("owned_routes", [])
    if not isinstance(raw_owned, list):
        raise RouteStateError("route state owned_routes must be an array")
    try:
        owned_routes = _canonical_route_set(raw_owned)
    except RouteFileError as exc:
        raise RouteStateError("invalid owned route in route state") from exc
    if len(owned_routes) != len(raw_owned):
        raise RouteStateError("duplicate routes in route state owned_routes")
    return _RouteState(targets=targets, owned_routes=owned_routes)


def _dump_state(state: _RouteState) -> str:
    document = {
        "version": _STATE_VERSION,
        "targets": {
            target: {"routes": _sorted_routes(routes)}
            for target, routes in sorted(state.targets.items())
        },
        "owned_routes": _sorted_routes(state.owned_routes),
    }
    return json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def _route_from_line(line: str) -> str | None:
    candidate = line.strip()
    if not candidate or candidate.startswith("#"):
        return None
    try:
        return _canonical_exact_route(candidate)
    except RouteFileError:
        return None


def _routes_present(content: str) -> set[str]:
    return {route for line in content.splitlines() if (route := _route_from_line(line)) is not None}


def _remove_owned_line(content: str, route: str) -> tuple[str, bool]:
    lines = content.splitlines(keepends=True)
    for index, line in enumerate(lines):
        # Netprobe writes the canonical route with no surrounding whitespace.
        # Restrict removal to that exact representation; a manually reformatted
        # equivalent is deliberately preserved.
        if line.rstrip("\r\n") == route:
            del lines[index]
            return "".join(lines), True
    return content, False


def _detect_newline(content: str) -> str:
    first_lf = content.find("\n")
    if first_lf >= 1 and content[first_lf - 1] == "\r":
        return "\r\n"
    return "\n"


def _append_routes(content: str, routes: list[str]) -> str:
    if not routes:
        return content
    newline = _detect_newline(content)
    separator = "" if not content or content.endswith(("\n", "\r")) else newline
    return f"{content}{separator}{newline.join(routes)}{newline}"


class ManagedRouteFile:
    """Synchronize per-target exact routes without altering manual entries."""

    def __init__(self, route_file: str | os.PathLike[str]) -> None:
        self.route_file = Path(route_file)
        self.state_file = self.route_file.with_name(f"{self.route_file.name}.netprobe.json")
        # Common aliases make the sidecar location easy for callers to inspect.
        self.path = self.route_file
        self.state_path = self.state_file
        self._lock = _path_lock(self.route_file)
        self._validate_paths()

    def _validate_paths(self) -> None:
        _reject_symlink_components(self.route_file)
        _reject_symlink_components(self.state_file)
        for path in (self.route_file, self.state_file):
            try:
                metadata = os.lstat(path)
            except FileNotFoundError:
                continue
            if stat.S_ISLNK(metadata.st_mode):
                raise UnsafeRoutePathError(f"symlinks are not allowed: {path}")
            if not stat.S_ISREG(metadata.st_mode):
                raise UnsafeRoutePathError(f"path is not a regular file: {path}")

    def sync(self, target: str, routes: Iterable[str]) -> RouteSyncResult:
        """Make ``routes`` the desired exact routes for ``target``."""

        normalized_target = _validate_target(target)
        desired = _canonical_route_set(routes)
        return self._update(normalized_target, desired)

    def remove(self, target: str) -> RouteSyncResult:
        """Remove a target and any now-unreferenced routes owned by netprobe."""

        normalized_target = _validate_target(target)
        return self._update(normalized_target, None)

    def _update(self, target: str, desired: set[str] | None) -> RouteSyncResult:
        with self._lock:
            self._validate_paths()
            route_content = _read_regular_text(self.route_file, maximum_bytes=_MAX_ROUTE_FILE_BYTES)
            state_content = _read_regular_text(self.state_file, maximum_bytes=_MAX_STATE_FILE_BYTES)
            state = _load_state(state_content)

            if desired is None:
                if target not in state.targets:
                    return RouteSyncResult(target=target, routes=())
                del state.targets[target]
                result_routes: tuple[str, ...] = ()
            else:
                state.targets[target] = set(desired)
                result_routes = tuple(_sorted_routes(desired))

            content = route_content or ""
            referenced = {
                route for target_routes in state.targets.values() for route in target_routes
            }
            stale_owned = state.owned_routes - referenced
            removed: list[str] = []
            for route in _sorted_routes(stale_owned):
                content, did_remove = _remove_owned_line(content, route)
                if did_remove:
                    removed.append(route)
                state.owned_routes.discard(route)

            present = _routes_present(content)
            missing = _sorted_routes(referenced - present)
            if missing:
                content = _append_routes(content, missing)
                state.owned_routes.update(missing)

            new_state_content = _dump_state(state)
            if len(content.encode("utf-8")) > _MAX_ROUTE_FILE_BYTES:
                raise RouteFileError("updated route file would exceed its size limit")
            if len(new_state_content.encode("utf-8")) > _MAX_STATE_FILE_BYTES:
                raise RouteStateError("updated route state would exceed its size limit")
            if content != (route_content or ""):
                # Writing routes first is the fail-safe ordering: a crash before
                # the sidecar replace can leak an entry, but can never cause a
                # later run to mistake a manual entry for one it owns.
                _atomic_write_text(self.route_file, content)
            if new_state_content != state_content:
                _atomic_write_text(self.state_file, new_state_content)

            return RouteSyncResult(
                target=target,
                routes=result_routes,
                added=tuple(missing),
                removed=tuple(removed),
            )


__all__ = [
    "ManagedRouteFile",
    "RouteFileError",
    "RouteStateError",
    "RouteSyncResult",
    "UnsafeRoutePathError",
    "destination_networks",
]
