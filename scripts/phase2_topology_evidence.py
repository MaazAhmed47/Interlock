"""Strict schemas and validation for sanitized Phase 2 Docker topology evidence."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from pathlib import Path
from typing import Any

GATEWAY_OPTIONS = {
    "com.docker.network.bridge.gateway_mode_ipv4": "isolated",
    "com.docker.network.bridge.gateway_mode_ipv6": "isolated",
}
EXPECTED_NETWORK_OPTIONS = {
    "app_net": {
        **GATEWAY_OPTIONS,
        "com.docker.network.enable_ipv4": "true",
    },
    "denied_net": {"com.docker.network.enable_ipv4": "true"},
    "origin_net": {"com.docker.network.enable_ipv4": "true"},
}
EXPECTED_ATTACHMENTS = {
    "acceptance": ["app_net"],
    "certgen": [],
    "denied_sink": ["denied_net"],
    "dns": ["app_net"],
    "interlock": ["app_net"],
    "origin": ["origin_net"],
    "postgres": ["app_net"],
    "redis": ["app_net"],
    "squid": ["app_net", "denied_net", "origin_net"],
}
GATEWAY_METHODS = ("curl", "httpx", "requests", "socket", "urllib")
HOST_ALIASES = (
    "gateway.docker.internal",
    "host-gateway",
    "host.docker.internal",
)
TOPOLOGY_FILES = (
    "topology-addresses.json",
    "topology-attachments.json",
    "topology-containers.json",
    "topology-gateway-proof.json",
    "topology-host-bridge.json",
    "topology-neighbors-ipv4.json",
    "topology-neighbors-ipv6.json",
    "topology-networks.json",
    "topology-routes-ipv4.json",
    "topology-routes-ipv6.json",
    "topology-runtime-versions.json",
)

_PROJECT_NETWORK = re.compile(r"^interlock-p2-[a-f0-9]{12}[-_](app|origin|denied)_net$")
_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
_IMAGE_ID = re.compile(r"^sha256:[0-9a-f]{64}$")


def _reject(condition: bool, message: str) -> None:
    if condition:
        raise ValueError(message)


def _exact(value: Any, keys: set[str], message: str) -> dict[str, Any]:
    _reject(not isinstance(value, dict) or set(value) != keys, message)
    return value


def _load(path: Path, name: str) -> Any:
    return json.loads((path / name).read_text(encoding="utf-8"))


def parse_version(value: str) -> tuple[int, int, int]:
    match = re.search(r"(?:^|v)(\d+)\.(\d+)(?:\.(\d+))?", value)
    if match is None:
        raise ValueError("malformed runtime version")
    major, minor, patch = match.groups()
    return int(major), int(minor), int(patch or 0)


def source_bundle_sha256(root: Path, paths: list[Path]) -> str:
    """Hash source identities and bytes without ambiguous concatenation."""

    hasher = hashlib.sha256()
    for path in sorted(paths, key=lambda item: item.relative_to(root).as_posix()):
        relative = path.relative_to(root).as_posix().encode("utf-8")
        content = path.read_bytes()
        hasher.update(len(relative).to_bytes(4, "big"))
        hasher.update(relative)
        hasher.update(len(content).to_bytes(8, "big"))
        hasher.update(content)
    return hasher.hexdigest()


def _validate_routes(path: Path, name: str, family: int) -> list[dict[str, Any]]:
    document = _exact(
        _load(path, name),
        {"family", "routes", "schema"},
        "malformed route evidence",
    )
    _reject(
        document["schema"] != "interlock.phase2-topology-routes.v1",
        "wrong route schema",
    )
    _reject(document["family"] != family, "wrong route family")
    routes = document["routes"]
    _reject(not isinstance(routes, list) or not routes, "missing route table")
    _reject(any(not isinstance(item, dict) for item in routes), "malformed route entry")
    _reject(
        any(
            not isinstance(item.get("dev"), str)
            or not item.get("dev")
            or not isinstance(item.get("dst"), str)
            or not item.get("dst")
            for item in routes
        ),
        "incomplete route entry",
    )
    return routes


def validate_topology_evidence(evidence: Path) -> None:
    """Reject incomplete, stale-shaped, or non-isolated retained topology proof."""

    for name in TOPOLOGY_FILES:
        _reject(not (evidence / name).is_file(), "required topology artifact missing")

    versions = _exact(
        _load(evidence, "topology-runtime-versions.json"),
        {"compose", "docker_client", "docker_server", "schema"},
        "malformed runtime version evidence",
    )
    _reject(
        versions["schema"] != "interlock.phase2-topology-runtime.v1",
        "wrong runtime version schema",
    )
    for key in ("docker_client", "docker_server"):
        _exact(
            versions[key],
            {"api_version", "arch", "os", "version"},
            "malformed Docker version",
        )
    _reject(
        parse_version(versions["docker_server"]["version"]) < (28, 0, 0),
        "Docker Engine lacks isolated gateway mode",
    )
    _reject(
        parse_version(versions["compose"]) < (2, 33, 1),
        "Docker Compose version is unsupported",
    )
    _reject(versions["docker_server"]["os"] != "linux", "Docker server is not Linux")

    attachments = _exact(
        _load(evidence, "topology-attachments.json"),
        {"schema", "services"},
        "malformed attachment map",
    )
    _reject(
        attachments["schema"] != "interlock.phase2-topology-attachments.v1",
        "wrong attachment schema",
    )
    _reject(
        attachments["services"] != EXPECTED_ATTACHMENTS,
        "network attachment map mismatch",
    )

    containers = _exact(
        _load(evidence, "topology-containers.json"),
        {"containers", "schema"},
        "malformed container inspection evidence",
    )
    _reject(
        containers["schema"] != "interlock.phase2-topology-containers.v1",
        "wrong container schema",
    )
    entries = containers["containers"]
    _reject(not isinstance(entries, list), "container inspection list missing")
    by_service: dict[str, dict[str, Any]] = {}
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("service"), str):
            raise ValueError("malformed container inspection evidence")
        by_service[entry["service"]] = entry
    _reject(
        set(by_service) != set(EXPECTED_ATTACHMENTS),
        "owned container inventory mismatch",
    )
    _reject(len(entries) != len(by_service), "duplicate owned container evidence")
    for service, entry in by_service.items():
        _exact(
            entry,
            {
                "container_id",
                "extra_hosts_present",
                "health",
                "image_id",
                "network_mode",
                "networks",
                "published_ports",
                "service",
                "state",
            },
            "malformed container evidence",
        )
        _reject(
            entry["extra_hosts_present"] is not False, "extra_hosts retained in profile"
        )
        _reject(entry["published_ports"] != {}, "published port retained in profile")
        _reject(entry["network_mode"] == "host", "host networking retained in profile")
        _reject(
            not _HEX_64.fullmatch(str(entry["container_id"]))
            or not _IMAGE_ID.fullmatch(str(entry["image_id"])),
            "malformed container identity",
        )
        _reject(
            sorted(entry["networks"]) != EXPECTED_ATTACHMENTS[service],
            "container attachment mismatch",
        )
        for network in entry["networks"].values():
            _exact(
                network,
                {
                    "endpoint_id",
                    "gateway",
                    "global_ipv6_address",
                    "global_ipv6_prefix_len",
                    "ip_address",
                    "ip_prefix_len",
                    "ipv6_gateway",
                    "mac_address",
                    "network_id",
                },
                "malformed container network evidence",
            )
            _reject(
                not _HEX_64.fullmatch(str(network["endpoint_id"]))
                or not _HEX_64.fullmatch(str(network["network_id"])),
                "malformed container attachment identity",
            )
            try:
                ipv4 = ipaddress.ip_address(str(network["ip_address"]))
                ipv6 = ipaddress.ip_address(str(network["global_ipv6_address"]))
            except ValueError as exc:
                raise ValueError("malformed container attachment address") from exc
            _reject(
                ipv4.version != 4
                or ipv6.version != 6
                or network["ip_prefix_len"] != 24
                or network["global_ipv6_prefix_len"] != 64,
                "container dual-stack attachment evidence missing",
            )
    _reject(
        by_service["certgen"]["network_mode"] != "none",
        "cert generator is not networkless",
    )

    networks = _exact(
        _load(evidence, "topology-networks.json"),
        {"networks", "schema"},
        "malformed network inspection evidence",
    )
    _reject(
        networks["schema"] != "interlock.phase2-topology-networks.v1",
        "wrong network schema",
    )
    network_entries = networks["networks"]
    _reject(
        not isinstance(network_entries, list) or len(network_entries) != 3,
        "owned network inventory mismatch",
    )
    logical_networks: dict[str, dict[str, Any]] = {}
    for entry in network_entries:
        _exact(
            entry,
            {
                "attachable",
                "containers",
                "driver",
                "enable_ipv4",
                "enable_ipv6",
                "id",
                "ingress",
                "internal",
                "ipam_config",
                "ipam_driver",
                "name",
                "options",
                "scope",
            },
            "malformed network evidence",
        )
        match = _PROJECT_NETWORK.fullmatch(str(entry["name"]))
        if match is None:
            raise ValueError("unsafe network identity")
        logical = f"{match.group(1)}_net"
        _reject(logical in logical_networks, "duplicate logical network")
        logical_networks[logical] = entry
        _reject(
            entry["driver"] != "bridge" or entry["scope"] != "local",
            "unexpected network driver",
        )
        _reject(
            entry["attachable"] is not False
            or entry["ingress"] is not False
            or entry["ipam_driver"] != "default"
            or not _HEX_64.fullmatch(str(entry["id"])),
            "unexpected network settings",
        )
        _reject(
            entry["internal"] is not True
            or entry["enable_ipv4"] is not True
            or entry["enable_ipv6"] is not True,
            "network isolation or IPv6 disabled",
        )
        required_options = GATEWAY_OPTIONS if logical == "app_net" else {}
        allowed_options = {
            **required_options,
            "com.docker.network.enable_ipv4": "true",
        }
        _reject(
            any(
                entry["options"].get(key) != value
                for key, value in required_options.items()
            )
            or any(
                key not in allowed_options or allowed_options[key] != value
                for key, value in entry["options"].items()
            ),
            "unexpected effective network options",
        )
        configs = entry["ipam_config"]
        _reject(not isinstance(configs, list), "network IPAM evidence missing")
        try:
            families = {
                ipaddress.ip_network(str(config["subnet"]), strict=True).version
                for config in configs
            }
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError("malformed network IPAM evidence") from exc
        _reject(families != {4, 6}, "dual-stack network IPAM evidence missing")
    _reject(
        set(logical_networks) != {"app_net", "origin_net", "denied_net"},
        "logical network set mismatch",
    )
    app_network = logical_networks["app_net"]
    _reject(
        {key: app_network["options"].get(key) for key in GATEWAY_OPTIONS}
        != GATEWAY_OPTIONS,
        "effective app gateway mode is not isolated",
    )
    _reject(
        any(config.get("gateway") for config in app_network["ipam_config"]),
        "app network retained an IPAM gateway",
    )
    expected_network_services = {
        logical: sorted(
            service
            for service, attached in EXPECTED_ATTACHMENTS.items()
            if logical in attached
        )
        for logical in logical_networks
    }
    for logical, entry in logical_networks.items():
        network_containers = entry["containers"]
        _reject(
            not isinstance(network_containers, list), "network container map missing"
        )
        services = []
        for container in network_containers:
            _exact(
                container,
                {
                    "container_id",
                    "endpoint_id",
                    "ipv4_address",
                    "ipv6_address",
                    "mac_address",
                    "service",
                },
                "malformed network container evidence",
            )
            service = container["service"]
            if not isinstance(service, str):
                raise ValueError("malformed network container service")
            services.append(service)
            inspected = by_service.get(service)
            if inspected is None:
                raise ValueError("network references an unknown container")
            attachment = inspected["networks"].get(logical)
            if attachment is None:
                raise ValueError("container/network attachment disagreement")
            _reject(
                container["container_id"] != inspected["container_id"]
                or container["endpoint_id"] != attachment["endpoint_id"]
                or container["mac_address"] != attachment["mac_address"]
                or entry["id"] != attachment["network_id"]
                or container["ipv4_address"].split("/", 1)[0]
                != attachment["ip_address"]
                or container["ipv6_address"].split("/", 1)[0]
                != attachment["global_ipv6_address"],
                "container/network inspection evidence disagrees",
            )
        _reject(
            sorted(services) != expected_network_services[logical]
            or len(services) != len(set(services)),
            "network container attachment evidence mismatch",
        )
    for attachment in by_service["interlock"]["networks"].values():
        _reject(
            attachment["gateway"] != "" or attachment["ipv6_gateway"] != "",
            "Interlock retained a container gateway",
        )

    routes4 = _validate_routes(evidence, "topology-routes-ipv4.json", 4)
    routes6 = _validate_routes(evidence, "topology-routes-ipv6.json", 6)
    _reject(
        any(item.get("dst") == "default" for item in routes4 + routes6),
        "default route retained",
    )
    _reject(
        any(item.get("gateway") or item.get("via") for item in routes4 + routes6),
        "gateway route retained",
    )

    addresses = _exact(
        _load(evidence, "topology-addresses.json"),
        {"interfaces", "schema"},
        "malformed address evidence",
    )
    _reject(
        addresses["schema"] != "interlock.phase2-topology-addresses.v1",
        "wrong address schema",
    )
    _reject(
        not isinstance(addresses["interfaces"], list) or not addresses["interfaces"],
        "address table missing",
    )
    families = {
        address.get("family")
        for interface in addresses["interfaces"]
        for address in interface.get("addr_info", [])
        if interface.get("ifname") != "lo"
    }
    _reject(
        not {"inet", "inet6"}.issubset(families),
        "dual-stack application addresses missing",
    )
    observed_addresses = {
        address.get("local")
        for interface in addresses["interfaces"]
        for address in interface.get("addr_info", [])
        if interface.get("ifname") != "lo"
    }
    app_attachment = by_service["interlock"]["networks"]["app_net"]
    _reject(
        bool(
            {
                app_attachment["ip_address"],
                app_attachment["global_ipv6_address"],
            }
            - observed_addresses
        ),
        "application address and container inspection disagree",
    )

    for name, family in (
        ("topology-neighbors-ipv4.json", 4),
        ("topology-neighbors-ipv6.json", 6),
    ):
        neighbors = _exact(
            _load(evidence, name),
            {"family", "neighbors", "schema"},
            "malformed neighbor evidence",
        )
        _reject(
            neighbors["schema"] != "interlock.phase2-topology-neighbors.v1",
            "wrong neighbor schema",
        )
        _reject(
            neighbors["family"] != family
            or not isinstance(neighbors["neighbors"], list),
            "neighbor evidence missing",
        )

    host_bridge = _exact(
        _load(evidence, "topology-host-bridge.json"),
        {
            "interface",
            "interfaces",
            "network_id",
            "schema",
            "test_only_host_namespace_probe",
        },
        "malformed host bridge evidence",
    )
    _reject(
        host_bridge["schema"] != "interlock.phase2-topology-host-bridge.v1",
        "wrong host bridge schema",
    )
    _reject(
        host_bridge["test_only_host_namespace_probe"] is not True,
        "host bridge probe boundary missing",
    )
    _reject(
        not re.fullmatch(r"br-[0-9a-f]{12}", str(host_bridge["interface"])),
        "malformed bridge interface",
    )
    _reject(
        not _HEX_64.fullmatch(str(host_bridge["network_id"])),
        "malformed bridge network identity",
    )
    _reject(
        host_bridge["network_id"] != app_network["id"]
        or host_bridge["interface"] != "br-" + str(app_network["id"])[:12],
        "host bridge and app network identity disagree",
    )
    _reject(
        len(host_bridge["interfaces"]) != 1, "host bridge interface evidence missing"
    )
    _reject(
        host_bridge["interfaces"][0].get("ifname") != host_bridge["interface"],
        "host bridge identity mismatch",
    )
    _reject(
        bool(host_bridge["interfaces"][0].get("addr_info")),
        "host bridge retained an address",
    )

    gateway = _exact(
        _load(evidence, "topology-gateway-proof.json"),
        {
            "alias_resolution",
            "container_gateway_fields",
            "discovered_targets",
            "effective_gateway_modes",
            "host_bridge_addresses",
            "listener",
            "method_results",
            "method_summary",
            "network_ipam_gateways",
            "no_host_gateway_reachable",
            "positive_proxy_control_passed",
            "required_gateway_modes",
            "route_gateways",
            "schema",
            "statement",
        },
        "malformed gateway proof",
    )
    _reject(
        gateway["schema"] != "interlock.phase2-topology-gateway-proof.v1",
        "wrong gateway proof schema",
    )
    _reject(
        gateway["required_gateway_modes"] != GATEWAY_OPTIONS,
        "required gateway modes missing",
    )
    _reject(
        gateway["effective_gateway_modes"] != GATEWAY_OPTIONS,
        "effective gateway modes missing",
    )
    for key in (
        "network_ipam_gateways",
        "container_gateway_fields",
        "route_gateways",
        "host_bridge_addresses",
    ):
        _reject(gateway[key] != [], "gateway address remained present")
    _reject(
        gateway["no_host_gateway_reachable"] is not True,
        "host gateway reachability not denied",
    )
    _reject(
        gateway["positive_proxy_control_passed"] is not True,
        "positive proxy control missing",
    )
    _reject(
        gateway["statement"] != "no host gateway was reachable from Interlock",
        "gateway conclusion missing",
    )
    aliases = gateway["alias_resolution"]
    _reject(not isinstance(aliases, list), "host alias proof missing")
    alias_names = []
    expected_target_sources: dict[str, set[str]] = {}
    for alias in aliases:
        _exact(
            alias,
            {"addresses", "category", "hostname"},
            "malformed host alias proof",
        )
        _reject(
            not isinstance(alias["addresses"], list), "host alias addresses missing"
        )
        hostname = alias["hostname"]
        alias_names.append(hostname)
        for address in alias["addresses"]:
            try:
                ipaddress.ip_address(str(address).split("%", 1)[0])
            except ValueError as exc:
                raise ValueError("malformed host alias address") from exc
            expected_target_sources.setdefault(str(address), set()).add(
                f"dns_alias:{hostname}"
            )
    _reject(
        sorted(alias_names) != sorted(HOST_ALIASES)
        or len(alias_names) != len(set(alias_names)),
        "host alias proof is incomplete",
    )
    targets = gateway["discovered_targets"]
    _reject(not isinstance(targets, list), "gateway target inventory missing")
    raw_target_addresses = [
        target.get("address") for target in targets if isinstance(target, dict)
    ]
    _reject(
        len(raw_target_addresses) != len(targets)
        or any(not isinstance(address, str) for address in raw_target_addresses)
        or len(set(raw_target_addresses)) != len(targets),
        "duplicate gateway targets",
    )
    target_addresses: list[str] = [str(address) for address in raw_target_addresses]
    for address in target_addresses:
        try:
            ipaddress.ip_address(str(address).split("%", 1)[0])
        except ValueError as exc:
            raise ValueError("malformed gateway target") from exc
    for target in targets:
        _exact(
            target,
            {"address", "family", "sources"},
            "malformed gateway target",
        )
        _reject(
            target["family"] not in (4, 6)
            or not isinstance(target["sources"], list)
            or not target["sources"],
            "malformed gateway target metadata",
        )
        parsed = ipaddress.ip_address(str(target["address"]).split("%", 1)[0])
        _reject(
            target["family"] != parsed.version
            or set(target["sources"])
            != expected_target_sources.get(str(target["address"]), set()),
            "gateway target discovery evidence disagrees",
        )
    _reject(
        set(target_addresses) != set(expected_target_sources),
        "host alias targets are missing from gateway attempts",
    )
    summaries = gateway["method_summary"]
    _reject(set(summaries) != set(GATEWAY_METHODS), "gateway method summary incomplete")
    results = gateway["method_results"]
    _reject(not isinstance(results, list), "gateway method results missing")
    expected_pairs = {
        (method, address) for method in GATEWAY_METHODS for address in target_addresses
    }
    actual_pairs = {
        (item.get("method"), item.get("address"))
        for item in results
        if isinstance(item, dict)
    }
    _reject(
        actual_pairs != expected_pairs or len(results) != len(expected_pairs),
        "gateway attempts missing or duplicated",
    )
    _reject(
        any(item.get("connected") is not False for item in results),
        "host gateway bypass succeeded",
    )
    for item in results:
        _exact(
            item,
            {"address", "connected", "family", "method"},
            "malformed gateway attempt",
        )
    for method in GATEWAY_METHODS:
        summary = _exact(
            summaries[method],
            {"connected_count", "target_count"},
            "malformed gateway method summary",
        )
        _reject(
            summary["target_count"] != len(targets) or summary["connected_count"] != 0,
            "gateway method counter mismatch",
        )
    listener = _exact(
        gateway["listener"],
        {"bound_addresses", "failed_addresses", "started"},
        "malformed gateway listener evidence",
    )
    _reject(
        listener["started"] is not bool(targets), "gateway listener execution mismatch"
    )
    bound_addresses = listener["bound_addresses"]
    _reject(
        not isinstance(bound_addresses, list)
        or any(not isinstance(address, str) for address in bound_addresses),
        "malformed gateway listener addresses",
    )
    _reject(
        sorted(str(address) for address in bound_addresses) != sorted(target_addresses)
        or listener["failed_addresses"] != [],
        "gateway listener did not bind every discovered target",
    )
