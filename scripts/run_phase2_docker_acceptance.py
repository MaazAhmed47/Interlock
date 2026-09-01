"""Run the uniquely-owned Docker Phase 2 profile and retain exact evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import time
import uuid
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

try:
    from scripts.phase2_topology_evidence import (
        EXPECTED_ATTACHMENTS,
        GATEWAY_METHODS,
        GATEWAY_OPTIONS,
        TOPOLOGY_FILES,
        parse_version,
        source_bundle_sha256,
    )
except ModuleNotFoundError:  # direct script execution
    from phase2_topology_evidence import (  # type: ignore[no-redef]
        EXPECTED_ATTACHMENTS,
        GATEWAY_METHODS,
        GATEWAY_OPTIONS,
        TOPOLOGY_FILES,
        parse_version,
        source_bundle_sha256,
    )

ROOT = Path(__file__).resolve().parents[1]
PROFILE = ROOT / "deploy" / "phase2-docker"
COMPOSE = PROFILE / "compose.yaml"
SQUID_IMAGE = "ghcr.io/cybozu/squid:7.6.0.1@sha256:b5fff668ddbf5738a779ada37893569e6640d2a2ac384a834095ac443d12d60a"
SQUID_DIGEST = "sha256:b5fff668ddbf5738a779ada37893569e6640d2a2ac384a834095ac443d12d60a"
PROJECT_PREFIX = "interlock-p2-"
SAFE_PROJECT = re.compile(r"^interlock-p2-[a-f0-9]{12}$")
MINIMUM_DOCKER_ENGINE = (28, 0, 0)
MINIMUM_DOCKER_COMPOSE = (2, 33, 1)
ROUTE_FIELDS = {
    "dev",
    "dst",
    "expires",
    "flags",
    "gateway",
    "linkdown",
    "metric",
    "mtu",
    "nhid",
    "pref",
    "prefsrc",
    "protocol",
    "scope",
    "src",
    "table",
    "type",
    "via",
}
ADDRESS_FIELDS = {
    "address",
    "addr_info",
    "broadcast",
    "flags",
    "group",
    "ifindex",
    "ifname",
    "link_type",
    "mtu",
    "operstate",
    "qdisc",
}
ADDRESS_INFO_FIELDS = {
    "broadcast",
    "dynamic",
    "family",
    "label",
    "local",
    "nodad",
    "preferred_life_time",
    "prefixlen",
    "scope",
    "valid_life_time",
}
NEIGHBOR_FIELDS = {"dev", "dst", "flags", "lladdr", "router", "state"}

sys.path.insert(0, str(PROFILE))
from phase2_cases import REQUIRED_CASES  # noqa: E402


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def run(
    args: list[str],
    *,
    env: dict[str, str],
    check: bool = True,
    timeout: int = 1800,
) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        args,
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        check=False,
    )
    if check and completed.returncode:
        raise RuntimeError(
            f"command failed safely: {args[0]} exit {completed.returncode}"
        )
    return completed


def compose(project: str, *args: str) -> list[str]:
    return ["docker", "compose", "-p", project, "-f", str(COMPOSE), *args]


def parse_results(output: str) -> list[dict[str, str]]:
    results: list[dict[str, str]] = []
    for line in output.splitlines():
        try:
            candidate = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(candidate, dict) and set(candidate) == {
            "case",
            "category",
            "outcome",
        }:
            results.append({key: str(value) for key, value in candidate.items()})
    return results


def inspect_json(args: list[str], env: dict[str, str]) -> Any:
    return json.loads(run(args, env=env).stdout)


def write_json(path: Path, value: Any) -> None:
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def _selected(value: dict[str, Any], fields: set[str]) -> dict[str, Any]:
    return {key: value[key] for key in sorted(fields & set(value))}


def sanitize_routes(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not value:
        raise RuntimeError("route capture failed safely")
    if any(not isinstance(item, dict) for item in value):
        raise RuntimeError("route capture was malformed")
    return [_selected(item, ROUTE_FIELDS) for item in value]


def sanitize_addresses(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not value:
        raise RuntimeError("address capture failed safely")
    result = []
    for interface in value:
        if not isinstance(interface, dict):
            raise RuntimeError("address capture was malformed")
        selected = _selected(interface, ADDRESS_FIELDS)
        addresses = interface.get("addr_info", [])
        if not isinstance(addresses, list) or any(
            not isinstance(address, dict) for address in addresses
        ):
            raise RuntimeError("address capture was malformed")
        selected["addr_info"] = [
            _selected(address, ADDRESS_INFO_FIELDS) for address in addresses
        ]
        result.append(selected)
    return result


def sanitize_neighbors(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
        raise RuntimeError("neighbor capture was malformed")
    return [_selected(item, NEIGHBOR_FIELDS) for item in value]


def logical_network(name: str) -> str:
    for expected in ("app_net", "origin_net", "denied_net"):
        if name.endswith(("_" + expected, "-" + expected)):
            return expected
    raise RuntimeError("unexpected owned network identity")


def capture_container_evidence(
    project: str, env: dict[str, str]
) -> tuple[dict[str, Any], dict[str, list[str]], dict[str, Any]]:
    container_ids = run(compose(project, "ps", "-aq"), env=env).stdout.split()
    inspected = inspect_json(["docker", "inspect", *container_ids], env)
    containers = []
    attachments: dict[str, list[str]] = {}
    interlock: dict[str, Any] | None = None
    for item in inspected:
        service = (
            item.get("Config", {}).get("Labels", {}).get("com.docker.compose.service")
        )
        if service not in EXPECTED_ATTACHMENTS:
            raise RuntimeError("unexpected owned container")
        network_values = item.get("NetworkSettings", {}).get("Networks") or {}
        if service == "certgen":
            if set(network_values) - {"none"}:
                raise RuntimeError("networkless certificate generator was attached")
            network_values = {}
        networks = {
            logical_network(name): {
                "endpoint_id": value.get("EndpointID", ""),
                "gateway": value.get("Gateway", ""),
                "global_ipv6_address": value.get("GlobalIPv6Address", ""),
                "global_ipv6_prefix_len": value.get("GlobalIPv6PrefixLen", 0),
                "ip_address": value.get("IPAddress", ""),
                "ip_prefix_len": value.get("IPPrefixLen", 0),
                "ipv6_gateway": value.get("IPv6Gateway", ""),
                "mac_address": value.get("MacAddress", ""),
                "network_id": value.get("NetworkID", ""),
            }
            for name, value in network_values.items()
        }
        attachments[service] = sorted(networks)
        state = item.get("State", {})
        ports = {
            port: bindings
            for port, bindings in (
                item.get("NetworkSettings", {}).get("Ports") or {}
            ).items()
            if bindings
        }
        selected = {
            "container_id": item.get("Id", ""),
            "extra_hosts_present": bool(item.get("HostConfig", {}).get("ExtraHosts")),
            "health": (state.get("Health") or {}).get("Status", ""),
            "image_id": item.get("Image", ""),
            "network_mode": item.get("HostConfig", {}).get("NetworkMode", ""),
            "networks": networks,
            "published_ports": ports,
            "service": service,
            "state": state.get("Status", ""),
        }
        containers.append(selected)
        if service == "interlock":
            interlock = item
    if set(attachments) != set(EXPECTED_ATTACHMENTS) or interlock is None:
        raise RuntimeError("owned container evidence is incomplete")
    containers.sort(key=lambda item: item["service"])
    return (
        {
            "containers": containers,
            "schema": "interlock.phase2-topology-containers.v1",
        },
        attachments,
        interlock,
    )


def capture_network_evidence(
    project: str, env: dict[str, str]
) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    network_ids = run(
        [
            "docker",
            "network",
            "ls",
            "--filter",
            f"label=com.docker.compose.project={project}",
            "--format",
            "{{.ID}}",
        ],
        env=env,
    ).stdout.split()
    inspected = [
        inspect_json(["docker", "network", "inspect", network_id], env)[0]
        for network_id in network_ids
    ]
    networks = []
    by_logical: dict[str, dict[str, Any]] = {}
    allowed_options = set(GATEWAY_OPTIONS) | {"com.docker.network.enable_ipv4"}
    for item in inspected:
        name = str(item.get("Name", ""))
        logical = logical_network(name)
        raw_options = item.get("Options") or {}
        if set(raw_options) - allowed_options:
            raise RuntimeError("unexpected Docker network option")
        options = {
            key: value for key, value in raw_options.items() if key in allowed_options
        }
        ipam_config = [
            {
                key.lower(): value
                for key, value in config.items()
                if key in {"AuxiliaryAddresses", "Gateway", "IPRange", "Subnet"}
            }
            for config in item.get("IPAM", {}).get("Config", [])
        ]
        container_values = []
        for container_id, value in sorted((item.get("Containers") or {}).items()):
            container_name = str(value.get("Name", ""))
            prefix = project + "-"
            if not container_name.startswith(prefix) or not container_name.endswith(
                "-1"
            ):
                raise RuntimeError("unexpected owned container name")
            service = container_name[len(prefix) : -2]
            container_values.append(
                {
                    "container_id": container_id,
                    "endpoint_id": value.get("EndpointID", ""),
                    "ipv4_address": value.get("IPv4Address", ""),
                    "ipv6_address": value.get("IPv6Address", ""),
                    "mac_address": value.get("MacAddress", ""),
                    "service": service,
                }
            )
        selected = {
            "attachable": item.get("Attachable") is True,
            "containers": container_values,
            "driver": item.get("Driver", ""),
            "enable_ipv4": item.get("EnableIPv4") is True,
            "enable_ipv6": item.get("EnableIPv6") is True,
            "id": item.get("Id", ""),
            "ingress": item.get("Ingress") is True,
            "internal": item.get("Internal") is True,
            "ipam_config": ipam_config,
            "ipam_driver": item.get("IPAM", {}).get("Driver", ""),
            "name": name,
            "options": options,
            "scope": item.get("Scope", ""),
        }
        networks.append(selected)
        by_logical[logical] = selected
    if set(by_logical) != {"app_net", "origin_net", "denied_net"}:
        raise RuntimeError("owned network evidence is incomplete")
    networks.sort(key=lambda item: item["name"])
    return (
        {"networks": networks, "schema": "interlock.phase2-topology-networks.v1"},
        by_logical,
    )


def interlock_json(
    project: str, env: dict[str, str], *command: str, check: bool = True
) -> Any:
    completed = run(
        compose(project, "exec", "-T", "interlock", *command),
        env=env,
        check=check,
    )
    if not completed.stdout.strip():
        return []
    return json.loads(completed.stdout)


def _gateway_values(routes: list[dict[str, Any]]) -> list[str]:
    values = set()
    for route in routes:
        for key in ("gateway", "via"):
            value = route.get(key)
            if isinstance(value, str) and value:
                values.add(value)
            elif isinstance(value, dict) and value.get("addr"):
                values.add(str(value["addr"]))
    return sorted(values)


def capture_topology(
    project: str,
    env: dict[str, str],
    docker_version: dict[str, Any],
    compose_version: str,
) -> tuple[dict[str, Any], list[dict[str, str]]]:
    containers, attachments, interlock_inspect = capture_container_evidence(
        project, env
    )
    networks, by_logical = capture_network_evidence(project, env)
    app_network = by_logical["app_net"]

    routes4 = sanitize_routes(
        interlock_json(project, env, "ip", "-j", "-4", "route", "show", "table", "all")
    )
    routes6 = sanitize_routes(
        interlock_json(project, env, "ip", "-j", "-6", "route", "show", "table", "all")
    )
    addresses = sanitize_addresses(
        interlock_json(project, env, "ip", "-j", "address", "show")
    )
    neighbors4 = sanitize_neighbors(
        interlock_json(project, env, "ip", "-j", "-4", "neighbor", "show")
    )
    neighbors6 = sanitize_neighbors(
        interlock_json(project, env, "ip", "-j", "-6", "neighbor", "show")
    )

    bridge_interface = "br-" + str(app_network["id"])[:12]
    image = f"interlock-phase2-reference:{env['INTERLOCK_SOURCE_SHA']}"
    host_probe_name = f"{project}-host-inspector"
    host_probe = run(
        [
            "docker",
            "run",
            "--rm",
            "--name",
            host_probe_name,
            "--network",
            "host",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            image,
            "python",
            "/app/deploy/phase2-docker/topology_probe.py",
            "host-bridge",
            "--interface",
            bridge_interface,
        ],
        env=env,
    )
    host_interfaces = sanitize_addresses(json.loads(host_probe.stdout))

    alias_document = interlock_json(
        project,
        env,
        "python",
        "/app/deploy/phase2-docker/topology_probe.py",
        "discover",
    )
    if (
        not isinstance(alias_document, dict)
        or alias_document.get("schema") != "interlock.phase2-topology-aliases.v1"
        or not isinstance(alias_document.get("aliases"), list)
    ):
        raise RuntimeError("host alias discovery failed safely")

    app_container_networks = interlock_inspect["NetworkSettings"]["Networks"]
    container_gateways = sorted(
        {
            value
            for network in app_container_networks.values()
            for value in (network.get("Gateway"), network.get("IPv6Gateway"))
            if value
        }
    )
    ipam_gateways = sorted(
        {
            str(config["gateway"])
            for config in app_network["ipam_config"]
            if config.get("gateway")
        }
    )
    route_gateways = sorted(set(_gateway_values(routes4 + routes6)))
    host_bridge_addresses = sorted(
        {
            str(address["local"])
            for interface in host_interfaces
            for address in interface.get("addr_info", [])
            if address.get("local")
        }
    )
    sources: dict[str, set[str]] = {}

    def add_targets(values: list[str], source: str) -> None:
        for value in values:
            sources.setdefault(value, set()).add(source)

    add_targets(ipam_gateways, "network_ipam")
    add_targets(container_gateways, "container_inspect")
    add_targets(route_gateways, "route_table")
    add_targets(host_bridge_addresses, "host_bridge")
    for alias in alias_document["aliases"]:
        if not isinstance(alias, dict):
            raise RuntimeError("host alias discovery was malformed")
        hostname = str(alias.get("hostname", ""))
        values = alias.get("addresses")
        if not isinstance(values, list):
            raise RuntimeError("host alias discovery was malformed")
        add_targets([str(value) for value in values], f"dns_alias:{hostname}")

    targets = sorted(sources)
    listener_name: str | None = None
    listener = {
        "bound_addresses": [],
        "failed_addresses": [],
        "started": bool(targets),
    }
    try:
        if targets:
            listener_name = f"{project}-gateway-listener"
            listener_command = [
                "docker",
                "run",
                "-d",
                "--name",
                listener_name,
                "--network",
                "host",
                "--read-only",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges",
                image,
                "python",
                "/app/deploy/phase2-docker/host_gateway_listener.py",
            ]
            for target in targets:
                listener_command.extend(("--address", target))
            run(listener_command, env=env)
            listener_output = ""
            for _attempt in range(30):
                listener_output = run(
                    ["docker", "logs", listener_name], env=env, check=False
                ).stdout.strip()
                if listener_output:
                    break
                time.sleep(0.1)
            try:
                listener_result = json.loads(listener_output.splitlines()[0])
            except (json.JSONDecodeError, IndexError) as exc:
                raise RuntimeError("gateway listener failed safely") from exc
            if (
                listener_result.get("schema")
                != "interlock.phase2-host-gateway-listener.v1"
            ):
                raise RuntimeError("gateway listener returned malformed evidence")
            bound_addresses = listener_result.get("bound_addresses")
            failed_addresses = listener_result.get("failed_addresses")
            if (
                not isinstance(bound_addresses, list)
                or any(not isinstance(address, str) for address in bound_addresses)
                or not isinstance(failed_addresses, list)
            ):
                raise RuntimeError("gateway listener returned malformed evidence")
            bound_address_list = [str(address) for address in bound_addresses]
            listener = {
                "bound_addresses": bound_address_list,
                "failed_addresses": failed_addresses,
                "started": True,
            }
            if sorted(bound_address_list) != targets or failed_addresses != []:
                raise RuntimeError(
                    "gateway listener did not bind every discovered target"
                )

        attempt_command = [
            "python",
            "/app/deploy/phase2-docker/topology_probe.py",
            "attempt",
        ]
        for target in targets:
            attempt_command.extend(("--target", target))
        attempt_document = interlock_json(project, env, *attempt_command)
    finally:
        if listener_name is not None:
            run(
                ["docker", "rm", "-f", listener_name],
                env=env,
                check=False,
            )
    if (
        not isinstance(attempt_document, dict)
        or attempt_document.get("schema") != "interlock.phase2-topology-attempts.v1"
        or not isinstance(attempt_document.get("results"), list)
    ):
        raise RuntimeError("gateway attempts failed safely")
    method_results = attempt_document["results"]
    method_summary = {
        method: {
            "connected_count": sum(
                item.get("method") == method and item.get("connected") is True
                for item in method_results
            ),
            "target_count": len(targets),
        }
        for method in GATEWAY_METHODS
    }
    no_core_gateway = not (
        ipam_gateways or container_gateways or route_gateways or host_bridge_addresses
    )
    no_connection = not any(item.get("connected") is True for item in method_results)
    effective_modes = {
        key: app_network["options"].get(key, "") for key in GATEWAY_OPTIONS
    }
    gateway_proof = {
        "alias_resolution": alias_document["aliases"],
        "container_gateway_fields": container_gateways,
        "discovered_targets": [
            {
                "address": target,
                "family": 6 if ":" in target else 4,
                "sources": sorted(sources[target]),
            }
            for target in targets
        ],
        "effective_gateway_modes": effective_modes,
        "host_bridge_addresses": host_bridge_addresses,
        "listener": listener,
        "method_results": method_results,
        "method_summary": method_summary,
        "network_ipam_gateways": ipam_gateways,
        "no_host_gateway_reachable": no_core_gateway and no_connection,
        "positive_proxy_control_passed": False,
        "required_gateway_modes": GATEWAY_OPTIONS,
        "route_gateways": route_gateways,
        "schema": "interlock.phase2-topology-gateway-proof.v1",
        "statement": (
            "no host gateway was reachable from Interlock"
            if no_core_gateway and no_connection
            else "host gateway isolation failed"
        ),
    }
    topology = {
        "topology-addresses.json": {
            "interfaces": addresses,
            "schema": "interlock.phase2-topology-addresses.v1",
        },
        "topology-attachments.json": {
            "schema": "interlock.phase2-topology-attachments.v1",
            "services": attachments,
        },
        "topology-containers.json": containers,
        "topology-gateway-proof.json": gateway_proof,
        "topology-host-bridge.json": {
            "interface": bridge_interface,
            "interfaces": host_interfaces,
            "network_id": app_network["id"],
            "schema": "interlock.phase2-topology-host-bridge.v1",
            "test_only_host_namespace_probe": True,
        },
        "topology-neighbors-ipv4.json": {
            "family": 4,
            "neighbors": neighbors4,
            "schema": "interlock.phase2-topology-neighbors.v1",
        },
        "topology-neighbors-ipv6.json": {
            "family": 6,
            "neighbors": neighbors6,
            "schema": "interlock.phase2-topology-neighbors.v1",
        },
        "topology-networks.json": networks,
        "topology-routes-ipv4.json": {
            "family": 4,
            "routes": routes4,
            "schema": "interlock.phase2-topology-routes.v1",
        },
        "topology-routes-ipv6.json": {
            "family": 6,
            "routes": routes6,
            "schema": "interlock.phase2-topology-routes.v1",
        },
        "topology-runtime-versions.json": {
            "compose": compose_version,
            "docker_client": {
                "api_version": docker_version.get("Client", {}).get("ApiVersion", ""),
                "arch": docker_version.get("Client", {}).get("Arch", ""),
                "os": docker_version.get("Client", {}).get("Os", ""),
                "version": docker_version.get("Client", {}).get("Version", ""),
            },
            "docker_server": {
                "api_version": docker_version.get("Server", {}).get("ApiVersion", ""),
                "arch": docker_version.get("Server", {}).get("Arch", ""),
                "os": docker_version.get("Server", {}).get("Os", ""),
                "version": docker_version.get("Server", {}).get("Version", ""),
            },
            "schema": "interlock.phase2-topology-runtime.v1",
        },
    }
    if set(topology) != set(TOPOLOGY_FILES):
        raise RuntimeError("topology artifact contract is incomplete")
    topology_results = [
        {
            "case": "topology_docker_engine_gateway_mode_supported",
            "category": "",
            "outcome": (
                "passed"
                if parse_version(docker_version["Server"]["Version"])
                >= MINIMUM_DOCKER_ENGINE
                else "failed"
            ),
        },
        {
            "case": "topology_compose_gateway_mode_supported",
            "category": "",
            "outcome": (
                "passed"
                if parse_version(compose_version) >= MINIMUM_DOCKER_COMPOSE
                else "failed"
            ),
        },
    ]
    checks = {
        "topology_app_gateway_mode_ipv4_isolated": effective_modes.get(
            "com.docker.network.bridge.gateway_mode_ipv4"
        )
        == "isolated",
        "topology_app_gateway_mode_ipv6_isolated": effective_modes.get(
            "com.docker.network.bridge.gateway_mode_ipv6"
        )
        == "isolated",
        "topology_app_ipam_gateway_ipv4_absent": not any(
            ":" not in value for value in ipam_gateways
        ),
        "topology_app_ipam_gateway_ipv6_absent": not any(
            ":" in value for value in ipam_gateways
        ),
        "topology_interlock_gateway_fields_empty": not container_gateways,
        "topology_host_bridge_addresses_absent": not host_bridge_addresses,
        "topology_route_gateways_absent": not route_gateways,
        "topology_host_aliases_unreachable": no_connection,
        "topology_host_gateway_no_bypass": no_core_gateway and no_connection,
    }
    for name, passed in checks.items():
        topology_results.append(
            {
                "case": name,
                "category": "" if passed else "gateway_isolation",
                "outcome": "passed" if passed else "failed",
            }
        )
    for method in GATEWAY_METHODS:
        passed = method_summary[method]["connected_count"] == 0
        topology_results.append(
            {
                "case": f"direct_host_gateway_{method}_denied",
                "category": "" if passed else "gateway_bypass",
                "outcome": "passed" if passed else "failed",
            }
        )
    return topology, topology_results


def case(
    results: list[dict[str, str]], name: str, passed: bool, category: str = ""
) -> None:
    results.append(
        {
            "case": name,
            "category": category[:80],
            "outcome": "passed" if passed else "failed",
        }
    )


def write_junit(path: Path, results: list[dict[str, str]]) -> None:
    failures = sum(result["outcome"] != "passed" for result in results)
    suite = ET.Element(
        "testsuite",
        name="phase2_docker_acceptance",
        tests=str(len(results)),
        failures=str(failures),
        errors="0",
        skipped="0",
    )
    for result in results:
        item = ET.SubElement(
            suite, "testcase", classname="phase2.docker", name=result["case"]
        )
        if result["outcome"] != "passed":
            failure = ET.SubElement(
                item, "failure", message=result["category"] or "failed"
            )
            failure.text = "Phase 2 case failed; consult bounded category only."
    ET.ElementTree(suite).write(path, encoding="utf-8", xml_declaration=True)


def clean_text(value: str) -> str:
    lines = []
    for line in value.splitlines():
        if any(
            marker in line.lower()
            for marker in ("authorization:", "proxy-authorization:", "?")
        ):
            continue
        lines.append(line[:1000])
    return "\n".join(lines) + ("\n" if lines else "")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--allow-dirty-development-run", action="store_true")
    options = parser.parse_args()
    source_sha = options.source_sha.lower()
    if not re.fullmatch(r"[0-9a-f]{40}", source_sha):
        raise SystemExit("source SHA must be forty lowercase hexadecimal characters")
    head = run(["git", "rev-parse", "HEAD"], env=os.environ.copy()).stdout.strip()
    if head != source_sha:
        raise SystemExit("source SHA does not equal HEAD")
    dirty = bool(
        run(["git", "status", "--porcelain=v1"], env=os.environ.copy()).stdout.strip()
    )
    if dirty and not options.allow_dirty_development_run:
        raise SystemExit("final evidence requires a clean source worktree")
    output = options.output.resolve()
    if output.exists():
        raise SystemExit("evidence output must not already exist")
    output.mkdir(parents=True)
    project = PROJECT_PREFIX + uuid.uuid4().hex[:12]
    if not SAFE_PROJECT.fullmatch(project):
        raise SystemExit("unsafe generated Compose project name")
    env = os.environ.copy()
    env["INTERLOCK_SOURCE_SHA"] = source_sha
    sentinels = {
        "query": "p2q_" + uuid.uuid4().hex,
        "authorization": "p2a_" + uuid.uuid4().hex,
        "proxy_credential": "p2c_" + uuid.uuid4().hex,
    }
    sentinel_exec = [
        "-e",
        f"PHASE2_QUERY_SENTINEL={sentinels['query']}",
        "-e",
        f"PHASE2_AUTHORIZATION_SENTINEL={sentinels['authorization']}",
        "-e",
        f"PHASE2_PROXY_CREDENTIAL_SENTINEL={sentinels['proxy_credential']}",
    ]
    results: list[dict[str, str]] = []
    compose_rendered = ""
    docker_version: dict[str, Any] = {}
    compose_version = ""
    logs: dict[str, str] = {}
    topology_documents: dict[str, Any] = {}
    started = time.time()
    try:
        docker_version = json.loads(
            run(["docker", "version", "--format", "{{json .}}"], env=env).stdout
        )
        compose_version = run(
            ["docker", "compose", "version", "--short"], env=env
        ).stdout.strip()
        if (
            parse_version(str(docker_version.get("Server", {}).get("Version", "")))
            < MINIMUM_DOCKER_ENGINE
        ):
            raise RuntimeError("Docker Engine does not support isolated gateway mode")
        if parse_version(compose_version) < MINIMUM_DOCKER_COMPOSE:
            raise RuntimeError("Docker Compose version is unsupported")
        compose_rendered = run(
            compose(project, "config", "--format", "json"), env=env
        ).stdout
        rendered = json.loads(compose_rendered)
        rendered_app = rendered.get("networks", {}).get("app_net", {})
        if rendered_app.get("driver_opts") != GATEWAY_OPTIONS:
            raise RuntimeError("rendered Compose lost isolated gateway mode")
        run(compose(project, "build", "--pull"), env=env, timeout=3600)
        run(
            compose(
                project, "pull", "--policy", "always", "postgres", "redis", "squid"
            ),
            env=env,
            timeout=1800,
        )
        run(
            compose(project, "up", "-d", "--wait", "--wait-timeout", "180"),
            env=env,
            timeout=600,
        )

        good_parse = run(
            compose(
                project,
                "exec",
                "-T",
                "squid",
                "squid",
                "-k",
                "parse",
                "-f",
                "/etc/squid/squid.conf",
            ),
            env=env,
            check=False,
        )
        bad_parse = run(
            compose(
                project,
                "exec",
                "-T",
                "squid",
                "squid",
                "-k",
                "parse",
                "-f",
                "/etc/squid/invalid-squid.conf",
            ),
            env=env,
            check=False,
        )
        case(results, "squid_policy_parses", good_parse.returncode == 0)
        malformed_policy_rejected = bad_parse.returncode != 0

        policy_text = (PROFILE / "squid.conf").read_text(encoding="utf-8").lower()
        case(
            results,
            "squid_no_tls_interception",
            "ssl_bump" not in policy_text and "https_port" not in policy_text,
        )
        case(results, "squid_via_enabled", "via off" not in policy_text)

        interlock_id = run(
            compose(project, "ps", "-q", "interlock"), env=env
        ).stdout.strip()
        squid_id = run(compose(project, "ps", "-q", "squid"), env=env).stdout.strip()
        interlock_inspect = inspect_json(["docker", "inspect", interlock_id], env)[0]
        squid_inspect = inspect_json(["docker", "inspect", squid_id], env)[0]
        interlock_networks = sorted(interlock_inspect["NetworkSettings"]["Networks"])
        squid_networks = sorted(squid_inspect["NetworkSettings"]["Networks"])
        case(
            results,
            "topology_interlock_app_network_only",
            len(interlock_networks) == 1 and interlock_networks[0].endswith("_app_net"),
        )
        case(
            results,
            "topology_proxy_only_upstream_bridge",
            len(squid_networks) == 3
            and any(name.endswith("_origin_net") for name in squid_networks)
            and any(name.endswith("_denied_net") for name in squid_networks),
        )
        network_ids = run(
            [
                "docker",
                "network",
                "ls",
                "--filter",
                f"label=com.docker.compose.project={project}",
                "--format",
                "{{.ID}}",
            ],
            env=env,
        ).stdout.split()
        network_data = [
            inspect_json(["docker", "network", "inspect", network_id], env)[0]
            for network_id in network_ids
        ]
        case(
            results,
            "topology_ipv6_enabled_all_networks",
            len(network_data) == 3
            and all(item.get("EnableIPv6") is True for item in network_data),
        )

        image_data = inspect_json(["docker", "image", "inspect", SQUID_IMAGE], env)[0]
        repo_digests = image_data.get("RepoDigests") or []
        case(
            results,
            "squid_image_digest_exact",
            any(value.endswith("@" + SQUID_DIGEST) for value in repo_digests),
        )

        topology_documents, topology_results = capture_topology(
            project, env, docker_version, compose_version
        )
        results.extend(topology_results)

        direct = run(
            compose(
                project,
                "exec",
                "-T",
                *sentinel_exec,
                "-e",
                "PHASE2_CA_FILE=/tmp/not-used",
                "interlock",
                "python",
                "/app/deploy/phase2-docker/acceptance.py",
                "direct-only",
            ),
            env=env,
            check=False,
        )
        results.extend(parse_results(direct.stdout))

        acceptance = run(
            compose(
                project,
                "exec",
                "-T",
                *sentinel_exec,
                "acceptance",
                "python",
                "/app/deploy/phase2-docker/acceptance.py",
            ),
            env=env,
            check=False,
            timeout=900,
        )
        results.extend(parse_results(acceptance.stdout))

        run(compose(project, "stop", "squid"), env=env)
        proxy_down = run(
            compose(
                project,
                "exec",
                "-T",
                *sentinel_exec,
                "acceptance",
                "python",
                "/app/deploy/phase2-docker/acceptance.py",
                "proxy-down",
            ),
            env=env,
            check=False,
        )
        proxy_down_results = parse_results(proxy_down.stdout)
        results.extend(proxy_down_results)
        case(
            results,
            "squid_malformed_policy_rejected",
            malformed_policy_rejected
            and any(
                item["case"] == "proxy_unavailable_no_fallback"
                and item["outcome"] == "passed"
                for item in proxy_down_results
            ),
        )
        run(compose(project, "start", "squid"), env=env)

        for service in ("origin", "denied_sink", "dns", "squid", "interlock"):
            raw = run(
                compose(project, "logs", "--no-color", service), env=env, check=False
            ).stdout
            raw_lower = raw.lower()
            if any(value.lower() in raw_lower for value in sentinels.values()):
                raise RuntimeError("raw service log disclosed a run sentinel")
            if (
                "proxy-authorization:" in raw_lower
                or "authorization: bearer" in raw_lower
            ):
                raise RuntimeError("raw service log disclosed an authorization field")
            logs[service] = clean_text(raw)
            (output / f"{service}.log").write_text(
                logs[service], encoding="utf-8", newline="\n"
            )
        case(
            results,
            "denied_sink_zero_requests",
            "denied_connection" not in logs["denied_sink"],
        )
        case(
            results,
            "origin_safe_log_fields_only",
            all(
                term not in logs["origin"].lower()
                for term in ("query", 'authorization": "', "body")
            ),
        )
        case(
            results,
            "wrong_hostname_origin_zero_http_requests",
            '"route": "/wrong-host-proof"' not in logs["origin"],
        )
        case(
            results,
            "untrusted_ca_origin_zero_http_requests",
            '"route": "/untrusted-ca-proof"' not in logs["origin"],
        )
        case(
            results,
            "proxy_safe_log_fields_only",
            all(
                term not in logs["squid"].lower()
                for term in ("http://", "https://", "authorization", "?")
            ),
        )

        combined_logs = "\n".join(logs.values()).lower()
        case(
            results,
            "retained_logs_sentinel_free",
            not any(value.lower() in combined_logs for value in sentinels.values()),
        )
        case(results, "junit_sentinel_free", True)
        case(results, "manifest_sentinel_free", True)

        positive_proxy_control = all(
            any(
                item["case"] == required and item["outcome"] == "passed"
                for item in results
            )
            for required in (
                "allowed_http_through_proxy",
                "allowed_https_connect_through_proxy",
                "positive_origin_not_block_all_control",
            )
        )
        topology_documents["topology-gateway-proof.json"][
            "positive_proxy_control_passed"
        ] = positive_proxy_control
        for name, document in topology_documents.items():
            write_json(output / name, document)
        case(
            results,
            "topology_retained_evidence_complete",
            set(TOPOLOGY_FILES).issubset(
                {path.name for path in output.iterdir() if path.is_file()}
            ),
        )

        names = [item["case"] for item in results]
        unexpected = sorted(set(names) - set(REQUIRED_CASES))
        missing = sorted(set(REQUIRED_CASES) - set(names))
        duplicates = sorted({name for name in names if names.count(name) != 1})
        if unexpected or missing or duplicates:
            raise RuntimeError(
                "case contract mismatch: "
                f"missing={missing!r} unexpected={unexpected!r} duplicates={duplicates!r}"
            )
        results.sort(key=lambda item: REQUIRED_CASES.index(item["case"]))
        result_path = output / "results.jsonl"
        result_path.write_text(
            "".join(json.dumps(item, sort_keys=True) + "\n" for item in results),
            encoding="utf-8",
            newline="\n",
        )
        junit_path = output / "junit.xml"
        write_junit(junit_path, results)
        artifact_hashes = {
            path.name: sha256_file(path)
            for path in sorted(output.iterdir())
            if path.is_file() and path.name != "manifest.json"
        }
        test_sources = [
            PROFILE / name
            for name in (
                "Dockerfile",
                "acceptance.py",
                "certgen.py",
                "denied_sink.py",
                "dns_server.py",
                "healthcheck.py",
                "host_gateway_listener.py",
                "invalid-squid.conf",
                "origin.py",
                "phase2_cases.py",
                "topology_probe.py",
            )
        ] + [
            Path(__file__).resolve(),
            ROOT / "scripts" / "phase2_topology_evidence.py",
            ROOT / "scripts" / "verify_phase2_docker_evidence.py",
        ]
        test_source_hash = source_bundle_sha256(ROOT, test_sources)
        manifest = {
            "schema": "interlock.phase2-docker-evidence.v2",
            "source_sha": source_sha,
            "source_dirty_development_run": dirty,
            "squid_image": SQUID_IMAGE,
            "squid_image_digest": SQUID_DIGEST,
            "squid_policy_sha256": sha256_file(PROFILE / "squid.conf"),
            "squid_allowed_domains_sha256": sha256_file(
                PROFILE / "allowed-domains.txt"
            ),
            "squid_policy_bundle_sha256": sha256_bytes(
                (PROFILE / "squid.conf").read_bytes()
                + (PROFILE / "allowed-domains.txt").read_bytes()
            ),
            "compose_source_sha256": sha256_file(COMPOSE),
            "compose_rendered_sha256": sha256_bytes(compose_rendered.encode("utf-8")),
            "test_source_sha256": test_source_hash,
            "docker_client_version": docker_version.get("Client", {}).get("Version"),
            "docker_server_version": docker_version.get("Server", {}).get("Version"),
            "docker_server_os": docker_version.get("Server", {}).get("Os"),
            "compose_version": compose_version,
            "compose_project_name": project,
            "project_name_hash": sha256_bytes(project.encode("ascii")),
            "expected_case_count": len(REQUIRED_CASES),
            "executed_case_count": len(results),
            "passed_case_count": sum(item["outcome"] == "passed" for item in results),
            "failed_case_count": sum(item["outcome"] != "passed" for item in results),
            "required_cases": list(REQUIRED_CASES),
            "results_sha256": sha256_file(result_path),
            "artifact_sha256": artifact_hashes,
            "topology_artifact_sha256": {
                name: artifact_hashes[name] for name in TOPOLOGY_FILES
            },
            "sentinel_sha256": {
                "authorization_header": sha256_bytes(
                    sentinels["authorization"].encode("ascii")
                ),
                "proxy_header": sha256_bytes(
                    sentinels["proxy_credential"].encode("ascii")
                ),
                "url_query": sha256_bytes(sentinels["query"].encode("ascii")),
            },
            "duration_seconds": round(time.time() - started, 3),
        }
        (output / "manifest.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        retained = b"\n".join(
            path.read_bytes() for path in output.iterdir() if path.is_file()
        )
        if any(value.encode("ascii") in retained for value in sentinels.values()):
            raise RuntimeError("retained Phase 2 evidence disclosed a run sentinel")
    finally:
        if SAFE_PROJECT.fullmatch(project):
            run(
                compose(
                    project, "down", "--volumes", "--remove-orphans", "--timeout", "10"
                ),
                env=env,
                check=False,
                timeout=180,
            )
    verifier = run(
        [
            sys.executable,
            str(ROOT / "scripts" / "verify_phase2_docker_evidence.py"),
            str(output),
        ],
        env=env,
        check=False,
    )
    sys.stdout.write(verifier.stdout)
    sys.stderr.write(verifier.stderr)
    return verifier.returncode


if __name__ == "__main__":
    raise SystemExit(main())
