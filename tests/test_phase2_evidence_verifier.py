from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from scripts import verify_phase2_docker_evidence as verifier
from scripts.phase2_topology_evidence import (
    EXPECTED_ATTACHMENTS,
    EXPECTED_NETWORK_OPTIONS,
    GATEWAY_METHODS,
    GATEWAY_OPTIONS,
    HOST_ALIASES,
    TOPOLOGY_FILES,
)

PROFILE = Path(__file__).resolve().parents[1] / "deploy" / "phase2-docker"
sys.path.insert(0, str(PROFILE))
from phase2_cases import REQUIRED_CASES  # noqa: E402


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _topology_documents() -> dict[str, object]:
    project = "interlock-p2-123456789abc"
    network_ids = {
        "app_net": "a" * 64,
        "origin_net": "b" * 64,
        "denied_net": "c" * 64,
    }
    containers = []
    for index, (service, networks) in enumerate(EXPECTED_ATTACHMENTS.items(), start=1):
        containers.append(
            {
                "container_id": f"{index:064x}",
                "extra_hosts_present": False,
                "health": "healthy" if service != "certgen" else "",
                "image_id": "sha256:" + f"{index + 20:064x}",
                "network_mode": (
                    "none" if service == "certgen" else f"{project}_app_net"
                ),
                "networks": {
                    network: {
                        "endpoint_id": f"{index + 40:064x}",
                        "gateway": "",
                        "global_ipv6_address": "fd00:1:2:3::10",
                        "global_ipv6_prefix_len": 64,
                        "ip_address": "172.31.250.10",
                        "ip_prefix_len": 24,
                        "ipv6_gateway": "",
                        "mac_address": "02:42:ac:1f:fa:0a",
                        "network_id": network_ids[network],
                    }
                    for network in networks
                },
                "published_ports": {},
                "service": service,
                "state": "exited" if service == "certgen" else "running",
            }
        )
    network_documents = []
    for logical in ("app_net", "origin_net", "denied_net"):
        options = dict(EXPECTED_NETWORK_OPTIONS[logical])
        attached_services = [
            (index, service)
            for index, (service, networks) in enumerate(
                EXPECTED_ATTACHMENTS.items(), start=1
            )
            if logical in networks
        ]
        network_documents.append(
            {
                "attachable": False,
                "containers": [
                    {
                        "container_id": f"{index:064x}",
                        "endpoint_id": f"{index + 40:064x}",
                        "ipv4_address": "172.31.250.10/24",
                        "ipv6_address": "fd00:1:2:3::10/64",
                        "mac_address": "02:42:ac:1f:fa:0a",
                        "service": service,
                    }
                    for index, service in attached_services
                ],
                "driver": "bridge",
                "enable_ipv4": True,
                "enable_ipv6": True,
                "id": network_ids[logical],
                "ingress": False,
                "internal": True,
                "ipam_config": [
                    {"subnet": "172.31.250.0/24"},
                    {"subnet": "fd00:1:2:3::/64"},
                ],
                "ipam_driver": "default",
                "name": f"{project}_{logical}",
                "options": options,
                "scope": "local",
            }
        )
    return {
        "topology-addresses.json": {
            "interfaces": [
                {
                    "addr_info": [
                        {"family": "inet", "local": "172.31.250.10", "prefixlen": 24},
                        {"family": "inet6", "local": "fd00:1:2:3::10", "prefixlen": 64},
                    ],
                    "ifindex": 2,
                    "ifname": "eth0",
                }
            ],
            "schema": "interlock.phase2-topology-addresses.v1",
        },
        "topology-attachments.json": {
            "schema": "interlock.phase2-topology-attachments.v1",
            "services": EXPECTED_ATTACHMENTS,
        },
        "topology-containers.json": {
            "containers": containers,
            "schema": "interlock.phase2-topology-containers.v1",
        },
        "topology-gateway-proof.json": {
            "alias_resolution": [
                {"addresses": [], "category": "gaierror", "hostname": hostname}
                for hostname in HOST_ALIASES
            ],
            "container_gateway_fields": [],
            "discovered_targets": [],
            "effective_gateway_modes": GATEWAY_OPTIONS,
            "host_bridge_addresses": [],
            "listener": {
                "bound_addresses": [],
                "failed_addresses": [],
                "started": False,
            },
            "method_results": [],
            "method_summary": {
                method: {"connected_count": 0, "target_count": 0}
                for method in GATEWAY_METHODS
            },
            "network_ipam_gateways": [],
            "no_host_gateway_reachable": True,
            "positive_proxy_control_passed": True,
            "required_gateway_modes": GATEWAY_OPTIONS,
            "route_gateways": [],
            "schema": "interlock.phase2-topology-gateway-proof.v1",
            "statement": "no host gateway was reachable from Interlock",
        },
        "topology-host-bridge.json": {
            "interface": "br-" + network_ids["app_net"][:12],
            "interfaces": [
                {
                    "addr_info": [],
                    "ifindex": 42,
                    "ifname": "br-" + network_ids["app_net"][:12],
                }
            ],
            "network_id": network_ids["app_net"],
            "schema": "interlock.phase2-topology-host-bridge.v1",
            "test_only_host_namespace_probe": True,
        },
        "topology-neighbors-ipv4.json": {
            "family": 4,
            "neighbors": [],
            "schema": "interlock.phase2-topology-neighbors.v1",
        },
        "topology-neighbors-ipv6.json": {
            "family": 6,
            "neighbors": [],
            "schema": "interlock.phase2-topology-neighbors.v1",
        },
        "topology-networks.json": {
            "networks": network_documents,
            "schema": "interlock.phase2-topology-networks.v1",
        },
        "topology-routes-ipv4.json": {
            "family": 4,
            "routes": [{"dev": "eth0", "dst": "172.31.250.0/24", "scope": "link"}],
            "schema": "interlock.phase2-topology-routes.v1",
        },
        "topology-routes-ipv6.json": {
            "family": 6,
            "routes": [{"dev": "eth0", "dst": "fd00:1:2:3::/64", "scope": "link"}],
            "schema": "interlock.phase2-topology-routes.v1",
        },
        "topology-runtime-versions.json": {
            "compose": "2.38.2",
            "docker_client": {
                "api_version": "1.48",
                "arch": "amd64",
                "os": "linux",
                "version": "28.0.4",
            },
            "docker_server": {
                "api_version": "1.48",
                "arch": "amd64",
                "os": "linux",
                "version": "28.0.4",
            },
            "schema": "interlock.phase2-topology-runtime.v1",
        },
    }


def _write_evidence(path: Path) -> None:
    path.mkdir()
    results = [
        {"case": name, "category": "", "outcome": "passed"} for name in REQUIRED_CASES
    ]
    results_path = path / "results.jsonl"
    results_path.write_text(
        "".join(json.dumps(item, sort_keys=True) + "\n" for item in results),
        encoding="utf-8",
    )
    suite = ET.Element(
        "testsuite",
        tests=str(len(results)),
        failures="0",
        errors="0",
        skipped="0",
    )
    for item in results:
        ET.SubElement(suite, "testcase", name=item["case"])
    junit = path / "junit.xml"
    ET.ElementTree(suite).write(junit, encoding="utf-8", xml_declaration=True)
    log = path / "proxy.log"
    log.write_text("safe numeric log\n", encoding="utf-8")
    for name, document in _topology_documents().items():
        (path / name).write_text(json.dumps(document, sort_keys=True), encoding="utf-8")
    artifacts = {
        item.name: _digest(item)
        for item in path.iterdir()
        if item.is_file() and item.name != "manifest.json"
    }
    manifest = {
        "schema": "interlock.phase2-docker-evidence.v2",
        "source_sha": subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=Path(__file__).resolve().parents[1],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip(),
        "source_dirty_development_run": False,
        "squid_image": verifier.SQUID_IMAGE,
        "squid_image_digest": verifier.SQUID_DIGEST,
        "squid_policy_sha256": _digest(PROFILE / "squid.conf"),
        "squid_allowed_domains_sha256": _digest(PROFILE / "allowed-domains.txt"),
        "squid_policy_bundle_sha256": hashlib.sha256(
            (PROFILE / "squid.conf").read_bytes()
            + (PROFILE / "allowed-domains.txt").read_bytes()
        ).hexdigest(),
        "compose_source_sha256": _digest(PROFILE / "compose.yaml"),
        "compose_rendered_sha256": "b" * 64,
        "compose_version": "2.38.2",
        "compose_project_name": "interlock-p2-123456789abc",
        "docker_client_version": "28.0.4",
        "docker_server_os": "linux",
        "docker_server_version": "28.0.4",
        "project_name_hash": hashlib.sha256(b"interlock-p2-123456789abc").hexdigest(),
        "test_source_sha256": verifier.test_source_digest(),
        "sentinel_sha256": {
            "authorization": "c" * 64,
            "proxy_credential": "d" * 64,
            "query": "e" * 64,
        },
        "required_cases": list(REQUIRED_CASES),
        "expected_case_count": len(results),
        "executed_case_count": len(results),
        "passed_case_count": len(results),
        "failed_case_count": 0,
        "results_sha256": _digest(results_path),
        "artifact_sha256": artifacts,
        "topology_artifact_sha256": {name: artifacts[name] for name in TOPOLOGY_FILES},
    }
    (path / "manifest.json").write_text(
        json.dumps(manifest, sort_keys=True), encoding="utf-8"
    )


def _verify(monkeypatch: pytest.MonkeyPatch, path: Path) -> int:
    monkeypatch.setattr(
        verifier, "rendered_compose_digest", lambda _sha, _project: "b" * 64
    )
    monkeypatch.setattr(sys, "argv", ["verify", str(path)])
    return verifier.main()


def _rehash(path: Path) -> None:
    manifest_path = path / "manifest.json"
    manifest = json.loads(manifest_path.read_text("utf-8"))
    manifest["results_sha256"] = _digest(path / "results.jsonl")
    manifest["artifact_sha256"] = {
        item.name: _digest(item)
        for item in path.iterdir()
        if item.is_file() and item.name != "manifest.json"
    }
    manifest["topology_artifact_sha256"] = {
        name: manifest["artifact_sha256"][name]
        for name in TOPOLOGY_FILES
        if name in manifest["artifact_sha256"]
    }
    manifest_path.write_text(json.dumps(manifest, sort_keys=True), encoding="utf-8")


def test_verifier_accepts_exact_complete_evidence(tmp_path, monkeypatch):
    evidence = tmp_path / "evidence"
    _write_evidence(evidence)
    assert _verify(monkeypatch, evidence) == 0


def test_verifier_accepts_docker_28_without_implicit_enable_ipv4_option(
    tmp_path, monkeypatch
):
    evidence = tmp_path / "evidence"
    _write_evidence(evidence)
    networks_path = evidence / "topology-networks.json"
    document = json.loads(networks_path.read_text("utf-8"))
    for network in document["networks"]:
        network["options"].pop("com.docker.network.enable_ipv4", None)
    networks_path.write_text(json.dumps(document), encoding="utf-8")
    _rehash(evidence)
    assert _verify(monkeypatch, evidence) == 0


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("com.docker.network.enable_ipv4", "false"),
        ("com.docker.network.bridge.gateway_mode_ipv4", "nat"),
        ("unexpected.network.option", "true"),
    ],
)
def test_verifier_rejects_unsafe_or_unknown_effective_network_option(
    tmp_path, monkeypatch, name, value
):
    evidence = tmp_path / "evidence"
    _write_evidence(evidence)
    networks_path = evidence / "topology-networks.json"
    document = json.loads(networks_path.read_text("utf-8"))
    app = next(
        network
        for network in document["networks"]
        if network["name"].endswith("app_net")
    )
    app["options"][name] = value
    networks_path.write_text(json.dumps(document), encoding="utf-8")
    _rehash(evidence)
    with pytest.raises(ValueError):
        _verify(monkeypatch, evidence)


@pytest.mark.parametrize("mutation", ["missing", "duplicate", "failed", "malformed"])
def test_verifier_rejects_result_mutations(tmp_path, monkeypatch, mutation):
    evidence = tmp_path / "evidence"
    _write_evidence(evidence)
    path = evidence / "results.jsonl"
    values = [json.loads(line) for line in path.read_text("utf-8").splitlines()]
    if mutation == "missing":
        values.pop()
    elif mutation == "duplicate":
        values[-1] = values[0]
    elif mutation == "failed":
        values[-1]["outcome"] = "failed"
    else:
        values[-1]["unexpected"] = True
    path.write_text(
        "".join(json.dumps(item, sort_keys=True) + "\n" for item in values),
        encoding="utf-8",
    )
    _rehash(evidence)
    with pytest.raises(ValueError):
        _verify(monkeypatch, evidence)


@pytest.mark.parametrize("node", ["failure", "error", "skipped"])
def test_verifier_rejects_junit_non_pass_nodes(tmp_path, monkeypatch, node):
    evidence = tmp_path / "evidence"
    _write_evidence(evidence)
    junit = evidence / "junit.xml"
    suite = ET.parse(junit).getroot()
    suite.set(node if node != "skipped" else "skipped", "1")
    ET.SubElement(suite.findall("testcase")[0], node)
    ET.ElementTree(suite).write(junit, encoding="utf-8", xml_declaration=True)
    _rehash(evidence)
    with pytest.raises(ValueError):
        _verify(monkeypatch, evidence)


@pytest.mark.parametrize("marker", ["xfail", "xpass"])
def test_verifier_rejects_pytest_outcome_markers(tmp_path, monkeypatch, marker):
    evidence = tmp_path / "evidence"
    _write_evidence(evidence)
    junit = evidence / "junit.xml"
    suite = ET.parse(junit).getroot()
    suite.findall("testcase")[0].set("status", marker)
    ET.ElementTree(suite).write(junit, encoding="utf-8", xml_declaration=True)
    _rehash(evidence)
    with pytest.raises(ValueError):
        _verify(monkeypatch, evidence)


def test_verifier_rejects_stale_artifact_digest(tmp_path, monkeypatch):
    evidence = tmp_path / "evidence"
    _write_evidence(evidence)
    (evidence / "proxy.log").write_text("changed\n", encoding="utf-8")
    with pytest.raises(ValueError):
        _verify(monkeypatch, evidence)


@pytest.mark.parametrize(
    "disclosure",
    [
        "postgresql://user:password@database:5432/name",
        "mysql://user:password@database:3306/name",
        "http://squid:3128",
        "Authorization: Bearer retained-value",
        "Authorization: ApiKey retained-value",
        '{"authorization":"retained-value"}',
        "ADMIN_TOKEN=retained-value",
        "api_key=retained-value",
        "password=retained-value",
        "https://user:password@allowed.phase2.test/path",
        "https://allowed.phase2.test/path?query=retained-value",
    ],
)
def test_verifier_rejects_retained_sensitive_output(tmp_path, monkeypatch, disclosure):
    evidence = tmp_path / "evidence"
    _write_evidence(evidence)
    (evidence / "proxy.log").write_text(disclosure + "\n", encoding="utf-8")
    _rehash(evidence)
    with pytest.raises(ValueError):
        _verify(monkeypatch, evidence)


def test_verifier_rejects_counter_inconsistency(tmp_path, monkeypatch):
    evidence = tmp_path / "evidence"
    _write_evidence(evidence)
    manifest_path = evidence / "manifest.json"
    manifest = json.loads(manifest_path.read_text("utf-8"))
    manifest["passed_case_count"] -= 1
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(ValueError):
        _verify(monkeypatch, evidence)


def test_verifier_rejects_stale_rendered_compose(tmp_path, monkeypatch):
    evidence = tmp_path / "evidence"
    _write_evidence(evidence)
    manifest_path = evidence / "manifest.json"
    manifest = json.loads(manifest_path.read_text("utf-8"))
    manifest["compose_rendered_sha256"] = "a" * 64
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(ValueError):
        _verify(monkeypatch, evidence)


@pytest.mark.parametrize(
    "name",
    [
        "topology-routes-ipv4.json",
        "topology-routes-ipv6.json",
        "topology-host-bridge.json",
        "topology-gateway-proof.json",
    ],
)
def test_verifier_rejects_missing_required_topology_artifact(
    tmp_path, monkeypatch, name
):
    evidence = tmp_path / "evidence"
    _write_evidence(evidence)
    (evidence / name).unlink()
    manifest_path = evidence / "manifest.json"
    manifest = json.loads(manifest_path.read_text("utf-8"))
    manifest["artifact_sha256"].pop(name)
    manifest["topology_artifact_sha256"].pop(name)
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(ValueError):
        _verify(monkeypatch, evidence)


def test_verifier_rejects_removed_ipv6_gateway_mode_proof(tmp_path, monkeypatch):
    evidence = tmp_path / "evidence"
    _write_evidence(evidence)
    gateway = evidence / "topology-gateway-proof.json"
    document = json.loads(gateway.read_text("utf-8"))
    document["effective_gateway_modes"].pop(
        "com.docker.network.bridge.gateway_mode_ipv6"
    )
    gateway.write_text(json.dumps(document), encoding="utf-8")
    _rehash(evidence)
    with pytest.raises(ValueError):
        _verify(monkeypatch, evidence)


@pytest.mark.parametrize(
    ("manifest_key", "replacement"),
    [
        ("docker_client_version", "29.0.0"),
        ("docker_server_version", "29.0.0"),
        ("docker_server_os", "windows"),
        ("compose_version", "2.39.0"),
    ],
)
def test_verifier_rejects_runtime_version_manifest_disagreement(
    tmp_path, monkeypatch, manifest_key, replacement
):
    evidence = tmp_path / "evidence"
    _write_evidence(evidence)
    manifest_path = evidence / "manifest.json"
    manifest = json.loads(manifest_path.read_text("utf-8"))
    manifest[manifest_key] = replacement
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(ValueError):
        _verify(monkeypatch, evidence)


@pytest.mark.parametrize(
    "mutation",
    ["app_ipam_gateway", "host_bridge_address", "missing_host_alias"],
)
def test_verifier_rejects_incomplete_gateway_isolation_proof(
    tmp_path, monkeypatch, mutation
):
    evidence = tmp_path / "evidence"
    _write_evidence(evidence)
    if mutation == "app_ipam_gateway":
        path = evidence / "topology-networks.json"
        document = json.loads(path.read_text("utf-8"))
        app = next(
            item for item in document["networks"] if item["name"].endswith("app_net")
        )
        app["ipam_config"][0]["gateway"] = "172.31.250.1"
    elif mutation == "host_bridge_address":
        path = evidence / "topology-host-bridge.json"
        document = json.loads(path.read_text("utf-8"))
        document["interfaces"][0]["addr_info"] = [
            {"family": "inet", "local": "172.31.250.1", "prefixlen": 24}
        ]
    else:
        path = evidence / "topology-gateway-proof.json"
        document = json.loads(path.read_text("utf-8"))
        document["alias_resolution"].pop()
    path.write_text(json.dumps(document), encoding="utf-8")
    _rehash(evidence)
    with pytest.raises(ValueError):
        _verify(monkeypatch, evidence)


def test_verifier_rejects_removed_gateway_method_result(tmp_path, monkeypatch):
    evidence = tmp_path / "evidence"
    _write_evidence(evidence)
    gateway = evidence / "topology-gateway-proof.json"
    document = json.loads(gateway.read_text("utf-8"))
    document["alias_resolution"][0]["addresses"] = ["192.0.2.1"]
    alias_source = "dns_alias:" + document["alias_resolution"][0]["hostname"]
    document["discovered_targets"] = [
        {"address": "192.0.2.1", "family": 4, "sources": [alias_source]}
    ]
    document["listener"]["bound_addresses"] = ["192.0.2.1"]
    document["listener"]["started"] = True
    for method in GATEWAY_METHODS:
        document["method_summary"][method]["target_count"] = 1
        document["method_results"].append(
            {
                "address": "192.0.2.1",
                "connected": False,
                "family": 4,
                "method": method,
            }
        )
    document["method_results"].pop()
    gateway.write_text(json.dumps(document), encoding="utf-8")
    _rehash(evidence)
    with pytest.raises(ValueError):
        _verify(monkeypatch, evidence)
