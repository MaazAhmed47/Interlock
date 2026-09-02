"""Static security invariants for the disposable Kubernetes enforcement profile."""

import json
import os
from pathlib import Path
import subprocess
import sys

import yaml

from scripts.run_kubernetes_enforcement_acceptance import (
    KIND_IMAGE_LOAD_TIMEOUT_SECONDS,
)

ROOT = Path(__file__).resolve().parents[1]
PROFILE = ROOT / "deploy" / "kubernetes-enforcement"
NAMESPACES = {
    "interlock-agent",
    "interlock-gateway",
    "interlock-mcp",
    "interlock-control",
}


def _documents(relative_path: str) -> list[dict]:
    with (PROFILE / relative_path).open(encoding="utf-8") as handle:
        return [item for item in yaml.safe_load_all(handle) if item]


def _policies() -> dict[tuple[str, str], dict]:
    return {
        (item["metadata"]["namespace"], item["metadata"]["name"]): item
        for item in _documents("manifests/network-policies.yaml")
    }


def test_kind_configuration_disables_default_cni_and_pins_node_digest():
    config = _documents("kind/cluster.yaml")[0]

    assert config["kind"] == "Cluster"
    assert config["networking"]["disableDefaultCNI"] is True
    assert config["networking"]["podSubnet"] == "192.168.0.0/16"
    assert len(config["nodes"]) == 1
    assert config["nodes"][0]["image"] == (
        "kindest/node:v1.36.4@sha256:"
        "099e049362a1526b2db71494e1947aae99bd16290d7c895f2b7ea312e3cbfaed"
    )


def test_calico_manifest_and_runtime_images_are_exactly_pinned():
    versions = json.loads((PROFILE / "kind" / "versions.json").read_text())
    calico = versions["calico"]

    assert calico["version"] == "v3.32.2"
    assert len(calico["manifest_sha256"]) == 64
    assert set(calico["images"]) == {"cni", "kube_controllers", "node"}
    for image in calico["images"].values():
        assert image.startswith("quay.io/calico/")
        assert "@sha256:" in image
        assert ":v3.32.2" not in image


def test_profile_uses_four_exact_labeled_namespaces():
    documents = _documents("manifests/namespaces.yaml")
    assert {item["metadata"]["name"] for item in documents} == NAMESPACES
    for item in documents:
        assert item["kind"] == "Namespace"
        assert item["metadata"]["labels"]["interlock.test/boundary"] == "true"


def test_every_profile_namespace_has_ingress_and_egress_default_deny():
    policies = _policies()
    for namespace in NAMESPACES:
        policy = policies[(namespace, "default-deny")]
        assert policy["spec"]["podSelector"] == {}
        assert set(policy["spec"]["policyTypes"]) == {"Ingress", "Egress"}
        assert policy["spec"]["ingress"] == []
        assert policy["spec"]["egress"] == []


def test_dns_is_the_only_shared_egress_rule():
    policies = _policies()
    for namespace in NAMESPACES:
        policy = policies[(namespace, "allow-dns")]
        assert policy["spec"]["policyTypes"] == ["Egress"]
        rule = policy["spec"]["egress"]
        assert len(rule) == 1
        assert rule[0]["to"] == [
            {
                "namespaceSelector": {
                    "matchLabels": {"kubernetes.io/metadata.name": "kube-system"}
                },
                "podSelector": {"matchLabels": {"k8s-app": "kube-dns"}},
            }
        ]
        assert {port["port"] for port in rule[0]["ports"]} == {53}
        assert {port["protocol"] for port in rule[0]["ports"]} == {"TCP", "UDP"}


def test_agent_can_reach_only_gateway_application_peer():
    policy = _policies()[("interlock-agent", "agent-to-gateway")]
    rule = policy["spec"]["egress"]
    assert len(rule) == 1
    assert rule[0]["ports"] == [{"protocol": "TCP", "port": 8001}]
    peer = rule[0]["to"][0]
    assert peer["namespaceSelector"]["matchLabels"] == {
        "kubernetes.io/metadata.name": "interlock-gateway"
    }
    assert peer["podSelector"]["matchLabels"] == {
        "app.kubernetes.io/name": "interlock-gateway"
    }


def test_gateway_to_mcp_requires_both_namespace_and_pod_identity():
    policies = _policies()
    egress = policies[("interlock-gateway", "gateway-to-mcp")]["spec"]["egress"]
    ingress = policies[("interlock-mcp", "gateway-to-mcp")]["spec"]["ingress"]
    assert len(egress) == len(ingress) == 1
    assert egress[0]["ports"] == [{"protocol": "TCP", "port": 8080}]
    assert ingress[0]["ports"] == [{"protocol": "TCP", "port": 8080}]
    assert egress[0]["to"][0]["namespaceSelector"]["matchLabels"] == {
        "kubernetes.io/metadata.name": "interlock-mcp"
    }
    assert egress[0]["to"][0]["podSelector"]["matchLabels"] == {
        "app.kubernetes.io/name": "interlock-mcp-test-server"
    }
    assert ingress[0]["from"][0]["namespaceSelector"]["matchLabels"] == {
        "kubernetes.io/metadata.name": "interlock-gateway"
    }
    assert ingress[0]["from"][0]["podSelector"]["matchLabels"] == {
        "app.kubernetes.io/name": "interlock-gateway"
    }


def test_workloads_disable_service_account_tokens_and_harden_containers():
    for document in _documents("manifests/workloads.yaml"):
        if document["kind"] not in {"Deployment", "Pod"}:
            continue
        spec = (
            document["spec"]["template"]["spec"]
            if document["kind"] == "Deployment"
            else document["spec"]
        )
        assert spec["automountServiceAccountToken"] is False
        for container in [*spec.get("initContainers", []), *spec["containers"]]:
            security = container["securityContext"]
            assert security["allowPrivilegeEscalation"] is False
            assert security["readOnlyRootFilesystem"] is True
            assert security["runAsNonRoot"] is True
            assert security["capabilities"]["drop"] == ["ALL"]


def test_tracked_profile_contains_no_literal_secret_or_mutable_latest_tag():
    tracked_text = "\n".join(
        path.read_text(encoding="utf-8")
        for path in PROFILE.rglob("*")
        if path.is_file() and path.suffix in {".md", ".json", ".py", ".yaml"}
    ).lower()

    assert "authorization:" not in tracked_text
    assert "proxy-authorization:" not in tracked_text
    assert "private key" not in tracked_text
    assert "BEGIN PRIVATE KEY".lower() not in tracked_text
    assert "image: latest" not in tracked_text
    assert ":latest" not in tracked_text
    assert "value: lf_" not in tracked_text


def test_ci_runs_live_acceptance_and_reverifies_exact_head_evidence():
    workflow = yaml.safe_load(
        (ROOT / ".github" / "workflows" / "tests.yml").read_text()
    )
    job = workflow["jobs"]["kubernetes-enforcement"]
    steps = "\n".join(str(step) for step in job["steps"])

    assert "github.event.pull_request.head.sha" in steps
    assert "run_kubernetes_enforcement_acceptance.py" in steps
    assert "verify_kubernetes_enforcement_evidence.py" in steps
    assert "if-no-files-found" in steps and "error" in steps


def test_kind_image_import_allows_for_slow_local_docker_transfers():
    assert KIND_IMAGE_LOAD_TIMEOUT_SECONDS >= 1200


def test_lab_bootstrap_direct_execution_resolves_repository_modules(tmp_path):
    script = PROFILE / "scripts" / "lab_entrypoint.py"
    environment = os.environ.copy()
    environment.pop("DATABASE_URL", None)
    environment.update(
        {
            "FIREWALL_DB_PATH": str(tmp_path / "lab.db"),
            "INTERLOCK_LAB_API_KEY": "lf_" + "developer_" + "local_test_only",
            "MCP_REGISTRY_ALLOWED_HOSTS": "mcp.interlock-mcp.svc.cluster.local",
        }
    )

    completed = subprocess.run(
        [sys.executable, str(script), "bootstrap"],
        cwd=tmp_path,
        env=environment,
        text=True,
        capture_output=True,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    assert '"bootstrap": "complete"' in completed.stdout
    assert "ModuleNotFoundError" not in completed.stderr
