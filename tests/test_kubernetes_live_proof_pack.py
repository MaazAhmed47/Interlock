"""Tests for the credential-gated live Kubernetes/kubectl proof pack.

Run: python3 -m pytest tests/test_kubernetes_live_proof_pack.py -q -s
"""

import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from demo.provider_packs.kubernetes_live import (
    LiveKubernetesConfig,
    run_kubernetes_live_proof_pack,
)


class FakeKubectlClient:
    provider_kind = "kubernetes"
    provider_name = "fake-kubectl-sandbox"

    def __init__(self):
        self.objects = []
        self.cleaned = False

    def prepare(self):
        return {"prepared": True}

    def read_state(self):
        return {
            "resource_count": len(self.objects),
            "objects": [{"name": name, "kind": "Deployment"} for name in self.objects],
        }

    def server_dry_run(self, *, mode):
        return {"dry_run": True, "preview": True, "would_apply": 1, "mode": mode}

    def apply_canary(self, *, mode):
        self.objects.append(f"secret-object-{mode}-{len(self.objects)}")
        return {"applied": True, "mode": mode}

    def delete_canary(self, *, mode):
        if self.objects:
            self.objects.pop()
        return {"deleted": True, "mode": mode}

    def cleanup(self):
        self.cleaned = True
        self.objects.clear()


def _config():
    return LiveKubernetesConfig(
        context="kind-interlock-secret",
        namespace="interlock-secret-namespace",
        canary_label="interlock-k8s-canary-001",
        allow_live=True,
    )


def _by_name(report):
    return {scenario["name"]: scenario for scenario in report["scenarios"]}


def test_kubernetes_live_pack_safely_skips_without_explicit_config():
    report = run_kubernetes_live_proof_pack(env={})

    assert report["provider"] == "kubernetes"
    assert report["mode"] == "credential_gated_kubectl_sandbox"
    assert report["summary"]["executed"] is False
    assert report["summary"]["all_passed"] is True
    assert report["scenarios"] == []
    assert "No Kubernetes cluster was contacted" in " ".join(report["limitations"])


def test_kubernetes_live_pack_rejects_non_interlock_namespace():
    report = run_kubernetes_live_proof_pack(
        env={
            "INTERLOCK_ALLOW_LIVE_KUBERNETES_PROOFS": "1",
            "INTERLOCK_KUBERNETES_CONTEXT": "kind-safe",
            "INTERLOCK_KUBERNETES_NAMESPACE": "default",
        }
    )

    assert report["summary"]["executed"] is False
    assert report["summary"]["status"] == "skipped_unsafe_namespace"


def test_kubernetes_live_pack_covers_real_kubectl_scenarios_with_injected_client():
    client = FakeKubectlClient()
    report = run_kubernetes_live_proof_pack(client=client, config=_config())
    scenarios = _by_name(report)

    assert report["provider"] == "kubernetes"
    assert report["mode"] == "credential_gated_kubectl_sandbox"
    assert report["summary"]["executed"] is True
    assert report["summary"]["all_passed"] is True
    assert client.cleaned is True
    assert set(scenarios) == {
        "live_kubectl_inventory_no_change_control",
        "live_kubectl_server_dry_run_control",
        "live_kubectl_hidden_apply_readback_drift",
        "live_kubectl_expected_apply_allowed_control",
        "live_kubectl_hidden_delete_readback_drift",
        "live_kubectl_secret_read_to_exec_chain_drift",
        "live_kubectl_inventory_to_delete_namespace_chain_drift",
    }

    inventory = scenarios["live_kubectl_inventory_no_change_control"]
    assert inventory["ok"] is True
    assert inventory["severity"] == "none"
    assert inventory["decision"] == "allow"

    dry_run = scenarios["live_kubectl_server_dry_run_control"]
    assert dry_run["ok"] is True
    assert dry_run["severity"] == "none"
    assert dry_run["decision"] == "allow"

    apply = scenarios["live_kubectl_hidden_apply_readback_drift"]
    assert apply["ok"] is True
    assert apply["severity"] == "critical"
    assert apply["decision"] == "quarantine"
    assert "silent_side_effect_drift" in apply["finding_types"]
    assert "effect_response_contradicted_by_readback" in apply["finding_types"]
    assert (
        apply["readback"]["after_resource_count"]
        > apply["readback"]["before_resource_count"]
    )
    assert (
        apply["receipt"]["drift_evidence"]["evidence_ref"]["type"]
        == "readback-effect-drift"
    )

    expected_apply = scenarios["live_kubectl_expected_apply_allowed_control"]
    assert expected_apply["ok"] is True
    assert expected_apply["severity"] == "none"
    assert expected_apply["decision"] == "allow"

    delete = scenarios["live_kubectl_hidden_delete_readback_drift"]
    assert delete["ok"] is True
    assert delete["severity"] == "critical"
    assert delete["decision"] == "quarantine"
    assert "silent_side_effect_drift" in delete["finding_types"]
    assert (
        delete["readback"]["after_resource_count"]
        < delete["readback"]["before_resource_count"]
    )

    secret_exec = scenarios["live_kubectl_secret_read_to_exec_chain_drift"]
    assert secret_exec["ok"] is True
    assert secret_exec["severity"] == "critical"
    assert secret_exec["decision"] == "deny"
    assert "chain_secret_to_execution" in secret_exec["finding_types"]

    delete_chain = scenarios["live_kubectl_inventory_to_delete_namespace_chain_drift"]
    assert delete_chain["ok"] is True
    assert delete_chain["severity"] == "critical"
    assert delete_chain["decision"] == "deny"
    assert "chain_preview_to_destructive" in delete_chain["finding_types"]


def test_kubernetes_live_pack_is_evidence_safe_and_honest():
    report = run_kubernetes_live_proof_pack(
        client=FakeKubectlClient(), config=_config()
    )
    encoded = json.dumps(report, sort_keys=True).lower()
    limitations = " ".join(report["limitations"]).lower()

    assert "credential-gated" in limitations
    assert "sandbox" in limitations
    assert "no cloud provider" in limitations
    assert "not eks/gke/aks" in limitations
    assert "kind-interlock-secret" not in encoded
    assert "interlock-secret-namespace" not in encoded
    assert "secret-object" not in encoded
    assert "cluster-admin-secret" not in encoded
    assert "pod-token-secret" not in encoded
    assert "sha256:" in encoded


def test_kubernetes_live_pack_cli_skips_without_credentials():
    script = (
        Path(__file__).resolve().parents[1]
        / "demo"
        / "run_kubernetes_live_proof_pack.py"
    )
    out = subprocess.run(
        [sys.executable, str(script)],
        check=True,
        text=True,
        capture_output=True,
    )

    assert "Kubernetes live proof pack" in out.stdout
    assert "SKIP" in out.stdout
    assert "No Kubernetes cluster was contacted" in out.stdout
