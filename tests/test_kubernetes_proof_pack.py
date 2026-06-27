"""Tests for the Kubernetes provider proof pack.

Run: python3 -m pytest tests/test_kubernetes_proof_pack.py -q -s
"""

import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from demo.provider_packs.kubernetes import run_kubernetes_proof_pack


def _by_name(report):
    return {scenario["name"]: scenario for scenario in report["scenarios"]}


def test_kubernetes_proof_pack_covers_easy_to_extreme_scenarios():
    report = run_kubernetes_proof_pack()
    scenarios = _by_name(report)

    assert report["provider"] == "kubernetes"
    assert report["mode"] == "local_mock_sandbox"
    assert report["summary"]["all_passed"] is True
    assert set(scenarios) == {
        "clean_inventory_false_positive_control",
        "dry_run_to_apply_effect_drift",
        "dry_run_to_delete_namespace_temporal_drift",
        "hidden_apply_provider_readback_drift",
        "secret_read_to_exec_chain_drift",
        "inventory_to_delete_namespace_chain_drift",
    }

    clean = scenarios["clean_inventory_false_positive_control"]
    assert clean["ok"] is True
    assert clean["severity"] == "none"
    assert clean["decision"] == "allow"
    assert clean["drift_detected"] is False

    apply = scenarios["dry_run_to_apply_effect_drift"]
    assert apply["ok"] is True
    assert apply["severity"] in {"high", "critical"}
    assert apply["decision"] == "quarantine"
    assert "effect_mutation_after_preview" in apply["finding_types"]
    assert apply["receipt"]["drift_evidence"]["evidence_ref"]["type"] == "effect-drift"

    temporal = scenarios["dry_run_to_delete_namespace_temporal_drift"]
    assert temporal["ok"] is True
    assert temporal["severity"] == "critical"
    assert temporal["decision"] == "quarantine"
    assert "effect_temporal_destructive_after_preview" in temporal["finding_types"]
    assert "effect_destructive_after_preview" in temporal["finding_types"]
    assert (
        temporal["receipt"]["drift_evidence"]["evidence_ref"]["type"] == "effect-drift"
    )

    readback = scenarios["hidden_apply_provider_readback_drift"]
    assert readback["ok"] is True
    assert readback["severity"] == "critical"
    assert readback["decision"] == "quarantine"
    assert "silent_side_effect_drift" in readback["finding_types"]
    assert "effect_response_contradicted_by_readback" in readback["finding_types"]
    assert readback["readback"]["before_resource_count"] == 0
    assert readback["readback"]["after_resource_count"] == 1
    assert (
        readback["receipt"]["drift_evidence"]["evidence_ref"]["type"]
        == "readback-effect-drift"
    )

    secret_exec = scenarios["secret_read_to_exec_chain_drift"]
    assert secret_exec["ok"] is True
    assert secret_exec["severity"] == "critical"
    assert secret_exec["decision"] == "deny"
    assert "chain_secret_to_execution" in secret_exec["finding_types"]
    assert (
        secret_exec["receipt"]["drift_evidence"]["evidence_ref"]["type"]
        == "chain-drift"
    )

    delete_chain = scenarios["inventory_to_delete_namespace_chain_drift"]
    assert delete_chain["ok"] is True
    assert delete_chain["severity"] == "critical"
    assert delete_chain["decision"] == "deny"
    assert "chain_preview_to_destructive" in delete_chain["finding_types"]
    assert (
        delete_chain["receipt"]["drift_evidence"]["evidence_ref"]["type"]
        == "chain-drift"
    )


def test_kubernetes_proof_pack_is_evidence_safe_and_honest_about_scope():
    report = run_kubernetes_proof_pack()
    encoded = json.dumps(report, sort_keys=True)
    limitations = " ".join(report["limitations"]).lower()

    assert "local mock" in limitations
    assert "no real kubernetes cluster" in limitations
    assert "no kubectl" in limitations
    assert "no cloud provider" in limitations
    assert "no production mcp server" in limitations
    assert "prod-namespace-secret" not in encoded
    assert "pod-token-secret" not in encoded
    assert "cluster-admin-secret" not in encoded
    assert "kubeconfig=" not in encoded.lower()
    assert "/.kube/" not in encoded.lower()
    assert "sha256:" in encoded


def test_kubernetes_proof_pack_cli_runs_and_prints_pass_lines():
    script = (
        Path(__file__).resolve().parents[1] / "demo" / "run_kubernetes_proof_pack.py"
    )
    out = subprocess.run(
        [sys.executable, str(script)],
        check=True,
        text=True,
        capture_output=True,
    )

    assert "PASS clean_inventory_false_positive_control" in out.stdout
    assert "PASS dry_run_to_apply_effect_drift" in out.stdout
    assert "PASS dry_run_to_delete_namespace_temporal_drift" in out.stdout
    assert "PASS hidden_apply_provider_readback_drift" in out.stdout
    assert "PASS secret_read_to_exec_chain_drift" in out.stdout
    assert "PASS inventory_to_delete_namespace_chain_drift" in out.stdout
    assert "no real Kubernetes cluster" in out.stdout
