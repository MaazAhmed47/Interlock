"""Tests for the Terraform provider proof pack.

Run: python3 -m pytest tests/test_terraform_proof_pack.py -q -s
"""

import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from demo.provider_packs.terraform import run_terraform_proof_pack


def _by_name(report):
    return {scenario["name"]: scenario for scenario in report["scenarios"]}


def test_terraform_proof_pack_covers_easy_to_extreme_scenarios():
    report = run_terraform_proof_pack()
    scenarios = _by_name(report)

    assert report["provider"] == "terraform"
    assert report["mode"] == "local_mock_sandbox"
    assert report["summary"]["all_passed"] is True
    assert set(scenarios) == {
        "clean_plan_false_positive_control",
        "plan_to_apply_effect_drift",
        "plan_to_scheduled_destroy_temporal_drift",
        "hidden_apply_provider_readback_drift",
        "plan_apply_destroy_chain_drift",
    }

    clean = scenarios["clean_plan_false_positive_control"]
    assert clean["ok"] is True
    assert clean["severity"] == "none"
    assert clean["decision"] == "allow"
    assert clean["drift_detected"] is False

    apply = scenarios["plan_to_apply_effect_drift"]
    assert apply["ok"] is True
    assert apply["severity"] == "high"
    assert apply["decision"] == "quarantine"
    assert "effect_mutation_after_preview" in apply["finding_types"]
    assert apply["receipt"]["drift_evidence"]["evidence_ref"]["type"] == "effect-drift"

    temporal = scenarios["plan_to_scheduled_destroy_temporal_drift"]
    assert temporal["ok"] is True
    assert temporal["severity"] == "critical"
    assert temporal["decision"] == "quarantine"
    assert "effect_temporal_destructive_after_preview" in temporal["finding_types"]
    assert (
        temporal["receipt"]["drift_evidence"]["evidence_ref"]["type"] == "effect-drift"
    )

    readback = scenarios["hidden_apply_provider_readback_drift"]
    assert readback["ok"] is True
    assert readback["severity"] == "critical"
    assert readback["decision"] == "quarantine"
    assert "silent_side_effect_drift" in readback["finding_types"]
    assert (
        readback["receipt"]["drift_evidence"]["evidence_ref"]["type"]
        == "readback-effect-drift"
    )

    chain = scenarios["plan_apply_destroy_chain_drift"]
    assert chain["ok"] is True
    assert chain["severity"] == "critical"
    assert chain["decision"] == "deny"
    assert "chain_preview_to_deploy" in chain["finding_types"]
    assert "chain_preview_to_destructive" in chain["finding_types"]
    assert chain["receipt"]["drift_evidence"]["evidence_ref"]["type"] == "chain-drift"


def test_terraform_proof_pack_is_evidence_safe_and_honest_about_scope():
    report = run_terraform_proof_pack()
    encoded = json.dumps(report, sort_keys=True)

    assert "local mock" in report["limitations"][0].lower()
    assert "no real terraform" in " ".join(report["limitations"]).lower()
    assert "no cloud credentials" in " ".join(report["limitations"]).lower()
    assert "prod-vpc-secret" not in encoded
    assert "tfstate-secret" not in encoded
    assert "secret-workspace" not in encoded
    assert "sha256:" in encoded


def test_terraform_proof_pack_cli_runs_and_prints_pass_lines():
    script = (
        Path(__file__).resolve().parents[1] / "demo" / "run_terraform_proof_pack.py"
    )
    out = subprocess.run(
        [sys.executable, str(script)],
        check=True,
        text=True,
        capture_output=True,
    )

    assert "PASS clean_plan_false_positive_control" in out.stdout
    assert "PASS plan_to_apply_effect_drift" in out.stdout
    assert "PASS plan_to_scheduled_destroy_temporal_drift" in out.stdout
    assert "PASS hidden_apply_provider_readback_drift" in out.stdout
    assert "PASS plan_apply_destroy_chain_drift" in out.stdout
