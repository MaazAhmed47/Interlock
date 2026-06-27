"""Tests for the App Store / release automation provider proof pack.

Run: python3 -m pytest tests/test_app_store_proof_pack.py -q -s
"""

import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from demo.provider_packs.app_store import run_app_store_proof_pack


def _by_name(report):
    return {scenario["name"]: scenario for scenario in report["scenarios"]}


def test_app_store_proof_pack_covers_easy_to_extreme_scenarios():
    report = run_app_store_proof_pack()
    scenarios = _by_name(report)

    assert report["provider"] == "app_store"
    assert report["mode"] == "local_mock_sandbox"
    assert report["summary"]["all_passed"] is True
    assert set(scenarios) == {
        "metadata_preview_false_positive_control",
        "preview_to_submit_effect_drift",
        "preview_to_scheduled_release_temporal_drift",
        "hidden_release_provider_readback_drift",
        "expected_release_allowed_control",
        "metadata_to_pricing_to_submit_chain_drift",
        "tester_pii_to_external_invite_chain_drift",
    }

    clean = scenarios["metadata_preview_false_positive_control"]
    assert clean["ok"] is True
    assert clean["severity"] == "none"
    assert clean["decision"] == "allow"
    assert clean["drift_detected"] is False

    submit = scenarios["preview_to_submit_effect_drift"]
    assert submit["ok"] is True
    assert submit["severity"] == "critical"
    assert submit["decision"] == "quarantine"
    assert "effect_external_send_after_preview" in submit["finding_types"]
    assert submit["receipt"]["drift_evidence"]["evidence_ref"]["type"] == "effect-drift"

    scheduled = scenarios["preview_to_scheduled_release_temporal_drift"]
    assert scheduled["ok"] is True
    assert scheduled["severity"] == "critical"
    assert scheduled["decision"] == "quarantine"
    assert "effect_temporal_deploy_after_preview" in scheduled["finding_types"]
    assert "effect_deploy_after_preview" in scheduled["finding_types"]
    assert (
        scheduled["receipt"]["drift_evidence"]["evidence_ref"]["type"] == "effect-drift"
    )

    hidden = scenarios["hidden_release_provider_readback_drift"]
    assert hidden["ok"] is True
    assert hidden["severity"] == "critical"
    assert hidden["decision"] == "quarantine"
    assert "silent_side_effect_drift" in hidden["finding_types"]
    assert "effect_response_contradicted_by_readback" in hidden["finding_types"]
    assert hidden["readback"]["before_release_count"] == 0
    assert hidden["readback"]["after_release_count"] == 1
    assert (
        hidden["receipt"]["drift_evidence"]["evidence_ref"]["type"]
        == "readback-effect-drift"
    )

    expected = scenarios["expected_release_allowed_control"]
    assert expected["ok"] is True
    assert expected["severity"] == "none"
    assert expected["decision"] == "allow"

    release_chain = scenarios["metadata_to_pricing_to_submit_chain_drift"]
    assert release_chain["ok"] is True
    assert release_chain["severity"] == "critical"
    assert release_chain["decision"] == "deny"
    assert "chain_preview_to_external_effect" in release_chain["finding_types"]
    assert (
        release_chain["receipt"]["drift_evidence"]["evidence_ref"]["type"]
        == "chain-drift"
    )

    invite_chain = scenarios["tester_pii_to_external_invite_chain_drift"]
    assert invite_chain["ok"] is True
    assert invite_chain["severity"] == "critical"
    assert invite_chain["decision"] == "deny"
    assert "chain_sensitive_read_to_external_effect" in invite_chain["finding_types"]
    assert (
        invite_chain["receipt"]["drift_evidence"]["evidence_ref"]["type"]
        == "chain-drift"
    )


def test_app_store_proof_pack_is_evidence_safe_and_honest_about_scope():
    report = run_app_store_proof_pack()
    encoded = json.dumps(report, sort_keys=True).lower()
    limitations = " ".join(report["limitations"]).lower()

    assert "local mock" in limitations
    assert "no app store connect" in limitations
    assert "no apple account" in limitations
    assert "no production app" in limitations
    assert "sandbox app" in limitations
    assert "app_secret" not in encoded
    assert "build_secret" not in encoded
    assert "tester@example.com" not in encoded
    assert "api_key_secret" not in encoded
    assert "sha256:" in encoded


def test_app_store_proof_pack_cli_runs_and_prints_pass_lines():
    script = (
        Path(__file__).resolve().parents[1] / "demo" / "run_app_store_proof_pack.py"
    )
    out = subprocess.run(
        [sys.executable, str(script)],
        check=True,
        text=True,
        capture_output=True,
    )

    assert "PASS metadata_preview_false_positive_control" in out.stdout
    assert "PASS preview_to_submit_effect_drift" in out.stdout
    assert "PASS preview_to_scheduled_release_temporal_drift" in out.stdout
    assert "PASS hidden_release_provider_readback_drift" in out.stdout
    assert "PASS expected_release_allowed_control" in out.stdout
    assert "PASS metadata_to_pricing_to_submit_chain_drift" in out.stdout
    assert "PASS tester_pii_to_external_invite_chain_drift" in out.stdout
    assert "no app store connect" in out.stdout.lower()
