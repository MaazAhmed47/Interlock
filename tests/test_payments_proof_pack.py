"""Tests for the payments provider proof pack.

Run: python3 -m pytest tests/test_payments_proof_pack.py -q -s
"""

import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from demo.provider_packs.payments import run_payments_proof_pack


def _by_name(report):
    return {scenario["name"]: scenario for scenario in report["scenarios"]}


_VOLATILE_TIME_FIELDS = {"created_at", "timestamp", "timestamp_iso"}


def _without_volatile_timestamps(value):
    if isinstance(value, dict):
        return {
            key: _without_volatile_timestamps(item)
            for key, item in value.items()
            if key not in _VOLATILE_TIME_FIELDS
        }
    if isinstance(value, list):
        return [_without_volatile_timestamps(item) for item in value]
    return value


def test_payments_proof_pack_covers_easy_to_extreme_scenarios():
    report = run_payments_proof_pack()
    scenarios = _by_name(report)

    assert report["provider"] == "payments"
    assert report["mode"] == "local_mock_sandbox"
    assert report["summary"]["all_passed"] is True
    assert set(scenarios) == {
        "quote_preview_false_positive_control",
        "preview_to_charge_effect_drift",
        "preview_to_scheduled_refund_temporal_drift",
        "hidden_charge_provider_readback_drift",
        "expected_charge_allowed_control",
        "payment_method_to_charge_chain_drift",
        "quote_to_transfer_chain_drift",
    }

    clean = scenarios["quote_preview_false_positive_control"]
    assert clean["ok"] is True
    assert clean["severity"] == "none"
    assert clean["decision"] == "allow"
    assert clean["drift_detected"] is False

    charge = scenarios["preview_to_charge_effect_drift"]
    assert charge["ok"] is True
    assert charge["severity"] == "critical"
    assert charge["decision"] == "quarantine"
    assert "effect_money_movement_after_preview" in charge["finding_types"]
    assert charge["receipt"]["drift_evidence"]["evidence_ref"]["type"] == "effect-drift"

    refund = scenarios["preview_to_scheduled_refund_temporal_drift"]
    assert refund["ok"] is True
    assert refund["severity"] == "critical"
    assert refund["decision"] == "quarantine"
    assert "effect_temporal_money_movement_after_preview" in refund["finding_types"]
    assert "effect_money_movement_after_preview" in refund["finding_types"]
    assert refund["receipt"]["drift_evidence"]["evidence_ref"]["type"] == "effect-drift"

    hidden = scenarios["hidden_charge_provider_readback_drift"]
    assert hidden["ok"] is True
    assert hidden["severity"] == "critical"
    assert hidden["decision"] == "quarantine"
    assert "silent_side_effect_drift" in hidden["finding_types"]
    assert "effect_response_contradicted_by_readback" in hidden["finding_types"]
    assert hidden["readback"]["before_ledger_count"] == 0
    assert hidden["readback"]["after_ledger_count"] == 1
    assert (
        hidden["receipt"]["drift_evidence"]["evidence_ref"]["type"]
        == "readback-effect-drift"
    )

    expected = scenarios["expected_charge_allowed_control"]
    assert expected["ok"] is True
    assert expected["severity"] == "none"
    assert expected["decision"] == "allow"

    method_chain = scenarios["payment_method_to_charge_chain_drift"]
    assert method_chain["ok"] is True
    assert method_chain["severity"] == "critical"
    assert method_chain["decision"] == "deny"
    assert "chain_sensitive_read_to_external_effect" in method_chain["finding_types"]
    assert (
        method_chain["receipt"]["drift_evidence"]["evidence_ref"]["type"]
        == "chain-drift"
    )

    transfer_chain = scenarios["quote_to_transfer_chain_drift"]
    assert transfer_chain["ok"] is True
    assert transfer_chain["severity"] == "critical"
    assert transfer_chain["decision"] == "deny"
    assert "chain_preview_to_money_movement" in transfer_chain["finding_types"]
    assert (
        transfer_chain["receipt"]["drift_evidence"]["evidence_ref"]["type"]
        == "chain-drift"
    )


def test_payments_proof_pack_is_evidence_safe_and_honest_about_scope():
    report = run_payments_proof_pack()
    encoded = json.dumps(report, sort_keys=True).lower()
    limitations = " ".join(report["limitations"]).lower()

    assert "local mock" in limitations
    assert "no real payment provider" in limitations
    assert "no stripe" in limitations
    assert "no card" in limitations
    assert "no production" in limitations
    assert "cus_secret" not in encoded
    assert "pm_secret" not in encoded
    assert "ch_secret" not in encoded
    assert "acct_secret" not in encoded

    # The card-number sentinel can appear by chance inside receipt timestamps
    # (for example, microseconds). Keep the payload/evidence scan strict while
    # removing volatile clock fields that are not payment data.
    stable_encoded = json.dumps(
        _without_volatile_timestamps(report), sort_keys=True
    ).lower()
    assert "4242" not in stable_encoded
    assert "sha256:" in encoded


def test_payments_proof_pack_cli_runs_and_prints_pass_lines():
    script = Path(__file__).resolve().parents[1] / "demo" / "run_payments_proof_pack.py"
    out = subprocess.run(
        [sys.executable, str(script)],
        check=True,
        text=True,
        capture_output=True,
    )

    assert "PASS quote_preview_false_positive_control" in out.stdout
    assert "PASS preview_to_charge_effect_drift" in out.stdout
    assert "PASS preview_to_scheduled_refund_temporal_drift" in out.stdout
    assert "PASS hidden_charge_provider_readback_drift" in out.stdout
    assert "PASS expected_charge_allowed_control" in out.stdout
    assert "PASS payment_method_to_charge_chain_drift" in out.stdout
    assert "PASS quote_to_transfer_chain_drift" in out.stdout
    assert "no real payment provider" in out.stdout.lower()
