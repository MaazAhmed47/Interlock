"""Tests for the credential-gated Stripe test-mode payments proof pack.

Run: python3 -m pytest tests/test_payments_live_proof_pack.py -q -s
"""

import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from demo.provider_packs.payments_live import (
    LivePaymentsConfig,
    run_payments_live_proof_pack,
)


class FakeStripeClient:
    provider_kind = "stripe"
    provider_name = "fake-stripe-test-mode"

    def __init__(self):
        self.ledger = []

    def read_state(self):
        return {
            "ledger_count": len(self.ledger),
            "entries": [
                {"id": item["id"], "kind": item["kind"]} for item in self.ledger
            ],
        }

    def create_quote_preview(self, *, mode):
        return {"preview": True, "quote": True, "estimated_amount": 100}

    def create_charge(self, *, mode):
        item = {"id": f"pi_secret_{mode}_{len(self.ledger)}", "kind": "charge"}
        self.ledger.append(item)
        return {"charged": True, "id_hash": "sha256:" + "a" * 64}

    def create_refund(self, *, mode):
        item = {"id": f"re_secret_{mode}_{len(self.ledger)}", "kind": "refund"}
        self.ledger.append(item)
        return {"refunded": True, "id_hash": "sha256:" + "b" * 64}

    def cleanup(self):
        self.ledger.clear()


def _config():
    return LivePaymentsConfig(
        provider_kind="stripe",
        provider_name="stripe-test-mode",
        canary_label="interlock-stripe-canary-001",
        allow_live=True,
    )


def _by_name(report):
    return {scenario["name"]: scenario for scenario in report["scenarios"]}


def test_payments_live_pack_safely_skips_without_explicit_config():
    report = run_payments_live_proof_pack(env={})

    assert report["provider"] == "payments"
    assert report["mode"] == "credential_gated_stripe_test_mode"
    assert report["summary"]["executed"] is False
    assert report["summary"]["all_passed"] is True
    assert report["scenarios"] == []
    assert "No payment provider was contacted" in " ".join(report["limitations"])


def test_payments_live_pack_rejects_live_mode_keys():
    report = run_payments_live_proof_pack(
        env={
            "INTERLOCK_ALLOW_LIVE_PAYMENTS_PROOFS": "1",
            "INTERLOCK_STRIPE_SECRET_KEY": "sk_live_secret",
        }
    )

    assert report["summary"]["executed"] is False
    assert report["summary"]["status"] == "skipped_non_test_mode_key"
    assert report["summary"]["all_passed"] is True


def test_payments_live_pack_covers_stripe_test_mode_with_injected_client():
    report = run_payments_live_proof_pack(client=FakeStripeClient(), config=_config())
    scenarios = _by_name(report)

    assert report["provider"] == "payments"
    assert report["mode"] == "credential_gated_stripe_test_mode"
    assert report["summary"]["executed"] is True
    assert report["summary"]["all_passed"] is True
    assert set(scenarios) == {
        "live_stripe_quote_no_change_control",
        "live_stripe_hidden_charge_readback_drift",
        "live_stripe_expected_charge_allowed_control",
        "live_stripe_hidden_refund_readback_drift",
        "live_stripe_payment_method_to_charge_chain_drift",
        "live_stripe_quote_to_transfer_chain_drift",
    }

    quote = scenarios["live_stripe_quote_no_change_control"]
    assert quote["ok"] is True
    assert quote["severity"] == "none"
    assert quote["decision"] == "allow"

    hidden_charge = scenarios["live_stripe_hidden_charge_readback_drift"]
    assert hidden_charge["ok"] is True
    assert hidden_charge["severity"] == "critical"
    assert hidden_charge["decision"] == "quarantine"
    assert "silent_side_effect_drift" in hidden_charge["finding_types"]
    assert "effect_response_contradicted_by_readback" in hidden_charge["finding_types"]
    assert (
        hidden_charge["readback"]["after_ledger_count"]
        > hidden_charge["readback"]["before_ledger_count"]
    )
    assert (
        hidden_charge["receipt"]["drift_evidence"]["evidence_ref"]["type"]
        == "readback-effect-drift"
    )

    expected_charge = scenarios["live_stripe_expected_charge_allowed_control"]
    assert expected_charge["ok"] is True
    assert expected_charge["severity"] == "none"
    assert expected_charge["decision"] == "allow"

    hidden_refund = scenarios["live_stripe_hidden_refund_readback_drift"]
    assert hidden_refund["ok"] is True
    assert hidden_refund["severity"] == "critical"
    assert hidden_refund["decision"] == "quarantine"
    assert "silent_side_effect_drift" in hidden_refund["finding_types"]

    method_chain = scenarios["live_stripe_payment_method_to_charge_chain_drift"]
    assert method_chain["ok"] is True
    assert method_chain["severity"] == "critical"
    assert method_chain["decision"] == "deny"
    assert "chain_sensitive_read_to_external_effect" in method_chain["finding_types"]

    transfer_chain = scenarios["live_stripe_quote_to_transfer_chain_drift"]
    assert transfer_chain["ok"] is True
    assert transfer_chain["severity"] == "critical"
    assert transfer_chain["decision"] == "deny"
    assert "chain_preview_to_money_movement" in transfer_chain["finding_types"]


def test_payments_live_pack_is_evidence_safe_and_honest():
    report = run_payments_live_proof_pack(client=FakeStripeClient(), config=_config())
    encoded = json.dumps(report, sort_keys=True).lower()
    limitations = " ".join(report["limitations"]).lower()

    assert "credential-gated" in limitations
    assert "test-mode" in limitations
    assert "no live-mode" in limitations
    assert "not pci" in limitations
    assert "interlock-stripe-canary-001" not in encoded
    assert "pi_secret" not in encoded
    assert "re_secret" not in encoded
    assert "cus_secret" not in encoded
    assert "pm_secret" not in encoded
    assert "sk_test_secret" not in encoded
    assert "sk_live_secret" not in encoded
    assert "sha256:" in encoded


def test_payments_live_pack_cli_skips_without_credentials():
    script = (
        Path(__file__).resolve().parents[1] / "demo" / "run_payments_live_proof_pack.py"
    )
    out = subprocess.run(
        [sys.executable, str(script)],
        check=True,
        text=True,
        capture_output=True,
    )

    assert "Payments live proof pack" in out.stdout
    assert "SKIP" in out.stdout
    assert "No payment provider was contacted" in out.stdout
