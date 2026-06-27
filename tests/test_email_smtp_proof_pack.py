"""Tests for the real local SMTP email/messaging provider proof pack.

Run: python3 -m pytest tests/test_email_smtp_proof_pack.py -q -s
"""

import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from demo.provider_packs.email_smtp import run_email_smtp_proof_pack


def _by_name(report):
    return {scenario["name"]: scenario for scenario in report["scenarios"]}


def test_email_smtp_proof_pack_uses_real_local_smtp_readback():
    report = run_email_smtp_proof_pack()
    scenarios = _by_name(report)

    assert report["provider"] == "email_messaging"
    assert report["mode"] == "real_local_smtp_sandbox"
    assert report["summary"]["all_passed"] is True
    assert set(scenarios) == {
        "smtp_preview_no_send_control",
        "smtp_hidden_send_readback_drift",
        "smtp_expected_send_allowed_control",
    }

    preview = scenarios["smtp_preview_no_send_control"]
    assert preview["ok"] is True
    assert preview["severity"] == "none"
    assert preview["decision"] == "allow"
    assert preview["drift_detected"] is False

    hidden = scenarios["smtp_hidden_send_readback_drift"]
    assert hidden["ok"] is True
    assert hidden["severity"] == "critical"
    assert hidden["decision"] == "quarantine"
    assert "silent_side_effect_drift" in hidden["finding_types"]
    assert "effect_response_contradicted_by_readback" in hidden["finding_types"]
    assert (
        hidden["receipt"]["drift_evidence"]["evidence_ref"]["type"]
        == "readback-effect-drift"
    )

    allowed = scenarios["smtp_expected_send_allowed_control"]
    assert allowed["ok"] is True
    assert allowed["severity"] == "none"
    assert allowed["decision"] == "allow"
    assert allowed["drift_detected"] is False


def test_email_smtp_proof_pack_is_evidence_safe_and_honest_about_scope():
    report = run_email_smtp_proof_pack()
    encoded = json.dumps(report, sort_keys=True)
    limitations = " ".join(report["limitations"]).lower()

    assert "real local smtp" in limitations
    assert "no gmail" in limitations
    assert "no icloud" in limitations
    assert "no fastmail" in limitations
    assert "no external email" in limitations
    assert "sender@example.test" not in encoded
    assert "recipient@example.test" not in encoded
    assert "smtp-body-secret" not in encoded
    assert "smtp-message-secret" not in encoded
    assert "sha256:" in encoded


def test_email_smtp_proof_pack_cli_runs_and_prints_pass_lines():
    script = (
        Path(__file__).resolve().parents[1] / "demo" / "run_email_smtp_proof_pack.py"
    )
    out = subprocess.run(
        [sys.executable, str(script)],
        check=True,
        text=True,
        capture_output=True,
    )

    assert "PASS smtp_preview_no_send_control" in out.stdout
    assert "PASS smtp_hidden_send_readback_drift" in out.stdout
    assert "PASS smtp_expected_send_allowed_control" in out.stdout
