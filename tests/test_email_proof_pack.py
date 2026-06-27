"""Tests for the email/messaging provider proof pack.

Run: python3 -m pytest tests/test_email_proof_pack.py -q -s
"""

import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from demo.provider_packs.email import run_email_proof_pack


def _by_name(report):
    return {scenario["name"]: scenario for scenario in report["scenarios"]}


def test_email_proof_pack_covers_easy_to_extreme_scenarios():
    report = run_email_proof_pack()
    scenarios = _by_name(report)

    assert report["provider"] == "email_messaging"
    assert report["mode"] == "local_mock_sandbox"
    assert report["summary"]["all_passed"] is True
    assert set(scenarios) == {
        "clean_draft_false_positive_control",
        "draft_to_sent_effect_drift",
        "draft_to_scheduled_send_temporal_drift",
        "recipient_domain_external_reach_drift",
        "hidden_send_provider_readback_drift",
        "read_inbox_to_slack_chain_drift",
    }

    clean = scenarios["clean_draft_false_positive_control"]
    assert clean["ok"] is True
    assert clean["severity"] == "none"
    assert clean["decision"] == "allow"
    assert clean["drift_detected"] is False

    sent = scenarios["draft_to_sent_effect_drift"]
    assert sent["ok"] is True
    assert sent["severity"] == "critical"
    assert sent["decision"] == "quarantine"
    assert "effect_external_send_after_preview" in sent["finding_types"]
    assert sent["receipt"]["drift_evidence"]["evidence_ref"]["type"] == "effect-drift"

    temporal = scenarios["draft_to_scheduled_send_temporal_drift"]
    assert temporal["ok"] is True
    assert temporal["severity"] == "critical"
    assert temporal["decision"] == "quarantine"
    assert "effect_temporal_external_after_preview" in temporal["finding_types"]
    assert "effect_external_send_after_preview" in temporal["finding_types"]
    assert (
        temporal["receipt"]["drift_evidence"]["evidence_ref"]["type"] == "effect-drift"
    )

    reach = scenarios["recipient_domain_external_reach_drift"]
    assert reach["ok"] is True
    assert reach["severity"] == "critical"
    assert reach["decision"] == "quarantine"
    assert "external_secret_destination_added" in reach["finding_types"]
    assert (
        reach["receipt"]["drift_evidence"]["evidence_ref"]["type"]
        == "external-reach-drift"
    )

    readback = scenarios["hidden_send_provider_readback_drift"]
    assert readback["ok"] is True
    assert readback["severity"] == "critical"
    assert readback["decision"] == "quarantine"
    assert "silent_side_effect_drift" in readback["finding_types"]
    assert "effect_response_contradicted_by_readback" in readback["finding_types"]
    assert (
        readback["receipt"]["drift_evidence"]["evidence_ref"]["type"]
        == "readback-effect-drift"
    )

    chain = scenarios["read_inbox_to_slack_chain_drift"]
    assert chain["ok"] is True
    assert chain["severity"] == "critical"
    assert chain["decision"] == "deny"
    assert "chain_sensitive_read_to_external_effect" in chain["finding_types"]
    assert chain["receipt"]["drift_evidence"]["evidence_ref"]["type"] == "chain-drift"


def test_email_proof_pack_is_evidence_safe_and_honest_about_scope():
    report = run_email_proof_pack()
    encoded = json.dumps(report, sort_keys=True)
    limitations = " ".join(report["limitations"]).lower()

    assert "local mock" in limitations
    assert "no gmail" in limitations
    assert "no icloud" in limitations
    assert "no fastmail" in limitations
    assert "no smtp credentials" in limitations
    assert "person@example.com" not in encoded
    assert "vip@example.com" not in encoded
    assert "secret-channel" not in encoded
    assert "message-secret" not in encoded
    assert "body-secret" not in encoded
    assert "sha256:" in encoded


def test_email_proof_pack_cli_runs_and_prints_pass_lines():
    script = Path(__file__).resolve().parents[1] / "demo" / "run_email_proof_pack.py"
    out = subprocess.run(
        [sys.executable, str(script)],
        check=True,
        text=True,
        capture_output=True,
    )

    assert "PASS clean_draft_false_positive_control" in out.stdout
    assert "PASS draft_to_sent_effect_drift" in out.stdout
    assert "PASS draft_to_scheduled_send_temporal_drift" in out.stdout
    assert "PASS recipient_domain_external_reach_drift" in out.stdout
    assert "PASS hidden_send_provider_readback_drift" in out.stdout
    assert "PASS read_inbox_to_slack_chain_drift" in out.stdout
