"""Tests for the database/admin-SaaS provider proof pack.

Run: python3 -m pytest tests/test_database_admin_proof_pack.py -q -s
"""

import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from demo.provider_packs.database_admin import run_database_admin_proof_pack


def _by_name(report):
    return {scenario["name"]: scenario for scenario in report["scenarios"]}


def test_database_admin_pack_covers_easy_to_extreme_scenarios():
    report = run_database_admin_proof_pack()
    scenarios = _by_name(report)

    assert report["provider"] == "database_admin"
    assert report["mode"] == "local_sqlite_sandbox"
    assert report["summary"]["all_passed"] is True
    assert set(scenarios) == {
        "readonly_select_false_positive_control",
        "select_to_update_effect_drift",
        "select_to_drop_table_destructive_drift",
        "readonly_to_scheduled_privilege_change_temporal_drift",
        "hidden_db_write_readback_drift",
        "expected_db_write_allowed_control",
        "customer_data_to_external_export_chain_drift",
        "db_secret_to_shell_exec_chain_drift",
        "admin_directory_to_disable_user_chain_drift",
    }

    clean = scenarios["readonly_select_false_positive_control"]
    assert clean["ok"] is True
    assert clean["severity"] == "none"
    assert clean["decision"] == "allow"
    assert clean["drift_detected"] is False

    update = scenarios["select_to_update_effect_drift"]
    assert update["ok"] is True
    assert update["severity"] == "high"
    assert update["decision"] == "quarantine"
    assert "effect_mutation_after_preview" in update["finding_types"]
    assert update["receipt"]["drift_evidence"]["evidence_ref"]["type"] == "effect-drift"

    drop = scenarios["select_to_drop_table_destructive_drift"]
    assert drop["ok"] is True
    assert drop["severity"] == "critical"
    assert drop["decision"] == "quarantine"
    assert "effect_destructive_after_preview" in drop["finding_types"]
    assert drop["receipt"]["drift_evidence"]["evidence_ref"]["type"] == "effect-drift"

    privilege = scenarios["readonly_to_scheduled_privilege_change_temporal_drift"]
    assert privilege["ok"] is True
    assert privilege["severity"] == "high"
    assert privilege["decision"] == "quarantine"
    assert "effect_temporal_action_after_preview" in privilege["finding_types"]

    hidden = scenarios["hidden_db_write_readback_drift"]
    assert hidden["ok"] is True
    assert hidden["severity"] == "critical"
    assert hidden["decision"] == "quarantine"
    assert "silent_side_effect_drift" in hidden["finding_types"]
    assert "effect_response_contradicted_by_readback" in hidden["finding_types"]
    assert hidden["readback"]["before_customer_count"] == 2
    assert hidden["readback"]["after_customer_count"] == 3
    assert (
        hidden["receipt"]["drift_evidence"]["evidence_ref"]["type"]
        == "readback-effect-drift"
    )

    expected = scenarios["expected_db_write_allowed_control"]
    assert expected["ok"] is True
    assert expected["severity"] == "none"
    assert expected["decision"] == "allow"

    export_chain = scenarios["customer_data_to_external_export_chain_drift"]
    assert export_chain["ok"] is True
    assert export_chain["severity"] == "critical"
    assert export_chain["decision"] == "deny"
    assert "chain_sensitive_read_to_external_effect" in export_chain["finding_types"]
    assert (
        export_chain["receipt"]["drift_evidence"]["evidence_ref"]["type"]
        == "chain-drift"
    )

    exec_chain = scenarios["db_secret_to_shell_exec_chain_drift"]
    assert exec_chain["ok"] is True
    assert exec_chain["severity"] == "critical"
    assert exec_chain["decision"] == "deny"
    assert "chain_secret_to_execution" in exec_chain["finding_types"]

    disable_chain = scenarios["admin_directory_to_disable_user_chain_drift"]
    assert disable_chain["ok"] is True
    assert disable_chain["severity"] == "critical"
    assert disable_chain["decision"] == "deny"
    assert "chain_sensitive_read_to_external_effect" in disable_chain["finding_types"]


def test_database_admin_pack_is_evidence_safe_and_honest_about_scope():
    report = run_database_admin_proof_pack()
    encoded = json.dumps(report, sort_keys=True).lower()
    limitations = " ".join(report["limitations"]).lower()

    assert "local sqlite" in limitations
    assert "no remote database" in limitations
    assert "no production" in limitations
    assert "no mysql" in limitations
    assert "no postgres" in limitations
    assert "alice@example.com" not in encoded
    assert "bob@example.com" not in encoded
    assert "db_password_secret" not in encoded
    assert "sk_admin_secret" not in encoded
    assert "drop table" not in encoded
    assert "update customers" not in encoded
    assert "sha256:" in encoded


def test_database_admin_pack_cli_runs_and_prints_pass_lines():
    script = (
        Path(__file__).resolve().parents[1]
        / "demo"
        / "run_database_admin_proof_pack.py"
    )
    out = subprocess.run(
        [sys.executable, str(script)],
        check=True,
        text=True,
        capture_output=True,
    )

    assert "PASS readonly_select_false_positive_control" in out.stdout
    assert "PASS select_to_update_effect_drift" in out.stdout
    assert "PASS select_to_drop_table_destructive_drift" in out.stdout
    assert "PASS readonly_to_scheduled_privilege_change_temporal_drift" in out.stdout
    assert "PASS hidden_db_write_readback_drift" in out.stdout
    assert "PASS expected_db_write_allowed_control" in out.stdout
    assert "PASS customer_data_to_external_export_chain_drift" in out.stdout
    assert "PASS db_secret_to_shell_exec_chain_drift" in out.stdout
    assert "PASS admin_directory_to_disable_user_chain_drift" in out.stdout
    assert "no remote database" in out.stdout.lower()
