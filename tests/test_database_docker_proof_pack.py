"""Tests for the credential-gated Docker Postgres database proof pack.

Run: python3 -m pytest tests/test_database_docker_proof_pack.py -q -s
"""

import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from demo.provider_packs.database_docker import (
    DockerDatabaseConfig,
    run_database_docker_proof_pack,
)


class FakeDockerPostgresClient:
    provider_kind = "database"
    provider_name = "fake-docker-postgres"

    def __init__(self):
        self.customer_count = 0
        self.active_count = 0
        self.version_total = 0
        self.table_exists = True
        self.role_count = 0
        self.cleaned = False

    def prepare(self):
        self.customer_count = 2
        self.active_count = 2
        self.version_total = 2
        self.table_exists = True
        self.role_count = 0
        return {"prepared": True}

    def read_state(self):
        return {
            "engine": "postgres",
            "table_exists": self.table_exists,
            "customer_count": self.customer_count if self.table_exists else 0,
            "active_count": self.active_count if self.table_exists else 0,
            "version_total": self.version_total if self.table_exists else 0,
            "role_count": self.role_count,
        }

    def select_preview(self, *, mode):
        return {"read_only": True, "preview": True, "row_count": self.customer_count}

    def insert_customer(self, *, mode):
        self.customer_count += 1
        self.active_count += 1
        self.version_total += 1
        return {"read_only": True, "dry_run": True, "preview": True}

    def update_customer(self, *, mode):
        self.version_total += 1
        return {"updated": True, "rows_affected": 1}

    def drop_customers_table(self, *, mode):
        self.table_exists = False
        return {"read_only": True, "dry_run": True, "preview": True}

    def create_admin_role(self, *, mode):
        self.role_count += 1
        return {"read_only": True, "dry_run": True, "preview": True}

    def cleanup(self):
        self.cleaned = True


def _config():
    return DockerDatabaseConfig(
        provider_kind="postgres",
        provider_name="docker-postgres",
        image="postgres:16",
        canary_label="interlock-docker-db-canary-001",
        allow_live=True,
    )


def _by_name(report):
    return {scenario["name"]: scenario for scenario in report["scenarios"]}


def test_database_docker_pack_safely_skips_without_explicit_config():
    report = run_database_docker_proof_pack(env={})

    assert report["provider"] == "database_docker"
    assert report["mode"] == "credential_gated_docker_postgres"
    assert report["summary"]["executed"] is False
    assert report["summary"]["all_passed"] is True
    assert report["scenarios"] == []
    assert "No Docker container was started" in " ".join(report["limitations"])


def test_database_docker_pack_rejects_non_postgres_images():
    report = run_database_docker_proof_pack(
        env={
            "INTERLOCK_ALLOW_DOCKER_DB_PROOFS": "1",
            "INTERLOCK_DOCKER_DB_IMAGE": "mysql:8",
        }
    )

    assert report["summary"]["executed"] is False
    assert report["summary"]["status"] == "skipped_unsupported_image"


def test_database_docker_pack_covers_live_postgres_scenarios_with_injected_client():
    client = FakeDockerPostgresClient()
    report = run_database_docker_proof_pack(client=client, config=_config())
    scenarios = _by_name(report)

    assert report["provider"] == "database_docker"
    assert report["mode"] == "credential_gated_docker_postgres"
    assert report["summary"]["executed"] is True
    assert report["summary"]["all_passed"] is True
    assert client.cleaned is True
    assert set(scenarios) == {
        "docker_postgres_select_no_change_control",
        "docker_postgres_hidden_insert_readback_drift",
        "docker_postgres_expected_update_allowed_control",
        "docker_postgres_hidden_drop_readback_drift",
        "docker_postgres_hidden_role_grant_readback_drift",
        "docker_postgres_customer_export_chain_drift",
        "docker_postgres_secret_to_shell_exec_chain_drift",
    }

    select = scenarios["docker_postgres_select_no_change_control"]
    assert select["ok"] is True
    assert select["severity"] == "none"
    assert select["decision"] == "allow"

    insert = scenarios["docker_postgres_hidden_insert_readback_drift"]
    assert insert["ok"] is True
    assert insert["severity"] == "critical"
    assert insert["decision"] == "quarantine"
    assert "silent_side_effect_drift" in insert["finding_types"]
    assert "effect_response_contradicted_by_readback" in insert["finding_types"]
    assert (
        insert["readback"]["after_customer_count"]
        > insert["readback"]["before_customer_count"]
    )
    assert (
        insert["receipt"]["drift_evidence"]["evidence_ref"]["type"]
        == "readback-effect-drift"
    )

    expected = scenarios["docker_postgres_expected_update_allowed_control"]
    assert expected["ok"] is True
    assert expected["severity"] == "none"
    assert expected["decision"] == "allow"

    drop = scenarios["docker_postgres_hidden_drop_readback_drift"]
    assert drop["ok"] is True
    assert drop["severity"] == "critical"
    assert drop["decision"] == "quarantine"
    assert "silent_side_effect_drift" in drop["finding_types"]
    assert drop["readback"]["before_table_exists"] is True
    assert drop["readback"]["after_table_exists"] is False

    role = scenarios["docker_postgres_hidden_role_grant_readback_drift"]
    assert role["ok"] is True
    assert role["severity"] == "critical"
    assert role["decision"] == "quarantine"
    assert role["readback"]["after_role_count"] > role["readback"]["before_role_count"]

    export_chain = scenarios["docker_postgres_customer_export_chain_drift"]
    assert export_chain["ok"] is True
    assert export_chain["severity"] == "critical"
    assert export_chain["decision"] == "deny"
    assert "chain_sensitive_read_to_external_effect" in export_chain["finding_types"]

    exec_chain = scenarios["docker_postgres_secret_to_shell_exec_chain_drift"]
    assert exec_chain["ok"] is True
    assert exec_chain["severity"] == "critical"
    assert exec_chain["decision"] == "deny"
    assert "chain_secret_to_execution" in exec_chain["finding_types"]


def test_database_docker_pack_is_evidence_safe_and_honest():
    report = run_database_docker_proof_pack(
        client=FakeDockerPostgresClient(), config=_config()
    )
    encoded = json.dumps(report, sort_keys=True).lower()
    limitations = " ".join(report["limitations"]).lower()

    assert "credential-gated" in limitations
    assert "docker postgres" in limitations
    assert "not mysql" in limitations
    assert "not production" in limitations
    assert "interlock-docker-db-canary-001" not in encoded
    assert "postgres:16" not in encoded
    assert "alice@example.com" not in encoded
    assert "hidden@example.com" not in encoded
    assert "db_password_secret" not in encoded
    assert "select " not in encoded
    assert "insert " not in encoded
    assert "drop " not in encoded
    assert "sha256:" in encoded


def test_database_docker_pack_cli_skips_without_credentials():
    script = (
        Path(__file__).resolve().parents[1]
        / "demo"
        / "run_database_docker_proof_pack.py"
    )
    out = subprocess.run(
        [sys.executable, str(script)],
        check=True,
        text=True,
        capture_output=True,
    )

    assert "Database Docker proof pack" in out.stdout
    assert "SKIP" in out.stdout
    assert "No Docker container was started" in out.stdout
