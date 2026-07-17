"""Tests for scoped admin tokens and admin RBAC."""

import json
import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi import HTTPException

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

os.environ["PYTHON_DOTENV_DISABLED"] = "1"
os.environ.pop("DATABASE_URL", None)

TEST_DB = tempfile.mktemp(suffix="_admin_rbac_test.db")
os.environ["FIREWALL_DB_PATH"] = TEST_DB

from core import admin  # noqa: E402
from core import db  # noqa: E402

ROOT_TOKEN = "root-admin-test-token"


@pytest.fixture(scope="module", autouse=True)
def setup_db():
    old_db_path = db.DB_PATH
    old_admin_token = admin.ADMIN_TOKEN
    db.DB_PATH = TEST_DB
    admin.ADMIN_TOKEN = ROOT_TOKEN
    db.init_db()
    yield
    db.DB_PATH = old_db_path
    admin.ADMIN_TOKEN = old_admin_token
    for path in (TEST_DB, TEST_DB + "-wal", TEST_DB + "-shm"):
        try:
            os.unlink(path)
        except OSError:
            pass


def test_bootstrap_root_creates_owner_token_and_hash_is_hidden():
    created = admin.create_admin_token(
        admin.CreateAdminTokenRequest(label="platform-owner", role="owner"),
        x_admin_token=ROOT_TOKEN,
    )

    assert created["raw_token"].startswith("ia_")
    assert created["permissions"] == ["*"]

    listed = admin.list_admin_tokens(x_admin_token=created["raw_token"])["tokens"]
    assert any(row["token_prefix"] == created["token_prefix"] for row in listed)
    assert all("token_hash" not in row for row in listed)
    assert all(row.get("raw_token") != created["raw_token"] for row in listed)


def test_operator_can_manage_customer_keys_but_not_admin_tokens():
    operator = admin.create_admin_token(
        admin.CreateAdminTokenRequest(label="pilot-operator", role="operator"),
        x_admin_token=ROOT_TOKEN,
    )

    key = admin.create_key(
        admin.CreateKeyRequest(plan="developer", label="operator-created"),
        x_admin_token=operator["raw_token"],
    )
    assert key["raw_key"].startswith("lf_developer_")

    listed = admin.list_all_keys(x_admin_token=operator["raw_token"])["keys"]
    assert any(row["key_prefix"] == key["key_prefix"] for row in listed)

    with pytest.raises(HTTPException) as exc:
        admin.create_admin_token(
            admin.CreateAdminTokenRequest(label="should-fail", role="auditor"),
            x_admin_token=operator["raw_token"],
        )
    assert exc.value.status_code == 403


def test_auditor_is_read_only():
    auditor = admin.create_admin_token(
        admin.CreateAdminTokenRequest(label="audit-review", role="auditor"),
        x_admin_token=ROOT_TOKEN,
    )

    keys = admin.list_all_keys(x_admin_token=auditor["raw_token"])
    assert "keys" in keys

    retention = admin.get_retention_policy(x_admin_token=auditor["raw_token"])
    assert "policy" in retention

    with pytest.raises(HTTPException) as exc:
        admin.create_key(
            admin.CreateKeyRequest(plan="free", label="auditor-should-not-create"),
            x_admin_token=auditor["raw_token"],
        )
    assert exc.value.status_code == 403

    with pytest.raises(HTTPException) as exc:
        admin.update_retention_policy(
            admin.RetentionPolicyRequest(scan_history_days=7),
            x_admin_token=auditor["raw_token"],
        )
    assert exc.value.status_code == 403


def test_retention_checkpoint_actor_projection_excludes_email_and_extra_claims():
    email = "operator@example.test"
    context = admin.AdminContext(
        auth_type="oidc",
        role="operator",
        label=email,
        permissions={"retention:write"},
        subject="oidc-principal-123",
        email=email,
    )

    actor = admin._retention_checkpoint_actor_fields(context)

    assert actor == {
        "actor_auth_type": "oidc",
        "actor_role": "operator",
        "actor_subject": "oidc-principal-123",
    }
    assert email not in json.dumps(actor)


def test_prune_retention_binds_authenticated_actor_to_checkpoint(tmp_path):
    old_db_path = db.DB_PATH
    db.DB_PATH = str(tmp_path / "retention_actor.db")
    try:
        db.init_db()
        operator = db.generate_admin_token(label="retention-operator", role="operator")
        old_ts = (datetime.now(timezone.utc) - timedelta(days=40)).isoformat()
        current_ts = datetime.now(timezone.utc).isoformat()
        db.log_mcp_audit_event(
            {
                "ts": old_ts,
                "server_id": "retention-test",
                "tool_name": "old-tool",
                "role": "readonly_agent",
                "action": "allow",
            }
        )
        db.log_mcp_audit_event(
            {
                "ts": current_ts,
                "server_id": "retention-test",
                "tool_name": "current-tool",
                "role": "readonly_agent",
                "action": "allow",
            }
        )
        db.log_admin_audit_event(
            {
                "ts": old_ts,
                "actor_auth_type": "bootstrap",
                "actor_role": "owner",
                "action": "old-admin-event",
            }
        )
        db.log_admin_audit_event(
            {
                "ts": current_ts,
                "actor_auth_type": "bootstrap",
                "actor_role": "owner",
                "action": "current-admin-event",
            }
        )
        db.set_retention_policy(
            {
                "scan_history_days": 30,
                "mcp_audit_days": 30,
                "admin_audit_days": 30,
                "usage_log_days": 30,
            }
        )

        result = admin.prune_retention(x_admin_token=operator["raw_token"])

        assert result["mcp_audit_deleted"] == 1
        assert result["admin_audit_deleted"] == 1
        expected_actor = {
            "actor_auth_type": "scoped_token",
            "actor_role": "operator",
            "actor_token_prefix": operator["token_prefix"],
        }
        with db.get_conn() as conn:
            checkpoints = conn.execute(
                "SELECT chain, actor FROM audit_chain_checkpoints ORDER BY chain"
            ).fetchall()
            audit_row = conn.execute("""
                SELECT actor_auth_type, actor_role, actor_label, actor_email,
                       actor_subject, actor_token_prefix, action
                  FROM admin_audit_log
                 WHERE action = 'retention.pruned'
                 ORDER BY id DESC
                 LIMIT 1
                """).fetchone()
        assert {row["chain"]: json.loads(row["actor"]) for row in checkpoints} == {
            "admin_audit_log": expected_actor,
            "mcp_audit_log": expected_actor,
        }
        assert all(operator["raw_token"] not in row["actor"] for row in checkpoints)
        assert dict(audit_row) == {
            **expected_actor,
            "actor_label": "",
            "actor_email": "",
            "actor_subject": "",
            "action": "retention.pruned",
        }
        assert operator["raw_token"] not in json.dumps(dict(audit_row))
        assert db.verify_audit_chain()["valid"] is True
    finally:
        db.DB_PATH = old_db_path


def test_revoked_admin_token_is_rejected():
    token = admin.create_admin_token(
        admin.CreateAdminTokenRequest(label="temporary-operator", role="operator"),
        x_admin_token=ROOT_TOKEN,
    )
    result = admin.revoke_admin_token(token["token_prefix"], x_admin_token=ROOT_TOKEN)
    assert result["ok"] is True

    with pytest.raises(HTTPException) as exc:
        admin.list_all_keys(x_admin_token=token["raw_token"])
    assert exc.value.status_code == 401


def test_scoped_token_still_works_after_bootstrap_token_removed():
    operator = admin.create_admin_token(
        admin.CreateAdminTokenRequest(
            label="bootstrap-removed-operator", role="operator"
        ),
        x_admin_token=ROOT_TOKEN,
    )
    old_admin_token = admin.ADMIN_TOKEN
    admin.ADMIN_TOKEN = ""
    try:
        keys = admin.list_all_keys(x_admin_token=operator["raw_token"])
        assert "keys" in keys
    finally:
        admin.ADMIN_TOKEN = old_admin_token
