"""Tests for admin identity audit logging."""
import os
import sys
import tempfile
from pathlib import Path

import pytest
from fastapi import HTTPException

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

os.environ["PYTHON_DOTENV_DISABLED"] = "1"
os.environ.pop("DATABASE_URL", None)

TEST_DB = tempfile.mktemp(suffix="_admin_audit_test.db")
os.environ["FIREWALL_DB_PATH"] = TEST_DB

from core import db
from core import admin

ROOT_TOKEN = "root-admin-audit-token"


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


def test_bootstrap_and_scoped_admin_actions_are_attributed():
    operator = admin.create_admin_token(
        admin.CreateAdminTokenRequest(label="audit-operator", role="operator"),
        x_admin_token=ROOT_TOKEN,
    )
    key = admin.create_key(
        admin.CreateKeyRequest(plan="developer", label="audit-key"),
        x_admin_token=operator["raw_token"],
    )

    events = db.list_admin_audit_logs(limit=10)
    create_key_event = next(event for event in events if event["action"] == "api_key.created")
    create_token_event = next(event for event in events if event["action"] == "admin_token.created")

    assert create_key_event["actor_auth_type"] == "scoped_token"
    assert create_key_event["actor_role"] == "operator"
    assert create_key_event["actor_label"] == "audit-operator"
    assert create_key_event["actor_token_prefix"] == operator["token_prefix"]
    assert create_key_event["target_type"] == "api_key"
    assert create_key_event["target_id"] == key["key_prefix"]
    assert create_key_event["details"]["label"] == "audit-key"
    assert key["raw_key"] not in str(create_key_event)
    assert operator["raw_token"] not in str(create_key_event)

    assert create_token_event["actor_auth_type"] == "bootstrap"
    assert create_token_event["actor_role"] == "owner"
    assert create_token_event["target_id"] == operator["token_prefix"]
    assert operator["raw_token"] not in str(create_token_event)


def test_auditor_can_read_admin_audit_but_not_write_actions():
    auditor = admin.create_admin_token(
        admin.CreateAdminTokenRequest(label="audit-reader", role="auditor"),
        x_admin_token=ROOT_TOKEN,
    )

    events = admin.list_admin_audit(x_admin_token=auditor["raw_token"])["events"]
    assert any(event["action"] == "admin_token.created" for event in events)

    with pytest.raises(HTTPException) as exc:
        admin.create_key(
            admin.CreateKeyRequest(plan="free", label="auditor-should-not-write"),
            x_admin_token=auditor["raw_token"],
        )
    assert exc.value.status_code == 403


def test_retention_and_shadow_review_actions_are_logged():
    operator = admin.create_admin_token(
        admin.CreateAdminTokenRequest(label="audit-retention-operator", role="operator"),
        x_admin_token=ROOT_TOKEN,
    )

    admin.update_retention_policy(
        admin.RetentionPolicyRequest(scan_history_days=14),
        x_admin_token=operator["raw_token"],
    )

    with db.get_conn() as conn:
        now = "2026-05-26T00:00:00+00:00"
        cursor = conn.execute(
            "INSERT INTO shadow_mcp_servers (url, first_seen, last_seen) VALUES (?, ?, ?)",
            ("https://shadow.example.com/mcp", now, now),
        )
        server_id = cursor.lastrowid

    admin.review_shadow_server(
        server_id,
        admin.ShadowServerReviewRequest(status="approved", notes="reviewed by security"),
        x_admin_token=operator["raw_token"],
    )

    events = db.list_admin_audit_logs(limit=20)
    assert any(event["action"] == "retention.updated" and event["details"]["updated_fields"] == ["scan_history_days"] for event in events)
    shadow_event = next(event for event in events if event["action"] == "shadow_server.reviewed")
    assert shadow_event["actor_label"] == "audit-retention-operator"
    assert shadow_event["target_id"] == str(server_id)
    assert shadow_event["reason"] == "reviewed by security"
