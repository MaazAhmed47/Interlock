"""Tests for scoped admin tokens and admin RBAC."""
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

TEST_DB = tempfile.mktemp(suffix="_admin_rbac_test.db")
os.environ["FIREWALL_DB_PATH"] = TEST_DB

from core import db
from core import admin

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
        admin.CreateAdminTokenRequest(label="bootstrap-removed-operator", role="operator"),
        x_admin_token=ROOT_TOKEN,
    )
    old_admin_token = admin.ADMIN_TOKEN
    admin.ADMIN_TOKEN = ""
    try:
        keys = admin.list_all_keys(x_admin_token=operator["raw_token"])
        assert "keys" in keys
    finally:
        admin.ADMIN_TOKEN = old_admin_token
