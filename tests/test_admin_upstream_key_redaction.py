"""Admin API responses must never disclose stored upstream credentials."""

import json
import logging
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from core import admin, db
from proxy import app

ROOT_TOKEN = "root-upstream-redaction-test-token"
UPSTREAM_SECRET = "sk-upstream-regression-secret-never-serialize"
COLLIDING_TOKENS = (
    "sameAAAAAAAAAAAAAAAAAAAA",
    "sameBBBBBBBBBBBBBBBBBBBB",
)


@pytest.fixture()
def sqlite_key_db(tmp_path, monkeypatch):
    old_path = db.DB_PATH
    old_use_postgres = db.USE_POSTGRES
    old_admin_token = admin.ADMIN_TOKEN
    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "upstream-redaction.db"))
    monkeypatch.setattr(db, "USE_POSTGRES", False)
    monkeypatch.setattr(admin, "ADMIN_TOKEN", ROOT_TOKEN)
    db.init_db()
    yield
    db.DB_PATH = old_path
    db.USE_POSTGRES = old_use_postgres
    admin.ADMIN_TOKEN = old_admin_token


def _serialized(value) -> str:
    return json.dumps(value, sort_keys=True, default=str)


def test_seeded_upstream_credential_stays_inside_server_side_lookup(
    sqlite_key_db, caplog
):
    caplog.set_level(logging.INFO)
    with patch("core.db.secrets.token_urlsafe", side_effect=COLLIDING_TOKENS):
        secret_key = db.generate_key(
            "free",
            label="secret-bearing",
            upstream_key=UPSTREAM_SECRET,
            scopes=["audit.read", "audit.export"],
        )
        colliding_key = db.generate_key("free", label="collision-control")

    # Trusted internal lookups retain the configured credential for any
    # server-side forwarding consumer. Public/admin representations must not.
    assert db.lookup_key(secret_key["raw_key"])["upstream_key"] == UPSTREAM_SECRET

    client = TestClient(app)
    headers = {"x-admin-token": ROOT_TOKEN}

    listed = client.get("/admin/keys?include_inactive=true", headers=headers)
    assert listed.status_code == 200
    assert UPSTREAM_SECRET not in listed.text
    row = next(item for item in listed.json()["keys"] if item["id"] == secret_key["id"])
    assert "upstream_key" not in row
    assert row["upstream_key_configured"] is True
    assert "key_hash" not in row
    assert "raw_key" not in row

    # Canonical usage is another API-key read path. The legacy collision also
    # exercises an error response built after inspecting secret-bearing rows.
    db.log_usage(secret_key["id"], "/secret-key-usage", False)
    usage = client.get(f"/admin/keys/id/{secret_key['id']}/usage", headers=headers)
    assert usage.status_code == 200
    assert UPSTREAM_SECRET not in usage.text

    ambiguous = client.get(
        f"/admin/keys/{secret_key['key_prefix']}/usage", headers=headers
    )
    assert ambiguous.status_code == 409
    assert secret_key["key_prefix"] == colliding_key["key_prefix"]
    assert UPSTREAM_SECRET not in ambiguous.text

    # A benign update forces an audit event after the secret-bearing row is
    # selected. Neither audit details nor chain verification may carry it.
    updated = client.patch(
        f"/admin/keys/id/{secret_key['id']}",
        headers=headers,
        json={"label": "secret-bearing-updated"},
    )
    assert updated.status_code == 200
    audit = client.get("/admin/audit", headers=headers)
    assert audit.status_code == 200
    assert UPSTREAM_SECRET not in audit.text
    verified = client.get("/admin/audit/verify", headers=headers)
    assert verified.status_code == 200
    assert UPSTREAM_SECRET not in verified.text

    # Security Receipts are built only from MCP audit rows, but their auth path
    # still resolves this secret-bearing key. Exercise both success and error
    # responses to keep that boundary under regression coverage.
    receipt_export = client.get(
        "/audit/receipt/export", headers={"x-api-key": secret_key["raw_key"]}
    )
    assert receipt_export.status_code == 200
    assert UPSTREAM_SECRET not in receipt_export.text
    receipt_error = client.get(
        "/audit/receipt/export?format=unsupported",
        headers={"x-api-key": secret_key["raw_key"]},
    )
    assert receipt_error.status_code == 400
    assert UPSTREAM_SECRET not in receipt_error.text

    assert UPSTREAM_SECRET not in caplog.text
    assert UPSTREAM_SECRET not in _serialized(db.list_admin_audit_logs(limit=20))
