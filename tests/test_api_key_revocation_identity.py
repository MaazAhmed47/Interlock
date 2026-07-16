"""API-key revocation must use an immutable row identity, not a display prefix."""

from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from core import admin, db
from proxy import app

ROOT_TOKEN = "root-key-identity-test-token"
COLLIDING_TOKENS = (
    "sameAAAAAAAAAAAAAAAAAAAA",
    "sameBBBBBBBBBBBBBBBBBBBB",
)


@pytest.fixture()
def sqlite_key_db(tmp_path, monkeypatch):
    old_path = db.DB_PATH
    old_use_postgres = db.USE_POSTGRES
    old_admin_token = admin.ADMIN_TOKEN
    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "api-key-identity.db"))
    monkeypatch.setattr(db, "USE_POSTGRES", False)
    monkeypatch.setattr(admin, "ADMIN_TOKEN", ROOT_TOKEN)
    db.init_db()
    yield
    db.DB_PATH = old_path
    db.USE_POSTGRES = old_use_postgres
    admin.ADMIN_TOKEN = old_admin_token


def _generate_colliding_keys():
    with patch("core.db.secrets.token_urlsafe", side_effect=COLLIDING_TOKENS):
        first = db.generate_key("free", label="collision-first")
        second = db.generate_key("free", label="collision-second")
    assert first["key_prefix"] == second["key_prefix"] == "lf_free_same"
    return first, second


def test_legacy_prefix_revoke_rejects_ambiguity_without_revoking(sqlite_key_db):
    first, second = _generate_colliding_keys()

    with pytest.raises(db.AmbiguousKeyPrefixError) as exc:
        db.revoke_key(first["key_prefix"])

    assert exc.value.match_count == 2
    assert db.lookup_key(first["raw_key"]) is not None
    assert db.lookup_key(second["raw_key"]) is not None


def test_id_revoke_deactivates_only_the_selected_key(sqlite_key_db):
    first, second = _generate_colliding_keys()

    revoked = db.revoke_key_by_id(first["id"])

    assert revoked == {"id": first["id"], "key_prefix": first["key_prefix"]}
    assert db.lookup_key(first["raw_key"]) is None
    assert db.lookup_key(second["raw_key"]) is not None


def test_admin_api_lists_and_revokes_by_id(sqlite_key_db):
    client = TestClient(app)
    headers = {"x-admin-token": ROOT_TOKEN}
    with patch("core.db.secrets.token_urlsafe", side_effect=COLLIDING_TOKENS):
        first = client.post(
            "/admin/keys",
            headers=headers,
            json={"plan": "free", "label": "route-first"},
        ).json()
        second = client.post(
            "/admin/keys",
            headers=headers,
            json={"plan": "free", "label": "route-second"},
        ).json()

    listed = client.get("/admin/keys", headers=headers)
    assert listed.status_code == 200
    rows = listed.json()["keys"]
    assert {row["id"] for row in rows} >= {first["id"], second["id"]}
    assert first["key_prefix"] == second["key_prefix"] == "lf_free_same"

    legacy = client.delete(f"/admin/keys/{first['key_prefix']}", headers=headers)
    assert legacy.status_code == 409
    assert db.lookup_key(first["raw_key"]) is not None
    assert db.lookup_key(second["raw_key"]) is not None

    canonical = client.delete(f"/admin/keys/id/{first['id']}", headers=headers)
    assert canonical.status_code == 200
    assert canonical.json() == {
        "ok": True,
        "revoked_id": first["id"],
        "key_prefix": first["key_prefix"],
    }
    assert db.lookup_key(first["raw_key"]) is None
    assert db.lookup_key(second["raw_key"]) is not None

    events = db.list_admin_audit_logs(limit=20)
    revoked_event = next(
        event for event in events if event["action"] == "api_key.revoked"
    )
    assert revoked_event["target_id"] == str(first["id"])
    assert revoked_event["details"]["key_prefix"] == first["key_prefix"]
    assert first["raw_key"] not in str(revoked_event)
    assert second["raw_key"] not in str(revoked_event)


def test_legacy_prefix_route_allows_one_active_match(sqlite_key_db):
    client = TestClient(app)
    headers = {"x-admin-token": ROOT_TOKEN}
    created = client.post(
        "/admin/keys",
        headers=headers,
        json={"plan": "developer", "label": "legacy-exactly-one"},
    ).json()

    response = client.delete(f"/admin/keys/{created['key_prefix']}", headers=headers)

    assert response.status_code == 200
    assert response.json() == {
        "ok": True,
        "revoked": created["key_prefix"],
        "revoked_id": created["id"],
    }
    assert db.lookup_key(created["raw_key"]) is None


def test_dashboard_admin_client_builds_revoke_url_from_key_id():
    source = (
        Path(__file__).parents[1] / "interlock-web" / "src" / "api.ts"
    ).read_text()

    assert "revokeAdminKey: (accessToken: string, keyId: number)" in source
    assert "/admin/keys/id/${encodeURIComponent(String(keyId))}" in source
    assert "/admin/keys/${encodeURIComponent(key.key_prefix)}" not in source


def test_admin_patch_and_usage_routes_reject_prefix_collision(sqlite_key_db):
    client = TestClient(app)
    headers = {"x-admin-token": ROOT_TOKEN}
    with patch("core.db.secrets.token_urlsafe", side_effect=COLLIDING_TOKENS):
        first = client.post(
            "/admin/keys",
            headers=headers,
            json={"plan": "free", "label": "patch-first"},
        ).json()
        second = client.post(
            "/admin/keys",
            headers=headers,
            json={"plan": "free", "label": "patch-second"},
        ).json()

    db.log_usage(first["id"], "/first")
    db.log_usage(second["id"], "/second")
    db.log_usage(second["id"], "/second-again")

    legacy_patch = client.patch(
        f"/admin/keys/{first['key_prefix']}",
        headers=headers,
        json={"label": "must-not-apply"},
    )
    assert legacy_patch.status_code == 409
    assert db.lookup_key_by_id(first["id"])["label"] == "patch-first"
    assert db.lookup_key_by_id(second["id"])["label"] == "patch-second"

    canonical_patch = client.patch(
        f"/admin/keys/id/{first['id']}",
        headers=headers,
        json={"label": "selected-only"},
    )
    assert canonical_patch.status_code == 200
    assert canonical_patch.json() == {
        "ok": True,
        "key_id": first["id"],
        "key_prefix": first["key_prefix"],
        "updated_fields": ["label"],
    }
    assert db.lookup_key_by_id(first["id"])["label"] == "selected-only"
    assert db.lookup_key_by_id(second["id"])["label"] == "patch-second"

    update_event = next(
        event
        for event in db.list_admin_audit_logs(limit=20)
        if event["action"] == "api_key.updated"
    )
    assert update_event["target_id"] == str(first["id"])
    assert update_event["details"]["key_prefix"] == first["key_prefix"]
    assert first["raw_key"] not in str(update_event)
    assert second["raw_key"] not in str(update_event)

    assert db.revoke_key_by_id(first["id"]) is not None
    legacy_usage = client.get(
        f"/admin/keys/{first['key_prefix']}/usage", headers=headers
    )
    assert legacy_usage.status_code == 409

    id_usage = client.get(f"/admin/keys/id/{first['id']}/usage", headers=headers)
    assert id_usage.status_code == 200
    assert id_usage.json()["key_id"] == first["id"]
    assert id_usage.json()["key_prefix"] == first["key_prefix"]
    assert id_usage.json()["used_this_month"] == 1


def test_legacy_patch_and_usage_allow_exactly_one_match(sqlite_key_db):
    client = TestClient(app)
    headers = {"x-admin-token": ROOT_TOKEN}
    created = client.post(
        "/admin/keys",
        headers=headers,
        json={"plan": "startup", "label": "legacy-single"},
    ).json()
    db.log_usage(created["id"], "/single")

    patched = client.patch(
        f"/admin/keys/{created['key_prefix']}",
        headers=headers,
        json={"label": "legacy-updated"},
    )
    assert patched.status_code == 200
    assert patched.json()["key_id"] == created["id"]
    assert db.lookup_key_by_id(created["id"])["label"] == "legacy-updated"
    update_event = next(
        event
        for event in db.list_admin_audit_logs(limit=20)
        if event["action"] == "api_key.updated"
    )
    assert update_event["target_id"] == str(created["id"])
    assert update_event["details"]["key_prefix"] == created["key_prefix"]

    usage = client.get(f"/admin/keys/{created['key_prefix']}/usage", headers=headers)
    assert usage.status_code == 200
    assert usage.json()["key_id"] == created["id"]
    assert usage.json()["used_this_month"] == 1

    assert (
        client.patch(
            "/admin/keys/lf_free_missing",
            headers=headers,
            json={"label": "missing"},
        ).status_code
        == 404
    )
    assert (
        client.get("/admin/keys/lf_free_missing/usage", headers=headers).status_code
        == 404
    )
    assert (
        client.patch(
            "/admin/keys/id/999999",
            headers=headers,
            json={"label": "missing"},
        ).status_code
        == 404
    )
    assert client.get("/admin/keys/id/999999/usage", headers=headers).status_code == 404


def test_dashboard_admin_client_builds_patch_and_usage_urls_from_key_id():
    source = (
        Path(__file__).parents[1] / "interlock-web" / "src" / "api.ts"
    ).read_text()

    assert "updateAdminKey: (accessToken: string, keyId: number" in source
    assert "adminKeyUsage: (accessToken: string, keyId: number)" in source
    assert "`/admin/keys/id/${encodeURIComponent(String(keyId))}`" in source
    assert "`/admin/keys/id/${encodeURIComponent(String(keyId))}/usage`" in source
