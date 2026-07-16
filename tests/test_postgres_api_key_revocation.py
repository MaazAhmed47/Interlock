"""Real-Postgres migration proof for immutable API-key revocation identity.

Run with:

  INTERLOCK_TEST_DATABASE_URL=postgresql://postgres:pw@127.0.0.1:54331/postgres \
      python -m pytest tests/test_postgres_api_key_revocation.py -q -ra
"""

import hashlib
import importlib
import os

import pytest

DB_URL_ENV = "INTERLOCK_TEST_DATABASE_URL"
DB_URL = os.getenv(DB_URL_ENV)
FIRST_RAW = "lf_free_sameAAAAAAAAAAAAAAAAAAAA"
SECOND_RAW = "lf_free_sameBBBBBBBBBBBBBBBBBBBB"
DISPLAY_PREFIX = "lf_free_same"
ROOT_TOKEN = "postgres-key-identity-test-token"
UPSTREAM_SECRET = "sk-postgres-upstream-secret-never-serialize"

pytestmark = pytest.mark.skipif(
    not DB_URL,
    reason=f"{DB_URL_ENV} not set; API-key migration test needs disposable Postgres",
)


LEGACY_API_KEYS_SCHEMA = """
DROP TABLE IF EXISTS usage_log CASCADE;
DROP TABLE IF EXISTS admin_audit_log CASCADE;
DROP TABLE IF EXISTS audit_chain_checkpoints CASCADE;
DROP TABLE IF EXISTS api_keys CASCADE;
CREATE TABLE api_keys (
    id                 SERIAL PRIMARY KEY,
    key_hash           TEXT    NOT NULL UNIQUE,
    key_prefix         TEXT    NOT NULL,
    label              TEXT    NOT NULL DEFAULT '',
    plan               TEXT    NOT NULL DEFAULT 'free',
    monthly_limit      INTEGER NOT NULL DEFAULT 1000,
    rate_per_min       INTEGER NOT NULL DEFAULT 10,
    fail_mode          TEXT    NOT NULL DEFAULT 'fail_closed',
    webhook_url        TEXT,
    custom_policy      TEXT,
    siem_configs       TEXT,
    upstream_key       TEXT,
    is_active          BOOLEAN NOT NULL DEFAULT TRUE,
    created_at         TEXT    NOT NULL,
    revoked_at         TEXT
);
"""


@pytest.fixture()
def migrated_pg_db(monkeypatch):
    import psycopg2

    raw = psycopg2.connect(DB_URL)
    raw.autocommit = True
    with raw.cursor() as cur:
        cur.execute(LEGACY_API_KEYS_SCHEMA)
        cur.execute(
            """
            INSERT INTO api_keys
              (key_hash, key_prefix, label, plan, is_active, created_at)
            VALUES (%s, %s, %s, 'free', TRUE, %s),
                   (%s, %s, %s, 'free', TRUE, %s)
            RETURNING id
            """,
            (
                hashlib.sha256(FIRST_RAW.encode()).hexdigest(),
                DISPLAY_PREFIX,
                "legacy-first",
                "2026-01-01T00:00:00+00:00",
                hashlib.sha256(SECOND_RAW.encode()).hexdigest(),
                DISPLAY_PREFIX,
                "legacy-second",
                "2026-01-02T00:00:00+00:00",
            ),
        )
        original_ids = [row[0] for row in cur.fetchall()]
    raw.close()

    monkeypatch.setenv("DATABASE_URL", DB_URL)
    monkeypatch.setenv("PYTHON_DOTENV_DISABLED", "1")

    import core.db as db

    db = importlib.reload(db)
    assert db.USE_POSTGRES, "test must exercise the Postgres path"
    db.init_db()

    import core.admin as admin

    monkeypatch.setattr(admin, "ADMIN_TOKEN", ROOT_TOKEN)
    yield db, original_ids

    if db._pg_pool is not None:
        db._pg_pool.closeall()
        db._pg_pool = None
    monkeypatch.delenv("DATABASE_URL", raising=False)
    importlib.reload(db)


def test_migrated_same_plan_keys_revoke_independently(migrated_pg_db):
    from fastapi.testclient import TestClient

    from proxy import app

    db, original_ids = migrated_pg_db
    client = TestClient(app)
    headers = {"x-admin-token": ROOT_TOKEN}

    rows = [row for row in db.list_keys() if row["key_prefix"] == DISPLAY_PREFIX]
    assert sorted(row["id"] for row in rows) == sorted(original_ids)
    assert db.lookup_key(FIRST_RAW) is not None
    assert db.lookup_key(SECOND_RAW) is not None

    ambiguous_patch = client.patch(
        f"/admin/keys/{DISPLAY_PREFIX}",
        headers=headers,
        json={"label": "must-not-apply"},
    )
    assert ambiguous_patch.status_code == 409
    assert db.lookup_key_by_id(original_ids[0])["label"] == "legacy-first"
    assert db.lookup_key_by_id(original_ids[1])["label"] == "legacy-second"

    selected_patch = client.patch(
        f"/admin/keys/id/{original_ids[0]}",
        headers=headers,
        json={"label": "selected-only"},
    )
    assert selected_patch.status_code == 200
    assert selected_patch.json()["key_id"] == original_ids[0]
    assert db.lookup_key_by_id(original_ids[0])["label"] == "selected-only"
    assert db.lookup_key_by_id(original_ids[1])["label"] == "legacy-second"

    update_event = next(
        event
        for event in db.list_admin_audit_logs(limit=20)
        if event["action"] == "api_key.updated"
    )
    assert update_event["target_id"] == str(original_ids[0])
    assert update_event["details"]["key_prefix"] == DISPLAY_PREFIX

    db.log_usage(original_ids[0], "/first", False)
    db.log_usage(original_ids[1], "/second", False)
    db.log_usage(original_ids[1], "/second-again", False)
    ambiguous_usage = client.get(f"/admin/keys/{DISPLAY_PREFIX}/usage", headers=headers)
    assert ambiguous_usage.status_code == 409
    selected_usage = client.get(
        f"/admin/keys/id/{original_ids[0]}/usage", headers=headers
    )
    assert selected_usage.status_code == 200
    assert selected_usage.json()["key_id"] == original_ids[0]
    assert selected_usage.json()["used_this_month"] == 1

    with pytest.raises(db.AmbiguousKeyPrefixError) as exc:
        db.revoke_key(DISPLAY_PREFIX)
    assert exc.value.match_count == 2
    assert db.lookup_key(FIRST_RAW) is not None
    assert db.lookup_key(SECOND_RAW) is not None

    revoked = db.revoke_key_by_id(original_ids[0])
    assert revoked == {"id": original_ids[0], "key_prefix": DISPLAY_PREFIX}
    assert db.lookup_key(FIRST_RAW) is None
    assert db.lookup_key(SECOND_RAW) is not None
    with pytest.raises(db.AmbiguousKeyPrefixError):
        db.lookup_key_by_prefix(DISPLAY_PREFIX, include_inactive=True)


def test_postgres_admin_list_redacts_seeded_upstream_credential(migrated_pg_db):
    db, _ = migrated_pg_db
    created = db.generate_key(
        "developer", label="postgres-secret-bearing", upstream_key=UPSTREAM_SECRET
    )

    assert db.lookup_key(created["raw_key"])["upstream_key"] == UPSTREAM_SECRET

    row = next(item for item in db.list_keys() if item["id"] == created["id"])
    assert "upstream_key" not in row
    assert row["upstream_key_configured"] is True
    assert "key_hash" not in row
    assert UPSTREAM_SECRET not in str(row)
