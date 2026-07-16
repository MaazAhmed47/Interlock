"""Real-Postgres expand-contract proof for the dormant API-key column.

Run with:

  INTERLOCK_TEST_DATABASE_URL=postgresql://postgres:pw@127.0.0.1:54347/postgres \
      python -m pytest \
      tests/test_postgres_obsolete_api_key_credential_compatibility.py -q -ra
"""

import hashlib
import importlib
import os
from urllib.parse import urlparse

import pytest

DB_URL_ENV = "INTERLOCK_TEST_DATABASE_URL"
DB_URL = os.getenv(DB_URL_ENV)
LEGACY_COLUMN = "upstream" + "_key"
SENTINEL = "legacy-postgres-credential-sentinel"

pytestmark = pytest.mark.skipif(
    not DB_URL,
    reason=f"{DB_URL_ENV} not set; compatibility proof needs Postgres",
)


@pytest.fixture()
def empty_pg_db(monkeypatch):
    import psycopg2

    host = (urlparse(DB_URL).hostname or "").lower()
    assert host in {
        "127.0.0.1",
        "localhost",
        "::1",
    }, "compatibility tests refuse non-loopback Postgres"

    raw = psycopg2.connect(DB_URL)
    raw.autocommit = True
    with raw.cursor() as cursor:
        cursor.execute("DROP SCHEMA public CASCADE")
        cursor.execute("CREATE SCHEMA public")
    raw.close()

    monkeypatch.setenv("DATABASE_URL", DB_URL)
    monkeypatch.setenv("PYTHON_DOTENV_DISABLED", "1")

    import core.db as db

    db = importlib.reload(db)
    assert db.USE_POSTGRES
    yield db

    if db._pg_pool is not None:
        db._pg_pool.closeall()
        db._pg_pool = None
    monkeypatch.delenv("DATABASE_URL", raising=False)
    importlib.reload(db)


def _api_key_columns(db):
    with db.get_conn() as conn:
        return db.table_columns("api_keys", conn=conn)


def _create_legacy_table(db) -> None:
    with db.get_conn() as conn:
        conn.execute(f"""
            CREATE TABLE api_keys (
                id                 SERIAL PRIMARY KEY,
                key_hash           TEXT NOT NULL UNIQUE,
                key_prefix         TEXT NOT NULL,
                label              TEXT NOT NULL DEFAULT '',
                plan               TEXT NOT NULL DEFAULT 'free',
                monthly_limit      INTEGER NOT NULL DEFAULT 1000,
                rate_per_min       INTEGER NOT NULL DEFAULT 10,
                fail_mode          TEXT NOT NULL DEFAULT 'fail_closed',
                webhook_url        TEXT,
                custom_policy      TEXT,
                siem_configs       TEXT,
                {LEGACY_COLUMN}    TEXT,
                scopes             TEXT NOT NULL DEFAULT '["mcp.call","mcp.read"]',
                role               TEXT NOT NULL DEFAULT 'readonly_agent',
                is_active          BOOLEAN NOT NULL DEFAULT TRUE,
                created_at         TEXT NOT NULL,
                revoked_at         TEXT,
                max_response_bytes INTEGER DEFAULT 50000,
                max_array_items    INTEGER DEFAULT 500
            )
        """)
        conn.execute(
            f"""
            INSERT INTO api_keys
              (id, key_hash, key_prefix, label, {LEGACY_COLUMN}, is_active, created_at)
            VALUES
              (7, ?, 'lf_free_olda', 'legacy-active', ?, TRUE,
               '2026-01-01T00:00:00+00:00'),
              (11, ?, 'lf_free_oldi', 'legacy-inactive', NULL, FALSE,
               '2026-01-02T00:00:00+00:00')
            """,
            (
                hashlib.sha256(b"legacy-active").hexdigest(),
                SENTINEL,
                hashlib.sha256(b"legacy-inactive").hexdigest(),
            ),
        )


def _prior_release_insert(db, conn, raw_key: str) -> int:
    row = conn.execute(
        f"""
        INSERT INTO api_keys
          (key_hash, key_prefix, label, plan, monthly_limit, rate_per_min,
           fail_mode, webhook_url, custom_policy, siem_configs, {LEGACY_COLUMN},
           is_active, created_at, max_response_bytes, max_array_items,
           scopes, role)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        RETURNING id
        """,
        (
            db._hash_key(raw_key),
            raw_key[:12],
            "prior-release-compatible",
            "free",
            1000,
            10,
            "fail_closed",
            None,
            None,
            None,
            "prior-release-insert-value",
            True,
            "2026-07-17T00:00:00+00:00",
            50000,
            500,
            '["mcp.call","mcp.read"]',
            "readonly_agent",
        ),
    ).fetchone()
    assert row is not None
    return int(row["id"])


def test_fresh_postgres_schema_has_no_obsolete_credential_column(empty_pg_db):
    db = empty_pg_db
    db.init_db()

    assert LEGACY_COLUMN not in _api_key_columns(db)
    assert LEGACY_COLUMN not in db.SCHEMA
    created = db.generate_key("free", label="fresh-postgres-no-obsolete-field")
    assert LEGACY_COLUMN not in db.lookup_key(created["raw_key"])


def test_legacy_postgres_column_is_retained_for_rollback_compatibility(empty_pg_db):
    db = empty_pg_db
    _create_legacy_table(db)

    db.init_db()
    assert LEGACY_COLUMN in _api_key_columns(db)
    with db.get_conn() as conn:
        rows_after_first_init = conn.execute(
            f"SELECT id, key_prefix, label, is_active, {LEGACY_COLUMN} "
            "FROM api_keys ORDER BY id"
        ).fetchall()
    assert [tuple(row.values()) for row in rows_after_first_init] == [
        (7, "lf_free_olda", "legacy-active", True, SENTINEL),
        (11, "lf_free_oldi", "legacy-inactive", False, None),
    ]

    active = db.lookup_key("legacy-active")
    assert active is not None
    assert LEGACY_COLUMN not in active
    assert all(LEGACY_COLUMN not in row for row in db.list_keys(include_inactive=True))

    db.init_db()
    assert LEGACY_COLUMN in _api_key_columns(db)
    with db.get_conn() as conn:
        rows_after_second_init = conn.execute(
            f"SELECT id, key_prefix, label, is_active, {LEGACY_COLUMN} "
            "FROM api_keys ORDER BY id"
        ).fetchall()
    assert [tuple(row.values()) for row in rows_after_second_init] == [
        (7, "lf_free_olda", "legacy-active", True, SENTINEL),
        (11, "lf_free_oldi", "legacy-inactive", False, None),
    ]


def test_prior_release_postgres_sql_shape_still_writes_after_new_init(empty_pg_db):
    db = empty_pg_db
    _create_legacy_table(db)
    db.init_db()

    raw_key = "lf_free_prior_release_postgres_compatibility"
    with db.get_conn() as conn:
        key_id = _prior_release_insert(db, conn, raw_key)
        conn.execute(
            f"UPDATE api_keys SET {LEGACY_COLUMN} = ? WHERE id = ?",
            ("prior-release-update-value", key_id),
        )
        dormant_value = conn.execute(
            f"SELECT {LEGACY_COLUMN} FROM api_keys WHERE id = ?", (key_id,)
        ).fetchone()[LEGACY_COLUMN]

    assert dormant_value == "prior-release-update-value"
    current = db.lookup_key(raw_key)
    assert current is not None
    assert current["id"] == key_id
    assert LEGACY_COLUMN not in current
    listed = next(row for row in db.list_keys() if row["id"] == key_id)
    assert LEGACY_COLUMN not in listed
