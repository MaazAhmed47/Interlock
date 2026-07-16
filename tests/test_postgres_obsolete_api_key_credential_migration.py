"""Real-Postgres proof for removal of the obsolete API-key credential column.

Run with:

  INTERLOCK_TEST_DATABASE_URL=postgresql://postgres:pw@127.0.0.1:54347/postgres \
      python -m pytest tests/test_postgres_obsolete_api_key_credential_migration.py -q -ra
"""

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
    reason=f"{DB_URL_ENV} not set; obsolete-column migration needs Postgres",
)


@pytest.fixture()
def empty_pg_db(monkeypatch):
    import psycopg2

    host = (urlparse(DB_URL).hostname or "").lower()
    assert host in {
        "127.0.0.1",
        "localhost",
        "::1",
    }, "obsolete-column migration tests refuse non-loopback Postgres"

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


def test_fresh_postgres_schema_has_no_obsolete_credential_column(empty_pg_db):
    db = empty_pg_db
    db.init_db()

    assert LEGACY_COLUMN not in _api_key_columns(db)
    assert LEGACY_COLUMN not in db.SCHEMA
    created = db.generate_key("free", label="fresh-postgres-no-obsolete-field")
    assert LEGACY_COLUMN not in db.lookup_key(created["raw_key"])


def test_legacy_postgres_column_drops_idempotently_and_preserves_rows(
    empty_pg_db, monkeypatch
):
    import psycopg2

    db = empty_pg_db
    raw = psycopg2.connect(DB_URL)
    raw.autocommit = True
    with raw.cursor() as cursor:
        cursor.execute(f"""
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
        cursor.execute(
            f"""
            INSERT INTO api_keys
              (id, key_hash, key_prefix, label, {LEGACY_COLUMN}, is_active, created_at)
            VALUES
              (7, 'hash-active', 'lf_free_olda', 'legacy-active', %s, TRUE,
               '2026-01-01T00:00:00+00:00'),
              (11, 'hash-inactive', 'lf_free_oldi', 'legacy-inactive', NULL, FALSE,
               '2026-01-02T00:00:00+00:00')
            """,
            (SENTINEL,),
        )
    raw.close()

    db.init_db()
    assert LEGACY_COLUMN not in _api_key_columns(db)
    with db.get_conn() as conn:
        rows_after_first_init = conn.execute(
            "SELECT id, key_prefix, label, is_active FROM api_keys ORDER BY id"
        ).fetchall()
    assert [tuple(row.values()) for row in rows_after_first_init] == [
        (7, "lf_free_olda", "legacy-active", True),
        (11, "lf_free_oldi", "legacy-inactive", False),
    ]

    migration_calls = []
    original_migration = db._drop_obsolete_api_key_columns

    def record_migration(conn):
        changed = original_migration(conn)
        migration_calls.append(changed)
        return changed

    monkeypatch.setattr(db, "_drop_obsolete_api_key_columns", record_migration)
    db.init_db()
    assert migration_calls == [False]
    assert LEGACY_COLUMN not in _api_key_columns(db)
    with db.get_conn() as conn:
        rows_after_second_init = conn.execute(
            "SELECT id, key_prefix, label, is_active FROM api_keys ORDER BY id"
        ).fetchall()
    assert [tuple(row.values()) for row in rows_after_second_init] == [
        (7, "lf_free_olda", "legacy-active", True),
        (11, "lf_free_oldi", "legacy-inactive", False),
    ]
