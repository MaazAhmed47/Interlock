"""Real-Postgres proof for persistence boolean schema and migration behavior.

Run with:

  INTERLOCK_TEST_DATABASE_URL=postgresql://postgres:pw@127.0.0.1:54340/postgres \
      python -m pytest tests/test_postgres_usage_boolean.py -q -ra
"""

import importlib
import os
from urllib.parse import urlparse

import pytest

DB_URL_ENV = "INTERLOCK_TEST_DATABASE_URL"
DB_URL = os.getenv(DB_URL_ENV)

pytestmark = pytest.mark.skipif(
    not DB_URL,
    reason=f"{DB_URL_ENV} not set; persistence migration test needs Postgres",
)


def _column_metadata(db, table: str, column: str):
    with db.get_conn() as conn:
        return conn.execute(
            """
            SELECT data_type, column_default
              FROM information_schema.columns
             WHERE table_schema = current_schema()
               AND table_name = ?
               AND column_name = ?
            """,
            (table, column),
        ).fetchone()


@pytest.fixture()
def empty_pg_db(monkeypatch):
    import psycopg2

    host = (urlparse(DB_URL).hostname or "").lower()
    assert host in {
        "127.0.0.1",
        "localhost",
        "::1",
    }, "persistence migration tests refuse non-loopback Postgres"

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


def test_fresh_postgres_booleans_log_usage_and_persist_scan(empty_pg_db, monkeypatch):
    from models.schemas import ScanResult, ThreatLevel

    db = empty_pg_db
    db.init_db()

    usage_column = _column_metadata(db, "usage_log", "threat_blocked")
    scan_column = _column_metadata(db, "scan_history", "is_threat")
    assert usage_column["data_type"] == "boolean"
    assert str(usage_column["column_default"]).lower().startswith("false")
    assert scan_column["data_type"] == "boolean"
    assert str(scan_column["column_default"]).lower().startswith("false")

    created = db.generate_key("free", label="fresh-postgres-usage")
    key = db.lookup_key(created["raw_key"])
    db.log_usage(key["id"], "/scan", False)
    db.log_usage(key["id"], "/scan", True)
    assert db.usage_this_month(key["id"]) == 2

    with db.get_conn() as conn:
        values = [
            row["threat_blocked"]
            for row in conn.execute(
                "SELECT threat_blocked FROM usage_log WHERE key_id = ? ORDER BY id",
                (key["id"],),
            ).fetchall()
        ]
    assert values == [False, True]

    scan_key = db.generate_key("free", label="fresh-postgres-scan-persistence")
    scan_key_row = db.lookup_key(scan_key["raw_key"])

    import proxy

    scan_routes = proxy.scan_routes

    monkeypatch.setattr(scan_routes.proxy, "_bump_usage_cache", lambda _key_id: None)
    scan_routes._persist_scan_event(
        scan_key["raw_key"],
        scan_key_row["id"],
        "/scan",
        ScanResult(
            is_threat=True,
            threat_level=ThreatLevel.HIGH,
            reason="postgres persistence proof",
            original_prompt="test",
            safe_to_proceed=False,
        ),
    )

    assert db.usage_this_month(scan_key_row["id"]) == 1
    with db.get_conn() as conn:
        scan_row = conn.execute(
            """
            SELECT is_threat
              FROM scan_history
             WHERE key_hash = ?
             ORDER BY id DESC
             LIMIT 1
            """,
            (db._hash_key(scan_key["raw_key"]),),
        ).fetchone()
    assert scan_row is not None
    assert scan_row["is_threat"] is True


def test_integer_persistence_columns_migrate_rows_and_second_init_is_noop(
    empty_pg_db, monkeypatch
):
    import psycopg2

    db = empty_pg_db
    raw = psycopg2.connect(DB_URL)
    raw.autocommit = True
    with raw.cursor() as cursor:
        cursor.execute("""
            CREATE TABLE usage_log (
                id SERIAL PRIMARY KEY,
                key_id INTEGER NOT NULL,
                ts TEXT NOT NULL,
                endpoint TEXT NOT NULL,
                threat_blocked INTEGER NOT NULL DEFAULT 0
            )
            """)
        cursor.execute("""
            INSERT INTO usage_log (key_id, ts, endpoint, threat_blocked)
            VALUES (10, '2026-07-01T00:00:00+00:00', '/zero', 0),
                   (11, '2026-07-01T00:00:00+00:00', '/one', 1),
                   (12, '2026-07-01T00:00:00+00:00', '/nonzero', -7)
            """)
        cursor.execute("""
            CREATE TABLE scan_history (
                id SERIAL PRIMARY KEY,
                is_threat INTEGER NOT NULL DEFAULT 0
            )
            """)
        cursor.execute("INSERT INTO scan_history (is_threat) VALUES (0), (1), (9)")
    raw.close()

    db.init_db()

    usage_column = _column_metadata(db, "usage_log", "threat_blocked")
    scan_column = _column_metadata(db, "scan_history", "is_threat")
    assert usage_column["data_type"] == "boolean"
    assert str(usage_column["column_default"]).lower().startswith("false")
    assert scan_column["data_type"] == "boolean"
    assert str(scan_column["column_default"]).lower().startswith("false")

    with db.get_conn() as conn:
        usage_rows = conn.execute(
            "SELECT id, key_id, threat_blocked FROM usage_log ORDER BY id"
        ).fetchall()
        scan_rows = conn.execute(
            "SELECT id, is_threat FROM scan_history ORDER BY id"
        ).fetchall()
    assert [
        (row["id"], row["key_id"], row["threat_blocked"]) for row in usage_rows
    ] == [
        (1, 10, False),
        (2, 11, True),
        (3, 12, True),
    ]
    assert [(row["id"], row["is_threat"]) for row in scan_rows] == [
        (1, False),
        (2, True),
        (3, True),
    ]

    migration_calls = []
    original_migration = db._ensure_postgres_boolean_column

    def record_migration(conn, table, column):
        changed = original_migration(conn, table, column)
        migration_calls.append((table, column, changed))
        return changed

    monkeypatch.setattr(db, "_ensure_postgres_boolean_column", record_migration)
    db.init_db()

    assert migration_calls == [
        ("usage_log", "threat_blocked", False),
        ("scan_history", "is_threat", False),
    ]
    with db.get_conn() as conn:
        assert conn.execute("SELECT COUNT(*) AS n FROM usage_log").fetchone()["n"] == 3
        assert (
            conn.execute("SELECT COUNT(*) AS n FROM scan_history").fetchone()["n"] == 3
        )
