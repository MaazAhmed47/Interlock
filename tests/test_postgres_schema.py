"""Postgres schema conversion tests for the DB layer."""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core import db


class RecordingCursor:
    def __init__(self, raw):
        self.raw = raw
        self.sql = ""
        self.params = ()
        self.rowcount = 0

    def execute(self, sql, params=()):
        self.sql = sql
        self.params = params
        self.raw.statements.append((sql, params))
        return self

    def fetchall(self):
        if "information_schema.columns" in self.sql:
            return []
        return []

    def fetchone(self):
        return None


class RecordingRaw:
    def __init__(self):
        self.statements = []
        self.closed = False

    def cursor(self):
        return RecordingCursor(self)

    def close(self):
        self.closed = True


def test_postgres_schema_conversion_removes_sqlite_only_constructs():
    converted = db._postgres_schema_sql(db.SCHEMA)

    assert "AUTOINCREMENT" not in converted
    assert "SERIAL PRIMARY KEY" in converted
    assert "is_active       BOOLEAN NOT NULL DEFAULT TRUE" in converted
    assert "verified        BOOLEAN NOT NULL DEFAULT FALSE" in converted
    assert "CREATE TABLE IF NOT EXISTS admin_tokens" in converted
    assert "enabled    INTEGER DEFAULT 1" in converted


def test_pg_sql_converts_placeholders_and_sqlite_upserts():
    insert_ignore = db._pg_sql(
        "INSERT OR IGNORE INTO mcp_servers (server_id, url) VALUES (?, ?)"
    )
    assert insert_ignore == "INSERT INTO mcp_servers (server_id, url) VALUES (%s, %s) ON CONFLICT DO NOTHING"

    upsert = db._pg_sql(
        "INSERT OR REPLACE INTO system_config (key, value) VALUES (?, ?)"
    )
    assert upsert == (
        "INSERT INTO system_config (key, value) VALUES (%s, %s) "
        "ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value"
    )


def test_postgres_ensure_column_uses_information_schema_and_pg_definition():
    raw = RecordingRaw()
    conn = db._PostgresConn(raw)

    db._ensure_column(conn, "api_keys", "is_active", "INTEGER NOT NULL DEFAULT 1")

    statements = [sql for sql, _params in raw.statements]
    assert any("information_schema.columns" in sql for sql in statements)
    assert any("ALTER TABLE api_keys ADD COLUMN is_active BOOLEAN NOT NULL DEFAULT TRUE" in sql for sql in statements)


def test_postgres_init_runs_schema_instead_of_skipping(monkeypatch):
    raw = RecordingRaw()
    conn = db._PostgresConn(raw)

    class FakeConnManager:
        def __enter__(self):
            return conn

        def __exit__(self, *_exc):
            return False

    monkeypatch.setattr(db, "USE_POSTGRES", True)
    monkeypatch.setattr(db, "get_conn", lambda: FakeConnManager())

    db.init_db()

    statements = [sql for sql, _params in raw.statements]
    assert any("CREATE TABLE IF NOT EXISTS api_keys" in sql for sql in statements)
    assert any("CREATE TABLE IF NOT EXISTS admin_tokens" in sql for sql in statements)
    assert any("information_schema.columns" in sql for sql in statements)
    assert not any("PRAGMA table_info" in sql for sql in statements)

def test_database_url_is_stripped_when_loaded(monkeypatch):
    import importlib

    monkeypatch.setenv("DATABASE_URL", "postgresql://user:pass@example.com:5432/postgres\n")
    reloaded = importlib.reload(db)

    assert reloaded.DATABASE_URL == "postgresql://user:pass@example.com:5432/postgres"
    assert reloaded.USE_POSTGRES is True

    monkeypatch.delenv("DATABASE_URL", raising=False)
    importlib.reload(db)
