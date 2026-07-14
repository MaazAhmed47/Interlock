"""
Registry migration behavior on real Postgres (not SQLite alone).

SQLite is loosely typed, so a boolean/integer column mismatch passes there and
only fails on Postgres. These tests run against a disposable Postgres and prove
that the probe-authorization columns migrate and round-trip correctly:

  INTERLOCK_TEST_DATABASE_URL=postgresql://postgres:pw@127.0.0.1:54331/postgres \
      python -m pytest tests/test_postgres_registry_migration.py

Skipped when the env var is absent (same convention as the audit-chain race
test).
"""

import importlib
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

DB_URL_ENV = "INTERLOCK_TEST_DATABASE_URL"
DB_URL = os.getenv(DB_URL_ENV)

pytestmark = pytest.mark.skipif(
    not DB_URL,
    reason=f"{DB_URL_ENV} not set; registry migration test needs a disposable Postgres",
)

LEGACY_SERVER = "legacy-pg-server"

# The pre-upgrade mcp_servers table: no environment / probes_enabled columns.
LEGACY_SCHEMA = """
DROP TABLE IF EXISTS mcp_tool_metadata CASCADE;
DROP TABLE IF EXISTS mcp_servers CASCADE;
CREATE TABLE mcp_servers (
    server_id       TEXT    PRIMARY KEY,
    url             TEXT    NOT NULL,
    description     TEXT    NOT NULL DEFAULT '',
    allowed_tools   TEXT    NOT NULL DEFAULT '[]',
    blocked_tools   TEXT    NOT NULL DEFAULT '[]',
    rate_limit      INTEGER NOT NULL DEFAULT 60,
    auth_type       TEXT    NOT NULL DEFAULT 'none',
    auth_header     TEXT    NOT NULL DEFAULT '',
    auth_token_env  TEXT    NOT NULL DEFAULT '',
    verified        BOOLEAN NOT NULL DEFAULT FALSE,
    registered_at   TEXT    NOT NULL
);
"""


@pytest.fixture()
def pg_db(monkeypatch):
    """Seed a pre-upgrade registry, then re-import core.db against Postgres."""
    import psycopg2

    raw = psycopg2.connect(DB_URL)
    raw.autocommit = True
    with raw.cursor() as cur:
        cur.execute(LEGACY_SCHEMA)
        cur.execute(
            """
            INSERT INTO mcp_servers (server_id, url, registered_at, verified)
            VALUES (%s, %s, %s, TRUE)
            """,
            (LEGACY_SERVER, "http://safe.example/mcp", "2026-01-01T00:00:00+00:00"),
        )
    raw.close()

    monkeypatch.setenv("DATABASE_URL", DB_URL)
    monkeypatch.setenv("MCP_REGISTRY_ALLOWED_HOSTS", "safe.example")
    monkeypatch.setenv("PYTHON_DOTENV_DISABLED", "1")

    import core.db as db

    db = importlib.reload(db)
    assert db.USE_POSTGRES, "test must exercise the Postgres path"
    db.init_db()
    yield db

    for server_id in (LEGACY_SERVER, "_pg_probe_enabled", "_pg_env_update"):
        try:
            db.unregister_mcp_server(server_id)
        except Exception:
            pass
    monkeypatch.delenv("DATABASE_URL", raising=False)
    importlib.reload(db)


def test_probes_enabled_is_a_postgres_boolean_column():
    """Guards the psycopg2 gotcha: a Python bool bound to an INTEGER column
    raises on Postgres. probes_enabled must convert to BOOLEAN like verified."""
    import core.db as db

    converted = db._postgres_schema_sql(db.SCHEMA)
    assert "probes_enabled  BOOLEAN NOT NULL DEFAULT FALSE" in converted
    assert (
        db._postgres_column_definition("INTEGER NOT NULL DEFAULT 0", "probes_enabled")
        == "BOOLEAN NOT NULL DEFAULT FALSE"
    )


def test_migration_backfills_existing_server_to_production_probes_disabled(pg_db):
    """A server that predates the columns must fail closed after migration."""
    server = pg_db.lookup_mcp_server(LEGACY_SERVER)

    assert server is not None
    assert server["environment"] == "production"
    assert server["probes_enabled"] is False


def test_register_and_lookup_round_trip_probe_state_on_postgres(pg_db):
    pg_db.register_mcp_server(
        "_pg_probe_enabled",
        {
            "url": "http://safe.example/mcp",
            "description": "pg probe-enabled server",
            "allowed_tools": ["read_file"],
            "blocked_tools": [],
            "environment": "non_production",
            "probes_enabled": True,
        },
    )
    server = pg_db.lookup_mcp_server("_pg_probe_enabled")

    assert server["environment"] == "non_production"
    assert server["probes_enabled"] is True

    listed = {s["server_id"]: s for s in pg_db.list_mcp_servers()}
    assert listed["_pg_probe_enabled"]["probes_enabled"] is True
    assert listed[LEGACY_SERVER]["probes_enabled"] is False


def test_admin_environment_update_round_trips_on_postgres(pg_db):
    pg_db.register_mcp_server(
        "_pg_env_update",
        {
            "url": "http://safe.example/mcp",
            "description": "pg env update server",
            "allowed_tools": ["read_file"],
            "blocked_tools": [],
        },
    )
    assert pg_db.lookup_mcp_server("_pg_env_update")["probes_enabled"] is False

    assert pg_db.set_mcp_server_environment(
        "_pg_env_update", "non_production", probes_enabled=True
    )
    updated = pg_db.lookup_mcp_server("_pg_env_update")
    assert updated["environment"] == "non_production"
    assert updated["probes_enabled"] is True

    # ...and back to fail-closed.
    assert pg_db.set_mcp_server_environment(
        "_pg_env_update", "production", probes_enabled=False
    )
    reverted = pg_db.lookup_mcp_server("_pg_env_update")
    assert reverted["environment"] == "production"
    assert reverted["probes_enabled"] is False


def test_probe_gate_reads_migrated_postgres_state(pg_db):
    """End-to-end: the probe authorization gate must fail closed for the
    migrated legacy server and open only after the admin update path."""
    from core.effective_permission import probe_authorization_gate

    legacy = pg_db.lookup_mcp_server(LEGACY_SERVER)
    denied = probe_authorization_gate(legacy)
    assert denied is not None
    assert denied["error"] == "probes_not_enabled"

    pg_db.set_mcp_server_environment(
        LEGACY_SERVER, "non_production", probes_enabled=True
    )
    allowed = pg_db.lookup_mcp_server(LEGACY_SERVER)
    assert probe_authorization_gate(allowed) is None
