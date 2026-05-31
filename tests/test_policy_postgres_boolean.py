"""Postgres boolean handling for ``policies.is_active`` (seed + CRUD).

``policies.is_active`` is declared ``INTEGER`` in the SQLite schema but is
rewritten to ``BOOLEAN`` on Postgres via ``_POSTGRES_BOOLEAN_COLUMNS``
(see ``core/db.py``). Writing or comparing it with the integer literals
``1``/``0`` raises ``psycopg2.errors.DatatypeMismatch`` ("column is_active is
of type boolean but expression is of type integer") on Postgres while
silently working on SQLite.

These tests drive the policy seed and CRUD functions through the
Postgres-style ``_PostgresConn`` adapter and pin the emitted SQL/params to
booleans, so the integer-vs-boolean regression cannot come back.
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core import db


class _FakeCursor:
    def __init__(self, raw):
        self.raw = raw
        self.sql = ""
        self.params = ()
        self.rowcount = 1
        self.lastrowid = 1

    def execute(self, sql, params=()):
        self.sql = sql
        self.params = params
        self.raw.statements.append((sql, params))
        return self

    def fetchall(self):
        return []

    def fetchone(self):
        return self.raw.fetchone_for(self.sql)


class _FakePostgresRaw:
    """Minimal psycopg2-style connection that records every statement.

    ``existing_policy_id`` drives ``upsert_policy`` down its UPDATE branch when
    set, and down its INSERT branch when ``None``.
    """

    def __init__(self, existing_policy_id=None):
        self.statements = []
        self.existing_policy_id = existing_policy_id
        self.autocommit = False

    def cursor(self):
        return _FakeCursor(self)

    def fetchone_for(self, sql):
        if "select id from policies" in sql.lower():
            if self.existing_policy_id is None:
                return None
            return {"id": self.existing_policy_id}
        return None

    def close(self):
        pass


def _use_postgres_conn(monkeypatch, raw):
    conn = db._PostgresConn(raw)

    class _Manager:
        def __enter__(self):
            return conn

        def __exit__(self, *_exc):
            return False

    monkeypatch.setattr(db, "get_conn", lambda: _Manager())
    return conn


def _statements_for(raw, needle):
    return [(sql, params) for sql, params in raw.statements if needle in sql]


def _has_bare_int(params):
    """True if any param is a plain int (bool is a subclass of int and is OK)."""
    return any(isinstance(p, int) and not isinstance(p, bool) for p in params)


def test_seed_default_policies_inserts_boolean_is_active(monkeypatch):
    raw = _FakePostgresRaw()
    _use_postgres_conn(monkeypatch, raw)

    db.seed_default_policies({"support_agent": {"allow": ["read"]}}, policy_type="role")

    inserts = _statements_for(raw, "INSERT INTO policies")
    assert inserts, "expected an INSERT INTO policies statement"
    _sql, params = inserts[0]
    assert any(p is True for p in params), "is_active must be bound as bool True"
    assert not _has_bare_int(params), "is_active must not be inserted as integer 1"


def test_upsert_policy_insert_uses_boolean_is_active(monkeypatch):
    raw = _FakePostgresRaw(existing_policy_id=None)
    _use_postgres_conn(monkeypatch, raw)

    db.upsert_policy("role", "finance_agent", '{"allow": []}', updated_by="tester")

    inserts = _statements_for(raw, "INSERT INTO policies")
    assert inserts, "expected an INSERT INTO policies statement"
    _sql, params = inserts[0]
    assert any(p is True for p in params), "is_active must be bound as bool True"
    assert not _has_bare_int(params), "is_active must not be inserted as integer 1"


def test_upsert_policy_update_uses_boolean_literal(monkeypatch):
    raw = _FakePostgresRaw(existing_policy_id=7)
    _use_postgres_conn(monkeypatch, raw)

    db.upsert_policy("role", "finance_agent", '{"allow": []}', updated_by="tester")

    updates = _statements_for(raw, "UPDATE policies")
    assert updates, "expected an UPDATE policies statement"
    sql = updates[0][0]
    assert "is_active = TRUE" in sql
    assert "is_active = 1" not in sql


def test_delete_policy_uses_boolean_false_literal(monkeypatch):
    raw = _FakePostgresRaw()
    _use_postgres_conn(monkeypatch, raw)

    db.delete_policy(7)

    updates = _statements_for(raw, "UPDATE policies")
    assert updates, "expected an UPDATE policies statement"
    sql = updates[0][0]
    assert "is_active = FALSE" in sql
    assert "is_active = 0" not in sql


def test_get_policy_by_name_filters_on_boolean_literal(monkeypatch):
    raw = _FakePostgresRaw()
    _use_postgres_conn(monkeypatch, raw)

    # server_id forces both the primary and the server-scoped fallback SELECT.
    db.get_policy_by_name("role", "support_agent", server_id="srv-1")

    selects = _statements_for(raw, "SELECT * FROM policies")
    assert len(selects) == 2, "expected primary + fallback SELECT * FROM policies"
    for sql, _params in selects:
        assert "is_active = TRUE" in sql
        assert "is_active = 1" not in sql
