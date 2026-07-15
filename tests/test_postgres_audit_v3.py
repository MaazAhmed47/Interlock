"""
v3 audit hashing + retention checkpoints on real Postgres (not SQLite alone).

SQLite is loosely typed and single-writer, so three whole failure classes only
exist on Postgres: float4 (REAL) columns corrupting the fixed-precision float
encoding in v3 envelopes, psycopg2 parameter/type mismatches, and the
transactional behavior of checkpoint-write + prefix-delete under the advisory
chain lock. These tests run against a disposable Postgres:

  docker run -d --name interlock-v3-pg -e POSTGRES_PASSWORD=v3pw \
      -p 54333:5432 postgres:16
  INTERLOCK_TEST_DATABASE_URL=postgresql://postgres:v3pw@127.0.0.1:54333/postgres \
      python -m pytest tests/test_postgres_audit_v3.py

Skipped when the env var is absent (same convention as the audit-chain race
test and the registry migration test).
"""

import importlib
import os
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

DB_URL_ENV = "INTERLOCK_TEST_DATABASE_URL"
DB_URL = os.getenv(DB_URL_ENV)

pytestmark = pytest.mark.skipif(
    not DB_URL,
    reason=f"{DB_URL_ENV} not set; v3 audit tests need a disposable Postgres",
)

# A pre-upgrade deployment: audit tables exist, float columns are REAL
# (float4), admin_audit_log has no hash_v column, no checkpoint table.
LEGACY_SCHEMA = """
DROP TABLE IF EXISTS audit_chain_checkpoints CASCADE;
DROP TABLE IF EXISTS mcp_audit_log CASCADE;
DROP TABLE IF EXISTS admin_audit_log CASCADE;
CREATE TABLE mcp_audit_log (
    id                  SERIAL PRIMARY KEY,
    ts                  TEXT    NOT NULL,
    server_id           TEXT    NOT NULL,
    tool_name           TEXT    NOT NULL,
    principal_id        TEXT    NOT NULL DEFAULT '',
    role                TEXT    NOT NULL DEFAULT '',
    action              TEXT    NOT NULL,
    matched_rule        TEXT    NOT NULL DEFAULT '',
    reason              TEXT    NOT NULL DEFAULT '',
    effects             TEXT    NOT NULL DEFAULT '[]',
    side_effect         TEXT    NOT NULL DEFAULT 'unknown',
    data_classes        TEXT    NOT NULL DEFAULT '[]',
    externality         TEXT    NOT NULL DEFAULT 'unknown',
    verification_level  TEXT    NOT NULL DEFAULT 'unknown',
    confidence          REAL    NOT NULL DEFAULT 0,
    warnings            TEXT    NOT NULL DEFAULT '[]',
    argument_keys       TEXT    NOT NULL DEFAULT '[]',
    blocked_by          TEXT    NOT NULL DEFAULT '',
    probe_id            TEXT    NOT NULL DEFAULT '',
    argument_hash       TEXT    NOT NULL DEFAULT '',
    expected_outcome    TEXT    NOT NULL DEFAULT '',
    expected_status_code INTEGER,
    observed_outcome    TEXT    NOT NULL DEFAULT '',
    observed_status_code INTEGER,
    observed_error_class TEXT   NOT NULL DEFAULT '',
    drift_status        TEXT    NOT NULL DEFAULT '',
    drift_severity      TEXT    NOT NULL DEFAULT 'none',
    drift_action        TEXT    NOT NULL DEFAULT 'allow',
    drift_types         TEXT    NOT NULL DEFAULT '[]',
    drift_reasons       TEXT    NOT NULL DEFAULT '[]',
    drift_baseline_hash TEXT    NOT NULL DEFAULT '',
    drift_current_hash  TEXT    NOT NULL DEFAULT '',
    scan_time_ms        REAL,
    call_id             TEXT    NOT NULL DEFAULT '',
    hash_v              INTEGER NOT NULL DEFAULT 1,
    prev_hash           TEXT    NOT NULL DEFAULT '',
    integrity_hash      TEXT    NOT NULL DEFAULT ''
);
CREATE TABLE admin_audit_log (
    id                 SERIAL PRIMARY KEY,
    ts                 TEXT    NOT NULL,
    actor_auth_type    TEXT    NOT NULL DEFAULT '',
    actor_role         TEXT    NOT NULL DEFAULT '',
    actor_label        TEXT    NOT NULL DEFAULT '',
    actor_email        TEXT    NOT NULL DEFAULT '',
    actor_subject      TEXT    NOT NULL DEFAULT '',
    actor_token_prefix TEXT    NOT NULL DEFAULT '',
    action             TEXT    NOT NULL,
    target_type        TEXT    NOT NULL DEFAULT '',
    target_id          TEXT    NOT NULL DEFAULT '',
    result             TEXT    NOT NULL DEFAULT 'success',
    reason             TEXT    NOT NULL DEFAULT '',
    details            TEXT    NOT NULL DEFAULT '{}',
    prev_hash          TEXT    NOT NULL DEFAULT '',
    integrity_hash     TEXT    NOT NULL DEFAULT ''
);
"""

POLICY = {
    "scan_history_days": 30,
    "mcp_audit_days": 30,
    "admin_audit_days": 30,
    "usage_log_days": 30,
}

ACTOR = {"actor_auth_type": "scoped_token", "actor_role": "operator"}


@pytest.fixture(scope="module")
def pg_db():
    """Seed a pre-upgrade audit schema, then re-import core.db on Postgres."""
    import psycopg2

    raw = psycopg2.connect(DB_URL)
    raw.autocommit = True
    with raw.cursor() as cur:
        cur.execute(LEGACY_SCHEMA)
    raw.close()

    os.environ["DATABASE_URL"] = DB_URL
    os.environ["PYTHON_DOTENV_DISABLED"] = "1"

    import core.db as db

    db = importlib.reload(db)
    assert db.USE_POSTGRES, "test must exercise the Postgres path"
    db.init_db()
    yield db

    os.environ.pop("DATABASE_URL", None)
    importlib.reload(db)


@pytest.fixture(autouse=True)
def clean_chains(pg_db):
    with pg_db.get_conn() as conn:
        conn.execute("DELETE FROM audit_chain_checkpoints")
        conn.execute("DELETE FROM mcp_audit_log")
        conn.execute("DELETE FROM admin_audit_log")
    yield


def _column_type(pg_db, table, column):
    with pg_db.get_conn() as conn:
        row = conn.execute(
            """
            SELECT data_type FROM information_schema.columns
             WHERE table_schema = current_schema()
               AND table_name = ? AND column_name = ?
            """,
            (table, column),
        ).fetchone()
    return dict(row)["data_type"] if row else None


def _ts(days_ago: int, seq: int = 0) -> str:
    moment = (
        datetime.now(timezone.utc) - timedelta(days=days_ago) + timedelta(seconds=seq)
    )
    return moment.isoformat()


def _log_mcp(pg_db, days_ago=0, seq=0, **overrides):
    event = {
        "server_id": "pg-v3-server",
        "tool_name": f"tool_{days_ago}_{seq}",
        "principal_id": "pg-principal",
        "role": "readonly_agent",
        "action": "quarantine",
        "matched_rule": "effective_permission_probe",
        "reason": "pg v3 event",
        "effects": ["read", "export"],
        "data_classes": ["email"],
        "confidence": 0.1 + 0.2,  # 0.30000000000000004 — float8 must round-trip
        "warnings": ["pii detected"],
        "argument_keys": ["path"],
        "blocked_by": "tool_quarantined",
        "probe_id": "pg-probe",
        "argument_hash": "sha256:" + "a" * 64,
        "expected_outcome": "denied",
        "expected_status_code": 403,
        "observed_outcome": "allowed",
        "observed_status_code": 200,
        "observed_error_class": "PermissionError",
        "drift_status": "quarantined",
        "drift_severity": "critical",
        "drift_action": "quarantine",
        "drift_types": ["effect_escalated"],
        "drift_reasons": ["read-only tool gained export effect"],
        "drift_baseline_hash": "sha256:" + "b" * 64,
        "drift_current_hash": "sha256:" + "c" * 64,
        "scan_time_ms": 12.3456789,
        "ts": _ts(days_ago, seq),
    }
    event.update(overrides)
    return pg_db.log_mcp_audit_event(event)


def _log_admin(pg_db, days_ago=0, seq=0, **overrides):
    event = {
        "actor_auth_type": "scoped_token",
        "actor_role": "operator",
        "actor_label": "pg-ops",
        "action": f"pg_action_{days_ago}_{seq}",
        "target_type": "api_key",
        "target_id": f"pg-target-{days_ago}-{seq}",
        "details": {"plan": "developer", "nested": {"scopes": ["mcp.call", 2]}},
        "ts": _ts(days_ago, seq),
    }
    event.update(overrides)
    return pg_db.log_admin_audit_event(event)


def _set_column(pg_db, table, column, value, row_id):
    with pg_db._db_lock, pg_db.get_conn() as conn:
        conn.execute(f"UPDATE {table} SET {column} = ? WHERE id = ?", (value, row_id))


def _checkpoints(pg_db, chain):
    with pg_db.get_conn() as conn:
        return pg_db._list_chain_checkpoints(conn, chain)


def _count(pg_db, table):
    with pg_db.get_conn() as conn:
        row = conn.execute(f"SELECT COUNT(*) AS n FROM {table}").fetchone()
    return int(dict(row)["n"])


# ── schema migration ──────────────────────────────────────────────────────────


def test_migration_widens_real_float_columns_to_double_precision(pg_db):
    assert _column_type(pg_db, "mcp_audit_log", "confidence") == "double precision"
    assert _column_type(pg_db, "mcp_audit_log", "scan_time_ms") == "double precision"


def test_migration_adds_admin_hash_v_and_checkpoint_table(pg_db):
    assert _column_type(pg_db, "admin_audit_log", "hash_v") == "integer"
    assert _column_type(pg_db, "audit_chain_checkpoints", "chain") == "text"
    assert (
        _column_type(pg_db, "audit_chain_checkpoints", "first_retained_id") == "integer"
    )


def test_new_schema_creates_audit_floats_as_double_precision(pg_db):
    converted = pg_db._postgres_schema_sql(pg_db.SCHEMA)
    assert " REAL" not in converted
    assert "scan_time_ms        DOUBLE PRECISION" in converted


# ── v3 rows round-trip and verify on Postgres ────────────────────────────────


def test_v3_rows_with_awkward_floats_verify_on_postgres(pg_db):
    saved = _log_mcp(pg_db, confidence=0.30000000000000004, scan_time_ms=12.3456789)
    admin = _log_admin(pg_db)

    assert saved["hash_v"] == 3
    assert pg_db.verify_mcp_audit_record(saved["id"])["chain_verified"] is True
    chain = pg_db.verify_audit_chain()
    assert chain["valid"] is True, chain
    assert chain["mcp"]["total"] == 1
    assert chain["admin"]["total"] == 1
    assert admin["hash_v"] == 3


def test_chain_of_many_v3_rows_verifies_on_postgres(pg_db):
    for seq in range(5):
        _log_mcp(pg_db, seq=seq, scan_time_ms=1.5 * (seq + 1))
        _log_admin(pg_db, seq=seq)
    chain = pg_db.verify_audit_chain()
    assert chain["valid"] is True, chain
    assert chain["mcp"]["total"] == 5
    assert chain["admin"]["total"] == 5


# ── adversarial mutations fail closed on Postgres ────────────────────────────

MCP_PG_MUTATIONS = [
    ("principal_id", "someone-else"),
    ("matched_rule", "no_rule_matched"),
    ("blocked_by", ""),
    ("effects", '["read"]'),
    ("observed_status_code", 403),
    ("observed_outcome", "denied"),
    ("drift_reasons", '["harmless rewording"]'),
    ("confidence", 0.01),
    ("scan_time_ms", 999.75),
    ("prev_hash", "e" * 64),
    ("hash_v", 1),
    ("hash_v", 4),  # future version must not be reinterpreted as v3
]


@pytest.mark.parametrize("column,tampered", MCP_PG_MUTATIONS)
def test_mutating_mcp_field_fails_closed_on_postgres(pg_db, column, tampered):
    saved = _log_mcp(pg_db)
    _set_column(pg_db, "mcp_audit_log", column, tampered, saved["id"])
    assert pg_db.verify_mcp_audit_record(saved["id"])["chain_verified"] is False
    assert pg_db.verify_audit_chain()["valid"] is False


def test_mutating_admin_nested_details_fails_closed_on_postgres(pg_db):
    saved = _log_admin(pg_db)
    _set_column(
        pg_db,
        "admin_audit_log",
        "details",
        '{"nested":{"scopes":["mcp.call",3]},"plan":"developer"}',
        saved["id"],
    )
    chain = pg_db.verify_audit_chain()
    assert chain["valid"] is False
    assert chain["broken_at"]["table"] == "admin_audit_log"


# ── float integrity on real float8 storage ────────────────────────────────────


def test_sub_precision_float_mutation_fails_closed_on_postgres(pg_db):
    """The lossless-encoding regression: 0.85 -> 0.8500001 aliased under the
    old .6f canonical form and verified after mutation."""
    saved = _log_mcp(pg_db, confidence=0.85)
    _set_column(pg_db, "mcp_audit_log", "confidence", 0.8500001, saved["id"])
    assert pg_db.verify_mcp_audit_record(saved["id"])["chain_verified"] is False
    assert pg_db.verify_audit_chain()["valid"] is False


def test_extreme_floats_round_trip_and_verify_on_postgres(pg_db):
    """Every accepted double must round-trip float8 storage bit-exactly."""
    for confidence, scan_time_ms in [
        (0.8500001, 12.5000001),
        (5e-324, 1.7976931348623157e308),
        (0.0, 0.0),
    ]:
        saved = _log_mcp(pg_db, confidence=confidence, scan_time_ms=scan_time_ms)
        assert pg_db.verify_mcp_audit_record(saved["id"])["chain_verified"] is True
    assert pg_db.verify_audit_chain()["valid"] is True


def test_negative_zero_is_normalized_before_hashing_on_postgres(pg_db):
    """float8 preserves -0.0 but SQLite does not, so writers normalize it to
    0.0 before hashing; the stored row must verify and hold +0.0."""
    import math

    saved = _log_mcp(pg_db, confidence=-0.0, scan_time_ms=-0.0)
    row = pg_db.get_mcp_audit_log(saved["id"])
    assert math.copysign(1.0, float(row["confidence"])) == 1.0
    assert math.copysign(1.0, float(row["scan_time_ms"])) == 1.0
    assert pg_db.verify_mcp_audit_record(saved["id"])["chain_verified"] is True


def test_nonfinite_float_event_is_rejected_on_postgres(pg_db):
    before = _count(pg_db, "mcp_audit_log")
    with pytest.raises(ValueError):
        _log_mcp(pg_db, confidence=float("nan"))
    with pytest.raises(ValueError):
        _log_mcp(pg_db, scan_time_ms=float("inf"))
    assert _count(pg_db, "mcp_audit_log") == before


def test_tampering_float_to_nan_fails_cleanly_on_postgres(pg_db):
    """Postgres float8 can store NaN (SQLite cannot); a row tampered to NaN
    must fail verification with a clean verdict, never an exception."""
    saved = _log_mcp(pg_db)
    _set_column(pg_db, "mcp_audit_log", "confidence", float("nan"), saved["id"])
    assert pg_db.verify_mcp_audit_record(saved["id"])["chain_verified"] is False
    assert pg_db.verify_audit_chain()["valid"] is False


# ── typed storage: JSON stored-form tampering on Postgres ─────────────────────
#
# Postgres INTEGER/DOUBLE PRECISION columns reject 200.9-in-int and ''-in-
# numeric at the SQL layer (covered by canonical-envelope unit tests); the
# JSON columns are TEXT on both backends, so the ''-for-default alias is a
# real Postgres tampering vector too.


@pytest.mark.parametrize("column", ["effects", "warnings"])
def test_empty_json_list_tampered_to_empty_text_fails_on_postgres(pg_db, column):
    saved = _log_mcp(pg_db, effects=[], warnings=[], data_classes=[], argument_keys=[])
    _set_column(pg_db, "mcp_audit_log", column, "", saved["id"])
    assert pg_db.verify_mcp_audit_record(saved["id"])["chain_verified"] is False
    assert pg_db.verify_audit_chain()["valid"] is False


def test_empty_admin_details_tampered_to_empty_text_fails_on_postgres(pg_db):
    saved = _log_admin(pg_db, details={})
    _set_column(pg_db, "admin_audit_log", "details", "", saved["id"])
    chain = pg_db.verify_audit_chain()
    assert chain["valid"] is False
    assert chain["broken_at"]["table"] == "admin_audit_log"


def test_empty_checkpoint_actor_tampered_to_empty_text_fails_on_postgres(pg_db):
    _log_mcp(pg_db, days_ago=40, seq=0)
    _log_mcp(pg_db, days_ago=1, seq=0)
    pg_db.prune_retention(POLICY)  # no actor -> stored actor is '{}'
    checkpoint = _checkpoints(pg_db, "mcp_audit_log")[0]
    assert checkpoint["actor"] == "{}"

    _set_column(pg_db, "audit_chain_checkpoints", "actor", "", checkpoint["id"])
    assert pg_db.verify_audit_chain()["valid"] is False


def test_optional_null_status_codes_verify_on_postgres(pg_db):
    saved = _log_mcp(
        pg_db, expected_status_code=None, observed_status_code=None, scan_time_ms=None
    )
    row = pg_db.get_mcp_audit_log(saved["id"])
    assert row["expected_status_code"] is None
    assert row["scan_time_ms"] is None
    assert pg_db.verify_mcp_audit_record(saved["id"])["chain_verified"] is True
    assert pg_db.verify_audit_chain()["valid"] is True


def test_writer_rejects_non_integer_status_code_on_postgres(pg_db):
    before = _count(pg_db, "mcp_audit_log")
    with pytest.raises(ValueError):
        _log_mcp(pg_db, expected_status_code=200.9)
    assert _count(pg_db, "mcp_audit_log") == before


# ── exact hash-version enforcement on Postgres ────────────────────────────────


@pytest.mark.parametrize("bad_version", [0, -1, 4, 99])
def test_invalid_mcp_hash_version_fails_closed_on_postgres(pg_db, bad_version):
    saved = _log_mcp(pg_db)
    _set_column(pg_db, "mcp_audit_log", "hash_v", bad_version, saved["id"])
    record = pg_db.verify_mcp_audit_record(saved["id"])
    assert record["chain_verified"] is False, record
    chain = pg_db.verify_audit_chain()
    assert chain["valid"] is False
    assert chain["reason"] == "unsupported hash version"


def test_admin_future_hash_version_fails_closed_on_postgres(pg_db):
    saved = _log_admin(pg_db)
    _set_column(pg_db, "admin_audit_log", "hash_v", 4, saved["id"])
    chain = pg_db.verify_audit_chain()
    assert chain["valid"] is False
    assert chain["reason"] == "unsupported hash version"


def test_checkpoint_future_hash_version_fails_closed_on_postgres(pg_db):
    _log_mcp(pg_db, days_ago=40, seq=0)
    _log_mcp(pg_db, days_ago=1, seq=0)
    pg_db.prune_retention(POLICY, actor=ACTOR)
    checkpoint = _checkpoints(pg_db, "mcp_audit_log")[0]

    _set_column(pg_db, "audit_chain_checkpoints", "hash_v", 4, checkpoint["id"])
    chain = pg_db.verify_audit_chain()
    assert chain["valid"] is False
    assert chain["reason"] == "unsupported checkpoint hash version"


# ── boundary binding on Postgres ──────────────────────────────────────────────


def _forge_checkpoints(pg_db, chain, mutate):
    """Rewrite checkpoint fields AND recompute the checkpoint hash chain,
    modeling an actor with database write access."""
    with pg_db._db_lock, pg_db.get_conn() as conn:
        checkpoints = pg_db._list_chain_checkpoints(conn, chain)
        prev = "GENESIS"
        for cp in checkpoints:
            mutate(cp)
            cp["prev_hash"] = prev
            cp["integrity_hash"] = pg_db.audit_envelope.compute_hash_v3(
                "audit_chain_checkpoint", cp, prev
            )
            conn.execute(
                "UPDATE audit_chain_checkpoints SET last_deleted_id = ?,"
                " last_deleted_hash = ?, first_retained_id = ?,"
                " first_retained_prev_hash = ?, prev_hash = ?,"
                " integrity_hash = ? WHERE id = ?",
                (
                    cp["last_deleted_id"],
                    cp["last_deleted_hash"],
                    cp["first_retained_id"],
                    cp["first_retained_prev_hash"],
                    cp["prev_hash"],
                    cp["integrity_hash"],
                    cp["id"],
                ),
            )
            prev = cp["integrity_hash"]


def test_forged_first_retained_prev_hash_fails_on_postgres(pg_db):
    _log_mcp(pg_db, days_ago=40, seq=0)
    kept = _log_mcp(pg_db, days_ago=1, seq=0)
    pg_db.prune_retention(POLICY, actor=ACTOR)

    def mutate(cp):
        cp["first_retained_prev_hash"] = "f" * 64

    _forge_checkpoints(pg_db, "mcp_audit_log", mutate)
    assert pg_db.verify_audit_chain()["valid"] is False
    assert pg_db.verify_mcp_audit_record(kept["id"])["chain_verified"] is False


def test_forged_last_deleted_hash_fails_on_postgres(pg_db):
    _log_mcp(pg_db, days_ago=40, seq=0)
    kept = _log_mcp(pg_db, days_ago=1, seq=0)
    pg_db.prune_retention(POLICY, actor=ACTOR)

    def mutate(cp):
        cp["last_deleted_hash"] = "f" * 64

    _forge_checkpoints(pg_db, "mcp_audit_log", mutate)
    assert pg_db.verify_audit_chain()["valid"] is False
    assert pg_db.verify_mcp_audit_record(kept["id"])["chain_verified"] is False


def test_tampered_retained_row_prev_hash_fails_on_postgres(pg_db):
    _log_mcp(pg_db, days_ago=40, seq=0)
    kept = _log_mcp(pg_db, days_ago=1, seq=0)
    pg_db.prune_retention(POLICY, actor=ACTOR)

    with pg_db._db_lock, pg_db.get_conn() as conn:
        row = pg_db.row_to_plain_dict(
            conn.execute(
                "SELECT * FROM mcp_audit_log WHERE id = ?", (kept["id"],)
            ).fetchone()
        )
        row["prev_hash"] = "f" * 64
        forged = pg_db.audit_envelope.compute_hash_v3(
            "mcp_audit_log", row, row["prev_hash"]
        )
        conn.execute(
            "UPDATE mcp_audit_log SET prev_hash = ?, integrity_hash = ?"
            " WHERE id = ?",
            (row["prev_hash"], forged, kept["id"]),
        )
    assert pg_db.verify_audit_chain()["valid"] is False
    assert pg_db.verify_mcp_audit_record(kept["id"])["chain_verified"] is False


# ── legacy rows keep verifying on Postgres ────────────────────────────────────


def test_legacy_v1_and_v2_rows_verify_next_to_v3_on_postgres(pg_db):
    ts = "2026-01-01T00:00:00+00:00"
    with pg_db._db_lock, pg_db.get_conn() as conn:
        v1_hash = pg_db._compute_audit_hash(
            "GENESIS", ts, "allow", "legacy_tool", "legacy_role", "legacy reason"
        )
        v1_id = pg_db._insert_returning_id(
            conn,
            """
            INSERT INTO mcp_audit_log
              (ts, server_id, tool_name, role, action, reason,
               prev_hash, integrity_hash, hash_v)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)
            """,
            (
                ts,
                "legacy-server",
                "legacy_tool",
                "legacy_role",
                "allow",
                "legacy reason",
                "GENESIS",
                v1_hash,
            ),
        )
        v2_hash = pg_db._compute_audit_hash_v2(
            v1_hash,
            ts,
            "deny",
            "v2_tool",
            "v2_role",
            "v2 reason",
            "v2-server",
            "v2-call-id",
            "sha256:" + "d" * 64,
            "",
            "",
        )
        v2_id = pg_db._insert_returning_id(
            conn,
            """
            INSERT INTO mcp_audit_log
              (ts, server_id, tool_name, role, action, reason, call_id,
               argument_hash, prev_hash, integrity_hash, hash_v)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 2)
            """,
            (
                ts,
                "v2-server",
                "v2_tool",
                "v2_role",
                "deny",
                "v2 reason",
                "v2-call-id",
                "sha256:" + "d" * 64,
                v1_hash,
                v2_hash,
            ),
        )
    v3 = _log_mcp(pg_db)

    assert pg_db.verify_mcp_audit_record(v1_id)["chain_verified"] is True
    assert pg_db.verify_mcp_audit_record(v2_id)["chain_verified"] is True
    assert pg_db.verify_mcp_audit_record(v3["id"])["chain_verified"] is True
    chain = pg_db.verify_audit_chain()
    assert chain["valid"] is True, chain
    assert chain["mcp"]["total"] == 3


# ── retention checkpoints on Postgres ─────────────────────────────────────────


def test_prune_checkpoints_and_verifies_on_postgres(pg_db):
    _log_mcp(pg_db, days_ago=40, seq=0)
    old_b = _log_mcp(pg_db, days_ago=40, seq=1)
    kept = _log_mcp(pg_db, days_ago=1, seq=0)
    _log_admin(pg_db, days_ago=40, seq=0)
    _log_admin(pg_db, days_ago=1, seq=0)

    boundary = pg_db.get_mcp_audit_log(old_b["id"])["integrity_hash"]
    assert pg_db.verify_audit_chain()["valid"] is True

    result = pg_db.prune_retention(POLICY, actor=ACTOR)
    assert result["mcp_audit_deleted"] == 2
    assert result["admin_audit_deleted"] == 1

    checkpoint = _checkpoints(pg_db, "mcp_audit_log")[0]
    assert checkpoint["last_deleted_hash"] == boundary
    assert checkpoint["first_retained_id"] == kept["id"]
    assert checkpoint["first_retained_prev_hash"] == boundary

    chain = pg_db.verify_audit_chain()
    assert chain["valid"] is True, chain
    assert chain["mcp"]["anchor"] == boundary
    assert pg_db.verify_mcp_audit_record(kept["id"])["chain_verified"] is True

    # idempotent: second prune is a no-op
    second = pg_db.prune_retention(POLICY, actor=ACTOR)
    assert second["mcp_audit_deleted"] == 0
    assert second["mcp_audit_checkpoint_id"] is None
    assert len(_checkpoints(pg_db, "mcp_audit_log")) == 1


def test_all_row_prune_then_append_continues_from_checkpoint_on_postgres(pg_db):
    old = _log_mcp(pg_db, days_ago=40, seq=0)
    boundary = pg_db.get_mcp_audit_log(old["id"])["integrity_hash"]

    result = pg_db.prune_retention(POLICY, actor=ACTOR)
    assert result["mcp_audit_deleted"] == 1
    assert _count(pg_db, "mcp_audit_log") == 0
    assert pg_db.verify_audit_chain()["valid"] is True

    fresh = _log_mcp(pg_db)
    row = pg_db.get_mcp_audit_log(fresh["id"])
    assert row["prev_hash"] == boundary
    assert pg_db.verify_mcp_audit_record(fresh["id"])["chain_verified"] is True
    assert pg_db.verify_audit_chain()["valid"] is True


def test_failed_prune_rolls_back_atomically_on_postgres(pg_db, monkeypatch):
    _log_mcp(pg_db, days_ago=40, seq=0)
    _log_mcp(pg_db, days_ago=1, seq=0)
    before = _count(pg_db, "mcp_audit_log")

    def boom(conn, table, boundary_id):
        raise RuntimeError("injected deletion failure")

    monkeypatch.setattr(pg_db, "_delete_chain_prefix", boom)
    with pytest.raises(RuntimeError, match="injected deletion failure"):
        pg_db.prune_retention(POLICY, actor=ACTOR)
    monkeypatch.undo()

    # the transaction rolled back: no checkpoint, no deletion, chain valid
    assert _count(pg_db, "mcp_audit_log") == before
    assert _checkpoints(pg_db, "mcp_audit_log") == []
    assert pg_db.verify_audit_chain()["valid"] is True

    # and a retry completes cleanly
    result = pg_db.prune_retention(POLICY, actor=ACTOR)
    assert result["mcp_audit_deleted"] == 1
    assert pg_db.verify_audit_chain()["valid"] is True


def test_checkpoint_tampering_fails_closed_on_postgres(pg_db):
    _log_mcp(pg_db, days_ago=40, seq=0)
    _log_mcp(pg_db, days_ago=1, seq=0)
    pg_db.prune_retention(POLICY, actor=ACTOR)
    checkpoint = _checkpoints(pg_db, "mcp_audit_log")[0]

    _set_column(
        pg_db,
        "audit_chain_checkpoints",
        "last_deleted_hash",
        "f" * 64,
        checkpoint["id"],
    )
    assert pg_db.verify_audit_chain()["valid"] is False
