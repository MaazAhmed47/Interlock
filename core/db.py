"""
SQLite-backed API key storage.

Replaces legacy per-key dictionaries with a single ApiKey record.

All per-key state lives in one row. JSON columns for the things that vary in shape
(custom policies, SIEM configs) so we don't need a migration every time the rule
engine grows a new field.

Postgres support is available behind DATABASE_URL for hosted deployments. The
schema initializer is backend-aware and idempotent for SQLite/Postgres. We use
plain SQL — no ORM — to keep the surface tiny and review-able.
"""

import os
import json
import time
import secrets
import sqlite3
import hashlib
import logging
import copy
import re
from contextlib import contextmanager
from datetime import datetime, timezone, timedelta
from threading import Lock
from typing import Optional, List, Dict, Any
from core.mcp_drift import classify_tool_drift

logger = logging.getLogger("interlock.db")

DATABASE_URL = (os.getenv("DATABASE_URL") or "").strip()
USE_POSTGRES = DATABASE_URL.startswith(("postgresql://", "postgres://"))
DB_PATH = os.getenv("FIREWALL_DB_PATH", "data/firewall.db")
_db_lock = Lock()  # SQLite is fine concurrent-read, one-writer; lock guards writes
_pg_pool = None
_pg_pool_lock = Lock()


# ── Connection helper ────────────────────────────────────────────────────────
def _postgres_pool_size(name: str, default: int) -> int:
    try:
        return max(1, int(os.getenv(name, str(default))))
    except ValueError:
        return default


def _get_postgres_pool():
    global _pg_pool
    if _pg_pool is not None:
        return _pg_pool

    with _pg_pool_lock:
        if _pg_pool is not None:
            return _pg_pool

        import psycopg2.extras
        import psycopg2.pool

        minconn = _postgres_pool_size("POSTGRES_POOL_MIN", 1)
        maxconn = max(minconn, _postgres_pool_size("POSTGRES_POOL_MAX", 5))
        _pg_pool = psycopg2.pool.ThreadedConnectionPool(
            minconn,
            maxconn,
            DATABASE_URL,
            cursor_factory=psycopg2.extras.RealDictCursor,
        )
        return _pg_pool


class _PostgresConn:
    def __init__(self, conn):
        self._conn = conn

    def execute(self, sql: str, params=()):
        cur = self._conn.cursor()
        cur.execute(_pg_sql(sql), params)
        return cur

    def executescript(self, script: str) -> None:
        for statement in script.split(";"):
            statement = statement.strip()
            if statement:
                self.execute(statement)

    def close(self) -> None:
        self._conn.close()


_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_POSTGRES_BOOLEAN_COLUMNS = ("is_active", "verified")


def _postgres_column_definition(definition: str, column: str = "") -> str:
    converted = definition.strip()
    if column in _POSTGRES_BOOLEAN_COLUMNS:
        converted = re.sub(r"\bINTEGER\b", "BOOLEAN", converted, count=1)
        converted = re.sub(
            r"DEFAULT\s+1\b", "DEFAULT TRUE", converted, flags=re.IGNORECASE
        )
        converted = re.sub(
            r"DEFAULT\s+0\b", "DEFAULT FALSE", converted, flags=re.IGNORECASE
        )
    return converted


def _postgres_schema_sql(sql: str) -> str:
    converted = sql.replace("INTEGER PRIMARY KEY AUTOINCREMENT", "SERIAL PRIMARY KEY")
    for column in _POSTGRES_BOOLEAN_COLUMNS:
        converted = re.sub(
            rf"(\b{column}\s+)INTEGER(\s+NOT NULL)?\s+DEFAULT\s+1\b",
            lambda m: f"{m.group(1)}BOOLEAN{m.group(2) or ''} DEFAULT TRUE",
            converted,
            flags=re.IGNORECASE,
        )
        converted = re.sub(
            rf"(\b{column}\s+)INTEGER(\s+NOT NULL)?\s+DEFAULT\s+0\b",
            lambda m: f"{m.group(1)}BOOLEAN{m.group(2) or ''} DEFAULT FALSE",
            converted,
            flags=re.IGNORECASE,
        )
    return converted


def _pg_sql(sql: str) -> str:
    converted = _postgres_schema_sql(sql)
    insert_ignore = "INSERT OR IGNORE INTO" in converted
    insert_replace_system_config = "INSERT OR REPLACE INTO system_config" in converted
    converted = converted.replace("INSERT OR IGNORE INTO", "INSERT INTO")
    converted = converted.replace(
        "INSERT OR REPLACE INTO system_config", "INSERT INTO system_config"
    )
    converted = converted.replace("?", "%s")
    if insert_ignore:
        converted = converted.rstrip().rstrip(";") + " ON CONFLICT DO NOTHING"
    if insert_replace_system_config:
        converted = (
            converted.rstrip().rstrip(";")
            + " ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value"
        )
    return converted


def _schema_statements(script: str) -> List[str]:
    return [statement.strip() for statement in script.split(";") if statement.strip()]


def _is_index_statement(statement: str) -> bool:
    return statement.lstrip().upper().startswith("CREATE INDEX")


def _run_schema_statements(conn, *, indexes: bool) -> None:
    for statement in _schema_statements(SCHEMA):
        if _is_index_statement(statement) == indexes:
            conn.execute(statement)


@contextmanager
def get_conn():
    raw = None
    if USE_POSTGRES:
        pool = _get_postgres_pool()
        raw = pool.getconn()
        raw.autocommit = True
        conn = _PostgresConn(raw)
    else:
        os.makedirs(os.path.dirname(DB_PATH) or ".", exist_ok=True)
        conn = sqlite3.connect(DB_PATH, timeout=10, isolation_level=None)  # autocommit
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")  # better concurrency
        conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
    finally:
        if USE_POSTGRES:
            _get_postgres_pool().putconn(raw)
        else:
            conn.close()


# ── Schema ───────────────────────────────────────────────────────────────────
SCHEMA = """
CREATE TABLE IF NOT EXISTS api_keys (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    key_hash        TEXT    NOT NULL UNIQUE,    -- sha256 of raw key, never the raw key
    key_prefix      TEXT    NOT NULL,           -- first 12 chars, for display
    label           TEXT    NOT NULL DEFAULT '',
    plan            TEXT    NOT NULL DEFAULT 'free',
    monthly_limit   INTEGER NOT NULL DEFAULT 1000,
    rate_per_min    INTEGER NOT NULL DEFAULT 10,
    fail_mode       TEXT    NOT NULL DEFAULT 'fail_open_safe',
    webhook_url     TEXT,
    custom_policy   TEXT,                        -- JSON {blocked_keywords, max_prompt_length}
    siem_configs    TEXT,                        -- JSON list of SIEM provider configs
    upstream_key    TEXT,                        -- if customer wants us to forward their LLM key
    is_active       INTEGER NOT NULL DEFAULT 1,
    created_at      TEXT    NOT NULL,
    revoked_at      TEXT
);

CREATE INDEX IF NOT EXISTS idx_keys_active ON api_keys(is_active);

CREATE TABLE IF NOT EXISTS usage_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    key_id          INTEGER NOT NULL,
    ts              TEXT    NOT NULL,
    endpoint        TEXT    NOT NULL,
    threat_blocked  INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (key_id) REFERENCES api_keys(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_usage_key_ts ON usage_log(key_id, ts);

CREATE TABLE IF NOT EXISTS scan_history (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    key_hash         TEXT    NOT NULL,
    ts               TEXT    NOT NULL,
    is_threat        INTEGER NOT NULL DEFAULT 0,
    threat_level     TEXT    NOT NULL DEFAULT 'SAFE',
    threat_type      TEXT    NOT NULL DEFAULT '',
    reason           TEXT    NOT NULL DEFAULT '',
    confidence       REAL,
    layer_caught     TEXT    NOT NULL DEFAULT '',
    scan_time_ms     REAL,
    risk_score       INTEGER,
    endpoint         TEXT    NOT NULL DEFAULT '/scan',
    prompt_preview   TEXT    NOT NULL DEFAULT '',
    sanitized_output TEXT,
    redactions       TEXT    NOT NULL DEFAULT '[]'
);

CREATE INDEX IF NOT EXISTS idx_scan_history_key_ts ON scan_history(key_hash, ts);

CREATE TABLE IF NOT EXISTS mcp_servers (
    server_id       TEXT    PRIMARY KEY,
    url             TEXT    NOT NULL,
    description     TEXT    NOT NULL DEFAULT '',
    allowed_tools   TEXT    NOT NULL DEFAULT '[]',  -- JSON list
    blocked_tools   TEXT    NOT NULL DEFAULT '[]',  -- JSON list
    rate_limit      INTEGER NOT NULL DEFAULT 60,
    auth_type       TEXT    NOT NULL DEFAULT 'none',
    auth_header     TEXT    NOT NULL DEFAULT '',
    auth_token_env  TEXT    NOT NULL DEFAULT '',
    verified        INTEGER NOT NULL DEFAULT 0,
    registered_at   TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS mcp_tool_metadata (
    server_id           TEXT    NOT NULL,
    tool_name           TEXT    NOT NULL,
    tool_schema_hash    TEXT    NOT NULL,
    description_hash    TEXT    NOT NULL,
    normalized_metadata TEXT    NOT NULL,
    raw_annotations     TEXT    NOT NULL DEFAULT '{}',
    raw_tool_definition TEXT    NOT NULL DEFAULT '{}',
    first_seen          TEXT    NOT NULL,
    last_seen           TEXT    NOT NULL,
    last_changed        TEXT,
    status              TEXT    NOT NULL DEFAULT 'active',
    drift_severity      TEXT    NOT NULL DEFAULT 'none',
    drift_action        TEXT    NOT NULL DEFAULT 'allow',
    drift_types         TEXT    NOT NULL DEFAULT '[]',
    drift_reasons       TEXT    NOT NULL DEFAULT '[]',
    previous_metadata   TEXT    NOT NULL DEFAULT '{}',
    previous_tool_definition TEXT NOT NULL DEFAULT '{}',
    PRIMARY KEY (server_id, tool_name),
    FOREIGN KEY (server_id) REFERENCES mcp_servers(server_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_mcp_tool_metadata_server ON mcp_tool_metadata(server_id);
CREATE INDEX IF NOT EXISTS idx_mcp_tool_metadata_status ON mcp_tool_metadata(status);

CREATE TABLE IF NOT EXISTS mcp_audit_log (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    ts                  TEXT    NOT NULL,
    server_id           TEXT    NOT NULL,
    tool_name           TEXT    NOT NULL,
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
    prev_hash           TEXT    NOT NULL DEFAULT '',
    integrity_hash      TEXT    NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_mcp_audit_ts ON mcp_audit_log(ts);
CREATE INDEX IF NOT EXISTS idx_mcp_audit_server_tool ON mcp_audit_log(server_id, tool_name);
CREATE INDEX IF NOT EXISTS idx_mcp_audit_action ON mcp_audit_log(action);
CREATE INDEX IF NOT EXISTS idx_mcp_audit_drift_severity ON mcp_audit_log(drift_severity);

CREATE TABLE IF NOT EXISTS tool_surface_snapshots (
    surface_hash   TEXT PRIMARY KEY,
    canonical_json TEXT NOT NULL,
    created_at     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS mcp_permission_probes (
    probe_id                   TEXT PRIMARY KEY,
    server_id                  TEXT    NOT NULL,
    tool_name                  TEXT    NOT NULL,
    argument_hash              TEXT    NOT NULL,
    expected_outcome           TEXT    NOT NULL,
    expected_status_code       INTEGER,
    expected_error_fingerprint TEXT    NOT NULL DEFAULT '',
    non_production             INTEGER NOT NULL DEFAULT 1,
    safety_note                TEXT    NOT NULL,
    created_at                 TEXT    NOT NULL,
    updated_at                 TEXT    NOT NULL,
    last_run_at                TEXT,
    last_observed_outcome      TEXT    NOT NULL DEFAULT '',
    last_observed_status_code  INTEGER,
    last_observed_error_class  TEXT    NOT NULL DEFAULT '',
    last_decision              TEXT    NOT NULL DEFAULT '',
    last_finding_types         TEXT    NOT NULL DEFAULT '[]',
    last_audit_id              INTEGER,
    FOREIGN KEY (server_id) REFERENCES mcp_servers(server_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_mcp_permission_probes_server_tool
ON mcp_permission_probes(server_id, tool_name);

CREATE TABLE IF NOT EXISTS system_config (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS admin_tokens (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    token_hash      TEXT    NOT NULL UNIQUE,
    token_prefix    TEXT    NOT NULL,
    label           TEXT    NOT NULL DEFAULT '',
    role            TEXT    NOT NULL DEFAULT 'operator',
    permissions     TEXT    NOT NULL DEFAULT '[]',
    is_active       INTEGER NOT NULL DEFAULT 1,
    created_at      TEXT    NOT NULL,
    revoked_at      TEXT,
    last_used_at    TEXT
);

CREATE INDEX IF NOT EXISTS idx_admin_tokens_active ON admin_tokens(is_active);
CREATE INDEX IF NOT EXISTS idx_admin_tokens_prefix ON admin_tokens(token_prefix);

CREATE TABLE IF NOT EXISTS admin_audit_log (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
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

CREATE INDEX IF NOT EXISTS idx_admin_audit_ts ON admin_audit_log(ts);
CREATE INDEX IF NOT EXISTS idx_admin_audit_action ON admin_audit_log(action);
CREATE INDEX IF NOT EXISTS idx_admin_audit_actor ON admin_audit_log(actor_auth_type, actor_subject, actor_token_prefix);

CREATE TABLE IF NOT EXISTS shadow_mcp_servers (
    id                     INTEGER PRIMARY KEY AUTOINCREMENT,
    url                    TEXT NOT NULL UNIQUE,
    probe_path             TEXT DEFAULT '/tools/list',
    status                 TEXT DEFAULT 'unreviewed',
    first_seen             TEXT NOT NULL,
    last_seen              TEXT NOT NULL,
    auth_required          INTEGER DEFAULT 0,
    tool_listing_available INTEGER DEFAULT 0,
    risk_score             INTEGER DEFAULT 0,
    notes                  TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS shadow_scan_targets (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    url        TEXT NOT NULL UNIQUE,
    probe_path TEXT DEFAULT '/tools/list',
    enabled    INTEGER DEFAULT 1,
    added_at   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS latency_samples (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          TEXT    NOT NULL,
    endpoint    TEXT    NOT NULL DEFAULT '/scan',
    latency_ms  REAL    NOT NULL,
    is_threat   INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_latency_samples_ts ON latency_samples(ts);

CREATE TABLE IF NOT EXISTS policies (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    policy_type TEXT    NOT NULL,
    name        TEXT    NOT NULL,
    server_id   TEXT    NOT NULL DEFAULT '',
    rules_json  TEXT    NOT NULL,
    is_active   INTEGER NOT NULL DEFAULT 1,
    created_at  TEXT    NOT NULL,
    updated_at  TEXT    NOT NULL,
    updated_by  TEXT    NOT NULL DEFAULT '',
    UNIQUE(policy_type, name, server_id)
);

CREATE INDEX IF NOT EXISTS idx_policies_type_name ON policies(policy_type, name, server_id);
CREATE INDEX IF NOT EXISTS idx_policies_active ON policies(is_active);
"""


def init_db() -> None:
    with _db_lock, get_conn() as conn:
        _run_schema_statements(conn, indexes=False)
        _ensure_column(conn, "scan_history", "key_hash", "TEXT NOT NULL DEFAULT ''")
        _ensure_column(conn, "scan_history", "ts", "TEXT NOT NULL DEFAULT ''")
        _ensure_column(conn, "scan_history", "confidence", "REAL")
        _ensure_column(
            conn, "scan_history", "endpoint", "TEXT NOT NULL DEFAULT '/scan'"
        )
        _ensure_column(conn, "scan_history", "sanitized_output", "TEXT")
        _ensure_column(conn, "scan_history", "redactions", "TEXT NOT NULL DEFAULT '[]'")
        _ensure_column(
            conn, "mcp_tool_metadata", "drift_severity", "TEXT NOT NULL DEFAULT 'none'"
        )
        _ensure_column(
            conn, "mcp_tool_metadata", "drift_action", "TEXT NOT NULL DEFAULT 'allow'"
        )
        _ensure_column(
            conn, "mcp_tool_metadata", "drift_types", "TEXT NOT NULL DEFAULT '[]'"
        )
        _ensure_column(
            conn, "mcp_tool_metadata", "drift_reasons", "TEXT NOT NULL DEFAULT '[]'"
        )
        _ensure_column(
            conn, "mcp_tool_metadata", "previous_metadata", "TEXT NOT NULL DEFAULT '{}'"
        )
        _ensure_column(
            conn,
            "mcp_tool_metadata",
            "previous_tool_definition",
            "TEXT NOT NULL DEFAULT '{}'",
        )
        _ensure_column(
            conn, "mcp_audit_log", "drift_status", "TEXT NOT NULL DEFAULT ''"
        )
        _ensure_column(
            conn, "mcp_audit_log", "drift_severity", "TEXT NOT NULL DEFAULT 'none'"
        )
        _ensure_column(
            conn, "mcp_audit_log", "drift_action", "TEXT NOT NULL DEFAULT 'allow'"
        )
        _ensure_column(
            conn, "mcp_audit_log", "drift_types", "TEXT NOT NULL DEFAULT '[]'"
        )
        _ensure_column(
            conn, "mcp_audit_log", "drift_reasons", "TEXT NOT NULL DEFAULT '[]'"
        )
        _ensure_column(conn, "mcp_audit_log", "scan_time_ms", "REAL")
        _ensure_column(conn, "mcp_audit_log", "probe_id", "TEXT NOT NULL DEFAULT ''")
        _ensure_column(
            conn, "mcp_audit_log", "argument_hash", "TEXT NOT NULL DEFAULT ''"
        )
        _ensure_column(
            conn, "mcp_audit_log", "expected_outcome", "TEXT NOT NULL DEFAULT ''"
        )
        _ensure_column(conn, "mcp_audit_log", "expected_status_code", "INTEGER")
        _ensure_column(
            conn, "mcp_audit_log", "observed_outcome", "TEXT NOT NULL DEFAULT ''"
        )
        _ensure_column(conn, "mcp_audit_log", "observed_status_code", "INTEGER")
        _ensure_column(
            conn,
            "mcp_audit_log",
            "observed_error_class",
            "TEXT NOT NULL DEFAULT ''",
        )
        _ensure_column(conn, "api_keys", "max_response_bytes", "INTEGER DEFAULT 50000")
        _ensure_column(conn, "api_keys", "max_array_items", "INTEGER DEFAULT 500")
        _ensure_column(conn, "mcp_servers", "auth_type", "TEXT NOT NULL DEFAULT 'none'")
        _ensure_column(conn, "mcp_servers", "auth_header", "TEXT NOT NULL DEFAULT ''")
        _ensure_column(
            conn, "mcp_servers", "auth_token_env", "TEXT NOT NULL DEFAULT ''"
        )
        _ensure_column(conn, "mcp_servers", "source_type", "TEXT DEFAULT 'unknown'")
        _ensure_column(conn, "mcp_servers", "registry", "TEXT DEFAULT ''")
        _ensure_column(conn, "mcp_servers", "package_name", "TEXT DEFAULT ''")
        _ensure_column(conn, "mcp_servers", "package_version", "TEXT DEFAULT ''")
        _ensure_column(conn, "mcp_servers", "source_url", "TEXT DEFAULT ''")
        _ensure_column(conn, "mcp_servers", "source_hash", "TEXT DEFAULT ''")
        _ensure_column(
            conn, "mcp_servers", "provenance_status", "TEXT DEFAULT 'unknown'"
        )
        _ensure_column(
            conn, "admin_audit_log", "actor_email", "TEXT NOT NULL DEFAULT ''"
        )
        _ensure_column(
            conn, "admin_audit_log", "actor_subject", "TEXT NOT NULL DEFAULT ''"
        )
        _ensure_column(
            conn, "admin_audit_log", "actor_token_prefix", "TEXT NOT NULL DEFAULT ''"
        )
        _ensure_column(conn, "admin_audit_log", "reason", "TEXT NOT NULL DEFAULT ''")
        _ensure_column(conn, "admin_audit_log", "details", "TEXT NOT NULL DEFAULT '{}'")
        _ensure_column(conn, "mcp_audit_log", "prev_hash", "TEXT NOT NULL DEFAULT ''")
        _ensure_column(
            conn, "mcp_audit_log", "integrity_hash", "TEXT NOT NULL DEFAULT ''"
        )
        _ensure_column(
            conn, "mcp_audit_log", "drift_baseline_hash", "TEXT NOT NULL DEFAULT ''"
        )
        _ensure_column(
            conn, "mcp_audit_log", "drift_current_hash", "TEXT NOT NULL DEFAULT ''"
        )
        _ensure_column(conn, "admin_audit_log", "prev_hash", "TEXT NOT NULL DEFAULT ''")
        _ensure_column(
            conn, "admin_audit_log", "integrity_hash", "TEXT NOT NULL DEFAULT ''"
        )
        _run_schema_statements(conn, indexes=True)
    logger.info(
        "%s DB initialized", "Postgres" if USE_POSTGRES else f"SQLite at {DB_PATH}"
    )


# ── Helpers ──────────────────────────────────────────────────────────────────
def _hash_key(raw: str) -> str:
    """Hash the raw key. We never store raw keys — same approach as Stripe/GitHub."""
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _row_to_dict(row) -> Dict[str, Any]:
    d = dict(row)
    # Decode JSON columns
    for col in ("custom_policy", "siem_configs"):
        if d.get(col):
            try:
                d[col] = json.loads(d[col])
            except (json.JSONDecodeError, TypeError):
                d[col] = None
    return d


def _row_to_admin_token(row, include_hash: bool = False) -> Dict[str, Any]:
    d = dict(row)
    raw_permissions = d.get("permissions") or "[]"
    try:
        permissions = json.loads(raw_permissions)
    except (json.JSONDecodeError, TypeError):
        permissions = []
    if not isinstance(permissions, list):
        permissions = []
    d["permissions"] = permissions
    d["is_active"] = bool(d.get("is_active", False))
    if not include_hash:
        d.pop("token_hash", None)
    return d


def _is_integrity_error(exc: Exception) -> bool:
    return isinstance(exc, sqlite3.IntegrityError) or exc.__class__.__name__ in {
        "IntegrityError",
        "UniqueViolation",
    }


def _stable_json(value: Any) -> str:
    return json.dumps(value or {}, sort_keys=True, separators=(",", ":"), default=str)


def _hash_json(value: Any) -> str:
    return hashlib.sha256(_stable_json(value).encode("utf-8")).hexdigest()


def _hash_text(value: Any) -> str:
    return hashlib.sha256(str(value or "").encode("utf-8")).hexdigest()


def _compute_audit_hash(
    prev_hash: str,
    ts: str,
    action: str,
    tool_or_target: str,
    role: str,
    reason: str,
) -> str:
    data = f"{prev_hash}|{ts}|{action}|{tool_or_target}|{role}|{reason}"
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def _is_postgres_conn(conn) -> bool:
    return isinstance(conn, _PostgresConn)


def _validate_identifier(value: str) -> None:
    if not _IDENTIFIER_RE.match(value or ""):
        raise ValueError(f"Unsafe SQL identifier: {value!r}")


def _table_columns(conn, table: str) -> List[str]:
    _validate_identifier(table)
    if _is_postgres_conn(conn):
        rows = conn.execute(
            """
            SELECT column_name
              FROM information_schema.columns
             WHERE table_schema = current_schema()
               AND table_name = ?
             ORDER BY ordinal_position
            """,
            (table,),
        ).fetchall()
        return [row_value(row, "column_name", 0) for row in rows]
    rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    return [row_value(row, "name", 1) for row in rows]


def table_columns(table: str, conn=None) -> List[str]:
    if conn is not None:
        return _table_columns(conn, table)
    with get_conn() as owned_conn:
        return _table_columns(owned_conn, table)


def row_value(row, key: str, index: int = 0):
    if row is None:
        return None
    if isinstance(row, dict):
        return row.get(key)
    try:
        return row[key]
    except (KeyError, IndexError, TypeError):
        return row[index]


def row_to_plain_dict(row, columns: Optional[List[str]] = None) -> Dict[str, Any]:
    if row is None:
        return {}
    if isinstance(row, (dict, sqlite3.Row)):
        return dict(row)
    if columns is None:
        raise ValueError("columns are required for positional rows")
    return dict(zip(columns, row))


def _ensure_column(conn, table: str, column: str, definition: str) -> None:
    try:
        _validate_identifier(table)
        _validate_identifier(column)
        existing = set(_table_columns(conn, table))
        if column not in existing:
            column_definition = (
                _postgres_column_definition(definition, column)
                if _is_postgres_conn(conn)
                else definition
            )
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {column_definition}")
    except Exception:
        logger.exception("Failed to ensure column %s.%s", table, column)
        raise


def _unique_list(values: List[Any]) -> List[Any]:
    out = []
    for value in values:
        if value not in out:
            out.append(value)
    return out


# ── Plan defaults ────────────────────────────────────────────────────────────
PLAN_DEFAULTS = {
    "free": {
        "monthly_limit": 1000,
        "rate_per_min": 10,
        "fail_mode": "fail_closed",
        "max_response_bytes": 50_000,
        "max_array_items": 500,
    },
    "developer": {
        "monthly_limit": 50000,
        "rate_per_min": 60,
        "fail_mode": "fail_open_safe",
        "max_response_bytes": 50_000,
        "max_array_items": 500,
    },
    "startup": {
        "monthly_limit": 500000,
        "rate_per_min": 300,
        "fail_mode": "fail_open_safe",
        "max_response_bytes": 50_000,
        "max_array_items": 500,
    },
    "enterprise": {
        "monthly_limit": 0,
        "rate_per_min": 1000,
        "fail_mode": "fail_open_safe",
        "max_response_bytes": 50_000,
        "max_array_items": 500,
    },  # 0 = unlimited
}


ADMIN_ROLE_DEFAULTS = {
    "owner": ["*"],
    "operator": [
        "keys:read",
        "keys:write",
        "retention:read",
        "retention:write",
        "mcp:read",
        "mcp:write",
        "shadow:read",
        "shadow:write",
        "admin_audit:read",
        "metrics:read",
    ],
    "security_reviewer": [
        "keys:read",
        "retention:read",
        "mcp:read",
        "mcp:write",
        "shadow:read",
        "shadow:write",
        "admin_audit:read",
        "metrics:read",
    ],
    "auditor": [
        "keys:read",
        "retention:read",
        "mcp:read",
        "shadow:read",
        "admin_audit:read",
    ],
}


# ── Key generation ───────────────────────────────────────────────────────────
def generate_key(plan: str = "free", label: str = "", **overrides) -> Dict[str, Any]:
    """
    Generate a new API key. Returns the raw key ONCE (caller must show it to user
    and not store it; only the hash is persisted).
    """
    if plan not in PLAN_DEFAULTS:
        raise ValueError(f"Unknown plan '{plan}'. Valid: {list(PLAN_DEFAULTS)}")

    raw = f"lf_{plan}_{secrets.token_urlsafe(24)}"
    key_hash = _hash_key(raw)
    key_prefix = raw[:12]

    defaults = PLAN_DEFAULTS[plan]
    monthly_limit = overrides.get("monthly_limit", defaults["monthly_limit"])
    rate_per_min = overrides.get("rate_per_min", defaults["rate_per_min"])
    fail_mode = overrides.get("fail_mode", defaults["fail_mode"])
    webhook_url = overrides.get("webhook_url")
    custom_policy = overrides.get("custom_policy")
    siem_configs = overrides.get("siem_configs")
    upstream_key = overrides.get("upstream_key")
    max_response_bytes = overrides.get(
        "max_response_bytes", defaults.get("max_response_bytes", 50_000)
    )
    max_array_items = overrides.get(
        "max_array_items", defaults.get("max_array_items", 500)
    )

    with _db_lock, get_conn() as conn:
        conn.execute(
            """
            INSERT INTO api_keys
              (key_hash, key_prefix, label, plan, monthly_limit, rate_per_min,
               fail_mode, webhook_url, custom_policy, siem_configs, upstream_key,
               is_active, created_at, max_response_bytes, max_array_items)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                key_hash,
                key_prefix,
                label,
                plan,
                monthly_limit,
                rate_per_min,
                fail_mode,
                webhook_url,
                json.dumps(custom_policy) if custom_policy else None,
                json.dumps(siem_configs) if siem_configs else None,
                upstream_key,
                True,
                datetime.now(timezone.utc).isoformat(),
                max_response_bytes,
                max_array_items,
            ),
        )

    logger.info(
        "Issued new API key: prefix=%s plan=%s label=%s", key_prefix, plan, label
    )
    return {
        "raw_key": raw,
        "key_prefix": key_prefix,
        "plan": plan,
        "label": label,
        "warning": "Store this key now. It will never be shown again.",
    }


# ── Lookup / verification ────────────────────────────────────────────────────
def lookup_key(raw_key: str) -> Optional[Dict[str, Any]]:
    """
    Return the full key record by raw key, or None if not found / inactive.
    O(1) hash lookup — does not scan the table.
    """
    if not raw_key:
        return None
    key_hash = _hash_key(raw_key.strip())
    with get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM api_keys WHERE key_hash = ? AND is_active = TRUE",
            (key_hash,),
        ).fetchone()
    return _row_to_dict(row) if row else None


def revoke_key(key_prefix: str) -> bool:
    """Mark a key inactive. Lookup by prefix (admin doesn't have the raw key)."""
    with _db_lock, get_conn() as conn:
        cursor = conn.execute(
            "UPDATE api_keys SET is_active = FALSE, revoked_at = ? WHERE key_prefix = ? AND is_active = TRUE",
            (datetime.now(timezone.utc).isoformat(), key_prefix),
        )
        revoked = cursor.rowcount > 0
    if revoked:
        logger.info("Revoked API key: prefix=%s", key_prefix)
    return revoked


def list_keys(include_inactive: bool = False) -> List[Dict[str, Any]]:
    q = (
        "SELECT * FROM api_keys"
        if include_inactive
        else "SELECT * FROM api_keys WHERE is_active = TRUE"
    )
    with get_conn() as conn:
        rows = conn.execute(q + " ORDER BY created_at DESC").fetchall()
    out = []
    for r in rows:
        d = _row_to_dict(r)
        d.pop("key_hash", None)  # never expose hash externally
        out.append(d)
    return out


def update_key(key_prefix: str, **fields) -> bool:
    """Update mutable fields on a key. Whitelist what's editable."""
    EDITABLE = {
        "label",
        "plan",
        "monthly_limit",
        "rate_per_min",
        "fail_mode",
        "webhook_url",
        "custom_policy",
        "siem_configs",
        "upstream_key",
        "max_response_bytes",
        "max_array_items",
    }
    fields = {k: v for k, v in fields.items() if k in EDITABLE}
    if not fields:
        return False

    # JSON-encode the JSON columns
    for col in ("custom_policy", "siem_configs"):
        if (
            col in fields
            and fields[col] is not None
            and not isinstance(fields[col], str)
        ):
            fields[col] = json.dumps(fields[col])

    set_clause = ", ".join(f"{k} = ?" for k in fields)
    values = list(fields.values()) + [key_prefix]

    with _db_lock, get_conn() as conn:
        cursor = conn.execute(
            f"UPDATE api_keys SET {set_clause} WHERE key_prefix = ?",
            values,
        )
    return cursor.rowcount > 0


# -- Admin token management ---------------------------------------------------
def _normalize_permissions(permissions: Optional[List[str]]) -> List[str]:
    if not permissions:
        return []
    clean = []
    for permission in permissions:
        value = str(permission or "").strip()
        if value and value not in clean:
            clean.append(value)
    return clean


def generate_admin_token(
    label: str, role: str = "operator", permissions: Optional[List[str]] = None
) -> Dict[str, Any]:
    """Generate a scoped admin token. Returns the raw token once."""
    role = (role or "operator").strip()
    if role not in ADMIN_ROLE_DEFAULTS:
        raise ValueError(
            f"Unknown admin role '{role}'. Valid: {list(ADMIN_ROLE_DEFAULTS)}"
        )

    effective_permissions = _normalize_permissions(permissions)
    if not effective_permissions:
        effective_permissions = list(ADMIN_ROLE_DEFAULTS[role])

    raw = f"ia_{secrets.token_urlsafe(32)}"
    token_hash = _hash_key(raw)
    token_prefix = raw[:16]
    now = datetime.now(timezone.utc).isoformat()

    with _db_lock, get_conn() as conn:
        conn.execute(
            """
            INSERT INTO admin_tokens
              (token_hash, token_prefix, label, role, permissions, is_active, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                token_hash,
                token_prefix,
                label or "",
                role,
                json.dumps(effective_permissions),
                True,
                now,
            ),
        )

    logger.info(
        "Issued scoped admin token: prefix=%s role=%s label=%s",
        token_prefix,
        role,
        label,
    )
    return {
        "raw_token": raw,
        "token_prefix": token_prefix,
        "label": label or "",
        "role": role,
        "permissions": effective_permissions,
        "warning": "Store this admin token now. It will never be shown again.",
    }


def lookup_admin_token(raw_token: str) -> Optional[Dict[str, Any]]:
    if not raw_token:
        return None
    token_hash = _hash_key(raw_token.strip())
    now = datetime.now(timezone.utc).isoformat()
    with _db_lock, get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM admin_tokens WHERE token_hash = ? AND is_active = TRUE",
            (token_hash,),
        ).fetchone()
        if row:
            conn.execute(
                "UPDATE admin_tokens SET last_used_at = ? WHERE token_hash = ?",
                (now, token_hash),
            )
    return _row_to_admin_token(row) if row else None


def list_admin_tokens(include_inactive: bool = False) -> List[Dict[str, Any]]:
    q = (
        "SELECT * FROM admin_tokens"
        if include_inactive
        else "SELECT * FROM admin_tokens WHERE is_active = TRUE"
    )
    with get_conn() as conn:
        rows = conn.execute(q + " ORDER BY created_at DESC").fetchall()
    return [_row_to_admin_token(row) for row in rows]


def revoke_admin_token(token_prefix: str) -> bool:
    with _db_lock, get_conn() as conn:
        cursor = conn.execute(
            "UPDATE admin_tokens SET is_active = FALSE, revoked_at = ? WHERE token_prefix = ? AND is_active = TRUE",
            (datetime.now(timezone.utc).isoformat(), token_prefix),
        )
        revoked = cursor.rowcount > 0
    if revoked:
        logger.info("Revoked admin token: prefix=%s", token_prefix)
    return revoked


# -- Admin audit log -----------------------------------------------------------
def _json_dumps_object(value: Any) -> str:
    if value is None:
        return "{}"
    if isinstance(value, str):
        return value
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def log_admin_audit_event(event: Dict[str, Any]) -> Dict[str, Any]:
    """Persist an auditable admin control-plane action."""
    now = event.get("ts") or datetime.now(timezone.utc).isoformat()
    details = _json_dumps_object(event.get("details") or {})
    with _db_lock, get_conn() as conn:
        row = conn.execute(
            "SELECT integrity_hash FROM admin_audit_log ORDER BY id DESC LIMIT 1"
        ).fetchone()
        prev_hash = (dict(row).get("integrity_hash") if row else None) or "GENESIS"
        integrity_hash = _compute_audit_hash(
            prev_hash,
            now,
            event.get("action") or "",
            event.get("target_id") or "",
            event.get("actor_role") or "",
            event.get("reason") or "",
        )
        cursor = conn.execute(
            """
            INSERT INTO admin_audit_log
              (ts, actor_auth_type, actor_role, actor_label, actor_email, actor_subject,
               actor_token_prefix, action, target_type, target_id, result, reason, details,
               prev_hash, integrity_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                now,
                event.get("actor_auth_type") or "",
                event.get("actor_role") or "",
                event.get("actor_label") or "",
                event.get("actor_email") or "",
                event.get("actor_subject") or "",
                event.get("actor_token_prefix") or "",
                event.get("action") or "",
                event.get("target_type") or "",
                event.get("target_id") or "",
                event.get("result") or "success",
                event.get("reason") or "",
                details,
                prev_hash,
                integrity_hash,
            ),
        )
    stored = dict(event)
    stored.update(
        {"id": cursor.lastrowid, "ts": now, "details": event.get("details") or {}}
    )
    return stored


def list_admin_audit_logs(limit: int = 100) -> List[Dict[str, Any]]:
    limit = max(1, min(int(limit or 100), 500))
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM admin_audit_log ORDER BY ts DESC, id DESC LIMIT ?",
            (limit,),
        ).fetchall()
    out = []
    for row in rows:
        item = row_to_plain_dict(row)
        raw_details = item.get("details") or "{}"
        try:
            item["details"] = json.loads(raw_details)
        except (json.JSONDecodeError, TypeError):
            item["details"] = {}
        out.append(item)
    return out


def verify_audit_chain() -> Dict[str, Any]:
    result: Dict[str, Any] = {"valid": True}

    checks = [
        ("mcp_audit_log", "mcp", "action", "tool_name", "role"),
        ("admin_audit_log", "admin", "action", "target_id", "actor_role"),
    ]

    for table, key, action_col, target_col, role_col in checks:
        with get_conn() as conn:
            rows = conn.execute(
                f"SELECT id, ts, {action_col}, {target_col}, {role_col}, "
                f"reason, prev_hash, integrity_hash FROM {table} ORDER BY id ASC"
            ).fetchall()

        if not rows:
            result[key] = {"total": 0, "first_ts": None, "last_ts": None}
            continue

        dicts = [dict(r) for r in rows]
        first_ts = dicts[0]["ts"]
        last_ts = dicts[-1]["ts"]
        prev_hash = "GENESIS"

        for record in dicts:
            stored_hash = record.get("integrity_hash") or ""
            if not stored_hash:
                result["valid"] = False
                result["broken_at"] = {"table": table, "record_id": record["id"]}
                result["reason"] = "pre-integrity records found"
                return result
            expected = _compute_audit_hash(
                prev_hash,
                record.get("ts") or "",
                record.get(action_col) or "",
                record.get(target_col) or "",
                record.get(role_col) or "",
                record.get("reason") or "",
            )
            if expected != stored_hash:
                result["valid"] = False
                result["broken_at"] = {"table": table, "record_id": record["id"]}
                result["reason"] = "hash mismatch"
                return result
            prev_hash = stored_hash

        result[key] = {"total": len(dicts), "first_ts": first_ts, "last_ts": last_ts}

    return result


# ── Usage logging + monthly quota ────────────────────────────────────────────
def log_usage(key_id: int, endpoint: str, threat_blocked: bool = False) -> None:
    with _db_lock, get_conn() as conn:
        conn.execute(
            "INSERT INTO usage_log (key_id, ts, endpoint, threat_blocked) VALUES (?, ?, ?, ?)",
            (
                key_id,
                datetime.now(timezone.utc).isoformat(),
                endpoint,
                bool(threat_blocked),
            ),
        )


def usage_this_month(key_id: int) -> int:
    month_start = (
        datetime.now(timezone.utc)
        .replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        .isoformat()
    )
    with get_conn() as conn:
        row = conn.execute(
            "SELECT COUNT(*) AS n FROM usage_log WHERE key_id = ? AND ts >= ?",
            (key_id, month_start),
        ).fetchone()
    return row["n"] if row else 0


# ── Bootstrap / seed ─────────────────────────────────────────────────────────
def seed_legacy_keys() -> None:
    """
    Intentional no-op. Historically this seeded three hardcoded demo API keys
    (lf-free-demo-key-123, lf-dev-key-456, lf-startup-key-789) into api_keys on
    startup. Those keys are publicly known (published across the repo, docs, and
    demos) and have been revoked on live systems, so they are NO LONGER seeded —
    seeding them would auto-recreate known-compromised credentials on a fresh or
    wiped database.

    Kept as a documented no-op because the symbol is still called from the
    startup lifespan (proxy.py) and from tests; removing it would break those
    callers. Issue keys via generate_key() / POST /admin/keys instead.
    """
    return


# ── Retention policy ─────────────────────────────────────────────────────────
DEFAULT_RETENTION_POLICY = {
    "scan_history_days": 30,
    "mcp_audit_days": 90,
    "admin_audit_days": 365,
    "usage_log_days": 365,
}


def get_system_config(key: str, default: Any = None) -> Any:
    with get_conn() as conn:
        row = conn.execute(
            "SELECT value FROM system_config WHERE key = ?", (key,)
        ).fetchone()
    if not row:
        return default
    raw = row["value"]
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return raw


def set_system_config(key: str, value: Any) -> None:
    raw = (
        json.dumps(value, sort_keys=True)
        if isinstance(value, (dict, list))
        else str(value)
    )
    with _db_lock, get_conn() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO system_config (key, value) VALUES (?, ?)",
            (key, raw),
        )


def get_retention_policy() -> Dict[str, int]:
    stored = get_system_config("retention_policy", {}) or {}
    policy = dict(DEFAULT_RETENTION_POLICY)
    if isinstance(stored, dict):
        for key in policy:
            try:
                value = int(stored.get(key, policy[key]))
            except (TypeError, ValueError):
                value = policy[key]
            policy[key] = max(1, value)
    return policy


def set_retention_policy(policy: Dict[str, int]) -> Dict[str, int]:
    current = get_retention_policy()
    for key in DEFAULT_RETENTION_POLICY:
        if key in policy and policy[key] is not None:
            current[key] = max(1, int(policy[key]))
    set_system_config("retention_policy", current)
    return current


def _delete_older_than(conn, table: str, ts_column: str, days: int) -> int:
    cutoff = (
        datetime.now(timezone.utc) - timedelta(days=max(1, int(days)))
    ).isoformat()
    cursor = conn.execute(
        f"DELETE FROM {table} WHERE {ts_column} < ?",
        (cutoff,),
    )
    return int(cursor.rowcount or 0)


def prune_retention(policy: Optional[Dict[str, int]] = None) -> Dict[str, Any]:
    policy = policy or get_retention_policy()
    with _db_lock, get_conn() as conn:
        deleted_scan_history = _delete_older_than(
            conn, "scan_history", "ts", policy["scan_history_days"]
        )
        deleted_mcp_audit = _delete_older_than(
            conn, "mcp_audit_log", "ts", policy["mcp_audit_days"]
        )
        deleted_admin_audit = _delete_older_than(
            conn, "admin_audit_log", "ts", policy["admin_audit_days"]
        )
        deleted_usage = _delete_older_than(
            conn, "usage_log", "ts", policy["usage_log_days"]
        )
    return {
        "scan_history_deleted": deleted_scan_history,
        "mcp_audit_deleted": deleted_mcp_audit,
        "admin_audit_deleted": deleted_admin_audit,
        "usage_log_deleted": deleted_usage,
        "policy": policy,
    }


# ── Performance metrics ───────────────────────────────────────────────────────

MAX_LATENCY_SAMPLES = 10_000


def record_latency_sample(
    endpoint: str,
    latency_ms: float,
    is_threat: bool = False,
) -> None:
    ts = datetime.now(timezone.utc).isoformat()
    with _db_lock, get_conn() as conn:
        conn.execute(
            "INSERT INTO latency_samples (ts, endpoint, latency_ms, is_threat) VALUES (?, ?, ?, ?)",
            (ts, endpoint, float(latency_ms), int(is_threat)),
        )
        conn.execute(
            """
            DELETE FROM latency_samples
             WHERE id NOT IN (
               SELECT id FROM latency_samples ORDER BY id DESC LIMIT ?
             )
            """,
            (MAX_LATENCY_SAMPLES,),
        )


def get_performance_metrics() -> Dict[str, Any]:
    cutoff_24h = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()

    with get_conn() as conn:
        sample_rows = conn.execute(
            "SELECT latency_ms FROM latency_samples WHERE ts >= ? ORDER BY latency_ms ASC",
            (cutoff_24h,),
        ).fetchall()

        scan_row = conn.execute(
            "SELECT COUNT(*) AS total, "
            "SUM(CASE WHEN is_threat = 1 THEN 1 ELSE 0 END) AS blocked "
            "FROM scan_history WHERE ts >= ?",
            (cutoff_24h,),
        ).fetchone()

        drift_row = conn.execute(
            "SELECT COUNT(*) AS cnt FROM mcp_audit_log "
            "WHERE drift_severity != 'none' AND ts >= ?",
            (cutoff_24h,),
        ).fetchone()

        q_row = conn.execute(
            "SELECT COUNT(*) AS cnt FROM mcp_audit_log WHERE action = 'quarantine'"
        ).fetchone()

        a_row = conn.execute(
            "SELECT COUNT(*) AS cnt FROM mcp_audit_log WHERE action = 'approve'"
        ).fetchone()

    latencies = [float(row_value(r, "latency_ms", 0)) for r in sample_rows]

    def _pct(data: list, p: int) -> float:
        if not data:
            return 0.0
        idx = max(0, min(int(len(data) * p / 100), len(data) - 1))
        return round(data[idx], 2)

    avg = round(sum(latencies) / len(latencies), 2) if latencies else 0.0
    total_val = row_value(scan_row, "total", 0) if scan_row else None
    blocked_val = row_value(scan_row, "blocked", 1) if scan_row else None
    total = int(total_val or 0)
    blocked = int(blocked_val or 0)
    drift_cnt = int(row_value(drift_row, "cnt", 0) or 0)
    q_total = int(row_value(q_row, "cnt", 0) or 0)
    approved = int(row_value(a_row, "cnt", 0) or 0)
    approval_rate = round(approved / q_total, 3) if q_total > 0 else 0.0

    return {
        "avg_scan_latency_ms": avg,
        "p95_scan_latency_ms": _pct(latencies, 95),
        "p99_scan_latency_ms": _pct(latencies, 99),
        "total_scans_24h": total,
        "blocked_24h": blocked,
        "mcp_tool_approval_rate": approval_rate,
        "drift_detections_24h": drift_cnt,
        "uptime_seconds": 0,  # filled in by the route layer
    }


# ── MCP server registry ───────────────────────────────────────────────────────


def _mcp_row_to_dict(row) -> Dict[str, Any]:
    d = dict(row)
    for col in ("allowed_tools", "blocked_tools"):
        raw = d.get(col)
        if isinstance(raw, list):
            d[col] = raw
            continue
        if isinstance(raw, tuple):
            d[col] = list(raw)
            continue
        if raw is None or raw == "":
            d[col] = []
            continue
        try:
            d[col] = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            d[col] = []
    d["verified"] = bool(d.get("verified", 0))
    return d


def _mcp_tool_metadata_row_to_dict(row) -> Dict[str, Any]:
    d = dict(row)
    for col in (
        "normalized_metadata",
        "raw_annotations",
        "raw_tool_definition",
        "previous_metadata",
        "previous_tool_definition",
    ):
        raw = d.get(col)
        if isinstance(raw, (dict, list)):
            continue
        if raw is None or raw == "":
            d[col] = {} if col != "normalized_metadata" else {}
            continue
        try:
            d[col] = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            d[col] = {}
    for col in ("drift_types", "drift_reasons"):
        raw = d.get(col)
        if isinstance(raw, list):
            continue
        if raw is None or raw == "":
            d[col] = []
            continue
        try:
            d[col] = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            d[col] = []
    return d


def _mcp_audit_row_to_dict(row) -> Dict[str, Any]:
    d = dict(row)
    for col in (
        "effects",
        "data_classes",
        "warnings",
        "argument_keys",
        "drift_types",
        "drift_reasons",
    ):
        raw = d.get(col)
        if isinstance(raw, list):
            continue
        if raw is None or raw == "":
            d[col] = []
            continue
        try:
            d[col] = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            d[col] = []
    return d


def _mcp_permission_probe_row_to_dict(row) -> Dict[str, Any]:
    d = dict(row)
    d["non_production"] = bool(d.get("non_production"))
    raw = d.get("last_finding_types")
    if isinstance(raw, list):
        return d
    if raw in (None, ""):
        d["last_finding_types"] = []
        return d
    try:
        d["last_finding_types"] = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        d["last_finding_types"] = []
    return d


def register_mcp_server(server_id: str, config: dict) -> bool:
    """Insert a new MCP server. Returns False if server_id already exists."""
    try:
        with _db_lock, get_conn() as conn:
            conn.execute(
                """
                INSERT INTO mcp_servers
                  (server_id, url, description, allowed_tools, blocked_tools,
                   rate_limit, auth_type, auth_header, auth_token_env, verified,
                   registered_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    server_id,
                    config["url"],
                    config.get("description", ""),
                    json.dumps(config.get("allowed_tools", [])),
                    json.dumps(config.get("blocked_tools", [])),
                    config.get("rate_limit", 60),
                    config.get("auth_type", "none"),
                    config.get("auth_header", ""),
                    config.get("auth_token_env", ""),
                    False,
                    datetime.now(timezone.utc).isoformat(),
                ),
            )
        logger.info("Registered MCP server: %s", server_id)
        return True
    except Exception as e:
        if _is_integrity_error(e):
            return False
        raise


def lookup_mcp_server(server_id: str) -> Optional[Dict[str, Any]]:
    """Return a server record by server_id, or None if not found."""
    with get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM mcp_servers WHERE server_id = ?",
            (server_id,),
        ).fetchone()
    return _mcp_row_to_dict(row) if row else None


def lookup_mcp_server_by_url(url: str) -> Optional[Dict[str, Any]]:
    """Return a server record by URL, or None if not found."""
    with get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM mcp_servers WHERE url = ?",
            (url,),
        ).fetchone()
    return _mcp_row_to_dict(row) if row else None


def list_mcp_servers(limit: Optional[int] = None) -> List[Dict[str, Any]]:
    """Return registered MCP servers ordered by registration time."""
    with get_conn() as conn:
        if limit is not None:
            rows = conn.execute(
                "SELECT * FROM mcp_servers ORDER BY registered_at ASC LIMIT ?",
                (limit,),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM mcp_servers ORDER BY registered_at ASC"
            ).fetchall()
    return [_mcp_row_to_dict(r) for r in rows]


def load_mcp04_policy() -> dict:
    """Return the current MCP04 provenance policy from system_config, or {} if unset."""
    try:
        with get_conn() as conn:
            row = conn.execute(
                "SELECT value FROM system_config WHERE key='mcp04_policy'"
            ).fetchone()
            if row:
                return json.loads(row_value(row, "value", 0))
    except Exception:
        logger.exception("Failed to load mcp04 policy")
    return {}


def update_mcp_server_provenance(server_id: str, provenance_status: str) -> bool:
    """Set provenance_status on an existing mcp_servers row."""
    with _db_lock, get_conn() as conn:
        cursor = conn.execute(
            "UPDATE mcp_servers SET provenance_status=? WHERE server_id=?",
            (provenance_status, server_id),
        )
    return cursor.rowcount > 0


def unregister_mcp_server(server_id: str) -> bool:
    """Delete a server from the registry. Returns False if not found."""
    with _db_lock, get_conn() as conn:
        cursor = conn.execute(
            "DELETE FROM mcp_servers WHERE server_id = ?",
            (server_id,),
        )
    return cursor.rowcount > 0


def verify_mcp_server(server_id: str) -> bool:
    """Mark a server as verified. Returns False if server_id not found."""
    with _db_lock, get_conn() as conn:
        cursor = conn.execute(
            "UPDATE mcp_servers SET verified = TRUE WHERE server_id = ?",
            (server_id,),
        )
    return cursor.rowcount > 0


def seed_mcp_servers() -> None:
    """Idempotent seed of the two pre-configured MCP servers. Safe to call on every startup."""
    seeds = [
        {
            "server_id": "trusted-filesystem",
            "url": "https://mcp.acme-corp.internal/filesystem",
            "description": "Sandboxed file system access",
            "allowed_tools": ["read_file", "list_directory"],
            "blocked_tools": ["write_file", "delete_file", "execute"],
            "rate_limit": 60,
            "verified": True,
        },
        {
            "server_id": "trusted-search",
            "url": "https://mcp.acme-corp.internal/search",
            "description": "Web search MCP",
            "allowed_tools": ["search", "fetch"],
            "blocked_tools": [],
            "rate_limit": 30,
            "verified": True,
        },
    ]
    for s in seeds:
        with _db_lock, get_conn() as conn:
            conn.execute(
                """
                INSERT OR IGNORE INTO mcp_servers
                  (server_id, url, description, allowed_tools, blocked_tools,
                   rate_limit, verified, registered_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    s["server_id"],
                    s["url"],
                    s["description"],
                    json.dumps(s["allowed_tools"]),
                    json.dumps(s["blocked_tools"]),
                    s["rate_limit"],
                    s["verified"],
                    datetime.now(timezone.utc).isoformat(),
                ),
            )
            # Always patch tool lists in case rows pre-existed with stale/empty data.
            conn.execute(
                """
                UPDATE mcp_servers
                   SET allowed_tools = ?, blocked_tools = ?, verified = ?
                 WHERE server_id = ?
                """,
                (
                    json.dumps(s["allowed_tools"]),
                    json.dumps(s["blocked_tools"]),
                    s["verified"],
                    s["server_id"],
                ),
            )
        logger.info("Seeded MCP server: %s", s["server_id"])


# ── MCP tool metadata registry ────────────────────────────────────────────────


def upsert_mcp_tool_metadata(
    server_id: str, tool: dict, normalized_metadata: dict
) -> Dict[str, Any]:
    """Insert or update normalized metadata for one discovered MCP tool."""
    tool = tool or {}
    tool_name = tool.get("name")
    if not server_id:
        raise ValueError("server_id is required")
    if not tool_name:
        raise ValueError("tool name is required")

    schema = tool.get("inputSchema", {}) or tool.get("input_schema", {}) or {}
    current_output_schema = (
        tool.get("outputSchema", {}) or tool.get("output_schema", {}) or {}
    )
    if not isinstance(current_output_schema, dict):
        current_output_schema = {}
    tool_schema_hash = _hash_json(schema)
    description_hash = _hash_text(tool.get("description", ""))
    raw_annotations = tool.get("annotations") or {}
    now = datetime.now(timezone.utc).isoformat()

    with _db_lock, get_conn() as conn:
        existing = conn.execute(
            """
            SELECT * FROM mcp_tool_metadata
             WHERE server_id = ? AND tool_name = ?
            """,
            (server_id, tool_name),
        ).fetchone()

        changed = False
        previous_schema_hash = None
        previous_description_hash = None
        previous_metadata: dict = {}
        previous_tool_definition: dict = {}
        first_seen = now
        last_changed = None
        status = "active"
        drift = {
            "severity": "none",
            "action": "allow",
            "types": [],
            "reasons": [],
            "findings": [],
        }

        if existing:
            existing_d = _mcp_tool_metadata_row_to_dict(existing)
            previous_schema_hash = existing_d["tool_schema_hash"]
            previous_description_hash = existing_d["description_hash"]
            previous_metadata = existing_d.get("normalized_metadata") or {}
            previous_tool_definition = existing_d.get("raw_tool_definition") or {}
            previous_output_schema = (
                previous_tool_definition.get("outputSchema", {})
                or previous_tool_definition.get("output_schema", {})
                or {}
            )
            if not isinstance(previous_output_schema, dict):
                previous_output_schema = {}
            first_seen = existing_d["first_seen"]
            last_changed = existing_d.get("last_changed")
            changed = (
                previous_schema_hash != tool_schema_hash
                or previous_description_hash != description_hash
                or previous_metadata != (normalized_metadata or {})
                or previous_output_schema != current_output_schema
            )
            if changed:
                drift = classify_tool_drift(
                    previous_tool_definition,
                    tool,
                    previous_metadata,
                    normalized_metadata or {},
                )
                status = "quarantined" if drift["action"] == "quarantine" else "changed"
                last_changed = now
            else:
                status = existing_d.get("status") or "active"
                drift = {
                    "severity": existing_d.get("drift_severity") or "none",
                    "action": existing_d.get("drift_action") or "allow",
                    "types": existing_d.get("drift_types") or [],
                    "reasons": existing_d.get("drift_reasons") or [],
                    "findings": [],
                }

            conn.execute(
                """
                UPDATE mcp_tool_metadata
                   SET tool_schema_hash = ?,
                       description_hash = ?,
                       normalized_metadata = ?,
                       raw_annotations = ?,
                       raw_tool_definition = ?,
                       last_seen = ?,
                       last_changed = ?,
                       status = ?,
                       drift_severity = ?,
                       drift_action = ?,
                       drift_types = ?,
                       drift_reasons = ?,
                       previous_metadata = ?,
                       previous_tool_definition = ?
                 WHERE server_id = ? AND tool_name = ?
                """,
                (
                    tool_schema_hash,
                    description_hash,
                    json.dumps(normalized_metadata or {}),
                    json.dumps(raw_annotations or {}),
                    json.dumps(tool or {}),
                    now,
                    last_changed,
                    status,
                    drift["severity"],
                    drift["action"],
                    json.dumps(drift["types"]),
                    json.dumps(drift["reasons"]),
                    json.dumps(previous_metadata or {}),
                    json.dumps(previous_tool_definition or {}),
                    server_id,
                    tool_name,
                ),
            )
        else:
            conn.execute(
                """
                INSERT INTO mcp_tool_metadata
                  (server_id, tool_name, tool_schema_hash, description_hash,
                   normalized_metadata, raw_annotations, raw_tool_definition,
                   first_seen, last_seen, last_changed, status, drift_severity,
                   drift_action, drift_types, drift_reasons, previous_metadata,
                   previous_tool_definition)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    server_id,
                    tool_name,
                    tool_schema_hash,
                    description_hash,
                    json.dumps(normalized_metadata or {}),
                    json.dumps(raw_annotations or {}),
                    json.dumps(tool or {}),
                    first_seen,
                    now,
                    None,
                    status,
                    drift["severity"],
                    drift["action"],
                    json.dumps(drift["types"]),
                    json.dumps(drift["reasons"]),
                    json.dumps({}),
                    json.dumps({}),
                ),
            )

    return {
        "server_id": server_id,
        "tool_name": tool_name,
        "tool_schema_hash": tool_schema_hash,
        "description_hash": description_hash,
        "previous_schema_hash": previous_schema_hash,
        "previous_description_hash": previous_description_hash,
        "changed": changed,
        "status": status,
        "drift_severity": drift["severity"],
        "drift_action": drift["action"],
        "drift_types": drift["types"],
        "drift_reasons": drift["reasons"],
        "drift_findings": drift.get("findings", []),
        "previous_metadata": previous_metadata,
        "previous_tool_definition": previous_tool_definition,
        "first_seen": first_seen,
        "last_seen": now,
        "last_changed": last_changed,
    }


def lookup_mcp_tool_metadata(
    server_id: str, tool_name: str
) -> Optional[Dict[str, Any]]:
    """Return stored metadata for a server/tool pair."""
    with get_conn() as conn:
        row = conn.execute(
            """
            SELECT * FROM mcp_tool_metadata
             WHERE server_id = ? AND tool_name = ?
            """,
            (server_id, tool_name),
        ).fetchone()
    return _mcp_tool_metadata_row_to_dict(row) if row else None


def list_mcp_tool_metadata(
    server_id: Optional[str] = None, limit: Optional[int] = None
) -> List[Dict[str, Any]]:
    """List stored MCP tool metadata, optionally filtered by server."""
    with get_conn() as conn:
        if server_id and limit is not None:
            rows = conn.execute(
                """
                SELECT * FROM mcp_tool_metadata
                 WHERE server_id = ?
                 ORDER BY tool_name ASC
                 LIMIT ?
                """,
                (server_id, limit),
            ).fetchall()
        elif server_id:
            rows = conn.execute(
                """
                SELECT * FROM mcp_tool_metadata
                 WHERE server_id = ?
                 ORDER BY tool_name ASC
                """,
                (server_id,),
            ).fetchall()
        elif limit is not None:
            rows = conn.execute(
                """
                SELECT * FROM mcp_tool_metadata
                 ORDER BY server_id ASC, tool_name ASC
                 LIMIT ?
                """,
                (limit,),
            ).fetchall()
        else:
            rows = conn.execute("""
                SELECT * FROM mcp_tool_metadata
                 ORDER BY server_id ASC, tool_name ASC
                """).fetchall()
    return [_mcp_tool_metadata_row_to_dict(r) for r in rows]


def get_known_tool_names(server_id: str) -> set:
    """Return the set of tool names currently tracked for a server."""
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT tool_name FROM mcp_tool_metadata WHERE server_id = ?",
            (server_id,),
        ).fetchall()
    return {row_value(r, "tool_name", 0) for r in rows if row_value(r, "tool_name", 0)}


def mark_mcp_tool_removed(
    server_id: str, tool_name: str, reason: str = ""
) -> Dict[str, Any]:
    """Mark a missing rediscovered tool as quarantined pending operator review."""
    reason = reason or (
        f"Tool '{tool_name}' disappeared from server '{server_id}' during discovery."
    )
    now = datetime.now(timezone.utc).isoformat()

    with _db_lock, get_conn() as conn:
        row = conn.execute(
            """
            SELECT * FROM mcp_tool_metadata
             WHERE server_id = ? AND tool_name = ?
            """,
            (server_id, tool_name),
        ).fetchone()
        if not row:
            return {"ok": False, "error": "not_found"}

        current = _mcp_tool_metadata_row_to_dict(row)
        drift_types = _unique_list(
            [*(current.get("drift_types") or []), "tool_removed"]
        )
        drift_reasons = _unique_list([*(current.get("drift_reasons") or []), reason])
        conn.execute(
            """
            UPDATE mcp_tool_metadata
               SET status = 'quarantined',
                   drift_severity = 'critical',
                   drift_action = 'quarantine',
                   drift_types = ?,
                   drift_reasons = ?,
                   last_changed = COALESCE(last_changed, ?)
             WHERE server_id = ? AND tool_name = ?
            """,
            (
                json.dumps(drift_types),
                json.dumps(drift_reasons),
                now,
                server_id,
                tool_name,
            ),
        )

    updated = lookup_mcp_tool_metadata(server_id, tool_name) or {}
    return {"ok": True, **updated}


def mark_mcp_tool_added_drift(
    server_id: str, tool_name: str, reason: str = ""
) -> Dict[str, Any]:
    """Quarantine a newly-discovered tool that introduced destructive or
    exfiltration capability against an existing baseline, pending operator review.

    A brand-new tool is otherwise upserted status='active'; this flips it to
    'quarantined' so the rug-pull capability cannot be used before review.
    """
    reason = reason or (
        f"New high-risk tool '{tool_name}' appeared on server '{server_id}'."
    )
    now = datetime.now(timezone.utc).isoformat()

    with _db_lock, get_conn() as conn:
        row = conn.execute(
            """
            SELECT * FROM mcp_tool_metadata
             WHERE server_id = ? AND tool_name = ?
            """,
            (server_id, tool_name),
        ).fetchone()
        if not row:
            return {"ok": False, "error": "not_found"}

        current = _mcp_tool_metadata_row_to_dict(row)
        drift_types = _unique_list([*(current.get("drift_types") or []), "tool_added"])
        drift_reasons = _unique_list([*(current.get("drift_reasons") or []), reason])
        conn.execute(
            """
            UPDATE mcp_tool_metadata
               SET status = 'quarantined',
                   drift_severity = 'critical',
                   drift_action = 'quarantine',
                   drift_types = ?,
                   drift_reasons = ?,
                   last_changed = COALESCE(last_changed, ?)
             WHERE server_id = ? AND tool_name = ?
            """,
            (
                json.dumps(drift_types),
                json.dumps(drift_reasons),
                now,
                server_id,
                tool_name,
            ),
        )

    updated = lookup_mcp_tool_metadata(server_id, tool_name) or {}
    return {"ok": True, **updated}


def mark_mcp_tool_effective_permission_drift(
    server_id: str, tool_name: str, reason: str = ""
) -> Dict[str, Any]:
    """Quarantine a known tool after a behavioral effective-permission drift."""
    reason = reason or (
        "Effective-permission probe observed broader access than expected."
    )
    now = datetime.now(timezone.utc).isoformat()

    with _db_lock, get_conn() as conn:
        row = conn.execute(
            """
            SELECT * FROM mcp_tool_metadata
             WHERE server_id = ? AND tool_name = ?
            """,
            (server_id, tool_name),
        ).fetchone()
        if not row:
            return {"ok": False, "error": "not_found"}

        current = _mcp_tool_metadata_row_to_dict(row)
        drift_types = _unique_list(
            [
                *(current.get("drift_types") or []),
                "effective_permission_expansion",
                "behavioral_scope_drift",
            ]
        )
        drift_reasons = _unique_list([*(current.get("drift_reasons") or []), reason])
        conn.execute(
            """
            UPDATE mcp_tool_metadata
               SET status = 'quarantined',
                   drift_severity = 'high',
                   drift_action = 'quarantine',
                   drift_types = ?,
                   drift_reasons = ?,
                   last_changed = COALESCE(last_changed, ?)
             WHERE server_id = ? AND tool_name = ?
            """,
            (
                json.dumps(drift_types),
                json.dumps(drift_reasons),
                now,
                server_id,
                tool_name,
            ),
        )

    updated = lookup_mcp_tool_metadata(server_id, tool_name) or {}
    return {"ok": True, **updated}


def list_drifted_mcp_tools(
    server_id: Optional[str] = None, limit: Optional[int] = None
) -> List[Dict[str, Any]]:
    """List MCP tools that need operator review because they changed or are quarantined."""
    with get_conn() as conn:
        if server_id and limit is not None:
            rows = conn.execute(
                """
                SELECT * FROM mcp_tool_metadata
                 WHERE server_id = ?
                   AND (status != 'active' OR drift_severity != 'none' OR drift_action != 'allow')
                 ORDER BY last_changed DESC, tool_name ASC
                 LIMIT ?
                """,
                (server_id, limit),
            ).fetchall()
        elif server_id:
            rows = conn.execute(
                """
                SELECT * FROM mcp_tool_metadata
                 WHERE server_id = ?
                   AND (status != 'active' OR drift_severity != 'none' OR drift_action != 'allow')
                 ORDER BY last_changed DESC, tool_name ASC
                """,
                (server_id,),
            ).fetchall()
        elif limit is not None:
            rows = conn.execute(
                """
                SELECT * FROM mcp_tool_metadata
                 WHERE status != 'active' OR drift_severity != 'none' OR drift_action != 'allow'
                 ORDER BY last_changed DESC, server_id ASC, tool_name ASC
                 LIMIT ?
                """,
                (limit,),
            ).fetchall()
        else:
            rows = conn.execute("""
                SELECT * FROM mcp_tool_metadata
                 WHERE status != 'active' OR drift_severity != 'none' OR drift_action != 'allow'
                 ORDER BY last_changed DESC, server_id ASC, tool_name ASC
                """).fetchall()
    return [_mcp_tool_metadata_row_to_dict(r) for r in rows]


def approve_mcp_tool_baseline(
    server_id: str,
    tool_name: str,
    reviewer: str = "operator",
    reason: str = "",
) -> Dict[str, Any]:
    """Approve the current stored MCP tool definition as the new trusted baseline."""
    reviewer = reviewer or "operator"
    reason = reason or "Approved current MCP tool definition as the new baseline."
    t0 = time.perf_counter()

    with _db_lock, get_conn() as conn:
        row = conn.execute(
            """
            SELECT * FROM mcp_tool_metadata
             WHERE server_id = ? AND tool_name = ?
            """,
            (server_id, tool_name),
        ).fetchone()
        if not row:
            return {"ok": False, "error": "not_found"}

        current = _mcp_tool_metadata_row_to_dict(row)
        conn.execute(
            """
            UPDATE mcp_tool_metadata
               SET status = 'active',
                   drift_severity = 'none',
                   drift_action = 'allow',
                   drift_types = '[]',
                   drift_reasons = '[]',
                   previous_metadata = '{}',
                   previous_tool_definition = '{}',
                   last_changed = NULL
             WHERE server_id = ? AND tool_name = ?
            """,
            (server_id, tool_name),
        )

    metadata = current.get("normalized_metadata") or {}
    log_mcp_audit_event(
        {
            "server_id": server_id,
            "tool_name": tool_name,
            "role": reviewer,
            "action": "approve",
            "matched_rule": "tool_baseline_approved",
            "reason": reason,
            "effects": metadata.get("effects") or [],
            "side_effect": metadata.get("side_effect") or "unknown",
            "data_classes": metadata.get("data_classes") or [],
            "externality": metadata.get("externality") or "unknown",
            "verification_level": metadata.get("verification_level") or "unknown",
            "confidence": metadata.get("confidence") or 0.0,
            "warnings": metadata.get("warnings") or [],
            "argument_keys": [],
            "blocked_by": "operator_review",
            "drift_status": "active",
            "drift_severity": "none",
            "drift_action": "allow",
            "drift_types": [],
            "drift_reasons": [],
            "scan_time_ms": round((time.perf_counter() - t0) * 1000, 2),
        }
    )

    updated = lookup_mcp_tool_metadata(server_id, tool_name) or {}
    return {"ok": True, **updated}


def quarantine_mcp_tool(
    server_id: str,
    tool_name: str,
    reviewer: str = "operator",
    reason: str = "",
) -> Dict[str, Any]:
    """Keep or mark an MCP tool quarantined until an operator approves a new baseline."""
    reviewer = reviewer or "operator"
    reason = reason or "Operator kept this MCP tool quarantined pending review."
    t0 = time.perf_counter()

    with _db_lock, get_conn() as conn:
        row = conn.execute(
            """
            SELECT * FROM mcp_tool_metadata
             WHERE server_id = ? AND tool_name = ?
            """,
            (server_id, tool_name),
        ).fetchone()
        if not row:
            return {"ok": False, "error": "not_found"}

        current = _mcp_tool_metadata_row_to_dict(row)
        drift_types = _unique_list(
            [*(current.get("drift_types") or []), "operator_quarantine"]
        )
        # Keep the detected drift signals as the drift bullets. The operator's
        # free-text reason is recorded as the audit `reason` (the receipt's WHY),
        # so appending it here would duplicate it verbatim in the receipt.
        drift_reasons = list(current.get("drift_reasons") or [])
        conn.execute(
            """
            UPDATE mcp_tool_metadata
               SET status = 'quarantined',
                   drift_severity = 'critical',
                   drift_action = 'quarantine',
                   drift_types = ?,
                   drift_reasons = ?,
                   last_changed = COALESCE(last_changed, ?)
             WHERE server_id = ? AND tool_name = ?
            """,
            (
                json.dumps(drift_types),
                json.dumps(drift_reasons),
                datetime.now(timezone.utc).isoformat(),
                server_id,
                tool_name,
            ),
        )

    metadata = current.get("normalized_metadata") or {}
    log_mcp_audit_event(
        {
            "server_id": server_id,
            "tool_name": tool_name,
            "role": reviewer,
            "action": "quarantine",
            "matched_rule": "operator_quarantine",
            "reason": reason,
            "effects": metadata.get("effects") or [],
            "side_effect": metadata.get("side_effect") or "unknown",
            "data_classes": metadata.get("data_classes") or [],
            "externality": metadata.get("externality") or "unknown",
            "verification_level": metadata.get("verification_level") or "unknown",
            "confidence": metadata.get("confidence") or 0.0,
            "warnings": metadata.get("warnings") or [],
            "argument_keys": [],
            "blocked_by": "operator_review",
            "drift_status": "quarantined",
            "drift_severity": "critical",
            "drift_action": "quarantine",
            "drift_types": drift_types,
            "drift_reasons": drift_reasons,
            "scan_time_ms": round((time.perf_counter() - t0) * 1000, 2),
        }
    )

    updated = lookup_mcp_tool_metadata(server_id, tool_name) or {}
    return {"ok": True, **updated}


def merge_stored_and_runtime_metadata(
    stored_metadata: dict, runtime_metadata: dict
) -> dict:
    """Prefer discovered metadata, but merge runtime warnings and sensitive classes."""
    if not stored_metadata:
        merged = copy.deepcopy(runtime_metadata or {})
        warnings = list(merged.get("warnings") or [])
        warnings.append(
            "No stored tool metadata was available; runtime inference was used."
        )
        merged["warnings"] = list(dict.fromkeys(warnings))
        return merged

    merged = copy.deepcopy(stored_metadata)
    runtime_metadata = runtime_metadata or {}
    for key in ("effects", "data_classes", "required_scopes"):
        values = list(merged.get(key) or [])
        for value in runtime_metadata.get(key) or []:
            if value not in values:
                values.append(value)
        merged[key] = values

    warnings = list(merged.get("warnings") or [])
    for warning in runtime_metadata.get("warnings") or []:
        if warning not in warnings:
            warnings.append(warning)
    if runtime_metadata.get("verification_level") == "heuristic":
        warnings.append("Runtime arguments added heuristic metadata signals.")
    merged["warnings"] = list(dict.fromkeys(warnings))
    return merged


# ── Tool surface snapshots (drift evidence) ──────────────────────────────────


# -- Effective-permission probe metadata --------------------------------------


def upsert_mcp_permission_probe(probe: Dict[str, Any]) -> Dict[str, Any]:
    """Persist a manual probe definition without raw arguments or secrets."""
    probe_id = str(probe.get("probe_id") or "").strip()
    if not probe_id:
        probe_id = "probe_" + secrets.token_urlsafe(16)
    server_id = str(probe.get("server_id") or "").strip()
    tool_name = str(probe.get("tool_name") or "").strip()
    if not server_id:
        raise ValueError("server_id is required")
    if not tool_name:
        raise ValueError("tool_name is required")

    now = datetime.now(timezone.utc).isoformat()
    with _db_lock, get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM mcp_permission_probes WHERE probe_id = ?",
            (probe_id,),
        ).fetchone()
        existing = _mcp_permission_probe_row_to_dict(row) if row else {}
        values = (
            server_id,
            tool_name,
            probe.get("argument_hash") or "",
            probe.get("expected_outcome") or "",
            probe.get("expected_status_code"),
            probe.get("expected_error_fingerprint") or "",
            1 if probe.get("non_production") else 0,
            probe.get("safety_note") or "",
            now,
            probe_id,
        )
        if existing:
            conn.execute(
                """
                UPDATE mcp_permission_probes
                   SET server_id = ?,
                       tool_name = ?,
                       argument_hash = ?,
                       expected_outcome = ?,
                       expected_status_code = ?,
                       expected_error_fingerprint = ?,
                       non_production = ?,
                       safety_note = ?,
                       updated_at = ?
                 WHERE probe_id = ?
                """,
                values,
            )
        else:
            conn.execute(
                """
                INSERT INTO mcp_permission_probes
                  (server_id, tool_name, argument_hash, expected_outcome,
                   expected_status_code, expected_error_fingerprint,
                   non_production, safety_note, updated_at, probe_id, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (*values, now),
            )

    saved = lookup_mcp_permission_probe(probe_id)
    if saved:
        return saved
    return {
        "probe_id": probe_id,
        "server_id": server_id,
        "tool_name": tool_name,
        "argument_hash": probe.get("argument_hash") or "",
        "expected_outcome": probe.get("expected_outcome") or "",
        "expected_status_code": probe.get("expected_status_code"),
        "expected_error_fingerprint": probe.get("expected_error_fingerprint") or "",
        "non_production": bool(probe.get("non_production")),
        "safety_note": probe.get("safety_note") or "",
        "created_at": existing.get("created_at") or now,
        "updated_at": now,
    }


def lookup_mcp_permission_probe(probe_id: str) -> Optional[Dict[str, Any]]:
    """Return a stored probe definition by id, without raw arguments."""
    with get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM mcp_permission_probes WHERE probe_id = ?",
            (probe_id,),
        ).fetchone()
    return _mcp_permission_probe_row_to_dict(row) if row else None


def update_mcp_permission_probe_result(
    probe_id: str, evaluation: Dict[str, Any], audit_id: int
) -> bool:
    """Attach the latest sanitized probe outcome to the stored probe."""
    now = datetime.now(timezone.utc).isoformat()
    with _db_lock, get_conn() as conn:
        cursor = conn.execute(
            """
            UPDATE mcp_permission_probes
               SET last_run_at = ?,
                   last_observed_outcome = ?,
                   last_observed_status_code = ?,
                   last_observed_error_class = ?,
                   last_decision = ?,
                   last_finding_types = ?,
                   last_audit_id = ?,
                   updated_at = ?
             WHERE probe_id = ?
            """,
            (
                now,
                evaluation.get("observed_outcome") or "",
                evaluation.get("observed_status_code"),
                evaluation.get("observed_error_class") or "",
                evaluation.get("decision") or "",
                json.dumps(evaluation.get("finding_types") or []),
                audit_id,
                now,
                probe_id,
            ),
        )
    return cursor.rowcount > 0


def save_tool_surface_snapshot(surface_hash: str, canonical_json: str) -> bool:
    """
    Retain the canonical tool-surface bytes behind a drift-evidence hash.

    Content-addressed and append-only: keyed by the surface hash itself, so
    later baseline approvals (which wipe previous_tool_definition on the
    metadata row) never destroy the bytes an emitted drift record committed
    to. Returns True if a new row was written.
    """
    if not surface_hash or not canonical_json:
        return False
    try:
        with _db_lock, get_conn() as conn:
            existing = conn.execute(
                "SELECT 1 FROM tool_surface_snapshots WHERE surface_hash = ?",
                (surface_hash,),
            ).fetchone()
            if existing:
                return False
            conn.execute(
                """
                INSERT INTO tool_surface_snapshots
                  (surface_hash, canonical_json, created_at)
                VALUES (?, ?, ?)
                """,
                (
                    surface_hash,
                    canonical_json,
                    datetime.now(timezone.utc).isoformat(),
                ),
            )
        return True
    except Exception as e:
        if _is_integrity_error(e):
            return False
        raise


def get_tool_surface_snapshot(surface_hash: str) -> Optional[Dict[str, Any]]:
    """Return a retained tool-surface snapshot by its content address."""
    with get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM tool_surface_snapshots WHERE surface_hash = ?",
            (surface_hash,),
        ).fetchone()
    return dict(row) if row else None


# ── MCP audit log ─────────────────────────────────────────────────────────────


def log_mcp_audit_event(event: dict) -> Dict[str, Any]:
    """Persist a durable MCP policy/audit event."""
    event = event or {}
    ts = event.get("ts") or datetime.now(timezone.utc).isoformat()
    with _db_lock, get_conn() as conn:
        row = conn.execute(
            "SELECT integrity_hash FROM mcp_audit_log ORDER BY id DESC LIMIT 1"
        ).fetchone()
        prev_hash = (dict(row).get("integrity_hash") if row else None) or "GENESIS"
        integrity_hash = _compute_audit_hash(
            prev_hash,
            ts,
            event.get("action", ""),
            event.get("tool_name", ""),
            event.get("role", "") or "",
            event.get("reason", ""),
        )
        cursor = conn.execute(
            """
            INSERT INTO mcp_audit_log
              (ts, server_id, tool_name, role, action, matched_rule, reason,
               effects, side_effect, data_classes, externality, verification_level,
               confidence, warnings, argument_keys, blocked_by, probe_id,
               argument_hash, expected_outcome, expected_status_code,
               observed_outcome, observed_status_code, observed_error_class,
               drift_status, drift_severity, drift_action, drift_types, drift_reasons,
               drift_baseline_hash, drift_current_hash,
               scan_time_ms, prev_hash, integrity_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                ts,
                event.get("server_id", ""),
                event.get("tool_name", ""),
                event.get("role", "") or "",
                event.get("action", ""),
                event.get("matched_rule", ""),
                event.get("reason", ""),
                json.dumps(event.get("effects", []) or []),
                event.get("side_effect", "unknown"),
                json.dumps(event.get("data_classes", []) or []),
                event.get("externality", "unknown"),
                event.get("verification_level", "unknown"),
                float(event.get("confidence") or 0.0),
                json.dumps(event.get("warnings", []) or []),
                json.dumps(event.get("argument_keys", []) or []),
                event.get("blocked_by", "") or "",
                event.get("probe_id", "") or "",
                event.get("argument_hash", "") or "",
                event.get("expected_outcome", "") or "",
                event.get("expected_status_code"),
                event.get("observed_outcome", "") or "",
                event.get("observed_status_code"),
                event.get("observed_error_class", "") or "",
                event.get("drift_status", "") or "",
                event.get("drift_severity", "none") or "none",
                event.get("drift_action", "allow") or "allow",
                json.dumps(event.get("drift_types", []) or []),
                json.dumps(event.get("drift_reasons", []) or []),
                event.get("drift_baseline_hash", "") or "",
                event.get("drift_current_hash", "") or "",
                event.get("scan_time_ms"),
                prev_hash,
                integrity_hash,
            ),
        )
        event_id = cursor.lastrowid

    saved = dict(event)
    saved["id"] = event_id
    saved["ts"] = ts
    return saved


def list_mcp_audit_logs(limit: int = 100) -> List[Dict[str, Any]]:
    """Return recent MCP audit events, newest first."""
    with get_conn() as conn:
        rows = conn.execute(
            """
            SELECT * FROM mcp_audit_log
             ORDER BY ts DESC, id DESC
             LIMIT ?
            """,
            (limit,),
        ).fetchall()
    return [_mcp_audit_row_to_dict(r) for r in rows]


def get_mcp_audit_log(audit_id: int) -> Optional[Dict[str, Any]]:
    """Return a single MCP audit event by id, or None if not found."""
    with get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM mcp_audit_log WHERE id = ?",
            (audit_id,),
        ).fetchone()
    if not row:
        return None
    return _mcp_audit_row_to_dict(row)


def list_mcp_audit_logs_between(
    from_ts: Optional[str] = None,
    to_ts: Optional[str] = None,
    limit: int = 1000,
) -> List[Dict[str, Any]]:
    """
    Return MCP audit events whose ts falls within [from_ts, to_ts], oldest
    first so a batch export reads in hash-chain order. Either bound may be
    omitted to leave that side open.
    """
    clauses: List[str] = []
    params: List[Any] = []
    if from_ts:
        clauses.append("ts >= ?")
        params.append(from_ts)
    if to_ts:
        clauses.append("ts <= ?")
        params.append(to_ts)
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    params.append(limit)
    with get_conn() as conn:
        rows = conn.execute(
            f"SELECT * FROM mcp_audit_log {where} ORDER BY ts ASC, id ASC LIMIT ?",
            tuple(params),
        ).fetchall()
    return [_mcp_audit_row_to_dict(r) for r in rows]


def verify_mcp_audit_record(audit_id: int) -> Dict[str, Any]:
    """
    Verify one mcp_audit_log record against the tamper-evident hash chain.

    Two independent checks:
      1. content integrity — the stored integrity_hash matches a fresh hash of
         the record's own fields (including its stored prev_hash); and
      2. linkage — the record's prev_hash equals the previous record's stored
         integrity_hash (or GENESIS for the first record).

    Together these make a single receipt tamper-evident without re-walking the
    entire chain from genesis.
    """
    with get_conn() as conn:
        row = conn.execute(
            "SELECT id, ts, action, tool_name, role, reason, prev_hash, "
            "integrity_hash FROM mcp_audit_log WHERE id = ?",
            (audit_id,),
        ).fetchone()
        if not row:
            return {"chain_verified": False, "reason": "record_not_found"}
        row = dict(row)
        prev = conn.execute(
            "SELECT integrity_hash FROM mcp_audit_log WHERE id < ? "
            "ORDER BY id DESC LIMIT 1",
            (audit_id,),
        ).fetchone()

    stored_hash = row.get("integrity_hash") or ""
    if not stored_hash:
        return {"chain_verified": False, "reason": "missing_integrity_hash"}

    expected_prev = (dict(prev).get("integrity_hash") if prev else None) or "GENESIS"
    recomputed = _compute_audit_hash(
        row.get("prev_hash") or "",
        row.get("ts") or "",
        row.get("action") or "",
        row.get("tool_name") or "",
        row.get("role") or "",
        row.get("reason") or "",
    )
    content_ok = recomputed == stored_hash
    link_ok = (row.get("prev_hash") or "") == expected_prev
    verified = content_ok and link_ok
    if verified:
        reason = "verified"
    elif not content_ok:
        reason = "hash mismatch"
    else:
        reason = "broken chain link"
    return {
        "chain_verified": verified,
        "reason": reason,
        "content_ok": content_ok,
        "link_ok": link_ok,
    }


# ── Policy helpers ────────────────────────────────────────────────────────────


def _policy_row_to_dict(row, cols: Optional[List[str]] = None) -> Dict[str, Any]:
    d = row_to_plain_dict(row, cols)
    d["is_active"] = bool(d.get("is_active", True))
    if d.get("rules_json"):
        try:
            d["rules"] = json.loads(d["rules_json"])
        except (json.JSONDecodeError, TypeError):
            d["rules"] = {}
    else:
        d["rules"] = {}
    return d


def list_policies(policy_type: Optional[str] = None) -> List[Dict[str, Any]]:
    """Return all policies, optionally filtered by type."""
    with get_conn() as conn:
        if policy_type:
            rows = conn.execute(
                "SELECT * FROM policies WHERE policy_type = ? ORDER BY name, server_id",
                (policy_type,),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM policies ORDER BY policy_type, name, server_id"
            ).fetchall()
        cols = table_columns("policies", conn=conn)
    return [_policy_row_to_dict(r, cols) for r in rows]


def get_policy(policy_id: int) -> Optional[Dict[str, Any]]:
    """Return a single policy by id, or None."""
    with get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM policies WHERE id = ?", (policy_id,)
        ).fetchone()
        if not row:
            return None
        cols = table_columns("policies", conn=conn)
    return _policy_row_to_dict(row, cols)


def get_policy_by_name(
    policy_type: str, name: str, server_id: str = ""
) -> Optional[Dict[str, Any]]:
    """
    Lookup active policy by (policy_type, name, server_id).
    Falls back to (policy_type, name, '') when server_id is specified but not found.
    """
    with get_conn() as conn:
        cols = table_columns("policies", conn=conn)
        row = conn.execute(
            """SELECT * FROM policies
               WHERE policy_type = ? AND name = ? AND server_id = ? AND is_active = TRUE
               ORDER BY id DESC LIMIT 1""",
            (policy_type, name, server_id or ""),
        ).fetchone()
        if not row and server_id:
            row = conn.execute(
                """SELECT * FROM policies
                   WHERE policy_type = ? AND name = ? AND server_id = '' AND is_active = TRUE
                   ORDER BY id DESC LIMIT 1""",
                (policy_type, name),
            ).fetchone()
        if not row:
            return None
    return _policy_row_to_dict(row, cols)


def upsert_policy(
    policy_type: str,
    name: str,
    rules_json: str,
    server_id: str = "",
    updated_by: str = "",
) -> Optional[Dict[str, Any]]:
    """
    Insert or update a policy row.
    Returns the saved policy record.
    """
    now = datetime.now(timezone.utc).isoformat()
    sid = server_id or ""
    with _db_lock, get_conn() as conn:
        row = conn.execute(
            "SELECT id FROM policies WHERE policy_type = ? AND name = ? AND server_id = ?",
            (policy_type, name, sid),
        ).fetchone()
        if row:
            policy_id = row_value(row, "id", 0)
            conn.execute(
                """UPDATE policies
                      SET rules_json = ?, updated_at = ?, updated_by = ?, is_active = TRUE
                    WHERE id = ?""",
                (rules_json, now, updated_by, policy_id),
            )
        else:
            conn.execute(
                """INSERT INTO policies
                     (policy_type, name, server_id, rules_json, is_active,
                      created_at, updated_at, updated_by)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (policy_type, name, sid, rules_json, True, now, now, updated_by),
            )
            fetched = conn.execute(
                "SELECT id FROM policies WHERE policy_type = ? AND name = ? AND server_id = ?",
                (policy_type, name, sid),
            ).fetchone()
            policy_id = row_value(fetched, "id", 0)
    return get_policy(policy_id)


def delete_policy(policy_id: int) -> bool:
    """Soft-delete a policy (sets is_active=0). Returns True if a row was updated."""
    now = datetime.now(timezone.utc).isoformat()
    with _db_lock, get_conn() as conn:
        cursor = conn.execute(
            "UPDATE policies SET is_active = FALSE, updated_at = ? WHERE id = ?",
            (now, policy_id),
        )
    return cursor.rowcount > 0


def seed_default_policies(defaults: Dict[str, Any], policy_type: str = "role") -> None:
    """
    Seed the policies table from a provided defaults dict.
    Only inserts rows that do not already exist (checked by policy_type + name + server_id).
    Never overwrites or modifies existing DB policies.
    """
    now = datetime.now(timezone.utc).isoformat()
    with _db_lock, get_conn() as conn:
        for name, rules in defaults.items():
            existing = conn.execute(
                "SELECT id FROM policies WHERE policy_type = ? AND name = ? AND server_id = ''",
                (policy_type, name),
            ).fetchone()
            if existing:
                continue
            try:
                conn.execute(
                    """INSERT OR IGNORE INTO policies
                         (policy_type, name, server_id, rules_json, is_active,
                          created_at, updated_at, updated_by)
                       VALUES (?, ?, '', ?, ?, ?, ?, 'system:seed')""",
                    (policy_type, name, json.dumps(rules, default=str), True, now, now),
                )
            except Exception:
                logger.exception("Failed to seed policy %s/%s", policy_type, name)
