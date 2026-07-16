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
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone, timedelta
from threading import Lock
from typing import Optional, List, Dict, Any
from urllib.parse import urlparse
from core import audit_envelope
from core import drift_evidence
from core.mcp_drift import classify_tool_drift
from core.tool_metadata import normalize_tool_metadata

logger = logging.getLogger("interlock.db")

DATABASE_URL = (os.getenv("DATABASE_URL") or "").strip()
USE_POSTGRES = DATABASE_URL.startswith(("postgresql://", "postgres://"))
DB_PATH = os.getenv("FIREWALL_DB_PATH", "data/firewall.db")
_db_lock = Lock()  # SQLite is fine concurrent-read, one-writer; lock guards writes
_pg_pool = None
_pg_pool_lock = Lock()

SEEDED_DEMO_SERVER_IDS = {"trusted-filesystem", "trusted-search"}
INTENDED_DEMO_SERVER_IDS = {
    *SEEDED_DEMO_SERVER_IDS,
    "clean-proof-docs",
}
FIXTURE_SERVER_PREFIX = "_fixture_"
LEGACY_DISPOSABLE_FIXTURE_SERVER_IDS = {
    "mock-test",
    "demo-docs2",
    "escalation-demo",
    "db-drift-demo",
    "db-drift-mock",
    "genesys-probe-live",
}
KNOWN_UNAPPROVED_EXTERNAL_SERVER_IDS = {"asmi-demo"}
KNOWN_UNAPPROVED_EXTERNAL_HOSTS = {"broen.tech"}
DISPOSABLE_FIXTURE_SERVER_RE = re.compile(r"^m\d+$")
PUBLIC_MOCK_HOST_SUFFIXES = (".web.val.run", ".localhost.run")
DEFAULT_MCP_REGISTRATION_ALLOWED_HOSTS = {
    "mcp.acme-corp.internal",
}
DEFAULT_MCP_REGISTRATION_ALLOWED_SUFFIXES = PUBLIC_MOCK_HOST_SUFFIXES
PRODUCTION_DATABASE_MARKERS = (
    "supabase.co",
    "supabase.com",
    "pooler.supabase.com",
)


def _csv_env(name: str) -> List[str]:
    raw = os.getenv(name, "")
    return [item.strip().lower() for item in raw.split(",") if item.strip()]


def _configured_allowed_mcp_hosts() -> set:
    return {
        *DEFAULT_MCP_REGISTRATION_ALLOWED_HOSTS,
        *_csv_env("MCP_REGISTRY_ALLOWED_HOSTS"),
    }


def _configured_allowed_mcp_suffixes() -> tuple:
    suffixes = [
        *DEFAULT_MCP_REGISTRATION_ALLOWED_SUFFIXES,
        *_csv_env("MCP_REGISTRY_ALLOWED_HOST_SUFFIXES"),
    ]
    return tuple(
        suffix if suffix.startswith(".") else f".{suffix}" for suffix in suffixes
    )


def is_production_database_url(database_url: str = "") -> bool:
    """Return True when a database URL points at managed production-like state."""
    raw = (database_url or DATABASE_URL or "").strip().lower()
    if not raw:
        return False
    if any(marker in raw for marker in PRODUCTION_DATABASE_MARKERS):
        return True
    host = (urlparse(raw).hostname or "").lower()
    return any(marker in host for marker in PRODUCTION_DATABASE_MARKERS)


def is_fixture_mcp_server_id(server_id: str) -> bool:
    sid = str(server_id or "").strip()
    return (
        sid.startswith(FIXTURE_SERVER_PREFIX)
        or sid.startswith("_test_")
        or sid.startswith("_st_")
        or sid in LEGACY_DISPOSABLE_FIXTURE_SERVER_IDS
        or bool(DISPOSABLE_FIXTURE_SERVER_RE.fullmatch(sid))
    )


def assert_not_production_fixture_write(
    server_id: str, context: str = "MCP registry"
) -> None:
    """Refuse fixture writes when DATABASE_URL targets live production data."""
    if is_fixture_mcp_server_id(server_id) and is_production_database_url():
        raise RuntimeError(
            f"Refusing to write fixture MCP server '{server_id}' via {context}: "
            "DATABASE_URL points at Supabase/production."
        )


def validate_mcp_registration_target(server_id: str, url: str) -> None:
    """Enforce fixture namespacing and explicit external-host registration."""
    sid = str(server_id or "").strip()
    assert_not_production_fixture_write(sid, "MCP server registration")

    parsed = urlparse(str(url or ""))
    host = (parsed.hostname or "").lower()
    if (
        is_production_database_url()
        and sid not in INTENDED_DEMO_SERVER_IDS
        and (not host or _is_loopback_host(host))
    ):
        raise RuntimeError(
            f"Refusing to register non-demo MCP server '{sid}' against "
            "Supabase/production DATABASE_URL."
        )
    if not host or _is_loopback_host(host):
        return

    if sid in INTENDED_DEMO_SERVER_IDS:
        return

    allowed_hosts = _configured_allowed_mcp_hosts()
    allowed_suffixes = _configured_allowed_mcp_suffixes()
    if host in allowed_hosts or any(
        host.endswith(suffix) for suffix in allowed_suffixes
    ):
        return

    raise ValueError(
        "External MCP server registration is restricted to the explicit allowlist. "
        f"Host '{host}' is not allowed."
    )


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
_POSTGRES_BOOLEAN_COLUMNS = (
    "is_active",
    "verified",
    "probes_enabled",
    "threat_blocked",
)


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
    # SQLite REAL is an 8-byte float; Postgres REAL is float4 and silently
    # loses precision, which would break the fixed-precision float encoding
    # in v3 audit envelopes (core/audit_envelope.py).
    converted = re.sub(r"\bREAL\b", "DOUBLE PRECISION", converted)
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
    # ``is_threat`` also exists on latency_samples, where the current storage
    # and queries intentionally use integers. Convert only scan_history, whose
    # writer binds a Python bool through psycopg2.
    converted = re.sub(
        r"(CREATE TABLE IF NOT EXISTS scan_history\s*\(.*?\bis_threat\s+)"
        r"INTEGER(\s+NOT NULL)?\s+DEFAULT\s+0\b",
        lambda match: (f"{match.group(1)}BOOLEAN{match.group(2) or ''} DEFAULT FALSE"),
        converted,
        count=1,
        flags=re.IGNORECASE | re.DOTALL,
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
    scopes          TEXT    NOT NULL DEFAULT '["mcp.call","mcp.read"]',
    role            TEXT    NOT NULL DEFAULT 'readonly_agent',
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
    environment     TEXT    NOT NULL DEFAULT 'production',
    probes_enabled  INTEGER NOT NULL DEFAULT 0,
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

CREATE INDEX IF NOT EXISTS idx_mcp_audit_ts ON mcp_audit_log(ts);
CREATE INDEX IF NOT EXISTS idx_mcp_audit_call_id ON mcp_audit_log(call_id);
CREATE INDEX IF NOT EXISTS idx_mcp_audit_server_tool ON mcp_audit_log(server_id, tool_name);
CREATE INDEX IF NOT EXISTS idx_mcp_audit_action ON mcp_audit_log(action);
CREATE INDEX IF NOT EXISTS idx_mcp_audit_drift_severity ON mcp_audit_log(drift_severity);

CREATE TABLE IF NOT EXISTS tool_surface_snapshots (
    surface_hash   TEXT PRIMARY KEY,
    canonical_json TEXT NOT NULL,
    created_at     TEXT NOT NULL
);

-- Rebaseline staging: at most ONE candidate per server (the latest validated
-- discovery). A newer discovery replaces the row, which invalidates any
-- approval still holding the older candidate's hash. Candidates never touch
-- mcp_tool_metadata until promoted.
CREATE TABLE IF NOT EXISTS mcp_rebaseline_candidates (
    server_id              TEXT NOT NULL PRIMARY KEY,
    candidate_surface_hash TEXT NOT NULL,
    canonical_surface      TEXT NOT NULL,
    tools_json             TEXT NOT NULL,
    tool_count             INTEGER NOT NULL,
    created_at             TEXT NOT NULL,
    created_by             TEXT NOT NULL DEFAULT '',
    FOREIGN KEY (server_id) REFERENCES mcp_servers(server_id) ON DELETE CASCADE
);

-- Immutable history of every ACTIVE baseline a server has had. Exactly one
-- row per server has replaced_at IS NULL (the current baseline version) and
-- prior rows are never rewritten beyond their replaced_at closing stamp.
CREATE TABLE IF NOT EXISTS mcp_baseline_versions (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    server_id         TEXT NOT NULL,
    version           INTEGER NOT NULL,
    surface_hash      TEXT NOT NULL,
    canonical_surface TEXT NOT NULL,
    promoted_at       TEXT NOT NULL,
    replaced_at       TEXT,
    approval_audit_id INTEGER,
    approved_by       TEXT NOT NULL DEFAULT '',
    UNIQUE (server_id, version),
    FOREIGN KEY (server_id) REFERENCES mcp_servers(server_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_mcp_baseline_versions_server
    ON mcp_baseline_versions(server_id, version);

CREATE TABLE IF NOT EXISTS mcp_response_profiles (
    server_id    TEXT    NOT NULL,
    tool_name    TEXT    NOT NULL,
    profile_hash TEXT    NOT NULL,
    profile_json TEXT    NOT NULL,
    first_seen   TEXT    NOT NULL,
    last_seen    TEXT    NOT NULL,
    updated_at   TEXT    NOT NULL,
    status       TEXT    NOT NULL DEFAULT 'approved',
    PRIMARY KEY (server_id, tool_name),
    FOREIGN KEY (server_id) REFERENCES mcp_servers(server_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_mcp_response_profiles_server
ON mcp_response_profiles(server_id);

CREATE TABLE IF NOT EXISTS mcp_external_reach_profiles (
    server_id    TEXT    NOT NULL,
    tool_name    TEXT    NOT NULL,
    profile_hash TEXT    NOT NULL,
    profile_json TEXT    NOT NULL,
    first_seen   TEXT    NOT NULL,
    last_seen    TEXT    NOT NULL,
    updated_at   TEXT    NOT NULL,
    status       TEXT    NOT NULL DEFAULT 'approved',
    PRIMARY KEY (server_id, tool_name),
    FOREIGN KEY (server_id) REFERENCES mcp_servers(server_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_mcp_external_reach_profiles_server
ON mcp_external_reach_profiles(server_id);

CREATE TABLE IF NOT EXISTS mcp_effect_profiles (
    server_id    TEXT    NOT NULL,
    tool_name    TEXT    NOT NULL,
    profile_hash TEXT    NOT NULL,
    profile_json TEXT    NOT NULL,
    first_seen   TEXT    NOT NULL,
    last_seen    TEXT    NOT NULL,
    updated_at   TEXT    NOT NULL,
    status       TEXT    NOT NULL DEFAULT 'approved',
    PRIMARY KEY (server_id, tool_name),
    FOREIGN KEY (server_id) REFERENCES mcp_servers(server_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_mcp_effect_profiles_server
ON mcp_effect_profiles(server_id);

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
    hash_v             INTEGER NOT NULL DEFAULT 1,
    prev_hash          TEXT    NOT NULL DEFAULT '',
    integrity_hash     TEXT    NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_admin_audit_ts ON admin_audit_log(ts);
CREATE INDEX IF NOT EXISTS idx_admin_audit_action ON admin_audit_log(action);
CREATE INDEX IF NOT EXISTS idx_admin_audit_actor ON admin_audit_log(actor_auth_type, actor_subject, actor_token_prefix);

CREATE TABLE IF NOT EXISTS audit_chain_checkpoints (
    id                       INTEGER PRIMARY KEY AUTOINCREMENT,
    chain                    TEXT    NOT NULL,
    created_at               TEXT    NOT NULL,
    last_deleted_id          INTEGER NOT NULL,
    last_deleted_hash        TEXT    NOT NULL DEFAULT '',
    first_retained_id        INTEGER,
    first_retained_prev_hash TEXT    NOT NULL DEFAULT '',
    deleted_count            INTEGER NOT NULL DEFAULT 0,
    retention_policy         TEXT    NOT NULL DEFAULT '{}',
    actor                    TEXT    NOT NULL DEFAULT '{}',
    hash_v                   INTEGER NOT NULL DEFAULT 3,
    prev_hash                TEXT    NOT NULL DEFAULT '',
    integrity_hash           TEXT    NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_audit_chain_checkpoints_chain ON audit_chain_checkpoints(chain);

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
            conn, "mcp_audit_log", "principal_id", "TEXT NOT NULL DEFAULT ''"
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
        # Existing keys migrate to runtime-only. Grandfathering them as admin
        # would preserve the control-plane privilege this migration closes.
        _ensure_column(
            conn,
            "api_keys",
            "scopes",
            'TEXT NOT NULL DEFAULT \'["mcp.call","mcp.read"]\'',
        )
        _ensure_column(
            conn, "api_keys", "role", "TEXT NOT NULL DEFAULT 'readonly_agent'"
        )
        _ensure_column(conn, "mcp_servers", "auth_type", "TEXT NOT NULL DEFAULT 'none'")
        _ensure_column(conn, "mcp_servers", "auth_header", "TEXT NOT NULL DEFAULT ''")
        _ensure_column(
            conn, "mcp_servers", "auth_token_env", "TEXT NOT NULL DEFAULT ''"
        )
        # Pre-existing servers migrate to production + probes disabled so
        # effective-permission probes fail closed until an admin explicitly
        # marks a server non-production and probe-enabled.
        _ensure_column(
            conn, "mcp_servers", "environment", "TEXT NOT NULL DEFAULT 'production'"
        )
        _ensure_column(
            conn, "mcp_servers", "probes_enabled", "INTEGER NOT NULL DEFAULT 0"
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
        _ensure_column(conn, "mcp_audit_log", "call_id", "TEXT NOT NULL DEFAULT ''")
        _ensure_column(conn, "mcp_audit_log", "hash_v", "INTEGER NOT NULL DEFAULT 1")
        _ensure_column(conn, "admin_audit_log", "prev_hash", "TEXT NOT NULL DEFAULT ''")
        _ensure_column(
            conn, "admin_audit_log", "integrity_hash", "TEXT NOT NULL DEFAULT ''"
        )
        _ensure_column(conn, "admin_audit_log", "hash_v", "INTEGER NOT NULL DEFAULT 1")
        # v3 envelopes commit float columns as fixed-precision decimals, which
        # only round-trip losslessly when Postgres stores them as float8.
        # Legacy deployments created them as REAL (float4); widen in place.
        _ensure_double_precision(conn, "mcp_audit_log", ("confidence", "scan_time_ms"))
        _ensure_postgres_boolean_column(conn, "usage_log", "threat_blocked")
        _ensure_postgres_boolean_column(conn, "scan_history", "is_threat")
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
    for col in ("custom_policy", "siem_configs", "scopes"):
        if d.get(col):
            try:
                d[col] = json.loads(d[col])
            except (json.JSONDecodeError, TypeError):
                d[col] = [] if col == "scopes" else None
    if not isinstance(d.get("scopes"), list):
        d["scopes"] = []
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


def _compute_audit_hash_v2(
    prev_hash: str,
    ts: str,
    action: str,
    tool_name: str,
    role: str,
    reason: str,
    server_id: str,
    call_id: str,
    argument_hash: str,
    drift_baseline_hash: str,
    drift_current_hash: str,
) -> str:
    """
    v2 mcp_audit_log chain hash. Extends v1 by committing to the receipt
    binding fields (target, call id, argument hash, before/after surface
    hashes) so a replayed receipt cannot be re-pointed at a different context
    without breaking chain verification. Rows written before this change keep
    hash_v=1 and verify under _compute_audit_hash.
    """
    data = "|".join(
        [
            prev_hash,
            ts,
            action,
            tool_name,
            role,
            reason,
            server_id,
            call_id,
            argument_hash,
            drift_baseline_hash,
            drift_current_hash,
            "v=2",
        ]
    )
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


# The exact hash versions each chain has ever written. Verification rejects
# anything outside these sets (audit_envelope.require_hash_version): a v3 row
# relabeled hash_v=4 must fail, not be reinterpreted under the v3 rule.
_MCP_HASH_VERSIONS = (1, 2, audit_envelope.HASH_V3)
_ADMIN_HASH_VERSIONS = (1, audit_envelope.HASH_V3)


def _recompute_mcp_audit_hash(row: Dict[str, Any]) -> str:
    """Recompute one mcp_audit_log row's integrity hash per its hash_v.

    Raises audit_envelope.UnsupportedHashVersionError for any hash_v outside
    exactly {1, 2, 3}; callers turn that into a failed verification.
    """
    version = audit_envelope.require_hash_version(row.get("hash_v"), _MCP_HASH_VERSIONS)
    if version == audit_envelope.HASH_V3:
        # v3: full-field canonical envelope — every stored security-
        # significant column is committed (core/audit_envelope.py).
        # strict=False: recomputing a possibly-tampered row must yield a
        # non-matching hash, never an exception.
        return audit_envelope.compute_hash_v3(
            "mcp_audit_log", row, row.get("prev_hash") or "", strict=False
        )
    if version == 2:
        return _compute_audit_hash_v2(
            row.get("prev_hash") or "",
            row.get("ts") or "",
            row.get("action") or "",
            row.get("tool_name") or "",
            row.get("role") or "",
            row.get("reason") or "",
            row.get("server_id") or "",
            row.get("call_id") or "",
            row.get("argument_hash") or "",
            row.get("drift_baseline_hash") or "",
            row.get("drift_current_hash") or "",
        )
    return _compute_audit_hash(
        row.get("prev_hash") or "",
        row.get("ts") or "",
        row.get("action") or "",
        row.get("tool_name") or "",
        row.get("role") or "",
        row.get("reason") or "",
    )


def _recompute_admin_audit_hash(row: Dict[str, Any]) -> str:
    """Recompute one admin_audit_log row's integrity hash per its hash_v.

    The admin chain only ever wrote v1 and v3; anything else (including 2)
    raises audit_envelope.UnsupportedHashVersionError and fails verification.
    """
    version = audit_envelope.require_hash_version(
        row.get("hash_v"), _ADMIN_HASH_VERSIONS
    )
    if version == audit_envelope.HASH_V3:
        return audit_envelope.compute_hash_v3(
            "admin_audit_log", row, row.get("prev_hash") or "", strict=False
        )
    return _compute_audit_hash(
        row.get("prev_hash") or "",
        row.get("ts") or "",
        row.get("action") or "",
        row.get("target_id") or "",
        row.get("actor_role") or "",
        row.get("reason") or "",
    )


def _latest_chain_checkpoint(conn, chain: str) -> Optional[Dict[str, Any]]:
    """Newest retention checkpoint for one audit chain, or None."""
    row = conn.execute(
        "SELECT * FROM audit_chain_checkpoints WHERE chain = ? "
        "ORDER BY id DESC LIMIT 1",
        (chain,),
    ).fetchone()
    return row_to_plain_dict(row) if row else None


def _list_chain_checkpoints(conn, chain: str) -> List[Dict[str, Any]]:
    """All retention checkpoints for one audit chain, oldest first."""
    rows = conn.execute(
        "SELECT * FROM audit_chain_checkpoints WHERE chain = ? ORDER BY id ASC",
        (chain,),
    ).fetchall()
    return [row_to_plain_dict(row) for row in rows]


def _verify_checkpoint_rows(checkpoints: List[Dict[str, Any]]) -> Optional[str]:
    """
    Verify one chain's retention checkpoints (their own hash chain from
    GENESIS). Returns None when valid, else a failure reason.

    Beyond the hash chain, each checkpoint's boundary fields must be
    internally consistent — the checkpoint hash only proves the fields were
    not mutated after the write, not that the writer recorded a coherent
    boundary, and an actor with database write access can recompute the
    checkpoint hashes at will. An honest prefix prune always satisfies:
    last_deleted_id < first_retained_id, first_retained_prev_hash equal to
    last_deleted_hash (both name the same boundary row), empty
    first_retained_prev_hash when nothing was retained, and strictly
    advancing deleted ranges across successive checkpoints.
    """
    prev_hash = "GENESIS"
    prev_last_deleted_id: Optional[int] = None
    for checkpoint in checkpoints:
        # The stored hash_v is not inside the checkpoint envelope (the prefix
        # pins the constant "3"), so it must be enforced here, exactly.
        try:
            audit_envelope.require_hash_version(
                checkpoint.get("hash_v"), (audit_envelope.HASH_V3,)
            )
        except audit_envelope.UnsupportedHashVersionError:
            return "unsupported checkpoint hash version"
        stored = checkpoint.get("integrity_hash") or ""
        if not stored:
            return "checkpoint missing integrity hash"
        if (checkpoint.get("prev_hash") or "") != prev_hash:
            return "checkpoint chain link broken"
        expected = audit_envelope.compute_hash_v3(
            "audit_chain_checkpoint", checkpoint, prev_hash, strict=False
        )
        if expected != stored:
            return "checkpoint hash mismatch"

        last_deleted_id = int(checkpoint.get("last_deleted_id") or 0)
        first_retained_id = checkpoint.get("first_retained_id")
        boundary_prev = checkpoint.get("first_retained_prev_hash") or ""
        if first_retained_id is not None:
            if last_deleted_id >= int(first_retained_id):
                return "checkpoint boundary ids out of order"
            if boundary_prev != (checkpoint.get("last_deleted_hash") or ""):
                return "checkpoint boundary hashes disagree"
        elif boundary_prev != "":
            return "checkpoint boundary hashes disagree"
        if prev_last_deleted_id is not None and last_deleted_id <= prev_last_deleted_id:
            return "checkpoint ranges not monotonic"
        prev_last_deleted_id = last_deleted_id

        prev_hash = stored
    return None


def _checkpoint_anchor(checkpoints: List[Dict[str, Any]]) -> str:
    """
    The hash the retained chain must start from: the newest checkpoint's
    recorded last-deleted hash, or GENESIS when nothing was ever pruned.
    """
    if not checkpoints:
        return "GENESIS"
    return checkpoints[-1].get("last_deleted_hash") or "GENESIS"


def _is_postgres_conn(conn) -> bool:
    return isinstance(conn, _PostgresConn)


def _audit_chain_lock_key(table: str) -> int:
    """
    Stable signed-64-bit advisory-lock key for one audit hash chain.

    Derived from the chain (table) name only, so every replica computes the
    same key, and distinct per table so the two chains never serialize each
    other.
    """
    digest = hashlib.sha256(f"interlock:audit-chain:{table}".encode()).digest()
    return int.from_bytes(digest[:8], "big", signed=True)


@contextmanager
def _serialized_chain_append(conn, table: str):
    """
    Serialize a read-tip-then-insert append to one audit hash chain.

    Both audit chains are globally scoped — one chain per table, tip = the row
    with the highest id — so appends must be serialized per table. The
    process-local _db_lock cannot do that across replicas sharing one
    Postgres: two replicas can read the same tip and both insert a row
    committing to it, forking the chain. On Postgres, take a
    transaction-scoped advisory lock keyed on the chain inside one explicit
    transaction, so exactly one append can extend each tip; the lock releases
    automatically at COMMIT/ROLLBACK. On SQLite the guard is a no-op: _db_lock
    (held by callers) plus the single-writer database already serialize
    appends.
    """
    if not _is_postgres_conn(conn):
        yield
        return
    conn.execute("BEGIN")
    try:
        conn.execute("SELECT pg_advisory_xact_lock(?)", (_audit_chain_lock_key(table),))
        yield
    except BaseException:
        try:
            conn.execute("ROLLBACK")
        except Exception:
            logger.exception("Failed to roll back %s chain append", table)
        raise
    conn.execute("COMMIT")


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


def _ensure_double_precision(conn, table: str, columns) -> None:
    """
    Widen Postgres float4 (REAL) columns to float8 in place.

    No-op on SQLite (REAL is already 8-byte) and for columns already float8.
    Widening is exact — existing float4 values convert without change.
    """
    if not _is_postgres_conn(conn):
        return
    _validate_identifier(table)
    for column in columns:
        _validate_identifier(column)
        row = conn.execute(
            """
            SELECT data_type
              FROM information_schema.columns
             WHERE table_schema = current_schema()
               AND table_name = ?
               AND column_name = ?
            """,
            (table, column),
        ).fetchone()
        data_type = str(row_value(row, "data_type", 0) or "").lower() if row else ""
        if data_type == "real":
            conn.execute(
                f"ALTER TABLE {table} ALTER COLUMN {column} TYPE double precision"
            )


def _ensure_postgres_boolean_column(conn, table: str, column: str) -> bool:
    """Converge a persistence flag to BOOLEAN NOT NULL DEFAULT FALSE."""
    if not _is_postgres_conn(conn):
        return False
    _validate_identifier(table)
    _validate_identifier(column)

    def read_state():
        row = conn.execute(
            """
            SELECT data_type, column_default, is_nullable
              FROM information_schema.columns
             WHERE table_schema = current_schema()
               AND table_name = ?
               AND column_name = ?
            """,
            (table, column),
        ).fetchone()
        if row is None:
            return None
        data_type = str(row_value(row, "data_type", 0) or "").lower()
        column_default = str(row_value(row, "column_default", 1) or "").lower()
        is_nullable = str(row_value(row, "is_nullable", 2) or "").upper() == "YES"
        integer_type = data_type in {"smallint", "integer", "bigint"}
        if not integer_type and data_type != "boolean":
            raise RuntimeError(
                f"Cannot migrate {table}.{column} from unexpected type {data_type!r}"
            )
        normalized_default = column_default.replace("'", "").split("::", 1)[0].strip()
        return integer_type, is_nullable, normalized_default == "false"

    state = read_state()
    if state is None:
        return False
    integer_type, is_nullable, default_is_false = state
    if not integer_type and default_is_false and not is_nullable:
        return False

    # The pooled Postgres connections use autocommit, so explicitly bound the
    # backfill and constraint changes to one transaction. Taking the table lock
    # first prevents a concurrent explicit NULL insert between the backfill and
    # SET NOT NULL. init_db always migrates usage_log before scan_history, which
    # gives concurrent initializers a consistent lock order.
    conn.execute("BEGIN")
    try:
        conn.execute(f"LOCK TABLE {table} IN ACCESS EXCLUSIVE MODE")
        # Another initializer may have completed while this connection waited
        # for the lock. Re-read under the lock so no stale type/nullability
        # decision can drive the migration SQL.
        state = read_state()
        if state is None:
            raise RuntimeError(f"Cannot migrate missing column {table}.{column}")
        integer_type, is_nullable, default_is_false = state
        if not integer_type and default_is_false and not is_nullable:
            conn.execute("COMMIT")
            return False
        if integer_type:
            if is_nullable:
                conn.execute(f"UPDATE {table} SET {column} = 0 WHERE {column} IS NULL")
            conn.execute(f"""
                ALTER TABLE {table}
                  ALTER COLUMN {column} DROP DEFAULT,
                  ALTER COLUMN {column} TYPE BOOLEAN USING ({column} <> 0),
                  ALTER COLUMN {column} SET DEFAULT FALSE,
                  ALTER COLUMN {column} SET NOT NULL
                """)
        else:
            if is_nullable:
                conn.execute(
                    f"UPDATE {table} SET {column} = FALSE WHERE {column} IS NULL"
                )
            alter_actions = []
            if not default_is_false:
                alter_actions.append(f"ALTER COLUMN {column} SET DEFAULT FALSE")
            if is_nullable:
                alter_actions.append(f"ALTER COLUMN {column} SET NOT NULL")
            conn.execute(f"ALTER TABLE {table} " + ", ".join(alter_actions))
        conn.execute("COMMIT")
    except BaseException:
        try:
            conn.execute("ROLLBACK")
        except Exception:
            logger.exception(
                "Failed to roll back boolean migration for %s.%s", table, column
            )
        raise
    return True


def _insert_returning_id(conn, sql: str, params) -> Optional[int]:
    """
    Execute an INSERT and return the new row's id on both backends.

    psycopg2's ``cursor.lastrowid`` carries row-OID semantics — 0 on modern
    Postgres tables — so the Postgres path appends ``RETURNING id`` and reads
    the real id; SQLite keeps ``cursor.lastrowid``.
    """
    if _is_postgres_conn(conn):
        cur = conn.execute(sql.rstrip().rstrip(";") + " RETURNING id", params)
        row = cur.fetchone()
        if row is None:
            return None
        value = row_value(row, "id", 0)
        return int(value) if value is not None else None
    return conn.execute(sql, params).lastrowid


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
API_KEY_SCOPES = {
    "mcp.call",
    "mcp.read",
    "mcp.discover",
    "mcp.probe",
    "audit.read",
    "audit.export",
    "admin",
}
DEFAULT_API_KEY_SCOPES = ["mcp.call", "mcp.read"]
MCP_SERVER_ENVIRONMENTS = {"production", "non_production"}
API_KEY_ROLES = {
    "support_agent",
    "devops_agent",
    "finance_agent",
    "readonly_agent",
    "data_analyst",
    "admin_agent",
}


def _normalize_scopes(scopes: Optional[List[str]]) -> List[str]:
    if scopes is None:
        return list(DEFAULT_API_KEY_SCOPES)
    normalized = []
    for scope in scopes:
        value = str(scope or "").strip()
        if value not in API_KEY_SCOPES:
            raise ValueError(
                f"Unknown API key scope '{value}'. Valid: {sorted(API_KEY_SCOPES)}"
            )
        if value not in normalized:
            normalized.append(value)
    return normalized


def _normalize_api_key_role(role: Optional[str]) -> str:
    value = str(role or "readonly_agent").strip()
    if value not in API_KEY_ROLES:
        raise ValueError(
            f"Unknown API key role '{value}'. Valid: {sorted(API_KEY_ROLES)}"
        )
    return value


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
    scopes = _normalize_scopes(overrides.get("scopes"))
    role = _normalize_api_key_role(overrides.get("role"))

    with _db_lock, get_conn() as conn:
        conn.execute(
            """
            INSERT INTO api_keys
              (key_hash, key_prefix, label, plan, monthly_limit, rate_per_min,
               fail_mode, webhook_url, custom_policy, siem_configs, upstream_key,
               is_active, created_at, max_response_bytes, max_array_items,
               scopes, role)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                json.dumps(scopes),
                role,
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
        "scopes": scopes,
        "role": role,
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
        "scopes",
        "role",
    }
    fields = {k: v for k, v in fields.items() if k in EDITABLE}
    if not fields:
        return False

    if "scopes" in fields:
        fields["scopes"] = _normalize_scopes(fields["scopes"])
    if "role" in fields:
        fields["role"] = _normalize_api_key_role(fields["role"])

    # JSON-encode the JSON columns
    for col in ("custom_policy", "siem_configs", "scopes"):
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
    # The exact values inserted below, keyed by column, so the v3 envelope
    # hashes precisely what a verifier will read back from either backend.
    record = {
        "ts": now,
        "actor_auth_type": event.get("actor_auth_type") or "",
        "actor_role": event.get("actor_role") or "",
        "actor_label": event.get("actor_label") or "",
        "actor_email": event.get("actor_email") or "",
        "actor_subject": event.get("actor_subject") or "",
        "actor_token_prefix": event.get("actor_token_prefix") or "",
        "action": event.get("action") or "",
        "target_type": event.get("target_type") or "",
        "target_id": event.get("target_id") or "",
        "result": event.get("result") or "success",
        "reason": event.get("reason") or "",
        "details": _json_dumps_object(event.get("details") or {}),
    }
    with (
        _db_lock,
        get_conn() as conn,
        _serialized_chain_append(conn, "admin_audit_log"),
    ):
        row = conn.execute(
            "SELECT integrity_hash FROM admin_audit_log ORDER BY id DESC LIMIT 1"
        ).fetchone()
        if row is not None:
            prev_hash = (dict(row).get("integrity_hash") or "") or "GENESIS"
        else:
            # Empty table: continue from the retention checkpoint boundary
            # (if the chain was pruned away entirely) instead of GENESIS.
            latest = _latest_chain_checkpoint(conn, "admin_audit_log")
            prev_hash = (latest or {}).get("last_deleted_hash") or "GENESIS"
        integrity_hash = audit_envelope.compute_hash_v3(
            "admin_audit_log", record, prev_hash
        )
        event_id = _insert_returning_id(
            conn,
            """
            INSERT INTO admin_audit_log
              (ts, actor_auth_type, actor_role, actor_label, actor_email, actor_subject,
               actor_token_prefix, action, target_type, target_id, result, reason, details,
               hash_v, prev_hash, integrity_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                record["ts"],
                record["actor_auth_type"],
                record["actor_role"],
                record["actor_label"],
                record["actor_email"],
                record["actor_subject"],
                record["actor_token_prefix"],
                record["action"],
                record["target_type"],
                record["target_id"],
                record["result"],
                record["reason"],
                record["details"],
                audit_envelope.HASH_V3,
                prev_hash,
                integrity_hash,
            ),
        )
    stored = dict(event)
    stored.update(
        {
            "id": event_id,
            "ts": now,
            "details": event.get("details") or {},
            "hash_v": audit_envelope.HASH_V3,
        }
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
    """
    Verify both audit hash chains end to end.

    A pruned chain no longer starts at GENESIS: retention writes a durable
    checkpoint binding the deleted boundary (see prune_retention), so the walk
    first verifies the chain's checkpoints (their own hash chain from
    GENESIS), then anchors the row walk at the newest checkpoint's recorded
    last-deleted hash. Every row is recomputed under its own hash version
    (v1/v2 legacy rules, v3 full-field envelope) with the walked prev hash, so
    content and linkage are proven together.
    """
    result: Dict[str, Any] = {"valid": True}

    checks = [
        ("mcp_audit_log", "mcp", _recompute_mcp_audit_hash),
        ("admin_audit_log", "admin", _recompute_admin_audit_hash),
    ]

    for table, key, recompute in checks:
        with get_conn() as conn:
            checkpoints = _list_chain_checkpoints(conn, table)
            rows = conn.execute(f"SELECT * FROM {table} ORDER BY id ASC").fetchall()

        checkpoint_failure = _verify_checkpoint_rows(checkpoints)
        if checkpoint_failure:
            result["valid"] = False
            result["broken_at"] = {"table": "audit_chain_checkpoints", "chain": table}
            result["reason"] = checkpoint_failure
            return result
        anchor = _checkpoint_anchor(checkpoints)
        latest_checkpoint = checkpoints[-1] if checkpoints else None

        dicts = [row_to_plain_dict(r) for r in rows]
        summary = {
            "total": len(dicts),
            "first_ts": dicts[0]["ts"] if dicts else None,
            "last_ts": dicts[-1]["ts"] if dicts else None,
            "checkpoints": len(checkpoints),
            "anchor": anchor,
        }

        if not dicts:
            # An empty chain is only clean when no checkpoint promised
            # retained rows (all-row prunes record first_retained_id NULL).
            if (
                latest_checkpoint is not None
                and latest_checkpoint.get("first_retained_id") is not None
            ):
                result["valid"] = False
                result["broken_at"] = {
                    "table": table,
                    "record_id": latest_checkpoint.get("first_retained_id"),
                }
                result["reason"] = "retained rows missing after checkpoint"
                return result
            result[key] = summary
            continue

        if latest_checkpoint is not None:
            first = dicts[0]
            first_retained_id = latest_checkpoint.get("first_retained_id")
            if first_retained_id is not None and int(first["id"]) != int(
                first_retained_id
            ):
                result["valid"] = False
                result["broken_at"] = {"table": table, "record_id": first["id"]}
                result["reason"] = "first retained row does not match checkpoint"
                return result
            # Three-way boundary binding: the checkpoint's last-deleted hash
            # (the anchor), its recorded first-retained prev hash, and the
            # first retained row's stored prev_hash must all agree exactly.
            # (_verify_checkpoint_rows already proved anchor == recorded prev
            # hash; both row-side comparisons are kept explicit anyway.)
            if first_retained_id is not None and (first.get("prev_hash") or "") != (
                latest_checkpoint.get("first_retained_prev_hash") or ""
            ):
                result["valid"] = False
                result["broken_at"] = {"table": table, "record_id": first["id"]}
                result["reason"] = (
                    "first retained row does not match checkpoint boundary"
                )
                return result
            if (first.get("prev_hash") or "") != anchor:
                result["valid"] = False
                result["broken_at"] = {"table": table, "record_id": first["id"]}
                result["reason"] = "retained chain does not start at checkpoint anchor"
                return result

        prev_hash = anchor
        for record in dicts:
            stored_hash = record.get("integrity_hash") or ""
            if not stored_hash:
                result["valid"] = False
                result["broken_at"] = {"table": table, "record_id": record["id"]}
                result["reason"] = "pre-integrity records found"
                return result
            # The stored prev_hash must equal the walked predecessor hash;
            # recomputing with the walked value alone would let a mutated
            # prev_hash column go unnoticed at chain level.
            if (record.get("prev_hash") or "") != prev_hash:
                result["valid"] = False
                result["broken_at"] = {"table": table, "record_id": record["id"]}
                result["reason"] = "broken chain link"
                return result
            try:
                expected = recompute({**record, "prev_hash": prev_hash})
            except audit_envelope.UnsupportedHashVersionError:
                result["valid"] = False
                result["broken_at"] = {"table": table, "record_id": record["id"]}
                result["reason"] = "unsupported hash version"
                return result
            if expected != stored_hash:
                result["valid"] = False
                result["broken_at"] = {"table": table, "record_id": record["id"]}
                result["reason"] = "hash mismatch"
                return result
            prev_hash = stored_hash

        result[key] = summary

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


# Raw value of the offline-demo API key. Seeded ONLY when the deployment opts
# in via INTERLOCK_OFFLINE_DEMO=true (the bundled docker-compose demo). Unlike
# the revoked legacy keys above, this key never ships enabled on hosted or
# default installs — see config.offline_demo_enabled().
OFFLINE_DEMO_KEY = "lf-demo-offline-key"


# The offline demo drives registration/review (admin), runtime calls,
# discovery, behavioral probes, and receipt verification/export from one
# bundled key. Each scope is explicit — the demo must not depend on scope
# inheritance beyond the deliberate admin super-scope.
OFFLINE_DEMO_KEY_SCOPES = [
    "admin",
    "mcp.call",
    "mcp.read",
    "mcp.discover",
    "mcp.probe",
    "audit.read",
    "audit.export",
]


def seed_offline_demo_key() -> None:
    """Idempotently seed the fixed offline-demo API key (hash only stored)."""
    key_hash = _hash_key(OFFLINE_DEMO_KEY)
    defaults = PLAN_DEFAULTS["developer"]
    with _db_lock, get_conn() as conn:
        existing = conn.execute(
            "SELECT id FROM api_keys WHERE key_hash = ?", (key_hash,)
        ).fetchone()
        if existing:
            conn.execute(
                "UPDATE api_keys SET scopes = ?, role = ? WHERE key_hash = ?",
                (
                    json.dumps(OFFLINE_DEMO_KEY_SCOPES),
                    "readonly_agent",
                    key_hash,
                ),
            )
            return
        conn.execute(
            """
            INSERT INTO api_keys
              (key_hash, key_prefix, label, plan, monthly_limit, rate_per_min,
               fail_mode, is_active, created_at, max_response_bytes, max_array_items,
               scopes, role)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                key_hash,
                OFFLINE_DEMO_KEY[:12],
                "offline demo key — local docker-compose demo only",
                "developer",
                defaults["monthly_limit"],
                defaults["rate_per_min"],
                defaults["fail_mode"],
                True,
                datetime.now(timezone.utc).isoformat(),
                defaults["max_response_bytes"],
                defaults["max_array_items"],
                json.dumps(OFFLINE_DEMO_KEY_SCOPES),
                "readonly_agent",
            ),
        )
    logger.info("Offline demo API key seeded (INTERLOCK_OFFLINE_DEMO).")


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


@contextmanager
def _chain_prune_transaction(conn, table: str):
    """
    Run one chain's checkpoint-write + prefix-delete atomically.

    Postgres: reuse the existing chain serialization mechanism — one explicit
    transaction holding the per-chain advisory lock — so a prune can never
    interleave with an append reading the tip or the checkpoint anchor.
    SQLite: callers hold _db_lock; an explicit transaction (the connection is
    opened in autocommit) makes checkpoint + delete atomic, so a failed prune
    rolls back to no-checkpoint-and-no-deletion.
    """
    if _is_postgres_conn(conn):
        with _serialized_chain_append(conn, table):
            yield
        return
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield
    except BaseException:
        try:
            conn.execute("ROLLBACK")
        except Exception:
            logger.exception("Failed to roll back %s chain prune", table)
        raise
    conn.execute("COMMIT")


def _delete_chain_prefix(conn, table: str, boundary_id: Optional[int]) -> int:
    """
    Delete one audit chain's id-prefix: every row below boundary_id, or every
    row when boundary_id is None (nothing is retained). Kept as a seam so
    tests can inject a failure between checkpoint write and deletion.
    """
    if boundary_id is None:
        cursor = conn.execute(f"DELETE FROM {table}")
    else:
        cursor = conn.execute(f"DELETE FROM {table} WHERE id < ?", (boundary_id,))
    return int(cursor.rowcount or 0)


def _prune_chain_with_checkpoint(
    conn,
    table: str,
    days: int,
    policy: Dict[str, int],
    actor: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    """
    Prune one audit hash chain, leaving a durable checkpoint.

    Deletes the contiguous id-prefix of rows older than the cutoff — never a
    mid-chain slice — so the retained chain has exactly one cut point. A
    backdated row sitting behind newer rows is kept until every row before it
    ages out; retention errs toward retaining rather than breaking the chain.

    Before deleting, writes an audit_chain_checkpoints row binding: the chain
    name, the last deleted row (id + integrity hash), the first retained row
    (id + its recorded prev hash; NULL/'' when nothing is retained), the
    deleted row count, the retention policy, the deletion timestamp, and the
    deletion actor/context. Checkpoints form their own hash chain (v3
    envelope), and chain verification anchors the retained walk at the newest
    checkpoint's last-deleted hash. Checkpoint + delete run in one
    transaction under the chain's serialization, so a failed prune leaves
    neither.
    """
    _validate_identifier(table)
    cutoff = (
        datetime.now(timezone.utc) - timedelta(days=max(1, int(days)))
    ).isoformat()
    with _chain_prune_transaction(conn, table):
        first_retained = conn.execute(
            f"SELECT id, prev_hash FROM {table} WHERE ts >= ? ORDER BY id ASC LIMIT 1",
            (cutoff,),
        ).fetchone()
        boundary_id = (
            int(row_value(first_retained, "id", 0)) if first_retained else None
        )
        if boundary_id is None:
            last_deleted = conn.execute(
                f"SELECT id, integrity_hash FROM {table} ORDER BY id DESC LIMIT 1"
            ).fetchone()
            count_row = conn.execute(f"SELECT COUNT(*) AS n FROM {table}").fetchone()
        else:
            last_deleted = conn.execute(
                f"SELECT id, integrity_hash FROM {table} WHERE id < ? "
                "ORDER BY id DESC LIMIT 1",
                (boundary_id,),
            ).fetchone()
            count_row = conn.execute(
                f"SELECT COUNT(*) AS n FROM {table} WHERE id < ?",
                (boundary_id,),
            ).fetchone()
        to_delete = int(row_value(count_row, "n", 0) or 0)
        if not last_deleted or to_delete <= 0:
            return {"deleted": 0, "checkpoint_id": None}

        previous_checkpoint = _latest_chain_checkpoint(conn, table)
        checkpoint_prev = (previous_checkpoint or {}).get("integrity_hash") or "GENESIS"
        checkpoint = {
            "chain": table,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "last_deleted_id": int(row_value(last_deleted, "id", 0)),
            "last_deleted_hash": row_value(last_deleted, "integrity_hash", 1) or "",
            "first_retained_id": boundary_id,
            "first_retained_prev_hash": (
                (row_value(first_retained, "prev_hash", 1) or "")
                if first_retained
                else ""
            ),
            "deleted_count": to_delete,
            "retention_policy": _json_dumps_object(policy),
            "actor": _json_dumps_object(actor or {}),
        }
        integrity_hash = audit_envelope.compute_hash_v3(
            "audit_chain_checkpoint", checkpoint, checkpoint_prev
        )
        checkpoint_id = _insert_returning_id(
            conn,
            """
            INSERT INTO audit_chain_checkpoints
              (chain, created_at, last_deleted_id, last_deleted_hash,
               first_retained_id, first_retained_prev_hash, deleted_count,
               retention_policy, actor, hash_v, prev_hash, integrity_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                checkpoint["chain"],
                checkpoint["created_at"],
                checkpoint["last_deleted_id"],
                checkpoint["last_deleted_hash"],
                checkpoint["first_retained_id"],
                checkpoint["first_retained_prev_hash"],
                checkpoint["deleted_count"],
                checkpoint["retention_policy"],
                checkpoint["actor"],
                audit_envelope.HASH_V3,
                checkpoint_prev,
                integrity_hash,
            ),
        )
        deleted = _delete_chain_prefix(conn, table, boundary_id)
    return {"deleted": deleted, "checkpoint_id": checkpoint_id}


def prune_retention(
    policy: Optional[Dict[str, int]] = None,
    actor: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    policy = policy or get_retention_policy()
    with _db_lock, get_conn() as conn:
        deleted_scan_history = _delete_older_than(
            conn, "scan_history", "ts", policy["scan_history_days"]
        )
        mcp_result = _prune_chain_with_checkpoint(
            conn, "mcp_audit_log", policy["mcp_audit_days"], policy, actor
        )
        admin_result = _prune_chain_with_checkpoint(
            conn, "admin_audit_log", policy["admin_audit_days"], policy, actor
        )
        deleted_usage = _delete_older_than(
            conn, "usage_log", "ts", policy["usage_log_days"]
        )
    return {
        "scan_history_deleted": deleted_scan_history,
        "mcp_audit_deleted": mcp_result["deleted"],
        "admin_audit_deleted": admin_result["deleted"],
        "usage_log_deleted": deleted_usage,
        "mcp_audit_checkpoint_id": mcp_result["checkpoint_id"],
        "admin_audit_checkpoint_id": admin_result["checkpoint_id"],
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


def _is_loopback_host(host: str) -> bool:
    return host in {"localhost", "127.0.0.1", "::1"}


def _is_public_mock_host(host: str) -> bool:
    return any(host.endswith(suffix) for suffix in PUBLIC_MOCK_HOST_SUFFIXES)


def _classify_mcp_server(row: Dict[str, Any]) -> Dict[str, Any]:
    d = dict(row or {})
    sid = str(d.get("server_id") or "").strip()
    description = str(d.get("description") or "")
    host = (urlparse(str(d.get("url") or "")).hostname or "").lower()
    lowered = f"{sid} {description}".lower()

    registry_class = "operator_registered"
    registry_note = "Operator-registered MCP server."
    demo_visible = True

    if (
        sid in KNOWN_UNAPPROVED_EXTERNAL_SERVER_IDS
        or host in KNOWN_UNAPPROVED_EXTERNAL_HOSTS
    ):
        registry_class = "external_unapproved"
        registry_note = "Known third-party server not owned by the Interlock demo."
        demo_visible = False
    elif sid in INTENDED_DEMO_SERVER_IDS:
        registry_class = "intended_demo"
        registry_note = "Buyer-facing Interlock demo server."
    elif is_fixture_mcp_server_id(sid) or sid.startswith("_"):
        registry_class = "disposable_fixture"
        registry_note = "Disposable test or matrix fixture."
        demo_visible = False
    elif _is_loopback_host(host) and any(
        token in lowered for token in ("test", "fixture", "probe", "matrix", "mock")
    ):
        registry_class = "disposable_fixture"
        registry_note = "Loopback-only proof or test server."
        demo_visible = False
    elif _is_loopback_host(host) and sid not in SEEDED_DEMO_SERVER_IDS:
        registry_class = "disposable_fixture"
        registry_note = "Loopback-only local fixture."
        demo_visible = False

    d["registry_class"] = registry_class
    d["registry_note"] = registry_note
    d["demo_visible"] = demo_visible
    return d


def canonicalize_mcp_tool_record(tool: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    d = dict(tool or {})
    metadata = d.get("normalized_metadata") or {}
    if isinstance(metadata, dict):
        for key in (
            "effects",
            "side_effect",
            "data_classes",
            "externality",
            "identity_mode",
            "required_scopes",
            "verification_level",
            "confidence",
            "warnings",
            "source",
            "inferred",
        ):
            if d.get(key) in (None, "", []):
                value = metadata.get(key)
                if value not in (None, ""):
                    d[key] = copy.deepcopy(value)

    raw_definition = d.get("raw_tool_definition") or {}
    if isinstance(raw_definition, dict) and not d.get("description"):
        d["description"] = raw_definition.get("description") or ""

    status = d.get("status") or "active"
    severity = d.get("drift_severity") or "none"
    action = d.get("drift_action") or "allow"

    if severity == "critical":
        status = "quarantined"
        action = "quarantine"
    elif severity == "high" and action == "allow":
        action = "deny"
    elif severity in {"minor", "moderate"} and action == "allow":
        action = "monitor"

    if status == "quarantined":
        action = "quarantine"
        if severity == "none":
            severity = "critical"
    elif status == "changed" and action == "allow":
        action = "monitor"
        if severity == "none":
            severity = "minor"
    elif status == "active" and action == "quarantine":
        status = "quarantined"
        if severity == "none":
            severity = "critical"
    elif status == "active" and action in {"deny", "monitor"}:
        status = "changed"
        if severity == "none":
            severity = "high" if action == "deny" else "minor"

    d["status"] = status
    d["drift_severity"] = severity
    d["drift_action"] = action
    return d


def _annotate_mcp_tools_with_server_registry(
    tools: List[Dict[str, Any]], *, demo_visible_only: bool = False
) -> List[Dict[str, Any]]:
    server_ids = sorted(
        {str(tool.get("server_id") or "") for tool in tools if tool.get("server_id")}
    )
    server_lookup = {sid: lookup_mcp_server(sid) or {} for sid in server_ids}
    annotated: List[Dict[str, Any]] = []

    for tool in tools:
        row = dict(tool)
        server = server_lookup.get(str(row.get("server_id") or "")) or {}
        row["server_registry_class"] = (
            server.get("registry_class") or "operator_registered"
        )
        row["server_registry_note"] = server.get("registry_note") or ""
        row["server_demo_visible"] = bool(server.get("demo_visible", True))
        if not demo_visible_only or row["server_demo_visible"]:
            annotated.append(row)
    return annotated


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
    d["environment"] = str(d.get("environment") or "production")
    d["probes_enabled"] = bool(d.get("probes_enabled", 0))
    return _classify_mcp_server(d)


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
    return canonicalize_mcp_tool_record(d)


def _mcp_response_profile_row_to_dict(row) -> Dict[str, Any]:
    d = dict(row)
    raw = d.get("profile_json")
    if isinstance(raw, dict):
        d["profile"] = raw
    else:
        try:
            d["profile"] = json.loads(raw or "{}")
        except (json.JSONDecodeError, TypeError):
            d["profile"] = {}
    d.pop("profile_json", None)
    return d


def _mcp_external_reach_profile_row_to_dict(row) -> Dict[str, Any]:
    d = dict(row)
    raw = d.get("profile_json")
    if isinstance(raw, dict):
        d["profile"] = raw
    else:
        try:
            d["profile"] = json.loads(raw or "{}")
        except (json.JSONDecodeError, TypeError):
            d["profile"] = {}
    d.pop("profile_json", None)
    return d


def _mcp_effect_profile_row_to_dict(row) -> Dict[str, Any]:
    d = dict(row)
    raw = d.get("profile_json")
    if isinstance(raw, dict):
        d["profile"] = raw
    else:
        try:
            d["profile"] = json.loads(raw or "{}")
        except (json.JSONDecodeError, TypeError):
            d["profile"] = {}
    d.pop("profile_json", None)
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
    if isinstance(raw, (str, bytes, bytearray)):
        try:
            d["last_finding_types"] = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            d["last_finding_types"] = []
    else:
        d["last_finding_types"] = []
    return d


def _normalize_mcp_server_environment(environment: Any) -> str:
    value = str(environment or "production").strip().lower()
    if value not in MCP_SERVER_ENVIRONMENTS:
        raise ValueError(
            f"Unknown MCP server environment '{environment}'. "
            f"Valid: {sorted(MCP_SERVER_ENVIRONMENTS)}"
        )
    return value


def register_mcp_server(server_id: str, config: dict) -> bool:
    """Insert a new MCP server. Returns False if server_id already exists."""
    validate_mcp_registration_target(server_id, str(config.get("url") or ""))
    environment = _normalize_mcp_server_environment(config.get("environment"))
    probes_enabled = bool(config.get("probes_enabled"))
    try:
        with _db_lock, get_conn() as conn:
            conn.execute(
                """
                INSERT INTO mcp_servers
                  (server_id, url, description, allowed_tools, blocked_tools,
                   rate_limit, auth_type, auth_header, auth_token_env, verified,
                   environment, probes_enabled, registered_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                    environment,
                    probes_enabled,
                    datetime.now(timezone.utc).isoformat(),
                ),
            )
        logger.info("Registered MCP server: %s", server_id)
        return True
    except Exception as e:
        if _is_integrity_error(e):
            return False
        raise


def set_mcp_server_environment(
    server_id: str, environment: str, probes_enabled: bool
) -> bool:
    """Persist the probe-authorization state for a server. Admin-only path;
    the runtime probe gate reads this instead of any request flag."""
    normalized = _normalize_mcp_server_environment(environment)
    with _db_lock, get_conn() as conn:
        cursor = conn.execute(
            "UPDATE mcp_servers SET environment = ?, probes_enabled = ? WHERE server_id = ?",
            (normalized, bool(probes_enabled), server_id),
        )
    return cursor.rowcount > 0


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


def list_mcp_servers(
    limit: Optional[int] = None, *, demo_visible_only: bool = False
) -> List[Dict[str, Any]]:
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
    servers = [_mcp_row_to_dict(r) for r in rows]
    if demo_visible_only:
        servers = [server for server in servers if server.get("demo_visible", True)]
    return servers


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
    """Delete a server from the registry. Returns False if not found.

    Server-lifecycle writer: serialize with candidate staging, active-surface
    writers, and promotion so a parent-row delete cannot interleave with the
    promotion transaction's candidate/history/audit writes.
    """
    with (
        _db_lock,
        get_conn() as conn,
        _rebaseline_transaction(conn, server_id),
    ):
        cursor = conn.execute(
            "DELETE FROM mcp_servers WHERE server_id = ?",
            (server_id,),
        )
    return cursor.rowcount > 0


def clear_mcp_tool_metadata(server_id: str) -> int:
    """Delete only stored tool baselines for an MCP server.

    Row-set writer: participates in the per-server rebaseline serialization
    domain so it can never interleave inside an in-flight promotion.
    """
    with (
        _db_lock,
        get_conn() as conn,
        _rebaseline_transaction(conn, server_id),
    ):
        cursor = conn.execute(
            "DELETE FROM mcp_tool_metadata WHERE server_id = ?",
            (server_id,),
        )
    return int(cursor.rowcount or 0)


def verify_mcp_server(server_id: str) -> bool:
    """Mark a server as verified. Returns False if server_id not found."""
    with _db_lock, get_conn() as conn:
        cursor = conn.execute(
            "UPDATE mcp_servers SET verified = TRUE WHERE server_id = ?",
            (server_id,),
        )
    return cursor.rowcount > 0


# ── MCP rebaseline: candidate staging, CAS approval, atomic promote ──────────
#
# Invariants this section enforces:
#   * Discovery only writes mcp_rebaseline_candidates — the active baseline in
#     mcp_tool_metadata is NEVER mutated by candidate creation.
#   * Promotion is compare-and-swap: both the active-baseline surface hash the
#     reviewer saw and the exact candidate hash they reviewed are re-read and
#     compared inside the final transaction; either differing rejects.
#   * Promotion is atomic: history snapshot, metadata replacement, candidate
#     consumption, and the audit-chain evidence row commit together or not at
#     all (SQLite: BEGIN IMMEDIATE under _db_lock; Postgres: per-server
#     advisory xact lock, plus the audit chain's lock for the evidence row).
#   * ONE serialization domain: every writer that can move CAS state takes the
#     same per-server lock — candidate staging (save_rebaseline_candidate) and
#     the active-surface writers (upsert_mcp_tool_metadata,
#     clear_mcp_tool_metadata, _replace_tool_metadata_from_candidate), plus
#     the server-lifecycle delete (unregister_mcp_server). A discovery or
#     unregister landing during an in-flight promote therefore WAITS and
#     applies after it, instead of interleaving inside it. Status-only writers
#     (approve/quarantine/mark_*) also share the lock: although they do not
#     change the hashed surface, promotion deletes and reinserts their rows,
#     so an unlocked status update could report success and then be lost.
#   * Promotion consumes the candidate defensively: DELETE keyed on server_id
#     AND candidate_surface_hash, requiring exactly one affected row — if the
#     reviewed row vanished or was replaced anyway, the whole transaction
#     rolls back and the caller gets stale_rebaseline_state with the CURRENT
#     hashes. A newer candidate can never be silently destroyed.


class _RebaselineCandidateRace(Exception):
    """The reviewed candidate row vanished or was replaced mid-promote."""


def _rebaseline_lock_key(server_id: str) -> int:
    """Stable signed-64-bit advisory-lock key for one server's rebaseline."""
    digest = hashlib.sha256(f"interlock:rebaseline:{server_id}".encode()).digest()
    return int.from_bytes(digest[:8], "big", signed=True)


@contextmanager
def _rebaseline_transaction(conn, server_id: str):
    """
    One atomic rebaseline promote per server.

    Postgres: explicit transaction + transaction-scoped advisory lock keyed
    on the server, so two replicas cannot interleave promote steps; the lock
    releases at COMMIT/ROLLBACK. SQLite: callers hold _db_lock; BEGIN
    IMMEDIATE makes the multi-statement promote roll back as a unit.
    """
    if _is_postgres_conn(conn):
        conn.execute("BEGIN")
        try:
            conn.execute(
                "SELECT pg_advisory_xact_lock(?)", (_rebaseline_lock_key(server_id),)
            )
            yield
        except BaseException:
            try:
                conn.execute("ROLLBACK")
            except Exception:
                logger.exception("Failed to roll back %s rebaseline", server_id)
            raise
        conn.execute("COMMIT")
        return
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield
    except BaseException:
        try:
            conn.execute("ROLLBACK")
        except Exception:
            logger.exception("Failed to roll back %s rebaseline", server_id)
        raise
    conn.execute("COMMIT")


def _active_baseline_from_conn(conn, server_id: str) -> Dict[str, Any]:
    """The server's exact live persisted rebaseline content and hash."""
    rows = conn.execute(
        "SELECT raw_tool_definition, normalized_metadata FROM mcp_tool_metadata "
        "WHERE server_id = ? ORDER BY tool_name",
        (server_id,),
    ).fetchall()
    validated_tools = []
    for row in rows:
        raw_tool = row_value(row, "raw_tool_definition", 0) or "{}"
        raw_metadata = row_value(row, "normalized_metadata", 1) or "{}"
        try:
            tool = json.loads(raw_tool)
        except (json.JSONDecodeError, TypeError):
            tool = {}
        try:
            normalized_metadata = json.loads(raw_metadata)
        except (json.JSONDecodeError, TypeError):
            normalized_metadata = {}
        validated_tools.append(
            {"tool": tool, "normalized_metadata": normalized_metadata}
        )
    return {
        "server_id": server_id,
        "surface_hash": drift_evidence.rebaseline_content_hash(validated_tools),
        "canonical_surface": drift_evidence.rebaseline_content_canonical_json(
            validated_tools
        ),
        "tool_count": len(validated_tools),
    }


def get_active_baseline(server_id: str) -> Dict[str, Any]:
    """Surface hash + canonical form of a server's current active baseline."""
    with get_conn() as conn:
        return _active_baseline_from_conn(conn, server_id)


def _baseline_versions_from_conn(
    conn, server_id: str, limit: int = 100
) -> List[Dict[str, Any]]:
    rows = conn.execute(
        "SELECT * FROM mcp_baseline_versions WHERE server_id = ? "
        "ORDER BY version ASC LIMIT ?",
        (server_id, int(limit)),
    ).fetchall()
    return [row_to_plain_dict(row) for row in rows]


def get_rebaseline_review_snapshot(server_id: str, limit: int = 100) -> Dict[str, Any]:
    """Return one coherent reviewer view under the server's lock domain."""
    with (
        _db_lock,
        get_conn() as conn,
        _rebaseline_transaction(conn, server_id),
    ):
        server = conn.execute(
            "SELECT server_id FROM mcp_servers WHERE server_id = ?",
            (server_id,),
        ).fetchone()
        if server is None:
            return {
                "ok": False,
                "error": "server_not_found",
                "server_id": server_id,
            }
        return {
            "ok": True,
            "server_id": server_id,
            "active": _active_baseline_from_conn(conn, server_id),
            "candidate": _rebaseline_candidate_from_conn(conn, server_id),
            "versions": _baseline_versions_from_conn(conn, server_id, limit),
        }


def save_rebaseline_candidate(
    server_id: str,
    validated_tools: List[Dict[str, Any]],
    created_by: str = "",
) -> Dict[str, Any]:
    """
    Stage one validated discovery result as the server's rebaseline
    candidate, replacing any prior candidate. ``validated_tools`` is a list
    of {"tool": <raw definition>, "normalized_metadata": <validator output>}
    — the complete surface, already validated by the caller. Never touches
    mcp_tool_metadata.
    """
    assert_not_production_fixture_write(server_id, "MCP rebaseline candidate")
    validated_tools = validated_tools or []
    canonical_surface = drift_evidence.rebaseline_content_canonical_json(
        validated_tools
    )
    candidate_surface_hash = drift_evidence.rebaseline_content_hash(validated_tools)
    now = datetime.now(timezone.utc).isoformat()
    # Staging shares the promote's serialization domain: a discovery landing
    # while an approval is mid-transaction waits for it instead of writing a
    # candidate row the promote would then consume.
    with (
        _db_lock,
        get_conn() as conn,
        _rebaseline_transaction(conn, server_id),
    ):
        server = conn.execute(
            "SELECT server_id FROM mcp_servers WHERE server_id = ?",
            (server_id,),
        ).fetchone()
        if server is None:
            return {
                "ok": False,
                "error": "server_not_found",
                "server_id": server_id,
            }
        active = _active_baseline_from_conn(conn, server_id)
        conn.execute(
            """
            INSERT INTO mcp_rebaseline_candidates
              (server_id, candidate_surface_hash, canonical_surface, tools_json,
               tool_count, created_at, created_by)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT (server_id) DO UPDATE SET
              candidate_surface_hash = excluded.candidate_surface_hash,
              canonical_surface = excluded.canonical_surface,
              tools_json = excluded.tools_json,
              tool_count = excluded.tool_count,
              created_at = excluded.created_at,
              created_by = excluded.created_by
            """,
            (
                server_id,
                candidate_surface_hash,
                canonical_surface,
                json.dumps(validated_tools),
                len(validated_tools),
                now,
                created_by or "",
            ),
        )
    return {
        "server_id": server_id,
        "candidate_surface_hash": candidate_surface_hash,
        "canonical_surface": canonical_surface,
        "tool_count": len(validated_tools),
        "created_at": now,
        "created_by": created_by or "",
        "active_surface_hash": active["surface_hash"],
    }


def _rebaseline_candidate_from_conn(conn, server_id: str) -> Optional[Dict[str, Any]]:
    row = conn.execute(
        "SELECT * FROM mcp_rebaseline_candidates WHERE server_id = ?",
        (server_id,),
    ).fetchone()
    if not row:
        return None
    candidate = row_to_plain_dict(row)
    try:
        candidate["validated_tools"] = json.loads(candidate.get("tools_json") or "[]")
    except (json.JSONDecodeError, TypeError):
        candidate["validated_tools"] = []
    candidate.pop("tools_json", None)
    return candidate


def get_rebaseline_candidate(server_id: str) -> Optional[Dict[str, Any]]:
    """The server's staged rebaseline candidate, or None."""
    with get_conn() as conn:
        return _rebaseline_candidate_from_conn(conn, server_id)


def list_baseline_versions(server_id: str, limit: int = 100) -> List[Dict[str, Any]]:
    """A server's baseline version history, oldest first."""
    with get_conn() as conn:
        return _baseline_versions_from_conn(conn, server_id, limit)


def _replace_tool_metadata_from_candidate(
    conn, server_id: str, candidate: Dict[str, Any]
) -> int:
    """
    Swap the server's stored tool metadata for the candidate's tools — fresh
    active rows, drift state reset. Runs inside the promote transaction;
    kept as a seam so tests can inject a failure between the history write
    and the swap.
    """
    conn.execute("DELETE FROM mcp_tool_metadata WHERE server_id = ?", (server_id,))
    now = datetime.now(timezone.utc).isoformat()
    inserted = 0
    for entry in candidate.get("validated_tools") or []:
        tool = entry.get("tool") or {}
        normalized_metadata = entry.get("normalized_metadata") or {}
        schema = tool.get("inputSchema", {}) or tool.get("input_schema", {}) or {}
        conn.execute(
            """
            INSERT INTO mcp_tool_metadata
              (server_id, tool_name, tool_schema_hash, description_hash,
               normalized_metadata, raw_annotations, raw_tool_definition,
               first_seen, last_seen, last_changed, status, drift_severity,
               drift_action, drift_types, drift_reasons, previous_metadata,
               previous_tool_definition)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', 'none', 'allow',
                    '[]', '[]', '{}', '{}')
            """,
            (
                server_id,
                str(tool.get("name") or "").strip(),
                _hash_json(schema),
                _hash_text(tool.get("description", "")),
                json.dumps(normalized_metadata),
                json.dumps(tool.get("annotations") or {}),
                json.dumps(tool),
                now,
                now,
                None,
            ),
        )
        inserted += 1
    return inserted


def promote_rebaseline_candidate(
    server_id: str,
    expected_current_hash: str,
    expected_candidate_hash: str,
    actor: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Atomically promote the staged candidate to the active baseline.

    Compare-and-swap: ``expected_current_hash`` (the active baseline the
    reviewer saw) and ``expected_candidate_hash`` (the exact candidate they
    reviewed) are re-read and compared inside the transaction; if either
    differs — the baseline moved, or a newer discovery replaced the
    candidate — nothing changes and the CURRENT hashes are returned so the
    caller can re-review (HTTP 409 at the route).

    On success, in one transaction: the outgoing active baseline is
    preserved in immutable version history, the candidate's tools replace
    mcp_tool_metadata (fresh active rows), the candidate is consumed, an
    audit-chain evidence row is appended, and the new version row records
    that audit id.
    """
    assert_not_production_fixture_write(server_id, "MCP rebaseline promote")
    actor = actor or {}
    with _db_lock, get_conn() as conn:
        try:
            return _promote_rebaseline_candidate_locked(
                conn, server_id, expected_current_hash, expected_candidate_hash, actor
            )
        except _RebaselineCandidateRace:
            # The reviewed candidate row vanished or was replaced despite the
            # CAS read — the transaction rolled back; report the CURRENT
            # hashes (read directly, post-rollback) so the caller re-reviews.
            active = _active_baseline_from_conn(conn, server_id)
            row = conn.execute(
                "SELECT candidate_surface_hash FROM mcp_rebaseline_candidates "
                "WHERE server_id = ?",
                (server_id,),
            ).fetchone()
            return {
                "ok": False,
                "error": "stale_rebaseline_state",
                "active_surface_hash": active["surface_hash"],
                "candidate_surface_hash": (
                    row_value(row, "candidate_surface_hash", 0) if row else None
                ),
            }


def _promote_rebaseline_candidate_locked(
    conn,
    server_id: str,
    expected_current_hash: str,
    expected_candidate_hash: str,
    actor: Dict[str, Any],
) -> Dict[str, Any]:
    with _rebaseline_transaction(conn, server_id):
        server = conn.execute(
            "SELECT server_id FROM mcp_servers WHERE server_id = ?",
            (server_id,),
        ).fetchone()
        if server is None:
            return {
                "ok": False,
                "error": "server_not_found",
                "active_surface_hash": None,
                "candidate_surface_hash": None,
            }
        if _is_postgres_conn(conn):
            # The evidence row extends the audit chain tip; take the
            # chain's advisory lock inside THIS transaction (nesting
            # _serialized_chain_append would BEGIN/COMMIT its own).
            conn.execute(
                "SELECT pg_advisory_xact_lock(?)",
                (_audit_chain_lock_key("mcp_audit_log"),),
            )
        active = _active_baseline_from_conn(conn, server_id)
        candidate = _rebaseline_candidate_from_conn(conn, server_id)
        if candidate is None:
            return {
                "ok": False,
                "error": "no_candidate",
                "active_surface_hash": active["surface_hash"],
                "candidate_surface_hash": None,
            }
        if (expected_current_hash or "") != active["surface_hash"] or (
            expected_candidate_hash or ""
        ) != candidate["candidate_surface_hash"]:
            return {
                "ok": False,
                "error": "stale_rebaseline_state",
                "active_surface_hash": active["surface_hash"],
                "candidate_surface_hash": candidate["candidate_surface_hash"],
            }

        # Consume EXACTLY the reviewed candidate, defensively: keyed on the
        # hash as well as the server, and requiring exactly one affected
        # row. If the row vanished or was replaced anyway, roll back the
        # whole transaction — a newer candidate must never be destroyed by
        # the promotion of an older one.
        consumed = conn.execute(
            "DELETE FROM mcp_rebaseline_candidates "
            "WHERE server_id = ? AND candidate_surface_hash = ?",
            (server_id, candidate["candidate_surface_hash"]),
        )
        if int(consumed.rowcount or 0) != 1:
            raise _RebaselineCandidateRace()

        now = datetime.now(timezone.utc).isoformat()
        current_version = conn.execute(
            "SELECT id, version FROM mcp_baseline_versions "
            "WHERE server_id = ? AND replaced_at IS NULL",
            (server_id,),
        ).fetchone()
        max_row = conn.execute(
            "SELECT COALESCE(MAX(version), 0) AS v FROM mcp_baseline_versions "
            "WHERE server_id = ?",
            (server_id,),
        ).fetchone()
        max_version = int(row_value(max_row, "v", 0) or 0)
        if current_version is not None:
            previous_version = int(row_value(current_version, "version", 1))
            conn.execute(
                "UPDATE mcp_baseline_versions SET replaced_at = ? WHERE id = ?",
                (now, int(row_value(current_version, "id", 0))),
            )
        else:
            # Legacy bootstrap: this baseline predates version history —
            # preserve it as a closed version row before replacing it.
            previous_version = max_version + 1
            max_version = previous_version
            conn.execute(
                """
                INSERT INTO mcp_baseline_versions
                  (server_id, version, surface_hash, canonical_surface,
                   promoted_at, replaced_at, approval_audit_id, approved_by)
                VALUES (?, ?, ?, ?, ?, ?, NULL, '')
                """,
                (
                    server_id,
                    previous_version,
                    active["surface_hash"],
                    active["canonical_surface"],
                    now,
                    now,
                ),
            )

        replaced_tools = _replace_tool_metadata_from_candidate(
            conn, server_id, candidate
        )
        saved_audit = _append_mcp_audit_event(
            conn,
            {
                "server_id": server_id,
                "tool_name": "",
                "role": actor.get("reviewer", "") or "operator",
                "principal_id": actor.get("principal_id", "") or "",
                "action": "rebaseline",
                "matched_rule": "rebaseline_promoted",
                "reason": (
                    f"Rebaseline promoted candidate "
                    f"{candidate['candidate_surface_hash']} over active "
                    f"{active['surface_hash']} "
                    f"({candidate['tool_count']} tools)."
                ),
                "verification_level": "manual",
                "confidence": 1.0,
                "drift_baseline_hash": active["surface_hash"],
                "drift_current_hash": candidate["candidate_surface_hash"],
            },
        )
        new_version = max_version + 1
        conn.execute(
            """
            INSERT INTO mcp_baseline_versions
              (server_id, version, surface_hash, canonical_surface,
               promoted_at, replaced_at, approval_audit_id, approved_by)
            VALUES (?, ?, ?, ?, ?, NULL, ?, ?)
            """,
            (
                server_id,
                new_version,
                candidate["candidate_surface_hash"],
                candidate["canonical_surface"],
                now,
                saved_audit["id"],
                actor.get("reviewer", "") or "",
            ),
        )
        return {
            "ok": True,
            "server_id": server_id,
            "version": new_version,
            "previous_version": previous_version,
            "old_surface_hash": active["surface_hash"],
            "new_surface_hash": candidate["candidate_surface_hash"],
            "tool_count": candidate["tool_count"],
            "replaced_tools": replaced_tools,
            "audit": {
                "audit_id": saved_audit["id"],
                "call_id": saved_audit["call_id"],
            },
        }


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
    assert_not_production_fixture_write(server_id, "MCP tool metadata upsert")
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

    # Active-surface writer: serialize with rebaseline promotion per server,
    # so an ordinary discovery cannot mutate the surface INSIDE an in-flight
    # approval (it waits and applies on top of the new baseline instead).
    with (
        _db_lock,
        get_conn() as conn,
        _rebaseline_transaction(conn, server_id),
    ):
        server = conn.execute(
            "SELECT server_id FROM mcp_servers WHERE server_id = ?",
            (server_id,),
        ).fetchone()
        if server is None:
            return {
                "ok": False,
                "error": "server_not_found",
                "server_id": server_id,
                "tool_name": tool_name,
            }
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


def rederive_mcp_tool_metadata(
    server_id: str, tool_name: str, *, dry_run: bool = False
) -> Dict[str, Any]:
    """Recompute metadata from the current raw tool while holding its server lock."""
    assert_not_production_fixture_write(server_id, "MCP metadata rederivation")
    with (
        _db_lock,
        get_conn() as conn,
        _rebaseline_transaction(conn, server_id),
    ):
        server = conn.execute(
            "SELECT server_id FROM mcp_servers WHERE server_id = ?",
            (server_id,),
        ).fetchone()
        if server is None:
            return {
                "ok": False,
                "outcome": "not_found",
                "error": "server_not_found",
                "server_id": server_id,
                "tool_name": tool_name,
            }

        row = conn.execute(
            "SELECT raw_tool_definition, normalized_metadata "
            "FROM mcp_tool_metadata WHERE server_id = ? AND tool_name = ?",
            (server_id, tool_name),
        ).fetchone()
        if row is None:
            return {
                "ok": False,
                "outcome": "not_found",
                "error": "tool_not_found",
                "server_id": server_id,
                "tool_name": tool_name,
            }

        raw_tool_value = row_value(row, "raw_tool_definition", 0)
        raw_metadata_value = row_value(row, "normalized_metadata", 1)
        try:
            raw_tool = (
                dict(raw_tool_value)
                if isinstance(raw_tool_value, dict)
                else json.loads(raw_tool_value)
            )
        except (json.JSONDecodeError, TypeError, ValueError):
            raw_tool = None
        if not isinstance(raw_tool, dict):
            return {
                "ok": False,
                "outcome": "corrupt",
                "error": "corrupt_raw_tool_definition",
                "server_id": server_id,
                "tool_name": tool_name,
            }

        try:
            old_metadata = (
                dict(raw_metadata_value)
                if isinstance(raw_metadata_value, dict)
                else json.loads(raw_metadata_value)
            )
        except (json.JSONDecodeError, TypeError, ValueError):
            old_metadata = None
        if not isinstance(old_metadata, dict):
            return {
                "ok": False,
                "outcome": "corrupt",
                "error": "corrupt_normalized_metadata",
                "server_id": server_id,
                "tool_name": tool_name,
            }

        try:
            new_metadata = normalize_tool_metadata(raw_tool)
        except Exception:
            logger.exception(
                "Failed to rederive MCP metadata for %s/%s", server_id, tool_name
            )
            return {
                "ok": False,
                "outcome": "corrupt",
                "error": "metadata_derivation_failed",
                "server_id": server_id,
                "tool_name": tool_name,
            }

        changed = old_metadata != new_metadata
        applied = False
        if changed and not dry_run:
            cursor = conn.execute(
                "UPDATE mcp_tool_metadata SET normalized_metadata = ? "
                "WHERE server_id = ? AND tool_name = ?",
                (json.dumps(new_metadata, sort_keys=True), server_id, tool_name),
            )
            if int(cursor.rowcount or 0) != 1:
                return {
                    "ok": False,
                    "outcome": "not_found",
                    "error": "tool_not_found",
                    "server_id": server_id,
                    "tool_name": tool_name,
                }
            applied = True

        return {
            "ok": True,
            "outcome": "changed" if changed else "unchanged",
            "server_id": server_id,
            "tool_name": tool_name,
            "changed": changed,
            "applied": applied,
            "old_metadata": old_metadata,
            "new_metadata": new_metadata,
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
    if not row:
        return None
    tool = _mcp_tool_metadata_row_to_dict(row)
    annotated = _annotate_mcp_tools_with_server_registry([tool])
    return annotated[0] if annotated else tool


def list_mcp_tool_metadata(
    server_id: Optional[str] = None,
    limit: Optional[int] = None,
    *,
    demo_visible_only: bool = False,
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
    tools = [_mcp_tool_metadata_row_to_dict(r) for r in rows]
    return _annotate_mcp_tools_with_server_registry(
        tools, demo_visible_only=demo_visible_only
    )


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

    with (
        _db_lock,
        get_conn() as conn,
        _rebaseline_transaction(conn, server_id),
    ):
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

    with (
        _db_lock,
        get_conn() as conn,
        _rebaseline_transaction(conn, server_id),
    ):
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

    with (
        _db_lock,
        get_conn() as conn,
        _rebaseline_transaction(conn, server_id),
    ):
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
    server_id: Optional[str] = None,
    limit: Optional[int] = None,
    *,
    demo_visible_only: bool = False,
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
    tools = [_mcp_tool_metadata_row_to_dict(r) for r in rows]
    return _annotate_mcp_tools_with_server_registry(
        tools, demo_visible_only=demo_visible_only
    )


def approve_mcp_tool_baseline(
    server_id: str,
    tool_name: str,
    reviewer: str = "operator",
    reason: str = "",
    principal_id: str = "",
) -> Dict[str, Any]:
    """Approve the current stored MCP tool definition as the new trusted baseline."""
    reviewer = reviewer or "operator"
    reason = reason or "Approved current MCP tool definition as the new baseline."
    t0 = time.perf_counter()

    with (
        _db_lock,
        get_conn() as conn,
        _rebaseline_transaction(conn, server_id),
    ):
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
            "principal_id": principal_id,
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
    principal_id: str = "",
) -> Dict[str, Any]:
    """Keep or mark an MCP tool quarantined until an operator approves a new baseline."""
    reviewer = reviewer or "operator"
    reason = reason or "Operator kept this MCP tool quarantined pending review."
    t0 = time.perf_counter()

    with (
        _db_lock,
        get_conn() as conn,
        _rebaseline_transaction(conn, server_id),
    ):
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
            "principal_id": principal_id,
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


def upsert_mcp_response_profile(
    server_id: str, tool_name: str, profile: Dict[str, Any]
) -> Dict[str, Any]:
    """Store the approved response exposure profile for a server/tool.

    ``profile`` must already be evidence-safe: no raw response bodies or raw
    values. The response_drift module builds this shape.
    """
    profile = dict(profile or {})
    profile_hash = str(profile.get("profile_hash") or "")
    now = datetime.now(timezone.utc).isoformat()
    with _db_lock, get_conn() as conn:
        existing = conn.execute(
            """
            SELECT first_seen FROM mcp_response_profiles
             WHERE server_id = ? AND tool_name = ?
            """,
            (server_id, tool_name),
        ).fetchone()
        first_seen = row_value(existing, "first_seen", 0) if existing else now
        if existing:
            conn.execute(
                """
                UPDATE mcp_response_profiles
                   SET profile_hash = ?,
                       profile_json = ?,
                       last_seen = ?,
                       updated_at = ?,
                       status = 'approved'
                 WHERE server_id = ? AND tool_name = ?
                """,
                (
                    profile_hash,
                    json.dumps(profile, sort_keys=True),
                    now,
                    now,
                    server_id,
                    tool_name,
                ),
            )
        else:
            conn.execute(
                """
                INSERT INTO mcp_response_profiles
                  (server_id, tool_name, profile_hash, profile_json,
                   first_seen, last_seen, updated_at, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, 'approved')
                """,
                (
                    server_id,
                    tool_name,
                    profile_hash,
                    json.dumps(profile, sort_keys=True),
                    first_seen,
                    now,
                    now,
                ),
            )
    return lookup_mcp_response_profile(server_id, tool_name) or {}


def lookup_mcp_response_profile(
    server_id: str, tool_name: str
) -> Optional[Dict[str, Any]]:
    """Return the approved response exposure profile for a server/tool."""
    with get_conn() as conn:
        row = conn.execute(
            """
            SELECT * FROM mcp_response_profiles
             WHERE server_id = ? AND tool_name = ?
            """,
            (server_id, tool_name),
        ).fetchone()
    return _mcp_response_profile_row_to_dict(row) if row else None


def upsert_mcp_external_reach_profile(
    server_id: str, tool_name: str, profile: Dict[str, Any]
) -> Dict[str, Any]:
    """Store the approved external destination profile for a server/tool.

    ``profile`` must be evidence-safe: URL hosts and email domains are kept,
    but raw URLs, paths, email local-parts, channels, buckets, and tokens are
    never stored. The external_reach module builds this shape.
    """
    profile = dict(profile or {})
    profile_hash = str(profile.get("profile_hash") or "")
    now = datetime.now(timezone.utc).isoformat()
    with _db_lock, get_conn() as conn:
        existing = conn.execute(
            """
            SELECT first_seen FROM mcp_external_reach_profiles
             WHERE server_id = ? AND tool_name = ?
            """,
            (server_id, tool_name),
        ).fetchone()
        first_seen = row_value(existing, "first_seen", 0) if existing else now
        if existing:
            conn.execute(
                """
                UPDATE mcp_external_reach_profiles
                   SET profile_hash = ?,
                       profile_json = ?,
                       last_seen = ?,
                       updated_at = ?,
                       status = 'approved'
                 WHERE server_id = ? AND tool_name = ?
                """,
                (
                    profile_hash,
                    json.dumps(profile, sort_keys=True),
                    now,
                    now,
                    server_id,
                    tool_name,
                ),
            )
        else:
            conn.execute(
                """
                INSERT INTO mcp_external_reach_profiles
                  (server_id, tool_name, profile_hash, profile_json,
                   first_seen, last_seen, updated_at, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, 'approved')
                """,
                (
                    server_id,
                    tool_name,
                    profile_hash,
                    json.dumps(profile, sort_keys=True),
                    first_seen,
                    now,
                    now,
                ),
            )
    return lookup_mcp_external_reach_profile(server_id, tool_name) or {}


def lookup_mcp_external_reach_profile(
    server_id: str, tool_name: str
) -> Optional[Dict[str, Any]]:
    """Return the approved external destination profile for a server/tool."""
    with get_conn() as conn:
        row = conn.execute(
            """
            SELECT * FROM mcp_external_reach_profiles
             WHERE server_id = ? AND tool_name = ?
            """,
            (server_id, tool_name),
        ).fetchone()
    return _mcp_external_reach_profile_row_to_dict(row) if row else None


def mark_mcp_tool_external_reach_drift(
    server_id: str, tool_name: str, finding_types: List[str], reason: str = ""
) -> Dict[str, Any]:
    """Quarantine a known tool after critical destination/reach drift."""
    reason = reason or "External destination drift introduced critical reach expansion."
    now = datetime.now(timezone.utc).isoformat()
    with (
        _db_lock,
        get_conn() as conn,
        _rebaseline_transaction(conn, server_id),
    ):
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
            [*(current.get("drift_types") or []), *(finding_types or [])]
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


def upsert_mcp_effect_profile(
    server_id: str, tool_name: str, profile: Dict[str, Any]
) -> Dict[str, Any]:
    """Store the approved effect/outcome profile for a server/tool.

    ``profile`` must be evidence-safe: effect labels and shape only, never raw
    resource ids, response bodies, tokens, or provider payload values.
    """
    profile = dict(profile or {})
    profile_hash = str(profile.get("profile_hash") or "")
    now = datetime.now(timezone.utc).isoformat()
    with _db_lock, get_conn() as conn:
        existing = conn.execute(
            """
            SELECT first_seen FROM mcp_effect_profiles
             WHERE server_id = ? AND tool_name = ?
            """,
            (server_id, tool_name),
        ).fetchone()
        first_seen = row_value(existing, "first_seen", 0) if existing else now
        if existing:
            conn.execute(
                """
                UPDATE mcp_effect_profiles
                   SET profile_hash = ?,
                       profile_json = ?,
                       last_seen = ?,
                       updated_at = ?,
                       status = 'approved'
                 WHERE server_id = ? AND tool_name = ?
                """,
                (
                    profile_hash,
                    json.dumps(profile, sort_keys=True),
                    now,
                    now,
                    server_id,
                    tool_name,
                ),
            )
        else:
            conn.execute(
                """
                INSERT INTO mcp_effect_profiles
                  (server_id, tool_name, profile_hash, profile_json,
                   first_seen, last_seen, updated_at, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, 'approved')
                """,
                (
                    server_id,
                    tool_name,
                    profile_hash,
                    json.dumps(profile, sort_keys=True),
                    first_seen,
                    now,
                    now,
                ),
            )
    return lookup_mcp_effect_profile(server_id, tool_name) or {}


def lookup_mcp_effect_profile(
    server_id: str, tool_name: str
) -> Optional[Dict[str, Any]]:
    """Return the approved effect/outcome profile for a server/tool."""
    with get_conn() as conn:
        row = conn.execute(
            """
            SELECT * FROM mcp_effect_profiles
             WHERE server_id = ? AND tool_name = ?
            """,
            (server_id, tool_name),
        ).fetchone()
    return _mcp_effect_profile_row_to_dict(row) if row else None


def mark_mcp_tool_effect_drift(
    server_id: str, tool_name: str, finding_types: List[str], reason: str = ""
) -> Dict[str, Any]:
    """Quarantine a known tool after material effect/outcome drift."""
    reason = reason or "Observed effect drift introduced unexpected side effects."
    now = datetime.now(timezone.utc).isoformat()
    with (
        _db_lock,
        get_conn() as conn,
        _rebaseline_transaction(conn, server_id),
    ):
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
            [*(current.get("drift_types") or []), *(finding_types or [])]
        )
        drift_reasons = _unique_list([*(current.get("drift_reasons") or []), reason])
        conn.execute(
            """
            UPDATE mcp_tool_metadata
               SET status = 'quarantined',
                   drift_severity = ?,
                   drift_action = 'quarantine',
                   drift_types = ?,
                   drift_reasons = ?,
                   last_changed = COALESCE(last_changed, ?)
             WHERE server_id = ? AND tool_name = ?
            """,
            (
                (
                    "critical"
                    if any(
                        str(t).startswith("effect_destructive")
                        or str(t).startswith("effect_external")
                        or str(t).startswith("effect_money")
                        or str(t).startswith("effect_deploy")
                        or str(t).startswith("effect_execution")
                        or str(t).startswith("effect_temporal_external")
                        or str(t).startswith("effect_temporal_destructive")
                        or str(t).startswith("effect_temporal_deploy")
                        or str(t).startswith("effect_temporal_execution")
                        or str(t).startswith("effect_temporal_money")
                        or str(t).startswith("readback_")
                        or str(t) == "silent_side_effect_drift"
                        or str(t) == "effect_response_contradicted_by_readback"
                        for t in finding_types or []
                    )
                    else "high"
                ),
                json.dumps(drift_types),
                json.dumps(drift_reasons),
                now,
                server_id,
                tool_name,
            ),
        )

    updated = lookup_mcp_tool_metadata(server_id, tool_name) or {}
    return {"ok": True, **updated}


def mark_mcp_tool_response_drift(
    server_id: str, tool_name: str, finding_types: List[str], reason: str = ""
) -> Dict[str, Any]:
    """Quarantine a known tool after critical response/data-exposure drift."""
    reason = reason or "Response exposure drift introduced critical data exposure."
    now = datetime.now(timezone.utc).isoformat()
    with (
        _db_lock,
        get_conn() as conn,
        _rebaseline_transaction(conn, server_id),
    ):
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
            [*(current.get("drift_types") or []), *(finding_types or [])]
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


# ── MCP audit log ─────────────────────────────────────────────────────────────


def _append_mcp_audit_event(conn, event: dict) -> Dict[str, Any]:
    """
    Append one event to the mcp_audit_log hash chain on an EXISTING
    connection. The caller must already hold the chain's serialization
    (_db_lock + _serialized_chain_append, or an open transaction that took
    the chain's advisory lock on Postgres) — this lets an atomic operation
    like a rebaseline promote record its audit evidence inside the same
    transaction as the state change it evidences.
    """
    event = event or {}
    ts = event.get("ts") or datetime.now(timezone.utc).isoformat()
    call_id = str(event.get("call_id") or "") or uuid.uuid4().hex
    # The exact values inserted below, keyed by column, so the v3 envelope
    # hashes precisely what a verifier will read back from either backend.
    record = {
        "ts": ts,
        "server_id": event.get("server_id", ""),
        "tool_name": event.get("tool_name", ""),
        "principal_id": event.get("principal_id", "") or "",
        "role": event.get("role", "") or "",
        "action": event.get("action", ""),
        "matched_rule": event.get("matched_rule", ""),
        "reason": event.get("reason", ""),
        "effects": json.dumps(event.get("effects", []) or []),
        "side_effect": event.get("side_effect", "unknown"),
        "data_classes": json.dumps(event.get("data_classes", []) or []),
        "externality": event.get("externality", "unknown"),
        "verification_level": event.get("verification_level", "unknown"),
        # normalize_stored_float: what is hashed must be exactly what either
        # backend hands back — non-finite rejected, -0.0 folded to 0.0.
        "confidence": audit_envelope.normalize_stored_float(
            event.get("confidence"), 0.0
        ),
        "warnings": json.dumps(event.get("warnings", []) or []),
        "argument_keys": json.dumps(event.get("argument_keys", []) or []),
        "blocked_by": event.get("blocked_by", "") or "",
        "probe_id": event.get("probe_id", "") or "",
        "argument_hash": event.get("argument_hash", "") or "",
        "expected_outcome": event.get("expected_outcome", "") or "",
        # normalize_stored_int: optional codes stay NULL; non-integer inputs
        # are rejected before anything is hashed or written.
        "expected_status_code": audit_envelope.normalize_stored_int(
            event.get("expected_status_code")
        ),
        "observed_outcome": event.get("observed_outcome", "") or "",
        "observed_status_code": audit_envelope.normalize_stored_int(
            event.get("observed_status_code")
        ),
        "observed_error_class": event.get("observed_error_class", "") or "",
        "drift_status": event.get("drift_status", "") or "",
        "drift_severity": event.get("drift_severity", "none") or "none",
        "drift_action": event.get("drift_action", "allow") or "allow",
        "drift_types": json.dumps(event.get("drift_types", []) or []),
        "drift_reasons": json.dumps(event.get("drift_reasons", []) or []),
        "drift_baseline_hash": event.get("drift_baseline_hash", "") or "",
        "drift_current_hash": event.get("drift_current_hash", "") or "",
        "scan_time_ms": audit_envelope.normalize_stored_float(
            event.get("scan_time_ms")
        ),
        "call_id": call_id,
    }
    row = conn.execute(
        "SELECT integrity_hash FROM mcp_audit_log ORDER BY id DESC LIMIT 1"
    ).fetchone()
    if row is not None:
        prev_hash = (dict(row).get("integrity_hash") or "") or "GENESIS"
    else:
        # Empty table: continue from the retention checkpoint boundary
        # (if the chain was pruned away entirely) instead of GENESIS.
        latest = _latest_chain_checkpoint(conn, "mcp_audit_log")
        prev_hash = (latest or {}).get("last_deleted_hash") or "GENESIS"
    integrity_hash = audit_envelope.compute_hash_v3("mcp_audit_log", record, prev_hash)
    event_id = _insert_returning_id(
        conn,
        """
        INSERT INTO mcp_audit_log
          (ts, server_id, tool_name, principal_id, role, action, matched_rule, reason,
           effects, side_effect, data_classes, externality, verification_level,
           confidence, warnings, argument_keys, blocked_by, probe_id,
           argument_hash, expected_outcome, expected_status_code,
           observed_outcome, observed_status_code, observed_error_class,
           drift_status, drift_severity, drift_action, drift_types, drift_reasons,
           drift_baseline_hash, drift_current_hash,
           scan_time_ms, call_id, hash_v, prev_hash, integrity_hash)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            record["ts"],
            record["server_id"],
            record["tool_name"],
            record["principal_id"],
            record["role"],
            record["action"],
            record["matched_rule"],
            record["reason"],
            record["effects"],
            record["side_effect"],
            record["data_classes"],
            record["externality"],
            record["verification_level"],
            record["confidence"],
            record["warnings"],
            record["argument_keys"],
            record["blocked_by"],
            record["probe_id"],
            record["argument_hash"],
            record["expected_outcome"],
            record["expected_status_code"],
            record["observed_outcome"],
            record["observed_status_code"],
            record["observed_error_class"],
            record["drift_status"],
            record["drift_severity"],
            record["drift_action"],
            record["drift_types"],
            record["drift_reasons"],
            record["drift_baseline_hash"],
            record["drift_current_hash"],
            record["scan_time_ms"],
            record["call_id"],
            audit_envelope.HASH_V3,
            prev_hash,
            integrity_hash,
        ),
    )

    saved = dict(event)
    saved["id"] = event_id
    saved["ts"] = ts
    saved["call_id"] = call_id
    saved["hash_v"] = audit_envelope.HASH_V3
    return saved


def log_mcp_audit_event(event: dict) -> Dict[str, Any]:
    """Persist a durable MCP policy/audit event."""
    with (
        _db_lock,
        get_conn() as conn,
        _serialized_chain_append(conn, "mcp_audit_log"),
    ):
        return _append_mcp_audit_event(conn, event)


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


def lookup_latest_mcp_audit_log_by_probe_id(probe_id: str) -> Optional[Dict[str, Any]]:
    """Return the newest MCP audit event for a manual probe id."""
    with get_conn() as conn:
        row = conn.execute(
            """
            SELECT * FROM mcp_audit_log
             WHERE probe_id = ?
             ORDER BY ts DESC, id DESC
             LIMIT 1
            """,
            (probe_id,),
        ).fetchone()
    if not row:
        return None
    return _mcp_audit_row_to_dict(row)


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


def get_mcp_audit_log_by_call_id(call_id: str) -> Optional[Dict[str, Any]]:
    """Return the MCP audit event bound to a runtime call id, or None."""
    if not call_id:
        return None
    with get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM mcp_audit_log WHERE call_id = ? ORDER BY id ASC LIMIT 1",
            (call_id,),
        ).fetchone()
    if not row:
        return None
    return _mcp_audit_row_to_dict(row)


def list_mcp_audit_after(
    server_id: str,
    tool_name: str,
    after_ts: str,
    exclude_id: Optional[int] = None,
    limit: int = 500,
) -> List[Dict[str, Any]]:
    """
    Return audit events for one server/tool at or after a timestamp, oldest
    first. This is the evidence query behind receipt claim 4 ("did any
    boundary-crossing call execute after drift detection?"): the caller splits
    the result into forwarded (action=allow) vs blocked rows. Ties on ts are
    resolved by id so events logged in the same instant as the detection row
    are still included.
    """
    anchor_id = exclude_id if exclude_id is not None else -1
    with get_conn() as conn:
        rows = conn.execute(
            """
            SELECT * FROM mcp_audit_log
             WHERE server_id = ? AND tool_name = ?
               AND (ts > ? OR (ts = ? AND id > ?))
             ORDER BY ts ASC, id ASC
             LIMIT ?
            """,
            (server_id, tool_name, after_ts, after_ts, anchor_id, limit),
        ).fetchall()
    return [_mcp_audit_row_to_dict(r) for r in rows]


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

    v3 rows commit every stored security-significant column, so the full row
    is loaded and recomputed. The first retained record of a pruned chain
    links to the retention checkpoint's recorded boundary hash instead of
    GENESIS; the checkpoints themselves are verified before being trusted as
    an anchor.
    """
    with get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM mcp_audit_log WHERE id = ?",
            (audit_id,),
        ).fetchone()
        if not row:
            return {"chain_verified": False, "reason": "record_not_found"}
        row = row_to_plain_dict(row)
        prev = conn.execute(
            "SELECT integrity_hash FROM mcp_audit_log WHERE id < ? "
            "ORDER BY id DESC LIMIT 1",
            (audit_id,),
        ).fetchone()
        checkpoints = (
            _list_chain_checkpoints(conn, "mcp_audit_log") if prev is None else []
        )

    stored_hash = row.get("integrity_hash") or ""
    if not stored_hash:
        return {"chain_verified": False, "reason": "missing_integrity_hash"}

    if prev is None and checkpoints:
        checkpoint_failure = _verify_checkpoint_rows(checkpoints)
        if checkpoint_failure:
            return {"chain_verified": False, "reason": checkpoint_failure}
        # This row is the start of the retained chain: it must be exactly the
        # row the newest checkpoint promised to retain (a self-consistent
        # replacement row linking to the anchor must still fail).
        first_retained_id = checkpoints[-1].get("first_retained_id")
        if first_retained_id is not None and int(row["id"]) != int(first_retained_id):
            return {
                "chain_verified": False,
                "reason": "first retained row does not match checkpoint",
            }
        expected_prev = _checkpoint_anchor(checkpoints)
    else:
        expected_prev = (
            dict(prev).get("integrity_hash") if prev else None
        ) or "GENESIS"
    try:
        recomputed = _recompute_mcp_audit_hash(row)
    except audit_envelope.UnsupportedHashVersionError:
        return {
            "chain_verified": False,
            "reason": "unsupported hash version",
            "content_ok": False,
            "link_ok": False,
        }
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
