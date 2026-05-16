"""
SQLite-backed API key storage.

Replaces the hardcoded VALID_API_KEYS / FAIL_MODE_BY_KEY / WEBHOOK_URLS /
CUSTOM_POLICIES / SIEM_CONFIGS_BY_KEY dicts with a single ApiKey record.

All per-key state lives in one row. JSON columns for the things that vary in shape
(custom policies, SIEM configs) so we don't need a migration every time the rule
engine grows a new field.

Migration to Postgres later is a connect-string change. We use plain SQL — no ORM —
to keep the surface tiny and review-able.
"""

import os
import json
import secrets
import sqlite3
import hashlib
import logging
from contextlib import contextmanager
from datetime import datetime
from threading import Lock
from typing import Optional, List, Dict, Any

logger = logging.getLogger("interlock.db")

DATABASE_URL = os.getenv("DATABASE_URL")
USE_POSTGRES = DATABASE_URL is not None and DATABASE_URL.startswith("postgresql")
DB_PATH = os.getenv("FIREWALL_DB_PATH", "data/firewall.db")
_db_lock = Lock()  # SQLite is fine concurrent-read, one-writer; lock guards writes


# ── Connection helper ────────────────────────────────────────────────────────
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


def _pg_sql(sql: str) -> str:
    converted = sql.replace("INTEGER PRIMARY KEY AUTOINCREMENT", "SERIAL PRIMARY KEY")
    converted = converted.replace("is_active       INTEGER NOT NULL DEFAULT 1", "is_active       BOOLEAN NOT NULL DEFAULT TRUE")
    insert_ignore = "INSERT OR IGNORE INTO" in converted
    converted = converted.replace("INSERT OR IGNORE INTO", "INSERT INTO")
    converted = converted.replace("?", "%s")
    if insert_ignore:
        converted = converted.rstrip().rstrip(";") + " ON CONFLICT DO NOTHING"
    return converted


@contextmanager
def get_conn():
    if USE_POSTGRES:
        import psycopg2
        import psycopg2.extras
        raw = psycopg2.connect(DATABASE_URL)
        raw.autocommit = True
        raw.cursor_factory = psycopg2.extras.RealDictCursor
        conn = _PostgresConn(raw)
    else:
        os.makedirs(os.path.dirname(DB_PATH) or ".", exist_ok=True)
        conn = sqlite3.connect(DB_PATH, timeout=10, isolation_level=None)  # autocommit
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")     # better concurrency
        conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
    finally:
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

CREATE TABLE IF NOT EXISTS mcp_servers (
    server_id       TEXT    PRIMARY KEY,
    url             TEXT    NOT NULL,
    description     TEXT    NOT NULL DEFAULT '',
    allowed_tools   TEXT    NOT NULL DEFAULT '[]',  -- JSON list
    blocked_tools   TEXT    NOT NULL DEFAULT '[]',  -- JSON list
    rate_limit      INTEGER NOT NULL DEFAULT 60,
    verified        INTEGER NOT NULL DEFAULT 0,
    registered_at   TEXT    NOT NULL
);
"""


def init_db() -> None:
    if USE_POSTGRES:
        logger.info("Using Postgres - skipping schema creation (tables already exist in Supabase)")
        return
    with _db_lock, get_conn() as conn:
        conn.executescript(SCHEMA)
    logger.info("SQLite DB initialized at %s", DB_PATH)


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


def _is_integrity_error(exc: Exception) -> bool:
    return isinstance(exc, sqlite3.IntegrityError) or exc.__class__.__name__ in {
        "IntegrityError",
        "UniqueViolation",
    }


# ── Plan defaults ────────────────────────────────────────────────────────────
PLAN_DEFAULTS = {
    "free":      {"monthly_limit": 1000,   "rate_per_min": 10,  "fail_mode": "fail_closed"},
    "developer": {"monthly_limit": 50000,  "rate_per_min": 60,  "fail_mode": "fail_open_safe"},
    "startup":   {"monthly_limit": 500000, "rate_per_min": 300, "fail_mode": "fail_open_safe"},
    "enterprise":{"monthly_limit": 0,      "rate_per_min": 1000,"fail_mode": "fail_open_safe"},  # 0 = unlimited
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
    rate_per_min  = overrides.get("rate_per_min",  defaults["rate_per_min"])
    fail_mode     = overrides.get("fail_mode",     defaults["fail_mode"])
    webhook_url   = overrides.get("webhook_url")
    custom_policy = overrides.get("custom_policy")
    siem_configs  = overrides.get("siem_configs")
    upstream_key  = overrides.get("upstream_key")

    with _db_lock, get_conn() as conn:
        conn.execute(
            """
            INSERT INTO api_keys
              (key_hash, key_prefix, label, plan, monthly_limit, rate_per_min,
               fail_mode, webhook_url, custom_policy, siem_configs, upstream_key,
               is_active, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                key_hash, key_prefix, label, plan, monthly_limit, rate_per_min,
                fail_mode, webhook_url,
                json.dumps(custom_policy) if custom_policy else None,
                json.dumps(siem_configs)  if siem_configs  else None,
                upstream_key,
                True,
                datetime.utcnow().isoformat(),
            ),
        )

    logger.info("Issued new API key: prefix=%s plan=%s label=%s", key_prefix, plan, label)
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
            (datetime.utcnow().isoformat(), key_prefix),
        )
        revoked = cursor.rowcount > 0
    if revoked:
        logger.info("Revoked API key: prefix=%s", key_prefix)
    return revoked


def list_keys(include_inactive: bool = False) -> List[Dict[str, Any]]:
    q = "SELECT * FROM api_keys" if include_inactive else "SELECT * FROM api_keys WHERE is_active = TRUE"
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
        "label", "plan", "monthly_limit", "rate_per_min", "fail_mode",
        "webhook_url", "custom_policy", "siem_configs", "upstream_key",
    }
    fields = {k: v for k, v in fields.items() if k in EDITABLE}
    if not fields:
        return False

    # JSON-encode the JSON columns
    for col in ("custom_policy", "siem_configs"):
        if col in fields and fields[col] is not None and not isinstance(fields[col], str):
            fields[col] = json.dumps(fields[col])

    set_clause = ", ".join(f"{k} = ?" for k in fields)
    values = list(fields.values()) + [key_prefix]

    with _db_lock, get_conn() as conn:
        cursor = conn.execute(
            f"UPDATE api_keys SET {set_clause} WHERE key_prefix = ?",
            values,
        )
    return cursor.rowcount > 0


# ── Usage logging + monthly quota ────────────────────────────────────────────
def log_usage(key_id: int, endpoint: str, threat_blocked: bool = False) -> None:
    with _db_lock, get_conn() as conn:
        conn.execute(
            "INSERT INTO usage_log (key_id, ts, endpoint, threat_blocked) VALUES (?, ?, ?, ?)",
            (key_id, datetime.utcnow().isoformat(), endpoint, 1 if threat_blocked else 0),
        )


def usage_this_month(key_id: int) -> int:
    month_start = datetime.utcnow().replace(day=1, hour=0, minute=0, second=0, microsecond=0).isoformat()
    with get_conn() as conn:
        row = conn.execute(
            "SELECT COUNT(*) AS n FROM usage_log WHERE key_id = ? AND ts >= ?",
            (key_id, month_start),
        ).fetchone()
    return row["n"] if row else 0


# ── Bootstrap / seed ─────────────────────────────────────────────────────────
def seed_legacy_keys() -> None:
    """
    Idempotent migration: insert the three hardcoded keys from proxy.py if they
    don't exist yet. Lets you flip the proxy over with zero customer disruption.
    """
    legacy = [
        ("lf-free-demo-key-123", "free",      "Legacy free demo"),
        ("lf-dev-key-456",       "developer", "Legacy developer"),
        ("lf-startup-key-789",   "startup",   "Legacy startup"),
    ]
    for raw, plan, label in legacy:
        if lookup_key(raw):
            continue
        defaults = PLAN_DEFAULTS[plan]
        with _db_lock, get_conn() as conn:
            conn.execute(
                """
                INSERT OR IGNORE INTO api_keys
                  (key_hash, key_prefix, label, plan, monthly_limit, rate_per_min,
                   fail_mode, is_active, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    _hash_key(raw), raw[:12], label, plan,
                    defaults["monthly_limit"], defaults["rate_per_min"],
                    defaults["fail_mode"],
                    True,
                    datetime.utcnow().isoformat(),
                ),
            )
        logger.info("Seeded legacy key: %s (%s)", raw[:12], plan)


# ── MCP server registry ───────────────────────────────────────────────────────

def _mcp_row_to_dict(row) -> Dict[str, Any]:
    d = dict(row)
    for col in ("allowed_tools", "blocked_tools"):
        raw = d.get(col)
        try:
            d[col] = json.loads(raw) if raw else []
        except (json.JSONDecodeError, TypeError):
            d[col] = []
    d["verified"] = bool(d.get("verified", 0))
    return d


def register_mcp_server(server_id: str, config: dict) -> bool:
    """Insert a new MCP server. Returns False if server_id already exists."""
    try:
        with _db_lock, get_conn() as conn:
            conn.execute(
                """
                INSERT INTO mcp_servers
                  (server_id, url, description, allowed_tools, blocked_tools,
                   rate_limit, verified, registered_at)
                VALUES (?, ?, ?, ?, ?, ?, 0, ?)
                """,
                (
                    server_id,
                    config["url"],
                    config.get("description", ""),
                    json.dumps(config.get("allowed_tools", [])),
                    json.dumps(config.get("blocked_tools", [])),
                    config.get("rate_limit", 60),
                    datetime.utcnow().isoformat(),
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


def list_mcp_servers() -> List[Dict[str, Any]]:
    """Return all registered MCP servers ordered by registration time."""
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM mcp_servers ORDER BY registered_at ASC"
        ).fetchall()
    return [_mcp_row_to_dict(r) for r in rows]


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
            "UPDATE mcp_servers SET verified = 1 WHERE server_id = ?",
            (server_id,),
        )
    return cursor.rowcount > 0


def seed_mcp_servers() -> None:
    """Idempotent seed of the two pre-configured MCP servers. Safe to call on every startup."""
    seeds = [
        {
            "server_id": "trusted-filesystem",
            "url": "http://localhost:3000/mcp",
            "description": "Sandboxed file system access",
            "allowed_tools": ["read_file", "list_directory"],
            "blocked_tools": ["write_file", "delete_file", "execute"],
            "rate_limit": 60,
            "verified": 1,
        },
        {
            "server_id": "trusted-search",
            "url": "http://localhost:3001/mcp",
            "description": "Web search MCP",
            "allowed_tools": ["search", "fetch"],
            "blocked_tools": [],
            "rate_limit": 30,
            "verified": 1,
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
                    s["server_id"], s["url"], s["description"],
                    json.dumps(s["allowed_tools"]),
                    json.dumps(s["blocked_tools"]),
                    s["rate_limit"], s["verified"],
                    datetime.utcnow().isoformat(),
                ),
            )
        logger.info("Seeded MCP server: %s", s["server_id"])
