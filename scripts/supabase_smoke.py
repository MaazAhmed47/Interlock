#!/usr/bin/env python3
"""Safe Supabase/Postgres smoke test for Interlock.

Default mode is schema/readiness only:
- loads DATABASE_URL from .env or the process environment
- masks secrets in output
- runs db.init_db() so required tables/columns exist
- verifies required tables and production-critical columns

Use --write-test to create and revoke one admin token plus one customer API key.
That mode leaves only revoked smoke-test rows for auditability.
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from urllib.parse import urlsplit

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

REQUIRED_TABLES = {
    "api_keys",
    "usage_log",
    "scan_history",
    "mcp_servers",
    "mcp_tool_metadata",
    "mcp_audit_log",
    "system_config",
    "admin_tokens",
    "admin_audit_log",
    "shadow_mcp_servers",
    "shadow_scan_targets",
}

REQUIRED_COLUMNS = {
    "api_keys": {"key_hash", "key_prefix", "plan", "fail_mode", "max_response_bytes", "max_array_items"},
    "admin_tokens": {"token_hash", "token_prefix", "role", "permissions", "revoked_at", "last_used_at"},
    "admin_audit_log": {"actor_auth_type", "actor_role", "actor_label", "action", "target_type", "target_id", "details"},
    "mcp_servers": {"server_id", "url", "verified", "source_type", "provenance_status"},
    "mcp_tool_metadata": {"server_id", "tool_name", "drift_severity", "drift_action", "previous_metadata"},
    "scan_history": {"key_hash", "ts", "risk_score", "sanitized_output", "redactions"},
}


def masked_database_url(value: str) -> str:
    try:
        parsed = urlsplit(value)
        # Accessing .port validates it and raises if the URL is malformed.
        parsed_port = parsed.port
    except ValueError:
        return "<malformed DATABASE_URL>"
    host = parsed.hostname or "unknown-host"
    port = f":{parsed_port}" if parsed_port else ""
    username = parsed.username or "user"
    db_name = parsed.path.lstrip("/") or "database"
    return f"{parsed.scheme}://{username}:***@{host}{port}/{db_name}"


def database_url_is_well_formed(value: str) -> bool:
    try:
        parsed = urlsplit(value)
        _ = parsed.port
    except ValueError:
        return False
    return bool(parsed.scheme and parsed.hostname and parsed.path)


def row_value(row, key: str, index: int = 0):
    if isinstance(row, dict):
        return row.get(key)
    try:
        return row[key]
    except Exception:
        return row[index]


def table_exists(conn, table: str) -> bool:
    row = conn.execute(
        """
        SELECT EXISTS (
            SELECT 1
              FROM information_schema.tables
             WHERE table_schema = current_schema()
               AND table_name = ?
        ) AS exists
        """,
        (table,),
    ).fetchone()
    return bool(row_value(row, "exists", 0))


def main() -> int:
    parser = argparse.ArgumentParser(description="Smoke test Interlock against Supabase/Postgres")
    parser.add_argument("--env-file", default=str(ROOT / ".env"), help="Env file containing DATABASE_URL")
    parser.add_argument("--write-test", action="store_true", help="Create and revoke one smoke admin token and API key")
    args = parser.parse_args()

    load_dotenv(args.env_file)
    database_url = (os.getenv("DATABASE_URL") or "").strip()
    if not database_url:
        print("DATABASE_URL is not set. Add it to .env or export it before running this smoke test.", file=sys.stderr)
        return 2
    if not database_url.startswith(("postgresql://", "postgres://")):
        print("DATABASE_URL must be a Supabase/Postgres connection string.", file=sys.stderr)
        return 2
    if not database_url_is_well_formed(database_url):
        print("DATABASE_URL is malformed. Use the Supabase Postgres URI format and URL-encode special characters in the password.", file=sys.stderr)
        print("Expected shape: postgresql://USER:PASSWORD@HOST:5432/DATABASE", file=sys.stderr)
        return 2

    from core import db

    db.DATABASE_URL = database_url
    db.USE_POSTGRES = True

    print("Target:", masked_database_url(database_url))
    print("Initializing schema...")
    db.init_db()

    missing_tables: list[str] = []
    missing_columns: dict[str, list[str]] = {}

    with db.get_conn() as conn:
        for table in sorted(REQUIRED_TABLES):
            if not table_exists(conn, table):
                missing_tables.append(table)

        for table, required in REQUIRED_COLUMNS.items():
            if table in missing_tables:
                continue
            columns = set(db.table_columns(table, conn=conn))
            missing = sorted(required - columns)
            if missing:
                missing_columns[table] = missing

    if missing_tables or missing_columns:
        print("Smoke test failed.")
        if missing_tables:
            print("Missing tables:", ", ".join(missing_tables))
        if missing_columns:
            print("Missing columns:")
            for table, columns in missing_columns.items():
                print(f"- {table}: {', '.join(columns)}")
        return 1

    print(f"Schema OK: {len(REQUIRED_TABLES)} required tables verified.")

    if args.write_test:
        admin_token = db.generate_admin_token(label="supabase-smoke-test", role="auditor")
        if not db.lookup_admin_token(admin_token["raw_token"]):
            print("Admin token lookup failed.")
            return 1
        if not db.revoke_admin_token(admin_token["token_prefix"]):
            print("Admin token revoke failed.")
            return 1

        api_key = db.generate_key("free", label="supabase-smoke-test")
        if not db.lookup_key(api_key["raw_key"]):
            print("API key lookup failed.")
            return 1
        if not db.revoke_key(api_key["key_prefix"]):
            print("API key revoke failed.")
            return 1

        print("Write test OK: smoke admin token and API key created, looked up, and revoked.")

    print("Supabase smoke test passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
