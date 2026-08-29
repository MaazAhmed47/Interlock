"""Positive authorization guard for destructive disposable-PostgreSQL tests.

This module is test infrastructure only.  It deliberately refuses broad
"looks non-production" heuristics: destructive SQL is authorized only for the
exact documented database/user, a narrow host boundary, an exact confirmation
sentinel, and a fresh prepared-session marker.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import os
import re
import sys
from dataclasses import dataclass
from typing import Mapping
from urllib.parse import unquote, urlsplit

DATABASE_URL_ENV = "INTERLOCK_TEST_DATABASE_URL"
CONFIRMATION_ENV = "INTERLOCK_ALLOW_DESTRUCTIVE_TEST_DATABASE"
CONFIRMATION_VALUE = "interlock-disposable-only"
RUN_ID_ENV = "INTERLOCK_DESTRUCTIVE_TEST_RUN_ID"
SESSION_TOKEN_ENV = "INTERLOCK_DESTRUCTIVE_TEST_SESSION_TOKEN"

EXPECTED_DATABASE = "interlock_test"
EXPECTED_USER = "interlock_test"
ALLOWED_HOSTS = frozenset({"localhost", "127.0.0.1", "::1", "postgres"})
MARKER_TABLE = "interlock_disposable_test_sessions"
MARKER_FORMAT_VERSION = 1

REBASELINE_OWNED_TABLES = (
    "mcp_rebaseline_candidates",
    "mcp_baseline_versions",
    "mcp_tool_metadata",
    "tool_surface_snapshots",
    "mcp_audit_log",
    "audit_chain_checkpoints",
    "mcp_servers",
)
BOUNDARY_REVIEW_OWNED_TABLES = (
    "ci_review_idempotency",
    "tool_surface_snapshots",
    "mcp_rebaseline_candidates",
    "mcp_baseline_versions",
    "mcp_response_profiles",
    "mcp_external_reach_profiles",
    "mcp_effect_profiles",
    "mcp_permission_probes",
    "mcp_tool_metadata",
    "mcp_audit_log",
    "audit_chain_checkpoints",
    "mcp_servers",
    "api_keys",
    "usage_log",
)
AUDIT_CHAIN_OWNED_TABLES = (
    "mcp_audit_log",
    "admin_audit_log",
    "audit_chain_checkpoints",
)
POSTGRES_SECURITY_OWNED_TABLES = tuple(
    sorted(
        set(REBASELINE_OWNED_TABLES)
        | set(BOUNDARY_REVIEW_OWNED_TABLES)
        | set(AUDIT_CHAIN_OWNED_TABLES)
    )
)

_RUN_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{8,200}$")
_TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{32,200}$")
_PRIVATE_SERVER_NETWORKS = tuple(
    ipaddress.ip_network(network)
    for network in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7")
)


class DisposableDatabaseError(RuntimeError):
    """The target is not positively authorized for destructive test SQL."""


@dataclass(frozen=True)
class RequestedTarget:
    host: str
    database: str
    user: str


@dataclass(frozen=True)
class DatabaseIdentity:
    database: str
    user: str
    server_address: str
    run_id: str


def _fail(reason: str) -> DisposableDatabaseError:
    return DisposableDatabaseError(
        f"disposable PostgreSQL authorization failed: {reason}"
    )


def _authorization(env: Mapping[str, str]) -> tuple[str, str]:
    if env.get(CONFIRMATION_ENV) != CONFIRMATION_VALUE:
        raise _fail("exact destructive-test confirmation is required")
    run_id = str(env.get(RUN_ID_ENV) or "")
    token = str(env.get(SESSION_TOKEN_ENV) or "")
    if not _RUN_ID_RE.fullmatch(run_id):
        raise _fail("a valid disposable run identifier is required")
    if not _TOKEN_RE.fullmatch(token):
        raise _fail("a valid disposable session token is required")
    return run_id, token


def parse_disposable_target(database_url: str) -> RequestedTarget:
    """Parse and positively constrain the requested disposable target."""
    try:
        parsed = urlsplit(str(database_url or ""))
        port = parsed.port
    except (TypeError, ValueError) as exc:
        raise _fail("target URL is not approved") from exc
    if parsed.scheme not in {"postgres", "postgresql"}:
        raise _fail("target URL is not approved")
    if parsed.query or parsed.fragment:
        raise _fail("target URL options are not approved")
    if not parsed.netloc or not parsed.hostname:
        raise _fail("an explicit network host is required")
    authority_without_user = parsed.netloc.rsplit("@", 1)[-1]
    if "," in authority_without_user or "%" in (parsed.hostname or ""):
        raise _fail("multiple or ambiguous hosts are not approved")
    host = (parsed.hostname or "").lower()
    if host not in ALLOWED_HOSTS:
        raise _fail("target host is not approved")
    if port is not None and not (1 <= port <= 65535):
        raise _fail("target port is not approved")
    if parsed.path != f"/{EXPECTED_DATABASE}":
        raise _fail("target database name is not approved")
    if unquote(parsed.path) != parsed.path:
        raise _fail("encoded database names are not approved")
    user = unquote(parsed.username or "")
    if user != EXPECTED_USER or user != (parsed.username or ""):
        raise _fail("target database user is not approved")
    return RequestedTarget(host=host, database=EXPECTED_DATABASE, user=user)


def _execute(connection, statement: str, params=()):
    if hasattr(connection, "execute"):
        return connection.execute(statement, params)
    cursor = connection.cursor()
    cursor.execute(statement, params)
    return cursor


def _row_value(row, key: str, index: int):
    if row is None:
        return None
    if isinstance(row, dict):
        return row.get(key)
    try:
        return row[key]
    except (KeyError, IndexError, TypeError):
        return row[index]


def _identity(connection) -> tuple[str, str, str]:
    row = _execute(
        connection,
        "SELECT current_database() AS database_name, "
        "current_user AS database_user, "
        "host(inet_server_addr()) AS server_address",
    ).fetchone()
    database = str(_row_value(row, "database_name", 0) or "")
    user = str(_row_value(row, "database_user", 1) or "")
    address = str(_row_value(row, "server_address", 2) or "")
    if database != EXPECTED_DATABASE or user != EXPECTED_USER or not address:
        raise _fail("connected database identity is not approved")
    try:
        server_ip = ipaddress.ip_address(address)
    except ValueError as exc:
        raise _fail("connected server address is not approved") from exc
    if not (
        server_ip.is_loopback
        or any(server_ip in network for network in _PRIVATE_SERVER_NETWORKS)
    ):
        raise _fail("connected server address is not approved")
    return database, user, address


def _token_digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def assert_disposable_database(
    connection,
    *,
    database_url: str | None = None,
    env: Mapping[str, str] | None = None,
) -> DatabaseIdentity:
    """Fail closed unless connection and fresh session marker are authorized."""
    values = os.environ if env is None else env
    run_id, token = _authorization(values)
    requested = parse_disposable_target(
        database_url if database_url is not None else values.get(DATABASE_URL_ENV, "")
    )
    database, user, address = _identity(connection)
    if database != requested.database or user != requested.user:
        raise _fail("requested and connected database identity differ")
    try:
        row = _execute(
            connection,
            f"SELECT run_id, token_sha256, database_name, database_user "
            f", format_version "
            f"FROM {MARKER_TABLE} WHERE run_id = %s",
            (run_id,),
        ).fetchone()
    except Exception as exc:
        raise _fail("disposable session marker is missing or invalid") from exc
    marker = (
        str(_row_value(row, "run_id", 0) or ""),
        str(_row_value(row, "token_sha256", 1) or ""),
        str(_row_value(row, "database_name", 2) or ""),
        str(_row_value(row, "database_user", 3) or ""),
        int(_row_value(row, "format_version", 4) or 0),
    )
    expected = (run_id, _token_digest(token), database, user, MARKER_FORMAT_VERSION)
    if marker != expected:
        raise _fail("disposable session marker is missing or invalid")
    return DatabaseIdentity(database, user, address, run_id)


def _connect(database_url: str):
    import psycopg2

    connection = psycopg2.connect(database_url)
    connection.autocommit = True
    return connection


def prepare_session(*, env: Mapping[str, str] | None = None) -> None:
    values = os.environ if env is None else env
    run_id, token = _authorization(values)
    database_url = str(values.get(DATABASE_URL_ENV) or "")
    requested = parse_disposable_target(database_url)
    connection = _connect(database_url)
    try:
        database, user, _address = _identity(connection)
        if database != requested.database or user != requested.user:
            raise _fail("requested and connected database identity differ")
        _execute(
            connection,
            f"CREATE TABLE IF NOT EXISTS {MARKER_TABLE} ("
            "run_id TEXT PRIMARY KEY, token_sha256 TEXT NOT NULL, "
            "database_name TEXT NOT NULL, database_user TEXT NOT NULL, "
            "format_version INTEGER NOT NULL, "
            "created_at TIMESTAMPTZ NOT NULL DEFAULT NOW())",
        )
        _execute(
            connection,
            f"INSERT INTO {MARKER_TABLE} "
            "(run_id, token_sha256, database_name, database_user, format_version) "
            "VALUES (%s, %s, %s, %s, %s) "
            "ON CONFLICT (run_id) DO UPDATE SET "
            "token_sha256 = EXCLUDED.token_sha256, "
            "database_name = EXCLUDED.database_name, "
            "database_user = EXCLUDED.database_user, "
            "format_version = EXCLUDED.format_version, created_at = NOW()",
            (
                run_id,
                _token_digest(token),
                database,
                user,
                MARKER_FORMAT_VERSION,
            ),
        )
    finally:
        connection.close()


def verify_cleanup(*, env: Mapping[str, str] | None = None) -> None:
    values = os.environ if env is None else env
    database_url = str(values.get(DATABASE_URL_ENV) or "")
    connection = _connect(database_url)
    try:
        assert_disposable_database(connection, database_url=database_url, env=values)
        residue = []
        for table in POSTGRES_SECURITY_OWNED_TABLES:
            row = _execute(
                connection, f"SELECT COUNT(*) AS row_count FROM {table}"
            ).fetchone()
            if int(_row_value(row, "row_count", 0) or 0):
                residue.append(table)
        if residue:
            raise _fail("owned test tables are not empty: " + ", ".join(residue))
    finally:
        connection.close()


def clear_session(*, env: Mapping[str, str] | None = None) -> None:
    values = os.environ if env is None else env
    database_url = str(values.get(DATABASE_URL_ENV) or "")
    run_id = str(values.get(RUN_ID_ENV) or "")
    connection = _connect(database_url)
    try:
        assert_disposable_database(connection, database_url=database_url, env=values)
        _execute(
            connection,
            f"DELETE FROM {MARKER_TABLE} WHERE run_id = %s",
            (run_id,),
        )
        remaining = _execute(
            connection, f"SELECT COUNT(*) AS row_count FROM {MARKER_TABLE}"
        ).fetchone()
        if int(_row_value(remaining, "row_count", 0) or 0) == 0:
            _execute(connection, f"DROP TABLE {MARKER_TABLE}")
    finally:
        connection.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("prepare", "verify-clean", "clear"))
    args = parser.parse_args(argv)
    try:
        if args.command == "prepare":
            prepare_session()
        elif args.command == "verify-clean":
            verify_cleanup()
        else:
            clear_session()
    except DisposableDatabaseError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    except Exception:
        print("Disposable PostgreSQL operation failed safely", file=sys.stderr)
        return 1
    print(f"Disposable PostgreSQL {args.command} passed for {EXPECTED_DATABASE}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
