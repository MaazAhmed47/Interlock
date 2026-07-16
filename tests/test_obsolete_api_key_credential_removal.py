"""Expand-contract retirement tests for the obsolete API-key credential field."""

import hashlib
import json
import logging
import sqlite3
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from core import admin, db
from proxy import app

ROOT_TOKEN = "root-obsolete-credential-test-token"
LEGACY_COLUMN = "upstream" + "_key"
LEGACY_STATUS_FIELD = LEGACY_COLUMN + "_configured"
SENTINEL = "legacy-credential-sentinel-never-serialize"
COLLIDING_TOKENS = (
    "sameAAAAAAAAAAAAAAAAAAAA",
    "sameBBBBBBBBBBBBBBBBBBBB",
)


@pytest.fixture()
def sqlite_key_db(tmp_path, monkeypatch):
    old_path = db.DB_PATH
    old_use_postgres = db.USE_POSTGRES
    old_admin_token = admin.ADMIN_TOKEN
    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "credential-removal.db"))
    monkeypatch.setattr(db, "USE_POSTGRES", False)
    monkeypatch.setattr(admin, "ADMIN_TOKEN", ROOT_TOKEN)
    db.init_db()
    yield
    db.DB_PATH = old_path
    db.USE_POSTGRES = old_use_postgres
    admin.ADMIN_TOKEN = old_admin_token


def _legacy_sqlite_api_keys(path: Path) -> None:
    conn = sqlite3.connect(path)
    try:
        conn.executescript(f"""
            CREATE TABLE api_keys (
                id                 INTEGER PRIMARY KEY AUTOINCREMENT,
                key_hash           TEXT NOT NULL UNIQUE,
                key_prefix         TEXT NOT NULL,
                label              TEXT NOT NULL DEFAULT '',
                plan               TEXT NOT NULL DEFAULT 'free',
                monthly_limit      INTEGER NOT NULL DEFAULT 1000,
                rate_per_min       INTEGER NOT NULL DEFAULT 10,
                fail_mode          TEXT NOT NULL DEFAULT 'fail_closed',
                webhook_url        TEXT,
                custom_policy      TEXT,
                siem_configs       TEXT,
                {LEGACY_COLUMN}    TEXT,
                scopes             TEXT NOT NULL DEFAULT '["mcp.call","mcp.read"]',
                role               TEXT NOT NULL DEFAULT 'readonly_agent',
                is_active          INTEGER NOT NULL DEFAULT 1,
                created_at         TEXT NOT NULL,
                revoked_at         TEXT,
                max_response_bytes INTEGER DEFAULT 50000,
                max_array_items    INTEGER DEFAULT 500
            );
            """)
        conn.executemany(
            f"""
            INSERT INTO api_keys
              (id, key_hash, key_prefix, label, plan, {LEGACY_COLUMN},
               is_active, created_at)
            VALUES (?, ?, ?, ?, 'free', ?, ?, ?)
            """,
            (
                (
                    7,
                    hashlib.sha256(b"legacy-active").hexdigest(),
                    "lf_free_olda",
                    "legacy-active",
                    SENTINEL,
                    1,
                    "2026-01-01T00:00:00+00:00",
                ),
                (
                    11,
                    hashlib.sha256(b"legacy-inactive").hexdigest(),
                    "lf_free_oldi",
                    "legacy-inactive",
                    None,
                    0,
                    "2026-01-02T00:00:00+00:00",
                ),
            ),
        )
        conn.commit()
    finally:
        conn.close()


def _prior_release_insert(conn, raw_key: str) -> int:
    cursor = conn.execute(
        f"""
        INSERT INTO api_keys
          (key_hash, key_prefix, label, plan, monthly_limit, rate_per_min,
           fail_mode, webhook_url, custom_policy, siem_configs, {LEGACY_COLUMN},
           is_active, created_at, max_response_bytes, max_array_items,
           scopes, role)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            db._hash_key(raw_key),
            raw_key[:12],
            "prior-release-compatible",
            "free",
            1000,
            10,
            "fail_closed",
            None,
            None,
            None,
            "prior-release-insert-value",
            True,
            "2026-07-17T00:00:00+00:00",
            50000,
            500,
            '["mcp.call","mcp.read"]',
            "readonly_agent",
        ),
    )
    assert cursor.lastrowid is not None
    return int(cursor.lastrowid)


def test_fresh_sqlite_schema_has_no_obsolete_credential_column(sqlite_key_db):
    assert LEGACY_COLUMN not in db.table_columns("api_keys")
    assert LEGACY_COLUMN not in db.SCHEMA

    created = db.generate_key("free", label="fresh-no-obsolete-credential")
    assert LEGACY_COLUMN not in db.lookup_key(created["raw_key"])
    assert LEGACY_STATUS_FIELD not in db.list_keys()[0]


def test_new_runtime_source_does_not_name_or_read_the_dormant_column():
    root = Path(__file__).parents[1]
    searched_paths = [
        root / "core",
        root / "models",
        root / "routes",
        root / "proxy.py",
        root / "scripts",
        root / "docs",
        root / "interlock-web" / "src",
    ]
    for path in searched_paths:
        files = [path] if path.is_file() else path.rglob("*")
        for candidate in files:
            if candidate.is_file() and candidate.suffix in {
                ".md",
                ".py",
                ".ts",
                ".tsx",
            }:
                source = candidate.read_text(encoding="utf-8")
                assert LEGACY_COLUMN not in source, candidate
                assert LEGACY_STATUS_FIELD not in source, candidate


def test_legacy_sqlite_schema_is_retained_and_new_reads_exclude_column(
    tmp_path, monkeypatch
):
    database_path = tmp_path / "legacy-api-keys.db"
    _legacy_sqlite_api_keys(database_path)
    monkeypatch.setattr(db, "DB_PATH", str(database_path))
    monkeypatch.setattr(db, "USE_POSTGRES", False)

    db.init_db()
    assert LEGACY_COLUMN in db.table_columns("api_keys")
    with db.get_conn() as conn:
        rows_after_first_init = [
            tuple(row)
            for row in conn.execute(
                f"SELECT id, key_prefix, label, is_active, {LEGACY_COLUMN} "
                "FROM api_keys ORDER BY id"
            ).fetchall()
        ]
    assert rows_after_first_init == [
        (7, "lf_free_olda", "legacy-active", 1, SENTINEL),
        (11, "lf_free_oldi", "legacy-inactive", 0, None),
    ]

    active = db.lookup_key("legacy-active")
    assert active is not None
    assert LEGACY_COLUMN not in active
    assert all(LEGACY_COLUMN not in row for row in db.list_keys(include_inactive=True))

    db.init_db()
    assert LEGACY_COLUMN in db.table_columns("api_keys")
    with db.get_conn() as conn:
        rows_after_second_init = [
            tuple(row)
            for row in conn.execute(
                f"SELECT id, key_prefix, label, is_active, {LEGACY_COLUMN} "
                "FROM api_keys ORDER BY id"
            ).fetchall()
        ]
    assert rows_after_second_init == rows_after_first_init


def test_prior_release_sql_shape_still_writes_after_new_initialization(
    tmp_path, monkeypatch
):
    database_path = tmp_path / "rollback-compatible-api-keys.db"
    _legacy_sqlite_api_keys(database_path)
    monkeypatch.setattr(db, "DB_PATH", str(database_path))
    monkeypatch.setattr(db, "USE_POSTGRES", False)
    db.init_db()

    raw_key = "lf_free_prior_release_compatibility"
    with db.get_conn() as conn:
        key_id = _prior_release_insert(conn, raw_key)
        conn.execute(
            f"UPDATE api_keys SET {LEGACY_COLUMN} = ? WHERE id = ?",
            ("prior-release-update-value", key_id),
        )
        dormant_value = conn.execute(
            f"SELECT {LEGACY_COLUMN} FROM api_keys WHERE id = ?", (key_id,)
        ).fetchone()[LEGACY_COLUMN]

    assert dormant_value == "prior-release-update-value"
    current = db.lookup_key(raw_key)
    assert current is not None
    assert current["id"] == key_id
    assert LEGACY_COLUMN not in current
    listed = next(row for row in db.list_keys() if row["id"] == key_id)
    assert LEGACY_COLUMN not in listed


def test_removed_internal_write_inputs_fail_without_echoing_credentials(
    sqlite_key_db, caplog
):
    caplog.set_level(logging.INFO)
    with pytest.raises(ValueError, match="Unsupported API key override") as exc:
        db.generate_key(
            "free", label="rejected-obsolete-write", **{LEGACY_COLUMN: SENTINEL}
        )
    assert LEGACY_COLUMN not in str(exc.value)
    assert SENTINEL not in str(exc.value)

    created = db.generate_key("free", label="update-probe")
    assert db.update_key_by_id(created["id"], **{LEGACY_COLUMN: SENTINEL}) is None
    assert LEGACY_COLUMN not in db.lookup_key(created["raw_key"])
    assert SENTINEL not in caplog.text
    assert LEGACY_COLUMN not in caplog.text


def test_admin_errors_audit_logs_and_receipts_never_name_removed_field(
    sqlite_key_db, caplog
):
    caplog.set_level(logging.INFO)
    client = TestClient(app)
    admin_headers = {"x-admin-token": ROOT_TOKEN}

    create_response = client.post(
        "/admin/keys",
        headers=admin_headers,
        json={"plan": "free", "label": "extra-field-probe", LEGACY_COLUMN: SENTINEL},
    )
    assert create_response.status_code == 200
    assert LEGACY_COLUMN not in create_response.text
    assert SENTINEL not in create_response.text

    with patch("core.db.secrets.token_urlsafe", side_effect=COLLIDING_TOKENS):
        first = db.generate_key(
            "free",
            label="surface-first",
            scopes=["audit.read", "audit.export"],
        )
        second = db.generate_key("free", label="surface-second")

    with db.get_conn() as conn:
        conn.execute(f"ALTER TABLE api_keys ADD COLUMN {LEGACY_COLUMN} TEXT")
        conn.execute(
            f"UPDATE api_keys SET {LEGACY_COLUMN} = ? WHERE id = ?",
            (SENTINEL, first["id"]),
        )

    internal = db.lookup_key(first["raw_key"])
    assert internal is not None
    assert LEGACY_COLUMN not in internal

    listed = client.get("/admin/keys?include_inactive=true", headers=admin_headers)
    assert listed.status_code == 200
    assert LEGACY_COLUMN not in listed.text
    assert LEGACY_STATUS_FIELD not in listed.text
    assert SENTINEL not in listed.text

    db.log_usage(first["id"], "/removed-field-usage", False)
    usage = client.get(f"/admin/keys/id/{first['id']}/usage", headers=admin_headers)
    assert usage.status_code == 200
    assert LEGACY_COLUMN not in usage.text

    ambiguous = client.get(
        f"/admin/keys/{first['key_prefix']}/usage", headers=admin_headers
    )
    assert ambiguous.status_code == 409
    assert first["key_prefix"] == second["key_prefix"]
    assert LEGACY_COLUMN not in ambiguous.text
    assert SENTINEL not in ambiguous.text

    ignored_patch = client.patch(
        f"/admin/keys/id/{first['id']}",
        headers=admin_headers,
        json={LEGACY_COLUMN: SENTINEL},
    )
    assert ignored_patch.status_code == 400
    assert LEGACY_COLUMN not in ignored_patch.text
    assert SENTINEL not in ignored_patch.text

    updated = client.patch(
        f"/admin/keys/id/{first['id']}",
        headers=admin_headers,
        json={"label": "surface-first-updated"},
    )
    assert updated.status_code == 200
    audit = client.get("/admin/audit", headers=admin_headers)
    assert audit.status_code == 200
    assert LEGACY_COLUMN not in audit.text
    assert SENTINEL not in audit.text
    verified = client.get("/admin/audit/verify", headers=admin_headers)
    assert verified.status_code == 200
    assert LEGACY_COLUMN not in verified.text

    receipt_export = client.get(
        "/audit/receipt/export", headers={"x-api-key": first["raw_key"]}
    )
    assert receipt_export.status_code == 200
    assert LEGACY_COLUMN not in receipt_export.text
    receipt_error = client.get(
        "/audit/receipt/export?format=unsupported",
        headers={"x-api-key": first["raw_key"]},
    )
    assert receipt_error.status_code == 400
    assert LEGACY_COLUMN not in receipt_error.text
    assert SENTINEL not in receipt_error.text

    audit_json = json.dumps(db.list_admin_audit_logs(limit=20), sort_keys=True)
    assert LEGACY_COLUMN not in audit_json
    assert SENTINEL not in audit_json
    assert LEGACY_COLUMN not in caplog.text
    assert SENTINEL not in caplog.text

    frontend_api = (
        Path(__file__).parents[1] / "interlock-web" / "src" / "api.ts"
    ).read_text(encoding="utf-8")
    assert LEGACY_COLUMN not in frontend_api
    assert LEGACY_STATUS_FIELD not in frontend_api
