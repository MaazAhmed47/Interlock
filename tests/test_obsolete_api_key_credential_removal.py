"""The retired API-key credential field must not remain a storage capability."""

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


def test_fresh_sqlite_schema_has_no_obsolete_credential_column(sqlite_key_db):
    assert LEGACY_COLUMN not in db.table_columns("api_keys")
    assert LEGACY_COLUMN not in db.SCHEMA

    created = db.generate_key("free", label="fresh-no-obsolete-credential")
    assert LEGACY_COLUMN not in db.lookup_key(created["raw_key"])
    assert LEGACY_STATUS_FIELD not in db.list_keys()[0]


def test_removed_field_name_exists_only_in_one_way_database_migration():
    root = Path(__file__).parents[1]
    db_source = (root / "core" / "db.py").read_text(encoding="utf-8")
    assert db_source.count(LEGACY_COLUMN) == 1

    searched_paths = [
        root / "core" / "admin.py",
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


def test_legacy_sqlite_schema_drops_column_and_preserves_rows(tmp_path, monkeypatch):
    database_path = tmp_path / "legacy-api-keys.db"
    _legacy_sqlite_api_keys(database_path)
    monkeypatch.setattr(db, "DB_PATH", str(database_path))
    monkeypatch.setattr(db, "USE_POSTGRES", False)

    db.init_db()
    assert LEGACY_COLUMN not in db.table_columns("api_keys")
    with db.get_conn() as conn:
        rows_after_first_init = [
            tuple(row)
            for row in conn.execute(
                "SELECT id, key_prefix, label, is_active FROM api_keys ORDER BY id"
            ).fetchall()
        ]
        table_sql = conn.execute(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'api_keys'"
        ).fetchone()["sql"]
    assert rows_after_first_init == [
        (7, "lf_free_olda", "legacy-active", 1),
        (11, "lf_free_oldi", "legacy-inactive", 0),
    ]
    assert LEGACY_COLUMN not in table_sql

    db.init_db()
    assert LEGACY_COLUMN not in db.table_columns("api_keys")
    with db.get_conn() as conn:
        rows_after_second_init = [
            tuple(row)
            for row in conn.execute(
                "SELECT id, key_prefix, label, is_active FROM api_keys ORDER BY id"
            ).fetchall()
        ]
    assert rows_after_second_init == rows_after_first_init


def test_legacy_sqlite_migration_requires_native_drop_column_support(
    tmp_path, monkeypatch
):
    database_path = tmp_path / "unsupported-sqlite.db"
    _legacy_sqlite_api_keys(database_path)
    monkeypatch.setattr(db, "DB_PATH", str(database_path))
    monkeypatch.setattr(db, "USE_POSTGRES", False)
    monkeypatch.setattr(db.sqlite3, "sqlite_version_info", (3, 34, 1))

    with db.get_conn() as conn:
        with pytest.raises(RuntimeError, match="SQLite 3.35 or newer") as exc:
            db._drop_obsolete_api_key_columns(conn)

    assert LEGACY_COLUMN not in str(exc.value)
    assert LEGACY_COLUMN in db.table_columns("api_keys")


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
    ).read_text()
    assert LEGACY_COLUMN not in frontend_api
    assert LEGACY_STATUS_FIELD not in frontend_api
