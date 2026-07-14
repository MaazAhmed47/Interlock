"""
Probe authorization is decided by the persisted registry, not the request.

- Servers default to production + probes disabled (fail closed).
- Only the admin registration/update path can mark a server
  non-production + probe-enabled.
- A probe requires BOTH the `mcp.probe` scope and a stored
  non-production, probe-enabled server; the request-body
  `non_production` flag is audit context, never authorization.

Run: python -m pytest tests/test_probe_lockdown.py -q
"""

import asyncio
import os
import sqlite3
import sys
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ["PYTHON_DOTENV_DISABLED"] = "1"
os.environ.pop("DATABASE_URL", None)
os.environ.setdefault("MCP_REGISTRY_ALLOWED_HOSTS", "safe.example")
TEST_DB = tempfile.mktemp(suffix="_probe_lockdown.db")
os.environ.setdefault("FIREWALL_DB_PATH", TEST_DB)

from core import db  # noqa: E402
from core import effective_permission  # noqa: E402
import proxy  # noqa: E402

READ_TOOL = {
    "name": "read_document",
    "description": "Read a document.",
    "inputSchema": {
        "type": "object",
        "properties": {"doc_id": {"type": "string"}},
        "required": ["doc_id"],
    },
}

READ_TOOL_METADATA = {
    "effects": ["read"],
    "side_effect": "read_only",
    "data_classes": ["user_content"],
    "externality": "internal",
    "verification_level": "interlock_meta",
    "confidence": 0.95,
    "warnings": [],
}

PROBE_BODY = {
    "tool_name": "read_document",
    "arguments": {"doc_id": "d-1"},
    "expected_outcome": "denied",
    "expected_status_code": 403,
    "non_production": True,
    "safety_note": "Probe-lockdown test body.",
}

READBACK_BODY = {
    "target": {"tool_name": "read_document", "arguments": {"doc_id": "d-1"}},
    "readback": {"tool_name": "read_document", "arguments": {"doc_id": "d-1"}},
    "expected_effect": "no_change",
    "non_production": True,
    "safety_note": "Probe-lockdown readback body.",
}


@pytest.fixture(autouse=True)
def isolated_db():
    prior_db_path = db.DB_PATH
    db.DB_PATH = TEST_DB
    db.init_db()
    proxy._key_record_cache.clear()
    yield
    db.DB_PATH = prior_db_path
    for suffix in ("", "-wal", "-shm"):
        try:
            os.remove(TEST_DB + suffix)
        except OSError:
            pass


@pytest.fixture()
def client():
    return TestClient(proxy.app)


def mint(scopes):
    return db.generate_key("developer", label="probe-lockdown", scopes=scopes)[
        "raw_key"
    ]


def seed_server(server_id, **extra_config):
    config = {
        "url": "http://safe.example/mcp",
        "description": "Probe lockdown test server",
        "allowed_tools": ["read_document"],
        "blocked_tools": [],
        "rate_limit": 10,
    }
    config.update(extra_config)
    db.register_mcp_server(server_id, config)
    db.verify_mcp_server(server_id)
    db.upsert_mcp_tool_metadata(server_id, READ_TOOL, READ_TOOL_METADATA)
    return server_id


def upstream_403():
    resp = MagicMock()
    resp.status_code = 403
    resp.headers = {}
    resp.json.return_value = {"error": {"message": "Forbidden"}}
    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.post = AsyncMock(return_value=resp)
    return mock_client


def test_register_defaults_to_production_and_probes_disabled():
    seed_server("_lockdown_defaults")
    try:
        server = db.lookup_mcp_server("_lockdown_defaults")
        assert server["environment"] == "production"
        assert server["probes_enabled"] is False
    finally:
        db.unregister_mcp_server("_lockdown_defaults")


def test_probe_route_fails_closed_on_default_production_server(client):
    server_id = seed_server("_lockdown_prod_probe")
    key = mint(["mcp.probe"])
    try:
        with patch(
            "core.effective_permission.httpx.AsyncClient",
            side_effect=AssertionError("upstream contacted for denied probe"),
        ):
            response = client.post(
                f"/mcp/servers/{server_id}/probes/run",
                headers={"x-api-key": key},
                json=PROBE_BODY,
            )
        assert response.status_code == 403, response.text
        detail = response.json().get("detail", "")
        assert "probe" in detail.lower(), response.text
    finally:
        db.unregister_mcp_server(server_id)


def test_readback_route_fails_closed_on_default_production_server(client):
    server_id = seed_server("_lockdown_prod_readback")
    key = mint(["mcp.probe"])
    try:
        with patch(
            "core.effect_readback.httpx.AsyncClient",
            side_effect=AssertionError("upstream contacted for denied readback"),
        ):
            response = client.post(
                f"/mcp/servers/{server_id}/effects/readback/run",
                headers={"x-api-key": key},
                json=READBACK_BODY,
            )
        assert response.status_code == 403, response.text
    finally:
        db.unregister_mcp_server(server_id)


def test_core_probe_gate_fails_closed_for_direct_callers():
    server_id = seed_server("_lockdown_direct_core")
    try:
        result = asyncio.run(
            effective_permission.run_effective_permission_probe(
                server_id, dict(PROBE_BODY)
            )
        )
        assert result["ok"] is False
        assert result["error"] == "probes_not_enabled"
    finally:
        db.unregister_mcp_server(server_id)


def test_registration_can_mark_non_production_probe_enabled(client):
    admin_key = mint(["admin"])
    server_id = "_lockdown_reg_enabled"
    try:
        response = client.post(
            "/mcp/servers",
            headers={"x-api-key": admin_key},
            json={
                "server_id": server_id,
                "url": "http://safe.example/mcp",
                "allowed_tools": ["read_document"],
                "environment": "non_production",
                "probes_enabled": True,
            },
        )
        assert response.status_code == 200, response.text
        server = db.lookup_mcp_server(server_id)
        assert server["environment"] == "non_production"
        assert server["probes_enabled"] is True
    finally:
        db.unregister_mcp_server(server_id)


def test_admin_environment_update_enables_probes(client):
    server_id = seed_server("_lockdown_env_update")
    admin_key = mint(["admin"])
    probe_key = mint(["mcp.probe"])
    try:
        response = client.post(
            f"/mcp/servers/{server_id}/environment",
            headers={"x-api-key": admin_key},
            json={"environment": "non_production", "probes_enabled": True},
        )
        assert response.status_code == 200, response.text

        server = db.lookup_mcp_server(server_id)
        assert server["environment"] == "non_production"
        assert server["probes_enabled"] is True

        with patch(
            "core.effective_permission.httpx.AsyncClient",
            return_value=upstream_403(),
        ):
            probe = client.post(
                f"/mcp/servers/{server_id}/probes/run",
                headers={"x-api-key": probe_key},
                json=PROBE_BODY,
            )
        assert probe.status_code == 200, probe.text
        assert probe.json()["ok"] is True
    finally:
        db.unregister_mcp_server(server_id)


def test_environment_update_requires_admin_scope(client):
    server_id = seed_server("_lockdown_env_nonadmin")
    runtime_key = mint(
        ["mcp.call", "mcp.read", "mcp.discover", "mcp.probe", "audit.read"]
    )
    try:
        response = client.post(
            f"/mcp/servers/{server_id}/environment",
            headers={"x-api-key": runtime_key},
            json={"environment": "non_production", "probes_enabled": True},
        )
        assert response.status_code == 403, response.text
        server = db.lookup_mcp_server(server_id)
        assert server["environment"] == "production"
        assert server["probes_enabled"] is False
    finally:
        db.unregister_mcp_server(server_id)


def test_environment_update_unknown_server_is_404(client):
    admin_key = mint(["admin"])
    response = client.post(
        "/mcp/servers/_lockdown_missing/environment",
        headers={"x-api-key": admin_key},
        json={"environment": "non_production", "probes_enabled": True},
    )
    assert response.status_code == 404, response.text


def test_request_body_non_production_is_not_authorization(client):
    """Body says non_production=True on a production server -> denied.
    Body says non_production=False on an enabled server -> probe still runs.
    The stored registry decides; the body flag is audit context only."""
    denied_id = seed_server("_lockdown_body_flag_denied")
    enabled_id = seed_server(
        "_lockdown_body_flag_enabled",
        environment="non_production",
        probes_enabled=True,
    )
    key = mint(["mcp.probe"])
    try:
        response = client.post(
            f"/mcp/servers/{denied_id}/probes/run",
            headers={"x-api-key": key},
            json=dict(PROBE_BODY, non_production=True),
        )
        assert response.status_code == 403, response.text

        with patch(
            "core.effective_permission.httpx.AsyncClient",
            return_value=upstream_403(),
        ):
            response = client.post(
                f"/mcp/servers/{enabled_id}/probes/run",
                headers={"x-api-key": key},
                json=dict(PROBE_BODY, non_production=False),
            )
        assert response.status_code == 200, response.text
        assert response.json()["ok"] is True
    finally:
        db.unregister_mcp_server(denied_id)
        db.unregister_mcp_server(enabled_id)


def test_probe_still_requires_safety_note(client):
    server_id = seed_server(
        "_lockdown_safety_note",
        environment="non_production",
        probes_enabled=True,
    )
    key = mint(["mcp.probe"])
    try:
        response = client.post(
            f"/mcp/servers/{server_id}/probes/run",
            headers={"x-api-key": key},
            json=dict(PROBE_BODY, safety_note="  "),
        )
        assert response.status_code == 400, response.text
    finally:
        db.unregister_mcp_server(server_id)


def test_sqlite_migration_backfills_environment_defaults():
    """A pre-upgrade mcp_servers table (no environment/probes_enabled
    columns) must migrate to production + probes-disabled on init_db."""
    legacy_db = tempfile.mktemp(suffix="_probe_lockdown_legacy.db")
    conn = sqlite3.connect(legacy_db)
    conn.execute("""
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
            verified        INTEGER NOT NULL DEFAULT 0,
            registered_at   TEXT    NOT NULL
        )
        """)
    conn.execute("""
        INSERT INTO mcp_servers (server_id, url, registered_at, verified)
        VALUES ('legacy-server', 'http://safe.example/mcp',
                '2026-01-01T00:00:00+00:00', 1)
        """)
    conn.commit()
    conn.close()

    prior_db_path = db.DB_PATH
    db.DB_PATH = legacy_db
    try:
        db.init_db()
        server = db.lookup_mcp_server("legacy-server")
        assert server is not None
        assert server["environment"] == "production"
        assert server["probes_enabled"] is False
    finally:
        db.DB_PATH = prior_db_path
        for suffix in ("", "-wal", "-shm"):
            try:
                os.remove(legacy_db + suffix)
            except OSError:
                pass
