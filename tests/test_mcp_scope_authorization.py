"""Control-plane MCP routes require an API key with the admin scope."""

import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ["PYTHON_DOTENV_DISABLED"] = "1"
os.environ.pop("DATABASE_URL", None)
TEST_DB = tempfile.mktemp(suffix="_scope_auth.db")
os.environ["FIREWALL_DB_PATH"] = TEST_DB

from core import db  # noqa: E402
import proxy  # noqa: E402


def _headers(raw_key):
    return {"x-api-key": raw_key}


def _request(client, method, path, raw_key, body):
    return client.request(method.upper(), path, headers=_headers(raw_key), json=body)


def test_runtime_key_is_denied_and_admin_key_reaches_every_control_plane_route():
    db.init_db()
    runtime_key = db.generate_key("free", label="runtime-only")["raw_key"]
    admin_key = db.generate_key(
        "free", label="control-plane", scopes=["admin", "mcp.read", "mcp.call"]
    )["raw_key"]
    client = TestClient(proxy.app)
    server_id = "scope-auth-server"
    register_body = {
        "server_id": server_id,
        "url": "http://localhost:9777/mcp",
        "allowed_tools": ["read_document"],
    }
    cases = [
        ("post", "/mcp/servers", register_body),
        ("post", f"/mcp/servers/{server_id}/verify", None),
        ("post", f"/mcp/servers/{server_id}/rebaseline", {"confirm_rebaseline": True}),
        (
            "post",
            f"/mcp/tools/{server_id}/read_document/approve",
            {"reviewer": "test", "reason": "reviewed"},
        ),
        (
            "post",
            f"/mcp/tools/{server_id}/read_document/quarantine",
            {"reviewer": "test", "reason": "hold"},
        ),
        ("get", "/mcp/audit", None),
        ("delete", f"/mcp/servers/{server_id}", None),
    ]

    for method, path, body in cases:
        response = _request(client, method, path, runtime_key, body)
        assert response.status_code == 403, (method, path, response.text)

    with (
        patch(
            "routes.mcp.discover_mcp_tools", new=AsyncMock(return_value={"ok": True})
        ),
        patch(
            "routes.mcp.db.approve_mcp_tool_baseline",
            return_value={
                "ok": True,
                "server_id": server_id,
                "tool_name": "read_document",
            },
        ),
        patch(
            "routes.mcp.db.quarantine_mcp_tool",
            return_value={
                "ok": True,
                "server_id": server_id,
                "tool_name": "read_document",
            },
        ),
    ):
        for method, path, body in cases:
            response = _request(client, method, path, admin_key, body)
            assert response.status_code < 400, (method, path, response.text)


def test_new_keys_default_to_runtime_only():
    db.init_db()
    key = db.generate_key("free", label="runtime-default")
    assert db.lookup_key(key["raw_key"])["scopes"] == ["mcp.call", "mcp.read"]


def test_offline_demo_seed_explicitly_upgrades_demo_key_to_admin():
    db.init_db()
    db.seed_offline_demo_key()
    record = db.lookup_key(db.OFFLINE_DEMO_KEY)
    assert record["scopes"] == db.OFFLINE_DEMO_KEY_SCOPES
    # Every scope the offline demo needs is granted explicitly.
    assert set(record["scopes"]) == {
        "admin",
        "mcp.call",
        "mcp.read",
        "mcp.discover",
        "mcp.probe",
        "audit.read",
        "audit.export",
    }
