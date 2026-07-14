"""
Table-driven API-scope deny matrix for every MCP and receipt endpoint.

For each route: a key holding every scope EXCEPT the required one (and not
admin) must get HTTP 403, and a key holding ONLY the required scope must
reach the route's normal behavior. `admin` is a deliberate super-scope for
backward-compatible administration.

Run: python -m pytest tests/test_mcp_scope_matrix.py -q
"""

import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ["PYTHON_DOTENV_DISABLED"] = "1"
os.environ.pop("DATABASE_URL", None)
os.environ.setdefault("MCP_REGISTRY_ALLOWED_HOSTS", "safe.example")
TEST_DB = tempfile.mktemp(suffix="_scope_matrix.db")
os.environ.setdefault("FIREWALL_DB_PATH", TEST_DB)

from core import db  # noqa: E402
import proxy  # noqa: E402

NON_ADMIN_SCOPES = [
    "mcp.call",
    "mcp.read",
    "mcp.discover",
    "mcp.probe",
    "audit.read",
    "audit.export",
]

PROBE_BODY = {
    "tool_name": "read_document",
    "arguments": {"doc_id": "d-1"},
    "expected_outcome": "denied",
    "expected_status_code": 403,
    "non_production": True,
    "safety_note": "Scope-matrix probe body.",
}

READBACK_BODY = {
    "target": {"tool_name": "read_document", "arguments": {}},
    "readback": {"tool_name": "read_document", "arguments": {}},
    "expected_effect": "no_change",
    "non_production": True,
    "safety_note": "Scope-matrix readback body.",
}

# (method, path, body, required_scope, patch_key)
MATRIX = [
    (
        "post",
        "/mcp/call",
        {"server_id": "matrix-missing", "tool_name": "t", "arguments": {}},
        "mcp.call",
        None,
    ),
    ("get", "/mcp/servers", None, "mcp.read", None),
    ("get", "/mcp/tools", None, "mcp.read", None),
    ("get", "/mcp/tools/drifted", None, "mcp.read", None),
    (
        "post",
        "/mcp/discover",
        {"server_url": "http://safe.example/mcp"},
        "mcp.discover",
        "discover",
    ),
    (
        "post",
        "/mcp/validate-tool",
        {
            "tool_definition": {
                "name": "read_thing",
                "description": "Read a thing.",
                "inputSchema": {"type": "object", "properties": {}},
            }
        },
        "mcp.discover",
        None,
    ),
    (
        "post",
        "/mcp/chains/analyze",
        {
            "steps": [{"tool_name": "read_thing", "arguments": {}}],
            "safety_note": "Scope-matrix chain body.",
        },
        "mcp.call",
        None,
    ),
    (
        "post",
        "/mcp/servers/matrix-probe-server/probes/run",
        PROBE_BODY,
        "mcp.probe",
        "probe",
    ),
    (
        "post",
        "/mcp/servers/matrix-probe-server/effects/readback/run",
        READBACK_BODY,
        "mcp.probe",
        "readback",
    ),
    ("get", "/audit/receipt/999999", None, "audit.read", None),
    ("get", "/audit/receipt/999999/claims", None, "audit.read", None),
    (
        "post",
        "/audit/receipt/verify",
        {"context": {"server_id": "x"}},
        "audit.read",
        None,
    ),
    ("get", "/audit/evidence/surface/deadbeef", None, "audit.read", None),
    ("get", "/audit/receipt/export", None, "audit.export", None),
]

MATRIX_IDS = [f"{m[0].upper()} {m[1]} -> {m[3]}" for m in MATRIX]


@pytest.fixture(autouse=True)
def isolated_db():
    prior_db_path = db.DB_PATH
    db.DB_PATH = TEST_DB
    db.init_db()
    proxy._key_record_cache.clear()
    yield
    db.DB_PATH = prior_db_path


@pytest.fixture()
def client():
    return TestClient(proxy.app)


def mint(scopes):
    return db.generate_key("developer", label="scope-matrix", scopes=scopes)["raw_key"]


def call_route(client, method, path, key, body):
    return client.request(method.upper(), path, headers={"x-api-key": key}, json=body)


def happy_path_patches(patch_key):
    """Patch route internals so a correctly-scoped request completes without
    real upstream servers. Scope checks always run before these are hit."""
    if patch_key == "discover":
        return [
            patch(
                "routes.mcp.discover_mcp_tools",
                new=AsyncMock(return_value={"ok": True, "total_tools": 0}),
            )
        ]
    if patch_key == "probe":
        return [
            patch(
                "routes.mcp.run_effective_permission_probe",
                new=AsyncMock(return_value={"ok": True}),
            )
        ]
    if patch_key == "readback":
        return [
            patch(
                "routes.mcp.run_effect_readback_observer",
                new=AsyncMock(return_value={"ok": True}),
            )
        ]
    return []


@pytest.mark.parametrize("method,path,body,required,patch_key", MATRIX, ids=MATRIX_IDS)
def test_wrong_scope_is_denied_with_403(
    client, method, path, body, required, patch_key
):
    """A key with every scope EXCEPT the required one must be rejected —
    ordinary runtime/read keys must not inherit other scopes."""
    wrong = [s for s in NON_ADMIN_SCOPES if s != required]
    key = mint(wrong)

    sentinels = [
        patch(
            "routes.mcp.run_effective_permission_probe",
            new=AsyncMock(side_effect=AssertionError("probe ran despite 403")),
        ),
        patch(
            "routes.mcp.run_effect_readback_observer",
            new=AsyncMock(side_effect=AssertionError("readback ran despite 403")),
        ),
        patch(
            "routes.mcp.discover_mcp_tools",
            new=AsyncMock(side_effect=AssertionError("discovery ran despite 403")),
        ),
    ]
    try:
        for sentinel in sentinels:
            sentinel.start()
        response = call_route(client, method, path, key, body)
    finally:
        for sentinel in sentinels:
            sentinel.stop()

    assert response.status_code == 403, (method, path, response.text)
    assert required in response.json().get("detail", ""), response.text


@pytest.mark.parametrize("method,path,body,required,patch_key", MATRIX, ids=MATRIX_IDS)
def test_correct_scope_reaches_normal_behavior(
    client, method, path, body, required, patch_key
):
    key = mint([required])
    patches = happy_path_patches(patch_key)
    try:
        for p in patches:
            p.start()
        response = call_route(client, method, path, key, body)
    finally:
        for p in patches:
            p.stop()

    assert response.status_code not in (401, 403), (method, path, response.text)
    assert response.status_code < 500, (method, path, response.text)


@pytest.mark.parametrize("method,path,body,required,patch_key", MATRIX, ids=MATRIX_IDS)
def test_admin_super_scope_reaches_every_route(
    client, method, path, body, required, patch_key
):
    """`admin` deliberately acts as a super-scope for backward-compatible
    administration."""
    key = mint(["admin"])
    patches = happy_path_patches(patch_key)
    try:
        for p in patches:
            p.start()
        response = call_route(client, method, path, key, body)
    finally:
        for p in patches:
            p.stop()

    assert response.status_code not in (401, 403), (method, path, response.text)
    assert response.status_code < 500, (method, path, response.text)


def test_new_keys_still_default_to_runtime_only():
    record = db.generate_key("free", label="matrix-default")
    assert db.lookup_key(record["raw_key"])["scopes"] == ["mcp.call", "mcp.read"]


def test_denied_mcp_call_makes_no_upstream_request_and_writes_no_audit(client):
    """Scope denial on /mcp/call must short-circuit BEFORE the gateway:
    no upstream HTTP request, no forwarded audit event."""
    server_id = "matrix-upstream-guard"
    db.register_mcp_server(
        server_id,
        {
            "url": "http://safe.example/mcp",
            "description": "Scope matrix upstream guard",
            "allowed_tools": ["read_document"],
            "blocked_tools": [],
            "rate_limit": 10,
        },
    )
    db.verify_mcp_server(server_id)
    key = mint([s for s in NON_ADMIN_SCOPES if s != "mcp.call"])

    try:
        before = len(db.list_mcp_audit_logs(500))
        with patch("core.mcp_gateway.httpx.AsyncClient") as upstream:
            response = call_route(
                client,
                "post",
                "/mcp/call",
                key,
                {
                    "server_id": server_id,
                    "tool_name": "read_document",
                    "arguments": {"doc_id": "d-1"},
                },
            )
        assert response.status_code == 403, response.text
        upstream.assert_not_called()
        after = len(db.list_mcp_audit_logs(500))
        assert after == before, "denied /mcp/call must not write audit events"
    finally:
        db.unregister_mcp_server(server_id)
