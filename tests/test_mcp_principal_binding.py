"""MCP calls derive authorization identity from the authenticated API key."""

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
os.environ["FIREWALL_DB_PATH"] = tempfile.mktemp(suffix="_principal_binding.db")

from core import db  # noqa: E402
from core.receipt import build_receipt  # noqa: E402
import proxy  # noqa: E402


def test_conflicting_request_role_is_ignored_in_favor_of_key_role():
    db.init_db()
    key = db.generate_key("free", label="devops principal", role="devops_agent")
    forwarded = AsyncMock(return_value={"ok": False, "error": "expected-test-stop"})
    with patch("routes.mcp.proxy_mcp_tool_call", new=forwarded):
        response = TestClient(proxy.app).post(
            "/mcp/call",
            headers={"x-api-key": key["raw_key"]},
            json={
                "server_id": "test-server",
                "tool_name": "run_command",
                "arguments": {"command": "whoami"},
                "role": "admin_agent",
            },
        )

    assert response.status_code == 200
    assert forwarded.await_args.kwargs["role"] == "devops_agent"
    assert forwarded.await_args.kwargs["principal_id"] == key["key_prefix"]


def test_audit_row_and_receipt_include_resolved_principal_and_role():
    db.init_db()
    saved = db.log_mcp_audit_event(
        {
            "server_id": "test-server",
            "tool_name": "read_document",
            "principal_id": "lf_free_abcd",
            "role": "readonly_agent",
            "action": "allow",
            "reason": "test",
        }
    )
    row = db.get_mcp_audit_log(saved["id"])
    receipt = build_receipt(row)

    assert row["principal_id"] == "lf_free_abcd"
    assert row["role"] == "readonly_agent"
    assert receipt["principal_id"] == "lf_free_abcd"
    assert receipt["agent_role"] == "readonly_agent"
