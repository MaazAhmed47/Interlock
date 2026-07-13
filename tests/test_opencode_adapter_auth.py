"""OpenCode example must follow server-bound MCP authorization semantics."""

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ADAPTER_PATH = ROOT / "examples" / "opencode" / "interlock_mcp_adapter.py"


def _load_adapter():
    spec = importlib.util.spec_from_file_location("interlock_mcp_adapter", ADAPTER_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_mcp_call_schema_and_payload_do_not_accept_caller_role(monkeypatch):
    adapter = _load_adapter()
    tool = next(
        item for item in adapter._tools() if item["name"] == "interlock_mcp_call"
    )
    assert "role" not in tool["inputSchema"]["properties"]

    captured = {}

    def fake_request(method, path, payload=None, *, admin=False):
        captured.update(method=method, path=path, payload=payload, admin=admin)
        return {"ok": True}

    monkeypatch.setattr(adapter, "_request", fake_request)
    adapter._call_tool(
        "interlock_mcp_call",
        {
            "server_id": "trusted-filesystem",
            "tool_name": "read_file",
            "arguments": {"path": "demo.txt"},
            "role": "admin_agent",
        },
    )

    assert captured["payload"] == {
        "server_id": "trusted-filesystem",
        "tool_name": "read_file",
        "arguments": {"path": "demo.txt"},
    }
    assert captured["admin"] is False


def test_global_audit_tool_uses_admin_key_path(monkeypatch):
    adapter = _load_adapter()
    captured = {}

    def fake_request(method, path, payload=None, *, admin=False):
        captured.update(method=method, path=path, admin=admin)
        return {"events": []}

    monkeypatch.setattr(adapter, "_request", fake_request)
    adapter._call_tool("interlock_mcp_audit", {"limit": 10})

    assert captured == {
        "method": "GET",
        "path": "/mcp/audit?limit=10",
        "admin": True,
    }
