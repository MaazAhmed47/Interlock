"""
Unit tests for the offline demo mock MCP server's phase logic.

The mock backs the two live-proven drift classes without any network:

  /docs — capability drift: phase 1 serves a clean read-only read_document
          (plus a list_documents control tool that never changes); phase 2
          serves the same tool NAME with a broader export/PII surface.
  /crm  — behavioral drift: the update_record schema is IDENTICAL in both
          phases; only the tools/call behavior flips (403 -> 200).

Pure functions are imported directly — no sockets involved.

Run: python -m pytest tests/test_offline_demo_mock.py -q
"""

import importlib.util
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
SERVER_PY = ROOT / "demo" / "offline" / "mock_server" / "server.py"
COMPOSE_YML = ROOT / "demo" / "offline" / "docker-compose.yml"

spec = importlib.util.spec_from_file_location("offline_mock_server", SERVER_PY)
mock = importlib.util.module_from_spec(spec)
sys.modules["offline_mock_server"] = mock
spec.loader.exec_module(mock)


def _tool_names(tools):
    return sorted(t["name"] for t in tools)


def test_compose_gateway_explicitly_allowlists_the_bundled_mock_host():
    compose = yaml.safe_load(COMPOSE_YML.read_text(encoding="utf-8"))
    gateway_environment = compose["services"]["gateway"]["environment"]

    assert gateway_environment["MCP_REGISTRY_ALLOWED_HOSTS"] == "mcp-mock"
    assert not gateway_environment.get("MCP_REGISTRY_ALLOWED_HOST_SUFFIXES")


def test_compose_publishes_demo_ports_on_loopback_only():
    compose = yaml.safe_load(COMPOSE_YML.read_text(encoding="utf-8"))
    expected_ports = {
        "gateway": ["127.0.0.1:8001:8001"],
        "dashboard": ["127.0.0.1:8080:80"],
        "mcp-mock": ["127.0.0.1:9100:9100"],
    }

    assert {
        service: compose["services"][service]["ports"] for service in expected_ports
    } == expected_ports


def test_compose_demo_runner_waits_for_successful_seeding():
    compose = yaml.safe_load(COMPOSE_YML.read_text(encoding="utf-8"))

    assert compose["services"]["demo-runner"]["depends_on"]["seeder"] == {
        "condition": "service_completed_successfully"
    }


# ── /docs capability drift ────────────────────────────────────────────────────


def test_docs_phase1_is_clean_read_only():
    tools = mock.tools_for("/docs", 1)
    assert _tool_names(tools) == ["list_documents", "read_document"]
    read_doc = next(t for t in tools if t["name"] == "read_document")
    assert read_doc["annotations"]["readOnlyHint"] is True
    assert "email" not in read_doc["inputSchema"]["properties"]
    assert "_meta" not in read_doc


def test_docs_phase2_mutates_read_document_same_name():
    tools = mock.tools_for("/docs", 2)
    assert _tool_names(tools) == ["list_documents", "read_document"]
    read_doc = next(t for t in tools if t["name"] == "read_document")
    assert read_doc["annotations"]["readOnlyHint"] is False
    assert "email" in read_doc["inputSchema"]["properties"]
    meta = read_doc["_meta"]["interlock"]
    assert "export" in meta["effects"]
    assert "pii" in meta["data_classes"]
    assert meta["externality"] == "external"


def test_docs_control_tool_never_changes():
    control_1 = next(
        t for t in mock.tools_for("/docs", 1) if t["name"] == "list_documents"
    )
    control_2 = next(
        t for t in mock.tools_for("/docs", 2) if t["name"] == "list_documents"
    )
    assert (
        control_1 == control_2
    ), "the control tool must be byte-identical across phases"


def test_docs_calls_succeed():
    status, body = mock.call_result("/docs", "list_documents", {}, 1)
    assert status == 200
    assert "result" in body
    status, body = mock.call_result("/docs", "read_document", {"doc_id": "a"}, 1)
    assert status == 200


# ── /crm behavioral drift (same schema, 403 -> 200) ──────────────────────────


def test_crm_schema_is_identical_across_phases():
    assert mock.tools_for("/crm", 1) == mock.tools_for(
        "/crm", 2
    ), "behavioral drift means the SCHEMA must not change between phases"


def test_crm_phase1_denies_update_record():
    status, body = mock.call_result("/crm", "update_record", {"record_id": "r1"}, 1)
    assert status == 403
    assert "forbidden" in str(body.get("error", {})).lower()


def test_crm_phase2_allows_update_record():
    status, body = mock.call_result("/crm", "update_record", {"record_id": "r1"}, 2)
    assert status == 200
    assert "result" in body


# ── phase state and path families ─────────────────────────────────────────────


def test_phase_state_is_per_path_instance():
    mock.set_phase("/crm/smoke-abc", 2)
    assert mock.get_phase("/crm/smoke-abc") == 2
    assert mock.get_phase("/crm") == 1, "other instances must stay isolated"
    mock.set_phase("/crm/smoke-abc", 1)


def test_unknown_tool_returns_jsonrpc_error():
    status, body = mock.call_result("/docs", "no_such_tool", {}, 1)
    assert status == 200
    assert body.get("error")


def test_path_family_resolution():
    assert mock.path_family("/crm/smoke-1") == "crm"
    assert mock.path_family("/docs") == "docs"
    assert mock.path_family("/docs/anything") == "docs"
    assert mock.path_family("/") == "docs"
