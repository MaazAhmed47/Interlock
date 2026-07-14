"""
Tests for manual effective-permission drift probes.

Run: python -m pytest tests/test_effective_permission_probes.py -q
"""

import asyncio
import json
import os
import re
import sys
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

TEST_DB = tempfile.mktemp(suffix="_effective_permission_probe_test.db")
os.environ["FIREWALL_DB_PATH"] = TEST_DB
os.environ["PYTHON_DOTENV_DISABLED"] = "1"

from core import db  # noqa: E402
from core import drift_evidence  # noqa: E402
from core import receipt as receipt_mod  # noqa: E402
from core.effective_permission import (  # noqa: E402
    arguments_hash,
    evaluate_effective_permission_probe,
    normalize_observed_result,
)
from core.mcp_drift import classify_tool_drift  # noqa: E402
import proxy  # noqa: E402

try:
    import jsonschema
except ImportError:  # pragma: no cover - optional dependency in local envs
    jsonschema = None


GENESYS_TOOL = {
    "name": "call_genesys_api",
    "description": "Call a Genesys API endpoint.",
    "inputSchema": {
        "type": "object",
        "properties": {
            "method": {"type": "string"},
            "path": {"type": "string"},
            "body": {"type": "object"},
        },
        "required": ["method", "path"],
    },
}

GENESYS_METADATA = {
    "effects": ["api_call"],
    "side_effect": "unknown",
    "data_classes": ["crm"],
    "externality": "external",
    "identity_mode": "authenticated_user",
    "required_scopes": ["genesys.api"],
    "verification_level": "interlock_meta",
    "confidence": 0.95,
    "warnings": [],
}

PROBE_ARGS = {
    "method": "POST",
    "path": "/api/v2/conversations/calls/canary/probe",
    "body": {"canary": True, "token_like": "argument-secret-value"},
}

SCHEMA_PATH = (
    ROOT
    / "interlock-web"
    / "public"
    / "schemas"
    / "effective-permission-drift-record.v1.json"
)


@pytest.fixture(autouse=True)
def isolated_db(monkeypatch):
    # The registry allowlist rejects unknown external hosts; permit the
    # fixture host explicitly, the same way test_hosted_safety.py does.
    monkeypatch.setenv("MCP_REGISTRY_ALLOWED_HOSTS", "genesys.example")
    # Upstream auth env vars must be explicitly allowlisted (default deny).
    monkeypatch.setenv("MCP_UPSTREAM_AUTH_ALLOWED_ENV_VARS", "TEST_MCP_PROBE_TOKEN")
    db.DB_PATH = TEST_DB
    db.init_db()
    key = db.generate_key("free", label="probe-test", scopes=["mcp.probe"])["raw_key"]
    monkeypatch.setenv("TEST_MCP_PROBE_TOKEN", "super-secret-token")
    yield key
    for suffix in ("", "-wal", "-shm"):
        try:
            os.remove(TEST_DB + suffix)
        except OSError:
            pass


def seed_probe_server(server_id="_probe_genesys"):
    db.register_mcp_server(
        server_id,
        {
            "url": "http://genesys.example/mcp",
            "description": "Genesys probe test server",
            "allowed_tools": ["call_genesys_api"],
            "blocked_tools": [],
            "rate_limit": 10,
            "auth_type": "bearer",
            "auth_token_env": "TEST_MCP_PROBE_TOKEN",
            # Probes require stored non-production, probe-enabled state.
            "environment": "non_production",
            "probes_enabled": True,
        },
    )
    db.verify_mcp_server(server_id)
    db.upsert_mcp_tool_metadata(server_id, GENESYS_TOOL, GENESYS_METADATA)
    return server_id


def probe_contract(expected="denied", expected_status_code=403):
    return {
        "probe_id": "genesys-deny-check",
        "server_id": "genesys",
        "tool_name": "call_genesys_api",
        "argument_hash": arguments_hash(PROBE_ARGS),
        "expected_outcome": expected,
        "expected_status_code": expected_status_code,
        "expected_error_fingerprint": "forbidden",
        "non_production": True,
        "safety_note": "Canary tenant mutation denied by design.",
    }


def evaluate_status(status_code, expected="denied", body=None, headers=None):
    observed = normalize_observed_result(
        status_code=status_code,
        json_body=body,
        headers=headers,
    )
    return evaluate_effective_permission_probe(
        probe_contract(expected=expected, expected_status_code=403), observed
    )


def validate_against_effective_permission_schema(record):
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    validator = getattr(jsonschema, "Draft202012Validator", None)
    if validator is not None:
        validator.check_schema(schema)
        validator(schema).validate(record)
        return

    assert set(record) == set(schema["properties"])
    assert set(schema["required"]).issubset(record)
    for field, rules in schema["properties"].items():
        value = record[field]
        if "const" in rules:
            assert value == rules["const"]
        if "enum" in rules:
            assert value in rules["enum"]
        if rules.get("type") == "string":
            assert isinstance(value, str)
        if rules.get("type") == "array":
            assert isinstance(value, list)
            assert all(isinstance(item, str) and item for item in value)
        if "pattern" in rules:
            assert re.match(rules["pattern"], value)


def test_same_manifest_schema_has_no_visible_drift():
    drift = classify_tool_drift(
        GENESYS_TOOL,
        dict(GENESYS_TOOL),
        GENESYS_METADATA,
        dict(GENESYS_METADATA),
    )

    assert drift["severity"] == "none"
    assert drift["action"] == "allow"
    assert drift["types"] == []


def test_expected_denied_observed_403_has_no_effective_permission_drift():
    observed = normalize_observed_result(
        status_code=403,
        json_body={"error": {"message": "Forbidden: missing scope"}},
    )

    result = evaluate_effective_permission_probe(probe_contract(), observed)

    assert result["observed_outcome"] == "denied"
    assert result["drift_detected"] is False
    assert result["severity"] == "none"
    assert result["decision"] == "allow"


def test_expected_denied_observed_200_is_behavioral_scope_drift():
    observed = normalize_observed_result(
        status_code=200,
        json_body={"result": {"id": "call-created"}},
    )

    result = evaluate_effective_permission_probe(probe_contract(), observed)

    assert result["observed_outcome"] == "allowed"
    assert result["drift_detected"] is True
    assert result["finding_type"] == "effective_permission_expansion"
    assert result["finding_types"] == [
        "effective_permission_expansion",
        "behavioral_scope_drift",
    ]
    assert result["severity"] == "high"
    assert result["decision"] == "quarantine"


@pytest.mark.parametrize("initial_denial_status", [401, 403])
def test_expected_denied_to_200_is_auth_scope_drift(initial_denial_status):
    probe = probe_contract(
        expected="denied", expected_status_code=initial_denial_status
    )
    observed = normalize_observed_result(
        status_code=200,
        json_body={"result": {"id": "call-created"}},
    )

    result = evaluate_effective_permission_probe(probe, observed)

    assert result["observed_outcome"] == "allowed"
    assert result["drift_detected"] is True
    assert result["finding_type"] == "effective_permission_expansion"
    assert result["severity"] == "high"
    assert result["decision"] == "quarantine"


@pytest.mark.parametrize("status_code", [201, 202, 204])
def test_expected_denied_to_accepted_status_is_permission_expansion(status_code):
    result = evaluate_status(status_code, body={} if status_code != 204 else None)

    assert result["observed_outcome"] == "accepted"
    assert result["drift_detected"] is True
    assert result["finding_type"] == "effective_permission_expansion"
    assert result["decision"] == "quarantine"


@pytest.mark.parametrize("status_code", [401, 403])
def test_expected_denied_observed_denied_has_no_drift(status_code):
    result = evaluate_status(status_code, body={"error": {"message": "auth denied"}})

    assert result["observed_outcome"] == "denied"
    assert result["drift_detected"] is False
    assert result["decision"] == "allow"
    assert result["finding_types"] == []


@pytest.mark.parametrize(
    ("status_code", "expected_outcome", "expected_error"),
    [
        (404, "unknown", "not_found"),
        (409, "unknown", "conflict"),
        (429, "inconclusive_rate_limited", "rate_limited"),
        (500, "inconclusive_upstream_error", "http_500"),
    ],
)
def test_inconclusive_or_unknown_statuses_do_not_quarantine(
    status_code, expected_outcome, expected_error
):
    result = evaluate_status(status_code, body={"error": {"message": "not allowed"}})

    assert result["observed_outcome"] == expected_outcome
    assert result["observed_error_class"] == expected_error
    assert result["drift_detected"] is False
    assert result["decision"] == "monitor"


def test_timeout_and_network_error_are_inconclusive_no_quarantine():
    for error_class in ("timeout", "network_error"):
        observed = normalize_observed_result(error_class=error_class)
        result = evaluate_effective_permission_probe(probe_contract(), observed)

        assert result["observed_outcome"] == "inconclusive"
        assert result["observed_error_class"] == error_class
        assert result["drift_detected"] is False
        assert result["decision"] == "monitor"


def test_malformed_upstream_response_is_inconclusive_probe_error():
    observed = normalize_observed_result(status_code=200, json_body=None)
    result = evaluate_effective_permission_probe(probe_contract(), observed)

    assert result["observed_outcome"] == "inconclusive_probe_error"
    assert result["observed_error_class"] == "malformed_response"
    assert result["drift_detected"] is False
    assert result["decision"] == "monitor"


def test_auth_login_redirect_is_denied_auth_required():
    result = evaluate_status(
        302,
        body={},
        headers={"location": "https://login.example.com/oauth/authorize"},
    )

    assert result["observed_outcome"] == "denied"
    assert result["observed_error_class"] == "auth_required"
    assert result["drift_detected"] is False


def test_expected_allowed_observed_denied_is_permission_regression_monitor():
    result = evaluate_status(
        403,
        expected="allowed",
        body={"error": {"message": "Forbidden"}},
    )

    assert result["observed_outcome"] == "denied"
    assert result["drift_detected"] is True
    assert result["finding_type"] == "permission_regression"
    assert result["finding_types"] == ["permission_regression"]
    assert result["severity"] == "moderate"
    assert result["decision"] == "monitor"


def test_probe_drift_run_writes_receipt_evidence(isolated_db):
    server_id = seed_probe_server()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "result": {"id": "call-created", "secret": "response-secret-value"}
    }
    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.post = AsyncMock(return_value=mock_resp)

    request = proxy.MCPEffectivePermissionProbeRequest(
        probe_id="probe-genesys-muted-call",
        tool_name="call_genesys_api",
        arguments=PROBE_ARGS,
        expected_outcome="denied",
        expected_status_code=403,
        expected_error_fingerprint="forbidden",
        non_production=True,
        safety_note="Canary-only Genesys tenant. The target call id is synthetic.",
    )

    with patch("core.effective_permission.httpx.AsyncClient", return_value=mock_client):
        result = asyncio.run(
            proxy.mcp_run_effective_permission_probe(
                server_id,
                request=request,
                x_api_key=isolated_db,
            )
        )

    assert result["ok"] is True
    assert result["evaluation"]["drift_detected"] is True
    assert result["evaluation"]["decision"] == "quarantine"
    assert result["evaluation"]["observed_outcome"] == "allowed"
    assert result["probe"]["argument_hash"] == arguments_hash(PROBE_ARGS)
    assert "arguments" not in result["probe"]

    stored_tool = db.lookup_mcp_tool_metadata(server_id, "call_genesys_api")
    assert stored_tool["status"] == "quarantined"
    assert stored_tool["drift_action"] == "quarantine"
    assert "behavioral_scope_drift" in stored_tool["drift_types"]

    row = db.list_mcp_audit_logs(limit=1)[0]
    assert row["probe_id"] == "probe-genesys-muted-call"
    assert row["server_id"] == server_id
    assert row["tool_name"] == "call_genesys_api"
    assert row["action"] == "quarantine"
    assert row["matched_rule"] == "effective_permission_probe"
    assert row["blocked_by"] == "effective_permission_probe"
    assert row["drift_severity"] == "high"
    assert "effective_permission_expansion" in row["drift_types"]
    assert row["argument_hash"] == arguments_hash(PROBE_ARGS)
    assert row["expected_outcome"] == "denied"
    assert row["expected_status_code"] == 403
    assert row["observed_outcome"] == "allowed"
    assert row["observed_status_code"] == 200

    receipt = receipt_mod.build_receipt(row, chain_verified=True)
    assert receipt["integrity_hash"] == row["integrity_hash"]
    assert receipt["chain_verified"] is True
    assert "effective_permission_expansion" in receipt["detections"]
    assert "behavioral_scope_drift" in receipt["detections"]
    assert "tool_definition_drift" not in receipt["detections"]
    evidence = receipt["drift_evidence"]
    assert evidence is not None
    assert evidence["evidence_ref"]["type"] == "effective-permission-drift"
    assert evidence["record"]["probe_id"] == "probe-genesys-muted-call"
    assert evidence["record"]["server_id"] == server_id
    assert evidence["record"]["tool_name"] == "call_genesys_api"
    assert evidence["record"]["argument_hash"] == arguments_hash(PROBE_ARGS)
    assert evidence["record"]["expected_outcome"] == "denied"
    assert evidence["record"]["expected_status_code"] == "403"
    assert evidence["record"]["observed_outcome"] == "allowed"
    assert evidence["record"]["observed_status_code"] == "200"
    assert evidence["record"]["observed_error_class"] == ""
    assert evidence["record"]["finding_type"] == "effective_permission_expansion"
    assert evidence["record"]["diff_classification"] == "auth-scope"
    assert evidence["record"]["severity"] == "high"
    assert evidence["record"]["decision"] == "quarantine"
    assert evidence["record"]["created_at"]
    verified = drift_evidence.verify_effective_permission_record(
        evidence["record"], evidence["evidence_ref"]["digest"]
    )
    assert verified["verified"] is True

    validate_against_effective_permission_schema(evidence["record"])


def test_probe_response_returns_real_persisted_audit_id_when_adapter_reports_zero(
    isolated_db, monkeypatch
):
    server_id = seed_probe_server("_probe_zero_adapter_id")
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"result": {"id": "call-created"}}
    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.post = AsyncMock(return_value=mock_resp)

    original_log = db.log_mcp_audit_event

    def postgres_style_zero_id(event):
        row = original_log(event)
        returned = dict(row)
        returned["id"] = 0
        return returned

    monkeypatch.setattr(db, "log_mcp_audit_event", postgres_style_zero_id)

    request = proxy.MCPEffectivePermissionProbeRequest(
        probe_id="probe-zero-adapter-id",
        tool_name="call_genesys_api",
        arguments=PROBE_ARGS,
        expected_outcome="denied",
        expected_status_code=403,
        non_production=True,
        safety_note="Canary-only run against synthetic data.",
    )

    with patch("core.effective_permission.httpx.AsyncClient", return_value=mock_client):
        result = asyncio.run(
            proxy.mcp_run_effective_permission_probe(
                server_id,
                request=request,
                x_api_key=isolated_db,
            )
        )

    persisted = [
        row
        for row in db.list_mcp_audit_logs(limit=10)
        if row["probe_id"] == "probe-zero-adapter-id"
    ][0]

    assert persisted["id"] > 0
    assert result["evidence"]["audit_id"] == persisted["id"]
    stored_probe = db.lookup_mcp_permission_probe("probe-zero-adapter-id")
    assert stored_probe["last_audit_id"] == persisted["id"]


def test_probe_storage_excludes_tokens_headers_arguments_and_response_body(isolated_db):
    server_id = seed_probe_server("_probe_no_secret_storage")
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "result": {"id": "call-created", "secret": "response-secret-value"}
    }
    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.post = AsyncMock(return_value=mock_resp)

    request = proxy.MCPEffectivePermissionProbeRequest(
        probe_id="probe-no-secret-storage",
        tool_name="call_genesys_api",
        arguments=PROBE_ARGS,
        expected_outcome="denied",
        non_production=True,
        safety_note="Canary-only run against synthetic data.",
    )

    with patch("core.effective_permission.httpx.AsyncClient", return_value=mock_client):
        result = asyncio.run(
            proxy.mcp_run_effective_permission_probe(
                server_id,
                request=request,
                x_api_key=isolated_db,
            )
        )

    persisted = db.lookup_mcp_permission_probe("probe-no-secret-storage")
    row = db.list_mcp_audit_logs(limit=1)[0]
    stored = json.dumps(
        {"probe": persisted, "audit": row, "response": result},
        sort_keys=True,
        default=str,
    )

    assert persisted["argument_hash"] == arguments_hash(PROBE_ARGS)
    assert "arguments" not in persisted
    assert row["argument_keys"] == []
    assert "argument-secret-value" not in stored
    assert "super-secret-token" not in stored
    assert "Authorization" not in stored
    assert "Bearer" not in stored
    assert "response-secret-value" not in stored


def test_inconclusive_probe_run_does_not_quarantine(isolated_db):
    server_id = seed_probe_server("_probe_inconclusive")
    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.post = AsyncMock(side_effect=httpx.TimeoutException("timeout"))

    request = proxy.MCPEffectivePermissionProbeRequest(
        probe_id="probe-timeout",
        tool_name="call_genesys_api",
        arguments=PROBE_ARGS,
        expected_outcome="denied",
        expected_status_code=403,
        non_production=True,
        safety_note="Canary-only run against synthetic data.",
    )

    with patch("core.effective_permission.httpx.AsyncClient", return_value=mock_client):
        result = asyncio.run(
            proxy.mcp_run_effective_permission_probe(
                server_id,
                request=request,
                x_api_key=isolated_db,
            )
        )

    assert result["evaluation"]["observed_outcome"] == "inconclusive"
    assert result["evaluation"]["drift_detected"] is False
    assert result["evaluation"]["decision"] == "monitor"
    stored_tool = db.lookup_mcp_tool_metadata(server_id, "call_genesys_api")
    assert stored_tool["status"] == "active"
    assert stored_tool["drift_action"] == "allow"


def test_probe_requires_registry_probe_enablement(isolated_db):
    """The stored registry state is the authorization decision. A request-body
    flag of non_production=true cannot enable probes on a production server."""
    server_id = seed_probe_server("_probe_requires_canary")
    db.set_mcp_server_environment(server_id, "production", probes_enabled=False)
    request = proxy.MCPEffectivePermissionProbeRequest(
        probe_id="probe-prod-rejected",
        tool_name="call_genesys_api",
        arguments=PROBE_ARGS,
        expected_outcome="denied",
        non_production=True,
        safety_note="This should be rejected by the registry gate.",
    )

    with pytest.raises(proxy.HTTPException) as exc:
        asyncio.run(
            proxy.mcp_run_effective_permission_probe(
                server_id,
                request=request,
                x_api_key=isolated_db,
            )
        )

    assert exc.value.status_code == 403
