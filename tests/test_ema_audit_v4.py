"""Adversarial authority-aware audit v4 and receipt tests."""

from __future__ import annotations

import os
import tempfile
from datetime import datetime, timedelta, timezone

import pytest

from core import audit_envelope, db

os.environ.pop("DATABASE_URL", None)


@pytest.fixture(autouse=True)
def fresh_db():
    old_path = db.DB_PATH
    path = tempfile.mktemp(suffix="_ema_audit_v4.db")
    db.DB_PATH = path
    db.init_db()
    yield
    db.DB_PATH = old_path
    for suffix in ("", "-wal", "-shm"):
        try:
            os.unlink(path + suffix)
        except OSError:
            pass


def _verified_context(**overrides):
    context = {
        "transport": "streamable_http",
        "mcp_resource_uri": "https://interlock.example/experimental/mcp",
        "mcp_protocol_version": "2025-11-25",
        "mcp_method": "tools/call",
        "authority_mode": "exchanged_access_token",
        "authority_status": "verified",
        "authority_profile": "interlock-experimental-ema-jwt-at-v1",
        "authority_artifact_type": "mcp_access_token",
        "authority_signature_algorithm": "RS256",
        "authority_token_type": "at+jwt",
        "authority_validation_boundary": "interlock_gateway",
        "authority_verified_at": 1_700_000_000,
        "authority_issuer": "https://issuer.example",
        "authority_audiences": ["https://interlock.example/experimental/mcp"],
        "authority_resource": "https://interlock.example/experimental/mcp",
        "authority_scopes": ["files:read"],
        "authority_expires_at": 1_700_003_600,
        "authority_not_before": 1_699_999_900,
        "authority_issued_at": 1_699_999_950,
        "oauth_client_binding": "client-binding-value",
        "oauth_client_binding_alg": "hmac-sha256-v1",
        "oauth_client_binding_key_id": "client-2026-07",
        "delegated_subject_binding": "subject-binding-value",
        "delegated_subject_binding_alg": "hmac-sha256-v1",
        "delegated_subject_binding_key_id": "subject-2026-07",
        "interlock_service_principal_id": "interlock-gateway-prod",
        "downstream_service_principal_id": "downstream-docs-service",
        "token_binding": "call-specific-token-binding",
        "token_binding_alg": "hmac-sha256-v1",
        "token_binding_key_id": "token-2026-07",
        "downstream_auth_mode": "configured_service_credential",
        "inbound_authority_forwarded": False,
        "downstream_authority_evaluated": False,
        "authority_failure_code": "",
    }
    context.update(overrides)
    return context


def _event():
    return {
        "server_id": "ema-docs",
        "tool_name": "read_file",
        "principal_id": "",
        "role": "readonly_agent",
        "action": "allow",
        "matched_rule": "no_rule_matched",
        "reason": "Allowed by Interlock gateway policy.",
        "effects": ["read"],
        "side_effect": "read",
        "data_classes": [],
        "externality": "internal",
        "verification_level": "verified",
        "confidence": 0.9,
        "warnings": [],
        "argument_keys": ["path"],
        "argument_hash": "sha256:" + ("a" * 64),
        "drift_status": "active",
        "drift_severity": "none",
        "drift_action": "allow",
        "drift_types": [],
        "drift_reasons": [],
        "drift_baseline_hash": "sha256:" + ("b" * 64),
        "drift_current_hash": "sha256:" + ("b" * 64),
        "scan_time_ms": 1.25,
        "call_id": "gateway-call-1",
    }


def _log_v4(context=None):
    from core.ema_context import authority_audit_scope

    with authority_audit_scope(context or _verified_context()):
        return db.log_mcp_audit_event(_event())


def test_context_writes_v4_without_overloading_legacy_principal():
    saved = _log_v4()
    row = db.get_mcp_audit_log(saved["id"])
    assert row["hash_v"] == 4
    assert row["principal_id"] == ""
    assert row["oauth_client_binding"] == "client-binding-value"
    assert row["delegated_subject_binding"] == "subject-binding-value"
    assert row["interlock_service_principal_id"] == "interlock-gateway-prod"
    assert row["downstream_service_principal_id"] == "downstream-docs-service"
    assert row["inbound_authority_forwarded"] is False
    assert row["downstream_authority_evaluated"] is False
    assert db.verify_mcp_audit_record(saved["id"])["chain_verified"] is True


def test_legacy_writer_stays_v3_and_v1_v2_v3_verification_is_unchanged():
    saved = db.log_mcp_audit_event(_event())
    assert db.get_mcp_audit_log(saved["id"])["hash_v"] == 3
    assert db.verify_mcp_audit_record(saved["id"])["chain_verified"] is True
    assert db._MCP_HASH_VERSIONS == (1, 2, 3, 4)


def test_denied_unverified_authority_has_exact_null_defaults():
    context = _verified_context(
        authority_status="denied",
        authority_signature_algorithm=None,
        authority_token_type=None,
        authority_verified_at=None,
        authority_issuer=None,
        authority_audiences=None,
        authority_resource=None,
        authority_scopes=None,
        authority_expires_at=None,
        authority_not_before=None,
        authority_issued_at=None,
        oauth_client_binding=None,
        oauth_client_binding_alg=None,
        oauth_client_binding_key_id=None,
        delegated_subject_binding=None,
        delegated_subject_binding_alg=None,
        delegated_subject_binding_key_id=None,
        downstream_service_principal_id=None,
        token_binding=None,
        token_binding_alg=None,
        token_binding_key_id=None,
        downstream_auth_mode="none",
        authority_failure_code="invalid_signature",
    )
    saved = _log_v4(context)
    row = db.get_mcp_audit_log(saved["id"])
    for field in (
        "authority_verified_at",
        "authority_signature_algorithm",
        "authority_token_type",
        "authority_issuer",
        "authority_audiences",
        "authority_resource",
        "authority_scopes",
        "authority_expires_at",
        "authority_not_before",
        "authority_issued_at",
        "oauth_client_binding",
        "oauth_client_binding_alg",
        "oauth_client_binding_key_id",
        "delegated_subject_binding",
        "delegated_subject_binding_alg",
        "delegated_subject_binding_key_id",
        "downstream_service_principal_id",
        "token_binding",
        "token_binding_alg",
        "token_binding_key_id",
    ):
        assert row[field] is None
    assert row["interlock_service_principal_id"] == "interlock-gateway-prod"
    assert row["authority_failure_code"] == "invalid_signature"


def test_verified_authority_context_rejects_nonempty_legacy_principal():
    from core.ema_context import authority_audit_scope

    event = _event()
    event["principal_id"] = "client-id-is-not-an-employee"
    with authority_audit_scope(_verified_context()):
        with pytest.raises(ValueError, match="principal_id"):
            db.log_mcp_audit_event(event)


def _mutated_value(field, kind, original):
    if kind == audit_envelope.JSON_LIST:
        return '["tampered"]'
    if kind == audit_envelope.INT:
        return 0 if original not in (0, None) else 1
    if kind == audit_envelope.FLOAT:
        return 999.25
    if kind == audit_envelope.BOOL:
        return not bool(original)
    return "tampered-value"


@pytest.mark.parametrize(
    "field,kind",
    audit_envelope.MCP_AUDIT_V4_FIELDS,
    ids=[name for name, _ in audit_envelope.MCP_AUDIT_V4_FIELDS],
)
def test_every_v4_field_is_hash_bound(field, kind):
    saved = _log_v4()
    row = db.get_mcp_audit_log(saved["id"])
    value = _mutated_value(field, kind, row.get(field))
    with db._db_lock, db.get_conn() as conn:
        conn.execute(
            f"UPDATE mcp_audit_log SET {field} = ? WHERE id = ?",
            (value, saved["id"]),
        )
    assert db.verify_mcp_audit_record(saved["id"])["chain_verified"] is False


def test_v4_receipt_uses_explicit_identities_and_gateway_boundary_wording():
    from core.receipt import build_receipt

    saved = _log_v4()
    row = db.get_mcp_audit_log(saved["id"])
    receipt = build_receipt(row, chain_verified=True)
    assert receipt["version"] == "4"
    assert "principal_id" not in receipt
    assert receipt["authority"]["oauth_client_binding"] == "client-binding-value"
    assert receipt["authority"]["delegated_subject_binding"] == "subject-binding-value"
    assert receipt["authority"]["token_binding"] == "call-specific-token-binding"
    assert receipt["authority"]["inbound_authority_forwarded"] is False
    assert receipt["authority"]["downstream_authority_evaluated"] is False
    assert receipt["authority"]["statement"] == (
        "Interlock validated delegated authority at its gateway. "
        "Interlock attempted the downstream call with a separately configured "
        "service identity; this receipt does not prove that the downstream "
        "server evaluated the employee's delegated scopes."
    )


def test_v4_receipt_authority_tampering_fails_ordinary_verification():
    from core.receipt import build_receipt
    from core.receipt_verify import verify_receipt_against_context

    saved = _log_v4()
    row = db.get_mcp_audit_log(saved["id"])
    receipt = build_receipt(row, chain_verified=True)
    receipt["authority"]["oauth_client_binding_key_id"] = "attacker-key"
    context = {
        "server_id": row["server_id"],
        "tool_name": row["tool_name"],
        "argument_hash": row["argument_hash"],
        "call_id": row["call_id"],
        "surface_hash": row["drift_current_hash"],
    }
    result = verify_receipt_against_context(
        context,
        presented_receipt=receipt,
    )
    assert result["verified"] is False
    assert any(
        item["field"] == "receipt_authority.oauth_client_binding_key_id"
        for item in result["mismatches"]
    )


def test_historical_v4_receipt_verification_does_not_need_retired_hmac_keys():
    from core.receipt import build_receipt
    from core.receipt_verify import verify_receipt_against_context

    saved = _log_v4()
    row = db.get_mcp_audit_log(saved["id"])
    receipt = build_receipt(row, chain_verified=True)
    context = {
        "server_id": row["server_id"],
        "tool_name": row["tool_name"],
        "argument_hash": row["argument_hash"],
        "call_id": row["call_id"],
        "surface_hash": row["drift_current_hash"],
    }
    # Ordinary verification deliberately has no settings/key-ring input.
    result = verify_receipt_against_context(
        context,
        presented_receipt=receipt,
    )
    assert result["verified"] is True


def test_ordinary_receipt_verification_has_no_bearer_token_parameter():
    import inspect

    from core.receipt_verify import verify_receipt_against_context

    parameters = inspect.signature(verify_receipt_against_context).parameters
    assert "token" not in parameters
    assert "bearer" not in parameters


def test_v4_rows_survive_retention_checkpoint_pruning_and_replay_verification():
    from core.ema_context import authority_audit_scope

    old = _event()
    old["ts"] = (datetime.now(timezone.utc) - timedelta(days=40)).isoformat()
    old["call_id"] = "old-v4-call"
    with authority_audit_scope(
        _verified_context(),
        call_id=old["call_id"],
    ):
        removed = db.log_mcp_audit_event(old)

    kept = _event()
    kept["ts"] = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    kept["call_id"] = "kept-v4-call"
    with authority_audit_scope(
        _verified_context(),
        call_id=kept["call_id"],
    ):
        retained = db.log_mcp_audit_event(kept)

    result = db.prune_retention(
        {
            "scan_history_days": 30,
            "mcp_audit_days": 30,
            "admin_audit_days": 30,
            "usage_log_days": 30,
        },
        actor={
            "actor_auth_type": "scoped_token",
            "actor_role": "operator",
        },
    )
    assert result["mcp_audit_deleted"] == 1
    assert db.get_mcp_audit_log(removed["id"]) is None
    assert db.get_mcp_audit_log(retained["id"])["hash_v"] == 4
    assert db.verify_mcp_audit_record(retained["id"])["chain_verified"] is True
    assert db.verify_audit_chain()["valid"] is True
