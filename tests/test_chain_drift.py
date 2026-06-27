"""Tests for multi-step MCP chain drift analysis.

Run: python3 -m pytest tests/test_chain_drift.py -q -s
"""

import json
import os
import sys
import tempfile
from pathlib import Path

import pytest

try:
    import jsonschema
except ImportError:  # pragma: no cover
    jsonschema = None

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import core.db as db
from core import receipt as receipt_builder
from core.chain_drift import (
    build_chain_drift_record,
    build_chain_profile,
    classify_chain_drift,
    compute_chain_drift_digest,
)

SCHEMA_PATH = (
    Path(__file__).resolve().parents[1]
    / "interlock-web"
    / "public"
    / "schemas"
    / "chain-drift-record.v1.json"
)


def validate_against_chain_schema(record):
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    validator = getattr(jsonschema, "Draft202012Validator", None)
    if validator is not None:
        validator.check_schema(schema)
        validator(schema).validate(record)
        return
    assert set(schema["required"]).issubset(record)
    assert record["record_type"] == "interlock.chain-drift-record"
    assert record["schema_version"] == "1"


def step(
    tool_name, *, effects=None, data_classes=None, externality="internal", args=None
):
    return {
        "server_id": "chain-test",
        "tool_name": tool_name,
        "arguments": args or {},
        "effects": effects or ["read"],
        "data_classes": data_classes or [],
        "externality": externality,
    }


def test_read_only_chain_is_allowed():
    steps = [
        step(
            "list_customers",
            data_classes=["customer"],
            args={"tenant": "secret-tenant"},
        ),
        step("summarize_customers", effects=["read"], data_classes=["customer"]),
    ]

    decision = classify_chain_drift(steps)

    assert decision["drift_detected"] is False
    assert decision["severity"] == "none"
    assert decision["action"] == "allow"
    assert decision["types"] == []


def test_sensitive_read_followed_by_external_send_is_critical_chain_drift():
    steps = [
        step(
            "read_inbox",
            effects=["read"],
            data_classes=["email", "pii"],
            args={"q": "secret-query"},
        ),
        step(
            "post_to_slack",
            effects=["sent"],
            externality="external",
            args={"channel": "secret-channel"},
        ),
    ]

    decision = classify_chain_drift(steps)

    assert decision["drift_detected"] is True
    assert decision["severity"] == "critical"
    assert decision["action"] == "deny"
    assert "chain_sensitive_read_to_external_effect" in decision["types"]
    assert "secret-query" not in json.dumps(decision)
    assert "secret-channel" not in json.dumps(decision)


def test_plan_then_apply_deploy_delete_or_charge_is_critical_chain_drift():
    steps = [
        step(
            "terraform_plan",
            effects=["plan"],
            data_classes=["infra"],
            args={"workspace": "secret-ws"},
        ),
        step(
            "terraform_apply", effects=["applied", "deployed"], data_classes=["infra"]
        ),
        step("cleanup_old_stack", effects=["deleted"], data_classes=["infra"]),
        step("charge_customer", effects=["charged"], data_classes=["financial"]),
    ]

    decision = classify_chain_drift(steps)

    assert decision["drift_detected"] is True
    assert decision["severity"] == "critical"
    assert decision["action"] == "deny"
    assert "chain_preview_to_deploy" in decision["types"]
    assert "chain_preview_to_destructive" in decision["types"]
    assert "chain_preview_to_money_movement" in decision["types"]


def test_secret_read_followed_by_execution_is_critical_chain_drift():
    steps = [
        step(
            "read_secret",
            effects=["read"],
            data_classes=["secret", "api_key"],
            args={"name": "prod-token"},
        ),
        step(
            "run_shell",
            effects=["executed"],
            externality="external",
            args={"cmd": "echo secret"},
        ),
    ]

    decision = classify_chain_drift(steps)

    assert decision["drift_detected"] is True
    assert decision["severity"] == "critical"
    assert decision["action"] == "deny"
    assert "chain_secret_to_execution" in decision["types"]
    assert "prod-token" not in json.dumps(decision)
    assert "echo secret" not in json.dumps(decision)


def test_chain_profile_and_record_are_evidence_safe_and_schema_valid():
    steps = [
        step(
            "read_inbox",
            effects=["read"],
            data_classes=["email"],
            args={"q": "secret-query"},
        ),
        step(
            "send_email",
            effects=["sent"],
            externality="external",
            args={"to": "person@example.com"},
        ),
    ]
    profile = build_chain_profile(steps)
    decision = classify_chain_drift(steps)
    record = build_chain_drift_record(
        chain_id="chain-proof-1",
        chain_profile_hash=profile["profile_hash"],
        finding_types=decision["types"],
        severity=decision["severity"],
        decision=decision["action"],
    )

    encoded = json.dumps(profile, sort_keys=True) + json.dumps(record, sort_keys=True)
    assert profile["profile_hash"].startswith("sha256:")
    assert record["record_type"] == "interlock.chain-drift-record"
    assert record["diff_classification"] == "chain"
    validate_against_chain_schema(record)
    assert compute_chain_drift_digest(record).startswith("sha256:")
    assert "secret-query" not in encoded
    assert "person@example.com" not in encoded


def test_chain_receipt_uses_chain_drift_evidence():
    tmp_db = tempfile.mktemp(suffix="_chain_drift_receipt_test.db")
    db.DB_PATH = tmp_db
    for suffix in ("", "-wal", "-shm"):
        try:
            os.unlink(tmp_db + suffix)
        except OSError:
            pass
    db.init_db()
    try:
        steps = [
            step(
                "read_inbox",
                effects=["read"],
                data_classes=["email"],
                args={"q": "secret-query"},
            ),
            step(
                "send_email",
                effects=["sent"],
                externality="external",
                args={"to": "person@example.com"},
            ),
        ]
        profile = build_chain_profile(steps)
        decision = classify_chain_drift(steps)
        row = db.log_mcp_audit_event(
            {
                "server_id": "multi-step-chain",
                "tool_name": "chain-proof-1",
                "role": "operator",
                "action": decision["action"],
                "matched_rule": "chain_drift",
                "reason": decision["reason"],
                "verification_level": "pre_execution_chain_analysis",
                "argument_keys": [],
                "blocked_by": "chain_drift",
                "probe_id": "chain-proof-1",
                "argument_hash": profile["argument_hash"],
                "drift_status": "chain_drift",
                "drift_severity": decision["severity"],
                "drift_action": decision["action"],
                "drift_types": decision["types"],
                "drift_reasons": decision["reasons"],
                "drift_current_hash": profile["profile_hash"],
            }
        )

        receipt = receipt_builder.build_receipt(row, chain_verified=True)
        evidence = receipt["drift_evidence"]
        encoded = json.dumps(evidence, sort_keys=True)
        assert evidence["record"]["record_type"] == "interlock.chain-drift-record"
        assert evidence["evidence_ref"]["type"] == "chain-drift"
        assert "secret-query" not in encoded
        assert "person@example.com" not in encoded
    finally:
        for suffix in ("", "-wal", "-shm"):
            try:
                os.unlink(tmp_db + suffix)
            except OSError:
                pass
