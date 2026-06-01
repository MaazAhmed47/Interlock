"""
Tests for the Security Receipt export feature.

A Security Receipt is a clean, tamper-evident artifact summarizing what
happened on a single MCP tool call (or a batch of them), pulled from the
mcp_audit_log hash chain.

Covers:
  - single receipt generation from an audit event
  - batch export over a time range (downloadable JSON artifact)
  - integrity hash + chain_verified included (tamper-evidence)
  - auth required (API key)

Run: python -m pytest tests/test_security_receipt.py -q
"""

import asyncio
import json
import os
import sys
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

os.environ["PYTHON_DOTENV_DISABLED"] = "1"
os.environ.pop("DATABASE_URL", None)
os.environ.pop("GROQ_API_KEY", None)

TEST_DB = tempfile.mktemp(suffix="_security_receipt_test.db")
os.environ["FIREWALL_DB_PATH"] = TEST_DB

from core import db  # noqa: E402
from core import receipt as receipt_mod  # noqa: E402
import proxy  # noqa: E402

TEST_KEY = "lf-free-demo-key-123"

# Three audit events with explicit timestamps so range queries are deterministic.
ALLOW_TS = "2026-05-01T10:00:00+00:00"
DENY_TS = "2026-05-01T11:00:00+00:00"
MONITOR_TS = "2026-05-02T09:00:00+00:00"
OUT_OF_RANGE_TS = "2026-04-01T09:00:00+00:00"


def run(coro):
    return asyncio.run(coro)


@pytest.fixture(scope="module", autouse=True)
def seeded_db():
    db.DB_PATH = TEST_DB
    db.init_db()
    db.seed_legacy_keys()

    ids = {}
    ids["out"] = db.log_mcp_audit_event(
        {
            "ts": OUT_OF_RANGE_TS,
            "server_id": "github",
            "tool_name": "list_repos",
            "role": "readonly_agent",
            "action": "allow",
            "reason": "clean read",
        }
    )["id"]
    ids["allow"] = db.log_mcp_audit_event(
        {
            "ts": ALLOW_TS,
            "server_id": "github",
            "tool_name": "create_issue",
            "role": "support_agent",
            "action": "allow",
            "matched_rule": "role_allows",
            "reason": "support_agent may create issues",
            "confidence": 0.95,
        }
    )["id"]
    ids["deny"] = db.log_mcp_audit_event(
        {
            "ts": DENY_TS,
            "server_id": "github",
            "tool_name": "delete_repo",
            "role": "support_agent",
            "action": "deny",
            "matched_rule": "rbac_denied",
            "reason": "support_agent cannot call delete_repo; SQL injection pattern in argument",
            "blocked_by": "rbac",
            "warnings": ["SQL injection pattern detected in 'query' argument"],
            "data_classes": ["email", "credit_card"],
            "drift_status": "drift_detected",
            "drift_severity": "high",
            "drift_types": ["description_changed"],
            "drift_reasons": ["tool description changed since approved baseline"],
            "confidence": 0.91,
        }
    )["id"]
    ids["monitor"] = db.log_mcp_audit_event(
        {
            "ts": MONITOR_TS,
            "server_id": "stripe",
            "tool_name": "create_charge",
            "role": "finance_agent",
            "action": "monitor",
            "matched_rule": "tool_metadata_drift",
            "reason": "tool changed; monitoring",
            "drift_status": "changed",
            "drift_severity": "minor",
            "drift_types": ["schema_changed"],
            "drift_reasons": ["new optional field added"],
            "confidence": 0.6,
        }
    )["id"]

    yield ids

    for path in (TEST_DB, TEST_DB + "-wal", TEST_DB + "-shm"):
        try:
            os.unlink(path)
        except OSError:
            pass


# ── db layer ──────────────────────────────────────────────────────────────────


def test_get_mcp_audit_log_returns_single_row(seeded_db):
    row = db.get_mcp_audit_log(seeded_db["deny"])
    assert row is not None
    assert row["id"] == seeded_db["deny"]
    assert row["tool_name"] == "delete_repo"
    # JSON columns parsed into lists
    assert row["data_classes"] == ["email", "credit_card"]
    assert row["warnings"] == ["SQL injection pattern detected in 'query' argument"]


def test_get_mcp_audit_log_missing_returns_none(seeded_db):
    assert db.get_mcp_audit_log(999999) is None


def test_list_mcp_audit_logs_between_filters_by_range(seeded_db):
    rows = db.list_mcp_audit_logs_between(ALLOW_TS, MONITOR_TS)
    ids = {r["id"] for r in rows}
    assert seeded_db["allow"] in ids
    assert seeded_db["deny"] in ids
    assert seeded_db["monitor"] in ids
    # The April event is before the window and must be excluded.
    assert seeded_db["out"] not in ids


def test_verify_mcp_audit_record_valid(seeded_db):
    result = db.verify_mcp_audit_record(seeded_db["allow"])
    assert result["chain_verified"] is True


def test_verify_mcp_audit_record_detects_tamper(seeded_db):
    target = seeded_db["monitor"]
    with db.get_conn() as conn:
        original = dict(
            conn.execute(
                "SELECT reason FROM mcp_audit_log WHERE id = ?", (target,)
            ).fetchone()
        )["reason"]
        conn.execute(
            "UPDATE mcp_audit_log SET reason = ? WHERE id = ?",
            ("tampered reason", target),
        )
    try:
        result = db.verify_mcp_audit_record(target)
        assert result["chain_verified"] is False
    finally:
        with db.get_conn() as conn:
            conn.execute(
                "UPDATE mcp_audit_log SET reason = ? WHERE id = ?", (original, target)
            )


# ── receipt builder (pure) ──────────────────────────────────────────────────────


def test_build_receipt_maps_core_fields(seeded_db):
    row = db.get_mcp_audit_log(seeded_db["deny"])
    rcpt = receipt_mod.build_receipt(row, chain_verified=True)

    assert rcpt["agent_role"] == "support_agent"
    assert rcpt["server_id"] == "github"
    assert rcpt["tool_name"] == "delete_repo"
    assert rcpt["decision"] == "deny"
    assert rcpt["rule_fired"] == "rbac_denied"
    assert "delete_repo" in rcpt["reason"]
    assert rcpt["integrity_hash"] == row["integrity_hash"]
    assert rcpt["prev_hash"] == row["prev_hash"]
    assert rcpt["chain_verified"] is True
    assert rcpt["receipt_id"]


def test_build_receipt_detections_and_redactions(seeded_db):
    row = db.get_mcp_audit_log(seeded_db["deny"])
    rcpt = receipt_mod.build_receipt(row, chain_verified=True)

    assert "pii" in rcpt["detections"]
    assert "sql_injection" in rcpt["detections"]
    assert "card number redacted" in rcpt["redactions"]
    assert "email redacted" in rcpt["redactions"]


def test_build_receipt_drift_block(seeded_db):
    row = db.get_mcp_audit_log(seeded_db["deny"])
    rcpt = receipt_mod.build_receipt(row, chain_verified=True)

    assert rcpt["drift"]["detected"] is True
    assert rcpt["drift"]["severity"] == "high"
    assert any("baseline" in c for c in rcpt["drift"]["changes"])


def test_build_receipt_risk_score_bounds(seeded_db):
    deny = receipt_mod.build_receipt(
        db.get_mcp_audit_log(seeded_db["deny"]), chain_verified=True
    )
    allow = receipt_mod.build_receipt(
        db.get_mcp_audit_log(seeded_db["allow"]), chain_verified=True
    )
    assert 0 <= deny["risk_score"] <= 100
    assert deny["risk_score"] >= 50
    assert allow["risk_score"] < deny["risk_score"]


def test_build_receipt_clean_allow_has_no_drift(seeded_db):
    rcpt = receipt_mod.build_receipt(
        db.get_mcp_audit_log(seeded_db["allow"]), chain_verified=True
    )
    assert rcpt["decision"] == "allow"
    assert rcpt["drift"]["detected"] is False
    assert rcpt["detections"] == []
    assert rcpt["redactions"] == []


# ── single receipt endpoint ──────────────────────────────────────────────────────


def test_receipt_endpoint_returns_receipt(seeded_db):
    rcpt = run(proxy.get_receipt(seeded_db["deny"], x_api_key=TEST_KEY))
    assert rcpt["tool_name"] == "delete_repo"
    assert rcpt["decision"] == "deny"
    assert len(rcpt["integrity_hash"]) == 64
    assert rcpt["chain_verified"] is True


def test_receipt_endpoint_404_for_missing(seeded_db):
    with pytest.raises(proxy.HTTPException) as exc:
        run(proxy.get_receipt(999999, x_api_key=TEST_KEY))
    assert exc.value.status_code == 404


def test_receipt_endpoint_requires_auth(seeded_db):
    with pytest.raises(proxy.HTTPException) as exc:
        run(proxy.get_receipt(seeded_db["deny"], x_api_key=None))
    assert exc.value.status_code == 401


def test_receipt_endpoint_rejects_invalid_key(seeded_db):
    with pytest.raises(proxy.HTTPException) as exc:
        run(proxy.get_receipt(seeded_db["deny"], x_api_key="not-a-real-key"))
    assert exc.value.status_code == 403


# ── batch export endpoint ────────────────────────────────────────────────────────


def _parse_response(resp):
    return json.loads(resp.body)


def test_export_returns_downloadable_batch(seeded_db):
    resp = run(
        proxy.export_receipts(
            from_ts=ALLOW_TS, to_ts=MONITOR_TS, format="json", x_api_key=TEST_KEY
        )
    )
    # Downloadable: attachment disposition with a filename.
    disposition = resp.headers.get("content-disposition", "")
    assert "attachment" in disposition
    assert ".json" in disposition

    payload = _parse_response(resp)
    assert payload["count"] == len(payload["receipts"]) == 3
    assert payload["from"] == ALLOW_TS
    assert payload["to"] == MONITOR_TS
    # Batch carries an overall chain-integrity proof.
    assert payload["chain_verified"] is True
    tools = {r["tool_name"] for r in payload["receipts"]}
    assert tools == {"create_issue", "delete_repo", "create_charge"}


def test_export_each_receipt_has_integrity_proof(seeded_db):
    resp = run(
        proxy.export_receipts(
            from_ts=ALLOW_TS, to_ts=MONITOR_TS, format="json", x_api_key=TEST_KEY
        )
    )
    payload = _parse_response(resp)
    for rcpt in payload["receipts"]:
        assert len(rcpt["integrity_hash"]) == 64
        assert rcpt["prev_hash"]
        assert "chain_verified" in rcpt


def test_export_requires_auth(seeded_db):
    with pytest.raises(proxy.HTTPException) as exc:
        run(
            proxy.export_receipts(
                from_ts=ALLOW_TS, to_ts=MONITOR_TS, format="json", x_api_key=None
            )
        )
    assert exc.value.status_code == 401


def test_export_unsupported_format_is_rejected_cleanly(seeded_db):
    with pytest.raises(proxy.HTTPException) as exc:
        run(
            proxy.export_receipts(
                from_ts=ALLOW_TS, to_ts=MONITOR_TS, format="pdf", x_api_key=TEST_KEY
            )
        )
    # Not yet implemented, but structured to add later — clean 400, not a 500.
    assert exc.value.status_code == 400
    assert "json" in str(exc.value.detail).lower()
