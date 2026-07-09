"""
Four-claim receipt evidence tests.

A four-claim view answers, from the hash-chained audit log:

  1. What was approved            (approved baseline surface hash, inspectable)
  2. What changed                 (observed surface / behavior, inspectable)
  3. What runtime decision fired  (verbatim decision + reason)
  4. Whether any boundary-crossing call executed AFTER drift detection
     — answered by a REAL audit-log query, never hardcoded copy.

Run: python -m pytest tests/test_receipt_claims.py -q
"""

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

TEST_DB = tempfile.mktemp(suffix="_receipt_claims_test.db")
os.environ["FIREWALL_DB_PATH"] = TEST_DB

from core import db  # noqa: E402
from core import receipt as receipt_mod  # noqa: E402
from core import receipt_verify  # noqa: E402

APPROVED_HASH = "sha256:" + "b" * 64
OBSERVED_HASH = "sha256:" + "c" * 64


@pytest.fixture(scope="module", autouse=True)
def seeded_db():
    db.DB_PATH = TEST_DB
    db.init_db()
    yield


def _detection_row(server_id="claims-docs", tool_name="read_document"):
    return db.log_mcp_audit_event(
        {
            "server_id": server_id,
            "tool_name": tool_name,
            "role": "system",
            "action": "quarantine",
            "matched_rule": "drift_detected",
            "reason": "Capability drift detected at discovery.",
            "drift_status": "quarantined",
            "drift_severity": "critical",
            "drift_action": "quarantine",
            "drift_types": ["effect_escalated"],
            "drift_reasons": ["read-only tool gained export effect"],
            "drift_baseline_hash": APPROVED_HASH,
            "drift_current_hash": OBSERVED_HASH,
        }
    )


def _blocked_attempt(server_id, tool_name):
    return db.log_mcp_audit_event(
        {
            "server_id": server_id,
            "tool_name": tool_name,
            "role": "readonly_agent",
            "action": "deny",
            "matched_rule": "tool_quarantined",
            "reason": "Tool is quarantined until reviewed.",
            "blocked_by": "tool_quarantined",
            "argument_hash": "sha256:" + "d" * 64,
        }
    )


def test_capability_claims_quarantine_before_execution():
    detection = _detection_row("cap-server", "read_document")
    _blocked_attempt("cap-server", "read_document")
    _blocked_attempt("cap-server", "read_document")

    row = db.get_mcp_audit_log(detection["id"])
    receipt = receipt_mod.build_receipt(row, chain_verified=True)
    claims = receipt_verify.build_claims(row, receipt)

    c1 = claims["claim_1_approved"]
    assert c1["approved_surface_hash"] == APPROVED_HASH

    c2 = claims["claim_2_observed"]
    assert c2["observed_surface_hash"] == OBSERVED_HASH
    assert c2["schema_unchanged"] is False
    assert "read-only tool gained export effect" in c2["changes"]

    c3 = claims["claim_3_decision"]
    assert c3["decision"] == "quarantine"
    assert c3["rule_fired"] == "drift_detected"
    assert c3["drift_severity"] == "critical"

    c4 = claims["claim_4_execution_after_detection"]
    assert c4["boundary_crossing_executed"] is False
    assert c4["executed_count"] == 0
    assert c4["blocked_attempts"] == 2
    assert c4["detection_ts"] == row["ts"]


def test_claim_4_is_a_real_query_not_copy():
    """A forwarded (allow) call logged after detection MUST flip claim 4."""
    detection = _detection_row("leaky-server", "read_document")
    db.log_mcp_audit_event(
        {
            "server_id": "leaky-server",
            "tool_name": "read_document",
            "role": "readonly_agent",
            "action": "allow",
            "matched_rule": "role_allows",
            "reason": "hypothetical forwarded call",
            "argument_hash": "sha256:" + "d" * 64,
        }
    )
    row = db.get_mcp_audit_log(detection["id"])
    claims = receipt_verify.build_claims(
        row, receipt_mod.build_receipt(row, chain_verified=True)
    )
    c4 = claims["claim_4_execution_after_detection"]
    assert c4["boundary_crossing_executed"] is True
    assert c4["executed_count"] == 1
    assert c4["executed_calls"][0]["action"] == "allow"


def test_behavioral_claims_show_unchanged_schema_and_changed_behavior():
    surface = "sha256:" + "5" * 64
    probe_row = db.log_mcp_audit_event(
        {
            "server_id": "beh-server",
            "tool_name": "update_record",
            "role": "operator",
            "action": "quarantine",
            "matched_rule": "effective_permission_probe",
            "reason": "Expected denied, upstream allowed it.",
            "blocked_by": "effective_permission_probe",
            "probe_id": "beh-server:update_record:abc",
            "argument_hash": "sha256:" + "6" * 64,
            "expected_outcome": "denied",
            "expected_status_code": 403,
            "observed_outcome": "allowed",
            "observed_status_code": 200,
            "drift_status": "behavioral_scope_drift",
            "drift_severity": "high",
            "drift_action": "quarantine",
            "drift_types": [
                "effective_permission_expansion",
                "behavioral_scope_drift",
            ],
            "drift_reasons": ["403 became 200 with an unchanged schema"],
            "drift_baseline_hash": surface,
            "drift_current_hash": surface,
        }
    )
    row = db.get_mcp_audit_log(probe_row["id"])
    claims = receipt_verify.build_claims(
        row, receipt_mod.build_receipt(row, chain_verified=True)
    )

    c1 = claims["claim_1_approved"]
    assert c1["approved_surface_hash"] == surface
    assert c1["expected_outcome"] == "denied"
    assert c1["expected_status_code"] == 403

    c2 = claims["claim_2_observed"]
    assert c2["schema_unchanged"] is True
    assert c2["observed_outcome"] == "allowed"
    assert c2["observed_status_code"] == 200

    c4 = claims["claim_4_execution_after_detection"]
    assert c4["boundary_crossing_executed"] is False


def test_claims_surface_inspect_paths_when_snapshot_retained():
    from core import drift_evidence

    tool_def = {
        "name": "snapshot_tool",
        "description": "x",
        "inputSchema": {"type": "object"},
    }
    surface_hash = drift_evidence.tool_surface_hash(tool_def)
    db.save_tool_surface_snapshot(
        surface_hash, drift_evidence.canonical_surface_json(tool_def)
    )
    detection = db.log_mcp_audit_event(
        {
            "server_id": "snap-server",
            "tool_name": "snapshot_tool",
            "role": "system",
            "action": "quarantine",
            "matched_rule": "drift_detected",
            "reason": "drift",
            "drift_severity": "critical",
            "drift_action": "quarantine",
            "drift_types": ["effect_escalated"],
            "drift_reasons": ["change"],
            "drift_baseline_hash": surface_hash,
            "drift_current_hash": "sha256:" + "9" * 64,
        }
    )
    row = db.get_mcp_audit_log(detection["id"])
    claims = receipt_verify.build_claims(
        row, receipt_mod.build_receipt(row, chain_verified=True)
    )
    assert (
        claims["claim_1_approved"]["inspect_path"]
        == f"/audit/evidence/surface/{surface_hash}"
    )
    # No snapshot retained for the observed hash → no inspect path claimed.
    assert claims["claim_2_observed"]["inspect_path"] is None
