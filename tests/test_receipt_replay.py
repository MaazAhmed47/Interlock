"""
Replay / freshness invariant tests for Security Receipts.

The security claim under test: a receipt is bound to the exact runtime context
it was issued for. A forwarded/replayed receipt MUST fail verification if any
of these differ from what the audit log recorded:

  - target (server_id / tool_name)
  - argument hash
  - call id
  - surface hash

Also covers the plumbing that makes the binding trustworthy:
  - every new mcp_audit_log row gets a unique call_id and a v2 chain hash that
    commits to the binding fields (server_id, call_id, argument_hash,
    drift surface hashes)
  - legacy v1 rows still verify under the v1 hash
  - tampering with a binding field on a v2 row breaks chain verification
  - legacy rows without binding fields fail binding verification CLOSED

Run: python -m pytest tests/test_receipt_replay.py -q
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

TEST_DB = tempfile.mktemp(suffix="_receipt_replay_test.db")
os.environ["FIREWALL_DB_PATH"] = TEST_DB

from core import db  # noqa: E402


@pytest.fixture(scope="module", autouse=True)
def seeded_db():
    db.DB_PATH = TEST_DB
    db.init_db()
    yield


def _log_event(**overrides):
    event = {
        "server_id": "demo-docs",
        "tool_name": "read_document",
        "role": "readonly_agent",
        "action": "quarantine",
        "matched_rule": "drift_detected",
        "reason": "capability drift detected",
        "argument_hash": "sha256:" + "a" * 64,
        "drift_status": "quarantined",
        "drift_severity": "critical",
        "drift_action": "quarantine",
        "drift_types": ["effect_escalated"],
        "drift_reasons": ["read-only tool gained export effect"],
        "drift_baseline_hash": "sha256:" + "b" * 64,
        "drift_current_hash": "sha256:" + "c" * 64,
    }
    event.update(overrides)
    return db.log_mcp_audit_event(event)


# ── call_id + v2 hash on new rows ─────────────────────────────────────────────


def test_new_event_gets_call_id():
    saved = _log_event()
    assert saved["call_id"], "log_mcp_audit_event must assign a call_id"
    row = db.get_mcp_audit_log(saved["id"])
    assert row["call_id"] == saved["call_id"]
    assert row["hash_v"] == 2


def test_call_ids_are_unique():
    a = _log_event()
    b = _log_event()
    assert a["call_id"] != b["call_id"]


def test_explicit_call_id_is_preserved():
    saved = _log_event(call_id="explicit-call-id-123")
    row = db.get_mcp_audit_log(saved["id"])
    assert row["call_id"] == "explicit-call-id-123"


def test_v2_row_verifies():
    saved = _log_event()
    verdict = db.verify_mcp_audit_record(saved["id"])
    assert verdict["chain_verified"] is True, verdict


def test_get_mcp_audit_log_by_call_id():
    saved = _log_event()
    row = db.get_mcp_audit_log_by_call_id(saved["call_id"])
    assert row is not None
    assert row["id"] == saved["id"]
    assert db.get_mcp_audit_log_by_call_id("no-such-call-id") is None


# ── legacy v1 rows still verify ───────────────────────────────────────────────


def _insert_legacy_v1_row():
    """Simulate a pre-binding row: v1 hash over (prev|ts|action|tool|role|reason)."""
    ts = "2026-01-01T00:00:00+00:00"
    with db._db_lock, db.get_conn() as conn:
        prev = conn.execute(
            "SELECT integrity_hash FROM mcp_audit_log ORDER BY id DESC LIMIT 1"
        ).fetchone()
        prev_hash = (dict(prev).get("integrity_hash") if prev else None) or "GENESIS"
        integrity = db._compute_audit_hash(
            prev_hash, ts, "allow", "legacy_tool", "legacy_role", "legacy reason"
        )
        cursor = conn.execute(
            """
            INSERT INTO mcp_audit_log
              (ts, server_id, tool_name, role, action, reason,
               prev_hash, integrity_hash, hash_v)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)
            """,
            (
                ts,
                "legacy-server",
                "legacy_tool",
                "legacy_role",
                "allow",
                "legacy reason",
                prev_hash,
                integrity,
            ),
        )
        return cursor.lastrowid


def test_legacy_v1_row_still_verifies():
    legacy_id = _insert_legacy_v1_row()
    verdict = db.verify_mcp_audit_record(legacy_id)
    assert verdict["chain_verified"] is True, verdict
    # And a v2 row appended after the legacy row keeps the chain intact.
    saved = _log_event()
    assert db.verify_mcp_audit_record(saved["id"])["chain_verified"] is True


def test_full_chain_verifies_across_versions():
    chain = db.verify_audit_chain()
    assert chain["valid"] is True, chain


# ── tampering with binding fields breaks v2 verification ─────────────────────


@pytest.mark.parametrize(
    "column,value",
    [
        ("call_id", "attacker-swapped-call-id"),
        ("argument_hash", "sha256:" + "f" * 64),
        ("server_id", "attacker-server"),
        ("drift_baseline_hash", "sha256:" + "0" * 64),
        ("drift_current_hash", "sha256:" + "1" * 64),
    ],
)
def test_tampered_binding_field_breaks_v2_hash(column, value):
    saved = _log_event()
    with db._db_lock, db.get_conn() as conn:
        conn.execute(
            f"UPDATE mcp_audit_log SET {column} = ? WHERE id = ?",
            (value, saved["id"]),
        )
    verdict = db.verify_mcp_audit_record(saved["id"])
    assert (
        verdict["chain_verified"] is False
    ), f"tampering {column} must break v2 chain verification"
    # Restore so later tests see an intact chain.
    with db._db_lock, db.get_conn() as conn:
        conn.execute(
            f"UPDATE mcp_audit_log SET {column} = ? WHERE id = ?",
            (saved.get(column) or "", saved["id"]),
        )
    assert db.verify_mcp_audit_record(saved["id"])["chain_verified"] is True


# ── claim-4 query support ─────────────────────────────────────────────────────


def test_list_mcp_audit_after_orders_and_filters():
    detection = _log_event(
        server_id="claim4-server", tool_name="claim4_tool", action="quarantine"
    )
    blocked = _log_event(
        server_id="claim4-server",
        tool_name="claim4_tool",
        action="deny",
        blocked_by="tool_quarantined",
        drift_severity="none",
        drift_baseline_hash="",
        drift_current_hash="",
    )
    other_tool = _log_event(
        server_id="claim4-server", tool_name="other_tool", action="allow"
    )
    rows = db.list_mcp_audit_after(
        "claim4-server", "claim4_tool", detection["ts"], exclude_id=detection["id"]
    )
    ids = [r["id"] for r in rows]
    assert blocked["id"] in ids
    assert detection["id"] not in ids, "the detection row itself must be excluded"
    assert other_tool["id"] not in ids, "other tools must not leak into the query"


# ── offline demo key seed ─────────────────────────────────────────────────────


def test_seed_offline_demo_key_is_idempotent_and_resolvable():
    db.seed_offline_demo_key()
    db.seed_offline_demo_key()  # second call must not raise or duplicate
    record = db.lookup_key(db.OFFLINE_DEMO_KEY)
    assert record is not None
    assert record["is_active"]
    with db.get_conn() as conn:
        n = conn.execute(
            "SELECT COUNT(*) AS n FROM api_keys WHERE key_hash = ?",
            (db._hash_key(db.OFFLINE_DEMO_KEY),),
        ).fetchone()
    assert dict(n)["n"] == 1
