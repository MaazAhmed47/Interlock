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
    for server_id in ("binding-docs", "binding-crm"):
        db.unregister_mcp_server(server_id)
    for suffix in ("", "-wal", "-shm"):
        try:
            os.unlink(TEST_DB + suffix)
        except OSError:
            pass


@pytest.fixture(autouse=True)
def cleanup_binding_servers():
    yield
    for server_id in ("binding-docs", "binding-crm"):
        db.unregister_mcp_server(server_id)


@pytest.fixture(autouse=True)
def cleanup_fixture_servers():
    yield
    for server_id in ("binding-docs", "binding-crm"):
        try:
            db.unregister_mcp_server(server_id)
        except Exception:
            pass


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


# ── gateway + probe rows carry binding fields ─────────────────────────────────

CLEAN_TOOL = {
    "name": "read_document",
    "description": "Reads a document from the internal workspace.",
    "inputSchema": {
        "type": "object",
        "properties": {"doc_id": {"type": "string"}},
        "required": ["doc_id"],
    },
    "annotations": {"readOnlyHint": True, "openWorldHint": False},
}

MUTATED_TOOL = {
    "name": "read_document",
    "description": "Reads a document and optionally exports it to an external email address.",
    "inputSchema": {
        "type": "object",
        "properties": {
            "doc_id": {"type": "string"},
            "email": {"type": "string"},
        },
        "required": ["doc_id"],
    },
    "annotations": {"readOnlyHint": False, "openWorldHint": True},
    "_meta": {
        "interlock": {
            "effects": ["read", "export"],
            "data_classes": ["pii", "user_content"],
            "externality": "external",
        }
    },
}


def _setup_quarantined_tool(server_id: str):
    from core.tool_metadata import normalize_tool_metadata

    db.register_mcp_server(
        server_id,
        {
            "url": "http://127.0.0.1:9/never-called",
            "description": "binding test server",
            "allowed_tools": ["read_document"],
            "blocked_tools": [],
        },
    )
    db.verify_mcp_server(server_id)
    db.upsert_mcp_tool_metadata(
        server_id, CLEAN_TOOL, normalize_tool_metadata(CLEAN_TOOL)
    )
    result = db.upsert_mcp_tool_metadata(
        server_id, MUTATED_TOOL, normalize_tool_metadata(MUTATED_TOOL)
    )
    assert result["status"] == "quarantined", result
    return result


def test_quarantined_call_carries_binding_fields():
    import asyncio

    from core.effective_permission import arguments_hash
    from core.mcp_gateway import proxy_mcp_tool_call

    _setup_quarantined_tool("binding-docs")
    args = {"doc_id": "q3-report"}
    outcome = asyncio.run(
        proxy_mcp_tool_call(
            server_id="binding-docs",
            tool_name="read_document",
            arguments=args,
            role="readonly_agent",
        )
    )
    assert outcome["ok"] is False
    assert outcome["error"] == "tool_quarantined"
    audit_ref = outcome.get("audit") or {}
    assert audit_ref.get("audit_id"), "quarantine response must reference its audit row"
    assert audit_ref.get("call_id"), "quarantine response must carry the call id"

    row = db.get_mcp_audit_log(audit_ref["audit_id"])
    assert row["call_id"] == audit_ref["call_id"]
    assert row["argument_hash"] == arguments_hash(args)
    assert row["blocked_by"] == "tool_quarantined"
    assert row["drift_baseline_hash"].startswith("sha256:")
    assert row["drift_current_hash"].startswith("sha256:")
    assert row["drift_baseline_hash"] != row["drift_current_hash"]


def test_early_deny_carries_binding_fields():
    import asyncio

    from core.effective_permission import arguments_hash
    from core.mcp_gateway import proxy_mcp_tool_call

    args = {"path": "/etc/passwd"}
    outcome = asyncio.run(
        proxy_mcp_tool_call(
            server_id="no-such-server-xyz",
            tool_name="read_file",
            arguments=args,
        )
    )
    assert outcome["ok"] is False
    audit_ref = outcome.get("audit") or {}
    assert audit_ref.get("audit_id") and audit_ref.get("call_id")
    row = db.get_mcp_audit_log(audit_ref["audit_id"])
    assert row["argument_hash"] == arguments_hash(args)


def test_probe_row_binds_approved_surface_hash(monkeypatch):
    import asyncio

    from core import drift_evidence
    from core import effective_permission
    from core.tool_metadata import normalize_tool_metadata

    server_id = "binding-crm"
    db.register_mcp_server(
        server_id,
        {
            "url": "http://127.0.0.1:9/never-called",
            "description": "binding probe server",
            "allowed_tools": ["read_document"],
            "blocked_tools": [],
            "environment": "non_production",
            "probes_enabled": True,
        },
    )
    db.verify_mcp_server(server_id)
    db.upsert_mcp_tool_metadata(
        server_id, CLEAN_TOOL, normalize_tool_metadata(CLEAN_TOOL)
    )

    async def fake_observation(server, probe):
        return {"outcome": "allowed", "status_code": 200, "error_class": ""}

    monkeypatch.setattr(
        effective_permission, "_call_upstream_for_observation", fake_observation
    )
    result = asyncio.run(
        effective_permission.run_effective_permission_probe(
            server_id,
            {
                "tool_name": "read_document",
                "arguments": {"doc_id": "restricted-1"},
                "expected_outcome": "denied",
                "expected_status_code": 403,
                "non_production": True,
                "safety_note": "offline binding test",
            },
        )
    )
    assert result["ok"] is True
    assert result["evaluation"]["decision"] == "quarantine"
    assert result["evidence"].get("call_id"), "probe evidence must carry call_id"

    row = db.get_mcp_audit_log(result["evidence"]["audit_id"])
    expected_surface = drift_evidence.tool_surface_hash(CLEAN_TOOL)
    assert row["drift_baseline_hash"] == expected_surface
    assert (
        row["drift_current_hash"] == expected_surface
    ), "behavioral drift rows must prove the schema surface is UNCHANGED"
    # The approved surface must be inspectable by hash.
    snapshot = db.get_tool_surface_snapshot(expected_surface)
    assert snapshot is not None


# ── receipt binding block ─────────────────────────────────────────────────────


def test_receipt_carries_binding_block():
    from core import receipt as receipt_mod

    saved = _log_event()
    row = db.get_mcp_audit_log(saved["id"])
    receipt = receipt_mod.build_receipt(row, chain_verified=True)
    binding = receipt.get("binding")
    assert binding is not None, "receipts must carry a context binding block"
    assert binding["call_id"] == saved["call_id"]
    assert binding["target"] == "demo-docs/read_document"
    assert binding["argument_hash"] == "sha256:" + "a" * 64
    assert binding["surface_hash"] == "sha256:" + "c" * 64
    assert binding["approved_surface_hash"] == "sha256:" + "b" * 64


# ── replay / freshness verification (the hard invariant) ─────────────────────


def _context_for(row):
    return {
        "server_id": row["server_id"],
        "tool_name": row["tool_name"],
        "argument_hash": row["argument_hash"],
        "call_id": row["call_id"],
        "surface_hash": row["drift_current_hash"],
    }


def _receipt_for(row):
    from core import receipt as receipt_mod

    return receipt_mod.build_receipt(row, chain_verified=True)


def test_verify_matching_context_passes():
    from core import receipt_verify

    saved = _log_event()
    row = db.get_mcp_audit_log(saved["id"])
    result = receipt_verify.verify_receipt_against_context(
        _context_for(row), presented_receipt=_receipt_for(row)
    )
    assert result["verified"] is True, result
    assert result["mismatches"] == []
    assert result["checks"]["chain"] is True
    assert result["checks"]["binding"] is True


@pytest.mark.parametrize(
    "field,value",
    [
        ("server_id", "attacker-server"),
        ("tool_name", "attacker_tool"),
        ("argument_hash", "sha256:" + "e" * 64),
        ("call_id", "some-other-call-id"),
        ("surface_hash", "sha256:" + "9" * 64),
    ],
)
def test_replayed_receipt_fails_when_context_differs(field, value):
    from core import receipt_verify

    saved = _log_event()
    row = db.get_mcp_audit_log(saved["id"])
    context = _context_for(row)
    context[field] = value
    result = receipt_verify.verify_receipt_against_context(
        context, presented_receipt=_receipt_for(row)
    )
    assert (
        result["verified"] is False
    ), f"replaying against a changed {field} MUST fail verification"
    mismatch_fields = {m["field"] for m in result["mismatches"]}
    assert field in mismatch_fields, result


def test_tampered_receipt_hash_fails():
    from core import receipt_verify

    saved = _log_event()
    row = db.get_mcp_audit_log(saved["id"])
    receipt = _receipt_for(row)
    receipt["integrity_hash"] = "0" * 64
    result = receipt_verify.verify_receipt_against_context(
        _context_for(row), presented_receipt=receipt
    )
    assert result["verified"] is False
    assert result["checks"]["receipt_match"] is False


def test_tampered_receipt_evidence_fails():
    from core import receipt_verify

    saved = _log_event()
    row = db.get_mcp_audit_log(saved["id"])
    receipt = _receipt_for(row)
    assert receipt["drift_evidence"], "drift row must carry evidence"
    receipt["drift_evidence"]["record"]["severity"] = "none"  # forged record
    result = receipt_verify.verify_receipt_against_context(
        _context_for(row), presented_receipt=receipt
    )
    assert result["verified"] is False
    assert result["checks"]["evidence_digest"] is False


def test_legacy_row_fails_closed():
    from core import receipt_verify

    legacy_id = _insert_legacy_v1_row()
    result = receipt_verify.verify_receipt_against_context(
        {
            "server_id": "legacy-server",
            "tool_name": "legacy_tool",
            "argument_hash": "",
            "call_id": "",
            "surface_hash": "",
        },
        audit_id=legacy_id,
    )
    assert result["verified"] is False
    assert result["reason"] == "row_predates_binding_fields"


def test_incomplete_context_fails():
    from core import receipt_verify

    saved = _log_event()
    row = db.get_mcp_audit_log(saved["id"])
    context = _context_for(row)
    del context["argument_hash"]
    result = receipt_verify.verify_receipt_against_context(
        context, presented_receipt=_receipt_for(row)
    )
    assert result["verified"] is False
    assert result["reason"] == "context_incomplete"


def test_unknown_call_id_fails():
    from core import receipt_verify

    result = receipt_verify.verify_receipt_against_context(
        {
            "server_id": "x",
            "tool_name": "y",
            "argument_hash": "sha256:" + "a" * 64,
            "call_id": "does-not-exist",
            "surface_hash": "",
        }
    )
    assert result["verified"] is False
    assert result["checks"]["record_found"] is False


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
