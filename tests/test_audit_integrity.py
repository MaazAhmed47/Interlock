import sys, os, tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest

_tmp_db = tempfile.mktemp(suffix="_audit_integrity_test.db")

import core.db as db

@pytest.fixture(scope="module", autouse=True)
def setup_db():
    db.DB_PATH = _tmp_db
    db.init_db()
    yield
    for p in (_tmp_db, _tmp_db + "-wal", _tmp_db + "-shm"):
        try:
            os.unlink(p)
        except OSError:
            pass


def test_mcp_audit_first_record_has_genesis_prev_hash():
    db.log_mcp_audit_event({
        "server_id": "s1", "tool_name": "t1", "action": "allow", "role": "r", "reason": "ok"
    })
    with db.get_conn() as conn:
        row = dict(conn.execute(
            "SELECT prev_hash, integrity_hash FROM mcp_audit_log ORDER BY id LIMIT 1"
        ).fetchone())
    assert row["prev_hash"] == "GENESIS"
    assert len(row["integrity_hash"]) == 64


def test_mcp_audit_chain_second_record_links_to_first():
    db.log_mcp_audit_event({
        "server_id": "s1", "tool_name": "t2", "action": "deny", "role": "r", "reason": "blocked"
    })
    with db.get_conn() as conn:
        rows = [dict(r) for r in conn.execute(
            "SELECT prev_hash, integrity_hash FROM mcp_audit_log ORDER BY id"
        ).fetchall()]
    assert rows[1]["prev_hash"] == rows[0]["integrity_hash"]


def test_admin_audit_first_record_has_genesis_prev_hash():
    db.log_admin_audit_event({
        "actor_role": "owner", "action": "key_created",
        "target_type": "api_key", "target_id": "test123"
    })
    with db.get_conn() as conn:
        row = dict(conn.execute(
            "SELECT prev_hash, integrity_hash FROM admin_audit_log ORDER BY id LIMIT 1"
        ).fetchone())
    assert row["prev_hash"] == "GENESIS"
    assert len(row["integrity_hash"]) == 64


def test_verify_audit_chain_valid():
    result = db.verify_audit_chain()
    assert result["valid"] is True
    assert result["mcp"]["total"] >= 2
    assert result["admin"]["total"] >= 1


def test_verify_audit_chain_detects_mcp_tamper():
    with db.get_conn() as conn:
        first_id = dict(conn.execute(
            "SELECT id FROM mcp_audit_log ORDER BY id LIMIT 1"
        ).fetchone())["id"]
        conn.execute(
            "UPDATE mcp_audit_log SET integrity_hash = 'tampered00000000000000000000000000000000000000000000000000000000' WHERE id = ?",
            (first_id,),
        )
    result = db.verify_audit_chain()
    assert result["valid"] is False
    assert result["broken_at"]["table"] == "mcp_audit_log"
    assert result["broken_at"]["record_id"] == first_id
