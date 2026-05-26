import os
import sys
import tempfile
from datetime import datetime, timezone, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

os.environ["PYTHON_DOTENV_DISABLED"] = "1"
os.environ.pop("DATABASE_URL", None)

TEST_DB = tempfile.mktemp(suffix="_retention_test.db")
os.environ["FIREWALL_DB_PATH"] = TEST_DB

from core import db


def setup_module():
    db.DB_PATH = TEST_DB
    db.init_db()


def teardown_module():
    for path in (TEST_DB, TEST_DB + "-wal", TEST_DB + "-shm"):
        try:
            os.unlink(path)
        except OSError:
            pass


def test_retention_policy_round_trips_with_defaults():
    policy = db.get_retention_policy()
    assert policy["scan_history_days"] == 30
    assert policy["mcp_audit_days"] == 90
    assert policy["admin_audit_days"] == 365
    assert policy["usage_log_days"] == 365

    updated = db.set_retention_policy({"scan_history_days": 7, "mcp_audit_days": 30, "admin_audit_days": 180})

    assert updated["scan_history_days"] == 7
    assert updated["mcp_audit_days"] == 30
    assert updated["admin_audit_days"] == 180
    assert updated["usage_log_days"] == 365
    assert db.get_retention_policy() == updated


def test_prune_retention_deletes_old_scan_mcp_and_usage_rows():
    old_ts = (datetime.now(timezone.utc) - timedelta(days=40)).isoformat()
    new_ts = datetime.now(timezone.utc).isoformat()
    key = db.generate_key("developer", label="retention")
    rec = db.lookup_key(key["raw_key"])
    key_hash = db._hash_key(key["raw_key"])

    with db.get_conn() as conn:
        conn.execute(
            "INSERT INTO scan_history (key_hash, ts, is_threat, threat_level, reason) VALUES (?, ?, ?, ?, ?)",
            (key_hash, old_ts, 0, "SAFE", "old scan"),
        )
        conn.execute(
            "INSERT INTO scan_history (key_hash, ts, is_threat, threat_level, reason) VALUES (?, ?, ?, ?, ?)",
            (key_hash, new_ts, 0, "SAFE", "new scan"),
        )
        conn.execute(
            "INSERT INTO mcp_audit_log (ts, server_id, tool_name, action) VALUES (?, ?, ?, ?)",
            (old_ts, "s", "old", "allow"),
        )
        conn.execute(
            "INSERT INTO mcp_audit_log (ts, server_id, tool_name, action) VALUES (?, ?, ?, ?)",
            (new_ts, "s", "new", "allow"),
        )
        conn.execute(
            "INSERT INTO admin_audit_log (ts, actor_auth_type, actor_role, action) VALUES (?, ?, ?, ?)",
            (old_ts, "scoped_token", "operator", "old_admin_action"),
        )
        conn.execute(
            "INSERT INTO admin_audit_log (ts, actor_auth_type, actor_role, action) VALUES (?, ?, ?, ?)",
            (new_ts, "scoped_token", "operator", "new_admin_action"),
        )
        conn.execute(
            "INSERT INTO usage_log (key_id, ts, endpoint, threat_blocked) VALUES (?, ?, ?, ?)",
            (rec["id"], old_ts, "/scan", 0),
        )
        conn.execute(
            "INSERT INTO usage_log (key_id, ts, endpoint, threat_blocked) VALUES (?, ?, ?, ?)",
            (rec["id"], new_ts, "/scan", 0),
        )

    result = db.prune_retention({"scan_history_days": 30, "mcp_audit_days": 30, "admin_audit_days": 30, "usage_log_days": 30})

    assert result["scan_history_deleted"] == 1
    assert result["mcp_audit_deleted"] == 1
    assert result["admin_audit_deleted"] == 1
    assert result["usage_log_deleted"] == 1
    with db.get_conn() as conn:
        assert conn.execute("SELECT COUNT(*) AS n FROM scan_history WHERE reason='new scan'").fetchone()["n"] == 1
        assert conn.execute("SELECT COUNT(*) AS n FROM mcp_audit_log WHERE tool_name='new'").fetchone()["n"] == 1
        assert conn.execute("SELECT COUNT(*) AS n FROM admin_audit_log WHERE action='new_admin_action'").fetchone()["n"] == 1
        assert conn.execute("SELECT COUNT(*) AS n FROM usage_log WHERE ts=?", (new_ts,)).fetchone()["n"] == 1
