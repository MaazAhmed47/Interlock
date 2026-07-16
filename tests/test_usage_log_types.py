"""SQLite persistence booleans remain integer-backed."""

from core import db
from core.history import save_scan
from models.schemas import ScanResult, ThreatLevel


def test_sqlite_usage_and_scan_booleans_remain_integers(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "usage-types.db"))
    monkeypatch.setattr(db, "USE_POSTGRES", False)
    db.init_db()

    with db.get_conn() as conn:
        usage_columns = {
            row["name"]: row for row in conn.execute("PRAGMA table_info(usage_log)")
        }
        scan_columns = {
            row["name"]: row for row in conn.execute("PRAGMA table_info(scan_history)")
        }
    assert usage_columns["threat_blocked"]["type"] == "INTEGER"
    assert usage_columns["threat_blocked"]["dflt_value"] == "0"
    assert scan_columns["is_threat"]["type"] == "INTEGER"
    assert scan_columns["is_threat"]["dflt_value"] == "0"

    created = db.generate_key("free", label="sqlite-usage-types")
    key = db.lookup_key(created["raw_key"])
    db.log_usage(key["id"], "/scan", False)
    db.log_usage(key["id"], "/scan", True)

    save_scan(
        created["raw_key"],
        ScanResult(
            is_threat=True,
            threat_level=ThreatLevel.HIGH,
            reason="sqlite integer proof",
            original_prompt="test",
            safe_to_proceed=False,
        ),
    )

    with db.get_conn() as conn:
        usage_values = [
            row["threat_blocked"]
            for row in conn.execute(
                "SELECT threat_blocked FROM usage_log ORDER BY id"
            ).fetchall()
        ]
        scan_value = conn.execute(
            "SELECT is_threat FROM scan_history ORDER BY id DESC LIMIT 1"
        ).fetchone()["is_threat"]

    assert usage_values == [0, 1]
    assert scan_value == 1
    assert db.usage_this_month(key["id"]) == 2
