import sys, os, tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import admin

import pytest
from fastapi.testclient import TestClient

_tmp_db = tempfile.mktemp(suffix="_perf_metrics_test.db")

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


def test_record_latency_sample_stores_row():
    db.record_latency_sample("/scan", 42.5, is_threat=False)
    with db.get_conn() as conn:
        row = dict(conn.execute(
            "SELECT endpoint, latency_ms, is_threat FROM latency_samples ORDER BY id DESC LIMIT 1"
        ).fetchone())
    assert row["endpoint"] == "/scan"
    assert abs(row["latency_ms"] - 42.5) < 0.01
    assert row["is_threat"] == 0


def test_record_latency_threat_flag():
    db.record_latency_sample("/scan", 10.0, is_threat=True)
    with db.get_conn() as conn:
        row = dict(conn.execute(
            "SELECT is_threat FROM latency_samples ORDER BY id DESC LIMIT 1"
        ).fetchone())
    assert row["is_threat"] == 1


def test_get_performance_metrics_returns_correct_keys():
    db.record_latency_sample("/scan", 15.0)
    db.record_latency_sample("/scan", 25.0)
    db.record_latency_sample("/scan", 35.0)
    metrics = db.get_performance_metrics()
    expected_keys = {
        "avg_scan_latency_ms", "p95_scan_latency_ms", "p99_scan_latency_ms",
        "total_scans_24h", "blocked_24h", "mcp_tool_approval_rate",
        "drift_detections_24h", "uptime_seconds",
    }
    assert expected_keys.issubset(metrics.keys())


def test_get_performance_metrics_avg_latency_nonzero():
    metrics = db.get_performance_metrics()
    assert metrics["avg_scan_latency_ms"] > 0


def test_metrics_endpoint_requires_admin_token():
    import proxy
    old_token = admin.ADMIN_TOKEN
    admin.ADMIN_TOKEN = "test-admin-tok"
    try:
        client = TestClient(proxy.app)
        # No admin token at all → 401
        resp = client.get("/metrics/performance")
        assert resp.status_code in (401, 403)
        # Invalid admin token → 401
        resp2 = client.get("/metrics/performance", headers={"x-admin-token": "wrong"})
        assert resp2.status_code in (401, 403)
    finally:
        admin.ADMIN_TOKEN = old_token


def test_metrics_endpoint_returns_data_with_admin_token():
    import proxy
    from core import db as _db
    _db.DB_PATH = _tmp_db
    old_token = admin.ADMIN_TOKEN
    admin.ADMIN_TOKEN = "test-admin-tok"
    try:
        client = TestClient(proxy.app)
        resp = client.get(
            "/metrics/performance",
            headers={"x-admin-token": "test-admin-tok"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "avg_scan_latency_ms" in data
        assert "uptime_seconds" in data
        assert "mcp_tool_approval_rate" in data  # renamed from false_positive_rate
        assert data["uptime_seconds"] >= 0
    finally:
        admin.ADMIN_TOKEN = old_token
