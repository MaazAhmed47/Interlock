"""
Tests for three routes ported from api.py to proxy.py:
  POST /scan/output  — LLM response PII scanning
  WebSocket /ws      — real-time broadcast feed
  GET /usage         — per-key quota stats

Run: python test_new_routes.py
"""
import sys, os
sys.path.insert(0, ".")
os.environ.setdefault("FIREWALL_DB_PATH", "data/test_new_routes.db")

from starlette.testclient import TestClient
from proxy import app

TEST_KEY = "lf-free-demo-key-123"  # seeded by db.seed_legacy_keys()

with TestClient(app) as client:
    # ── POST /scan/output ─────────────────────────────────────────────────────

    print("Test 1: /scan/output blocks LLM response containing SSN ...")
    resp = client.post(
        "/scan/output",
        json={"prompt": "The patient's SSN is 123-45-6789 and they live in Denver."},
        headers={"x-api-key": TEST_KEY},
    )
    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"
    data = resp.json()
    assert data["is_threat"] is True, f"Expected is_threat=True, got {data}"
    assert data["threat_type"] == "OUTPUT_DATA_LEAK", f"Expected OUTPUT_DATA_LEAK, got {data['threat_type']}"
    print(f"  OK — blocked, threat_type={data['threat_type']}")

    print("Test 2: /scan/output passes clean LLM response ...")
    resp = client.post(
        "/scan/output",
        json={"prompt": "The weather in Denver is sunny with a high of 72 degrees."},
        headers={"x-api-key": TEST_KEY},
    )
    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"
    data = resp.json()
    assert data["is_threat"] is False, f"Expected is_threat=False, got {data}"
    print(f"  OK — clean, threat_level={data['threat_level']}")

    print("Test 3: /scan/output rejects request with no API key ...")
    resp = client.post("/scan/output", json={"prompt": "some text"})
    assert resp.status_code == 401, f"Expected 401, got {resp.status_code}"
    print("  OK — 401 without key")

    # ── GET /usage ────────────────────────────────────────────────────────────

    print("Test 4: /usage returns used_this_month, monthly_limit, remaining ...")
    resp = client.get("/usage", headers={"x-api-key": TEST_KEY})
    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"
    data = resp.json()
    assert "used_this_month" in data, f"Missing used_this_month: {data}"
    assert "monthly_limit" in data, f"Missing monthly_limit: {data}"
    assert "remaining" in data, f"Missing remaining: {data}"
    assert "plan" in data, f"Missing plan: {data}"
    if data["monthly_limit"] == 0:
        assert data["remaining"] is None, f"Expected remaining=None for unlimited, got {data}"
    else:
        expected_remaining = data["monthly_limit"] - data["used_this_month"]
        assert data["remaining"] == expected_remaining, f"remaining math wrong: {data}"
    print(f"  OK — {data}")

    print("Test 5: /usage rejects request with no API key ...")
    resp = client.get("/usage")
    assert resp.status_code == 401, f"Expected 401, got {resp.status_code}"
    print("  OK — 401 without key")

    # ── WebSocket /ws ─────────────────────────────────────────────────────────

    print("Test 6: /ws accepts WebSocket connection ...")
    with client.websocket_connect("/ws") as ws:
        # Connection accepted — dashboard uses this for the live scan feed
        pass
    print("  OK — WebSocket connected and disconnected cleanly")

print("\nAll tests passed.")
