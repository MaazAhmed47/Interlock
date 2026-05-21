"""
Smoke tests for routes ported from api.py to proxy.py:
  POST /scan/output  - response PII/data-leak scanning
  WebSocket /ws      - real-time broadcast feed handler
  GET /usage         - per-key quota stats

Run: python -m pytest tests/test_new_routes.py -v
"""
import asyncio
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

TEST_DB = tempfile.mktemp(suffix="_new_routes_test.db")
os.environ["FIREWALL_DB_PATH"] = TEST_DB

from core import db
import proxy


TEST_KEY = "lf-free-demo-key-123"


@pytest.fixture(scope="module", autouse=True)
def seeded_db():
    db.init_db()
    db.seed_legacy_keys()
    yield

    for path in (TEST_DB, TEST_DB + "-wal", TEST_DB + "-shm"):
        try:
            os.unlink(path)
        except OSError:
            pass


def run(coro):
    return asyncio.run(coro)


def test_scan_output_blocks_ssn():
    result = run(proxy.scan_output(
        proxy.ScanRequest(prompt="The patient's SSN is 123-45-6789 and they live in Denver."),
        x_api_key=TEST_KEY,
    ))

    assert result.is_threat is True
    assert result.threat_type == "OUTPUT_DATA_LEAK"
    assert result.safe_to_proceed is False


def test_scan_output_passes_clean_response():
    result = run(proxy.scan_output(
        proxy.ScanRequest(prompt="The weather in Denver is sunny with a high of 72 degrees."),
        x_api_key=TEST_KEY,
    ))

    assert result.is_threat is False
    assert result.safe_to_proceed is True


def test_scan_output_rejects_missing_key():
    with pytest.raises(proxy.HTTPException) as exc:
        run(proxy.scan_output(proxy.ScanRequest(prompt="some text"), x_api_key=None))

    assert exc.value.status_code == 401


def test_usage_returns_expected_fields():
    data = run(proxy.usage(x_api_key=TEST_KEY))

    assert "used_this_month" in data
    assert "monthly_limit" in data
    assert "remaining" in data
    assert "plan" in data


def test_usage_remaining_math():
    data = run(proxy.usage(x_api_key=TEST_KEY))

    if data["monthly_limit"] == 0:
        assert data["remaining"] is None
    else:
        assert data["remaining"] == data["monthly_limit"] - data["used_this_month"]


def test_usage_rejects_missing_key():
    with pytest.raises(proxy.HTTPException) as exc:
        run(proxy.usage(x_api_key=None))

    assert exc.value.status_code == 401


def test_websocket_handler_accepts_and_cleans_up_connection():
    class FakeWebSocket:
        def __init__(self):
            self.accepted = False

        async def accept(self):
            self.accepted = True

        async def send_json(self, _message):
            raise AssertionError("No ping should be sent before forced disconnect")

    async def disconnect_immediately(_seconds):
        raise proxy.WebSocketDisconnect(code=1000)

    fake = FakeWebSocket()
    original_sleep = proxy.asyncio.sleep
    proxy.asyncio.sleep = disconnect_immediately
    try:
        run(proxy.websocket_feed(fake))
    finally:
        proxy.asyncio.sleep = original_sleep

    assert fake.accepted is True
    assert fake not in proxy._active_ws
