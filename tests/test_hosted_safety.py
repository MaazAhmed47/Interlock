"""Hosted-mode safety hardening tests."""

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
TEST_DB = tempfile.mktemp(suffix="_hosted_safety_test.db")
os.environ["FIREWALL_DB_PATH"] = TEST_DB

import config
import proxy
from core import db
from core.limits import clamp_limit
from core.siem import send_to_siem
from core.url_security import OutboundUrlRejected, ensure_safe_outbound_url

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


def test_production_rejects_wildcard_cors(monkeypatch):
    monkeypatch.setenv("INTERLOCK_ENV", "production")
    monkeypatch.setenv("ALLOWED_ORIGINS", "*")

    with pytest.raises(RuntimeError):
        config.cors_allowed_origins()


def test_development_allows_default_cors(monkeypatch):
    monkeypatch.setenv("INTERLOCK_ENV", "development")
    monkeypatch.delenv("ALLOWED_ORIGINS", raising=False)

    assert config.cors_allowed_origins() == ["*"]


def test_api_docs_default_off_in_production(monkeypatch):
    monkeypatch.setenv("INTERLOCK_ENV", "production")
    monkeypatch.delenv("ENABLE_API_DOCS", raising=False)

    assert config.api_docs_enabled() is False


def test_outbound_guard_blocks_private_targets_in_protected_mode(monkeypatch):
    monkeypatch.setenv("INTERLOCK_ENV", "production")
    monkeypatch.delenv("INTERLOCK_ALLOW_PRIVATE_OUTBOUND", raising=False)

    blocked = [
        "http://localhost:9999/mcp",
        "http://127.0.0.1:9999/mcp",
        "http://0.0.0.0:9999/mcp",
        "http://10.0.0.5/mcp",
        "http://169.254.169.254/latest/meta-data",
        "http://metadata.google.internal/computeMetadata/v1",
        "file:///tmp/socket",
    ]
    for url in blocked:
        with pytest.raises(OutboundUrlRejected):
            ensure_safe_outbound_url(url, context="test")


def test_outbound_guard_allows_localhost_in_development(monkeypatch):
    monkeypatch.setenv("INTERLOCK_ENV", "development")
    monkeypatch.delenv("INTERLOCK_PROTECT_OUTBOUND_URLS", raising=False)

    assert (
        ensure_safe_outbound_url("http://localhost:9999/mcp", context="test")
        == "http://localhost:9999/mcp"
    )


def test_mcp_register_rejects_unsafe_url_in_production(monkeypatch):
    monkeypatch.setenv("INTERLOCK_ENV", "production")
    monkeypatch.delenv("INTERLOCK_ALLOW_PRIVATE_OUTBOUND", raising=False)

    with pytest.raises(proxy.HTTPException) as exc:
        run(
            proxy.mcp_register(
                proxy.MCPRegisterRequest(
                    server_id="unsafe-local",
                    url="http://127.0.0.1:9999/mcp",
                ),
                x_api_key=TEST_KEY,
            )
        )

    assert exc.value.status_code == 400
    assert "not allowed" in str(exc.value.detail)


def test_siem_test_does_not_call_private_webhook_in_production(monkeypatch):
    monkeypatch.setenv("INTERLOCK_ENV", "production")
    monkeypatch.delenv("INTERLOCK_ALLOW_PRIVATE_OUTBOUND", raising=False)

    result = proxy.ScanResult(
        is_threat=True,
        threat_level=proxy.ThreatLevel.HIGH,
        threat_type="TEST",
        reason="test",
        original_prompt="test",
        safe_to_proceed=False,
    )
    out = run(
        send_to_siem(
            "webhook",
            {"url": "http://127.0.0.1:9999/alerts"},
            result,
            "test-key",
        )
    )

    assert out["ok"] is False
    assert out["error"] == "unsafe_outbound_url"


def test_route_limits_are_clamped(monkeypatch):
    captured = {}

    def fake_history(_raw_key, limit):
        captured["scan_limit"] = limit
        return []

    def fake_audit(limit):
        captured["audit_limit"] = limit
        return []

    monkeypatch.setattr(proxy.scan_routes, "get_history", fake_history)
    monkeypatch.setattr(proxy.mcp_routes.db, "list_mcp_audit_logs", fake_audit)

    run(proxy.scan_history(limit=999999, x_api_key=TEST_KEY))
    run(proxy.mcp_audit(limit=999999, x_api_key=TEST_KEY))

    assert captured["scan_limit"] == proxy.scan_routes.MAX_SCAN_HISTORY_LIMIT
    assert captured["audit_limit"] == proxy.mcp_routes.MAX_MCP_AUDIT_LIMIT
    assert clamp_limit(0, default=50, maximum=500) == 1
