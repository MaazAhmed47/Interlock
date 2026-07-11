# ruff: noqa: E402
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

import config  # noqa: E402
import proxy  # noqa: E402
from core import db  # noqa: E402
from core.limits import clamp_limit  # noqa: E402
from core.siem import send_to_siem  # noqa: E402
from core.url_security import (
    OutboundUrlRejected,
    ensure_safe_outbound_url,
)  # noqa: E402

TEST_KEY = None  # minted in the seeded_db fixture via db.generate_key


@pytest.fixture(scope="module", autouse=True)
def seeded_db():
    global TEST_KEY
    db.init_db()
    TEST_KEY = db.generate_key("free", label="test-hosted-safety")["raw_key"]
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


def test_offline_allowlist_accepts_bundled_mock_and_rejects_other_hosts(monkeypatch):
    allowed_server_id = "_test_offline_allowlisted_mock"
    rejected_server_id = "_test_offline_unallowlisted_host"
    db.unregister_mcp_server(allowed_server_id)
    db.unregister_mcp_server(rejected_server_id)
    monkeypatch.setenv("INTERLOCK_ENV", "local")
    monkeypatch.setenv("INTERLOCK_ALLOW_PRIVATE_OUTBOUND", "true")
    monkeypatch.setenv("MCP_REGISTRY_ALLOWED_HOSTS", "mcp-mock")

    try:
        accepted = run(
            proxy.mcp_register(
                proxy.MCPRegisterRequest(
                    server_id=allowed_server_id,
                    url="http://mcp-mock:9100/docs",
                ),
                x_api_key=TEST_KEY,
            )
        )
        assert accepted.get("ok") is True
        assert db.lookup_mcp_server(allowed_server_id) is not None

        with pytest.raises(proxy.HTTPException) as exc:
            run(
                proxy.mcp_register(
                    proxy.MCPRegisterRequest(
                        server_id=rejected_server_id,
                        url="https://not-allowlisted.invalid/mcp",
                    ),
                    x_api_key=TEST_KEY,
                )
            )

        assert exc.value.status_code == 400
        assert "Host 'not-allowlisted.invalid' is not allowed" in str(exc.value.detail)
        assert db.lookup_mcp_server(rejected_server_id) is None
    finally:
        db.unregister_mcp_server(allowed_server_id)
        db.unregister_mcp_server(rejected_server_id)


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
