# ruff: noqa: E402
"""Hosted-mode safety hardening tests."""

import asyncio
import logging
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
    TEST_KEY = db.generate_key("free", label="test-hosted-safety", scopes=["admin"])[
        "raw_key"
    ]
    yield
    for path in (TEST_DB, TEST_DB + "-wal", TEST_DB + "-shm"):
        try:
            os.unlink(path)
        except OSError:
            pass


def run(coro):
    return asyncio.run(coro)


async def run_lifespan():
    async with proxy.lifespan(proxy.app):
        pass


PRODUCTION_ENV_VARS = (
    "INTERLOCK_ENV",
    "APP_ENV",
    "ENVIRONMENT",
    "ENV",
    "RENDER",
    "VERCEL",
    "RAILWAY_ENVIRONMENT",
    "FLY_APP_NAME",
    "K_SERVICE",
)


def clear_production_environment(monkeypatch):
    for name in PRODUCTION_ENV_VARS:
        monkeypatch.delenv(name, raising=False)


def registry_row_counts():
    with db.get_conn() as conn:
        server_count = conn.execute(
            "SELECT COUNT(*) AS count FROM mcp_servers"
        ).fetchone()["count"]
        tool_count = conn.execute(
            "SELECT COUNT(*) AS count FROM mcp_tool_metadata"
        ).fetchone()["count"]
    return server_count, tool_count


@pytest.mark.parametrize(
    "deployment_posture",
    ("explicit-production", "hosted-render-with-local-override"),
    ids=("explicit-production", "hosted-render"),
)
def test_offline_demo_fails_before_database_seeding_in_production(
    monkeypatch, caplog, deployment_posture
):
    clear_production_environment(monkeypatch)
    if deployment_posture == "explicit-production":
        monkeypatch.setenv("INTERLOCK_ENV", "production")
    else:
        monkeypatch.setenv("INTERLOCK_ENV", "local")
        monkeypatch.setenv("RENDER", "true")
    monkeypatch.setenv("INTERLOCK_OFFLINE_DEMO", "true")
    caplog.set_level(logging.DEBUG)
    startup_db_calls = []

    for function_name in (
        "init_db",
        "seed_legacy_keys",
        "seed_mcp_servers",
        "seed_default_policies",
        "seed_offline_demo_key",
    ):
        monkeypatch.setattr(
            db,
            function_name,
            lambda *args, _name=function_name, **kwargs: startup_db_calls.append(_name),
        )

    with pytest.raises(RuntimeError) as exc:
        run(run_lifespan())

    assert startup_db_calls == []
    emitted_text = f"{exc.value}\n{caplog.text}"
    assert "production or hosted" in emitted_text
    assert db.OFFLINE_DEMO_KEY not in emitted_text


@pytest.mark.parametrize(
    "deployment_posture",
    ("normal-local", "explicit-production", "hosted-render"),
)
def test_non_demo_startup_seeds_no_demo_credentials_or_registry_data(
    monkeypatch, tmp_path, deployment_posture
):
    clear_production_environment(monkeypatch)
    if deployment_posture == "normal-local":
        monkeypatch.setenv("INTERLOCK_ENV", "local")
    elif deployment_posture == "explicit-production":
        monkeypatch.setenv("INTERLOCK_ENV", "production")
    else:
        monkeypatch.setenv("RENDER", "true")
    monkeypatch.delenv("INTERLOCK_OFFLINE_DEMO", raising=False)
    monkeypatch.setattr(
        db, "DB_PATH", str(tmp_path / f"{deployment_posture}-startup.db")
    )

    run(run_lifespan())

    assert db.lookup_key(db.OFFLINE_DEMO_KEY) is None
    assert db.list_mcp_servers() == []
    assert registry_row_counts() == (0, 0)


def test_local_offline_demo_startup_seeds_fixed_demo_key(monkeypatch, tmp_path):
    clear_production_environment(monkeypatch)
    monkeypatch.setenv("INTERLOCK_ENV", "local")
    monkeypatch.setenv("INTERLOCK_OFFLINE_DEMO", "true")
    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "local-offline-demo.db"))

    run(run_lifespan())

    record = db.lookup_key(db.OFFLINE_DEMO_KEY)
    assert record is not None
    assert record["role"] == "readonly_agent"
    assert record["scopes"] == db.OFFLINE_DEMO_KEY_SCOPES
    assert {server["server_id"] for server in db.list_mcp_servers()} == (
        db.SEEDED_DEMO_SERVER_IDS
    )
    assert registry_row_counts() == (len(db.SEEDED_DEMO_SERVER_IDS), 0)


def test_registry_allowlists_default_empty_and_external_fixtures_rejected(
    monkeypatch,
):
    monkeypatch.delenv("MCP_REGISTRY_ALLOWED_HOSTS", raising=False)
    monkeypatch.delenv("MCP_REGISTRY_ALLOWED_HOST_SUFFIXES", raising=False)

    assert db._configured_allowed_mcp_hosts() == set()
    assert db._configured_allowed_mcp_suffixes() == ()

    rejected_targets = (
        ("_fixture_public_mock", "https://fixture.web.val.run/mcp"),
        ("trusted-filesystem", "https://mcp.acme-corp.internal/filesystem"),
        ("clean-proof-docs", "https://demo.web.val.run/mcp"),
    )
    for server_id, url in rejected_targets:
        with pytest.raises(ValueError, match="explicit allowlist"):
            db.validate_mcp_registration_target(server_id, url)


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
