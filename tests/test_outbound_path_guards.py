"""Hermetic transport-boundary tests for configurable server-side egress."""

from __future__ import annotations

import asyncio
import json
import socket
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from core import (
    admin,
    effect_readback,
    effective_permission,
    mcp_gateway,
    shadow_scanner,
)
from core import siem, webhook
from core.ema_auth import EMAAuthError, TrustedJWKSCache
from core.outbound_http import create_async_client
from core.url_security import OutboundUrlRejected
from models.schemas import ScanResult, ThreatLevel
from tests.test_ema_config import valid_raw_config


def _run(coro):
    return asyncio.run(coro)


def _private_resolution(_host, port, **_kwargs):
    return [
        (
            socket.AF_INET,
            socket.SOCK_STREAM,
            socket.IPPROTO_TCP,
            "",
            ("10.0.0.8", port),
        )
    ]


def _protected(monkeypatch) -> None:
    monkeypatch.setenv("INTERLOCK_ENV", "production")
    monkeypatch.delenv("INTERLOCK_ALLOW_PRIVATE_OUTBOUND", raising=False)
    monkeypatch.delenv("INTERLOCK_OFFLINE_DEMO", raising=False)
    monkeypatch.setattr("core.url_security.socket.getaddrinfo", _private_resolution)


def _client_factory_counter():
    calls = []

    def factory(*args, **kwargs):
        calls.append((args, kwargs))
        raise AssertionError("HTTP client must not be constructed")

    return calls, factory


def _threat_result() -> ScanResult:
    return ScanResult(
        is_threat=True,
        threat_level=ThreatLevel.HIGH,
        threat_type="AUDIT",
        reason="content stays local",
        original_prompt="sensitive body stays local",
        safe_to_proceed=False,
    )


def _credentialed_server() -> dict:
    return {
        "server_id": "audit-server",
        "url": "http://service.audit.invalid/mcp",
        "verified": True,
        "allowed_tools": ["read_note"],
        "blocked_tools": [],
        "auth_type": "bearer",
        "auth_header": "Authorization",
        "auth_token_env": "AUDIT_UPSTREAM_TOKEN",
        "upstream_protocol_profile": "legacy",
        "environment": "non_production",
        "probes_enabled": True,
        "provenance_status": "verified",
    }


def test_per_key_webhook_rejects_before_payload_transport(monkeypatch):
    _protected(monkeypatch)
    calls, factory = _client_factory_counter()
    monkeypatch.setattr(
        webhook,
        "_resolve_webhook_url",
        lambda _key: "http://service.audit.invalid/hook-secret",
    )
    monkeypatch.setattr(webhook.httpx, "AsyncClient", factory)

    _run(webhook.fire_webhook("raw-key-must-not-be-forwarded", _threat_result()))

    assert calls == []


def test_siem_rejects_before_sensitive_headers_or_body_transport(monkeypatch):
    _protected(monkeypatch)
    calls, factory = _client_factory_counter()
    monkeypatch.setattr(siem.httpx, "AsyncClient", factory)

    result = _run(
        siem.send_to_siem(
            "webhook",
            {
                "url": "http://service.audit.invalid/events",
                "headers": {"Authorization": "Bearer must-stay-local"},
            },
            _threat_result(),
            "key-prefix",
        )
    )

    assert result["error"] == "unsafe_outbound_url"
    assert calls == []


def test_mcp_discovery_rejects_before_upstream_token_transport(monkeypatch):
    _protected(monkeypatch)
    monkeypatch.setenv("MCP_UPSTREAM_AUTH_ALLOWED_ENV_VARS", "AUDIT_UPSTREAM_TOKEN")
    monkeypatch.setenv("AUDIT_UPSTREAM_TOKEN", "must-stay-local")
    server = _credentialed_server()
    calls, factory = _client_factory_counter()
    monkeypatch.setattr(mcp_gateway.httpx, "AsyncClient", factory)
    monkeypatch.setattr(mcp_gateway.db, "lookup_mcp_server", lambda _sid: server)

    result = _run(
        mcp_gateway._fetch_tool_list_payload(server["url"], 3.0, server["server_id"])
    )

    assert result["error"] == "unsafe_mcp_server_url"
    assert calls == []


def test_mcp_call_rejects_before_token_and_arguments_transport(monkeypatch):
    _protected(monkeypatch)
    monkeypatch.setenv("MCP_UPSTREAM_AUTH_ALLOWED_ENV_VARS", "AUDIT_UPSTREAM_TOKEN")
    monkeypatch.setenv("AUDIT_UPSTREAM_TOKEN", "must-stay-local")
    server = _credentialed_server()
    calls, factory = _client_factory_counter()
    monkeypatch.setattr(mcp_gateway.httpx, "AsyncClient", factory)
    monkeypatch.setattr(mcp_gateway.db, "lookup_mcp_server", lambda _sid: server)
    monkeypatch.setattr(mcp_gateway.db, "lookup_mcp_tool_metadata", lambda *_args: None)
    monkeypatch.setattr(mcp_gateway.db, "get_policy_by_name", lambda *_args: None)
    monkeypatch.setattr(mcp_gateway.db, "load_mcp04_policy", lambda: {})
    monkeypatch.setattr(
        mcp_gateway,
        "evaluate_metadata_policy",
        lambda **_kwargs: {
            "action": "allow",
            "reason": "allowed",
            "matched_rule": "none",
            "warnings": [],
            "audit_context": {},
        },
    )
    monkeypatch.setattr(
        mcp_gateway, "_log_mcp_policy_audit", lambda *_args, **_kwargs: {"id": 1}
    )
    monkeypatch.setattr(
        "core.provenance.evaluate_provenance",
        lambda *_args, **_kwargs: SimpleNamespace(status="verified", reason="ok"),
    )

    result = _run(
        mcp_gateway.proxy_mcp_tool_call(
            server["server_id"], "read_note", {"id": "sensitive-argument"}
        )
    )

    assert result["error"] == "unsafe_mcp_server_url"
    assert calls == []


@pytest.mark.parametrize(
    "module,call,expected_error",
    (
        (
            effective_permission,
            lambda server: effective_permission._call_upstream_for_observation(
                server,
                {"tool_name": "read_note", "arguments": {"id": "sensitive"}},
            ),
            "unsafe_mcp_server_url",
        ),
        (
            effect_readback,
            lambda server: effect_readback._call_upstream_tool(
                server, "read_note", {"id": "sensitive"}
            ),
            "unsafe_mcp_server_url",
        ),
    ),
    ids=("effective-permission", "effect-readback"),
)
def test_probe_paths_reject_before_token_and_body_transport(
    monkeypatch, module, call, expected_error
):
    _protected(monkeypatch)
    monkeypatch.setenv("MCP_UPSTREAM_AUTH_ALLOWED_ENV_VARS", "AUDIT_UPSTREAM_TOKEN")
    monkeypatch.setenv("AUDIT_UPSTREAM_TOKEN", "must-stay-local")
    calls, factory = _client_factory_counter()
    monkeypatch.setattr(module.httpx, "AsyncClient", factory)

    result = _run(call(_credentialed_server()))

    assert result["error_class"] == expected_error
    assert calls == []


def test_shadow_scanner_rejects_before_get_transport(monkeypatch):
    _protected(monkeypatch)
    client = SimpleNamespace(get=AsyncMock(), aclose=AsyncMock())

    result = _run(
        shadow_scanner.probe_target("http://service.audit.invalid", client=client)
    )

    assert result.responded is False
    assert result.error == "unsafe_outbound_url"
    client.get.assert_not_awaited()


def test_ema_jwks_rejects_before_mock_transport(monkeypatch):
    _protected(monkeypatch)
    from core.ema_config import load_experimental_ema_settings

    settings = load_experimental_ema_settings(valid_raw_config())
    assert settings is not None
    requests = []

    async def handler(request):
        requests.append(request)
        return httpx.Response(200, content=json.dumps({"keys": []}).encode())

    cache = TrustedJWKSCache(settings, transport=httpx.MockTransport(handler))

    with pytest.raises(EMAAuthError, match="jwks_unavailable"):
        _run(cache._refresh())
    assert requests == []


def test_admin_oidc_jwks_rejects_before_dependency_client(monkeypatch):
    _protected(monkeypatch)
    monkeypatch.setattr(admin, "OIDC_JWKS_URL", "https://service.audit.invalid/jwks")
    monkeypatch.setattr(admin, "_OIDC_JWKS_CLIENT", None)
    monkeypatch.setattr(admin, "_OIDC_JWKS_CLIENT_URL", "")
    clients = []

    class FakeJWKClient:
        def __init__(self, url):
            clients.append(url)

        def get_signing_key_from_jwt(self, _token):
            return SimpleNamespace(key="unexpected")

    monkeypatch.setattr(admin.jwt, "PyJWKClient", FakeJWKClient)

    with pytest.raises(OutboundUrlRejected):
        admin._get_oidc_signing_key("synthetic-token")
    assert clients == []


def test_controlled_httpx_clients_disable_all_ambient_proxy_settings(monkeypatch):
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY"):
        monkeypatch.setenv(name, "http://proxy.audit.invalid:8080")

    with patch("core.outbound_http.httpx.AsyncClient") as constructor:
        create_async_client(timeout=1.0, purpose="ambient proxy regression")

    assert constructor.call_args.kwargs["trust_env"] is False
    assert constructor.call_args.kwargs["proxy"] is None


def test_pagerduty_guard_rejects_before_routing_key_enters_event(monkeypatch):
    result = _threat_result()
    guard = AsyncMock(side_effect=OutboundUrlRejected("blocked"))
    monkeypatch.setattr(siem, "ensure_safe_outbound_url_async", guard)

    def must_not_build(*_args, **_kwargs):
        raise AssertionError("routing key entered event before destination validation")

    monkeypatch.setattr(siem, "build_pagerduty_event", must_not_build)
    outcome = _run(
        siem.send_to_siem(
            "pagerduty",
            {"integration_key": "synthetic-routing-key"},
            result,
            "lf_test",
        )
    )

    assert outcome["ok"] is False
    assert outcome["error"] == "unsafe_outbound_url"


def test_outbound_and_siem_docs_state_proxy_and_private_destination_limits():
    root = Path(__file__).resolve().parents[1]
    outbound = (root / "docs/outbound-destination-security.md").read_text(
        encoding="utf-8"
    )
    siem_docs = (root / "docs/siem-integrations.md").read_text(encoding="utf-8")

    assert (
        "hostname resolution rejection is a partial mitigation; DNS rebinding "
        "requires connection pinning or an enforced egress proxy/firewall." in outbound
    )
    for variable in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY"):
        assert variable in outbound
    assert "unsupported\nfor guarded egress" in outbound
    assert "Direct private SIEM delivery is" in siem_docs
    assert "not supported by the Phase 1 production profile" in siem_docs
