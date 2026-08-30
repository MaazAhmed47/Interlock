from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from core.outbound_http import (
    OutboundHTTPConfigurationError,
    create_async_client,
    is_trusted_sync_client,
)


def _enforced(monkeypatch) -> None:
    monkeypatch.setenv("INTERLOCK_EGRESS_PROFILE", "enforced")
    monkeypatch.setenv("INTERLOCK_OUTBOUND_HTTP_PROXY", "http://egress-proxy:3128")


def _run(coroutine):
    return asyncio.run(coroutine)


def test_enforced_profile_disables_ollama_loopback_before_network(monkeypatch):
    _enforced(monkeypatch)
    from core import router

    with patch("core.router.create_async_client") as factory:
        result = _run(
            router.forward_to_provider(
                "ollama", {"model": "ollama:llama3", "messages": []}
            )
        )

    factory.assert_not_called()
    assert result == {
        "error": "outbound_profile_restriction",
        "provider": "ollama",
        "message": "Ollama loopback routing is disabled in the enforced egress profile.",
    }


def test_enforced_missing_proxy_stops_lifespan_before_database_work(monkeypatch):
    monkeypatch.setenv("INTERLOCK_EGRESS_PROFILE", "enforced")
    monkeypatch.delenv("INTERLOCK_OUTBOUND_HTTP_PROXY", raising=False)
    import proxy

    async def start_application():
        async with proxy.lifespan(proxy.app):
            raise AssertionError(
                "invalid egress configuration reached application body"
            )

    with patch.object(proxy.db, "init_db") as init_db:
        with pytest.raises(OutboundHTTPConfigurationError):
            _run(start_application())

    init_db.assert_not_called()


def test_groq_sdk_receives_factory_created_client_and_disables_sdk_retries(monkeypatch):
    _enforced(monkeypatch)
    from core import llm_judge

    monkeypatch.setattr(llm_judge, "GROQ_API_KEY", "gsk_synthetic_unit_test")
    built_sdk = MagicMock()
    with patch("core.llm_judge.Groq", return_value=built_sdk) as groq_ctor:
        sdk = llm_judge._build_groq_client()

    assert sdk is built_sdk
    kwargs = groq_ctor.call_args.kwargs
    assert kwargs["api_key"] == "gsk_synthetic_unit_test"
    assert kwargs["max_retries"] == 0
    assert is_trusted_sync_client(kwargs["http_client"])
    kwargs["http_client"].close()


def test_shadow_scanner_rejects_untrusted_injected_client_in_enforced_profile(
    monkeypatch,
):
    _enforced(monkeypatch)
    from core.shadow_scanner import probe_target

    untrusted = AsyncMock(spec=httpx.AsyncClient)
    with pytest.raises(OutboundHTTPConfigurationError):
        _run(probe_target("https://safe.example", client=untrusted))
    untrusted.get.assert_not_called()


def test_enforced_profile_rejects_factory_client_created_under_phase1(monkeypatch):
    monkeypatch.setenv("INTERLOCK_EGRESS_PROFILE", "phase1")
    monkeypatch.delenv("INTERLOCK_OUTBOUND_HTTP_PROXY", raising=False)
    from core.shadow_scanner import probe_target

    legacy_client = create_async_client(timeout=1.0, purpose="legacy client")
    _enforced(monkeypatch)

    async def exercise():
        try:
            with pytest.raises(OutboundHTTPConfigurationError):
                await probe_target("https://safe.example", client=legacy_client)
        finally:
            await legacy_client.aclose()

    _run(exercise())


def test_shadow_scanner_accepts_factory_created_client_in_enforced_profile(
    monkeypatch,
):
    _enforced(monkeypatch)
    from core import shadow_scanner

    response = SimpleNamespace(status_code=401)
    trusted = create_async_client(timeout=1.0, purpose="trusted injected test client")
    trusted.get = AsyncMock(return_value=response)
    monkeypatch.setattr(
        shadow_scanner,
        "ensure_safe_outbound_url_async",
        AsyncMock(return_value="https://safe.example/tools/list"),
    )

    async def exercise():
        try:
            return await shadow_scanner.probe_target(
                "https://safe.example", client=trusted
            )
        finally:
            await trusted.aclose()

    result = _run(exercise())

    assert result.auth_required is True
    trusted.get.assert_awaited_once()


def test_ema_rejects_untrusted_transport_in_enforced_profile(monkeypatch):
    _enforced(monkeypatch)
    from core.ema_auth import TrustedJWKSCache

    settings = SimpleNamespace(
        jwks_connect_timeout_seconds=1.0,
        jwks_read_timeout_seconds=1.0,
        jwks_total_timeout_seconds=2.0,
        jwks_uri="https://issuer.example/jwks",
        jwks_negative_cache_ttl_seconds=30,
        jwks_negative_cache_max_entries=10,
    )
    transport = httpx.MockTransport(lambda request: httpx.Response(200, json={}))
    cache = TrustedJWKSCache(settings, transport=transport)

    with pytest.raises(OutboundHTTPConfigurationError):
        _run(cache._refresh())


def test_router_does_not_disclose_query_or_transport_exception(monkeypatch):
    _enforced(monkeypatch)
    from core import router

    sentinel = "phase2-google-api-key-sentinel"
    failing_client = AsyncMock()
    failing_client.__aenter__.return_value = failing_client
    failing_client.__aexit__.return_value = False
    failing_client.post.side_effect = httpx.ConnectError(
        f"could not connect using {sentinel}",
        request=httpx.Request("POST", f"https://provider.example/model?key={sentinel}"),
    )
    monkeypatch.setattr(router, "create_async_client", lambda **kwargs: failing_client)

    result = _run(
        router.forward_to_provider(
            "google", {"model": "gemini-test", "messages": []}, api_key=sentinel
        )
    )

    assert result == {
        "error": "upstream_error",
        "provider": "google",
        "message": "connection_failed",
    }
    called_url = failing_client.post.call_args.args[0]
    called_headers = failing_client.post.call_args.kwargs["headers"]
    assert sentinel not in called_url
    assert "?" not in called_url
    assert called_headers["x-goog-api-key"] == sentinel
    assert sentinel not in repr(result)


def test_webhook_logs_never_disclose_transport_exception(monkeypatch, caplog):
    _enforced(monkeypatch)
    from core import webhook
    from models.schemas import ScanResult, ThreatLevel

    sentinel = "phase2-proxy-log-sentinel"
    failing_client = AsyncMock()
    failing_client.__aenter__.return_value = failing_client
    failing_client.__aexit__.return_value = False
    failing_client.post.side_effect = httpx.ConnectError(
        f"proxy credential {sentinel}",
        request=httpx.Request("POST", "https://webhook.example/alert"),
    )
    monkeypatch.setattr(
        webhook, "_resolve_webhook_url", lambda api_key: "https://webhook.example/alert"
    )
    monkeypatch.setattr(
        webhook,
        "ensure_safe_outbound_url_async",
        AsyncMock(return_value="https://webhook.example/alert"),
    )
    monkeypatch.setattr(webhook, "create_async_client", lambda **kwargs: failing_client)
    result = ScanResult(
        is_threat=True,
        threat_level=ThreatLevel.HIGH,
        reason="test",
        original_prompt="synthetic",
        safe_to_proceed=False,
        confidence=0.9,
    )

    _run(webhook.fire_webhook("lf-test-key", result))

    assert sentinel not in caplog.text
    assert "Webhook connection failed" in caplog.text


def test_webhook_redirect_response_is_not_reported_as_delivery(monkeypatch, caplog):
    from core import webhook
    from models.schemas import ScanResult, ThreatLevel

    response = SimpleNamespace(status_code=302)
    client = AsyncMock()
    client.__aenter__.return_value = client
    client.__aexit__.return_value = False
    client.post.return_value = response
    monkeypatch.setattr(
        webhook, "_resolve_webhook_url", lambda api_key: "https://webhook.example/alert"
    )
    monkeypatch.setattr(
        webhook,
        "ensure_safe_outbound_url_async",
        AsyncMock(return_value="https://webhook.example/alert"),
    )
    monkeypatch.setattr(webhook, "create_async_client", lambda **kwargs: client)
    result = ScanResult(
        is_threat=True,
        threat_level=ThreatLevel.HIGH,
        reason="test",
        original_prompt="synthetic",
        safe_to_proceed=False,
        confidence=0.9,
    )

    _run(webhook.fire_webhook("lf-test-key", result))

    assert "Webhook returned non-2xx" in caplog.text
    client.post.assert_awaited_once()


def test_siem_rejects_verify_ssl_false_without_disclosure(monkeypatch):
    _enforced(monkeypatch)
    from core import siem
    from models.schemas import ScanResult, ThreatLevel

    monkeypatch.setattr(
        siem,
        "ensure_safe_outbound_url_async",
        AsyncMock(return_value="https://splunk.example/services/collector/event"),
    )
    result = ScanResult(
        is_threat=True,
        threat_level=ThreatLevel.HIGH,
        reason="test",
        original_prompt="synthetic",
        safe_to_proceed=False,
        confidence=0.9,
    )
    config = {
        "url": "https://splunk.example",
        "token": "phase2-siem-token-sentinel",
        "verify_ssl": False,
    }

    outcome = _run(siem.send_to_siem("splunk_hec", config, result, "lf-test"))

    assert outcome == {
        "provider": "splunk_hec",
        "ok": False,
        "error": "outbound_configuration",
    }
    assert config["token"] not in repr(outcome)
