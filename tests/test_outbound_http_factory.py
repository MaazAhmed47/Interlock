from __future__ import annotations

import socket
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import MagicMock, patch

import httpx
import pytest

from core.outbound_http import (
    EgressProfile,
    OutboundHTTPConfigurationError,
    assert_outbound_http_config_valid,
    classify_outbound_http_failure,
    create_async_client,
    create_sync_client,
    current_egress_profile,
    is_trusted_async_client,
    is_trusted_sync_client,
)

PROFILE_ENV = "INTERLOCK_EGRESS_PROFILE"
PROXY_ENV = "INTERLOCK_OUTBOUND_HTTP_PROXY"
AMBIENT_PROXY_ENV = (
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
    "no_proxy",
)


@pytest.fixture(autouse=True)
def _clean_egress_environment(monkeypatch):
    monkeypatch.delenv(PROFILE_ENV, raising=False)
    monkeypatch.delenv(PROXY_ENV, raising=False)
    for name in AMBIENT_PROXY_ENV:
        monkeypatch.delenv(name, raising=False)


def _enable_enforced(monkeypatch, proxy: str = "http://egress-proxy:3128") -> None:
    monkeypatch.setenv(PROFILE_ENV, "enforced")
    monkeypatch.setenv(PROXY_ENV, proxy)


def test_sync_client_uses_required_proxy_and_fixed_security_options(monkeypatch):
    _enable_enforced(monkeypatch)
    constructed = MagicMock(spec=httpx.Client)

    with patch("core.outbound_http.httpx.Client", return_value=constructed) as ctor:
        client = create_sync_client(timeout=7.0, purpose="unit test")

    assert client is constructed
    kwargs = ctor.call_args.kwargs
    assert kwargs["proxy"] == "http://egress-proxy:3128"
    assert kwargs["trust_env"] is False
    assert kwargs["follow_redirects"] is False
    assert kwargs["verify"] is True
    assert is_trusted_sync_client(client)


def test_async_client_uses_required_proxy_and_fixed_security_options(monkeypatch):
    _enable_enforced(monkeypatch, "HTTP://Proxy.Example:8080")
    constructed = MagicMock(spec=httpx.AsyncClient)

    with patch(
        "core.outbound_http.httpx.AsyncClient", return_value=constructed
    ) as ctor:
        client = create_async_client(timeout=httpx.Timeout(5.0), purpose="unit test")

    assert client is constructed
    kwargs = ctor.call_args.kwargs
    assert kwargs["proxy"] == "http://proxy.example:8080"
    assert kwargs["trust_env"] is False
    assert kwargs["follow_redirects"] is False
    assert kwargs["verify"] is True
    assert is_trusted_async_client(client)


def test_hostile_proxy_environment_cannot_influence_enforced_client(monkeypatch):
    _enable_enforced(monkeypatch)
    for index, name in enumerate(AMBIENT_PROXY_ENV):
        monkeypatch.setenv(name, f"http://hostile-{index}.invalid:9")

    with patch("core.outbound_http.httpx.Client") as ctor:
        create_sync_client(timeout=1.0, purpose="ambient isolation")

    assert ctor.call_args.kwargs["proxy"] == "http://egress-proxy:3128"
    assert ctor.call_args.kwargs["trust_env"] is False


@pytest.mark.parametrize(
    "proxy_value",
    [
        None,
        "",
        "https://proxy.example:3128",
        "socks5://proxy.example:1080",
        "http://proxy.example",
        "http://proxy.example:0",
        "http://proxy.example:70000",
        "http://proxy.example:3128/path",
        "http://proxy.example:3128?mode=unsafe",
        "http://proxy.example:3128#fragment",
        "http://proxy..example:3128",
        "http://proxy_example:3128",
        "http://0x7f000001:3128",
        "http://0x7f.0.0.1:3128",
        "http://proxy.example\\evil:3128",
        "http://[::1:3128",
        " http://proxy.example:3128",
    ],
    ids=lambda _value: "invalid-proxy",
)
def test_enforced_profile_rejects_missing_or_malformed_proxy_before_client_creation(
    monkeypatch, proxy_value
):
    monkeypatch.setenv(PROFILE_ENV, "enforced")
    if proxy_value is None:
        monkeypatch.delenv(PROXY_ENV, raising=False)
    else:
        monkeypatch.setenv(PROXY_ENV, proxy_value)

    with patch("core.outbound_http.httpx.Client") as ctor:
        with pytest.raises(OutboundHTTPConfigurationError) as raised:
            create_sync_client(timeout=1.0, purpose="invalid config")

    ctor.assert_not_called()
    if proxy_value:
        assert proxy_value not in str(raised.value)


def test_credential_bearing_proxy_is_rejected_without_disclosure(monkeypatch):
    sentinel = "phase2-proxy-credential-sentinel"
    proxy = f"http://operator:{sentinel}@proxy.example:3128"
    _enable_enforced(monkeypatch, proxy)

    with pytest.raises(OutboundHTTPConfigurationError) as raised:
        assert_outbound_http_config_valid()

    rendered = str(raised.value)
    assert sentinel not in rendered
    assert proxy not in rendered
    assert "credentials" in rendered.lower()


def test_malformed_proxy_exception_chain_does_not_disclose_config(monkeypatch):
    sentinel = "phase2-malformed-port-sentinel"
    proxy = f"http://proxy.example:{sentinel}"
    _enable_enforced(monkeypatch, proxy)

    with pytest.raises(OutboundHTTPConfigurationError) as raised:
        assert_outbound_http_config_valid()

    assert raised.value.__cause__ is None
    assert sentinel not in repr(raised.value)
    assert proxy not in repr(raised.value)


@pytest.mark.parametrize(
    "profile",
    ["", " enforced", "enforced ", "phase2-profile-value-sentinel"],
    ids=lambda _value: "invalid-profile",
)
def test_explicit_malformed_profile_never_silently_selects_phase1(monkeypatch, profile):
    monkeypatch.setenv(PROFILE_ENV, profile)

    with patch("core.outbound_http.httpx.Client") as ctor:
        with pytest.raises(OutboundHTTPConfigurationError) as raised:
            create_sync_client(timeout=1.0, purpose="malformed profile")

    ctor.assert_not_called()
    assert "phase2-profile-value-sentinel" not in str(raised.value)


@pytest.mark.parametrize("verify", [False, 0])
def test_enforced_profile_rejects_disabled_tls_verification(monkeypatch, verify):
    _enable_enforced(monkeypatch)

    with patch("core.outbound_http.httpx.AsyncClient") as ctor:
        with pytest.raises(OutboundHTTPConfigurationError):
            create_async_client(
                timeout=1.0,
                verify=verify,
                purpose="insecure TLS mutation",
            )

    ctor.assert_not_called()


@pytest.mark.parametrize("insecure_setting", ["hostname", "certificate"])
def test_enforced_profile_rejects_insecure_ssl_context(monkeypatch, insecure_setting):
    _enable_enforced(monkeypatch)
    context = ssl.create_default_context()
    if insecure_setting == "hostname":
        context.check_hostname = False
    else:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

    with patch("core.outbound_http.httpx.Client") as ctor:
        with pytest.raises(OutboundHTTPConfigurationError):
            create_sync_client(
                timeout=1.0,
                verify=context,
                purpose="insecure SSL context mutation",
            )

    ctor.assert_not_called()


def test_enforced_profile_preserves_secure_custom_ssl_context(monkeypatch):
    _enable_enforced(monkeypatch)
    context = ssl.create_default_context()

    with patch("core.outbound_http.httpx.Client") as ctor:
        create_sync_client(
            timeout=1.0,
            verify=context,
            purpose="custom trust store",
        )

    assert ctor.call_args.kwargs["verify"] is context


def test_enforced_profile_rejects_custom_transport(monkeypatch):
    _enable_enforced(monkeypatch)
    transport = httpx.MockTransport(lambda request: httpx.Response(200))

    with pytest.raises(OutboundHTTPConfigurationError):
        create_async_client(
            timeout=1.0,
            transport=transport,
            purpose="untrusted transport",
        )


def test_phase1_legacy_profile_is_explicit_and_retains_direct_compatibility(
    monkeypatch,
):
    monkeypatch.setenv(PROFILE_ENV, "phase1")
    constructed = MagicMock(spec=httpx.Client)

    with patch("core.outbound_http.httpx.Client", return_value=constructed) as ctor:
        create_sync_client(
            timeout=1.0,
            verify=False,
            purpose="legacy compatibility",
        )

    assert current_egress_profile() is EgressProfile.PHASE1
    assert ctor.call_args.kwargs["proxy"] is None
    assert ctor.call_args.kwargs["trust_env"] is False
    assert ctor.call_args.kwargs["follow_redirects"] is False
    assert ctor.call_args.kwargs["verify"] is False


class _CountingHandler(BaseHTTPRequestHandler):
    hits = 0

    def do_GET(self):  # noqa: N802
        type(self).hits += 1
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"direct target")

    def log_message(self, format, *args):
        return


def test_proxy_connection_failure_never_falls_back_to_direct(monkeypatch):
    _CountingHandler.hits = 0
    target = ThreadingHTTPServer(("127.0.0.1", 0), _CountingHandler)
    target_thread = threading.Thread(target=target.serve_forever, daemon=True)
    target_thread.start()

    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    unavailable_proxy_port = probe.getsockname()[1]
    probe.close()
    _enable_enforced(monkeypatch, f"http://127.0.0.1:{unavailable_proxy_port}")
    for index, name in enumerate(AMBIENT_PROXY_ENV):
        hostile_value = (
            "*"
            if name.lower() == "no_proxy"
            else f"http://127.0.0.1:{target.server_port}"
        )
        monkeypatch.setenv(name, hostile_value)

    try:
        with create_sync_client(timeout=0.5, purpose="no fallback proof") as client:
            with pytest.raises(httpx.HTTPError):
                client.get(f"http://127.0.0.1:{target.server_port}/must-not-arrive")
        assert _CountingHandler.hits == 0
    finally:
        target.shutdown()
        target.server_close()
        target_thread.join(timeout=5)


def test_failure_classification_never_renders_exception_or_request_url():
    sentinel = "phase2-query-and-credential-sentinel"
    request = httpx.Request("GET", f"https://provider.example/path?key={sentinel}")
    error = httpx.ConnectError(
        f"proxy http://operator:{sentinel}@proxy.invalid failed", request=request
    )

    rendered = classify_outbound_http_failure(error)

    assert rendered == "connection_failed"
    assert sentinel not in rendered


def test_dependency_logging_does_not_retain_query_or_path_credentials(
    monkeypatch, caplog
):
    sentinel = "phase2-http-log-sentinel"
    monkeypatch.setenv(PROFILE_ENV, "phase1")
    transport = httpx.MockTransport(lambda request: httpx.Response(200))

    with caplog.at_level("DEBUG"):
        with create_sync_client(
            timeout=1.0,
            transport=transport,
            purpose="dependency log suppression",
        ) as client:
            client.get(f"https://webhook.example/{sentinel}?token={sentinel}")

    assert sentinel not in caplog.text
