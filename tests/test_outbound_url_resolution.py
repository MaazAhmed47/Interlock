"""Hermetic Phase 1 tests for outbound hostname resolution policy."""

from __future__ import annotations

import asyncio
import socket
import threading
from collections.abc import Callable

import httpx
import pytest

import config
from core import url_security
from core.url_security import OutboundUrlRejected, ensure_safe_outbound_url

Resolver = Callable[..., list[tuple[int, int, int, str, tuple[object, ...]]]]


def _resolver(*addresses: str) -> Resolver:
    def resolve(host: str, port: int, **_kwargs):
        answers = []
        for address in addresses:
            family = socket.AF_INET6 if ":" in address else socket.AF_INET
            sockaddr: tuple[object, ...]
            if family == socket.AF_INET6:
                sockaddr = (address, port, 0, 0)
            else:
                sockaddr = (address, port)
            answers.append((family, socket.SOCK_STREAM, 6, "", sockaddr))
        return answers

    return resolve


def _protected(monkeypatch) -> None:
    monkeypatch.setenv("INTERLOCK_ENV", "production")
    monkeypatch.delenv("INTERLOCK_ALLOW_PRIVATE_OUTBOUND", raising=False)
    monkeypatch.delenv("INTERLOCK_OFFLINE_DEMO", raising=False)


@pytest.mark.parametrize(
    "address",
    (
        "127.0.0.1",
        "10.0.0.8",
        "169.254.169.254",
        "0.0.0.0",
        "224.0.0.1",
        "240.0.0.1",
        "100.64.0.1",
        "::1",
        "fe80::1",
        "fc00::1",
        "ff02::1",
        "::",
        "::ffff:127.0.0.1",
        "fec0::1",
    ),
)
def test_protected_hostname_rejects_every_forbidden_answer(monkeypatch, address):
    _protected(monkeypatch)

    with pytest.raises(OutboundUrlRejected, match="resolved to a non-global address"):
        ensure_safe_outbound_url(
            "https://service.audit.invalid/hook",
            context="test",
            resolver=_resolver(address),
        )


def test_protected_hostname_rejects_mixed_global_and_forbidden_answers(monkeypatch):
    _protected(monkeypatch)

    with pytest.raises(OutboundUrlRejected, match="resolved to a non-global address"):
        ensure_safe_outbound_url(
            "https://service.audit.invalid/hook",
            context="test",
            resolver=_resolver("1.1.1.1", "10.0.0.8"),
        )


@pytest.mark.parametrize("host", ("127.1", "127.0.0.01", "0177.0.0.1"))
def test_alternate_numeric_loopback_forms_are_resolved_and_rejected(monkeypatch, host):
    _protected(monkeypatch)

    with pytest.raises(OutboundUrlRejected):
        ensure_safe_outbound_url(
            f"http://{host}/hook",
            context="test",
            resolver=_resolver("127.0.0.1"),
        )


def test_protected_hostname_accepts_only_global_answers(monkeypatch):
    _protected(monkeypatch)

    assert (
        ensure_safe_outbound_url(
            "https://service.audit.invalid/hook",
            context="test",
            resolver=_resolver("1.1.1.1", "2606:4700:4700::1111"),
        )
        == "https://service.audit.invalid/hook"
    )


def test_unicode_hostname_resolves_and_returns_httpx_canonical_host(monkeypatch):
    _protected(monkeypatch)
    resolved_hosts = []

    def resolver(host: str, port: int, **_kwargs):
        resolved_hosts.append(host)
        return _resolver("1.1.1.1")(host, port)

    validated = ensure_safe_outbound_url(
        "https://faß.audit.invalid/hook",
        context="test",
        resolver=resolver,
    )

    effective_host = httpx.URL(validated).raw_host.decode("ascii")
    assert resolved_hosts == [effective_host]
    assert effective_host == "xn--fa-hia.audit.invalid"
    assert validated == "https://xn--fa-hia.audit.invalid/hook"


def test_blank_dns_answer_fails_closed(monkeypatch):
    _protected(monkeypatch)

    with pytest.raises(OutboundUrlRejected, match="could not be resolved"):
        ensure_safe_outbound_url(
            "https://service.audit.invalid/hook",
            context="test",
            resolver=_resolver(),
        )


def test_resolver_failure_fails_closed_without_exposing_error(monkeypatch):
    _protected(monkeypatch)

    def unavailable(*_args, **_kwargs):
        raise socket.gaierror("resolver detail must not escape")

    with pytest.raises(OutboundUrlRejected, match="could not be resolved") as captured:
        ensure_safe_outbound_url(
            "https://service.audit.invalid/hook",
            context="test",
            resolver=unavailable,
        )
    assert "resolver detail" not in str(captured.value)


def test_production_override_cannot_allow_private_destination(monkeypatch):
    monkeypatch.setenv("INTERLOCK_ENV", "production")
    monkeypatch.setenv("INTERLOCK_ALLOW_PRIVATE_OUTBOUND", "true")

    with pytest.raises(OutboundUrlRejected):
        ensure_safe_outbound_url("http://127.0.0.1/hook", context="test")


def test_protected_offline_demo_allows_only_bundled_compose_mock(monkeypatch):
    monkeypatch.setenv("INTERLOCK_ENV", "local")
    monkeypatch.setenv("INTERLOCK_PROTECT_OUTBOUND_URLS", "true")
    monkeypatch.setenv("INTERLOCK_OFFLINE_DEMO", "true")
    monkeypatch.delenv("INTERLOCK_ALLOW_PRIVATE_OUTBOUND", raising=False)

    assert (
        ensure_safe_outbound_url(
            "http://mcp-mock:9100/mcp",
            context="test",
            resolver=_resolver("172.20.0.5"),
        )
        == "http://mcp-mock:9100/mcp"
    )

    with pytest.raises(OutboundUrlRejected):
        ensure_safe_outbound_url(
            "http://other.audit.invalid:9100/mcp",
            context="test",
            resolver=_resolver("172.20.0.6"),
        )


def test_production_cannot_disable_outbound_protection(monkeypatch):
    monkeypatch.setenv("INTERLOCK_ENV", "production")
    monkeypatch.setenv("INTERLOCK_PROTECT_OUTBOUND_URLS", "false")

    with pytest.raises(OutboundUrlRejected):
        ensure_safe_outbound_url(
            "https://service.audit.invalid/hook",
            resolver=_resolver("127.0.0.1"),
        )


@pytest.mark.parametrize(
    "marker",
    ("RENDER", "VERCEL", "RAILWAY_ENVIRONMENT", "FLY_APP_NAME", "K_SERVICE"),
)
def test_hosted_marker_forces_protection_even_with_local_profile(monkeypatch, marker):
    for name in (
        "RENDER",
        "VERCEL",
        "RAILWAY_ENVIRONMENT",
        "FLY_APP_NAME",
        "K_SERVICE",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv(marker, "hosted")
    monkeypatch.setenv("INTERLOCK_ENV", "local")
    monkeypatch.setenv("INTERLOCK_PROTECT_OUTBOUND_URLS", "false")

    assert config.protect_outbound_urls() is True


def test_hosted_marker_disables_offline_compose_exception(monkeypatch):
    monkeypatch.setenv("INTERLOCK_ENV", "local")
    monkeypatch.setenv("RENDER", "true")
    monkeypatch.setenv("INTERLOCK_OFFLINE_DEMO", "true")

    with pytest.raises(OutboundUrlRejected, match="not allowed in hosted mode"):
        ensure_safe_outbound_url(
            "http://mcp-mock:9100/mcp",
            context="test",
            resolver=_resolver("172.20.0.5"),
        )


def test_async_resolver_timeout_is_bounded_without_blocking_event_loop(monkeypatch):
    _protected(monkeypatch)
    heartbeat_ran = False
    resolver_started = asyncio.Event()

    async def blocked_resolver(_host, _port, **_kwargs):
        resolver_started.set()
        await asyncio.Event().wait()

    async def scenario():
        nonlocal heartbeat_ran
        task = asyncio.create_task(
            url_security.ensure_safe_outbound_url_async(
                "https://service.audit.invalid/hook",
                context="test",
                resolver=blocked_resolver,
                resolution_timeout_seconds=0.01,
            )
        )
        await resolver_started.wait()
        await asyncio.sleep(0)
        heartbeat_ran = True
        with pytest.raises(OutboundUrlRejected, match="resolution timed out"):
            await task

    asyncio.run(scenario())
    assert heartbeat_ran is True


def test_default_system_resolver_runs_off_thread_and_times_out(monkeypatch):
    _protected(monkeypatch)
    resolver_started = threading.Event()
    release_resolver = threading.Event()
    resolver_finished = threading.Event()
    resolver_threads: list[threading.Thread] = []
    heartbeat_ran = False

    def blocked_getaddrinfo(host: str, port: int, **_kwargs):
        resolver_threads.append(threading.current_thread())
        resolver_started.set()
        release_resolver.wait()
        resolver_finished.set()
        return _resolver("1.1.1.1")(host, port)

    monkeypatch.setattr(url_security.socket, "getaddrinfo", blocked_getaddrinfo)
    safety_release = threading.Timer(1.0, release_resolver.set)
    safety_release.start()

    async def scenario():
        nonlocal heartbeat_ran
        task = asyncio.create_task(
            url_security.ensure_safe_outbound_url_async(
                "https://service.audit.invalid/hook",
                context="test",
                resolution_timeout_seconds=0.01,
            )
        )
        try:
            for _ in range(100):
                if resolver_started.is_set():
                    break
                await asyncio.sleep(0.001)
            assert resolver_started.is_set()
            await asyncio.sleep(0)
            assert release_resolver.is_set() is False
            heartbeat_ran = True
            with pytest.raises(OutboundUrlRejected, match="resolution timed out"):
                await task
        finally:
            release_resolver.set()
            for _ in range(100):
                if resolver_finished.is_set():
                    break
                await asyncio.sleep(0.001)

    try:
        asyncio.run(scenario())
    finally:
        release_resolver.set()
        safety_release.cancel()
        safety_release.join(timeout=1.0)
        for thread in resolver_threads:
            if thread is not threading.current_thread():
                thread.join(timeout=1.0)

    assert heartbeat_ran is True
    assert resolver_finished.is_set()
    assert len(resolver_threads) == 1
    assert resolver_threads[0] is not threading.current_thread()
    assert resolver_threads[0].is_alive() is False


def test_development_default_preserves_local_infrastructure(monkeypatch):
    monkeypatch.setenv("INTERLOCK_ENV", "development")
    monkeypatch.delenv("INTERLOCK_PROTECT_OUTBOUND_URLS", raising=False)

    def must_not_resolve(*_args, **_kwargs):
        raise AssertionError("permissive local mode must not resolve")

    assert (
        ensure_safe_outbound_url(
            "http://localhost:11434/api/chat",
            context="test",
            resolver=must_not_resolve,
        )
        == "http://localhost:11434/api/chat"
    )


def test_resolver_only_validation_documents_rebinding_toctou(monkeypatch):
    _protected(monkeypatch)
    answers = iter(("1.1.1.1", "127.0.0.1"))
    calls = []

    def changing_resolver(host: str, port: int, **_kwargs):
        address = next(answers)
        calls.append(address)
        return _resolver(address)(host, port)

    ensure_safe_outbound_url(
        "https://service.audit.invalid/hook",
        context="test",
        resolver=changing_resolver,
    )
    connection_answer = changing_resolver(
        "service.audit.invalid", 443, type=socket.SOCK_STREAM
    )[0][4][0]

    assert calls == ["1.1.1.1", "127.0.0.1"]
    assert connection_answer == "127.0.0.1"
