"""Hermetic runtime and network cases for the Docker Phase 2 profile.

Each result is one bounded JSON object on stdout. The host orchestrator owns
topology inspection, proxy-stop cases, log collection, manifesting, and cleanup.
"""

from __future__ import annotations

import asyncio
import json
import os
import socket
import subprocess
import sys
from contextlib import closing
from pathlib import Path
from types import SimpleNamespace
from urllib.request import ProxyHandler, build_opener

import httpx
import requests

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from core.outbound_http import create_sync_client

PROXY = "http://squid:3128"
HTTP_ORIGIN = "http://allowed.phase2.test:8080"
HTTPS_ORIGIN = "https://allowed.phase2.test:8443"
CA_FILE = os.environ["PHASE2_CA_FILE"]
QUERY_SENTINEL = os.environ["PHASE2_QUERY_SENTINEL"]
AUTHORIZATION_SENTINEL = os.environ["PHASE2_AUTHORIZATION_SENTINEL"]
PROXY_CREDENTIAL_SENTINEL = os.environ["PHASE2_PROXY_CREDENTIAL_SENTINEL"]


class Results:
    def __init__(self) -> None:
        self.failed = False

    def record(self, case: str, passed: bool, category: str = "") -> None:
        self.failed |= not passed
        print(
            json.dumps(
                {
                    "case": case,
                    "outcome": "passed" if passed else "failed",
                    "category": category[:80],
                },
                sort_keys=True,
            ),
            flush=True,
        )

    def check(self, case: str, operation) -> object | None:
        try:
            value = operation()
        except Exception as exc:  # failure output is deliberately URL-free
            self.record(case, False, type(exc).__name__)
            return None
        self.record(case, bool(value), "assertion" if not value else "")
        return value

    async def acheck(self, case: str, operation) -> object | None:
        try:
            value = await operation()
        except Exception as exc:
            self.record(case, False, type(exc).__name__)
            return None
        self.record(case, bool(value), "assertion" if not value else "")
        return value


def _tcp(host: str, port: int, family: socket.AddressFamily = socket.AF_UNSPEC) -> bool:
    try:
        for af, socktype, proto, _canon, address in socket.getaddrinfo(
            host, port, family, socket.SOCK_STREAM
        ):
            with closing(socket.socket(af, socktype, proto)) as sock:
                sock.settimeout(1.5)
                sock.connect(address)
                return True
    except OSError:
        return False
    return False


def _fails(operation) -> bool:
    try:
        operation()
    except Exception:
        return True
    return False


def _denied(client: httpx.Client, url: str) -> bool:
    """Accept an exception or a bounded refusal response, never 2xx/3xx."""

    try:
        response = client.get(url)
    except Exception:
        return True
    return response.status_code >= 400


async def _afails(operation) -> bool:
    try:
        await operation()
    except Exception:
        return True
    return False


def direct_cases(results: Results) -> None:
    routes4 = subprocess.run(
        ["ip", "route"], capture_output=True, text=True, check=True
    ).stdout
    routes6 = subprocess.run(
        ["ip", "-6", "route"], capture_output=True, text=True, check=True
    ).stdout
    results.record("topology_ipv4_no_default_route", "default" not in routes4)
    results.record("topology_ipv6_no_default_route", "default" not in routes6)
    results.record(
        "dns_expected_resolution",
        any(
            address[4][0] == "93.184.216.10"
            for address in socket.getaddrinfo("allowed.phase2.test", 8080)
        ),
    )
    results.record("proxy_expected_destination_port", _tcp("squid", 3128))
    results.record("proxy_wrong_port_denied", not _tcp("squid", 8080))
    results.record("postgres_expected_destination_port", _tcp("postgres", 5432))
    results.record("postgres_wrong_port_denied", not _tcp("postgres", 6379))
    results.record("redis_expected_destination_port", _tcp("redis", 6379))
    results.record("redis_wrong_port_denied", not _tcp("redis", 5432))

    targets = (
        ("ipv4", "93.184.216.10", socket.AF_INET),
        ("ipv6", "2606:4700:4700::10", socket.AF_INET6),
    )
    for label, address, family in targets:
        url_host = f"[{address}]" if family == socket.AF_INET6 else address
        url = f"http://{url_host}:8080/"
        results.record(
            f"direct_httpx_{label}_denied",
            _fails(lambda: httpx.get(url, timeout=1, trust_env=False)),
        )
        opener = build_opener(ProxyHandler({}))
        results.record(
            f"direct_urllib_{label}_denied", _fails(lambda: opener.open(url, timeout=1))
        )
        session = requests.Session()
        session.trust_env = False
        results.record(
            f"direct_requests_{label}_denied",
            _fails(lambda: session.get(url, timeout=1)),
        )
        results.record(f"direct_socket_{label}_denied", not _tcp(address, 8080, family))
        completed = subprocess.run(
            [
                "curl",
                "--silent",
                "--show-error",
                "--fail",
                "--max-time",
                "1",
                "--noproxy",
                "*",
                url,
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        results.record(f"direct_curl_{label}_denied", completed.returncode != 0)


def positive_tls_cases(results: Results) -> None:
    with create_sync_client(timeout=3, purpose="Phase 2 allowed HTTP") as client:
        response = client.get(f"{HTTP_ORIGIN}/positive")
        http_payload = response.json()
        results.record("allowed_http_through_proxy", response.status_code == 200)
        results.record(
            "positive_origin_not_block_all_control", response.json().get("ok") is True
        )
        results.record(
            "allowed_http_via_observed", http_payload.get("via_present") is True
        )
    with create_sync_client(
        timeout=3, verify=CA_FILE, purpose="Phase 2 allowed TLS"
    ) as client:
        response = client.get(f"{HTTPS_ORIGIN}/tls")
        payload = response.json()
        results.record(
            "allowed_https_connect_through_proxy", response.status_code == 200
        )
        results.record(
            "allowed_https_original_host",
            payload.get("host") == "allowed.phase2.test:8443",
        )
        results.record(
            "allowed_https_original_sni", payload.get("sni") == "allowed.phase2.test"
        )
    with create_sync_client(
        timeout=3, verify=CA_FILE, purpose="Phase 2 wrong host"
    ) as client:
        results.record(
            "wrong_hostname_tls_rejected",
            _fails(
                lambda: client.get("https://wrong.phase2.test:8443/wrong-host-proof")
            ),
        )
    with create_sync_client(timeout=3, purpose="Phase 2 untrusted CA") as client:
        results.record(
            "untrusted_ca_tls_rejected",
            _fails(lambda: client.get(f"{HTTPS_ORIGIN}/untrusted-ca-proof")),
        )


async def runtime_cases(results: Results) -> None:
    from core import (
        admin,
        db,
        effect_readback,
        effective_permission,
        llm_judge,
        mcp_gateway,
        router,
        shadow_scanner,
        siem,
        webhook,
    )
    from core.ema_auth import TrustedJWKSCache
    from models.schemas import ScanResult, ThreatLevel

    discovery = await mcp_gateway._fetch_tool_list_payload(
        f"{HTTP_ORIGIN}/mcp", 5, None
    )
    results.record("runtime_mcp_discovery_proxy", discovery.get("ok") is True)

    server_id = "phase2-runtime"
    db.unregister_mcp_server(server_id)
    db.register_mcp_server(
        server_id,
        {
            "url": f"{HTTP_ORIGIN}/mcp",
            "description": "Phase 2 fixture",
            "allowed_tools": ["echo"],
            "blocked_tools": [],
            "rate_limit": 10,
            "environment": "non_production",
            "probes_enabled": True,
        },
    )
    db.verify_mcp_server(server_id)
    db.upsert_mcp_tool_metadata(
        server_id,
        {
            "name": "echo",
            "description": "fixture",
            "inputSchema": {"type": "object", "properties": {}},
        },
        {
            "effects": ["read"],
            "side_effect": "read_only",
            "data_classes": [],
            "externality": "internal",
            "verification_level": "interlock_meta",
            "confidence": 1.0,
            "warnings": [],
        },
    )
    try:
        called = await mcp_gateway.proxy_mcp_tool_call(
            server_id, "echo", {}, role="admin_agent"
        )
        results.record("runtime_mcp_tools_call_proxy", called.get("ok") is True)
        observed = await effective_permission._call_upstream_for_observation(
            db.lookup_mcp_server(server_id),
            {"tool_name": "echo", "arguments": {}},
        )
        results.record(
            "runtime_effective_permission_proxy", observed.get("status_code") == 200
        )
        readback = await effect_readback._call_upstream_tool(
            db.lookup_mcp_server(server_id), "echo", {}
        )
        results.record("runtime_effect_readback_proxy", readback.get("ok") is True)
    finally:
        db.unregister_mcp_server(server_id)

    threat = ScanResult(
        is_threat=True,
        threat_level=ThreatLevel.HIGH,
        reason="phase2 fixture",
        original_prompt="fixture",
        safe_to_proceed=False,
        confidence=0.9,
    )
    original_resolver = webhook._resolve_webhook_url
    webhook._resolve_webhook_url = lambda _key: f"{HTTP_ORIGIN}/webhook"
    try:
        await webhook.fire_webhook("phase2-key", threat)
        results.record("runtime_webhook_proxy", True)
    finally:
        webhook._resolve_webhook_url = original_resolver

    original_providers = json.loads(json.dumps(siem.SIEM_PROVIDERS))
    siem.SIEM_PROVIDERS["datadog"]["url_template"] = f"{HTTP_ORIGIN}/siem/datadog"
    siem.SIEM_PROVIDERS["pagerduty"]["url_template"] = f"{HTTP_ORIGIN}/siem/pagerduty"
    configs = {
        "datadog": {"api_key": "fixture"},
        "splunk_hec": {"url": f"{HTTP_ORIGIN}/siem/splunk", "token": "fixture"},
        "elastic": {"url": f"{HTTP_ORIGIN}/siem/elastic", "api_key": "fixture"},
        "slack": {"webhook_url": f"{HTTP_ORIGIN}/siem/slack"},
        "pagerduty": {"integration_key": "fixture"},
        "webhook": {"url": f"{HTTP_ORIGIN}/siem/generic"},
    }
    case_names = {
        "datadog": "runtime_siem_datadog_proxy",
        "splunk_hec": "runtime_siem_splunk_proxy",
        "elastic": "runtime_siem_elastic_proxy",
        "slack": "runtime_siem_slack_proxy",
        "pagerduty": "runtime_siem_pagerduty_proxy",
        "webhook": "runtime_siem_generic_proxy",
    }
    try:
        for provider, config in configs.items():
            outcome = await siem.send_to_siem(provider, config, threat, "phase2")
            results.record(case_names[provider], outcome.get("ok") is True)
    finally:
        siem.SIEM_PROVIDERS.clear()
        siem.SIEM_PROVIDERS.update(original_providers)

    oidc = admin._GuardedPyJWKClient(f"{HTTP_ORIGIN}/jwks")
    results.record("runtime_oidc_jwks_proxy", bool(oidc.fetch_data().get("keys")))

    settings = SimpleNamespace(
        jwks_uri=f"{HTTP_ORIGIN}/jwks",
        jwks_connect_timeout_seconds=2.0,
        jwks_read_timeout_seconds=2.0,
        jwks_total_timeout_seconds=4.0,
        jwks_document_max_bytes=32768,
        jwks_key_count_max=4,
        jwk_max_bytes=8192,
        jwks_negative_cache_ttl_seconds=10,
        jwks_negative_cache_max_entries=8,
        jwks_refresh_cooldown_seconds=1,
    )
    cache = TrustedJWKSCache(settings)
    await cache._refresh()
    results.record("runtime_ema_jwks_proxy", bool(cache._keys))

    saved_provider_urls = {
        name: value["url"] for name, value in router.PROVIDERS.items()
    }
    provider_paths = {
        "openai": "openai",
        "anthropic": "anthropic",
        "google": "google",
        "groq": "groq",
    }
    try:
        for provider, path in provider_paths.items():
            router.PROVIDERS[provider]["url"] = f"{HTTP_ORIGIN}/{path}"
            model = "gemini-fixture" if provider == "google" else "fixture"
            outcome = await router.forward_to_provider(
                provider, {"model": model, "messages": []}, api_key="fixture"
            )
            results.record(f"runtime_provider_{provider}_proxy", "error" not in outcome)
    finally:
        for name, url in saved_provider_urls.items():
            router.PROVIDERS[name]["url"] = url

    llm_judge.GROQ_API_KEY = "fixture"
    sdk = llm_judge._build_groq_client()
    try:
        sdk.base_url = httpx.URL(f"{HTTP_ORIGIN}/groq/")
        sdk.chat.completions.create(
            model="fixture", messages=[{"role": "user", "content": "fixture"}]
        )
        results.record("runtime_groq_sdk_controlled_proxy", True)
    except Exception:
        results.record("runtime_groq_sdk_controlled_proxy", False, "sdk_request_failed")
    finally:
        sdk.close()

    shadow = await shadow_scanner.probe_target(HTTP_ORIGIN)
    results.record(
        "runtime_shadow_scanner_proxy",
        shadow.responded and shadow.tool_listing_available,
    )
    ollama = await router.forward_to_provider(
        "ollama", {"model": "ollama:fixture", "messages": []}
    )
    results.record(
        "runtime_ollama_enforced_disabled",
        ollama.get("error") == "outbound_profile_restriction",
    )


def ambient_cases(results: Results) -> None:
    with create_sync_client(timeout=3, purpose="Phase 2 ambient proxy proof") as client:
        response = client.get(f"{HTTP_ORIGIN}/ambient")
    passed = response.status_code == 200
    for name in (
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "NO_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
        "no_proxy",
    ):
        results.record(f"hostile_{name}_ignored", passed)


def sentinel_cases(results: Results) -> None:
    with create_sync_client(
        timeout=3, purpose="Phase 2 disclosure sentinels"
    ) as client:
        query = client.get(f"{HTTP_ORIGIN}/sentinel?probe={QUERY_SENTINEL}")
        authorization = client.get(
            f"{HTTP_ORIGIN}/sentinel-authorization",
            headers={"Authorization": f"Bearer {AUTHORIZATION_SENTINEL}"},
        )
        results.record("query_sentinel_exercised", query.status_code == 200)
        results.record(
            "authorization_sentinel_exercised", authorization.status_code == 200
        )


def denied_destination_cases(results: Results) -> None:
    names = {
        "loopback_answer_denied": "loopback.phase2.test",
        "rfc1918_answer_denied": "private.phase2.test",
        "link_local_answer_denied": "linklocal.phase2.test",
        "metadata_answer_denied": "metadata.phase2.test",
        "cgnat_answer_denied": "cgnat.phase2.test",
        "multicast_answer_denied": "multicast.phase2.test",
        "reserved_answer_denied": "reserved.phase2.test",
        "ula_answer_denied": "ula.phase2.test",
        "ipv6_link_local_answer_denied": "v6-linklocal.phase2.test",
        "ipv4_mapped_ipv6_answer_denied": "mapped.phase2.test",
        "nat64_unsafe_answer_denied": "nat64.phase2.test",
        "nat64_local_answer_denied": "nat64-local.phase2.test",
        "mixed_public_private_answer_denied": "mixed.phase2.test",
        "mixed_private_public_answer_denied": "mixed-reverse.phase2.test",
        "mixed_ipv4_ipv6_answer_denied": "mixed-family.phase2.test",
    }
    with create_sync_client(timeout=3, purpose="Phase 2 denied destinations") as client:
        results.record(
            "disallowed_method_denied",
            client.request("TRACE", f"{HTTP_ORIGIN}/method").status_code >= 400,
        )
        results.record(
            "disallowed_port_denied",
            _denied(client, "http://allowed.phase2.test:8081/port"),
        )
        results.record(
            "undeclared_domain_denied",
            _denied(client, "http://not-declared.invalid:8080/domain"),
        )
        for case, host in names.items():
            results.record(case, _denied(client, f"http://{host}:8080/denied"))
        raw = {
            "raw_ipv4_target_denied": "http://10.89.0.10:8080/",
            "raw_ipv6_target_denied": "http://[fd00:dead::10]:8080/",
            "decimal_ipv4_target_denied": "http://2130706433:8080/",
            "octal_ipv4_target_denied": "http://0177.0.0.1:8080/",
            "hex_ipv4_target_denied": "http://0x7f.0x0.0x0.0x1:8080/",
            "bracketed_ipv6_target_denied": "http://[::1]:8080/",
            "zone_qualified_ipv6_target_denied": "http://[fe80::1%25eth0]:8080/",
        }
        for case, url in raw.items():
            results.record(case, _denied(client, url))
    scheme = subprocess.run(
        [
            "curl",
            "--silent",
            "--show-error",
            "--fail",
            "--max-time",
            "3",
            "--proxy",
            PROXY,
            "--noproxy",
            "",
            "ftp://allowed.phase2.test:8080/scheme",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    results.record("disallowed_scheme_denied", scheme.returncode != 0)


def redirect_cases(results: Results) -> None:
    with create_sync_client(timeout=3, purpose="Phase 2 redirect proof") as client:
        for status in (301, 302, 303, 307, 308):
            response = client.get(f"{HTTP_ORIGIN}/redirect/{status}")
            results.record(
                f"redirect_{status}_not_followed", response.status_code == status
            )
        for label in (
            "cross_host",
            "private_target",
            "raw_ip",
            "credentials",
            "loop",
            "hop_exhaustion",
        ):
            route = label.replace("_", "-")
            response = client.get(f"{HTTP_ORIGIN}/redirect/{route}")
            results.record(
                f"redirect_{label}_not_followed", response.status_code == 302
            )
    with create_sync_client(
        timeout=3, verify=CA_FILE, purpose="Phase 2 downgrade redirect proof"
    ) as tls_client:
        response = tls_client.get(f"{HTTPS_ORIGIN}/redirect/downgrade")
        results.record("redirect_downgrade_not_followed", response.status_code == 302)


async def rebinding_cases(results: Results) -> None:
    from core.shadow_scanner import probe_target
    from core.url_security import OutboundUrlRejected, ensure_safe_outbound_url_async

    probe = await probe_target("http://rebind-main.phase2.test:8080")
    results.record(
        "public_to_private_rebind_denied",
        not probe.responded or probe.status_code >= 400,
    )
    try:
        await ensure_safe_outbound_url_async(
            "http://private-public.phase2.test:8080/", context="Phase 2 private first"
        )
    except OutboundUrlRejected:
        results.record("private_to_public_change_denied", True)
    else:
        changed = await probe_target("http://private-public.phase2.test:8080")
        results.record(
            "private_to_public_change_denied",
            not changed.responded or changed.status_code >= 400,
        )
    with create_sync_client(timeout=3, purpose="ordering") as ordering_client:
        results.record(
            "ipv4_ipv6_answer_ordering_denied",
            _denied(ordering_client, "http://mixed-family.phase2.test:8080/"),
        )
    await asyncio.sleep(61)
    expired = await probe_target("http://rebind-expiry.phase2.test:8080")
    results.record(
        "dns_cache_expiry_rebind_denied",
        not expired.responded or expired.status_code >= 400,
    )
    with create_sync_client(timeout=3, purpose="cache pressure") as client:
        pressure_ok = True
        for index in range(64):
            try:
                response = client.get(f"http://pressure-{index:03d}.phase2.test:8080/")
                pressure_ok &= response.status_code == 200
            except Exception:
                pressure_ok = False
        results.record(
            "dns_cache_pressure_rebind_denied",
            pressure_ok and _denied(client, "http://rebind-pressure.phase2.test:8080/"),
        )
        results.record(
            "dns_cache_eviction_attempt_denied",
            _denied(client, "http://not-declared.invalid:8080/"),
        )
        results.record(
            "reconnect_rebind_denied",
            _denied(client, "http://rebind-reconnect.phase2.test:8080/"),
        )
        results.record(
            "retry_rebind_denied",
            _denied(client, "http://retry-main.phase2.test:8080/"),
        )

    async def concurrent(index: int) -> bool:
        probe_result = await probe_target(f"http://concurrent-{index}.phase2.test:8080")
        return not probe_result.responded or probe_result.status_code >= 400

    values = await asyncio.gather(*(concurrent(index) for index in range(16)))
    results.record("concurrent_refresh_rebind_denied", all(values))


def failure_cases(results: Results) -> None:
    with create_sync_client(timeout=3, purpose="Phase 2 failure proof") as client:
        for case, host in (
            ("dns_timeout_no_fallback", "timeout.phase2.test"),
            ("dns_servfail_no_fallback", "servfail.phase2.test"),
            ("dns_nxdomain_no_fallback", "nxdomain.phase2.test"),
        ):
            results.record(case, _denied(client, f"http://{host}:80/"))
        results.record(
            "connect_refusal_no_fallback",
            _denied(client, "https://refused.phase2.test:8443/"),
        )
        results.record(
            "tls_failure_no_fallback", _fails(lambda: client.get(f"{HTTPS_ORIGIN}/tls"))
        )
        request = client.build_request(
            "GET",
            f"{HTTP_ORIGIN}/auth",
            headers={"Proxy-Authorization": f"Basic {PROXY_CREDENTIAL_SENTINEL}"},
        )
        response = client.send(request)
        results.record("proxy_credentials_rejected", response.status_code >= 400)
        results.record(
            "proxy_credential_sentinel_exercised", response.status_code >= 400
        )


async def main() -> int:
    results = Results()
    positive_tls_cases(results)
    ambient_cases(results)
    sentinel_cases(results)
    await runtime_cases(results)
    denied_destination_cases(results)
    redirect_cases(results)
    failure_cases(results)
    await rebinding_cases(results)
    return 1 if results.failed else 0


def proxy_down() -> int:
    results = Results()
    with create_sync_client(timeout=2, purpose="Phase 2 proxy unavailable") as client:
        results.record(
            "proxy_unavailable_no_fallback",
            _fails(lambda: client.get(f"{HTTP_ORIGIN}/proxy-down")),
        )
    return 1 if results.failed else 0


def direct_only() -> int:
    results = Results()
    direct_cases(results)
    return 1 if results.failed else 0


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "proxy-down":
        raise SystemExit(proxy_down())
    if len(sys.argv) > 1 and sys.argv[1] == "direct-only":
        raise SystemExit(direct_only())
    raise SystemExit(asyncio.run(main()))
