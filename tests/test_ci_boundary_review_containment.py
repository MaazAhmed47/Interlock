"""
Containment regressions for the CI boundary-review gate.

Covers the final hostile-review findings: anti-cache headers on every response
class (including router-generated 405 and the default 500), TLS-failure
classification, bounded request bodies, base-URL path validation, fail-closed
configuration, and the sanitized-artifact / internal-audit boundary.

Run: python -m pytest tests/test_ci_boundary_review_containment.py -q
"""

from __future__ import annotations

import asyncio
import copy
import datetime
import json
import os
import ssl
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List

import httpx
import pytest
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

import config
import proxy
from core import db
from core import ci_boundary_review as cbr
from core.http_cache_headers import (
    apply_to_raw_headers,
    is_boundary_review_path,
    is_boundary_review_scope,
    merge_vary,
)
from core.tool_metadata import normalize_tool_metadata
from tests.test_ci_boundary_review_gate import (
    BASE_TOOLS,
    GATE_SCRIPT,
    ROOT,
    _free_port,
    _serve,
)

SERVER_ID = "_test_containment_server"
DECOY_KEY = "lf_containment_decoy_credential_0123456789"

CACHE_HEADERS = ("cache-control", "pragma", "expires", "vary")


# ── Unit: header merging ──────────────────────────────────────────────────────
def test_vary_merges_without_duplicates_and_preserves_existing():
    assert merge_vary([]) == "Authorization, X-API-Key, Idempotency-Key"
    assert merge_vary(["Accept-Encoding"]).startswith("Accept-Encoding, ")
    merged = merge_vary(["authorization", "Accept-Encoding"])
    assert merged.lower().count("authorization") == 1
    assert "Accept-Encoding" in merged
    # This endpoint names the credential selectors explicitly even if a
    # downstream layer attempted to replace Vary with a wildcard.
    assert merge_vary(["*"]) == "Authorization, X-API-Key, Idempotency-Key"


def test_apply_to_raw_headers_replaces_rather_than_appends():
    raw = [
        (b"content-type", b"application/json"),
        (b"cache-control", b"public, max-age=600"),
        (b"vary", b"Accept-Encoding"),
        (b"pragma", b"whatever"),
    ]
    out = apply_to_raw_headers(raw)
    names = [name.decode() for name, _ in out]
    for header in CACHE_HEADERS:
        assert names.count(header) == 1, header
    values = {name.decode(): value.decode() for name, value in out}
    assert values["cache-control"] == "no-store"
    assert values["pragma"] == "no-cache"
    assert values["expires"] == "0"
    assert values["vary"].startswith("Accept-Encoding, ")
    assert values["content-type"] == "application/json"


@pytest.mark.parametrize(
    "path,expected",
    [
        ("/mcp/servers/abc/boundary-review", True),
        ("/mcp/servers/a b/boundary-review", True),
        ("/mcp/servers/abc/boundary-review/", False),
        ("/mcp/servers/a/b/boundary-review", False),
        ("/mcp/servers/abc/rebaseline", False),
        ("/mcp/call", False),
        ("", False),
    ],
)
def test_boundary_review_path_matching(path, expected):
    assert is_boundary_review_path(path) is expected


def test_boundary_review_scope_matching_uses_route_relative_path():
    assert is_boundary_review_scope(
        {
            "type": "http",
            "root_path": "/interlock",
            "path": "/interlock/mcp/servers/abc/boundary-review",
        }
    )


# ── Live deployment fixture ───────────────────────────────────────────────────
@pytest.fixture
def live(tmp_path_factory):
    root = tmp_path_factory.mktemp("containment")
    prior_db_path = db.DB_PATH
    db.DB_PATH = str(Path(root) / "containment.db")
    db.init_db()
    proxy._key_record_cache.clear()
    proxy._usage_cache.clear()

    state: Dict[str, Any] = {"tools": copy.deepcopy(BASE_TOOLS)}
    upstream = FastAPI()

    @upstream.post("/mcp")
    async def upstream_mcp(request: Request):
        message = await request.json()
        return JSONResponse(
            {
                "jsonrpc": "2.0",
                "id": message.get("id"),
                "result": {"tools": state["tools"]},
            }
        )

    with _serve(upstream) as upstream_url:
        db.register_mcp_server(
            SERVER_ID,
            {
                "url": f"{upstream_url}/mcp",
                "description": "containment fixture",
                "allowed_tools": ["read_document", "list_documents"],
                "blocked_tools": [],
                "environment": "non_production",
            },
        )
        db.verify_mcp_server(SERVER_ID)
        for tool in BASE_TOOLS:
            db.upsert_mcp_tool_metadata(SERVER_ID, tool, normalize_tool_metadata(tool))

        keys = {
            "ci": db.generate_key(
                "developer", label="containment-ci", scopes=["mcp.review"]
            )["raw_key"],
            "wrong": db.generate_key(
                "developer", label="containment-wrong", scopes=["mcp.call"]
            )["raw_key"],
            "rate_limited": db.generate_key(
                "developer",
                label="containment-rl",
                scopes=["mcp.review"],
                rate_per_min=1,
            )["raw_key"],
        }

        with _serve(proxy.app) as base_url:
            yield {"base_url": base_url, "keys": keys, "state": state}

    db.unregister_mcp_server(SERVER_ID)
    proxy._key_record_cache.clear()
    proxy._usage_cache.clear()
    db.DB_PATH = prior_db_path


def _url(live, server_id=SERVER_ID):
    return f"{live['base_url']}/mcp/servers/{server_id}/boundary-review"


def _assert_no_store(response, label):
    values = {h: response.headers.get(h) for h in CACHE_HEADERS}
    assert values["cache-control"] == "no-store", (label, values)
    assert values["pragma"] == "no-cache", (label, values)
    assert values["expires"] == "0", (label, values)
    vary = (values["vary"] or "").lower()
    for token in ("authorization", "x-api-key", "idempotency-key"):
        assert [part.strip() for part in vary.split(",")].count(token) == 1, (
            label,
            values,
        )


# ── 1. Anti-cache headers on EVERY status ─────────────────────────────────────
def test_anti_cache_headers_on_every_boundary_review_status(live, monkeypatch):
    ci = live["keys"]["ci"]
    url = _url(live)
    seen = {}

    seen[200] = httpx.post(url, headers={"x-api-key": ci}, timeout=90)
    seen[401] = httpx.post(url, timeout=30)
    seen[403] = httpx.post(
        url, headers={"x-api-key": live["keys"]["wrong"]}, timeout=30
    )
    seen[404] = httpx.post(
        f"{live['base_url']}/mcp/servers/_test_absent/boundary-review",
        headers={"x-api-key": ci},
        timeout=60,
    )
    seen[405] = httpx.get(url, timeout=30)
    seen[400] = httpx.post(
        url, headers={"x-api-key": ci, "idempotency-key": "too-short"}, timeout=30
    )
    seen[413] = httpx.post(
        url, headers={"x-api-key": ci}, content=b"A" * (256 * 1024), timeout=60
    )

    key = "h" * 48
    httpx.post(url, headers={"x-api-key": ci, "idempotency-key": key}, timeout=90)
    seen[409] = httpx.post(
        f"{live['base_url']}/mcp/servers/{SERVER_ID}/boundary-review",
        headers={"x-api-key": live["keys"]["rate_limited"], "idempotency-key": key},
        timeout=90,
    )

    limited = live["keys"]["rate_limited"]
    httpx.post(url, headers={"x-api-key": limited}, timeout=90)
    seen[429] = httpx.post(url, headers={"x-api-key": limited}, timeout=30)

    for status, response in sorted(seen.items()):
        assert response.status_code == status, (status, response.status_code)
        _assert_no_store(response, f"status {status}")


def test_anti_cache_headers_on_the_default_500(live, monkeypatch):
    """The stock 500 is built above every user middleware, on the raw send."""
    import routes.mcp as mcp_routes

    async def boom(*args, **kwargs):
        raise RuntimeError("induced failure")

    monkeypatch.setattr(mcp_routes, "run_boundary_review", boom)
    response = httpx.post(
        _url(live), headers={"x-api-key": live["keys"]["ci"]}, timeout=60
    )
    assert response.status_code == 500
    _assert_no_store(response, "status 500")


def test_anti_cache_headers_on_all_statuses_behind_root_path(live, monkeypatch):
    import routes.mcp as mcp_routes

    with _serve(proxy.app, root_path="/interlock") as origin:
        # Uvicorn's --root-path models a proxy that has already stripped the
        # public /interlock prefix before forwarding to the app.
        base = origin
        ci = live["keys"]["ci"]
        url = f"{base}/mcp/servers/{SERVER_ID}/boundary-review"
        seen = {
            200: httpx.post(url, headers={"x-api-key": ci}, timeout=90),
            401: httpx.post(url, timeout=30),
            403: httpx.post(
                url, headers={"x-api-key": live["keys"]["wrong"]}, timeout=30
            ),
            404: httpx.post(
                f"{base}/mcp/servers/_test_absent/boundary-review",
                headers={"x-api-key": ci},
                timeout=60,
            ),
            405: httpx.get(url, timeout=30),
            400: httpx.post(
                url,
                headers={"x-api-key": ci, "idempotency-key": "short"},
                timeout=30,
            ),
            413: httpx.post(
                url, headers={"x-api-key": ci}, content=b"A" * (256 * 1024), timeout=60
            ),
        }
        limited = live["keys"]["rate_limited"]
        httpx.post(url, headers={"x-api-key": limited}, timeout=90)
        seen[429] = httpx.post(url, headers={"x-api-key": limited}, timeout=30)
        replay_key = "r" * 48
        httpx.post(
            url, headers={"x-api-key": ci, "idempotency-key": replay_key}, timeout=90
        )
        seen[409] = httpx.post(
            f"{base}/mcp/servers/_test_absent/boundary-review",
            headers={"x-api-key": ci, "idempotency-key": replay_key},
            timeout=30,
        )

        original = mcp_routes.run_boundary_review

        async def boom(*args, **kwargs):
            raise RuntimeError("induced root-path failure")

        monkeypatch.setattr(mcp_routes, "run_boundary_review", boom)
        seen[500] = httpx.post(url, headers={"x-api-key": ci}, timeout=30)
        monkeypatch.setattr(mcp_routes, "run_boundary_review", original)

        for status, response in sorted(seen.items()):
            assert response.status_code == status, (
                status,
                response.status_code,
                response.text,
            )
            _assert_no_store(response, f"root-path status {status}")


def test_other_routes_keep_their_normal_caching_behavior(live):
    """The middleware is scoped: it must not restyle the rest of the API."""
    response = httpx.get(
        f"{live['base_url']}/mcp/tools",
        headers={"x-api-key": live["keys"]["wrong"]},
        timeout=30,
    )
    assert response.headers.get("cache-control") is None


# ── 2. TLS classification ─────────────────────────────────────────────────────
def _self_signed_https_server():
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    pem_dir = Path(tempfile.mkdtemp())
    (pem_dir / "cert.pem").write_bytes(
        cert.public_bytes(serialization.Encoding.PEM)
        + key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            body = b"{}"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    port = _free_port()
    httpd = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(pem_dir / "cert.pem"))
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd, port


def _run_cli(base_url, output_dir, key=DECOY_KEY):
    env = dict(os.environ)
    env["PYTHONPATH"] = str(ROOT)
    env["INTERLOCK_BASE_URL"] = base_url
    env["INTERLOCK_CI_API_KEY"] = key
    return subprocess.run(
        [
            sys.executable,
            str(GATE_SCRIPT),
            "--server-id",
            "srv",
            "--output-dir",
            str(output_dir),
        ],
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )


def _artifact(output_dir: Path):
    path = output_dir / "interlock-boundary-review.json"
    assert path.is_file()
    text = path.read_text(encoding="utf-8")
    assert (output_dir / "interlock-boundary-review.md").is_file()
    return json.loads(text), text


def test_tls_verification_failure_is_protocol_error_not_inconclusive(tmp_path):
    httpd, port = _self_signed_https_server()
    try:
        result = _run_cli(f"https://localhost:{port}", tmp_path)
        artifact, text = _artifact(tmp_path)
    finally:
        httpd.shutdown()

    assert result.returncode == 4, (result.stdout, result.stderr)
    assert artifact["gate"]["outcome"] == "protocol_error"
    assert artifact["observation"]["error_class"] == "tls_verification_failed"
    assert DECOY_KEY not in text
    assert DECOY_KEY not in result.stdout + result.stderr


def test_ordinary_unreachable_host_stays_inconclusive(tmp_path):
    dead = _free_port()
    result = _run_cli(f"http://127.0.0.1:{dead}", tmp_path)
    artifact, _ = _artifact(tmp_path)
    assert result.returncode == 22
    assert artifact["observation"]["error_class"] == "gateway_unreachable"


# ── 3. Bounded request bodies ─────────────────────────────────────────────────
def _audit_count():
    return len(db.list_mcp_audit_logs(3000))


def _snapshot_count():
    with db.get_conn() as conn:
        row = conn.execute(
            "SELECT COUNT(*) AS n FROM tool_surface_snapshots"
        ).fetchone()
    return int(db.row_value(row, "n", 0))


def _idempotency_count():
    with db.get_conn() as conn:
        row = conn.execute("SELECT COUNT(*) AS n FROM ci_review_idempotency").fetchone()
    return int(db.row_value(row, "n", 0))


@pytest.mark.parametrize("size", [1024 * 1024, 32 * 1024 * 1024])
def test_declared_oversized_body_is_rejected_with_413_and_no_writes(live, size):
    before = (_audit_count(), _snapshot_count(), _idempotency_count())
    response = httpx.post(
        _url(live),
        headers={"x-api-key": live["keys"]["ci"], "idempotency-key": "b" * 48},
        content=b"A" * size,
        timeout=120,
    )
    assert response.status_code == 413
    assert response.json()["detail"]["error"] == "request_body_too_large"
    _assert_no_store(response, "413")
    assert (_audit_count(), _snapshot_count(), _idempotency_count()) == before


@pytest.mark.parametrize("size", [1024 * 1024, 32 * 1024 * 1024])
def test_chunked_oversized_body_is_rejected_with_413_and_no_writes(live, size):
    before = (_audit_count(), _snapshot_count(), _idempotency_count())

    def chunks():
        sent = 0
        while sent < size:
            block = b"B" * min(64 * 1024, size - sent)
            sent += len(block)
            yield block

    response = httpx.post(
        _url(live),
        headers={"x-api-key": live["keys"]["ci"], "idempotency-key": "c" * 48},
        content=chunks(),
        timeout=120,
    )
    assert response.status_code == 413
    assert (_audit_count(), _snapshot_count(), _idempotency_count()) == before


def test_small_body_is_accepted_and_cannot_influence_the_review(live):
    hostile = {
        "server_id": "someone-else",
        "reviewer": "attacker",
        "gate": {"outcome": "clean"},
        "findings": [],
        "evidence": {"receipt": {"chain_verified": True, "audit_id": 1}},
    }
    response = httpx.post(
        _url(live), headers={"x-api-key": live["keys"]["ci"]}, json=hostile, timeout=90
    )
    assert response.status_code == 200
    review = response.json()
    assert review["server"]["server_ref"] == cbr.opaque_ref(SERVER_ID)
    assert SERVER_ID not in json.dumps(review)
    assert "attacker" not in json.dumps(review)


def test_unauthenticated_oversized_body_never_reaches_the_body_check(live):
    """Authentication comes first: no credential means 401, not 413."""
    response = httpx.post(_url(live), content=b"A" * (256 * 1024), timeout=60)
    assert response.status_code == 401
    _assert_no_store(response, "401 oversized")


def test_request_byte_cap_is_configurable_and_bounded():
    assert config.ci_boundary_review_max_request_bytes() == 8 * 1024
    assert config.CI_BOUNDARY_REVIEW_MAX_REQUEST_BYTES_CEILING == 1024 * 1024


# ── 4. Base URL path validation ───────────────────────────────────────────────
def _gate_module():
    import importlib.util

    spec = importlib.util.spec_from_file_location("interlock_ci_gate", GATE_SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize(
    "base_url,expected",
    [
        ("https://h.example", ""),
        ("https://h.example/", ""),
        ("https://h.example/interlock", "/interlock"),
        ("https://h.example/interlock/", "/interlock"),
        ("https://h.example/a/b", "/a/b"),
        ("http://localhost:8001/interlock", "/interlock"),
    ],
)
def test_valid_reverse_proxy_prefixes_are_normalized(base_url, expected):
    gate = _gate_module()
    normalized, error = gate.validate_base_url(base_url)
    assert error is None, (base_url, error)
    assert normalized.endswith(expected)
    assert gate.review_url(normalized, "srv").endswith(
        f"{expected}/mcp/servers/srv/boundary-review"
    )


@pytest.mark.parametrize(
    "base_url,error",
    [
        ("https://h.example/%0d%0aX-Evil:1", "base_url_path_percent_encoded"),
        ("https://h.example/a%20b", "base_url_path_percent_encoded"),
        ("https://h.example//x", "base_url_path_ambiguous"),
        ("https://h.example/a//b", "base_url_path_ambiguous"),
        ("https://h.example/../etc", "base_url_path_traversal"),
        ("https://h.example/a/../b", "base_url_path_traversal"),
        ("https://h.example/./x", "base_url_path_traversal"),
        ("https://h.example/a\\b", "base_url_path_invalid"),
        ("https://h.example/x?y=1", "base_url_contains_query_or_fragment"),
        ("https://h.example/x#f", "base_url_contains_query_or_fragment"),
        ("https://u:p@h.example", "base_url_contains_userinfo"),
        ("https://h.example/a b", "invalid_base_url"),
    ],
)
def test_unsafe_base_url_paths_are_refused(base_url, error):
    gate = _gate_module()
    normalized, actual = gate.validate_base_url(base_url)
    assert normalized is None, base_url
    assert actual == error, (base_url, actual)


@pytest.mark.parametrize(
    "base_url",
    [
        "https://127%2e0%2e0%2e1",
        "https://example.com\\attacker.invalid",
        "https://example.com.",
        "https://127.000.000.001",
        "https://2130706433",
        "https://[0:0:0:0:0:0:0:1]",
        "https://[::1",
        "https://::1",
        "https://exa\tmple.com",
        "https://exa\nmple.com",
    ],
)
def test_hostile_authorities_are_rejected_before_fetch(base_url, tmp_path, monkeypatch):
    gate = _gate_module()
    attempted = []
    monkeypatch.setattr(
        gate,
        "fetch_review",
        lambda *args, **kwargs: attempted.append((args, kwargs)),
    )
    args = gate.build_parser(DECOY_KEY).parse_args(
        ["--server-id", "billing-mcp", "--output-dir", str(tmp_path)]
    )
    monkeypatch.setenv(gate.BASE_URL_ENV, base_url)
    assert gate.run(args, [], DECOY_KEY) == gate.OUTCOME_EXIT_CODES["config_error"]
    assert attempted == []


def test_unsafe_base_url_path_is_a_config_error_end_to_end(tmp_path):
    result = _run_cli("https://h.example/%0d%0aX-Evil:1", tmp_path)
    artifact, _ = _artifact(tmp_path)
    assert result.returncode == 2
    assert artifact["observation"]["error_class"] == "base_url_path_percent_encoded"


# ── 5. Fail-closed configuration ──────────────────────────────────────────────
@pytest.mark.parametrize(
    "name,value",
    [
        ("INTERLOCK_BOUNDARY_REVIEW_MAX_TOOLS", "not-a-number"),
        ("INTERLOCK_BOUNDARY_REVIEW_MAX_TOOLS", "-5"),
        ("INTERLOCK_BOUNDARY_REVIEW_MAX_TOOLS", "999999"),
        ("INTERLOCK_BOUNDARY_REVIEW_TIMEOUT_S", "0"),
        ("INTERLOCK_BOUNDARY_REVIEW_TIMEOUT_S", "abc"),
        ("INTERLOCK_BOUNDARY_REVIEW_TIMEOUT_S", "nan"),
        ("INTERLOCK_BOUNDARY_REVIEW_TIMEOUT_S", "NaN"),
        ("INTERLOCK_BOUNDARY_REVIEW_TIMEOUT_S", "inf"),
        ("INTERLOCK_BOUNDARY_REVIEW_TIMEOUT_S", "-inf"),
        ("INTERLOCK_BOUNDARY_REVIEW_TIMEOUT_S", "1e309"),
        ("INTERLOCK_BOUNDARY_REVIEW_MAX_RESPONSE_BYTES", "1"),
        ("INTERLOCK_BOUNDARY_REVIEW_MAX_FINDINGS", "0"),
        ("INTERLOCK_BOUNDARY_REVIEW_IDEMPOTENCY_TTL_S", "5"),
        ("INTERLOCK_CI_BOUNDARY_REVIEW_MAX_REQUEST_BYTES", "999999999"),
    ],
)
def test_explicitly_invalid_caps_raise_instead_of_substituting(
    monkeypatch, name, value
):
    monkeypatch.setenv(name, value)
    with pytest.raises(config.ConfigurationError) as excinfo:
        config.assert_boundary_review_config_valid()
    assert name in str(excinfo.value)


@pytest.mark.parametrize(
    "name",
    [
        "INTERLOCK_BOUNDARY_REVIEW_MAX_TOOLS",
        "INTERLOCK_CI_BOUNDARY_REVIEW_MAX_REQUEST_BYTES",
    ],
)
def test_unset_and_empty_settings_use_the_documented_default(monkeypatch, name):
    monkeypatch.delenv(name, raising=False)
    config.assert_boundary_review_config_valid()
    monkeypatch.setenv(name, "")
    config.assert_boundary_review_config_valid()
    monkeypatch.setenv(name, "   ")
    config.assert_boundary_review_config_valid()


def test_invalid_cap_stops_startup_before_any_database_work(monkeypatch):
    monkeypatch.setenv("INTERLOCK_BOUNDARY_REVIEW_MAX_TOOLS", "not-a-number")
    touched: List[str] = []
    monkeypatch.setattr(db, "init_db", lambda *a, **k: touched.append("init_db"))
    monkeypatch.setattr(db, "seed_legacy_keys", lambda *a, **k: touched.append("seed"))

    async def enter():
        async with proxy.lifespan(proxy.app):
            pass

    with pytest.raises(config.ConfigurationError):
        asyncio.run(enter())
    assert touched == [], "config must fail before database work"


def test_valid_configuration_still_starts(monkeypatch):
    monkeypatch.setenv("INTERLOCK_BOUNDARY_REVIEW_MAX_TOOLS", "50")
    touched: List[str] = []
    monkeypatch.setattr(db, "init_db", lambda *a, **k: touched.append("init_db"))
    monkeypatch.setattr(db, "seed_legacy_keys", lambda *a, **k: touched.append("seed"))
    monkeypatch.setattr(db, "seed_default_policies", lambda *a, **k: None)

    async def enter():
        async with proxy.lifespan(proxy.app):
            pass

    asyncio.run(enter())
    assert "init_db" in touched


# ── 6. Artifact / internal-audit boundary ─────────────────────────────────────
def test_internal_audit_never_stores_credentials_headers_arguments_or_keys(live):
    ci = live["keys"]["ci"]
    idempotency = "d" * 48
    response = httpx.post(
        _url(live),
        headers={"x-api-key": ci, "idempotency-key": idempotency},
        json={"argument_marker": "containment-argument-marker"},
        timeout=90,
    )
    assert response.status_code == 200

    rows = json.dumps(db.list_mcp_audit_logs(200), default=str)
    for forbidden in (
        ci,
        idempotency,
        db.hash_idempotency_key(idempotency),
        "containment-argument-marker",
        "x-api-key",
        "Authorization",
        "jsonrpc",
        "127.0.0.1",
    ):
        assert forbidden not in rows, f"internal audit retained {forbidden!r}"


def test_documentation_states_the_two_intentional_boundaries():
    doc = (ROOT / "docs" / "integrations" / "ci-boundary-review-gate.md").read_text(
        encoding="utf-8"
    )
    # Collapse wrapping so the assertions test the prose, not the line breaks.
    lowered = " ".join(doc.lower().split())
    assert "must not be used as an approval" in lowered
    assert "enforcement-only" in lowered
    assert "non-enforced material drift" in lowered
    # The sanitized-export vs internal-record boundary is stated explicitly.
    assert "internal audit record" in lowered or "internal audit records" in lowered
    assert "no policy-as-code" in lowered or "not policy-as-code" in lowered
