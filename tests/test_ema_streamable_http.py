"""Mock-only Streamable HTTP lifecycle and authorization tests."""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import tempfile
import time
from dataclasses import dataclass, replace
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from core import db
from core.ema_auth import EMAAccessTokenValidator, TrustedJWKSCache
from core.ema_config import load_experimental_ema_settings
from core.ema_sessions import EMASessionStore
from tests.ema_test_support import MockRS256Issuer
from tests.test_ema_auth import CountingJWKS
from tests.test_ema_config import valid_raw_config

os.environ.pop("DATABASE_URL", None)

SERVER_ID = "_fixture_ema_streamable"
RESOURCE_PATH = "/experimental/mcp"
PROTOCOL_VERSION = "2025-11-25"
CLIENT_ONE = "https://client.example/oauth/client.json"
CLIENT_TWO = "https://other-client.example/oauth/client.json"

READ_TOOL = {
    "name": "read_file",
    "description": "Read one file.",
    "inputSchema": {
        "type": "object",
        "properties": {"path": {"type": "string"}},
        "required": ["path"],
    },
}
LIST_TOOL = {
    "name": "list_directory",
    "description": "List one directory.",
    "inputSchema": {
        "type": "object",
        "properties": {"path": {"type": "string"}},
        "required": ["path"],
    },
}
UNMAPPED_TOOL = {
    "name": "delete_file",
    "description": "Delete one file.",
    "inputSchema": {
        "type": "object",
        "properties": {"path": {"type": "string"}},
        "required": ["path"],
    },
}


def _settings():
    raw = valid_raw_config()
    raw["INTERLOCK_EMA_SERVER_ID"] = SERVER_ID
    raw["INTERLOCK_EMA_ALLOWED_CLIENT_IDS"] = json.dumps([CLIENT_ONE, CLIENT_TWO])
    raw["INTERLOCK_EMA_TOOL_SCOPES"] = json.dumps(
        {
            SERVER_ID: {
                "read_file": ["files:read"],
                "list_directory": ["files:list"],
            }
        }
    )
    raw["INTERLOCK_EMA_UNAUTHENTICATED_RATE_LIMIT"] = "4"
    raw["INTERLOCK_EMA_AUTHENTICATED_RATE_LIMIT"] = "12"
    raw["INTERLOCK_EMA_RATE_LIMIT_MAX_KEYS"] = "32"
    value = load_experimental_ema_settings(raw)
    assert value is not None
    return value


@dataclass
class EndpointHarness:
    client: TestClient
    issuer: MockRS256Issuer
    jwks: CountingJWKS
    gateway_calls: list[dict]
    downstream_credential_digest: str
    sessions: EMASessionStore
    settings: Any = None
    authenticated_limiter: Any = None

    def token(self, **claims):
        return self.issuer.token(claims=self.issuer.claims(**claims))

    @staticmethod
    def headers(
        token: str,
        *,
        session_id: str | None = None,
        protocol: bool = False,
        origin: str | None = None,
    ) -> dict[str, str]:
        value = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
        }
        if session_id is not None:
            value["MCP-Session-Id"] = session_id
        if protocol:
            value["MCP-Protocol-Version"] = PROTOCOL_VERSION
        if origin is not None:
            value["Origin"] = origin
        return value

    def initialize(self, token: str | None = None) -> tuple[str, str]:
        token = token or self.token()
        response = self.client.post(
            RESOURCE_PATH,
            headers=self.headers(token),
            json={
                "jsonrpc": "2.0",
                "id": "initialize-request",
                "method": "initialize",
                "params": {
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": {},
                    "clientInfo": {"name": "mock-only-client", "version": "0"},
                },
            },
        )
        assert response.status_code == 200, response.text
        session_id = response.headers["MCP-Session-Id"]
        initialized = self.client.post(
            RESOURCE_PATH,
            headers=self.headers(
                token,
                session_id=session_id,
                protocol=True,
            ),
            json={
                "jsonrpc": "2.0",
                "method": "notifications/initialized",
            },
        )
        assert initialized.status_code == 202, initialized.text
        assert initialized.content == b""
        return token, session_id


@pytest.fixture
def endpoint(monkeypatch):
    path = tempfile.mktemp(suffix="_ema_streamable.db")
    old_path = db.DB_PATH
    db.DB_PATH = path
    db.init_db()
    monkeypatch.setenv(
        "MCP_UPSTREAM_AUTH_ALLOWED_ENV_VARS",
        "TEST_EMA_DOWNSTREAM_TOKEN",
    )
    downstream_credential = secrets.token_urlsafe(32)
    downstream_credential_digest = hashlib.sha256(
        downstream_credential.encode("ascii")
    ).hexdigest()
    monkeypatch.setenv("TEST_EMA_DOWNSTREAM_TOKEN", downstream_credential)
    db.register_mcp_server(
        SERVER_ID,
        {
            "url": "https://safe.example/mcp",
            "description": "mock-only EMA downstream",
            "allowed_tools": ["read_file", "list_directory", "delete_file"],
            "blocked_tools": [],
            "auth_type": "bearer",
            "auth_header": "Authorization",
            "auth_token_env": "TEST_EMA_DOWNSTREAM_TOKEN",
        },
    )
    db.verify_mcp_server(SERVER_ID)
    from core.tool_metadata import normalize_tool_metadata

    for tool in (READ_TOOL, LIST_TOOL, UNMAPPED_TOOL):
        db.upsert_mcp_tool_metadata(
            SERVER_ID,
            tool,
            normalize_tool_metadata(tool),
        )

    settings = _settings()
    issuer = MockRS256Issuer.create(
        resource=settings.resource_uri,
        client_id=CLIENT_ONE,
    )
    jwks = CountingJWKS(issuer.jwks())
    validator = EMAAccessTokenValidator(
        settings,
        cache=TrustedJWKSCache(settings, transport=jwks.transport()),
    )
    sessions = EMASessionStore(settings)
    from core.ema_rate_limit import BoundedWindowLimiter

    unauthenticated_limiter = BoundedWindowLimiter(
        limit=settings.unauthenticated_rate_limit,
        window_seconds=settings.rate_limit_window_seconds,
        max_keys=settings.rate_limit_max_keys,
    )
    authenticated_limiter = BoundedWindowLimiter(
        limit=settings.authenticated_rate_limit,
        window_seconds=settings.rate_limit_window_seconds,
        max_keys=settings.rate_limit_max_keys,
    )
    calls: list[dict] = []

    async def fake_gateway(**kwargs):
        from core.ema_context import mark_authority_downstream_attempt

        calls.append(dict(kwargs))
        mark_authority_downstream_attempt()
        saved = db.log_mcp_audit_event(
            {
                "server_id": kwargs["server_id"],
                "tool_name": kwargs["tool_name"],
                "principal_id": kwargs["principal_id"],
                "role": kwargs["role"],
                "action": "allow",
                "matched_rule": "no_rule_matched",
                "reason": "Mock-only gateway validation-code proof.",
                "argument_hash": "sha256:" + ("a" * 64),
            }
        )
        return {
            "ok": True,
            "result": {
                "content": [{"type": "text", "text": "mock-only result"}],
                "isError": False,
            },
            "audit": {
                "audit_id": saved["id"],
                "call_id": saved["call_id"],
            },
        }

    monkeypatch.setattr(
        "routes.ema_mcp.proxy_mcp_tool_call",
        fake_gateway,
    )
    from routes.ema_mcp import create_ema_router

    app = FastAPI()
    app.include_router(
        create_ema_router(
            settings,
            validator=validator,
            sessions=sessions,
            unauthenticated_limiter=unauthenticated_limiter,
            authenticated_limiter=authenticated_limiter,
        )
    )
    with TestClient(app) as client:
        yield EndpointHarness(
            client,
            issuer,
            jwks,
            calls,
            downstream_credential_digest,
            sessions,
            settings,
            authenticated_limiter,
        )

    db.unregister_mcp_server(SERVER_ID)
    db.DB_PATH = old_path
    for suffix in ("", "-wal", "-shm"):
        try:
            os.unlink(path + suffix)
        except OSError:
            pass


def test_disabled_endpoint_registers_no_transport_or_metadata_routes():
    from routes.ema_mcp import create_ema_router

    app = FastAPI()
    app.include_router(create_ema_router(None))
    client = TestClient(app)
    assert client.post(RESOURCE_PATH).status_code == 404
    assert (
        client.get("/.well-known/oauth-protected-resource/experimental/mcp").status_code
        == 404
    )


@pytest.mark.parametrize("resource_path", ["/mcp/call", "/scan", "/health"])
def test_ema_resource_path_cannot_collide_with_existing_routes(resource_path):
    from core.ema_config import EMAConfigError
    from proxy import app
    from routes.ema_mcp import include_experimental_ema_router

    settings = replace(
        _settings(),
        resource_uri=f"https://interlock.example{resource_path}",
        resource_path=resource_path,
        protected_resource_metadata_path=(
            f"/.well-known/oauth-protected-resource{resource_path}"
        ),
    )
    with pytest.raises(EMAConfigError, match="route collision"):
        include_experimental_ema_router(app, settings)


def test_ema_metadata_path_cannot_collide_with_existing_get_route():
    from core.ema_config import EMAConfigError
    from routes.ema_mcp import include_experimental_ema_router

    app = FastAPI()
    app.add_api_route(
        "/.well-known/oauth-protected-resource/experimental/mcp",
        lambda: {"existing": True},
        methods=["GET"],
    )
    with pytest.raises(EMAConfigError, match="route collision"):
        include_experimental_ema_router(app, _settings())


def test_ema_resource_path_cannot_collide_with_parameterized_existing_route():
    from core.ema_config import EMAConfigError
    from routes.ema_mcp import include_experimental_ema_router

    app = FastAPI()
    app.add_api_route("/mcp/{operation}", lambda: None, methods=["POST"])
    settings = replace(
        _settings(),
        resource_uri="https://interlock.example/mcp/call",
        resource_path="/mcp/call",
        protected_resource_metadata_path=(
            "/.well-known/oauth-protected-resource/mcp/call"
        ),
    )
    with pytest.raises(EMAConfigError, match="route collision"):
        include_experimental_ema_router(app, settings)


def test_non_conflicting_ema_endpoint_registers_transport_and_metadata_routes():
    from routes.ema_mcp import include_experimental_ema_router

    app = FastAPI()
    app.add_api_route("/mcp/call", lambda: None, methods=["POST"])
    include_experimental_ema_router(app, _settings())
    registered = {
        (route.path, method)
        for route in app.routes
        for method in (getattr(route, "methods", set()) or set())
    }
    assert (RESOURCE_PATH, "POST") in registered
    assert (RESOURCE_PATH, "GET") in registered
    assert (RESOURCE_PATH, "DELETE") in registered
    assert (
        "/.well-known/oauth-protected-resource/experimental/mcp",
        "GET",
    ) in registered


def test_protected_resource_metadata_is_exact_and_unprotected(endpoint):
    response = endpoint.client.get(
        "/.well-known/oauth-protected-resource/experimental/mcp"
    )
    assert response.status_code == 200
    assert response.json() == {
        "resource": "https://interlock.example/experimental/mcp",
        "authorization_servers": ["https://issuer.example"],
        "bearer_methods_supported": ["header"],
        "scopes_supported": ["files:list", "files:read"],
    }


def test_initialize_returns_standard_result_and_server_generated_session(endpoint):
    token = endpoint.token()
    response = endpoint.client.post(
        RESOURCE_PATH,
        headers=endpoint.headers(token),
        json={
            "jsonrpc": "2.0",
            "id": 7,
            "method": "initialize",
            "params": {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "mock-only-client", "version": "0"},
            },
        },
    )
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")
    assert len(response.headers["MCP-Session-Id"]) >= 43
    assert response.json() == {
        "jsonrpc": "2.0",
        "id": 7,
        "result": {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {
                "name": "interlock-experimental-ema-gateway",
                "version": "0.2.0-alpha.1",
            },
            "instructions": (
                "Experimental Interlock gateway authorization. Inbound "
                "bearer credentials are never forwarded downstream."
            ),
        },
    }


@pytest.mark.parametrize(
    "declared_length",
    [str((256 * 1024) + 1), "9" * 5000],
)
def test_oversized_content_length_is_rejected_before_body_or_session_processing(
    endpoint,
    monkeypatch,
    declared_length,
):
    session_lookups = []

    async def unexpected_session_lookup(*args, **kwargs):
        session_lookups.append((args, kwargs))
        raise AssertionError("oversized request reached session lookup")

    monkeypatch.setattr(endpoint.sessions, "authorize", unexpected_session_lookup)
    token = endpoint.token()
    headers = endpoint.headers(
        token,
        session_id="opaque-session-that-must-not-be-read",
        protocol=True,
    )
    headers["Content-Length"] = declared_length
    response = endpoint.client.post(
        RESOURCE_PATH,
        headers=headers,
        content=b"{}",
    )
    assert response.status_code == 413
    assert response.json() == {"error": "request_body_too_large"}
    assert session_lookups == []
    assert endpoint.gateway_calls == []
    assert db.list_mcp_audit_logs(limit=100) == []


def test_chunked_oversized_body_is_rejected_by_streaming_cap(
    endpoint,
    monkeypatch,
):
    session_lookups = []
    observed_content_lengths = []

    async def unexpected_session_lookup(*args, **kwargs):
        session_lookups.append((args, kwargs))
        raise AssertionError("oversized request reached session lookup")

    monkeypatch.setattr(endpoint.sessions, "authorize", unexpected_session_lookup)
    from routes import ema_mcp

    original_reader = ema_mcp._read_bounded_json_rpc_body

    async def observing_reader(request, maximum):
        observed_content_lengths.extend(
            value
            for name, value in request.scope["headers"]
            if name.lower() == b"content-length"
        )
        return await original_reader(request, maximum)

    monkeypatch.setattr(
        ema_mcp,
        "_read_bounded_json_rpc_body",
        observing_reader,
    )
    token = endpoint.token()
    headers = endpoint.headers(
        token,
        session_id="opaque-session-that-must-not-be-read",
        protocol=True,
    )
    headers["Transfer-Encoding"] = "chunked"

    def oversized_chunks():
        yield b"{" + (b"x" * (128 * 1024))
        yield b"x" * (128 * 1024)

    response = endpoint.client.post(
        RESOURCE_PATH,
        headers=headers,
        content=oversized_chunks(),
    )
    assert response.status_code == 413
    assert response.json() == {"error": "request_body_too_large"}
    assert observed_content_lengths == []
    assert session_lookups == []
    assert endpoint.gateway_calls == []
    assert db.list_mcp_audit_logs(limit=100) == []


@pytest.mark.parametrize(
    "message",
    [
        {
            "jsonrpc": "2.0",
            "method": "initialize",
            "params": {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "mock", "version": "0"},
            },
        },
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": [],
                "clientInfo": {"name": "mock", "version": "0"},
            },
        },
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "mock"},
            },
        },
    ],
)
def test_initialize_requires_the_standard_request_shape(endpoint, message):
    response = endpoint.client.post(
        RESOURCE_PATH,
        headers=endpoint.headers(endpoint.token()),
        json=message,
    )
    assert response.status_code == 400
    assert response.json()["error"]["code"] in {-32600, -32602}


def test_accept_media_parameters_are_supported(endpoint):
    headers = endpoint.headers(endpoint.token())
    headers["Accept"] = "application/json; q=1.0, text/event-stream; q=0.9"
    response = endpoint.client.post(
        RESOURCE_PATH,
        headers=headers,
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "mock", "version": "0"},
            },
        },
    )
    assert response.status_code == 200


def test_bearer_validation_precedes_json_parsing_and_session_lookup(endpoint):
    malformed = endpoint.client.post(
        RESOURCE_PATH,
        headers=endpoint.headers("not-a-jwt", session_id="stolen-session"),
        content=b"{not-json",
    )
    assert malformed.status_code == 401
    assert malformed.json()["error"] == "invalid_token"


@pytest.mark.parametrize("same_value", [True, False])
def test_duplicate_authorization_headers_are_rejected_before_all_trust_work(
    endpoint,
    monkeypatch,
    same_value,
):
    session_lookups = []

    async def unexpected_session_lookup(*args, **kwargs):
        session_lookups.append((args, kwargs))
        raise AssertionError("duplicate Authorization reached session lookup")

    monkeypatch.setattr(endpoint.sessions, "authorize", unexpected_session_lookup)
    first = endpoint.token()
    second = first if same_value else endpoint.token(sub="employee-conflict")
    headers = [
        ("Authorization", f"Bearer {first}"),
        ("Authorization", f"Bearer {second}"),
        ("Accept", "application/json, text/event-stream"),
        ("Content-Type", "application/json"),
        ("MCP-Session-Id", "must-not-be-read"),
        ("MCP-Protocol-Version", PROTOCOL_VERSION),
    ]
    response = endpoint.client.post(
        RESOURCE_PATH,
        headers=headers,
        content=b"{not-json",
    )
    assert response.status_code == 401
    assert response.json() == {"error": "invalid_token"}
    assert endpoint.jwks.calls == 0
    assert session_lookups == []
    assert endpoint.gateway_calls == []
    assert db.list_mcp_audit_logs(limit=100) == []


def test_unauthenticated_denial_rate_limit_bounds_audit_and_jwks_by_client_host(
    endpoint,
):
    assert endpoint.settings is not None
    limit = endpoint.settings.unauthenticated_rate_limit
    for index in range(limit):
        response = endpoint.client.post(
            RESOURCE_PATH,
            headers={
                **endpoint.headers("not-a-jwt"),
                "X-Forwarded-For": f"198.51.100.{index + 1}",
            },
            content=b"{not-json",
        )
        assert response.status_code == 401
        assert response.json() == {"error": "invalid_token"}

    before = len(db.list_mcp_audit_logs(limit=100))
    assert before == limit
    assert endpoint.jwks.calls == 0

    response = endpoint.client.post(
        RESOURCE_PATH,
        headers={
            **endpoint.headers(endpoint.token()),
            "X-Forwarded-For": "203.0.113.250",
        },
        content=b"{not-json",
    )
    assert response.status_code == 401
    assert response.json() == {"error": "invalid_token"}
    assert len(db.list_mcp_audit_logs(limit=100)) == before
    assert endpoint.jwks.calls == 0
    assert endpoint.gateway_calls == []


def test_authenticated_rate_limit_uses_only_verified_hmac_identity_bindings(
    endpoint,
):
    assert endpoint.settings is not None
    assert endpoint.authenticated_limiter is not None
    token = endpoint.token(scope="files:list")
    _, session_id = endpoint.initialize(token)
    consumed_by_initialize = 2
    for request_id in range(
        endpoint.settings.authenticated_rate_limit - consumed_by_initialize
    ):
        response = endpoint.client.post(
            RESOURCE_PATH,
            headers=endpoint.headers(
                token,
                session_id=session_id,
                protocol=True,
            ),
            json={
                "jsonrpc": "2.0",
                "id": request_id,
                "method": "tools/list",
                "params": {},
            },
        )
        assert response.status_code == 200

    original_authorize = endpoint.sessions.authorize

    async def unexpected_session_lookup(*args, **kwargs):
        raise AssertionError("rate-limited request reached session lookup")

    endpoint.sessions.authorize = unexpected_session_lookup
    audit_rows_before = len(db.list_mcp_audit_logs(limit=100))
    try:
        denied = endpoint.client.post(
            RESOURCE_PATH,
            headers=endpoint.headers(
                endpoint.token(scope="files:list"),
                session_id=session_id,
                protocol=True,
            ),
            json={
                "jsonrpc": "2.0",
                "id": "rate-limited",
                "method": "tools/list",
                "params": {},
            },
        )
    finally:
        endpoint.sessions.authorize = original_authorize
    assert denied.status_code == 429
    assert denied.json() == {"error": "rate_limit_exceeded"}
    assert endpoint.gateway_calls == []
    assert len(db.list_mcp_audit_logs(limit=100)) == audit_rows_before

    other_subject = "employee-other"
    alternative_tokens = [
        endpoint.token(
            client_id=CLIENT_ONE,
            sub=other_subject,
            scope="files:list",
        ),
        endpoint.token(
            client_id=CLIENT_TWO,
            sub=endpoint.issuer.subject,
            scope="files:list",
        ),
    ]
    for alternative_token in alternative_tokens:
        initialized, _other_session = endpoint.initialize(alternative_token)
        assert initialized == alternative_token

    limiter_state = json.dumps(
        endpoint.authenticated_limiter.safe_keys(),
        sort_keys=True,
    )
    assert token not in limiter_state
    assert all(value not in limiter_state for value in alternative_tokens)
    assert CLIENT_ONE not in limiter_state
    assert CLIENT_TWO not in limiter_state
    assert endpoint.issuer.subject not in limiter_state
    assert other_subject not in limiter_state


def test_missing_bearer_is_401_with_metadata_challenge(endpoint):
    response = endpoint.client.post(
        RESOURCE_PATH,
        headers={
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
        },
        content=b"{not-json",
    )
    assert response.status_code == 401
    challenge = response.headers["WWW-Authenticate"]
    assert challenge.startswith("Bearer ")
    assert "resource_metadata=" in challenge
    assert "files:list files:read" in challenge
    row = db.list_mcp_audit_logs(limit=1)[0]
    assert row["hash_v"] == 4
    assert row["authority_status"] == "denied"
    assert row["authority_failure_code"] == "missing_authorization"
    assert row["oauth_client_binding"] is None
    assert row["delegated_subject_binding"] is None
    assert row["token_binding"] is None
    assert row["downstream_service_principal_id"] is None
    assert row["authority_signature_algorithm"] is None
    assert row["authority_token_type"] is None


def test_invalid_origin_is_403(endpoint):
    response = endpoint.client.post(
        RESOURCE_PATH,
        headers=endpoint.headers(
            endpoint.token(),
            origin="https://attacker.example",
        ),
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "mock", "version": "0"},
            },
        },
    )
    assert response.status_code == 403
    assert response.json()["error"] == "invalid_origin"


def test_subsequent_requests_require_session_and_protocol_headers(endpoint):
    token = endpoint.token()
    missing_session = endpoint.client.post(
        RESOURCE_PATH,
        headers=endpoint.headers(token, protocol=True),
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
    )
    assert missing_session.status_code == 400
    assert missing_session.json()["error"] == "missing_session"

    _, session_id = endpoint.initialize(token)
    missing_protocol = endpoint.client.post(
        RESOURCE_PATH,
        headers=endpoint.headers(token, session_id=session_id),
        json={"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
    )
    assert missing_protocol.status_code == 400
    assert missing_protocol.json()["error"] == "invalid_protocol_version"


def test_tools_list_is_filtered_by_exact_current_scopes(endpoint):
    token, session_id = endpoint.initialize()
    response = endpoint.client.post(
        RESOURCE_PATH,
        headers=endpoint.headers(token, session_id=session_id, protocol=True),
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
    )
    assert response.status_code == 200
    assert [tool["name"] for tool in response.json()["result"]["tools"]] == [
        "list_directory",
        "read_file",
    ]
    assert "delete_file" not in response.text

    reduced = endpoint.token(scope="files:list")
    reduced_response = endpoint.client.post(
        RESOURCE_PATH,
        headers=endpoint.headers(
            reduced,
            session_id=session_id,
            protocol=True,
        ),
        json={"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
    )
    assert reduced_response.status_code == 200
    assert [tool["name"] for tool in reduced_response.json()["result"]["tools"]] == [
        "list_directory"
    ]


def test_tools_list_also_hides_registry_blocked_tools(endpoint):
    token, session_id = endpoint.initialize()
    with db._db_lock, db.get_conn() as conn:
        conn.execute(
            "UPDATE mcp_servers SET blocked_tools = ? WHERE server_id = ?",
            (json.dumps(["read_file"]), SERVER_ID),
        )
    response = endpoint.client.post(
        RESOURCE_PATH,
        headers=endpoint.headers(token, session_id=session_id, protocol=True),
        json={"jsonrpc": "2.0", "id": 31, "method": "tools/list", "params": {}},
    )
    assert response.status_code == 200
    assert [tool["name"] for tool in response.json()["result"]["tools"]] == [
        "list_directory"
    ]


@pytest.mark.parametrize("tool_name", ["list_directory", "delete_file", "unknown"])
def test_direct_tool_call_without_exact_scope_is_403(endpoint, tool_name):
    token = endpoint.token(scope="files:read")
    _, session_id = endpoint.initialize(token)
    response = endpoint.client.post(
        RESOURCE_PATH,
        headers=endpoint.headers(token, session_id=session_id, protocol=True),
        json={
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": tool_name, "arguments": {"path": "/tmp"}},
        },
    )
    assert response.status_code == 403
    assert response.json()["error"] == "insufficient_scope"
    assert tool_name not in response.text
    assert endpoint.gateway_calls == []


def test_authorized_tool_call_uses_existing_gateway_without_bearer_or_api_key(
    endpoint,
):
    token = endpoint.token(scope="files:read")
    _, session_id = endpoint.initialize(token)
    response = endpoint.client.post(
        RESOURCE_PATH,
        headers=endpoint.headers(token, session_id=session_id, protocol=True),
        json={
            "jsonrpc": "2.0",
            "id": "call-request-id",
            "method": "tools/call",
            "params": {"name": "read_file", "arguments": {"path": "/tmp/a"}},
        },
    )
    assert response.status_code == 200
    assert response.json()["result"]["content"][0]["text"] == "mock-only result"
    assert len(endpoint.gateway_calls) == 1
    call = endpoint.gateway_calls[0]
    assert call["server_id"] == SERVER_ID
    assert call["tool_name"] == "read_file"
    assert call["role"] == "readonly_agent"
    assert call["principal_id"] == ""
    assert call["api_key"] is None
    assert token not in json.dumps(call)
    from core.mcp_gateway import _resolve_upstream_auth_headers

    downstream_headers = _resolve_upstream_auth_headers(db.lookup_mcp_server(SERVER_ID))
    assert set(downstream_headers) == {"Authorization"}
    downstream_authorization = downstream_headers["Authorization"]
    assert downstream_authorization.startswith("Bearer ")
    assert (
        hashlib.sha256(
            downstream_authorization.removeprefix("Bearer ").encode("ascii")
        ).hexdigest()
        == endpoint.downstream_credential_digest
    )
    assert token not in json.dumps(downstream_headers)
    row = db.list_mcp_audit_logs(limit=1)[0]
    assert row["hash_v"] == 4
    assert row["principal_id"] == ""
    assert row["authority_status"] == "verified"
    assert row["oauth_client_binding_key_id"] == "client-2026-07"
    assert row["delegated_subject_binding_key_id"] == "subject-2026-07"
    assert row["token_binding_key_id"] == "token-2026-07"
    assert row["downstream_service_principal_id"] == "mcp-files-service"
    assert row["downstream_auth_mode"] == "configured_service_credential"
    assert row["inbound_authority_forwarded"] is False
    assert row["downstream_authority_evaluated"] is False
    serialized = json.dumps(row, sort_keys=True)
    assert token not in serialized
    assert CLIENT_ONE not in serialized
    assert endpoint.issuer.subject not in serialized
    assert downstream_authorization not in serialized
    assert "call-request-id" not in serialized
    from core.receipt import build_receipt

    receipt = json.dumps(build_receipt(row), sort_keys=True)
    assert token not in receipt
    assert CLIENT_ONE not in receipt
    assert endpoint.issuer.subject not in receipt
    assert downstream_authorization not in receipt


def test_downstream_identity_and_service_auth_configuration_must_agree(endpoint):
    token, session_id = endpoint.initialize()
    db.unregister_mcp_server(SERVER_ID)
    db.register_mcp_server(
        SERVER_ID,
        {
            "url": "https://safe.example/mcp",
            "allowed_tools": ["read_file"],
            "blocked_tools": [],
            "auth_type": "none",
        },
    )
    db.verify_mcp_server(SERVER_ID)
    response = endpoint.client.post(
        RESOURCE_PATH,
        headers=endpoint.headers(token, session_id=session_id, protocol=True),
        json={
            "jsonrpc": "2.0",
            "id": 11,
            "method": "tools/call",
            "params": {"name": "read_file", "arguments": {"path": "/tmp/a"}},
        },
    )
    assert response.status_code == 503
    assert response.json()["error"] == "downstream_identity_configuration_invalid"
    assert endpoint.gateway_calls == []
    row = db.list_mcp_audit_logs(limit=1)[0]
    assert row["hash_v"] == 4
    assert row["authority_status"] == "verified"
    assert row["downstream_service_principal_id"] is None
    assert row["authority_failure_code"] == (
        "downstream_identity_configuration_invalid"
    )


def test_token_binding_is_call_specific_without_retaining_the_token(endpoint):
    token, session_id = endpoint.initialize()
    for request_id in (21, 22):
        response = endpoint.client.post(
            RESOURCE_PATH,
            headers=endpoint.headers(
                token,
                session_id=session_id,
                protocol=True,
            ),
            json={
                "jsonrpc": "2.0",
                "id": request_id,
                "method": "tools/call",
                "params": {
                    "name": "read_file",
                    "arguments": {"path": "/tmp/a"},
                },
            },
        )
        assert response.status_code == 200
    rows = db.list_mcp_audit_logs(limit=2)
    assert rows[0]["call_id"] != rows[1]["call_id"]
    assert rows[0]["token_binding"] != rows[1]["token_binding"]
    assert all(token not in json.dumps(row, sort_keys=True) for row in rows)


def test_same_client_different_subject_cannot_reuse_session(endpoint):
    token, session_id = endpoint.initialize()
    replacement = endpoint.token(sub="different-subject")
    response = endpoint.client.post(
        RESOURCE_PATH,
        headers=endpoint.headers(
            replacement,
            session_id=session_id,
            protocol=True,
        ),
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
    )
    assert response.status_code == 403
    assert response.json()["error"] == "session_subject_mismatch"
    row = db.list_mcp_audit_logs(limit=1)[0]
    assert row["hash_v"] == 4
    assert row["authority_status"] == "verified"
    assert row["authority_failure_code"] == "session_subject_mismatch"
    assert row["downstream_service_principal_id"] is None


def test_same_subject_different_client_cannot_reuse_session(endpoint):
    token, session_id = endpoint.initialize()
    replacement = endpoint.token(client_id=CLIENT_TWO)
    response = endpoint.client.post(
        RESOURCE_PATH,
        headers=endpoint.headers(
            replacement,
            session_id=session_id,
            protocol=True,
        ),
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
    )
    assert response.status_code == 403
    assert response.json()["error"] == "session_client_mismatch"
    row = db.list_mcp_audit_logs(limit=1)[0]
    assert row["hash_v"] == 4
    assert row["authority_status"] == "verified"
    assert row["authority_failure_code"] == "session_client_mismatch"


def test_expired_replacement_token_is_rejected_but_valid_refresh_is_accepted(endpoint):
    token, session_id = endpoint.initialize()
    expired = endpoint.token(exp=1)
    denied = endpoint.client.post(
        RESOURCE_PATH,
        headers=endpoint.headers(expired, session_id=session_id, protocol=True),
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
    )
    assert denied.status_code == 401
    assert denied.json()["error"] == "token_expired"

    refreshed = endpoint.token(iat=int(time.time()))
    allowed = endpoint.client.post(
        RESOURCE_PATH,
        headers=endpoint.headers(
            refreshed,
            session_id=session_id,
            protocol=True,
        ),
        json={"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
    )
    assert allowed.status_code == 200


def test_authenticated_get_returns_405_and_delete_terminates_session(endpoint):
    token, session_id = endpoint.initialize()
    no_auth = endpoint.client.get(RESOURCE_PATH)
    assert no_auth.status_code == 401

    get_response = endpoint.client.get(
        RESOURCE_PATH,
        headers=endpoint.headers(token, session_id=session_id, protocol=True),
    )
    assert get_response.status_code == 405

    deleted = endpoint.client.delete(
        RESOURCE_PATH,
        headers=endpoint.headers(token, session_id=session_id, protocol=True),
    )
    assert deleted.status_code == 204
    reused = endpoint.client.post(
        RESOURCE_PATH,
        headers=endpoint.headers(token, session_id=session_id, protocol=True),
        json={"jsonrpc": "2.0", "id": 3, "method": "tools/list", "params": {}},
    )
    assert reused.status_code == 404
    assert reused.json()["error"] == "session_not_found"


def test_malformed_json_and_unknown_method_return_json_rpc_errors_after_auth(endpoint):
    token, session_id = endpoint.initialize()
    malformed = endpoint.client.post(
        RESOURCE_PATH,
        headers=endpoint.headers(token, session_id=session_id, protocol=True),
        content=b"{not-json",
    )
    assert malformed.status_code == 400
    assert malformed.json()["error"]["code"] == -32700

    unknown = endpoint.client.post(
        RESOURCE_PATH,
        headers=endpoint.headers(token, session_id=session_id, protocol=True),
        json={"jsonrpc": "2.0", "id": 9, "method": "resources/list", "params": {}},
    )
    assert unknown.status_code == 200
    assert unknown.json()["error"]["code"] == -32601
