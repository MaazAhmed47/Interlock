"""Opt-in experimental MCP Streamable HTTP resource endpoint.

This module validates only an exchanged access token.  It does not accept an
ID-JAG, perform token exchange, or infer authority from request claims.
"""

from __future__ import annotations

import json
import uuid
from typing import Any, Optional
from urllib.parse import urlsplit

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response

from core import db
from core.ema_auth import (
    EMAAccessTokenValidator,
    EMAAuthError,
    VerifiedAuthority,
    bind_access_token,
    bind_delegated_subject,
    bind_oauth_client,
    extract_bearer_token,
)
from core.ema_config import EMASettings
from core.ema_context import authority_audit_scope
from core.ema_sessions import EMASessionError, EMASessionStore
from core.mcp_gateway import proxy_mcp_tool_call
from core import drift_evidence

_JSON_RPC_VERSION = "2.0"


def _json_rpc_result(request_id: Any, result: Any) -> JSONResponse:
    return JSONResponse(
        {
            "jsonrpc": _JSON_RPC_VERSION,
            "id": request_id,
            "result": result,
        }
    )


def _json_rpc_error(
    request_id: Any,
    code: int,
    message: str,
    *,
    status_code: int = 200,
) -> JSONResponse:
    return JSONResponse(
        {
            "jsonrpc": _JSON_RPC_VERSION,
            "id": request_id,
            "error": {"code": code, "message": message},
        },
        status_code=status_code,
    )


def _error(code: str, status_code: int, headers: Optional[dict[str, str]] = None):
    return JSONResponse(
        {"error": code},
        status_code=status_code,
        headers=headers,
    )


def _metadata_uri(settings: EMASettings) -> str:
    parsed = urlsplit(settings.resource_uri)
    return (
        f"{parsed.scheme}://{parsed.netloc}"
        f"{settings.protected_resource_metadata_path}"
    )


def _challenge(settings: EMASettings, *, error: Optional[str] = None) -> str:
    scopes = " ".join(
        sorted(
            {scope for required in settings.tool_scopes.values() for scope in required}
        )
    )
    parts = [
        f'resource_metadata="{_metadata_uri(settings)}"',
        f'scope="{scopes}"',
    ]
    if error is not None:
        parts.append(f'error="{error}"')
    return "Bearer " + ", ".join(parts)


async def _authenticate(
    request: Request,
    settings: EMASettings,
    validator: EMAAccessTokenValidator,
) -> tuple[Optional[str], Optional[VerifiedAuthority], Optional[Response]]:
    """Validate bearer credentials before any body or session processing."""
    try:
        token = extract_bearer_token(
            request.headers.get("authorization"),
            settings,
        )
        authority = await validator.validate_token(token)
    except EMAAuthError as exc:
        return (
            None,
            None,
            _error(
                exc.code,
                exc.status_code,
                {
                    "WWW-Authenticate": _challenge(
                        settings,
                        error="invalid_token",
                    )
                },
            ),
        )
    return token, authority, None


def _origin_error(request: Request, settings: EMASettings) -> Optional[Response]:
    origin = request.headers.get("origin")
    if origin is None:
        return None
    if origin.rstrip("/") not in settings.allowed_origins:
        return _error("invalid_origin", 403)
    return None


def _transport_headers_error(request: Request) -> Optional[Response]:
    accept = {
        value.split(";", 1)[0].strip().lower()
        for value in (request.headers.get("accept") or "").split(",")
    }
    if "application/json" not in accept or "text/event-stream" not in accept:
        return _error("invalid_accept", 406)
    content_type = (request.headers.get("content-type") or "").split(";", 1)[0]
    if content_type.strip().lower() != "application/json":
        return _error("invalid_content_type", 415)
    return None


async def _authorized_session(
    request: Request,
    settings: EMASettings,
    sessions: EMASessionStore,
    authority: VerifiedAuthority,
):
    session_id = request.headers.get("mcp-session-id")
    if not session_id:
        return None, _error("missing_session", 400)
    if request.headers.get("mcp-protocol-version") != settings.protocol_version:
        return None, _error("invalid_protocol_version", 400)
    try:
        session = await sessions.authorize(session_id, authority)
    except EMASessionError as exc:
        return None, _error(exc.code, exc.status_code)
    return session, None


def _validate_message(message: Any):
    if not isinstance(message, dict):
        return None
    if message.get("jsonrpc") != _JSON_RPC_VERSION:
        return None
    method = message.get("method")
    if not isinstance(method, str) or not method:
        return None
    return message


def _verified_audit_context(
    settings: EMASettings,
    authority: VerifiedAuthority,
    raw_token: str,
    call_id: str,
    method: str,
) -> dict[str, Any]:
    client = bind_oauth_client(
        settings,
        authority.issuer,
        authority.client_id,
    )
    subject = bind_delegated_subject(
        settings,
        authority.issuer,
        authority.subject,
    )
    token = bind_access_token(settings, raw_token, call_id)
    return {
        "transport": "streamable_http",
        "mcp_resource_uri": settings.resource_uri,
        "mcp_protocol_version": settings.protocol_version,
        "mcp_method": method,
        "authority_mode": "exchanged_access_token",
        "authority_status": "verified",
        "authority_profile": settings.profile,
        "authority_artifact_type": "mcp_access_token",
        "authority_signature_algorithm": "RS256",
        "authority_token_type": "at+jwt",
        "authority_validation_boundary": "interlock_gateway",
        "authority_verified_at": authority.verified_at,
        "authority_issuer": authority.issuer,
        "authority_audiences": list(authority.audiences),
        "authority_resource": authority.resource,
        "authority_scopes": list(authority.scopes),
        "authority_expires_at": authority.expires_at,
        "authority_not_before": authority.not_before,
        "authority_issued_at": authority.issued_at,
        "oauth_client_binding": client.value,
        "oauth_client_binding_alg": client.algorithm,
        "oauth_client_binding_key_id": client.key_id,
        "delegated_subject_binding": subject.value,
        "delegated_subject_binding_alg": subject.algorithm,
        "delegated_subject_binding_key_id": subject.key_id,
        "interlock_service_principal_id": (settings.interlock_service_principal_id),
        "downstream_service_principal_id": None,
        "token_binding": token.value,
        "token_binding_alg": token.algorithm,
        "token_binding_key_id": token.key_id,
        "downstream_auth_mode": "none",
        "inbound_authority_forwarded": False,
        "downstream_authority_evaluated": False,
        "authority_failure_code": "",
    }


def _denied_audit_context(
    settings: EMASettings,
    failure_code: str,
) -> dict[str, Any]:
    return {
        "transport": "streamable_http",
        "mcp_resource_uri": settings.resource_uri,
        "mcp_protocol_version": settings.protocol_version,
        "mcp_method": "",
        "authority_mode": "exchanged_access_token",
        "authority_status": "denied",
        "authority_profile": settings.profile,
        "authority_artifact_type": "mcp_access_token",
        "authority_signature_algorithm": None,
        "authority_token_type": None,
        "authority_validation_boundary": "interlock_gateway",
        "authority_verified_at": None,
        "authority_issuer": None,
        "authority_audiences": None,
        "authority_resource": None,
        "authority_scopes": None,
        "authority_expires_at": None,
        "authority_not_before": None,
        "authority_issued_at": None,
        "oauth_client_binding": None,
        "oauth_client_binding_alg": None,
        "oauth_client_binding_key_id": None,
        "delegated_subject_binding": None,
        "delegated_subject_binding_alg": None,
        "delegated_subject_binding_key_id": None,
        "interlock_service_principal_id": (settings.interlock_service_principal_id),
        "downstream_service_principal_id": None,
        "token_binding": None,
        "token_binding_alg": None,
        "token_binding_key_id": None,
        "downstream_auth_mode": "none",
        "inbound_authority_forwarded": False,
        "downstream_authority_evaluated": False,
        "authority_failure_code": failure_code,
    }


def _audit_unverified_denial(settings: EMASettings, failure_code: str) -> None:
    call_id = uuid.uuid4().hex
    with authority_audit_scope(
        _denied_audit_context(settings, failure_code),
        call_id=call_id,
    ):
        db.log_mcp_audit_event(
            {
                "server_id": settings.server_id,
                "tool_name": "",
                "principal_id": "",
                "role": settings.role,
                "action": "deny",
                "matched_rule": "ema_authority_validation",
                "reason": "EMA bearer authorization was denied.",
                "blocked_by": failure_code,
                "argument_hash": "",
                "call_id": call_id,
            }
        )


def _audit_verified_denial(
    settings: EMASettings,
    authority: VerifiedAuthority,
    raw_token: str,
    method: str,
    failure_code: str,
) -> None:
    call_id = uuid.uuid4().hex
    context = _verified_audit_context(
        settings,
        authority,
        raw_token,
        call_id,
        method,
    )
    context["authority_failure_code"] = failure_code
    with authority_audit_scope(context, call_id=call_id):
        db.log_mcp_audit_event(
            {
                "server_id": settings.server_id,
                "tool_name": "",
                "principal_id": "",
                "role": settings.role,
                "action": "deny",
                "matched_rule": "ema_session_authorization",
                "reason": "The MCP session authorization check was denied.",
                "blocked_by": failure_code,
                "argument_hash": "",
                "call_id": call_id,
            }
        )


def _response_error_code(response: Response, default: str) -> str:
    try:
        value = json.loads(bytes(response.body)).get("error")
    except (AttributeError, json.JSONDecodeError, UnicodeDecodeError):
        value = None
    return str(value or default)


def _authorized_tools(
    settings: EMASettings,
    authority: VerifiedAuthority,
) -> list[dict[str, Any]]:
    granted = set(authority.scopes)
    server = db.lookup_mcp_server(settings.server_id)
    if not server or not server.get("verified"):
        return []
    allowed = set(server.get("allowed_tools") or [])
    blocked = set(server.get("blocked_tools") or [])
    tools = []
    for record in db.list_mcp_tool_metadata(settings.server_id):
        tool_name = record.get("tool_name")
        if not isinstance(tool_name, str):
            continue
        required = settings.tool_scopes.get((settings.server_id, tool_name))
        if not required or not required.issubset(granted):
            continue
        if (allowed and tool_name not in allowed) or tool_name in blocked:
            continue
        if record.get("status") != "active":
            continue
        raw = record.get("raw_tool_definition")
        if isinstance(raw, dict) and raw.get("name") == tool_name:
            tools.append(raw)
    return tools


def create_ema_router(
    settings: Optional[EMASettings],
    *,
    validator: Optional[EMAAccessTokenValidator] = None,
    sessions: Optional[EMASessionStore] = None,
) -> APIRouter:
    """Build no routes unless the complete experimental profile is enabled."""
    router = APIRouter()
    if settings is None:
        return router

    validator = validator or EMAAccessTokenValidator(settings)
    sessions = sessions or EMASessionStore(settings)

    @router.get(
        settings.protected_resource_metadata_path,
        include_in_schema=False,
    )
    async def protected_resource_metadata():
        return {
            "resource": settings.resource_uri,
            "authorization_servers": [settings.issuer],
            "bearer_methods_supported": ["header"],
            "scopes_supported": sorted(
                {
                    scope
                    for required in settings.tool_scopes.values()
                    for scope in required
                }
            ),
        }

    @router.post(settings.resource_path, include_in_schema=False)
    async def streamable_http_post(request: Request):
        origin_error = _origin_error(request, settings)
        if origin_error is not None:
            return origin_error

        raw_token, authority, auth_error = await _authenticate(
            request,
            settings,
            validator,
        )
        if auth_error is not None:
            failure = _response_error_code(auth_error, "invalid_token")
            _audit_unverified_denial(settings, failure)
            return auth_error
        assert raw_token is not None and authority is not None

        header_error = _transport_headers_error(request)
        if header_error is not None:
            return header_error

        # The body is deliberately first touched only after credential validation.
        body = await request.body()
        try:
            message = json.loads(body)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return _json_rpc_error(
                None,
                -32700,
                "Parse error",
                status_code=400,
            )
        message = _validate_message(message)
        if message is None:
            return _json_rpc_error(
                None,
                -32600,
                "Invalid Request",
                status_code=400,
            )

        request_id = message.get("id")
        method = message["method"]
        params = message.get("params") or {}
        if not isinstance(params, dict):
            return _json_rpc_error(request_id, -32602, "Invalid params")

        if method == "initialize":
            if "id" not in message or request_id is None:
                return _json_rpc_error(
                    None,
                    -32600,
                    "Invalid Request",
                    status_code=400,
                )
            if request.headers.get("mcp-session-id"):
                return _error("unexpected_session", 400)
            if params.get("protocolVersion") != settings.protocol_version:
                return _json_rpc_error(
                    request_id,
                    -32602,
                    "Unsupported protocol version",
                )
            client_info = params.get("clientInfo")
            if (
                not isinstance(params.get("capabilities"), dict)
                or not isinstance(client_info, dict)
                or not isinstance(client_info.get("name"), str)
                or not client_info.get("name")
                or not isinstance(client_info.get("version"), str)
                or not client_info.get("version")
            ):
                return _json_rpc_error(
                    request_id,
                    -32602,
                    "Invalid params",
                    status_code=400,
                )
            session = await sessions.create(authority)
            response = _json_rpc_result(
                request_id,
                {
                    "protocolVersion": settings.protocol_version,
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
            )
            response.headers["MCP-Session-Id"] = session.session_id
            return response

        session, session_error = await _authorized_session(
            request,
            settings,
            sessions,
            authority,
        )
        if session_error is not None:
            _audit_verified_denial(
                settings,
                authority,
                raw_token,
                method,
                _response_error_code(session_error, "session_denied"),
            )
            return session_error
        assert session is not None

        if method == "notifications/initialized":
            if "id" in message:
                return _json_rpc_error(
                    request_id,
                    -32600,
                    "Invalid Request",
                    status_code=400,
                )
            await sessions.mark_initialized(session.session_id, authority)
            return Response(status_code=202)
        if not session.initialized:
            return _error("session_not_initialized", 400)

        if method == "tools/list":
            if "id" not in message or request_id is None:
                return _json_rpc_error(
                    None,
                    -32600,
                    "Invalid Request",
                    status_code=400,
                )
            return _json_rpc_result(
                request_id,
                {"tools": _authorized_tools(settings, authority)},
            )

        if method == "tools/call":
            if "id" not in message or request_id is None:
                return _json_rpc_error(
                    None,
                    -32600,
                    "Invalid Request",
                    status_code=400,
                )
            tool_name = params.get("name")
            arguments = params.get("arguments", {})
            if not isinstance(tool_name, str) or not isinstance(arguments, dict):
                return _json_rpc_error(request_id, -32602, "Invalid params")
            required = settings.tool_scopes.get((settings.server_id, tool_name))
            if not required or not required.issubset(set(authority.scopes)):
                call_id = uuid.uuid4().hex
                context = _verified_audit_context(
                    settings,
                    authority,
                    raw_token,
                    call_id,
                    method,
                )
                with authority_audit_scope(context, call_id=call_id):
                    db.log_mcp_audit_event(
                        {
                            "server_id": settings.server_id,
                            "tool_name": tool_name,
                            "principal_id": "",
                            "role": settings.role,
                            "action": "deny",
                            "matched_rule": "ema_scope_to_tool",
                            "reason": (
                                "The verified token did not grant the exact "
                                "server-side scope mapping for this tool."
                            ),
                            "blocked_by": "insufficient_scope",
                            "argument_hash": (drift_evidence.arguments_hash(arguments)),
                            "call_id": call_id,
                        }
                    )
                return _error(
                    "insufficient_scope",
                    403,
                    {
                        "WWW-Authenticate": _challenge(
                            settings,
                            error="insufficient_scope",
                        )
                    },
                )
            server = db.lookup_mcp_server(settings.server_id)
            service_auth_configured = bool(
                server and str(server.get("auth_type") or "none") != "none"
            )
            service_principal_configured = bool(
                settings.downstream_service_principal_id
            )
            if service_auth_configured != service_principal_configured:
                call_id = uuid.uuid4().hex
                context = _verified_audit_context(
                    settings,
                    authority,
                    raw_token,
                    call_id,
                    method,
                )
                context["authority_failure_code"] = (
                    "downstream_identity_configuration_invalid"
                )
                with authority_audit_scope(context, call_id=call_id):
                    db.log_mcp_audit_event(
                        {
                            "server_id": settings.server_id,
                            "tool_name": tool_name,
                            "principal_id": "",
                            "role": settings.role,
                            "action": "deny",
                            "matched_rule": "ema_downstream_identity",
                            "reason": (
                                "The configured downstream service identity "
                                "does not match the server authentication mode."
                            ),
                            "blocked_by": ("downstream_identity_configuration_invalid"),
                            "argument_hash": (drift_evidence.arguments_hash(arguments)),
                            "call_id": call_id,
                        }
                    )
                return _error(
                    "downstream_identity_configuration_invalid",
                    503,
                )
            call_id = uuid.uuid4().hex
            context = _verified_audit_context(
                settings,
                authority,
                raw_token,
                call_id,
                method,
            )
            downstream_mode = (
                "configured_service_credential"
                if settings.downstream_service_principal_id
                else "none"
            )
            with authority_audit_scope(
                context,
                call_id=call_id,
                downstream_service_principal_id=(
                    settings.downstream_service_principal_id
                ),
                downstream_auth_mode=downstream_mode,
            ):
                result = await proxy_mcp_tool_call(
                    server_id=settings.server_id,
                    tool_name=tool_name,
                    arguments=arguments,
                    role=settings.role,
                    principal_id="",
                    api_key=None,
                )
            if result.get("ok"):
                tool_result = result.get("result")
            else:
                tool_result = {
                    "content": [
                        {
                            "type": "text",
                            "text": "Interlock denied the tool call.",
                        }
                    ],
                    "isError": True,
                }
            return _json_rpc_result(request_id, tool_result)

        return _json_rpc_error(request_id, -32601, "Method not found")

    @router.get(settings.resource_path, include_in_schema=False)
    async def streamable_http_get(request: Request):
        origin_error = _origin_error(request, settings)
        if origin_error is not None:
            return origin_error
        raw_token, authority, auth_error = await _authenticate(
            request,
            settings,
            validator,
        )
        if auth_error is not None:
            _audit_unverified_denial(
                settings,
                _response_error_code(auth_error, "invalid_token"),
            )
            return auth_error
        assert raw_token is not None and authority is not None
        _, session_error = await _authorized_session(
            request,
            settings,
            sessions,
            authority,
        )
        if session_error is not None:
            _audit_verified_denial(
                settings,
                authority,
                raw_token,
                "",
                _response_error_code(session_error, "session_denied"),
            )
            return session_error
        return _error(
            "sse_not_implemented",
            405,
            {"Allow": "POST, DELETE"},
        )

    @router.delete(settings.resource_path, include_in_schema=False)
    async def streamable_http_delete(request: Request):
        origin_error = _origin_error(request, settings)
        if origin_error is not None:
            return origin_error
        raw_token, authority, auth_error = await _authenticate(
            request,
            settings,
            validator,
        )
        if auth_error is not None:
            _audit_unverified_denial(
                settings,
                _response_error_code(auth_error, "invalid_token"),
            )
            return auth_error
        assert raw_token is not None and authority is not None
        session, session_error = await _authorized_session(
            request,
            settings,
            sessions,
            authority,
        )
        if session_error is not None:
            _audit_verified_denial(
                settings,
                authority,
                raw_token,
                "",
                _response_error_code(session_error, "session_denied"),
            )
            return session_error
        assert session is not None
        await sessions.terminate(session.session_id, authority)
        return Response(status_code=204)

    return router
