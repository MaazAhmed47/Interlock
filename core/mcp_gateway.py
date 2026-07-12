import re
import json
import os
import time
import contextvars
import httpx
from typing import Optional, Dict, Any
from datetime import datetime, timezone
from models.schemas import ScanResult, ThreatLevel
from core.metadata_policy import evaluate_metadata_policy
from core.url_security import OutboundUrlRejected, ensure_safe_outbound_url
from core.tool_inspector import inspect_tool_call
from core.tool_metadata import normalize_tool_metadata
from core import db
from core.response_scanner import scan_injection, scan_pii_and_volume
from core.effect_drift import (
    build_effect_profile,
    classify_effect_drift,
    effect_profile_hash,
)
from core.external_reach import (
    build_external_reach_profile,
    classify_external_reach_drift,
    external_reach_profile_hash,
)
from core.response_drift import (
    build_response_exposure_profile,
    classify_response_exposure_drift,
    response_profile_hash,
)
from core.mcp_drift import classify_server_drift
from core import drift_evidence

# Per-operation start time for gateway-path latency. Set at the top of each
# entry point that logs audit events (tool-call proxy, server registration);
# the audit helpers read it so every MCP audit row carries a real scan time.
# A ContextVar keeps concurrent async requests isolated.
_op_start: contextvars.ContextVar[Optional[float]] = contextvars.ContextVar(
    "mcp_op_start", default=None
)


def _begin_op() -> None:
    _op_start.set(time.perf_counter())


def _elapsed_ms() -> Optional[float]:
    start = _op_start.get()
    if start is None:
        return None
    return round((time.perf_counter() - start) * 1000, 2)


# ── MCP Server Registry ───────────────────────────────────────────────────────
# Used only as seed data for db.seed_mcp_servers() — never read directly at runtime.
TRUSTED_MCP_SERVERS = {
    "trusted-filesystem": {
        "url": "https://mcp.acme-corp.internal/filesystem",
        "description": "Sandboxed file system access",
        "allowed_tools": ["read_file", "list_directory"],
        "blocked_tools": ["write_file", "delete_file", "execute"],
        "rate_limit": 60,
        "verified": True,
    },
    "trusted-search": {
        "url": "https://mcp.acme-corp.internal/search",
        "description": "Web search MCP",
        "allowed_tools": ["search", "fetch"],
        "blocked_tools": [],
        "rate_limit": 30,
        "verified": True,
    },
}

UPSTREAM_AUTH_TYPES = {"none", "bearer", "x-api-key"}
AUTH_HEADER_RE = re.compile(r"^[A-Za-z0-9-]+$")


class UpstreamAuthConfigError(ValueError):
    """Raised when upstream MCP auth is configured unsafely or incompletely."""


def _normalize_upstream_auth_config(config: Optional[Dict[str, Any]]) -> Dict[str, str]:
    config = dict(config or {})
    auth_type = str(config.get("auth_type") or "none").strip().lower()
    if auth_type not in UPSTREAM_AUTH_TYPES:
        raise UpstreamAuthConfigError(
            "Upstream auth_type must be one of: none, bearer, x-api-key."
        )

    auth_header = str(config.get("auth_header") or "").strip()
    if not auth_header and auth_type == "bearer":
        auth_header = "Authorization"
    elif not auth_header and auth_type == "x-api-key":
        auth_header = "x-api-key"

    auth_token_env = str(config.get("auth_token_env") or "").strip()
    if auth_type == "none":
        return {"auth_type": "none", "auth_header": "", "auth_token_env": ""}

    if not auth_token_env:
        raise UpstreamAuthConfigError(
            "Upstream auth is enabled but auth_token_env is not configured."
        )
    if not auth_header or not AUTH_HEADER_RE.fullmatch(auth_header):
        raise UpstreamAuthConfigError("Upstream auth_header is invalid.")

    return {
        "auth_type": auth_type,
        "auth_header": auth_header,
        "auth_token_env": auth_token_env,
    }


def _resolve_upstream_auth_headers(server: Optional[Dict[str, Any]]) -> Dict[str, str]:
    auth_config = _normalize_upstream_auth_config(server)
    auth_type = auth_config["auth_type"]
    if auth_type == "none":
        return {}

    token_env = auth_config["auth_token_env"]
    token = os.getenv(token_env)
    if not token:
        raise UpstreamAuthConfigError(
            f"Upstream auth token env var '{token_env}' is not set."
        )

    header = auth_config["auth_header"]
    if auth_type == "bearer":
        return {header: f"Bearer {token}"}
    return {header: token}


def _mcp_post_kwargs(
    payload: Dict[str, Any], headers: Dict[str, str]
) -> Dict[str, Any]:
    kwargs: Dict[str, Any] = {"json": payload}
    if headers:
        kwargs["headers"] = headers
    return kwargs


# ── MCP Tool Definition Validation ────────────────────────────────────────────
SUSPICIOUS_TOOL_NAMES = [
    r"^(execute|eval|run)_?\w*$",
    # Ordinary destructive CRUD tools are handled by metadata policy/RBAC.
    (
        r"^(delete|drop|truncate|wipe|remove|destroy)_?"
        r"(all|everything|database|db|production|prod|system)(?:_?\w*)?$"
    ),
    r"^(shell|bash|cmd|powershell)_?\w*$",
    r"^(admin|root|sudo|superuser)_?\w*$",
    r"^(backdoor|reverse_shell|exploit)_?\w*$",
    r".*(execute|run).*(arbitrary|untrusted).*",
    r".*\.\.\/.*",  # path traversal in name
]

SUSPICIOUS_DESCRIPTIONS = [
    r"unrestricted",
    r"no.{0,10}sandbox",
    r"bypass.{0,10}(security|safety|restriction)",
    r"execute.{0,30}(arbitrary|user|untrusted)",
    r"full.{0,10}(system|admin|root).{0,10}access",
    r"download.{0,30}execute",
    r"reverse.{0,5}shell",
]

DANGEROUS_SCHEMA_FIELDS = [
    "command",
    "shell_cmd",
    "exec_command",
    "raw_query",
    "raw_sql",
    "system_call",
    "code_to_run",
    "script_content",
]

BULK_DESTRUCTIVE_SCHEMA_VALUE_RE = re.compile(
    r"^(delete|drop|truncate|wipe|remove|destroy|purge)_?"
    r"(all|everything|database|db|production|prod|system|records?)$",
    re.IGNORECASE,
)


def _malformed_tool_result(tool: Any, reason: str) -> ScanResult:
    return ScanResult(
        is_threat=True,
        threat_level=ThreatLevel.HIGH,
        threat_type="MCP_MALFORMED_TOOL_DEFINITION",
        reason=reason,
        original_prompt=f"Tool definition: {json.dumps(tool, default=str)[:300]}",
        safe_to_proceed=False,
        confidence=0.95,
        layer_caught="MCP Gateway - Tool Validator",
        tool_metadata=normalize_tool_metadata({}),
    )


def _schema_nodes(schema: Any):
    if not isinstance(schema, dict):
        return
    yield schema
    properties = schema.get("properties")
    if isinstance(properties, dict):
        for child in properties.values():
            yield from _schema_nodes(child)
    for key in ("items", "oneOf", "anyOf", "allOf"):
        child = schema.get(key)
        if isinstance(child, dict):
            yield from _schema_nodes(child)
        elif isinstance(child, list):
            for item in child:
                yield from _schema_nodes(item)


def _find_dangerous_schema_field(schema: dict) -> Optional[str]:
    dangerous = {field.lower() for field in DANGEROUS_SCHEMA_FIELDS}
    for node in _schema_nodes(schema):
        properties = node.get("properties")
        if not isinstance(properties, dict):
            continue
        for field in properties:
            if str(field).lower() in dangerous:
                return str(field)
    return None


def _find_bulk_destructive_enum_value(schema: dict) -> Optional[str]:
    for node in _schema_nodes(schema):
        values = []
        enum = node.get("enum")
        if isinstance(enum, list):
            values.extend(enum)
        if "const" in node:
            values.append(node["const"])
        for value in values:
            normalized = str(value).strip().replace("-", "_")
            if BULK_DESTRUCTIVE_SCHEMA_VALUE_RE.match(normalized):
                return str(value)
    return None


# ── Tool Definition Scanner ───────────────────────────────────────────────────
def validate_mcp_tool_definition(tool: dict) -> ScanResult:
    """
    Validate a tool definition from an MCP server BEFORE exposing it to agents.
    Catches:
    - Suspicious tool names (eval, execute, delete_all)
    - Malicious descriptions (prompt injections in tool descriptions)
    - Dangerous schema fields (raw command inputs)
    - Hidden instructions in descriptions
    """
    if not isinstance(tool, dict):
        return _malformed_tool_result(
            tool, "MCP tool definition must be a JSON object."
        )

    metadata = normalize_tool_metadata(tool)
    raw_name = tool.get("name")
    if not isinstance(raw_name, str) or not raw_name.strip():
        return _malformed_tool_result(
            tool, "MCP tool definition must include a non-empty string name."
        )

    name = raw_name.strip().lower()
    raw_description = tool.get("description", "")
    description = "" if raw_description is None else str(raw_description).lower()
    raw_schema = tool.get("inputSchema", {}) or tool.get("input_schema", {})
    schema = raw_schema if isinstance(raw_schema, dict) else {}

    # 1. Check for malicious tool names
    for pattern in SUSPICIOUS_TOOL_NAMES:
        if re.match(pattern, name, re.IGNORECASE):
            return ScanResult(
                is_threat=True,
                threat_level=ThreatLevel.HIGH,
                threat_type="MALICIOUS_MCP_TOOL_NAME",
                reason=f"Tool name '{name}' matches suspicious pattern '{pattern}'. Possible MCP supply chain attack.",
                original_prompt=f"Tool definition: {json.dumps(tool)[:300]}",
                safe_to_proceed=False,
                confidence=0.95,
                layer_caught="MCP Gateway — Tool Validator",
                tool_metadata=metadata,
            )

    # 2. Check for prompt injection in description
    for pattern in SUSPICIOUS_DESCRIPTIONS:
        if re.search(pattern, description, re.IGNORECASE):
            return ScanResult(
                is_threat=True,
                threat_level=ThreatLevel.CRITICAL,
                threat_type="MCP_TOOL_DESCRIPTION_INJECTION",
                reason=f"Tool description contains suspicious pattern '{pattern}'. Possible hidden instruction in tool definition.",
                original_prompt=f"Tool: {name} | Description: {description[:200]}",
                safe_to_proceed=False,
                confidence=0.95,
                layer_caught="MCP Gateway — Tool Validator",
                tool_metadata=metadata,
            )

    # 3. Check for prompt injection patterns in description
    injection_patterns = [
        r"ignore (all |previous )?(instructions|prompts)",
        r"forget (everything|all|your)",
        r"system prompt",
        r"reveal (your|the) (prompt|instructions)",
        r"act as (an? )?(unrestricted|admin|root)",
    ]
    for pattern in injection_patterns:
        if re.search(pattern, description, re.IGNORECASE):
            return ScanResult(
                is_threat=True,
                threat_level=ThreatLevel.CRITICAL,
                threat_type="MCP_TOOL_DESCRIPTION_INJECTION",
                reason="Hidden prompt injection detected in tool description.",
                original_prompt=f"Tool: {name}",
                safe_to_proceed=False,
                confidence=0.99,
                layer_caught="MCP Gateway — Tool Validator",
                tool_metadata=metadata,
            )

    # 4. Check schema for dangerous parameter fields
    dangerous_field = _find_dangerous_schema_field(schema)
    if dangerous_field:
        return ScanResult(
            is_threat=True,
            threat_level=ThreatLevel.HIGH,
            threat_type="MCP_DANGEROUS_SCHEMA",
            reason=f"Tool '{name}' accepts dangerous parameter '{dangerous_field}'. Allows arbitrary command/code execution.",
            original_prompt=f"Tool: {name} | Schema: {json.dumps(schema)[:200]}",
            safe_to_proceed=False,
            confidence=0.92,
            layer_caught="MCP Gateway - Tool Validator",
            tool_metadata=metadata,
        )

    destructive_value = _find_bulk_destructive_enum_value(schema)
    if destructive_value:
        return ScanResult(
            is_threat=True,
            threat_level=ThreatLevel.HIGH,
            threat_type="MCP_DANGEROUS_SCHEMA",
            reason=f"Tool '{name}' exposes bulk-destructive schema value '{destructive_value}'.",
            original_prompt=f"Tool: {name} | Schema: {json.dumps(schema)[:200]}",
            safe_to_proceed=False,
            confidence=0.9,
            layer_caught="MCP Gateway - Tool Validator",
            tool_metadata=metadata,
        )

    properties = schema.get("properties", {})
    for field in DANGEROUS_SCHEMA_FIELDS:
        if field in properties:
            return ScanResult(
                is_threat=True,
                threat_level=ThreatLevel.HIGH,
                threat_type="MCP_DANGEROUS_SCHEMA",
                reason=f"Tool '{name}' accepts dangerous parameter '{field}'. Allows arbitrary command/code execution.",
                original_prompt=f"Tool: {name} | Schema: {json.dumps(schema)[:200]}",
                safe_to_proceed=False,
                confidence=0.92,
                layer_caught="MCP Gateway — Tool Validator",
                tool_metadata=metadata,
            )

    # 5. Check for excessively long descriptions (token smuggling)
    if len(description) > 2000:
        return ScanResult(
            is_threat=True,
            threat_level=ThreatLevel.MEDIUM,
            threat_type="MCP_OVERSIZED_DESCRIPTION",
            reason=f"Tool description is {len(description)} chars. Possible token smuggling attack.",
            original_prompt=f"Tool: {name}",
            safe_to_proceed=False,
            confidence=0.85,
            layer_caught="MCP Gateway — Tool Validator",
            tool_metadata=metadata,
        )

    return ScanResult(
        is_threat=False,
        threat_level=ThreatLevel.SAFE,
        threat_type=None,
        reason=f"MCP tool '{name}' passed validation.",
        original_prompt=f"Tool: {name}",
        safe_to_proceed=True,
        confidence=0.97,
        layer_caught="MCP Gateway — Tool Validator",
        tool_metadata=metadata,
    )


# ── MCP Server Discovery ──────────────────────────────────────────────────────
async def discover_mcp_tools(
    server_url: str,
    timeout: float = 10.0,
    server_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Connect to an MCP server and discover its tools.
    Validates every tool definition before returning.
    """
    _begin_op()
    try:
        server_url = ensure_safe_outbound_url(server_url, context="MCP discovery")
        registered = (
            db.lookup_mcp_server(server_id)
            if server_id
            else db.lookup_mcp_server_by_url(server_url)
        )
        registry_server_id = server_id or (
            registered.get("server_id") if registered else None
        )
        headers = _resolve_upstream_auth_headers(registered)

        async with httpx.AsyncClient(timeout=timeout) as client:
            payload = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
            resp = await client.post(server_url, **_mcp_post_kwargs(payload, headers))
            resp.raise_for_status()
            data = resp.json()
            if not isinstance(data, dict):
                return {
                    "ok": False,
                    "error": "mcp_discovery_error",
                    "message": "MCP server returned a non-object JSON-RPC response.",
                    "server_url": server_url,
                }
            if data.get("error"):
                return {
                    "ok": False,
                    "error": "mcp_discovery_error",
                    "message": str(data["error"])[:200],
                    "server_url": server_url,
                }

            result = data.get("result") or {}
            tools = result.get("tools", []) if isinstance(result, dict) else []
            if not isinstance(tools, list):
                return {
                    "ok": False,
                    "error": "mcp_discovery_error",
                    "message": "MCP tools/list result.tools must be a list.",
                    "server_url": server_url,
                }

            seen_tool_names = set()
            duplicate_tool_names = set()
            for candidate in tools:
                if not isinstance(candidate, dict):
                    continue
                candidate_name = candidate.get("name")
                if not isinstance(candidate_name, str) or not candidate_name.strip():
                    continue
                normalized_name = candidate_name.strip()
                if normalized_name in seen_tool_names:
                    duplicate_tool_names.add(normalized_name)
                seen_tool_names.add(normalized_name)
            if duplicate_tool_names:
                return {
                    "ok": False,
                    "error": "duplicate_tool_names",
                    "message": f"MCP discovery returned duplicate tool names: {sorted(duplicate_tool_names)}.",
                    "server_url": server_url,
                }

            # Validate every tool
            validation_results = []
            safe_tools = []
            blocked_tools = []

            # ── Server-level drift check (tool additions / removals) ──────────
            # Must run BEFORE upsert so previous_names still reflects prior state.
            # Newly-added tools flagged critical here are quarantined AFTER upsert
            # (upsert always inserts new tools active), keyed by name below.
            quarantine_added: Dict[str, str] = {}
            if registry_server_id:
                current_tool_defs = {
                    t.get("name", "").strip(): t
                    for t in tools
                    if isinstance(t, dict)
                    and isinstance(t.get("name"), str)
                    and t.get("name", "").strip()
                }
                current_names = set(current_tool_defs)
                previous_names = db.get_known_tool_names(registry_server_id)
                if previous_names:
                    server_findings = classify_server_drift(
                        registry_server_id,
                        previous_names,
                        current_names,
                        current_tool_defs,
                    )
                    for finding in server_findings:
                        is_critical_added = (
                            finding["type"] == "tool_added"
                            and finding["severity"] == "critical"
                        )
                        if finding["type"] == "tool_removed":
                            db.mark_mcp_tool_removed(
                                registry_server_id,
                                finding["tool_name"],
                                finding["reason"],
                            )
                        elif is_critical_added:
                            quarantine_added[finding["tool_name"]] = finding["reason"]
                        # Critical new-tool drift is recorded once, by the per-tool
                        # drift_detected receipt below (with surface hashes); avoid a
                        # duplicate server-level row here.
                        if is_critical_added:
                            continue
                        db.log_mcp_audit_event(
                            {
                                "server_id": registry_server_id,
                                "tool_name": finding["tool_name"],
                                "action": (
                                    "quarantine"
                                    if finding["severity"] == "critical"
                                    else "deny"
                                ),
                                "role": "system",
                                "reason": finding["reason"],
                                "matched_rule": finding["type"],
                                "drift_status": finding["type"],
                                "drift_severity": finding["severity"],
                                "drift_action": (
                                    "quarantine"
                                    if finding["severity"] == "critical"
                                    else "deny"
                                ),
                                "drift_types": [finding["type"]],
                                "drift_reasons": [finding["reason"]],
                                "scan_time_ms": _elapsed_ms(),
                            }
                        )

            for tool in tools:
                validation = validate_mcp_tool_definition(tool)
                registry = {"persisted": False, "reason": "server_id_not_registered"}
                tool_name = (
                    tool.get("name", "").strip() if isinstance(tool, dict) else ""
                )
                quarantined_by_drift = False
                drift_block_reason = ""
                if registry_server_id and not validation.is_threat:
                    registry = db.upsert_mcp_tool_metadata(
                        registry_server_id,
                        tool,
                        validation.tool_metadata or {},
                    )
                    registry["persisted"] = True
                    # A new destructive/exfiltration tool passes the static
                    # validator (ordinary CRUD is handled by RBAC at call time),
                    # so the DRIFT path must quarantine it: it was just inserted
                    # active, flip it to quarantined before it can be used.
                    if tool_name and tool_name in quarantine_added:
                        db.mark_mcp_tool_added_drift(
                            registry_server_id,
                            tool_name,
                            quarantine_added[tool_name],
                        )
                        registry["status"] = "quarantined"
                        quarantined_by_drift = True
                        drift_block_reason = quarantine_added[tool_name]
                    elif registry.get("status") == "quarantined":
                        # An EXISTING approved tool escalated capability under the
                        # same name. Mirror the new-tool path so the discover
                        # response matches the registry status + call-time
                        # enforcement instead of leaving it in safe_tools.
                        quarantined_by_drift = True
                        _raw_reasons = registry.get("drift_reasons")
                        _reasons = (
                            _raw_reasons if isinstance(_raw_reasons, list) else []
                        )
                        drift_block_reason = (
                            "; ".join(str(r) for r in _reasons[:3])
                            or f"Tool '{tool_name}' quarantined by capability drift."
                        )
                    # Record DETECTION at discovery (no-op for unchanged tools):
                    # a drift_detected receipt distinct from call-time enforcement.
                    if tool_name:
                        _emit_discovery_drift_receipt(registry_server_id, tool_name)
                validation_results.append(
                    {
                        "tool_name": (
                            tool.get("name") if isinstance(tool, dict) else None
                        ),
                        "is_safe": not validation.is_threat
                        and not quarantined_by_drift,
                        "validation": (
                            validation.model_dump()
                            if hasattr(validation, "model_dump")
                            else vars(validation)
                        ),
                        "tool_metadata": validation.tool_metadata,
                        "registry": registry,
                    }
                )

                if validation.is_threat:
                    blocked_tools.append({"tool": tool, "reason": validation.reason})
                elif quarantined_by_drift:
                    blocked_tools.append({"tool": tool, "reason": drift_block_reason})
                else:
                    safe_tools.append(tool)

            return {
                "ok": True,
                "server_url": server_url,
                "total_tools": len(tools),
                "safe_tools": len(safe_tools),
                "blocked_tools": len(blocked_tools),
                "tools": safe_tools,
                "blocked": blocked_tools,
                "validations": validation_results,
            }

    except OutboundUrlRejected as exc:
        return {"ok": False, "error": "unsafe_mcp_server_url", "message": str(exc)}
    except UpstreamAuthConfigError as exc:
        return {
            "ok": False,
            "error": "upstream_auth_unavailable",
            "message": str(exc),
            "server_url": server_url,
        }
    except httpx.TimeoutException:
        return {"ok": False, "error": "MCP server timeout", "server_url": server_url}
    except Exception as e:
        return {"ok": False, "error": str(e)[:200], "server_url": server_url}


# ── MCP Tool Call Proxy ───────────────────────────────────────────────────────
async def proxy_mcp_tool_call(
    server_id: str,
    tool_name: str,
    arguments: dict,
    role: Optional[str] = None,
    principal_id: str = "",
    api_key: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Proxy an MCP tool call through the firewall.
    Validates → inspects → routes to MCP server → scans response.
    """
    _begin_op()
    # 1. Verify server is trusted
    server = db.lookup_mcp_server(server_id)
    if not server:
        saved = _log_mcp_gateway_audit(
            server_id=server_id,
            tool_name=tool_name,
            role=role,
            principal_id=principal_id,
            action="deny",
            matched_rule="untrusted_mcp_server",
            reason=f"MCP server '{server_id}' is not in the trusted registry.",
            arguments=arguments,
            blocked_by="untrusted_mcp_server",
        )
        return {
            "ok": False,
            "error": "untrusted_mcp_server",
            "message": f"MCP server '{server_id}' is not in the trusted registry. Add it via /mcp/servers endpoint first.",
            "audit": _audit_ref(saved),
        }

    if not server.get("verified"):
        saved = _log_mcp_gateway_audit(
            server_id=server_id,
            tool_name=tool_name,
            role=role,
            principal_id=principal_id,
            action="deny",
            matched_rule="unverified_mcp_server",
            reason=f"MCP server '{server_id}' is registered but not verified.",
            arguments=arguments,
            blocked_by="unverified_mcp_server",
        )
        return {
            "ok": False,
            "error": "unverified_mcp_server",
            "message": f"MCP server '{server_id}' is registered but not verified. Cannot proxy calls.",
            "audit": _audit_ref(saved),
        }

    # Fetch per-key volume thresholds for the response scanner (O(1) hash lookup).
    key_config = (db.lookup_key(api_key) or {}) if api_key else {}

    # 2. Check tool is in allowed list
    allowed = server.get("allowed_tools", [])
    blocked = server.get("blocked_tools", [])

    if blocked and tool_name in blocked:
        saved = _log_mcp_gateway_audit(
            server_id=server_id,
            tool_name=tool_name,
            role=role,
            principal_id=principal_id,
            action="deny",
            matched_rule="tool_blocked",
            reason=f"Tool '{tool_name}' is in the blocked list for server '{server_id}'.",
            arguments=arguments,
            blocked_by="tool_blocked",
        )
        return {
            "ok": False,
            "error": "tool_blocked",
            "message": f"Tool '{tool_name}' is in the blocked list for server '{server_id}'.",
            "audit": _audit_ref(saved),
        }

    if allowed is not None and (not allowed or tool_name not in allowed):
        saved = _log_mcp_gateway_audit(
            server_id=server_id,
            tool_name=tool_name,
            role=role,
            principal_id=principal_id,
            action="deny",
            matched_rule="tool_not_allowed",
            reason=f"Tool '{tool_name}' is not in the allowed list for server '{server_id}'.",
            arguments=arguments,
            blocked_by="tool_not_allowed",
        )
        return {
            "ok": False,
            "error": "tool_not_allowed",
            "message": f"Tool '{tool_name}' is not in the allowed list for server '{server_id}'. Allowed: {allowed}",
            "audit": _audit_ref(saved),
        }

    # 3. Normalize runtime metadata and apply metadata-aware policy.
    runtime_tool = {
        "name": tool_name,
        "description": "",
        "inputSchema": {
            "type": "object",
            "properties": {
                key: {"type": type(value).__name__}
                for key, value in (arguments or {}).items()
            },
        },
    }
    runtime_metadata = normalize_tool_metadata(runtime_tool)
    stored_tool = db.lookup_mcp_tool_metadata(server_id, tool_name)
    stored_metadata = (stored_tool or {}).get("normalized_metadata")
    tool_metadata = db.merge_stored_and_runtime_metadata(
        stored_metadata or {}, runtime_metadata
    )
    drift_context = _stored_tool_drift_context(stored_tool)
    external_reach_drift = None
    effect_drift = None
    if drift_context:
        warnings = list(tool_metadata.get("warnings") or [])
        drift_warning = (
            "Stored MCP tool metadata changed after initial discovery "
            f"({drift_context['severity']}/{drift_context['action']})."
        )
        if drift_warning not in warnings:
            warnings.append(drift_warning)
        tool_metadata["warnings"] = warnings
        tool_metadata["drift"] = drift_context

    policy_decision = evaluate_metadata_policy(
        server_id=server_id,
        tool_name=tool_name,
        arguments=arguments,
        role=role,
        tool_metadata=tool_metadata,
    )
    # Bind every audit row this call produces to the exact argument set. Only
    # the hash is recorded; raw argument values never enter the audit log.
    policy_decision.setdefault("audit_context", {})["argument_hash"] = (
        drift_evidence.arguments_hash(arguments or {})
    )
    policy_decision["audit_context"]["principal_id"] = principal_id
    _attach_drift_context(policy_decision, drift_context)

    if drift_context and (
        drift_context["severity"] == "critical"
        or drift_context["action"] == "quarantine"
    ):
        reason = _drift_reason(
            drift_context,
            "Stored MCP tool metadata drift is critical; the tool is quarantined until reviewed.",
        )
        _set_policy_decision(policy_decision, "deny", "tool_quarantined", reason)
        saved = _log_mcp_policy_audit(policy_decision, blocked_by="tool_quarantined")
        return {
            "ok": False,
            "error": "tool_quarantined",
            "message": reason,
            "drift": drift_context,
            "policy_decision": policy_decision,
            "audit": _audit_ref(saved),
        }

    if drift_context and (
        drift_context["severity"] == "high" or drift_context["action"] == "deny"
    ):
        reason = _drift_reason(
            drift_context,
            "Stored MCP tool metadata drift is high risk; blocking execution until reviewed.",
        )
        _set_policy_decision(policy_decision, "deny", "tool_metadata_drift", reason)
        saved = _log_mcp_policy_audit(policy_decision, blocked_by="metadata_drift")
        return {
            "ok": False,
            "error": "metadata_drift_violation",
            "message": reason,
            "drift": drift_context,
            "policy_decision": policy_decision,
            "audit": _audit_ref(saved),
        }

    if (
        drift_context
        and drift_context["action"] == "monitor"
        and policy_decision["action"] == "allow"
    ):
        policy_decision["action"] = "monitor"
        policy_decision["matched_rule"] = "tool_metadata_drift"
        policy_decision["reason"] = _drift_reason(
            drift_context,
            "Stored MCP tool metadata changed after initial discovery; allow but monitor.",
        )
        policy_decision["warnings"] = tool_metadata.get("warnings", [])
        policy_decision["audit_context"]["decision"] = "monitor"
        policy_decision["audit_context"]["matched_rule"] = "tool_metadata_drift"
        policy_decision["audit_context"]["reason"] = policy_decision["reason"]
        policy_decision["audit_context"]["warnings"] = policy_decision["warnings"]

    if policy_decision["action"] == "deny":
        saved = _log_mcp_policy_audit(policy_decision, blocked_by="metadata_policy")
        return {
            "ok": False,
            "error": "metadata_policy_violation",
            "message": policy_decision["reason"],
            "policy_decision": policy_decision,
            "audit": _audit_ref(saved),
        }

    # 3. Run through standard tool call inspector
    inspection = inspect_tool_call(tool_name, arguments)
    if inspection.is_threat:
        _log_mcp_policy_audit(policy_decision, blocked_by="tool_inspector")
        return {
            "ok": False,
            "error": "tool_call_blocked",
            "threat_level": inspection.threat_level.value,
            "threat_type": inspection.threat_type,
            "reason": inspection.reason,
            "confidence": inspection.confidence,
            "layer_caught": inspection.layer_caught,
            "policy_decision": policy_decision,
        }

    # 4. RBAC check if role provided
    if role:
        from core.policy import rbac_scan

        rbac_result = rbac_scan(json.dumps(arguments), tool_name, role)
        if rbac_result and rbac_result.is_threat:
            _log_mcp_policy_audit(policy_decision, blocked_by="rbac")
            return {
                "ok": False,
                "error": "rbac_violation",
                "threat_level": rbac_result.threat_level.value,
                "threat_type": rbac_result.threat_type,
                "reason": rbac_result.reason,
                "confidence": rbac_result.confidence,
                "policy_decision": policy_decision,
            }

    # 4b. Deterministic argument constraints from DB tool policy
    try:
        tool_policy_row = db.get_policy_by_name("tool", tool_name, server_id)
        if tool_policy_row:
            tool_rules = tool_policy_row.get("rules") or {}
            bound_violation = _check_param_bounds(arguments or {}, tool_rules)
            if bound_violation:
                _log_mcp_gateway_audit(
                    server_id=server_id,
                    tool_name=tool_name,
                    role=role,
                    action="deny",
                    matched_rule="param_bounds",
                    reason=bound_violation,
                    arguments=arguments or {},
                    blocked_by="param_bounds",
                    principal_id=principal_id,
                )
                return {
                    "ok": False,
                    "error": "param_bounds_violation",
                    "reason": bound_violation,
                }
    except Exception:
        import logging as _logging

        _logging.getLogger("interlock.mcp_gateway").exception(
            "Param bounds check failed — failing open"
        )

    # 4c. Provenance check (MCP04) — re-evaluate on every call to catch silent substitutions
    try:
        from core.provenance import evaluate_provenance

        policy = db.load_mcp04_policy()
        server_row = db.lookup_mcp_server(server_id)
        if server_row:
            prov = evaluate_provenance(server_row, policy)
            if prov.status in ("quarantine", "denied"):
                _log_mcp_gateway_audit(
                    server_id=server_id,
                    tool_name=tool_name,
                    role=role,
                    action="provenance_block",
                    matched_rule="mcp04_policy",
                    reason=prov.reason,
                    arguments=arguments,
                    blocked_by="mcp04_policy",
                    principal_id=principal_id,
                )
                return {
                    "ok": False,
                    "error": "provenance_quarantine",
                    "reason": prov.reason,
                }
    except Exception:
        import logging as _logging

        _logging.getLogger("interlock.mcp_gateway").exception(
            "Provenance check failed at tool-call time -- failing open"
        )

    # 4d. Destination-aware external reach drift. This runs before the
    # upstream call so a tool cannot publish/send/export to a newly observed
    # external destination before review. Only known discovered tools get
    # baselined; inferred-only calls still go through the existing policy path.
    stored_external_reach_profile = None
    current_external_reach_profile = None
    if stored_tool is not None:
        current_external_reach_profile = build_external_reach_profile(arguments or {})
        stored_external_reach_profile = db.lookup_mcp_external_reach_profile(
            server_id, tool_name
        )
        if stored_external_reach_profile is None:
            db.upsert_mcp_external_reach_profile(
                server_id, tool_name, current_external_reach_profile
            )
        else:
            external_reach_drift = classify_external_reach_drift(
                stored_external_reach_profile.get("profile") or {},
                current_external_reach_profile,
            )
            if not external_reach_drift.get("drift_detected"):
                external_reach_drift = None

    if external_reach_drift:
        external_stored_profile = stored_external_reach_profile or {}
        external_current_profile = current_external_reach_profile or {}
        external_baseline_hash = external_stored_profile.get(
            "profile_hash"
        ) or external_reach_profile_hash(external_stored_profile.get("profile") or {})
        external_current_hash = external_reach_profile_hash(external_current_profile)
        external_reason = _external_reach_drift_reason(external_reach_drift)
        external_action = external_reach_drift.get("action") or "monitor"
        if external_action == "quarantine":
            db.mark_mcp_tool_external_reach_drift(
                server_id,
                tool_name,
                external_reach_drift.get("types") or [],
                external_reason,
            )

        external_audit = dict(policy_decision.get("audit_context") or {})
        external_audit.update(
            {
                "action": external_action,
                "matched_rule": "external_reach_drift",
                "reason": external_reason,
                "blocked_by": (
                    "external_reach_drift"
                    if external_action in {"deny", "quarantine"}
                    else ""
                ),
                "drift_status": "external_reach_drift",
                "drift_severity": external_reach_drift.get("severity") or "none",
                "drift_action": external_action,
                "drift_types": external_reach_drift.get("types") or [],
                "drift_reasons": external_reach_drift.get("reasons") or [],
                "drift_baseline_hash": external_baseline_hash,
                "drift_current_hash": external_current_hash,
                "argument_keys": [],
                "scan_time_ms": _elapsed_ms(),
            }
        )
        external_public = _public_external_reach_drift_context(external_reach_drift)
        if external_action in {"deny", "quarantine"}:
            db.log_mcp_audit_event(external_audit)
            return {
                "ok": False,
                "error": "external_reach_drift_violation",
                "message": external_reason,
                "blocked_before_execution": True,
                "external_reach_drift": external_public,
                "drift": drift_context,
                "policy_decision": policy_decision,
            }

        policy_decision["action"] = "monitor"
        policy_decision["matched_rule"] = "external_reach_drift"
        policy_decision["reason"] = external_reason
        policy_decision["audit_context"].update(
            {
                "decision": "monitor",
                "matched_rule": "external_reach_drift",
                "reason": external_reason,
                "drift_status": "external_reach_drift",
                "drift_severity": external_reach_drift.get("severity") or "none",
                "drift_action": external_action,
                "drift_types": external_reach_drift.get("types") or [],
                "drift_reasons": external_reach_drift.get("reasons") or [],
                "drift_baseline_hash": external_baseline_hash,
                "drift_current_hash": external_current_hash,
                "argument_keys": [],
            }
        )

    # 5. Forward to actual MCP server
    try:
        server_url = ensure_safe_outbound_url(server["url"], context="MCP server")
        headers = _resolve_upstream_auth_headers(server)
        async with httpx.AsyncClient(timeout=30.0) as client:
            payload = {
                "jsonrpc": "2.0",
                "id": int(datetime.now(timezone.utc).timestamp()),
                "method": "tools/call",
                "params": {"name": tool_name, "arguments": arguments},
            }
            resp = await client.post(server_url, **_mcp_post_kwargs(payload, headers))
            data = resp.json()

            # 6. Scan the response — MCP06 (injection) then MCP10 (PII + volume).
            # Scan only the tool result payload, never the JSON-RPC envelope.
            # The envelope `id` is a unix-timestamp integer that the PII scanner
            # matches as a phone number and redacts, which would corrupt the
            # JSON we later re-parse. Only the result payload is real tool output.
            result_payload = data.get("result")
            response_text = json.dumps(result_payload)

            inj_result = scan_injection(response_text)
            if inj_result.is_threat:
                _log_mcp_policy_audit(
                    policy_decision,
                    blocked_by="response_injection",
                    extra={
                        "threat_type": inj_result.threat_type,
                        "confidence": inj_result.confidence,
                        "matched_patterns": inj_result.matched_patterns,
                    },
                )
                return {
                    "ok": False,
                    "error": "response_prompt_injection",
                    "message": "Tool response contains prompt injection attempt. Blocked.",
                    "blocked_response": True,
                    "threat_type": inj_result.threat_type,
                    "confidence": inj_result.confidence,
                    "matched_patterns": inj_result.matched_patterns,
                    "policy_decision": policy_decision,
                }

            max_response_bytes = key_config.get("max_response_bytes", 50_000)
            max_array_items = key_config.get("max_array_items", 500)
            pii_result = scan_pii_and_volume(
                response_text,
                max_bytes=max_response_bytes,
                max_items=max_array_items,
            )
            if pii_result.is_threat:
                _log_mcp_policy_audit(
                    policy_decision,
                    blocked_by="response_pii",
                    extra={
                        "threat_type": pii_result.threat_type,
                        "confidence": pii_result.confidence,
                        "matched_patterns": pii_result.matched_patterns,
                        "redactions": pii_result.redactions,
                    },
                )

            stored_effect_profile = None
            current_effect_profile = None
            # Effect drift is a post-execution observation. It cannot undo the
            # first observed side effect, so high/critical findings quarantine
            # future use and block the drifted response from continuing.
            if stored_tool is not None:
                current_effect_profile = build_effect_profile(result_payload)
                stored_effect_profile = db.lookup_mcp_effect_profile(
                    server_id, tool_name
                )
                if stored_effect_profile is None:
                    db.upsert_mcp_effect_profile(
                        server_id, tool_name, current_effect_profile
                    )
                else:
                    effect_drift = classify_effect_drift(
                        stored_effect_profile.get("profile") or {},
                        current_effect_profile,
                    )
                    if not effect_drift.get("drift_detected"):
                        effect_drift = None

            if effect_drift:
                effect_stored_profile = stored_effect_profile or {}
                effect_current_profile = current_effect_profile or {}
                effect_baseline_hash = effect_stored_profile.get(
                    "profile_hash"
                ) or effect_profile_hash(effect_stored_profile.get("profile") or {})
                effect_current_hash = effect_profile_hash(effect_current_profile)
                effect_reason = _effect_drift_reason(effect_drift)
                effect_action = effect_drift.get("action") or "monitor"
                if effect_action == "quarantine":
                    db.mark_mcp_tool_effect_drift(
                        server_id,
                        tool_name,
                        effect_drift.get("types") or [],
                        effect_reason,
                    )

                effect_audit = dict(policy_decision.get("audit_context") or {})
                effect_audit.update(
                    {
                        "action": effect_action,
                        "matched_rule": "effect_drift",
                        "reason": effect_reason,
                        "blocked_by": (
                            "effect_drift" if effect_action == "quarantine" else ""
                        ),
                        "drift_status": "effect_drift",
                        "drift_severity": effect_drift.get("severity") or "none",
                        "drift_action": effect_action,
                        "drift_types": effect_drift.get("types") or [],
                        "drift_reasons": effect_drift.get("reasons") or [],
                        "drift_baseline_hash": effect_baseline_hash,
                        "drift_current_hash": effect_current_hash,
                        "argument_keys": [],
                        "scan_time_ms": _elapsed_ms(),
                    }
                )
                effect_public = _public_effect_drift_context(effect_drift)
                if effect_action == "quarantine":
                    db.log_mcp_audit_event(effect_audit)
                    return {
                        "ok": False,
                        "error": "effect_drift_violation",
                        "message": effect_reason,
                        "blocked_response": True,
                        "effect_already_observed": True,
                        "effect_drift": effect_public,
                        "external_reach_drift": (
                            _public_external_reach_drift_context(external_reach_drift)
                            if external_reach_drift
                            else None
                        ),
                        "drift": drift_context,
                        "policy_decision": policy_decision,
                    }

                policy_decision["action"] = "monitor"
                policy_decision["matched_rule"] = "effect_drift"
                policy_decision["reason"] = effect_reason
                policy_decision["audit_context"].update(
                    {
                        "decision": "monitor",
                        "matched_rule": "effect_drift",
                        "reason": effect_reason,
                        "drift_status": "effect_drift",
                        "drift_severity": effect_drift.get("severity") or "none",
                        "drift_action": effect_action,
                        "drift_types": effect_drift.get("types") or [],
                        "drift_reasons": effect_drift.get("reasons") or [],
                        "drift_baseline_hash": effect_baseline_hash,
                        "drift_current_hash": effect_current_hash,
                        "argument_keys": [],
                    }
                )

            response_drift = None
            stored_response_profile = None
            response_profile = None
            # Response drift is a baseline comparison. Only create/enforce that
            # baseline for known tools discovered into the metadata registry;
            # inferred-only calls still get one-off response scanning/redaction.
            if stored_tool is not None:
                response_profile = build_response_exposure_profile(
                    response_text,
                    max_bytes=max_response_bytes,
                    max_items=max_array_items,
                )
                stored_response_profile = db.lookup_mcp_response_profile(
                    server_id, tool_name
                )
                if stored_response_profile is None:
                    db.upsert_mcp_response_profile(
                        server_id, tool_name, response_profile
                    )
                else:
                    response_drift = classify_response_exposure_drift(
                        stored_response_profile.get("profile") or {},
                        response_profile,
                    )
                    if not response_drift.get("drift_detected"):
                        response_drift = None

            if response_drift:
                response_stored_profile = stored_response_profile or {}
                response_current_profile = response_profile or {}
                response_baseline_hash = response_stored_profile.get(
                    "profile_hash"
                ) or response_profile_hash(response_stored_profile.get("profile") or {})
                response_current_hash = response_profile_hash(response_current_profile)
                response_reason = _response_drift_reason(response_drift)
                response_action = response_drift.get("action") or "monitor"
                if response_action == "quarantine":
                    db.mark_mcp_tool_response_drift(
                        server_id,
                        tool_name,
                        response_drift.get("types") or [],
                        response_reason,
                    )

                response_audit = dict(policy_decision.get("audit_context") or {})
                response_audit.update(
                    {
                        "action": response_action,
                        "matched_rule": "response_exposure_drift",
                        "reason": response_reason,
                        "blocked_by": (
                            "response_drift"
                            if response_action in {"deny", "quarantine"}
                            else ""
                        ),
                        "drift_status": "response_drift",
                        "drift_severity": response_drift.get("severity") or "none",
                        "drift_action": response_action,
                        "drift_types": response_drift.get("types") or [],
                        "drift_reasons": response_drift.get("reasons") or [],
                        "drift_baseline_hash": response_baseline_hash,
                        "drift_current_hash": response_current_hash,
                        "scan_time_ms": _elapsed_ms(),
                    }
                )
                response_public = _public_response_drift_context(response_drift)
                if response_action in {"deny", "quarantine"}:
                    db.log_mcp_audit_event(response_audit)
                    return {
                        "ok": False,
                        "error": "response_drift_violation",
                        "message": response_reason,
                        "blocked_response": True,
                        "response_drift": response_public,
                        "external_reach_drift": (
                            _public_external_reach_drift_context(external_reach_drift)
                            if external_reach_drift
                            else None
                        ),
                        "drift": drift_context,
                        "policy_decision": policy_decision,
                    }

                policy_decision["action"] = "monitor"
                policy_decision["matched_rule"] = "response_exposure_drift"
                policy_decision["reason"] = response_reason
                policy_decision["audit_context"].update(
                    {
                        "decision": "monitor",
                        "matched_rule": "response_exposure_drift",
                        "reason": response_reason,
                        "drift_status": "response_drift",
                        "drift_severity": response_drift.get("severity") or "none",
                        "drift_action": response_action,
                        "drift_types": response_drift.get("types") or [],
                        "drift_reasons": response_drift.get("reasons") or [],
                        "drift_baseline_hash": response_baseline_hash,
                        "drift_current_hash": response_current_hash,
                    }
                )

            if pii_result.is_threat and pii_result.sanitized_content is not None:
                effective_result = pii_result.sanitized_content
            else:
                effective_result = response_text

            saved = _log_mcp_policy_audit(policy_decision, blocked_by="")
            return {
                "ok": True,
                "server_id": server_id,
                "tool_name": tool_name,
                "audit": _audit_ref(saved),
                "result": json.loads(effective_result),
                "scanned": True,
                "threat_flags": (
                    [pii_result.threat_type] if pii_result.is_threat else []
                ),
                "redactions": pii_result.redactions,
                "drift": drift_context,
                "response_drift": (
                    _public_response_drift_context(response_drift)
                    if response_drift
                    else None
                ),
                "external_reach_drift": (
                    _public_external_reach_drift_context(external_reach_drift)
                    if external_reach_drift
                    else None
                ),
                "effect_drift": (
                    _public_effect_drift_context(effect_drift) if effect_drift else None
                ),
                "policy_decision": policy_decision,
            }

    except OutboundUrlRejected as exc:
        _log_mcp_policy_audit(policy_decision, blocked_by="unsafe_mcp_server_url")
        return {"ok": False, "error": "unsafe_mcp_server_url", "message": str(exc)}
    except UpstreamAuthConfigError as exc:
        _log_mcp_policy_audit(policy_decision, blocked_by="upstream_auth_unavailable")
        return {"ok": False, "error": "upstream_auth_unavailable", "message": str(exc)}
    except httpx.TimeoutException:
        _log_mcp_policy_audit(policy_decision, blocked_by="mcp_timeout")
        return {"ok": False, "error": "mcp_server_timeout"}
    except Exception as e:
        _log_mcp_policy_audit(policy_decision, blocked_by="mcp_server_error")
        return {"ok": False, "error": "mcp_server_error", "message": str(e)[:200]}


def _audit_ref(saved: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Compact reference to the audit row backing a gateway response, so the
    caller can fetch the Security Receipt and verify its context binding."""
    saved = saved or {}
    return {
        "audit_id": saved.get("id"),
        "call_id": saved.get("call_id") or "",
        "argument_hash": saved.get("argument_hash") or "",
    }


def _log_mcp_policy_audit(
    policy_decision: Dict[str, Any],
    blocked_by: str = "",
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    audit = dict(policy_decision.get("audit_context") or {})
    audit["action"] = audit.get("decision") or policy_decision.get("action", "")
    audit["blocked_by"] = blocked_by
    audit["scan_time_ms"] = _elapsed_ms()
    if extra:
        audit.update(extra)
    return db.log_mcp_audit_event(audit)


def _stored_tool_drift_context(
    stored_tool: Optional[Dict[str, Any]],
) -> Optional[Dict[str, Any]]:
    if not stored_tool:
        return None

    stored_tool = db.canonicalize_mcp_tool_record(stored_tool)
    status = stored_tool.get("status") or "active"
    severity = stored_tool.get("drift_severity") or "none"
    action = stored_tool.get("drift_action") or "allow"

    if status == "active" and severity == "none" and action == "allow":
        return None

    # Content-addressed drift evidence: hash the approved and current tool
    # surfaces and retain their canonical bytes so the hashes stay
    # re-derivable even after a later baseline approval wipes
    # previous_tool_definition. Best-effort — evidence emission must never
    # break the call path.
    baseline_surface_hash = ""
    current_surface_hash = ""
    try:
        previous_def = stored_tool.get("previous_tool_definition") or {}
        current_def = stored_tool.get("raw_tool_definition") or {}
        if previous_def:
            canonical = drift_evidence.canonical_surface_json(previous_def)
            baseline_surface_hash = drift_evidence.tool_surface_hash(previous_def)
            db.save_tool_surface_snapshot(baseline_surface_hash, canonical)
        if current_def:
            canonical = drift_evidence.canonical_surface_json(current_def)
            current_surface_hash = drift_evidence.tool_surface_hash(current_def)
            db.save_tool_surface_snapshot(current_surface_hash, canonical)
    except Exception:
        baseline_surface_hash = ""
        current_surface_hash = ""

    return {
        "status": status,
        "severity": severity,
        "action": action,
        "types": list(stored_tool.get("drift_types") or []),
        "reasons": list(stored_tool.get("drift_reasons") or []),
        "last_changed": stored_tool.get("last_changed"),
        "previous_schema_hash": stored_tool.get("previous_schema_hash"),
        "current_schema_hash": stored_tool.get("tool_schema_hash"),
        "baseline_surface_hash": baseline_surface_hash,
        "current_surface_hash": current_surface_hash,
    }


def _attach_drift_context(
    policy_decision: Dict[str, Any], drift: Optional[Dict[str, Any]]
) -> None:
    if not drift:
        return

    policy_decision["drift"] = drift
    tool_metadata = policy_decision.setdefault("tool_metadata", {})
    tool_metadata["drift"] = drift

    warnings = list(policy_decision.get("warnings") or [])
    warning = f"MCP tool drift severity={drift['severity']} action={drift['action']}."
    if warning not in warnings:
        warnings.append(warning)
    policy_decision["warnings"] = warnings

    audit = policy_decision.setdefault("audit_context", {})
    audit["warnings"] = warnings
    audit["drift_status"] = drift.get("status")
    audit["drift_severity"] = drift.get("severity")
    audit["drift_action"] = drift.get("action")
    audit["drift_types"] = drift.get("types") or []
    audit["drift_reasons"] = drift.get("reasons") or []
    audit["drift_baseline_hash"] = drift.get("baseline_surface_hash") or ""
    audit["drift_current_hash"] = drift.get("current_surface_hash") or ""


def _emit_discovery_drift_receipt(server_id: str, tool_name: str) -> None:
    """Emit a discovery-time ``drift_detected`` Security Receipt / audit event the
    moment discovery detects a tool drifted — a new destructive/exfiltration tool,
    or an existing approved tool escalating its capability under the same name.

    This records that DETECTION happened at discovery (timestamp T1), distinct
    from and prior to the call-time ``tool_quarantined`` enforcement receipt
    (timestamp T2). It carries the drift severity/action/types/reasons plus the
    before/after content-addressed surface hashes, hash-chain linked like every
    other audit row. Best-effort: evidence emission must never break discovery.
    """
    try:
        stored = db.lookup_mcp_tool_metadata(server_id, tool_name)
        drift = _stored_tool_drift_context(stored)
        if not drift:
            return
        db.log_mcp_audit_event(
            {
                "server_id": server_id,
                "tool_name": tool_name,
                "role": "system",
                "action": drift["action"],
                "matched_rule": "drift_detected",
                "reason": _drift_reason(
                    drift,
                    f"Capability drift detected at discovery for '{tool_name}'.",
                ),
                "blocked_by": "",
                "drift_status": drift["status"],
                "drift_severity": drift["severity"],
                "drift_action": drift["action"],
                "drift_types": drift.get("types") or [],
                "drift_reasons": drift.get("reasons") or [],
                "drift_baseline_hash": drift.get("baseline_surface_hash") or "",
                "drift_current_hash": drift.get("current_surface_hash") or "",
                "scan_time_ms": _elapsed_ms(),
            }
        )
    except Exception:
        import logging as _logging

        _logging.getLogger("interlock.mcp_gateway").exception(
            "Failed to emit discovery drift receipt for %s/%s", server_id, tool_name
        )


def _set_policy_decision(
    policy_decision: Dict[str, Any],
    action: str,
    matched_rule: str,
    reason: str,
) -> None:
    policy_decision["action"] = action
    policy_decision["matched_rule"] = matched_rule
    policy_decision["reason"] = reason
    policy_decision["audit_context"]["decision"] = action
    policy_decision["audit_context"]["matched_rule"] = matched_rule
    policy_decision["audit_context"]["reason"] = reason


def _drift_reason(drift: Dict[str, Any], fallback: str) -> str:
    reasons = drift.get("reasons") or []
    if not reasons:
        return fallback
    return f"{fallback} " + " ".join(str(reason) for reason in reasons[:3])


def _effect_drift_reason(drift: Dict[str, Any]) -> str:
    reasons = drift.get("reasons") or []
    if not reasons:
        return "Tool observed effect profile drifted from the approved baseline."
    return (
        "Tool observed effect profile drifted from the approved baseline. "
        + " ".join(str(reason) for reason in reasons[:3])
    )


def _public_effect_drift_context(
    drift: Optional[Dict[str, Any]],
) -> Optional[Dict[str, Any]]:
    if not drift:
        return None
    return {
        "detected": bool(drift.get("drift_detected")),
        "severity": drift.get("severity") or "none",
        "action": drift.get("action") or "allow",
        "types": list(drift.get("types") or []),
        "reasons": list(drift.get("reasons") or []),
    }


def _external_reach_drift_reason(drift: Dict[str, Any]) -> str:
    reasons = drift.get("reasons") or []
    if not reasons:
        return "Tool external destination profile drifted from the approved baseline."
    return (
        "Tool external destination profile drifted from the approved baseline. "
        + " ".join(str(reason) for reason in reasons[:3])
    )


def _public_external_reach_drift_context(
    drift: Optional[Dict[str, Any]],
) -> Optional[Dict[str, Any]]:
    if not drift:
        return None
    return {
        "detected": bool(drift.get("drift_detected")),
        "severity": drift.get("severity") or "none",
        "action": drift.get("action") or "allow",
        "types": list(drift.get("types") or []),
        "reasons": list(drift.get("reasons") or []),
    }


def _response_drift_reason(drift: Dict[str, Any]) -> str:
    reasons = drift.get("reasons") or []
    if not reasons:
        return "Tool response exposure profile drifted from the approved baseline."
    return (
        "Tool response exposure profile drifted from the approved baseline. "
        + " ".join(str(reason) for reason in reasons[:3])
    )


def _public_response_drift_context(
    drift: Optional[Dict[str, Any]],
) -> Optional[Dict[str, Any]]:
    if not drift:
        return None
    return {
        "detected": bool(drift.get("drift_detected")),
        "severity": drift.get("severity") or "none",
        "action": drift.get("action") or "allow",
        "types": list(drift.get("types") or []),
        "reasons": list(drift.get("reasons") or []),
    }


def _check_param_bounds(
    arguments: Dict[str, Any],
    rules: Dict[str, Any],
) -> Optional[str]:
    """
    Evaluate deterministic argument constraints defined in a tool policy.

    Supported constraints per parameter:
    - ``min`` / ``max``      — numeric lower / upper bound
    - ``max_length``         — maximum string length
    - ``allowed_values``     — enum allowlist

    Returns a human-readable denial reason string when a constraint is violated,
    or ``None`` when all constraints pass.  Silently skips parameters that are
    absent from ``arguments`` so callers need not pre-populate defaults.
    """
    param_bounds: Dict[str, Any] = rules.get("param_bounds") or {}
    for param, constraints in param_bounds.items():
        if param not in arguments:
            continue
        value = arguments[param]

        if "min" in constraints or "max" in constraints:
            if isinstance(value, (int, float)):
                lo = constraints.get("min")
                hi = constraints.get("max")
                if lo is not None and value < lo:
                    return f"Numeric bound violation: {param}={value} is below min={lo}"
                if hi is not None and value > hi:
                    return f"Numeric bound violation: {param}={value} exceeds max={hi}"

        if "max_length" in constraints and isinstance(value, str):
            ml = constraints["max_length"]
            if len(value) > ml:
                return (
                    f"String length violation: {param} length={len(value)}"
                    f" exceeds max_length={ml}"
                )

        if "allowed_values" in constraints:
            av = constraints["allowed_values"]
            if value not in av:
                return f"Enum violation: {param}={value} not in allowed_values"

    return None


def _log_mcp_gateway_audit(
    server_id: str,
    tool_name: str,
    role: Optional[str],
    action: str,
    matched_rule: str,
    reason: str,
    arguments: dict,
    blocked_by: str,
    principal_id: str = "",
) -> Dict[str, Any]:
    return db.log_mcp_audit_event(
        {
            "server_id": server_id,
            "tool_name": tool_name,
            "role": role or "unspecified",
            "principal_id": principal_id,
            "action": action,
            "matched_rule": matched_rule,
            "reason": reason,
            "effects": [],
            "side_effect": "unknown",
            "data_classes": [],
            "externality": "unknown",
            "verification_level": "unknown",
            "confidence": 0.0,
            "warnings": [],
            "argument_keys": sorted((arguments or {}).keys()),
            "argument_hash": drift_evidence.arguments_hash(arguments or {}),
            "blocked_by": blocked_by,
            "scan_time_ms": _elapsed_ms(),
        }
    )


# ── MCP Server Registration ───────────────────────────────────────────────────
def register_mcp_server(server_id: str, config: dict) -> dict:
    """Register a new MCP server in the persistent DB registry."""
    import logging as _logging

    _logger = _logging.getLogger("interlock.mcp_gateway")
    _begin_op()
    try:
        config = dict(config)
        config.update(_normalize_upstream_auth_config(config))
    except UpstreamAuthConfigError as exc:
        return {
            "ok": False,
            "error": "invalid_upstream_auth_config",
            "message": str(exc),
        }

    try:
        ok = db.register_mcp_server(server_id, config)
    except (RuntimeError, ValueError) as exc:
        return {
            "ok": False,
            "error": "registration_rejected",
            "message": str(exc),
        }
    if not ok:
        return {"ok": False, "error": "already_exists"}
    try:
        from core.provenance import evaluate_provenance

        policy = db.load_mcp04_policy()
        server_record = dict(config)
        prov = evaluate_provenance(server_record, policy)
        db.update_mcp_server_provenance(server_id, prov.status)
        _log_mcp_gateway_audit(
            server_id=server_id,
            tool_name="",
            role="system",
            action="provenance_check",
            matched_rule="mcp04_policy",
            reason=prov.reason,
            arguments={},
            blocked_by=(
                "mcp04_policy" if prov.status in ("quarantine", "denied") else ""
            ),
        )
    except Exception:
        _logger.exception("Provenance check failed at registration -- failing open")
    return {"ok": True, "server_id": server_id, "verified": False}


def list_mcp_servers(
    limit: Optional[int] = None, *, demo_visible_only: bool = False
) -> list:
    """List registered MCP servers from the DB."""
    return db.list_mcp_servers(limit=limit, demo_visible_only=demo_visible_only)
