import re
import json
import httpx
from typing import Optional, Dict, Any
from datetime import datetime, timezone
from models.schemas import ScanResult, ThreatLevel
from core.metadata_policy import evaluate_metadata_policy
from core.tool_inspector import inspect_tool_call
from core.tool_metadata import normalize_tool_metadata
from core import db
from core.response_scanner import scan_injection, scan_pii_and_volume

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

# ── MCP Tool Definition Validation ────────────────────────────────────────────
SUSPICIOUS_TOOL_NAMES = [
    r"^(execute|eval|run)_?\w*$",
    r"^(delete|drop|truncate|wipe)_?\w*$",
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
    metadata = normalize_tool_metadata(tool)
    name = tool.get("name", "").lower()
    description = tool.get("description", "").lower()
    schema = tool.get("inputSchema", {}) or tool.get("input_schema", {})

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
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            payload = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
            resp = await client.post(server_url, json=payload)
            data = resp.json()

            tools = data.get("result", {}).get("tools", [])

            # Validate every tool
            validation_results = []
            safe_tools = []
            blocked_tools = []

            registry_server_id = server_id
            if not registry_server_id:
                registered = db.lookup_mcp_server_by_url(server_url)
                registry_server_id = registered.get("server_id") if registered else None

            for tool in tools:
                validation = validate_mcp_tool_definition(tool)
                registry = {"persisted": False, "reason": "server_id_not_registered"}
                if registry_server_id and not validation.is_threat:
                    registry = db.upsert_mcp_tool_metadata(
                        registry_server_id,
                        tool,
                        validation.tool_metadata or {},
                    )
                    registry["persisted"] = True
                validation_results.append(
                    {
                        "tool_name": tool.get("name"),
                        "is_safe": not validation.is_threat,
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
    api_key: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Proxy an MCP tool call through the firewall.
    Validates → inspects → routes to MCP server → scans response.
    """
    # 1. Verify server is trusted
    server = db.lookup_mcp_server(server_id)
    if not server:
        _log_mcp_gateway_audit(
            server_id=server_id,
            tool_name=tool_name,
            role=role,
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
        }

    if not server.get("verified"):
        _log_mcp_gateway_audit(
            server_id=server_id,
            tool_name=tool_name,
            role=role,
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
        }

    # Fetch per-key volume thresholds for the response scanner (O(1) hash lookup).
    key_config = (db.lookup_key(api_key) or {}) if api_key else {}

    # 2. Check tool is in allowed list
    allowed = server.get("allowed_tools", [])
    blocked = server.get("blocked_tools", [])

    if blocked and tool_name in blocked:
        _log_mcp_gateway_audit(
            server_id=server_id,
            tool_name=tool_name,
            role=role,
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
        }

    if allowed is not None and (not allowed or tool_name not in allowed):
        _log_mcp_gateway_audit(
            server_id=server_id,
            tool_name=tool_name,
            role=role,
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
    _attach_drift_context(policy_decision, drift_context)

    if drift_context and drift_context["action"] == "quarantine":
        reason = _drift_reason(
            drift_context,
            "Stored MCP tool metadata drift is critical; the tool is quarantined until reviewed.",
        )
        _set_policy_decision(policy_decision, "deny", "tool_quarantined", reason)
        _log_mcp_policy_audit(policy_decision, blocked_by="tool_quarantined")
        return {
            "ok": False,
            "error": "tool_quarantined",
            "message": reason,
            "drift": drift_context,
            "policy_decision": policy_decision,
        }

    if drift_context and drift_context["action"] == "deny":
        reason = _drift_reason(
            drift_context,
            "Stored MCP tool metadata drift is high risk; blocking execution until reviewed.",
        )
        _set_policy_decision(policy_decision, "deny", "tool_metadata_drift", reason)
        _log_mcp_policy_audit(policy_decision, blocked_by="metadata_drift")
        return {
            "ok": False,
            "error": "metadata_drift_violation",
            "message": reason,
            "drift": drift_context,
            "policy_decision": policy_decision,
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
        _log_mcp_policy_audit(policy_decision, blocked_by="metadata_policy")
        return {
            "ok": False,
            "error": "metadata_policy_violation",
            "message": policy_decision["reason"],
            "policy_decision": policy_decision,
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

    # 4b. Provenance check (MCP04) — re-evaluate on every call to catch silent substitutions
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

    # 5. Forward to actual MCP server
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            payload = {
                "jsonrpc": "2.0",
                "id": int(datetime.now(timezone.utc).timestamp()),
                "method": "tools/call",
                "params": {"name": tool_name, "arguments": arguments},
            }
            resp = await client.post(server["url"], json=payload)
            data = resp.json()

            # 6. Scan the response — MCP06 (injection) then MCP10 (PII + volume).
            response_text = json.dumps(data)

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

            pii_result = scan_pii_and_volume(
                response_text,
                max_bytes=key_config.get("max_response_bytes", 50_000),
                max_items=key_config.get("max_array_items", 500),
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

            if pii_result.is_threat and pii_result.sanitized_content is not None:
                effective_result = pii_result.sanitized_content
            else:
                effective_result = response_text

            _log_mcp_policy_audit(policy_decision, blocked_by="")
            return {
                "ok": True,
                "server_id": server_id,
                "tool_name": tool_name,
                "result": json.loads(effective_result).get("result"),
                "scanned": True,
                "threat_flags": (
                    [pii_result.threat_type] if pii_result.is_threat else []
                ),
                "redactions": pii_result.redactions,
                "drift": drift_context,
                "policy_decision": policy_decision,
            }

    except httpx.TimeoutException:
        _log_mcp_policy_audit(policy_decision, blocked_by="mcp_timeout")
        return {"ok": False, "error": "mcp_server_timeout"}
    except Exception as e:
        _log_mcp_policy_audit(policy_decision, blocked_by="mcp_server_error")
        return {"ok": False, "error": "mcp_server_error", "message": str(e)[:200]}


def _log_mcp_policy_audit(
    policy_decision: Dict[str, Any],
    blocked_by: str = "",
    extra: Optional[Dict[str, Any]] = None,
) -> None:
    audit = dict(policy_decision.get("audit_context") or {})
    audit["action"] = audit.get("decision") or policy_decision.get("action", "")
    audit["blocked_by"] = blocked_by
    if extra:
        audit.update(extra)
    db.log_mcp_audit_event(audit)


def _stored_tool_drift_context(
    stored_tool: Optional[Dict[str, Any]],
) -> Optional[Dict[str, Any]]:
    if not stored_tool:
        return None

    status = stored_tool.get("status") or "active"
    severity = stored_tool.get("drift_severity") or "none"
    action = stored_tool.get("drift_action") or "allow"
    if status == "quarantined":
        action = "quarantine"
        if severity == "none":
            severity = "critical"
    elif status == "changed" and action == "allow":
        action = "monitor"
        if severity == "none":
            severity = "minor"

    if status == "active" and severity == "none" and action == "allow":
        return None

    return {
        "status": status,
        "severity": severity,
        "action": action,
        "types": list(stored_tool.get("drift_types") or []),
        "reasons": list(stored_tool.get("drift_reasons") or []),
        "last_changed": stored_tool.get("last_changed"),
        "previous_schema_hash": stored_tool.get("previous_schema_hash"),
        "current_schema_hash": stored_tool.get("tool_schema_hash"),
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


def _log_mcp_gateway_audit(
    server_id: str,
    tool_name: str,
    role: Optional[str],
    action: str,
    matched_rule: str,
    reason: str,
    arguments: dict,
    blocked_by: str,
) -> None:
    db.log_mcp_audit_event(
        {
            "server_id": server_id,
            "tool_name": tool_name,
            "role": role or "unspecified",
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
            "blocked_by": blocked_by,
        }
    )


# ── MCP Server Registration ───────────────────────────────────────────────────
def register_mcp_server(server_id: str, config: dict) -> dict:
    """Register a new MCP server in the persistent DB registry."""
    import logging as _logging

    _logger = _logging.getLogger("interlock.mcp_gateway")
    ok = db.register_mcp_server(server_id, config)
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


def list_mcp_servers() -> list:
    """List all registered MCP servers from the DB."""
    return db.list_mcp_servers()
