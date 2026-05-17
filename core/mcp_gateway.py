import re
import json
import httpx
from typing import Optional, List, Dict, Any
from datetime import datetime
from models.schemas import ScanResult, ThreatLevel
from core.tool_inspector import inspect_tool_call
from core import db

# ── MCP Server Registry ───────────────────────────────────────────────────────
# Used only as seed data for db.seed_mcp_servers() — never read directly at runtime.
TRUSTED_MCP_SERVERS = {
    "trusted-filesystem": {
        "url": "http://localhost:3000/mcp",
        "description": "Sandboxed file system access",
        "allowed_tools": ["read_file", "list_directory"],
        "blocked_tools": ["write_file", "delete_file", "execute"],
        "rate_limit": 60,
        "verified": True,
    },
    "trusted-search": {
        "url": "http://localhost:3001/mcp",
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
    r".*\.\.\/.*",                               # path traversal in name
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
    "command", "shell_cmd", "exec_command",
    "raw_query", "raw_sql", "system_call",
    "code_to_run", "script_content",
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
                reason=f"Hidden prompt injection detected in tool description.",
                original_prompt=f"Tool: {name}",
                safe_to_proceed=False,
                confidence=0.99,
                layer_caught="MCP Gateway — Tool Validator",
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
    )

# ── MCP Server Discovery ──────────────────────────────────────────────────────
async def discover_mcp_tools(server_url: str, timeout: float = 10.0) -> Dict[str, Any]:
    """
    Connect to an MCP server and discover its tools.
    Validates every tool definition before returning.
    """
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            payload = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/list",
                "params": {}
            }
            resp = await client.post(server_url, json=payload)
            data = resp.json()

            tools = data.get("result", {}).get("tools", [])

            # Validate every tool
            validation_results = []
            safe_tools = []
            blocked_tools = []

            for tool in tools:
                validation = validate_mcp_tool_definition(tool)
                validation_results.append({
                    "tool_name": tool.get("name"),
                    "is_safe": not validation.is_threat,
                    "validation": validation.dict() if hasattr(validation, "dict") else vars(validation),
                })

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
    api_key: Optional[str] = None
) -> Dict[str, Any]:
    """
    Proxy an MCP tool call through the firewall.
    Validates → inspects → routes to MCP server → scans response.
    """
    # 1. Verify server is trusted
    server = db.lookup_mcp_server(server_id)
    if not server:
        return {
            "ok": False,
            "error": "untrusted_mcp_server",
            "message": f"MCP server '{server_id}' is not in the trusted registry. Add it via /mcp/servers endpoint first.",
        }

    if not server.get("verified"):
        return {
            "ok": False,
            "error": "unverified_mcp_server",
            "message": f"MCP server '{server_id}' is registered but not verified. Cannot proxy calls.",
        }

    # 2. Check tool is in allowed list
    allowed = server.get("allowed_tools", [])
    blocked = server.get("blocked_tools", [])

    if blocked and tool_name in blocked:
        return {
            "ok": False,
            "error": "tool_blocked",
            "message": f"Tool '{tool_name}' is in the blocked list for server '{server_id}'.",
        }

    if allowed is not None and (not allowed or tool_name not in allowed):
        return {
            "ok": False,
            "error": "tool_not_allowed",
            "message": f"Tool '{tool_name}' is not in the allowed list for server '{server_id}'. Allowed: {allowed}",
        }

    # 3. Run through standard tool call inspector
    inspection = inspect_tool_call(tool_name, arguments)
    if inspection.is_threat:
        return {
            "ok": False,
            "error": "tool_call_blocked",
            "threat_level": inspection.threat_level.value,
            "threat_type": inspection.threat_type,
            "reason": inspection.reason,
            "confidence": inspection.confidence,
            "layer_caught": inspection.layer_caught,
        }

    # 4. RBAC check if role provided
    if role:
        from core.policy import rbac_scan
        rbac_result = rbac_scan(json.dumps(arguments), tool_name, role)
        if rbac_result and rbac_result.is_threat:
            return {
                "ok": False,
                "error": "rbac_violation",
                "threat_level": rbac_result.threat_level.value,
                "threat_type": rbac_result.threat_type,
                "reason": rbac_result.reason,
                "confidence": rbac_result.confidence,
            }

    # 5. Forward to actual MCP server
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            payload = {
                "jsonrpc": "2.0",
                "id": int(datetime.utcnow().timestamp()),
                "method": "tools/call",
                "params": {
                    "name": tool_name,
                    "arguments": arguments
                }
            }
            resp = await client.post(server["url"], json=payload)
            data = resp.json()

            # 6. Scan the response for data leaks
            response_text = json.dumps(data)
            from core.detector import PII_PATTERNS
            for pattern in PII_PATTERNS:
                if re.search(pattern, response_text):
                    return {
                        "ok": False,
                        "error": "response_data_leak",
                        "message": "MCP server response contains sensitive data (PII detected). Blocked.",
                        "blocked_response": True,
                    }

            return {
                "ok": True,
                "server_id": server_id,
                "tool_name": tool_name,
                "result": data.get("result"),
                "scanned": True,
            }

    except httpx.TimeoutException:
        return {"ok": False, "error": "mcp_server_timeout"}
    except Exception as e:
        return {"ok": False, "error": "mcp_server_error", "message": str(e)[:200]}

# ── MCP Server Registration ───────────────────────────────────────────────────
def register_mcp_server(server_id: str, config: dict) -> dict:
    """Register a new MCP server in the persistent DB registry."""
    ok = db.register_mcp_server(server_id, config)
    if not ok:
        return {"ok": False, "error": "already_exists"}
    return {"ok": True, "server_id": server_id, "verified": False}

def list_mcp_servers() -> list:
    """List all registered MCP servers from the DB."""
    return db.list_mcp_servers()