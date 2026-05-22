from models.schemas import ScanResult, ThreatLevel
from typing import Optional
from core import db

def policy_scan(prompt: str, api_key: str) -> Optional[ScanResult]:
    record = db.lookup_key(api_key)
    policy = (record or {}).get("custom_policy")
    if not policy:
        return None

    prompt_lower = prompt.lower()

    for keyword in policy.get("blocked_keywords", []):
        if keyword.lower() in prompt_lower:
            return ScanResult(
                is_threat=True,
                threat_level=ThreatLevel.MEDIUM,
                threat_type="CUSTOM_POLICY_VIOLATION",
                reason=f"Blocked keyword detected: '{keyword}' (custom policy)",
                original_prompt=prompt,
                safe_to_proceed=False,
                confidence=0.99,
                layer_caught="Custom Policy Engine",
            )

    max_len = policy.get("max_prompt_length", 4000)
    if len(prompt) > max_len:
        return ScanResult(
            is_threat=True,
            threat_level=ThreatLevel.LOW,
            threat_type="CUSTOM_POLICY_VIOLATION",
            reason=f"Prompt exceeds your custom limit of {max_len} characters.",
            original_prompt=prompt,
            safe_to_proceed=False,
            confidence=0.99,
            layer_caught="Custom Policy Engine",
        )

    return None


# ── Role-Based Access Control ─────────────────────────────────────────────────
ROLE_POLICIES = {
    "support_agent": {
        "allowed_tools": ["read_crm", "search_knowledge", "send_email", "create_ticket"],
        "blocked_tools": ["delete", "drop", "execute_sql", "run_code", "bash", "shell", "write_file", "admin"],
        "blocked_keywords": ["delete all", "drop table", "admin password", "root access", "sudo", "truncate"],
        "max_prompt_length": 2000,
        "description": "Support agents: CRM read + email only. No deletions or code execution."
    },
    "devops_agent": {
        "allowed_tools": ["deploy", "restart_service", "read_logs", "run_code", "bash", "monitor"],
        "blocked_tools": ["delete_database", "drop_table", "truncate", "delete_production", "rm_rf"],
        "blocked_keywords": ["drop database", "delete production", "rm -rf /", "format c:", "truncate production"],
        "max_prompt_length": 5000,
        "description": "DevOps agents: deploy and manage services. No production data deletion."
    },
    "finance_agent": {
        "allowed_tools": ["read_transactions", "generate_report", "read_ledger", "export_csv"],
        "blocked_tools": ["execute_sql", "delete_record", "run_code", "write_file", "bash", "shell", "modify_record", "update_record"],
        "blocked_keywords": ["delete", "drop", "truncate", "modify", "update", "insert", "alter", "grant", "revoke"],
        "max_prompt_length": 3000,
        "description": "Finance agents: strict read-only. No modifications to financial data."
    },
    "readonly_agent": {
        "allowed_tools": ["read_file", "search", "query", "list", "get", "fetch"],
        "blocked_tools": ["write", "delete", "execute", "run", "bash", "shell", "create", "modify", "update"],
        "blocked_keywords": ["delete", "drop", "truncate", "write", "modify", "insert", "update", "execute", "run"],
        "max_prompt_length": 2000,
        "description": "Read-only access across all systems."
    },
    "data_analyst": {
        "allowed_tools": ["read_database", "run_sql", "export_csv", "generate_report", "visualize"],
        "blocked_tools": ["delete", "drop", "truncate", "write_file", "bash", "execute_python"],
        "blocked_keywords": ["drop table", "delete from", "truncate", "alter table", "grant all"],
        "max_prompt_length": 8000,
        "description": "Data analysts: read + export only. No schema modifications."
    },
    "admin_agent": {
        "allowed_tools": [],  # admins can use any tool
        "blocked_tools": ["format_disk", "wipe_database", "delete_all_users"],
        "blocked_keywords": ["wipe all data", "delete all users", "format production"],
        "max_prompt_length": 10000,
        "description": "Admin agents: full access except catastrophic operations."
    },
}

def rbac_scan(
    prompt: str,
    tool_name: Optional[str],
    role: str,
    api_key: Optional[str] = None
) -> Optional[ScanResult]:
    policy = ROLE_POLICIES.get(role)
    if not policy:
        # Unknown role — block by default
        return ScanResult(
            is_threat=True,
            threat_level=ThreatLevel.HIGH,
            threat_type="UNKNOWN_ROLE",
            reason=f"Role '{role}' is not defined. Access denied by default. Valid roles: {list(ROLE_POLICIES.keys())}",
            original_prompt=prompt,
            safe_to_proceed=False,
            confidence=0.99,
            layer_caught="RBAC Policy Engine",
        )

    prompt_lower = prompt.lower()

    # Check prompt length
    max_len = policy.get("max_prompt_length", 4000)
    if len(prompt) > max_len:
        return ScanResult(
            is_threat=True,
            threat_level=ThreatLevel.LOW,
            threat_type="RBAC_VIOLATION",
            reason=f"Role '{role}' prompt exceeds allowed length ({len(prompt)} > {max_len} chars).",
            original_prompt=prompt,
            safe_to_proceed=False,
            confidence=0.99,
            layer_caught="RBAC Policy Engine",
        )

    # Check blocked tools
    if tool_name:
        tool_lower = tool_name.lower().replace("-", "_").replace(" ", "_")
        for blocked in policy.get("blocked_tools", []):
            if blocked.lower() in tool_lower:
                return ScanResult(
                    is_threat=True,
                    threat_level=ThreatLevel.HIGH,
                    threat_type="RBAC_VIOLATION",
                    reason=f"Role '{role}' is not permitted to use tool '{tool_name}'. {policy['description']}",
                    original_prompt=prompt,
                    safe_to_proceed=False,
                    confidence=0.99,
                    layer_caught="RBAC Policy Engine",
                )

        # Check if tool is in allowed list (if allowed list is specified)
        allowed = policy.get("allowed_tools", [])
        if allowed and role != "admin_agent":
            tool_allowed = any(a.lower() in tool_lower for a in allowed)
            if not tool_allowed:
                return ScanResult(
                    is_threat=True,
                    threat_level=ThreatLevel.MEDIUM,
                    threat_type="RBAC_VIOLATION",
                    reason=f"Role '{role}' is not in the allowed tools list for '{tool_name}'. Allowed: {allowed}",
                    original_prompt=prompt,
                    safe_to_proceed=False,
                    confidence=0.95,
                    layer_caught="RBAC Policy Engine",
                )

    # Check blocked keywords
    for keyword in policy.get("blocked_keywords", []):
        if keyword.lower() in prompt_lower:
            return ScanResult(
                is_threat=True,
                threat_level=ThreatLevel.HIGH,
                threat_type="RBAC_VIOLATION",
                reason=f"Role '{role}' attempted restricted action containing '{keyword}'. {policy['description']}",
                original_prompt=prompt,
                safe_to_proceed=False,
                confidence=0.97,
                layer_caught="RBAC Policy Engine",
            )

    return None