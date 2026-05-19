"""
Metadata-aware runtime policy decisions for MCP tool calls.

This layer turns normalized tool metadata into an allow/deny/monitor decision.
It stays separate from transport code so policy logic can be tested and audited
without standing up an MCP server.
"""

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


ALLOW = "allow"
DENY = "deny"
MONITOR = "monitor"


@dataclass
class PolicyDecision:
    action: str
    reason: str
    matched_rule: str
    tool_metadata: Dict[str, Any]
    warnings: List[str] = field(default_factory=list)
    audit_context: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def evaluate_metadata_policy(
    server_id: str,
    tool_name: str,
    arguments: dict,
    role: Optional[str],
    tool_metadata: Dict[str, Any],
) -> Dict[str, Any]:
    """Evaluate default metadata policy rules for one MCP tool call."""
    metadata = tool_metadata or {}
    effects = set(metadata.get("effects") or [])
    side_effect = metadata.get("side_effect") or "unknown"
    data_classes = set(metadata.get("data_classes") or [])
    externality = metadata.get("externality") or "unknown"
    verification_level = metadata.get("verification_level") or "unknown"
    confidence = float(metadata.get("confidence") or 0.0)
    warnings = list(metadata.get("warnings") or [])
    normalized_role = role or "unspecified"

    if normalized_role == "readonly_agent" and (side_effect != "read_only" or effects - {"read"}):
        return _decision(
            DENY,
            "readonly_agent may only use read-only tools; this tool is classified as "
            f"{side_effect} with effects {sorted(effects)}.",
            "readonly_agent_read_only",
            server_id,
            tool_name,
            normalized_role,
            arguments,
            metadata,
            warnings,
        )

    if side_effect == "destructive" and normalized_role != "admin_agent":
        return _decision(
            DENY,
            "Destructive tools require admin_agent.",
            "destructive_requires_admin",
            server_id,
            tool_name,
            normalized_role,
            arguments,
            metadata,
            warnings,
        )

    if effects.intersection({"execute"}) and normalized_role not in {"devops_agent", "admin_agent"}:
        return _decision(
            DENY,
            "Execute-class tools require devops_agent or admin_agent.",
            "execute_requires_privileged_role",
            server_id,
            tool_name,
            normalized_role,
            arguments,
            metadata,
            warnings,
        )

    if (
        normalized_role == "finance_agent"
        and externality == "external"
        and effects.intersection({"share", "export", "message"})
    ):
        return _decision(
            DENY,
            "finance_agent cannot perform external share/export/message actions by default.",
            "finance_external_transfer",
            server_id,
            tool_name,
            normalized_role,
            arguments,
            metadata,
            warnings,
        )

    if externality == "external" and "secrets" in data_classes and normalized_role != "admin_agent":
        return _decision(
            DENY,
            "External transfer of secrets is denied for non-admin roles.",
            "no_external_secrets",
            server_id,
            tool_name,
            normalized_role,
            arguments,
            metadata,
            warnings,
        )

    if externality == "external" and data_classes.intersection({"phi"}) and normalized_role not in {"admin_agent"}:
        return _decision(
            DENY,
            "External transfer of PHI requires admin_agent until an explicit approval workflow exists.",
            "no_external_phi_without_admin",
            server_id,
            tool_name,
            normalized_role,
            arguments,
            metadata,
            warnings,
        )

    if verification_level == "heuristic" and confidence < 0.7:
        return _decision(
            MONITOR,
            "Tool metadata was inferred with low confidence; allow but monitor this call.",
            "low_confidence_heuristic",
            server_id,
            tool_name,
            normalized_role,
            arguments,
            metadata,
            warnings,
        )

    if any("conflict" in warning.lower() or "marked read_only" in warning.lower() for warning in warnings):
        return _decision(
            MONITOR,
            "Tool metadata contains mismatch warnings; allow but monitor this call.",
            "metadata_mismatch",
            server_id,
            tool_name,
            normalized_role,
            arguments,
            metadata,
            warnings,
        )

    return _decision(
        ALLOW,
        "No metadata policy rule denied or elevated this tool call.",
        "default_allow",
        server_id,
        tool_name,
        normalized_role,
        arguments,
        metadata,
        warnings,
    )


def _decision(
    action: str,
    reason: str,
    matched_rule: str,
    server_id: str,
    tool_name: str,
    role: str,
    arguments: dict,
    metadata: Dict[str, Any],
    warnings: List[str],
) -> Dict[str, Any]:
    audit_context = {
        "server_id": server_id,
        "tool_name": tool_name,
        "role": role,
        "effects": metadata.get("effects") or [],
        "side_effect": metadata.get("side_effect") or "unknown",
        "data_classes": metadata.get("data_classes") or [],
        "externality": metadata.get("externality") or "unknown",
        "verification_level": metadata.get("verification_level") or "unknown",
        "confidence": metadata.get("confidence") or 0.0,
        "decision": action,
        "reason": reason,
        "matched_rule": matched_rule,
        "warnings": warnings,
        "argument_keys": sorted((arguments or {}).keys()),
    }
    return PolicyDecision(
        action=action,
        reason=reason,
        matched_rule=matched_rule,
        tool_metadata=metadata,
        warnings=warnings,
        audit_context=audit_context,
    ).to_dict()
