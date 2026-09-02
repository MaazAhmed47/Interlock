"""Immutable acceptance-case registry for the Kubernetes enforcement lab."""

from dataclasses import dataclass


@dataclass(frozen=True)
class ExpectedCase:
    expected_result: str
    source_workload: str
    destination_class: str
    enforcement_layer: str
    failure_category: str


REQUIRED_CASES: dict[str, ExpectedCase] = {
    "KE-001": ExpectedCase(
        "allowed",
        "agent",
        "interlock_gateway_mediated_mcp",
        "interlock_gateway",
        "none",
    ),
    "KE-002": ExpectedCase(
        "network_denied",
        "agent",
        "mcp_service_direct",
        "calico_network_policy",
        "connect_timeout",
    ),
    "KE-003": ExpectedCase(
        "network_denied",
        "agent",
        "mcp_pod_direct",
        "calico_network_policy",
        "connect_timeout",
    ),
    "KE-004": ExpectedCase(
        "network_denied",
        "agent",
        "mcp_namespace_fqdn_direct",
        "calico_network_policy",
        "connect_timeout",
    ),
    "KE-005": ExpectedCase(
        "network_denied",
        "unrelated",
        "mcp_service_direct",
        "calico_network_policy",
        "connect_timeout",
    ),
    "KE-006": ExpectedCase(
        "allowed",
        "interlock_gateway",
        "mcp_service",
        "calico_network_policy",
        "none",
    ),
    "KE-007": ExpectedCase(
        "verifier_rejected",
        "lab_controller",
        "mutated_evidence",
        "evidence_verifier",
        "result_mismatch",
    ),
    "KE-008": ExpectedCase(
        "allowed",
        "agent",
        "mcp_service_without_policy",
        "policy_negative_control",
        "none",
    ),
    "KE-009": ExpectedCase(
        "resolved",
        "agent",
        "cluster_dns",
        "coredns",
        "none",
    ),
    "KE-010": ExpectedCase(
        "network_denied",
        "agent_httpx",
        "mcp_service_direct",
        "calico_network_policy",
        "connect_timeout",
    ),
    "KE-011": ExpectedCase(
        "network_denied",
        "agent_requests",
        "mcp_service_direct",
        "calico_network_policy",
        "connect_timeout",
    ),
    "KE-012": ExpectedCase(
        "network_denied",
        "agent_urllib",
        "mcp_service_direct",
        "calico_network_policy",
        "connect_timeout",
    ),
    "KE-013": ExpectedCase(
        "network_denied",
        "agent_raw_socket",
        "mcp_service_direct",
        "calico_network_policy",
        "connect_timeout",
    ),
    "KE-014": ExpectedCase(
        "network_denied",
        "agent_curl",
        "mcp_service_direct",
        "calico_network_policy",
        "connect_timeout",
    ),
    "KE-015": ExpectedCase(
        "gateway_unavailable_no_fallback",
        "agent",
        "interlock_gateway",
        "agent_client",
        "gateway_unavailable",
    ),
    "KE-016": ExpectedCase(
        "network_denied",
        "agent",
        "mcp_service_after_policy_restore",
        "calico_network_policy",
        "connect_timeout",
    ),
    "KE-017": ExpectedCase(
        "verified",
        "agent",
        "interlock_audit_receipt",
        "interlock_audit_chain",
        "none",
    ),
    "KE-018": ExpectedCase(
        "allowed",
        "agent",
        "mcp_pod_without_policy",
        "policy_negative_control",
        "none",
    ),
}
