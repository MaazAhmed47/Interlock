# McpSecurityReceipt Draft v0.1

Status: discussion draft  
Author: Interlock  
Goal: shared evidence envelope for MCP runtime security

## Purpose

MCP servers, hosts, and gateways are starting to split security responsibility across different layers:

- The MCP spec defines identity, OAuth/scopes, consent, sampling, and elicitation.
- Hosts can provide user approval and local allow/deny controls.
- Servers can expose scoped tools, coarse safety modes, and tool-call evidence.
- Gateways can enforce cross-server policy, inspect arguments and responses, run shadow mode, aggregate audit logs, and send events to SIEM or review workflows.

This draft proposes a minimal receipt envelope that lets MCP servers emit structured evidence and lets gateways like Interlock reference that evidence when making runtime decisions.

The goal is not to make every MCP server a policy engine. The goal is to make server-side evidence stable enough that a gateway can consume, correlate, enforce, and audit it without re-deriving everything from tool names and raw payloads.

## Design Principle

Server emits evidence. Gateway makes cross-server decisions. Audit log links both.

```text
MCP Server Receipt
     |
     v
Interlock Gateway Decision
     |
     v
Audit Log / SIEM / Shadow Mode / Review Queue
```

The key lineage should be:

```text
server_receipt_id -> gateway_decision_id -> audit_event_id
```

## Non-Goals

This draft does not try to define:

- A full policy language.
- A UI format.
- A replacement for OAuth scopes.
- A replacement for host-level approval.
- A server-specific authorization model.
- A guarantee that server-provided metadata is trusted policy truth.

Gateway policy should still treat receipts as evidence, not as final authority.

## Receipt Types

This draft separates two related records:

1. `McpSecurityReceipt`: emitted by an MCP server or host boundary.
2. `GatewayDecisionReceipt`: emitted by a gateway such as Interlock.

The gateway receipt references the server receipt instead of duplicating or rewriting the server's evidence.

## McpSecurityReceipt

### Required Fields

```json
{
  "receipt_id": "mcp_rcpt_01HV...",
  "schema_version": "0.1",
  "issued_at": "2026-05-19T08:15:30Z",
  "server_id": "roam-code-local",
  "tool_name": "apply_patch",
  "tool_call_id": "call_01HV...",
  "client_id": "claude-code",
  "actor_ref_id": "user_123",
  "run_id": "run_01HV...",
  "run_event_id": "event_42"
}
```

### Identity and Correlation

These fields let a gateway connect one tool call to a user, client, run, and server.

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `receipt_id` | string | yes | Unique receipt identifier. |
| `schema_version` | string | yes | Receipt schema version. |
| `issued_at` | string | yes | RFC 3339 timestamp. |
| `server_id` | string | yes | Stable MCP server identifier. |
| `tool_name` | string | yes | MCP tool name. |
| `tool_call_id` | string | yes | Unique tool-call identifier if available. |
| `client_id` | string | recommended | MCP client or host identifier. |
| `actor_ref_id` | string | recommended | User, service account, or actor reference. |
| `session_id` | string | optional | Session identifier. |
| `run_id` | string | recommended | Agent run identifier. |
| `run_event_id` | string | recommended | Event identifier within a run. |

### Tool Intent

These fields describe what the server believes the tool is capable of doing.

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `declared_side_effects` | string[] | recommended | Effects such as `read`, `write`, `delete`, `execute`, `share`, `export`, `message`. |
| `side_effect` | string | recommended | Summary severity, such as `read_only`, `mutating`, `destructive`. |
| `data_classes` | string[] | recommended | Data classes such as `internal`, `pii`, `secrets`, `financial`, `source_code`. |
| `externality` | string | recommended | `internal`, `external`, or `third_party`. |
| `required_scopes` | string[] | optional | Server or OAuth scopes required by the tool. |
| `mode` | string | optional | Runtime mode, such as `read_only`, `safe_edit`, `migration`, `autonomous_pr`. |
| `tool_schema_hash` | string | recommended | Hash of canonical tool input schema. |
| `tool_description_hash` | string | optional | Hash of canonical tool description. |

### Input and Output Evidence

These fields allow audit and verification without requiring raw sensitive payloads to be copied into every system.

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `input_hash` | string | recommended | SHA-256 hash of canonical JSON input. |
| `argument_keys` | string[] | recommended | Top-level argument keys used in the call. |
| `input_ref` | string | optional | Reference to stored input evidence, if available. |
| `output_hash` | string | optional | SHA-256 hash of canonical output. |
| `output_ref` | string | optional | Reference to stored output evidence, if available. |
| `redactions` | object[] | recommended | Redaction records applied to input or output. |

Example redaction record:

```json
{
  "field": "output.text",
  "class": "secret",
  "method": "pattern",
  "replacement": "[REDACTED_SECRET]"
}
```

### Server Decision Context

These fields describe any decision the server or host already made before the gateway sees the event.

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `policy_decision` | string | optional | `allow`, `deny`, `monitor`, `redact`, `quarantine`, or `unknown`. |
| `policy_reason` | string | optional | Human-readable reason. |
| `matched_rule` | string | optional | Server-side rule or mode that matched. |
| `policy_version` | string | optional | Server policy version. |
| `override_used` | boolean | optional | Whether a local override was used. |
| `shadow_mode` | boolean | optional | Whether decision was observed but not enforced. |

### Verification

These fields let a gateway and later auditor check whether the receipt is trustworthy and whether the run ledger was tampered with.

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `receipt_signature` | string | optional | Signature or HMAC over canonical receipt content. |
| `signature_alg` | string | optional | Algorithm identifier. |
| `ledger_id` | string | optional | Run ledger identifier. |
| `ledger_seq` | integer | optional | Receipt sequence number in ledger. |
| `previous_hash` | string | optional | Previous ledger entry hash. |
| `verification_status` | string | optional | `ok`, `unsigned`, `tampered`, `empty`, or `unknown`. |

## GatewayDecisionReceipt

The gateway creates its own receipt after applying cross-server policy, argument inspection, response scanning, drift checks, and audit rules.

```json
{
  "gateway_decision_id": "gw_dec_01HV...",
  "schema_version": "0.1",
  "issued_at": "2026-05-19T08:15:31Z",
  "server_receipt_id": "mcp_rcpt_01HV...",
  "gateway_id": "interlock-prod",
  "server_id": "roam-code-local",
  "tool_name": "apply_patch",
  "actor_ref_id": "user_123",
  "role": "readonly_agent",
  "action": "deny",
  "matched_rule": "readonly_agent_no_mutating_tools",
  "reason": "readonly_agent cannot call tools with declared write side effects",
  "shadow_mode": false,
  "audit_event_id": "audit_01HV..."
}
```

### Gateway Decision Fields

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `gateway_decision_id` | string | yes | Unique gateway decision identifier. |
| `schema_version` | string | yes | Gateway receipt schema version. |
| `issued_at` | string | yes | RFC 3339 timestamp. |
| `server_receipt_id` | string | recommended | Referenced MCP server receipt. |
| `gateway_id` | string | recommended | Gateway instance identifier. |
| `server_id` | string | yes | MCP server identifier. |
| `tool_name` | string | yes | MCP tool name. |
| `actor_ref_id` | string | recommended | Actor reference used by gateway policy. |
| `role` | string | recommended | Gateway role or persona, such as `readonly_agent`. |
| `action` | string | yes | `allow`, `deny`, `monitor`, `quarantine`, or `redact`. |
| `matched_rule` | string | optional | Gateway policy rule that matched. |
| `reason` | string | recommended | Human-readable reason. |
| `policy_version` | string | optional | Gateway policy version. |
| `metadata_confidence` | number | optional | Gateway confidence in normalized metadata. |
| `warnings` | string[] | optional | Metadata, drift, receipt, or scan warnings. |
| `argument_scan_result` | object | optional | Summary of argument inspection. |
| `response_scan_result` | object | optional | Summary of response scanning. |
| `drift_result` | object | optional | Baseline drift result, if applicable. |
| `shadow_mode` | boolean | optional | Whether the decision was observed only. |
| `audit_event_id` | string | recommended | Linked audit event. |

## Example Flow

### Scenario

An MCP tool was previously read-only. A later version adds external sharing capability. The server emits a receipt that declares the tool's side effects and evidence hashes. Interlock compares the tool against its stored baseline, detects risky drift, quarantines the tool, and writes a gateway decision that references the original server receipt.

### Server Receipt

```json
{
  "receipt_id": "mcp_rcpt_roam_0001",
  "schema_version": "0.1",
  "issued_at": "2026-05-19T08:15:30Z",
  "server_id": "roam-code-local",
  "tool_name": "publish_artifact",
  "tool_call_id": "call_0001",
  "client_id": "claude-code",
  "actor_ref_id": "user_maaz",
  "run_id": "run_20260519_001",
  "run_event_id": "event_0042",
  "declared_side_effects": ["read", "export", "share"],
  "side_effect": "mutating",
  "data_classes": ["source_code", "internal"],
  "externality": "external",
  "required_scopes": ["repo.read", "artifact.write", "external.share"],
  "mode": "safe_edit",
  "tool_schema_hash": "sha256:9d3c...",
  "input_hash": "sha256:1a7b...",
  "argument_keys": ["path", "destination", "visibility"],
  "output_hash": "sha256:49cc...",
  "redactions": [],
  "policy_decision": "allow",
  "policy_reason": "safe_edit mode permits artifact publishing",
  "matched_rule": "safe_edit_publish_artifact",
  "policy_version": "roam-policy-2026-05-19",
  "override_used": false,
  "shadow_mode": false,
  "ledger_id": "roam_run_20260519_001",
  "ledger_seq": 42,
  "previous_hash": "sha256:abc1...",
  "verification_status": "ok"
}
```

### Gateway Decision Receipt

```json
{
  "gateway_decision_id": "gw_dec_interlock_0001",
  "schema_version": "0.1",
  "issued_at": "2026-05-19T08:15:31Z",
  "server_receipt_id": "mcp_rcpt_roam_0001",
  "gateway_id": "interlock-local",
  "server_id": "roam-code-local",
  "tool_name": "publish_artifact",
  "actor_ref_id": "user_maaz",
  "role": "developer_agent",
  "action": "quarantine",
  "matched_rule": "high_risk_externality_drift",
  "reason": "Tool added external share/export capability compared with stored baseline",
  "policy_version": "interlock-policy-0.1",
  "metadata_confidence": 0.91,
  "warnings": ["tool capability drift detected", "external sharing added"],
  "argument_scan_result": {
    "status": "pass",
    "argument_keys": ["path", "destination", "visibility"]
  },
  "response_scan_result": {
    "status": "not_run",
    "reason": "tool call quarantined before execution"
  },
  "drift_result": {
    "severity": "critical",
    "action": "quarantine",
    "changes": ["externality_changed_to_external", "effect_added_share", "scope_added_external_share"]
  },
  "shadow_mode": false,
  "audit_event_id": "audit_interlock_0001"
}
```

## Why This Helps Gateways

With this receipt model, a gateway can:

- Avoid guessing tool intent only from names and descriptions.
- Correlate tool calls across multiple MCP servers.
- Link server-side evidence to gateway-side enforcement.
- Preserve input/output evidence without always storing raw payloads.
- Run shadow mode and compare what would have been blocked.
- Detect drift between discovered baselines and runtime behavior.
- Produce auditable allow, deny, monitor, redact, and quarantine events.

## Output Sanitization Use Case

Response scanning is a strong gateway-owned use case because correct identity and scopes do not prevent malicious or sensitive data from crossing the boundary in tool output.

Example:

```text
1. Server emits McpSecurityReceipt with output_hash/output_ref.
2. Gateway retrieves or observes output.
3. Gateway response scanner detects token-like data or prompt-injection content.
4. Gateway redacts, denies, monitors, or quarantines the response.
5. GatewayDecisionReceipt references the original server receipt.
6. Audit log shows both the server evidence and gateway decision.
```

This keeps the server responsible for emitting evidence and keeps the gateway responsible for cross-server output policy and audit aggregation.

## Open Questions

1. Should `McpSecurityReceipt` be emitted before execution, after execution, or both?
2. Should receipt signing be required, recommended, or left to high-assurance servers?
3. Should `declared_side_effects` use a fixed vocabulary?
4. Should `data_classes` use a fixed vocabulary or allow vendor-specific extensions?
5. How should gateways handle missing, unsigned, or conflicting server receipts?
6. Should shadow-mode decisions live in the server receipt, gateway receipt, or both?
7. Should output references be pull-based, push-based, or implementation-specific?

## Proposed Minimal Vocabulary

### Actions

- `allow`
- `deny`
- `monitor`
- `redact`
- `quarantine`

### Effects

- `read`
- `write`
- `delete`
- `execute`
- `share`
- `export`
- `message`
- `network`

### Side Effect Severity

- `read_only`
- `mutating`
- `destructive`

### Externality

- `internal`
- `external`
- `third_party`

### Verification Status

- `ok`
- `unsigned`
- `tampered`
- `empty`
- `unknown`

## Next Step

Compare this draft with existing `McpDecisionReceipt` implementations and reduce it to the smallest stable envelope that servers and gateways can both support.

The immediate integration target for Interlock would be:

```text
Consume server receipt -> normalize metadata -> apply gateway policy -> scan response -> write gateway decision -> link audit event
```
