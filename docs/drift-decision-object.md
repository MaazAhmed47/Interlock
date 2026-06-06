# Drift Decision Object

Status: public product draft  
Scope: Interlock runtime-security profile  
Audience: MCP builders, gateway authors, policy engines, and design partners

## Purpose

The Drift Decision Object is Interlock's compact runtime signal for one question:

```text
Is this still the tool we approved?
```

Static policy answers whether a known call is allowed. The Drift Decision Object answers whether the tool being governed has changed since approval in a way that should affect trust.

This object is designed to be consumed by agent gateways, policy engines, review queues, SIEM pipelines, and audit receipt systems.

## Design Rules

- Keep core status small.
- Treat quarantine as profile-layer semantics, not a core status.
- Map enforced quarantine to `denied` when execution is terminally blocked.
- Map hold-for-review quarantine to `deferred` when execution pauses pending re-approval.
- Keep exact scoring weights private while Interlock is validating with operators.
- Expose reasons, evidence, and recommended action clearly enough for integration.

## Example

```json
{
  "schema_version": "0.1",
  "decision_id": "drift_dec_01JZ4K2S9QV7KX3H8R7P6D4NQZ",
  "issued_at": "2026-06-06T18:35:00Z",
  "gateway_id": "interlock-demo",
  "server_id": "docs-mcp",
  "tool_name": "read_document",
  "approved_baseline_id": "baseline_docs_mcp_read_document_v1",
  "live_tool_hash": "sha256:9a5f...",
  "baseline_tool_hash": "sha256:17be...",
  "drift_detected": true,
  "drift_status": "quarantined",
  "core_disposition": "denied",
  "terminal": true,
  "severity": "critical",
  "risk_score": 87,
  "reasons": [
    "externality_changed",
    "data_classes_added",
    "effect_escalation"
  ],
  "changes": [
    {
      "field": "effects",
      "before": ["read"],
      "after": ["read", "export"]
    },
    {
      "field": "externality",
      "before": "internal",
      "after": "external"
    },
    {
      "field": "data_classes",
      "before": ["internal"],
      "after": ["internal", "pii"]
    }
  ],
  "recommended_action": "require_review",
  "receipt_id": "rcpt_01JZ4K35VY7D3W2A8C9R0FN6KP"
}
```

## Field Reference

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `schema_version` | string | yes | Version of this object shape. |
| `decision_id` | string | yes | Stable ID for this drift decision. |
| `issued_at` | string | yes | RFC 3339 timestamp. |
| `gateway_id` | string | recommended | Gateway instance or deployment ID. |
| `server_id` | string | yes | MCP server identifier. |
| `tool_name` | string | yes | MCP tool name. |
| `approved_baseline_id` | string | recommended | Baseline used for comparison. |
| `live_tool_hash` | string | recommended | Hash of the canonical live tool definition. |
| `baseline_tool_hash` | string | recommended | Hash of the canonical approved baseline. |
| `drift_detected` | boolean | yes | Whether the live tool differs from baseline. |
| `drift_status` | string | yes | `clean`, `changed`, `review_required`, or `quarantined`. |
| `core_disposition` | string | yes | Maps to `allowed`, `denied`, `deferred`, or `error`. |
| `terminal` | boolean | yes | Whether this decision ends the attempted call path. |
| `severity` | string | recommended | `safe`, `low`, `medium`, `high`, or `critical`. |
| `risk_score` | number | optional | 0 to 100 score for operator sorting. |
| `reasons` | string[] | recommended | Machine-readable reason codes. |
| `changes` | object[] | recommended | Before and after evidence for changed fields. |
| `recommended_action` | string | recommended | `allow`, `monitor`, `require_review`, `approve_new_baseline`, or `keep_quarantined`. |
| `receipt_id` | string | recommended | Security Receipt ID for audit evidence. |

## Reason Codes

Initial reason codes:

```text
description_changed
schema_changed
required_parameters_changed
effect_escalation
data_classes_added
externality_changed
provenance_changed
tool_removed
tool_added
metadata_confidence_low
canonicalization_error
```

Reason codes are intentionally more specific than the core disposition. A gateway can deny or defer a call while still preserving the exact reason the runtime-security profile found it risky.

## Core Disposition Mapping

| Interlock drift state | Core disposition | Terminal | Meaning |
| --- | --- | --- | --- |
| `clean` | `allowed` | true | Tool matches approved baseline and policy allows execution. |
| `changed` | `allowed` or `deferred` | depends | Low-risk drift can be monitored, higher-risk drift can require review. |
| `review_required` | `deferred` | false | Hold execution until a reviewer approves or rejects the new baseline. |
| `quarantined` | `denied` | true | Block execution because drift is too risky to run. |
| `canonicalization_error` | `error` | true | Verifier failed to reach a reliable disposition. |

## Integration Pattern

Policy engines can consume the object as runtime context:

```text
agent request
  -> static policy check
  -> Interlock drift decision
  -> allow, deny, defer, or require review
  -> Security Receipt
```

The useful integration boundary is simple:

```text
Policy decides whether an action is allowed.
Interlock checks whether the tool being governed is still the trusted tool.
```

## Minimal Partner Payload

Partners that do not need the full object can start with this subset:

```json
{
  "server_id": "docs-mcp",
  "tool_name": "read_document",
  "drift_status": "quarantined",
  "core_disposition": "denied",
  "severity": "critical",
  "reasons": ["effect_escalation", "data_classes_added", "externality_changed"],
  "recommended_action": "require_review",
  "receipt_id": "rcpt_01JZ4K35VY7D3W2A8C9R0FN6KP"
}
```

## Current Limitations

- Exact scoring weights are not part of the public object.
- Canonicalization rules may change as MCP audit-record work matures.
- The object is not a replacement for MCP server RBAC, OAuth scopes, or host-level consent.
- Drift decisions are strongest when tools expose stable metadata and schemas.

## Related Docs

- [MCP Security Receipt Draft](mcp-security-receipt-draft.md)
- [MCP Threat Map](mcp-threat-map.md)
- [Production Readiness](production-readiness.md)
- [Enterprise Evaluation](enterprise-evaluation.md)
