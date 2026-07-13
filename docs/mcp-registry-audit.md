# MCP Tool Registry And Audit Log

Interlock persists discovered MCP tool metadata and writes durable audit events for MCP gateway decisions.

## Why This Exists

Runtime enforcement answers what happened during one call. A registry and audit log answer:

- what Interlock knew about a tool before the call
- whether the tool changed after discovery
- which metadata was used for policy
- which rule allowed, denied, or monitored the call
- why the decision was made

This is the control-plane foundation for pilots, incident review, compliance, and future approval workflows.

## Tool Metadata Registry

Discovery can persist normalized metadata per server/tool:

```text
/mcp/discover
-> validate tool definition
-> normalize metadata
-> hash schema and description
-> save per server_id + tool_name
-> classify drift severity when an existing tool changes
-> mark status active, changed, or quarantined
```

Stored fields:

```text
server_id
tool_name
tool_schema_hash
description_hash
normalized_metadata
raw_annotations
raw_tool_definition
first_seen
last_seen
last_changed
status
drift_severity
drift_action
drift_types
drift_reasons
previous_metadata
previous_tool_definition
```

Statuses:

```text
active      - first seen or unchanged
changed     - same server/tool name changed and should be monitored or denied
quarantined - critical drift was detected and execution is blocked until review
```

## Drift Severity

Interlock does not treat every hash change equally. It classifies drift by whether the approved tool contract changed in a way that affects runtime trust. Typical actions include allow, monitor, deny, and quarantine.

The examples below are illustrative, not exact enforcement logic. Deployed policy can tune severity and action per environment.

| Change type | Typical handling |
|---|---|
| Description-only or documentation changes | Usually monitor or review |
| Schema, data-class, external-reach, or effect expansion | May require denial or re-approval |
| Export, delete, destructive, or external-sharing capability added | May trigger quarantine before execution |
| Metadata confidence, provenance, or verification downgrade | May require review before continued trust |

## Runtime Use

During `/mcp/call`, Interlock now:

```text
loads stored metadata
normalizes runtime argument signals
merges stored metadata with runtime signals
runs drift enforcement
runs metadata policy
writes an audit event
```

If stored metadata is missing, Interlock falls back to runtime inference and adds a warning.

If stored metadata has monitor-level drift, Interlock allows the call but marks the decision `monitor`.

If stored metadata has high drift, Interlock denies before execution with `metadata_drift_violation`.

If stored metadata is quarantined, Interlock denies before execution with `tool_quarantined`.

## Operator Review Loop

Drift enforcement is not only automatic. Operators can review changed tools and either accept the current definition as the new baseline or keep the tool quarantined.

```text
discover
-> remember baseline
-> detect drift
-> monitor, deny, or quarantine
-> operator reviews drifted tools
-> approve new baseline or keep quarantined
```

Approval resets the current stored definition to `active` with:

```text
drift_severity = none
drift_action = allow
drift_types = []
drift_reasons = []
```

Quarantine sets or keeps:

```text
status = quarantined
drift_severity = critical
drift_action = quarantine
drift_types includes operator_quarantine
```

Both actions write audit events with the reviewer and reason.

## Audit Log

Every MCP gateway decision writes a durable audit event, including early gateway denials such as untrusted servers and blocked tools.

Stored fields:

```text
timestamp
server_id
tool_name
role
action
matched_rule
reason
effects
side_effect
data_classes
externality
verification_level
confidence
warnings
argument_keys
blocked_by
drift_status
drift_severity
drift_action
drift_types
drift_reasons
```

## API Endpoints

Discover and persist metadata:

```http
POST /mcp/discover
{
  "server_id": "nextcloud",
  "server_url": "http://localhost:3000/mcp"
}
```

List stored tool metadata:

```http
GET /mcp/tools
GET /mcp/tools?server_id=nextcloud
```

List tools needing review:

```http
GET /mcp/tools/drifted
GET /mcp/tools/drifted?server_id=nextcloud
```

Approve the current tool as the new baseline:

The following approve, quarantine, and global-audit operations require an API
key with the `admin` scope. Runtime-only keys (`mcp.call`, `mcp.read`) receive
HTTP 403. The same admin requirement applies to server register, verify,
rebaseline, and delete routes.

```http
POST /mcp/tools/{server_id}/{tool_name}/approve
{
  "reviewer": "maaz",
  "reason": "Reviewed expected schema update."
}
```

Keep or mark a tool quarantined:

```http
POST /mcp/tools/{server_id}/{tool_name}/quarantine
{
  "reviewer": "maaz",
  "reason": "Hold until tool owner confirms behavior."
}
```

List recent audit events:

```http
GET /mcp/audit
GET /mcp/audit?limit=25
```

## Product Story

Interlock now discovers every MCP tool, classifies it, remembers that classification, detects when the tool changes, enforces policy at runtime, and writes an audit trail for every allow, deny, or monitor decision.
