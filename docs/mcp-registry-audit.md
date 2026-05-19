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

Interlock does not treat every hash change equally. It classifies drift by what changed and maps it to a runtime action:

```text
none     -> allow
minor    -> monitor
moderate -> monitor
high     -> deny
critical -> quarantine
```

Examples:

```text
description changed                 -> minor / monitor
optional schema field added          -> moderate / monitor
required schema field added          -> high / deny
sensitive field added                -> high / deny
sensitive data class added            -> high / deny
internal tool became external         -> high / deny
authenticated user became service account -> high / deny
write/admin/execute scope added       -> high / deny
read-only tool became mutating        -> high / deny
execute/delete/share/export added     -> critical / quarantine
mutating tool became destructive      -> critical / quarantine
metadata verification level downgraded -> high / deny
```

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
