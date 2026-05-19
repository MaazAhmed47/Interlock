# Metadata Policy

Interlock uses normalized MCP tool metadata to make runtime policy decisions before a tool call executes.

This moves metadata from passive context to an active control point:

```text
trusted server
-> allowlist/blocklist
-> runtime metadata normalization
-> stored metadata drift enforcement
-> metadata policy decision
-> argument inspection
-> RBAC
-> MCP server execution
-> response scan
```

## Decision Shape

Each metadata policy evaluation returns:

```json
{
  "action": "allow",
  "reason": "No metadata policy rule denied or elevated this tool call.",
  "matched_rule": "default_allow",
  "tool_metadata": {},
  "warnings": [],
  "audit_context": {
    "server_id": "trusted-filesystem",
    "tool_name": "read_file",
    "role": "support_agent",
    "effects": ["read"],
    "side_effect": "read_only",
    "data_classes": ["user_content"],
    "externality": "internal",
    "verification_level": "heuristic",
    "confidence": 0.55,
    "decision": "allow",
    "reason": "No metadata policy rule denied or elevated this tool call.",
    "matched_rule": "default_allow",
    "warnings": [],
    "argument_keys": ["path"]
  }
}
```

Actions:

```text
allow   - continue normally
deny    - block before execution
monitor - continue, but mark the call as needing review
```

## Default Rules

Initial runtime rules:

1. `readonly_agent_read_only`
   - Deny `readonly_agent` unless the tool is read-only and only has `read` effects.

2. `destructive_requires_admin`
   - Deny destructive tools unless the role is `admin_agent`.

3. `execute_requires_privileged_role`
   - Deny execute-class tools unless the role is `devops_agent` or `admin_agent`.

4. `finance_external_transfer`
   - Deny `finance_agent` for external `share`, `export`, or `message` actions.

5. `no_external_secrets`
   - Deny external transfer of secrets for non-admin roles.

6. `no_external_phi_without_admin`
   - Deny external transfer of PHI unless the role is `admin_agent`.

7. `low_confidence_heuristic`
   - Monitor low-confidence heuristic metadata.

8. `metadata_mismatch`
   - Monitor calls where metadata warnings indicate conflicts or read-only mismatch.

9. `default_allow`
   - Allow when no rule denies or elevates the call.

## Runtime Metadata

During `/mcp/call`, Interlock now prefers stored discovery metadata from the MCP tool registry, then merges in runtime signals from:

- tool name
- argument keys
- argument value types

If no stored metadata exists, Interlock falls back to runtime inference and adds a warning. If stored metadata is marked `changed`, Interlock monitors the call unless a stricter rule denies it.

Stored drift can also make a decision before normal policy:

```text
monitor drift    - continue, but mark the call as monitor
high drift       - deny with metadata_drift_violation
critical drift   - quarantine and deny with tool_quarantined
```

Drift context is attached to the decision and audit event:

```json
{
  "drift": {
    "status": "changed",
    "severity": "high",
    "action": "deny",
    "types": ["required_field_added"],
    "reasons": ["Required schema fields added: ['region_id']."]
  }
}
```

## Audit Value

Every allowed, monitored, or denied call can now explain:

- which tool was requested
- which role requested it
- what the tool was classified as doing
- where the metadata came from
- how confident Interlock was
- which rule matched
- why the call was allowed, denied, or monitored

This is the foundation for a durable audit trail and future approval workflow.
