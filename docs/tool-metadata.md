# Tool Metadata

Interlock normalizes MCP tool metadata into one internal model before policy and audit decisions. This lets teams running multiple MCP servers reason about tools with one vocabulary, even when each server exposes different annotations.

## Why This Exists

Official MCP tool annotations are useful, but they are hints rather than trusted security contracts. Interlock therefore:

1. Reads official MCP annotations when present.
2. Reads richer `_meta.interlock` security metadata when present.
3. Reads generic `_meta.security` metadata when present.
4. Infers missing fields from tool names, descriptions, and schemas.
5. Emits warnings when metadata is inferred, incomplete, or inconsistent.

## Normalized Fields

Every tool is normalized into:

```json
{
  "effects": ["read"],
  "side_effect": "read_only",
  "data_classes": ["user_content"],
  "externality": "internal",
  "identity_mode": "authenticated_user",
  "required_scopes": ["files.read"],
  "source": "interlock_meta",
  "verification_level": "interlock_meta",
  "confidence": 0.95,
  "warnings": []
}
```

## Supported Values

`effects`:

```text
read, create, update, delete, share, export, message, execute
```

`side_effect`:

```text
read_only, mutating, destructive, unknown
```

`data_classes`:

```text
pii, phi, financial, legal, secrets, user_content, internal
```

`externality`:

```text
internal, external, unknown
```

`identity_mode`:

```text
authenticated_user, service_account, delegated_agent, unknown
```

`verification_level`:

```text
interlock_meta, security_meta, mcp_annotations, heuristic, unknown
```

## Official MCP Annotations

Interlock reads official MCP annotations:

```json
{
  "name": "list_files",
  "description": "List files in a workspace.",
  "annotations": {
    "readOnlyHint": true,
    "destructiveHint": false,
    "idempotentHint": true,
    "openWorldHint": false
  }
}
```

These produce normalized metadata, but Interlock still records that they are hints.

## Interlock Metadata

For best results, MCP servers can expose richer metadata under `_meta.interlock`:

```json
{
  "name": "share_file",
  "description": "Share a file with a recipient.",
  "_meta": {
    "interlock": {
      "effects": ["share"],
      "side_effect": "mutating",
      "externality": "external",
      "data_classes": ["user_content", "pii"],
      "identity_mode": "authenticated_user",
      "required_scopes": ["files.read", "sharing.write"]
    }
  },
  "inputSchema": {
    "type": "object",
    "properties": {
      "file_id": {"type": "string"},
      "recipient_email": {"type": "string"}
    }
  }
}
```

## Generic Security Metadata

Interlock also accepts `_meta.security`:

```json
{
  "name": "export_ledger",
  "_meta": {
    "security": {
      "effects": ["export"],
      "side_effect": "mutating",
      "externality": "external",
      "data_classes": ["financial", "internal"],
      "identity_mode": "service_account"
    }
  }
}
```

## Heuristic Fallback

If a server provides no metadata, Interlock infers a conservative starting point:

- `read`, `list`, `get`, `search`, `fetch` imply `read`.
- `create`, `write`, `update`, `send`, `share`, `export` imply mutating effects.
- `delete`, `drop`, `wipe`, `truncate` imply destructive effects.
- fields like `email`, `ssn`, `token`, `api_key`, `diagnosis`, and `ledger` imply sensitive data classes.

Heuristic metadata has lower confidence and includes warnings so operators know it should be reviewed.

## API Surface

`POST /mcp/validate-tool` returns `tool_metadata` on the validation result.

`POST /mcp/discover` includes `tool_metadata` for each validation entry.

This is currently informational. Enforcement still uses the existing server trust checks, allowlists/blocklists, tool-call inspector, RBAC, and response scanning.

