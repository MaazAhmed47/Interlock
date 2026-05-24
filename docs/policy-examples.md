# Policy Examples

Interlock includes role-aware policy for agent tool calls. The goal is simple: an agent's job role should control which tools it can call and which arguments are too risky.

---

## Built-In Roles

| Role | Intended access | Example blocked behavior |
|---|---|---|
| `support_agent` | CRM read, knowledge search, ticket/email workflows | database deletion, shell execution, admin access |
| `finance_agent` | read transactions, generate reports, export CSV | modify records, SQL execution, shell access |
| `readonly_agent` | read, search, list, get, fetch | write, delete, execute, create, update |
| `data_analyst` | read database, run SQL, export reports | drop table, schema changes, shell execution |
| `devops_agent` | deploy, restart services, read logs, monitor | production deletion, destructive database changes |
| `admin_agent` | broad admin access | catastrophic operations like wiping users or disks |

---

## Finance Agent Denial

```bash
curl -X POST http://localhost:8001/inspect/tool-call \
  -H "x-api-key: lf-dev-key-456" \
  -H "Content-Type: application/json" \
  -d '{
    "tool_name": "delete_record",
    "role": "finance_agent",
    "tool_args": {
      "table": "transactions",
      "where": "amount > 0"
    }
  }'
```

Expected: denied by RBAC before execution.

---

## Readonly Agent Denial

```bash
curl -X POST http://localhost:8001/inspect/tool-call \
  -H "x-api-key: lf-dev-key-456" \
  -H "Content-Type: application/json" \
  -d '{
    "tool_name": "write_file",
    "role": "readonly_agent",
    "tool_args": {
      "path": "/tmp/report.txt",
      "content": "overwrite"
    }
  }'
```

Expected: denied because a readonly agent cannot write files.

---

## Dangerous SQL Argument

```bash
curl -X POST http://localhost:8001/inspect/tool-call \
  -H "x-api-key: lf-dev-key-456" \
  -H "Content-Type: application/json" \
  -d '{
    "tool_name": "run_sql",
    "role": "data_analyst",
    "tool_args": {
      "query": "DROP TABLE customers"
    }
  }'
```

Expected: denied by the tool-call inspector.

---

## Per-Key Prompt Policy Example

Create or update an API key with a custom policy:

```json
{
  "custom_policy": {
    "blocked_keywords": ["export customer list", "admin password", "production secrets"],
    "max_prompt_length": 3000
  }
}
```

This is useful when a buyer wants policy by environment, customer, or pilot team.

---

## Buyer-Facing Policy Story

A CTO does not need to understand every regex. The story is:

1. Define what each agent role is allowed to do.
2. Baseline MCP tools at discovery.
3. Block risky tool calls before execution.
4. Quarantine drift when tools change after approval.
5. Record the reason so security can review it later.
