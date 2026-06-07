# Agent Client Integration Patterns

Interlock is designed to sit between an agent runtime and MCP/tool infrastructure. The exact adapter depends on the client, but the integration model stays the same: point tool calls through Interlock, pass the agent role, and let the gateway enforce policy before execution.

---

## 2-Minute OpenAI-Compatible Chat Proxy

Start Interlock locally:

```bash
./scripts/quickstart.sh
```

For OpenAI-compatible clients, the application change is intentionally small: use the Interlock key as the client API key and point `base_url` at Interlock.

```python
import os
from openai import OpenAI

client = OpenAI(
    api_key=os.environ["INTERLOCK_KEY"],
    base_url="https://interlock.onrender.com/v1",
)
```

Your upstream provider keys, such as `OPENAI_API_KEY` or `ANTHROPIC_API_KEY`, stay on the Interlock gateway host. The app does not need direct provider credentials once traffic is routed through Interlock.

Use this path for prompt and chat-completion protection. Use the MCP gateway path for agent tool execution.

---

## MCP Gateway Pattern

Register MCP servers, discover tools, then call tools through Interlock:

```bash
curl -X POST http://localhost:8001/mcp/servers \
  -H "x-api-key: <YOUR_INTERLOCK_API_KEY>" \
  -H "Content-Type: application/json" \
  -d '{
    "server_id": "internal-slack",
    "url": "http://localhost:3000",
    "description": "Internal Slack MCP server",
    "allowed_tools": ["search", "read_channel"],
    "blocked_tools": ["export_channel"]
  }'
```

```bash
curl -X POST http://localhost:8001/mcp/call \
  -H "x-api-key: <YOUR_INTERLOCK_API_KEY>" \
  -H "Content-Type: application/json" \
  -d '{
    "server_id": "internal-slack",
    "tool_name": "read_channel",
    "role": "support_agent",
    "arguments": {"channel": "support"}
  }'
```

---

## Claude Desktop / Cursor MCP Clients

For desktop MCP clients, use a small local adapter that exposes an MCP server to the client and forwards tool calls to Interlock. The adapter should:

- expose the same tool names the client expects
- add `server_id`, `tool_name`, `role`, and `arguments`
- call Interlock `/mcp/call`
- return the sanitized response or denial reason to the client

See `examples/opencode/interlock_mcp_adapter.py` for the current adapter shape.

---

## LangChain / CrewAI / Custom Agents

For framework-based agents, wrap tool invocation:

```python
def guarded_tool_call(tool_name: str, args: dict, role: str):
    response = requests.post(
        "http://localhost:8001/inspect/tool-call",
        headers={"x-api-key": os.environ["INTERLOCK_KEY"]},
        json={"tool_name": tool_name, "tool_args": args, "role": role},
        timeout=10,
    )
    decision = response.json()
    if decision.get("is_threat"):
        raise RuntimeError(decision["reason"])
    return actual_tool_call(tool_name, args)
```

For MCP servers, prefer `/mcp/call` because it adds server trust, whitelist, drift, provenance, response scanning, and audit.

---

## Trust Model For Integrators

- The app sends an Interlock API key; provider credentials stay server-side on the gateway.
- Raw Interlock keys are returned once and stored hashed in the key database.
- Use one key per environment or pilot team so audit logs and quotas remain clear.
- Pass an explicit `role` on tool calls so RBAC decisions are explainable.
- Start with one agent and one MCP server, then expand after allow/block/quarantine/audit are proven.

---

## Integration Checklist

- Pick the role for each agent.
- Route MCP tool calls through `/mcp/call` where possible.
- Use `/inspect/tool-call` for non-MCP tools.
- Use `/scan/output` for model/tool outputs that may be reused by an agent.
- Store one API key per environment or pilot team.
- Review audit logs after the first day of traffic.
