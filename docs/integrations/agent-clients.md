# Agent Client Integration Patterns

Interlock is designed to sit between an agent runtime and MCP/tool
infrastructure. The exact adapter depends on the client, but the integration
model stays the same: point tool calls through Interlock and let the gateway
resolve the agent role from the runtime API key before execution. Do not treat
an `/mcp/call` request-body role as authorization; it is ignored.

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

Use an admin-scoped API key for registry control and a runtime key with
`mcp.call`/`mcp.read` plus a bound role for agent traffic.

```bash
curl -X POST http://localhost:8001/mcp/servers \
  -H "x-api-key: <YOUR_ADMIN_SCOPED_INTERLOCK_API_KEY>" \
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
  -H "x-api-key: <YOUR_RUNTIME_INTERLOCK_API_KEY>" \
  -H "Content-Type: application/json" \
  -d '{
    "server_id": "internal-slack",
    "tool_name": "read_channel",
    "arguments": {"channel": "support"}
  }'
```

---

## MCP Streamable HTTP Clients

Interlock's inbound Streamable HTTP profile supports MCP `2026-07-28` for one
verified registry server at:

```text
http://localhost:8001/mcp/stream/<server_id>
```

Authenticate every POST with either `X-API-Key: <runtime-key>` or
`Authorization: Bearer <runtime-key>`. The key must have `mcp.call`; its stored
role and key identity are used for enforcement and audit evidence.

This is a stateless profile. Every request must carry the following:

- `MCP-Protocol-Version: 2026-07-28` and `Mcp-Method` headers;
- `Mcp-Name` for `tools/call`, matching `params.name` exactly;
- per-request protocol version and client capabilities in `params._meta`.
  Client identity is recommended and validated when present, but is optional.

Interlock implements `server/discover`, `tools/list`, and `tools/call`.
Successful responses include `resultType: "complete"` and server identity in
`result._meta`. Tool lists are deterministic and return a short, private cache
hint. The visible tool list contains only active, allowlisted, non-blocked,
non-quarantined tools with a trusted stored metadata baseline. The identical
eligibility check runs at the gateway boundary before a tool call; eligible
calls continue through the same trust, drift, inspection, RBAC, response-scan,
quarantine, and audit pipeline as `/mcp/call`.

```bash
curl -X POST http://localhost:8001/mcp/stream/internal-slack \
  -H "Authorization: Bearer <YOUR_RUNTIME_INTERLOCK_API_KEY>" \
  -H "Accept: application/json, text/event-stream" \
  -H "Content-Type: application/json" \
  -H "MCP-Protocol-Version: 2026-07-28" \
  -H "Mcp-Method: tools/list" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/list",
    "params": {
      "_meta": {
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientInfo": {
          "name": "pilot-client", "version": "1.0.0"
        },
        "io.modelcontextprotocol/clientCapabilities": {}
      }
    }
  }'
```

The former `initialize`/`notifications/initialized` lifecycle,
`MCP-Session-Id`, `ping`, HTTP GET lifecycle endpoint, and SSE resumption are
not supported. GET and DELETE return `405 Method Not Allowed`. This profile
does not yet advertise subscriptions, tasks, prompts, resources, MRTR, or
`x-mcp-header` parameter mirroring. Tools that require `x-mcp-header` are hidden
and denied before execution.

Registered upstreams default to the existing `legacy` bare JSON-RPC adapter.
Set `upstream_protocol_profile` to `2026-07-28` only for an upstream that
implements the pinned stateless profile. Interlock then sends `server/discover`,
`tools/list`, and `tools/call` with the required headers and per-request metadata
and never silently downgrades. See the exact supported, blocked, and future
boundary in [MCP 2026 compatibility](../mcp-2026-compatibility.md).

Browser-originated requests are accepted only when the complete Origin is
listed explicitly in `ALLOWED_ORIGINS`. The wildcard value does not authorize
an Origin for this endpoint. Non-browser MCP clients may omit Origin.

## Local Adapter For Other MCP Clients

For desktop MCP clients, use a small local adapter that exposes an MCP server to the client and forwards tool calls to Interlock. The adapter should:

- expose the same tool names the client expects
- add `server_id`, `tool_name`, and `arguments`
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
- Use separate control-plane and runtime keys per environment or pilot team so
  privileges, audit logs, and quotas remain clear.
- Bind the intended role when issuing the runtime key. A conflicting
  `/mcp/call` body role has no effect.
- Start with one agent and one MCP server, then expand after allow/block/quarantine/audit are proven.

---

## Integration Checklist

- Pick the role for each agent and bind it to that agent's runtime key.
- Prefer the native `/mcp/stream/<server_id>` endpoint for compatible
  Streamable HTTP clients; otherwise route MCP tool calls through `/mcp/call`.
- Use `/inspect/tool-call` for non-MCP tools.
- Use `/scan/output` for model/tool outputs that may be reused by an agent.
- Store one API key per environment or pilot team.
- Review audit logs after the first day of traffic.
