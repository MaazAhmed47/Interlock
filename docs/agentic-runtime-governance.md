# Agentic Runtime Governance

Agentic AI systems need runtime controls once agents can call tools, access data, and operate across systems. Periodic review is still useful, but it is not enough when an agent can take action through live tool interfaces.

Interlock focuses on one core runtime governance problem:

```text
Approved MCP tools should not be trusted forever if their schema, behavior, data access, or external reach changes after approval.
```

For MCP agents, the trust boundary is not only the prompt. It is also the tool surface the agent is allowed to use. If that surface changes after approval, the runtime path needs a way to detect the change, stop risky execution, and preserve evidence for review.

## Runtime Control Mapping

| Runtime governance need    | Interlock control                       |
| -------------------------- | --------------------------------------- |
| Live monitoring            | MCP gateway observes tool activity      |
| Baselines that flag drift  | Tool baseline + drift detection         |
| Stop mechanisms in seconds | Quarantine before execution             |
| Audit evidence             | Security Receipts and audit logs        |
| Tool interface control     | MCP policy enforcement before execution |

## Risky Drift Examples

Risky post-approval drift can include:

* new required parameters
* expanded data access
* external reach added
* read-only behavior becoming mutating behavior
* tool descriptions changing in a way that affects agent selection

These changes matter because policy that approved the old tool may no longer match the live tool. Interlock treats that mismatch as a runtime trust event, not just a documentation update.

## Disclaimer

Interlock is not affiliated with or endorsed by OWASP. This page maps Interlock's runtime controls to public agentic security themes for clarity.
