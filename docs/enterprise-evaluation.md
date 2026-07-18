# Enterprise Evaluation Guide

This is the buyer-facing checklist for evaluating Interlock as an MCP runtime trust layer for AI agents.

---

## Why A CTO Takes A Meeting

AI agents are moving from text-only workflows to tool execution. Once agents call MCP servers, databases, Slack, files, ticketing systems, and internal APIs, every tool call becomes a trust decision.

Interlock is useful when a team needs to answer:

- Which agent called which tool?
- Was the agent role allowed to call it?
- Did the MCP tool definition drift since approval?
- Did the request contain dangerous SQL, shell, file, or network intent?
- Did the tool response contain prompt injection, secrets, PII, or excess context?
- Can security review the decision later?

---

## What Makes Interlock Different

| Buyer concern | Interlock answer |
|---|---|
| Prompt filters do not control tool execution | Interlock sits on the agent-to-tool path, especially `POST /mcp/call` and `/inspect/tool-call`. |
| MCP tools can change after approval | Interlock stores baselines and detects schema, metadata, provenance, and capability drift. |
| Agents need different permissions | Built-in role policy blocks risky calls for support, finance, readonly, data analyst, devops, and admin agents. |
| Tool outputs can attack the next model step | Interlock scans MCP responses for prompt injection, secrets, PII, and volume anomalies. |
| Security teams need evidence | Interlock records allow, deny, monitor, quarantine, provenance, shadow, and response-scan decisions. |
| Enterprises want control | Interlock is self-hosted and can run inside the buyer's environment. |

---

## What Would Make A Buyer Say Yes

A serious buyer is more likely to pilot or buy when these are true:

- Install works in under 10 minutes with Docker or a single Helm release.
- The drift demo shows a clean MCP tool becoming risky and getting quarantined.
- Policy examples map to real teams: finance, support, devops, readonly, data analyst.
- Audit logs show the exact decision, reason, tool, role, and risk evidence.
- Response scanning blocks prompt injection and redacts secrets/PII before model reuse.
- The deployment guide is honest about single-node limits and high-availability requirements.
- The product has a clear license, support path, and design-partner motion.
- The team can run a pilot without sending sensitive prompts to a third-party SaaS gateway.

---

## What Would Make A Buyer Reject It

These are the main rejection risks and how the repo now addresses them:

| Rejection risk | Mitigation in repo |
|---|---|
| Unclear install path | `README.md` and `INSTALL.md` include Python, Docker, and Helm pilot quickstarts. |
| No visual proof | README includes dashboard and gateway screenshots near the top. |
| Overclaiming enterprise readiness | `INSTALL.md` now documents pilot readiness and production boundaries clearly. |
| No clear security model | `docs/threat-model.md` defines boundaries, trust assumptions, and non-goals. |
| No role policy examples | `docs/policy-examples.md` shows role behavior and sample blocked calls. |
| No integration path | `docs/integrations/agent-clients.md` explains client integration patterns. |
| No SIEM story | `docs/siem-integrations.md` documents Slack, Datadog, Splunk, Elastic, PagerDuty, and generic webhook configs. |
| No performance expectations | `docs/performance.md` defines what is in-path, what is upstream latency, and how to run the smoke benchmark. |
| No license clarity | `LICENSE` uses Apache-2.0 for enterprise-friendly evaluation and adoption. |

---

## Pilot Success Criteria

A 7-day pilot should prove these outcomes:

1. Interlock can sit between one agent workflow and one MCP server.
2. A clean tool baseline can be recorded.
3. A risky schema or capability drift is detected and quarantined.
4. At least one agent role policy blocks a risky call before execution.
5. Tool response scanning catches an injected instruction or sensitive data leak.
6. Audit logs are useful enough for security review.
7. Added latency is acceptable for the buyer's workflow.

---

## Demo Script For A CTO

Use this order:

1. Run the [offline MCP drift proof](../demo/offline/README.md#quickstart).
2. Show capability drift quarantined before continued gateway-mediated use.
3. Run the behavioral `403 denied -> 200 allowed` scenario with the same manifest.
4. Inspect the Security Receipt and recompute its hash chain.
5. State that receipts are not externally signed or independently anchored.
6. Review output scanning and role policy only as additional controls.

The point is not to claim perfection. The point is to show a control plane that catches real agent-to-tool risks that prompt filters miss.
