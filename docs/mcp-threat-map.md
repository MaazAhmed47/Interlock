# Interlock — MCP Threat Map

This page is the buyer-friendly threat map for Interlock. It explains the MCP risks Interlock is designed to reduce, how each risk maps to an Interlock control, and which claims are safe to use in public outreach.

Interlock does not replace secure MCP server design. It adds a runtime control plane in front of MCP tools: metadata baselining, drift detection, role-aware policy, argument inspection, response scanning, provenance checks, shadow-server discovery, and audit evidence.

---

## Safe Positioning

Use this wording in emails, docs, and demos:

> Interlock maps to the OWASP MCP Top 10 by enforcing runtime policy, detecting schema and provenance drift, scanning arguments and responses, probing operator-provided shadow targets, and auditing every allow, deny, monitor, and quarantine decision.

Avoid this wording:

> OWASP certified, guaranteed protection, every MCP server is discovered automatically, all developer environments were compromised.

OWASP does not certify Interlock, and shadow discovery only scans operator-provided targets.

---

## Threat Map

| Threat | What Can Happen | Interlock Defense | Demo Angle |
|---|---|---|---|
| Tool poisoning / full-schema poisoning | Malicious instructions or risky behavior are hidden in descriptions, parameter names, types, defaults, enums, required fields, or outputs. | Full-schema metadata baseline, drift scoring, response scanning, auto-quarantine for high-risk changes. | A tool adds an external-sharing parameter after approval; Interlock quarantines it. |
| Rug pull / post-deployment drift | A server appears safe at registration, then later returns changed tool definitions or behavior. | Per-call baseline comparison and drift detection, not just one-time registration review. | Clean baseline first, changed schema later, quarantine + audit event. |
| Supply-chain tampering | A package, connector, or MCP server dependency is replaced or altered after trust is established. | Provenance metadata, allowed registry policy, source URL policy, pinned version/hash checks, provenance drift audit. | Hash or version mismatch triggers monitor/quarantine. |
| Shadow MCP servers | Teams run unapproved MCP endpoints outside normal governance. | Operator-provided target probing, risk scoring, lifecycle review, shadow discovery audit. | Add a target URL, detect unregistered MCP-like endpoint, review it. |
| Command injection | Tool arguments contain shell, SQL, or path traversal payloads. | Argument inspection before execution, policy enforcement, deny/audit decision. | `../../etc/passwd` or SQL injection in tool args is blocked. |
| Token and secret exposure | Tool output contains API keys, bearer tokens, private keys, credentials, or other sensitive data. | Response scanner redacts secrets/PII before returning content to the agent/model. | Tool response includes token; Interlock redacts and records evidence. |
| Context injection / output injection | Retrieved content or tool output contains hidden instructions that hijack the model. | Response injection scanner blocks matched payloads and logs matched patterns/confidence. | Search result contains `SYSTEM: ignore previous instructions`; Interlock blocks it. |
| Privilege escalation / scope creep | A tool expands from read-only to write, delete, export, or external-sharing capability. | Metadata normalization, effect classification, role-aware policy, drift quarantine. | Read-only agent tries export/delete capability; Interlock denies or quarantines. |
| Missing audit trail | Teams cannot prove which tool call was allowed, denied, monitored, or quarantined. | Centralized audit log with role, server, tool, rule, reason, matched patterns, and decision. | Show audit event after approve/quarantine action. |
| Cascading multi-server risk | One compromised MCP server influences decisions across other tools or systems. | Per-server metadata, role policy, provenance checks, response scanning, and audit correlation through the gateway. | One risky server is contained instead of silently influencing other tool calls. |

---

## Public Claims To Use

These are safe:

- Interlock provides a documented OWASP MCP Top 10 coverage mapping.
- Interlock currently maps to 10/10 OWASP MCP categories in its coverage document.
- MCP04 and MCP09 are covered through provenance policy and operator-provided shadow target discovery.
- Shadow scanning is opt-in and only probes configured targets.
- Response scanning handles prompt-injection patterns, PII, secrets, and response-volume anomalies.
- Every allow, deny, monitor, and quarantine decision is auditable.

These need careful wording:

- Say "potentially affected environments" or "downloads" for dependency incidents unless a source proves actual compromise.
- Say "operator-provided target discovery," not "finds every MCP server automatically."
- Say "coverage mapping," not "OWASP certified."
- Say "reduces risk" or "defends against," not "guarantees prevention."

---

## Real-World Context

**OWASP MCP Top 10:** OWASP lists MCP risks including tool poisoning, supply-chain tampering, command injection, insufficient authorization, lack of audit telemetry, shadow MCP servers, and context over-sharing.

**CyberArk "Poison Everywhere":** CyberArk showed that MCP risk is not limited to obvious tool descriptions. Tool outputs and schema fields can carry malicious instructions or data that influence agent behavior.

**Endor Labs MCP AppSec report:** Endor Labs analyzed MCP implementations and highlighted classic application-security issues in MCP infrastructure, including path traversal, code injection, and command injection risk patterns.

**postmark-mcp incident:** CSO Online reported a squatted `postmark-mcp` npm package that silently copied outbound emails through a hidden Bcc behavior. This is the kind of supply-chain and post-deployment behavior change Interlock is designed to surface through provenance, drift, response scanning, and audit controls.

---

## Best Demo Story

Use this 2-minute flow:

1. Register a clean MCP tool baseline.
2. Simulate a changed tool schema that adds external sharing.
3. Interlock detects drift and quarantines the tool.
4. Simulate a malicious tool response containing hidden instructions and PII.
5. Interlock blocks or redacts the response.
6. Show the audit log with decision, reason, matched rule, and evidence.

This demo makes Interlock feel concrete: tool changed, risk detected, policy enforced, evidence recorded.

---

## Sources

- OWASP MCP Top 10: https://owasp.org/www-project-mcp-top-10/
- CyberArk "Poison Everywhere": https://www.cyberark.com/resources/threat-research-blog/poison-everywhere-no-output-from-your-mcp-server-is-safe
- Endor Labs MCP AppSec Report: https://www.endorlabs.com/learn/classic-vulnerabilities-meet-ai-infrastructure-why-mcp-needs-appsec
- Docker MCP supply-chain writeup: https://www.docker.com/blog/mcp-horror-stories-the-supply-chain-attack/
- CSO Online postmark-mcp report: https://www.csoonline.com/article/4064009/trust-in-mcp-takes-first-in-the-wild-hit-via-squatted-postmark-connector.html
