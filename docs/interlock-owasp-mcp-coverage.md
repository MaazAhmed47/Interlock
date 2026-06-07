# Interlock OWASP MCP Practical Mapping

Interlock maintains a practical product-evaluation mapping against OWASP MCP Top 10-style risk categories. This document explains where Interlock has runtime controls, where those controls are complementary, and where teams still need server-side or infrastructure controls.

This is Interlock's own practical mapping for product evaluation. It is not an OWASP certification, endorsement, or formal compliance claim.

## How To Read This

- **Mapped** means Interlock has a runtime control that directly helps evaluate or reduce the risk.
- **Partially mapped** means Interlock contributes evidence or enforcement, but the risk also depends on MCP server design, identity, deployment, or infrastructure controls.
- **Out of scope** means the risk should be handled outside Interlock.

Interlock should be evaluated as one runtime trust layer, not as a complete replacement for secure MCP server implementation.

---

## MCP01: Token Mismanagement And Secret Exposure

**Risk:** Tools, responses, logs, or model context may expose credentials, API keys, bearer tokens, or other sensitive values.

**Interlock mapping: Mapped**

- Response scanning can detect and redact common secret and credential patterns before output is forwarded downstream.
- Audit logs preserve the runtime decision and evidence category for later review.
- Policy can restrict roles from calling tools likely to handle sensitive data.

---

## MCP02: Privilege Escalation Via Scope Creep

**Risk:** A tool that was approved for narrow use later gains broader capability, such as write access, export behavior, or new sensitive data access.

**Interlock mapping: Mapped**

- Tool baselines capture the approved capability envelope.
- Drift detection compares the current tool definition with the approved baseline.
- Risky changes can require review or quarantine before execution.
- Audit evidence records the decision and review path.

---

## MCP03: Tool Poisoning

**Risk:** Tool metadata, descriptions, schemas, or outputs may steer an agent toward unsafe behavior.

**Interlock mapping: Mapped**

- Tool metadata is normalized and baselined at approval time.
- Schema and metadata changes can be detected as drift.
- Response scanning can inspect tool output before it reaches the next model step.
- High-risk changes can be held for review instead of silently trusted.

---

## MCP04: Supply Chain Attacks And Dependency Tampering

**Risk:** A package, connector, or MCP server dependency may be replaced, backdoored, typosquatted, or altered after trust was established.

**Interlock mapping: Partially mapped**

- Provenance metadata can be recorded and reviewed as part of server trust.
- Version, source, and hash changes can be treated as runtime trust signals.
- Audit logs can preserve provenance checks and operator decisions.

Still required: dependency scanning, package signing, SBOMs, secure build pipelines, and server-side supply-chain controls.

---

## MCP05: Command Injection And Execution

**Risk:** Tool arguments may carry shell, SQL, path traversal, or other dangerous payloads into an MCP server.

**Interlock mapping: Partially mapped**

- Runtime policy and argument inspection can block suspicious calls before they reach the MCP server.
- Audit logs record the decision and matched risk category.

Still required: secure MCP server implementation, input validation, sandboxing where appropriate, least-privilege credentials, and server-side tests.

---

## MCP06: Intent Flow Subversion

**Risk:** Retrieved content or tool output may contain instructions that try to hijack the agent's next step.

**Interlock mapping: Mapped**

- Response scanning can inspect tool output for instruction-like or exfiltration-oriented content.
- Runtime decisions can block, monitor, or record suspicious output before downstream reuse.
- Audit evidence keeps the finding explainable for review.

---

## MCP07: Insufficient Authentication And Authorization

**Risk:** Agents or users may invoke tools they should not be allowed to use.

**Interlock mapping: Partially mapped**

- Role-aware policy can enforce agent or operator permissions before tool execution.
- API key enforcement protects Interlock runtime APIs and feeds.
- Audit logs record role, rule, and decision context.

Still required: MCP server authentication, identity provider configuration, tenant isolation where needed, and least-privilege credentials.

---

## MCP08: Lack Of Audit And Telemetry

**Risk:** Teams may not know which agent called which tool, why a call was allowed or blocked, or what changed over time.

**Interlock mapping: Mapped**

- Runtime audit logs record allow, deny, monitor, and quarantine decisions.
- Security Receipts preserve evidence for drift, policy, and quarantine decisions.
- Webhook/SIEM-style event paths can support external monitoring workflows where configured.

---

## MCP09: Shadow MCP Servers

**Risk:** Teams may run unapproved MCP endpoints outside the expected gateway or governance path.

**Interlock mapping: Partially mapped**

- Shadow discovery is opt-in and limited to operator-provided targets.
- Findings can be reviewed with status, risk context, and audit evidence.
- Interlock does not claim to automatically discover every MCP server.

Still required: asset inventory, network governance, endpoint ownership, and deployment controls.

---

## MCP10: Context Injection And Over-Sharing

**Risk:** Tools may return more data than the agent needs, including PII, credentials, internal records, or instruction-bearing content.

**Interlock mapping: Mapped**

- Response scanning can redact common sensitive-data patterns.
- Oversized or unusual responses can be flagged for review.
- Tool metadata can support role-aware restrictions for sensitive data classes.

Still required: app-level data isolation, MCP server least privilege, prompt/context design, and customer-specific retention policy.

---

## Summary

| Risk area | Interlock mapping | Primary control |
|---|---|---|
| Token and secret exposure | Mapped | Response scanning, audit evidence |
| Scope creep and privilege expansion | Mapped | Tool baselines, drift detection, quarantine |
| Tool poisoning | Mapped | Metadata baseline, drift review, response scanning |
| Supply-chain tampering | Partially mapped | Provenance evidence and runtime drift signals |
| Command injection | Partially mapped | Argument inspection and policy enforcement |
| Intent flow subversion | Mapped | Response scanning and runtime decisions |
| Authorization gaps | Partially mapped | Role-aware policy and API key enforcement |
| Audit and telemetry gaps | Mapped | Audit logs, Security Receipts, SIEM-ready events |
| Shadow MCP servers | Partially mapped | Operator-provided target review |
| Context over-sharing | Mapped | Response scanning and data-class policy |

Use this page as a practical evaluation guide. Test Interlock against the target MCP workflow, then pair it with secure server design, identity controls, deployment hardening, and operational monitoring.
