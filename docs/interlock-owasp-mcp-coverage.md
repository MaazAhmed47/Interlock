# Interlock — OWASP MCP Top 10 Coverage

> Interlock turns MCP security from trust-on-first-use into continuous verification: baseline every tool, detect schema drift, enforce policy before execution, scan responses, and audit every decision.

---

## How Interlock Maps to the OWASP MCP Top 10

The OWASP MCP Top 10 (2025) is the first security framework dedicated to the Model Context Protocol. It catalogs the ten most critical risk categories in MCP deployments.

---

### MCP01:2025 — Token Mismanagement & Secret Exposure

**The risk:** Hard-coded credentials, long-lived tokens, and secrets stored in model memory or protocol logs. Attackers retrieve them through prompt injection, compromised context, or debug traces.

**Interlock coverage: ✅ COVERED**

- Response scanning detects secrets, API keys, and tokens in tool outputs before they reach the model.
- Audit log records every tool response, enabling forensic review of credential exposure.
- Policy rules can deny tool calls from roles that should never access credential-bearing tools.

---

### MCP02:2025 — Privilege Escalation via Scope Creep

**The risk:** Agent permissions expand over time beyond their intended scope. Tools that were once read-only quietly gain write or external-sharing capabilities.

**Interlock coverage: ✅ COVERED**

- Baseline captures the exact effects, side effects, and data classes a tool had at registration.
- Drift detection fires when a tool's permissions expand beyond its baseline.
- Quarantine holds any scope expansion until an operator approves it with a reason.
- Audit trail records exactly when permissions changed and who approved them.

---

### MCP03:2025 — Tool Poisoning

**The risk:** Malicious instructions hidden in tool descriptions, schemas, or outputs trick AI into executing harmful actions. CyberArk's "Poison Everywhere" research demonstrated Full-Schema Poisoning (FSP) — attacks embedded not just in descriptions but in parameter names, types, required fields, and default values.

**Interlock coverage: ✅ COVERED (core capability)**

- Metadata normalization captures the full tool schema at registration: effects, side effects, data classes, externality, identity mode.
- Baseline comparison detects any change to any schema field — descriptions, parameter names, types, defaults, enums, required fields.
- Drift scoring classifies changes by risk level (high, medium, low).
- Auto-quarantine holds high-risk changes until an operator reviews them.

**Source:** CyberArk "Poison Everywhere" — https://www.cyberark.com/resources/threat-research-blog/poison-everywhere-no-output-from-your-mcp-server-is-safe

---

### MCP04:2025 — Software Supply Chain Attacks & Dependency Tampering

**The risk:** Compromised MCP packages, typosquatted servers, and backdoored dependencies introduce malicious behavior into otherwise trusted tool chains.

**Interlock coverage: ✅ COVERED**

- Provenance metadata captured at registration: source_type, registry, package_name, package_version, source_url, source_hash.
- Trusted-source policy: allowed registries, allowed source URLs, pinned versions, pinned SHA-256 hashes. Stored in `system_config` and managed via `PUT /admin/mcp/provenance-policy`.
- Missing provenance → monitor (log, proceed). Unknown registry → monitor. Version/hash mismatch → quarantine (block until operator approves). Operator-set deny → permanent block.
- Drift detection: hash or version change after prior approval → quarantine + `provenance_drift` audit event. Re-evaluated on every tool call — not just at registration — to catch postmark-mcp style silent package substitutions.
- Full audit trail: `provenance_check`, `provenance_drift`, `provenance_approved`, `provenance_denied`, `provenance_block` events in `mcp_audit_log`.
- Operator override API: `PATCH /admin/mcp/servers/{id}/provenance` to approve or permanently deny a quarantined server.

**Real-world context:** The postmark-mcp supply chain attack (Sep 2025) — a fake npm package impersonated Postmark's email service, silently BCC'ing every agent-sent email to an attacker for weeks. Interlock detects hash or behavioral change after a malicious version replaces a trusted one, and re-evaluates provenance on every tool call.

---

### MCP05:2025 — Command Injection & Execution

**The risk:** Agents build shell commands, SQL queries, or API calls from untrusted input without validation, enabling arbitrary code execution on the host.

**Interlock coverage: ✅ COVERED**

- Argument scanning inspects every tool call's parameters before execution.
- Pattern detection for shell metacharacters, SQL injection, and path traversal payloads.
- Policy enforcement blocks tool calls with suspicious argument patterns before they reach the MCP server.

**Real-world context:** Endor Labs found that among 2,614 MCP implementations, 82% use filesystem operations prone to path traversal, 67% use code injection-prone APIs, and 34% use command injection-prone APIs.

**Source:** Endor Labs MCP AppSec Report — https://www.endorlabs.com/learn/classic-vulnerabilities-meet-ai-infrastructure-why-mcp-needs-appsec

---

### MCP06:2025 — Intent Flow Subversion / Prompt Injection via Context

**The risk:** Malicious instructions embedded in retrieved data, tool responses, or external content hijack the agent's reasoning chain, subverting the user's original intent.

**Interlock coverage: ✅ COVERED**

- Response scanning detects 20 injection patterns (16 shared with request scanning + 4 response-specific) in tool outputs before they reach the model.
- Confidence scoring: each matched pattern adds 0.35; one hit is enough to block the response entirely.
- Full audit trail: matched patterns, threat type, and confidence are written to the MCP audit log on every block.
- Detection covers nested JSON values — `json.dumps` flattening ensures injection in any field is caught without recursive traversal.

---

### MCP07:2025 — Insufficient Authentication & Authorization

**The risk:** Missing or weak authentication on MCP endpoints allows unauthorized clients to invoke tools. No authorization checks mean any authenticated user can access any functionality.

**Interlock coverage: ✅ COVERED**

- Runtime policy enforcement evaluates role-aware RBAC before every tool call — not after.
- Per-agent role definitions: readonly, finance, devops, admin, custom.
- Policy rules deny tool access based on agent role, tool effects, and data classification.
- Every allow/deny/monitor/quarantine decision is recorded with the role and rule that triggered it.

---

### MCP08:2025 — Lack of Audit and Telemetry

**The risk:** Without comprehensive logging, security incidents go undetected, forensic investigation becomes impossible, and compliance requirements cannot be met.

**Interlock coverage: ✅ COVERED (core capability)**

- Centralized audit log records every decision — allow, deny, monitor, quarantine — with full context: timestamp, agent role, tool name, server, matched rule, and reason.
- Every drift detection event is logged with the before/after diff.
- Every operator review (approve baseline, keep quarantined) is logged with operator identity and reason.
- Searchable, exportable audit trail for compliance.

---

### MCP09:2025 — Shadow MCP Servers

**The risk:** Unapproved MCP server deployments operating outside the organization's security governance, often with default credentials and permissive configurations.

**Interlock coverage: ✅ COVERED**

- Operator-provided target list: `POST /admin/shadow/targets` adds URLs to probe. No arbitrary network scanning — discovery is always operator-authorized.
- Periodic probing via `httpx.AsyncClient` (5s timeout). Detects MCP endpoints by: JSON `tools` array in 200 response, `error` key in 200 response, or 401/403 (auth-gated endpoint).
- Findings stored in `shadow_mcp_servers`: URL, probe_path, status, first_seen, last_seen, auth_required, tool_listing_available, risk_score.
- Risk scoring: 10 base + 40 for tool listing available + 30 for unauthenticated listing + 20 for auth-required. Maximum 100.
- Lifecycle management: unreviewed → approved / ignored / quarantined via `PATCH /admin/shadow/servers/{id}`.
- Full audit trail: `shadow_discovered` on first detection, `shadow_reviewed` on operator action.
- Opt-in activation: `SHADOW_SCAN_ENABLED=true` env var (default off). Scan interval configurable via `SHADOW_SCAN_INTERVAL` (default 3600s).

---

### MCP10:2025 — Context Injection & Over-Sharing

**The risk:** Tools return more data than the agent needs, exposing sensitive information to the model context. Tool outputs carry PII, credentials, or internal data that leak through the conversation.

**Interlock coverage: ✅ COVERED**

- In-place PII redaction: 12 pattern rules cover SSN (dashed and undashed), credit cards, email, phone, passwords, API keys (generic, AWS AKIA format), bearer tokens, and private key blocks. Sensitive values are replaced with typed markers (`[REDACTED-SSN]`, `[REDACTED-API-KEY]`, etc.) before the response reaches the model.
- Sanitized content is returned to the caller rather than blocking — legitimate data in mixed responses is preserved.
- Data volume anomaly detection: responses exceeding per-key byte or array-item thresholds are flagged as `CONTEXT_OVERSHARING` and logged. Volume alone does not block; it warns.
- Per-key configurable thresholds (`max_response_bytes`, `max_array_items`) managed via `PATCH /admin/keys/{prefix}`. Defaults: 50 KB / 500 items.
- Full audit trail: `threat_type`, `matched_patterns`, and `redactions` written to the MCP audit log on every scan with a finding.
- Data classification in tool metadata enables policy rules restricting which agent roles access tools that handle sensitive data classes.

---

## Coverage Summary

| ID | OWASP MCP Risk | Interlock Coverage | Key Control |
|---|---|---|---|
| MCP01 | Token Mismanagement & Secret Exposure | ✅ Covered | Response scanning, audit log |
| MCP02 | Privilege Escalation via Scope Creep | ✅ Covered | Drift detection, baseline comparison |
| MCP03 | Tool Poisoning | ✅ Covered (core) | Full-schema baseline, quarantine |
| MCP04 | Supply Chain Attacks | ✅ Covered | Provenance metadata, registry policy, hash pinning, drift detection |
| MCP05 | Command Injection & Execution | ✅ Covered | Argument scanning, policy enforcement |
| MCP06 | Intent Flow Subversion | ✅ Covered | Injection pattern matching on responses, confidence scoring, full audit trail |
| MCP07 | Insufficient Auth & Authorization | ✅ Covered | Role-aware RBAC, policy enforcement |
| MCP08 | Lack of Audit and Telemetry | ✅ Covered (core) | Centralized audit log |
| MCP09 | Shadow MCP Servers | ✅ Covered | Operator-provided target probing, risk scoring, lifecycle management |
| MCP10 | Context Injection & Over-Sharing | ✅ Covered | In-place PII redaction (12 rules), volume anomaly detection, per-key thresholds |

**10 of 10 fully covered.**

---

## Key Real-World Incidents

**postmark-mcp supply chain attack (Sep 2025):** A fake npm package impersonated Postmark's email service, silently BCC'ing every agent-sent email to an attacker. Interlock's baseline + drift detection catches when a trusted tool's behavior changes. *(Source: CSO Online)*

**CyberArk Full-Schema Poisoning (Dec 2025):** Demonstrated that every field in a tool schema — not just descriptions — is an attack vector. Interlock baselines every schema field and detects changes at the field level. *(Source: CyberArk "Poison Everywhere")*

**Endor Labs MCP Dependency Report:** Among 2,614 MCP implementations, 82% use filesystem operations prone to path traversal, 67% use code injection-prone APIs, 34% use command injection-prone APIs. *(Source: Endor Labs)*

---

## Sources

- OWASP MCP Top 10: https://owasp.org/www-project-mcp-top-10/
- OWASP MCP03 Tool Poisoning: https://owasp.org/www-project-mcp-top-10/2025/MCP03-2025–Tool-Poisoning
- OWASP MCP09 Shadow Servers: https://owasp.org/www-project-mcp-top-10/2025/MCP09-2025–Shadow-MCP-Servers
- CyberArk "Poison Everywhere": https://www.cyberark.com/resources/threat-research-blog/poison-everywhere-no-output-from-your-mcp-server-is-safe
- Endor Labs MCP AppSec Report: https://www.endorlabs.com/learn/classic-vulnerabilities-meet-ai-infrastructure-why-mcp-needs-appsec
- postmark-mcp incident: https://www.csoonline.com/article/4064009/trust-in-mcp-takes-first-in-the-wild-hit-via-squatted-postmark-connector.html
