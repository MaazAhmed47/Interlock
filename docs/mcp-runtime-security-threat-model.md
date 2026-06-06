# MCP Runtime Security Threat Model

Model Context Protocol (MCP) changes the security boundary for AI agents. An MCP server is not just a passive data source. It can expose tools that read data, write data, call APIs, execute workflows, and use credentials on behalf of a user, service account, or organization.

That makes MCP security a runtime problem, not only an admission-time or prompt-filtering problem. Once an agent can call tools, the system needs controls that decide whether a tool call should proceed, be monitored, be held for review, or be blocked before execution.

## Why MCP is different

MCP servers expose active execution surfaces. A tool definition can describe what a tool is expected to do, but the risk appears when an agent chooses and invokes that tool in context.

Important runtime questions include:

* Is this still the same tool that was approved?
* Did the tool schema, metadata, permissions, or behavior change?
* Is the calling agent allowed to use this tool for this purpose?
* Could the tool response carry prompt injection, secrets, PII, or excessive data?
* Is there enough audit evidence to explain what happened later?

## Key risks

### Prompt injection through tool context

Tool descriptions, metadata, retrieved documents, and tool responses can carry instructions that try to influence the agent. A tool can look useful while embedding text that asks the model to ignore prior instructions, reveal secrets, or call additional tools.

### Runtime exfiltration through legitimate tool calls

Exfiltration does not always require an obviously malicious prompt. An approved tool can be used in a risky way, such as exporting internal data, sending sensitive records to an external destination, or returning more data than the agent needs.

### Tool poisoning and malicious metadata

Tool names, descriptions, schemas, annotations, and examples can influence agent tool selection. Malicious or misleading metadata can steer an agent toward unsafe behavior even before the tool executes.

### Permission creep and tool drift

A tool approved under one contract can later gain broader permissions, new required parameters, external reach, sensitive data access, or mutating behavior. If policy only remembers the tool name, the changed tool may still look trusted.

### Shadow MCP servers

Teams may run MCP servers outside the expected inventory or gateway path. These unmanaged servers can bypass review, policy, logging, and drift detection.

### Weak visibility and audit gaps

Without runtime logs, teams may not know which agent called which tool, what decision was made, what data moved, whether drift was detected, or why a call was blocked.

### Config-as-execution authority in local stdio setups

Local MCP configurations can grant agents access to commands, files, credentials, and developer tools. A config entry can become an execution path, especially when it launches local processes or connects to privileged services.

## Recommended controls

Interlock maps these risks to runtime controls that can be evaluated in front of MCP tools:

| Control | Interlock capability |
| --- | --- |
| Centralized gateway | Route MCP tool calls through one enforcement point before execution. |
| Deny-by-default policy | Reject unknown, unverified, blocked, or out-of-policy tool calls. |
| Role-aware policy / RBAC | Apply different tool permissions for different agent or operator roles. |
| Tool baselines and metadata drift detection | Record approved tool contracts and detect security-relevant changes. |
| Quarantine before execution | Hold or block risky changed tools before the agent can call them. |
| Response scanning | Inspect outputs for injection, secrets, PII, and oversized responses. |
| API key enforcement | Protect runtime APIs and real-time feeds with API keys. |
| Tamper-evident audit logs | Record allow, deny, monitor, and quarantine decisions with integrity checks. |
| Security Receipts | Preserve evidence for drift, policy, and quarantine decisions. |
| Webhook / SIEM-ready events | Send runtime decisions to external monitoring and incident response systems. |

## What Interlock focuses on

Interlock does not try to solve every MCP security problem. Its core wedge is runtime trust: verifying that an approved MCP tool is still the same trusted tool before an agent executes it.

That means Interlock focuses on:

* tool baselines at approval or discovery time
* post-approval schema, metadata, capability, and behavior drift
* runtime policy enforcement before tool execution
* quarantine or denial when trust boundaries are crossed
* audit evidence that explains the decision

## Drift examples

Examples of security-relevant drift include:

* read-only to write
* internal-only to external
* deterministic to non-deterministic
* idempotent to non-idempotent
* cheap operation to expensive operation
* no sensitive data to sensitive data access
* schema or metadata changed after approval
* new required parameters
* new side effects, such as sending email, writing files, creating tickets, or changing state

Not every metadata change is dangerous. Changes inside an approved capability envelope may be normal versioning. Changes that expand authority, data access, external reach, side effects, cost, or operational impact should trigger review, deferred execution, quarantine, or denial depending on policy.

## Disclaimer

This document summarizes common MCP security patterns and design considerations. It is not a formal standard, certification, or endorsement. Interlock is not affiliated with or endorsed by OWASP or the Model Context Protocol project.
