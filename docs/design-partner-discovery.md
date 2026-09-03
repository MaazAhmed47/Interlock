# Interlock Design-Partner Discovery and Qualification

## How to use this document

The accountable partner operator completes this questionnaire before any
installation or traffic change. Short answers are acceptable; unknown answers
are not failures, but they must remain visible. Do not include secrets,
production credentials, customer data, raw payloads, or confidential incident
artifacts. Use sanitized identifiers.

The evaluation boundary and evidence classes are defined in the
[pilot runbook](design-partner-pilot.md) and
[Control Contract](control-contract.md).

## Operator questionnaire

### 1. Agent and MCP architecture

- What agent runtime, orchestration framework, MCP client, and exact versions
  are in scope?
- Which MCP protocol/profile and transport does each hop use?
- Which server IDs, endpoints, adapters, proxies, and gateways are on the
  intended path?
- Is the proposed Interlock entry point `/mcp/call`,
  `/mcp/stream/{server_id}`, a local compatibility adapter, or another path?
- Which components discover tools, cache definitions, refresh them, and invoke
  them? What triggers rediscovery?
- Draw the request and response route, including failure/fallback behavior.

### 2. Tool inventory and action risk

- List the three to ten tools in scope with sanitized names and owners.
- For each tool, what can it read, create, update, delete, send, execute,
  deploy, schedule, approve, or charge?
- Which data classes and external destinations can it reach?
- Which action is irreversible or high-impact and therefore excluded from the
  pilot?
- What post-approval surface or behavioral change would be material enough to
  trigger incident review?
- Which one safe, reversible, synthetic case represents that risk?

### 3. Identity, authorization, and credentials

- What principal authorizes the agent, gateway, adapter, and upstream server?
- Are credentials per user, workload, agent, environment, server, or shared?
- Where are secrets issued, stored, rotated, revoked, and audited?
- Which Interlock runtime role and API-key scopes are required? Who may
  register, approve/rebaseline, call, probe, read audit, and export audit?
- Can separate least-privilege control-plane, runtime, audit, and synthetic
  upstream credentials be issued for the pilot?
- Does any request-body identity or role conflict with the authenticated
  principal? Which identity is authoritative?

### 4. Direct MCP and bypass paths

- Can the agent, adapter, worker, developer workstation, or server call the MCP
  server without Interlock?
- Are direct URLs, alternate DNS names/IPs, cached connections, secondary SDKs,
  local stdio servers, fallback routes, or alternate credentials available?
- Can a tool be renamed, duplicated, or reached through another server ID?
- What egress path exists for HTTP(S) and for unenumerated protocols?
- Which bypasses can be safely tested, and which remain unknown?
- Who owns remediation if a bypass is found?

### 5. Deployment and network topology

- Is the environment local process, Docker/Compose, Kubernetes, VM, or another
  topology? Is it strictly non-production?
- For Docker, what Engine/Compose versions, networks, gateway modes, proxy,
  DNS, host access, and published ports exist?
- For Kubernetes, what cluster type/version, CNI/version, namespace, workload
  identity, NetworkPolicies, service mesh, ingress/egress gateway, and DNS path
  exist?
- Who can change routing, CNI, firewall, proxy, DNS, or network policy?
- Which repository reference profile, if any, exactly matches the proposed
  test? Record every difference.
- Can the environment be destroyed without affecting customer or internal
  systems?

### 6. Audit, evidence, and SIEM

- Which events must be retained: discovery, approval, drift, allow, deny,
  monitor, quarantine, later hold, review, or export?
- Who may read/export receipts and canonical surface snapshots?
- What retention, deletion, encryption, legal hold, residency, and access-log
  rules apply?
- Is JSON receipt export sufficient for the pilot?
- Is a synthetic scan alert to Slack, Datadog, Splunk HEC, Elastic,
  PagerDuty, Sumo Logic, or generic webhook required? Do not assume that this
  exports all MCP audit events; receipt export is separate. See
  [SIEM boundaries](siem-integrations.md).
- What must be redacted from screenshots, tickets, and support requests?

### 7. Incident ownership and review workflow

- If a tool drifts, whose incident review is it? Name the role and person.
- Who owns the MCP server, agent, credentials, network, Interlock deployment,
  evidence, and business decision?
- Who can quarantine, approve a new baseline, keep the hold, or revoke access?
- What is the escalation channel and response window during the exercise?
- Which decision requires two-person review?
- Who has final stop authority?

### 8. Change and approval workflow

- How are tool definitions, server versions, permissions, credentials, and
  deployment changes currently reviewed?
- What exact evidence makes an approved baseline valid?
- How and when is rediscovery triggered after a change?
- Who may approve/rebaseline, and how is stale review prevented?
- How will intentional changes be distinguished from unreviewed drift?
- What change window and freeze conditions apply?

### 9. Data classification and environments

- Which synthetic or non-sensitive dataset is allowed?
- Confirm that production credentials, customer data, regulated data, and live
  incident content are prohibited.
- Which logs or tool definitions may still reveal confidential metadata?
- Is every endpoint isolated from production dependencies and accounts?
- What artifact location and deletion date are approved?
- What evidence may leave the partner environment, if any?

### 10. Success criteria and rollback

- What is the first useful evidence the operator expects, and how will its
  elapsed time be measured?
- Which cases should be held, detected only, inconclusive, or out of scope?
- What maximum false-positive review burden, latency, and availability impact
  is acceptable for the named phase?
- What finding or unknown causes an immediate stop?
- Who is the rollback owner and backup?
- What exact routing, key-revocation, state-restoration, and component-removal
  steps restore the pre-pilot condition?
- Has rollback been rehearsed without Interlock? What proves it worked?

## Required evidence before qualification

| Gate | Required fact | Acceptable evidence | Failure consequence |
| --- | --- | --- | --- |
| Accountable technical owner | One named person owns the tool-drift incident and can stop the pilot. | Written owner/backup and escalation path. | No controlled exercise. |
| Bounded non-production environment | The target contains no production credentials or customer data and can be destroyed safely. | Environment/account IDs in sanitized form, data classification, and teardown owner. | NO-GO. |
| Known tool boundary | The team can enumerate the server, route, tools, authority, direct paths, and expected material change. | Versioned diagram and tool/path inventory. | Architecture review only. |
| Safe rollback path | The prior route and credentials can be restored/revoked without an irreversible action. | Rehearsed steps, owner, expected duration, and positive verification. | NO-GO for traffic or enforcement. |
| Safe exercise | The selected change uses synthetic/non-sensitive data and has no irreversible external effect. | Written case, expected outcome, positive control, and stop point. | Replace the case or stop. |
| Evidence handling | Storage, access, redaction, retention, deletion, and sharing are approved. | Named custodian and written handling rule. | Do not collect pilot evidence. |

## Qualification decision

### GO

Use GO only when all four mandatory gates are satisfied: accountable technical
owner, bounded non-production environment, known tool boundary, and safe
rollback path. The safe exercise and evidence-handling gates must also be
closed before Phase 2 collects artifacts or Phase 3 changes a boundary. Record
the exact phase authorized; GO for architecture review is not GO for
enforcement.

### PARTIAL

Use PARTIAL when the risk is meaningful and ownership exists, but one or more
facts remain unknown or an evidence/rollback detail needs repair. PARTIAL may
continue only with architecture review and sanitized planning. It does not
authorize target probing, credentials, traffic routing, controlled drift, or
blocking enforcement. Name the owner and due date for each gap.

### NO-GO

Use NO-GO when no accountable owner exists; the only available environment or
credential is production; customer/sensitive data is required; the tool/route
cannot be bounded; rollback is unsafe; the exercise is irreversible; broad
network changes are required; or the team wants a certification, endorsement,
security score, or production claim from a limited evaluation. Record the
reason without collecting sensitive evidence.

## Decision record

| Field | Entry |
| --- | --- |
| Decision | `GO` / `PARTIAL` / `NO-GO` |
| Authorized phase | Architecture only / Phase 2 / Phase 3 / Phase 4 |
| Accountable technical owner | |
| Security reviewer | |
| Rollback owner and backup | |
| Non-production environment | |
| Named server/tool boundary | |
| Known bypass/direct paths | |
| Open unknowns | |
| Evidence custodian and deletion date | |
| Decision date | |
| Re-review trigger | |
