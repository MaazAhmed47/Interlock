# Interlock Design-Partner Pilot

## Purpose and boundary

This kit is for a small technical team that already operates an agent or MCP
workflow with a meaningful tool boundary: access to data, code, infrastructure,
communications, money movement, or another action whose authority can change.
The pilot asks one bounded question:

> In the named non-production workflow and documented route, can Interlock
> produce useful evidence of a security-relevant post-approval tool change and,
> where the selected control has a pre-forward enforcement point, hold later
> gateway-mediated use at an acceptable operational cost?

The authoritative product boundary is the [Control Contract](control-contract.md).
The [Control Effectiveness Evidence](control-effectiveness-evidence.md) page
explains why results from different control paths must not be combined into a
single score.

This runbook operationalizes the existing
[30-day design-partner evaluation](design-partner-evaluation.md). If an artifact
appears to conflict with the Control Contract or a profile-specific limitation,
use the narrower claim and stop for review.

This is a design-partner evaluation, not a production deployment, security
audit, penetration test, endorsement, certification, customer reference, or
public partnership. Completing it creates none of those statuses. Any public
claim, logo use, case study, customer reference, or description of a
partnership requires separate written approval from both parties.

### Not a fit

Do not run this pilot merely to generate a security badge or a favorable
metric. It is not a fit when the team has no material agent/tool risk, cannot
name the person who owns a tool-drift incident, cannot isolate non-production
data and credentials, cannot identify the intended MCP route, or cannot safely
restore the pre-pilot path. Use the [discovery gates](design-partner-discovery.md)
before installing anything.

## Audited support boundary

The repository currently exposes two primary MCP entry paths:

- `POST /mcp/call`, an Interlock JSON gateway API for a registered server and
  tool; and
- `/mcp/stream/{server_id}`, a scoped, stateless MCP `2026-07-28` tools profile
  over Streamable HTTP POST with JSON responses.

Registered upstreams use either the default legacy bare JSON-RPC adapter or an
explicitly pinned `2026-07-28` profile. Modern upstream responses may be JSON or
bounded SSE; Interlock does not expose inbound SSE streams or MCP sessions on
its normal `2026-07-28` endpoint. Pagination, MRTR, resources, prompts,
subscriptions, Tasks, Apps, the standard MCP OAuth framework, and full MCP
conformance are not supported claims. The exact protocol boundary and named
tests are in [MCP 2026 compatibility](mcp-2026-compatibility.md) and the
[requirements matrix](mcp-2026-requirements-matrix.md).

The repository contains a Docker image, local Compose paths, and a Helm chart;
the CI workflow builds or renders those artifacts. Artifact presence is not
deployment enforcement evidence. The stronger network-enforcement evidence is
limited to the separate Docker Phase 2 and local kind reference profiles
described below. See the [CI workflow](../.github/workflows/tests.yml),
[production-readiness limits](production-readiness.md), and the exact
[Kubernetes reference profile](../deploy/kubernetes-enforcement/README.md).

## Capability and limitation matrix

| Control or workflow | Current Interlock behavior | Evidence type | Deployment precondition | Known limitation / bypass condition | Pilot validation method |
| --- | --- | --- | --- | --- | --- |
| Tool-definition and metadata drift | A successful discovery refresh compares a registered tool's observed surface with its stored approved boundary. Material changes can deny or quarantine the affected tool. [Source](../core/mcp_drift.py) [gateway path](../core/mcp_gateway.py) | Unit/integration tests and bundled local proof. [Tests](../tests/test_mcp_drift.py) [gateway tests](../tests/test_mcp_gateway.py) [offline evaluator](evaluator-quickstart.md) | Register, verify, discover, and explicitly approve one named server/tool; repeat discovery after the controlled change. | A mutation is not observed until a supported refresh succeeds. Unchanged definitions do not establish unchanged behavior. Direct calls bypass the comparison. | Baseline one synthetic read-only tool, change one approved surface field, rediscover, and retain the before/after hashes and drift receipt. |
| Effective-permission change | An explicitly enabled non-production probe normalizes a supported result; an expected denial becoming allowed is classified as effective-permission or behavioral-scope drift and can quarantine later use. [Source](../core/effective_permission.py) | Controlled synthetic tests, including `403 -> 200`, inconclusive outcomes, and evidence-safe storage. [Tests](../tests/test_effective_permission_probes.py) | Server is stored as non-production and probe-enabled; key has `mcp.probe`; the operator supplies a safe canary and safety note. | The probe is forwarded to learn the result. Timeouts, rate limits, malformed results, and network errors are inconclusive, not detection. This is not generic OAuth introspection. | Run only the agreed synthetic denial-to-allow canary, verify the probe receipt, then test a later mediated call to the same quarantined tool. |
| Destination-aware argument drift | For a known tool with an approved destination profile, a new external destination can be denied before upstream forwarding; a new destination with sensitive-payload indicators can quarantine the tool. [Source](../core/external_reach.py) | Runtime tests with upstream-call counters and evidence-safe storage assertions. [Tests](../tests/test_external_reach_runtime.py) | The call traverses `/mcp/call`; the tool has a supported approved destination profile; destination information is visible in supported arguments. | Internal destination changes are not findings in this layer. Opaque, indirect, encrypted, or unobserved destinations and direct routes remain outside it. | Use synthetic hosts or identifiers, assert the unsafe call's upstream delta is zero, and inspect the receipt without retaining raw URLs or payloads. |
| Response, reported-effect, and provider-readback drift | Supported response exposure can be blocked before release to the agent. Reported-effect and explicit provider-readback changes can quarantine later use after the observed call. [Gateway source](../core/mcp_gateway.py) [readback source](../core/effect_readback.py) | Runtime regression suites for response, effect, and readback paths. [Response tests](../tests/test_response_drift_runtime.py) [effect tests](../tests/test_effect_drift_runtime.py) [readback tests](../tests/test_effect_readback_runtime.py) | A supported evidence profile exists. Readback requires a non-production, probe-enabled server, safe target/readback tools, and a safety note. | These are post-call observations. They cannot undo the first side effect, prove causality, or infer facts absent from the trusted evidence source. | Exercise one synthetic exposure or no-change readback case; record whether the result was blocked, detected only, inconclusive, or not exercised. |
| Quarantine and hold | Quarantine is scoped to `(server_id, tool_name)`. A later gateway-mediated call to that quarantined tool is refused before Interlock builds and forwards the upstream call; unrelated eligible tools remain available. [Source](../core/mcp_gateway.py) | Gateway and four-claim receipt tests with upstream execution checks. [Gateway tests](../tests/test_mcp_gateway.py) [claim tests](../tests/test_receipt_claims.py) | The agent uses Interlock's gateway path and the same stored server/tool identity; detection or an authorized operator has set quarantine state. | It is not a server-wide pause. Direct agent-to-server calls, alternate credentials, renamed tools, or other paths are outside this hold unless the deployment separately prevents them. | After controlled drift, call the same tool through Interlock and prove zero upstream execution delta; call one unaffected tool as a positive control. |
| Security Receipts, audit export, and verification | MCP audit events are hash-chained. Authenticated routes expose one receipt, a four-claim view, retained canonical surface evidence, context-bound verification, and bounded JSON batch export. [Routes](../routes/audit.py) [builder](../core/receipt.py) [verifier](../core/receipt_verify.py) | Tamper, export, claim, and replay/substitution tests. [Receipt tests](../tests/test_security_receipt.py) [binding tests](../tests/test_receipt_replay.py) | Use keys with `audit.read` or `audit.export`; retain the relevant audit rows and surface snapshots; record the exact source revision and context. | Hash-chain integrity is not external signing, trusted timestamping, WORM storage, independent anchoring, attestation, or certification. Deletion/retention and host compromise remain operator concerns. | Export the selected JSON receipts, verify the chain and presented context, mutate a copy to prove rejection, and preserve the original read-only. |
| Default runtime identity and authorization binding | Raw API keys are hashed at rest. Runtime key identity and stored role, not a conflicting request-body role, drive gateway authorization and are included in audit/receipt context. [DB source](../core/db.py) [gateway integration](integrations/agent-clients.md) | Principal, role, scope, revocation, and receipt tests. [Principal tests](../tests/test_mcp_principal_binding.py) [scope tests](../tests/test_mcp_scope_authorization.py) | Issue separate least-privilege keys for control-plane, runtime, and audit use; bind the intended role; protect the bootstrap admin credential. | API-key binding does not establish end-user identity, enterprise IdP assurance, workload attestation, or a comprehensive OAuth lifecycle. The normal MCP `2026-07-28` endpoint is stateless and creates no MCP session. | Attempt a conflicting body role, verify it is ignored, inspect the resolved principal/role in a receipt, and revoke the test key. |
| Experimental EMA identity/session path | When separately enabled, the experimental path validates a constrained bearer-token profile and binds a server-generated session to normalized authority context. [Design boundary](experimental-ema-authority-evidence.md) | Auth, session-substitution, expiry, rotation, and transport tests. [Auth tests](../tests/test_ema_auth.py) [session tests](../tests/test_ema_sessions.py) [transport tests](../tests/test_ema_streamable_http.py) | Explicit experimental EMA configuration, controlled issuer/JWKS, and its separate resource path. | Experimental and not the default pilot path. Tests do not prove a partner IdP integration, production federation, general OAuth support, or identity assurance outside the configured profile. | Default to not exercised. If separately scoped, use a disposable issuer and record each verified claim/binding without retaining raw tokens. |
| Operator-targeted shadow MCP discovery | An opt-in scanner probes only administrator-supplied targets, records an unregistered MCP-like endpoint, and supports a review lifecycle with chained audit events. [Source](../core/shadow_scanner.py) | Unit tests for targets, failures, risk facts, deduplication, disablement, and audit chaining. [Scanner tests](../tests/test_shadow_scanner.py) [audit tests](../tests/test_shadow_audit_chain.py) | The operator supplies and authorizes exact target URLs; background scanning is explicitly enabled; outbound policy permits the targets. | This is not autonomous network discovery, traffic interception, or proof that all unmanaged MCP paths were found. Non-responding and unlisted targets remain unknown. | Add only agreed synthetic/non-production targets, include registered and unregistered controls, review the finding, then disable the target. |
| Application-layer outbound URL guard and enforced-client plumbing | The URL guard rejects non-global address classes and guarded HTTP clients ignore ambient proxy variables. The explicit `enforced` profile requires a forward proxy and has no direct application fallback. [Boundary](outbound-destination-security.md) [URL source](../core/url_security.py) [HTTP factory](../core/outbound_http.py) | URL-resolution, client-factory, inventory, and runtime-plumbing tests. [Resolution tests](../tests/test_outbound_url_resolution.py) [factory tests](../tests/test_outbound_http_factory.py) [inventory tests](../tests/test_outbound_inventory_contract.py) | Correct profile/configuration and coverage by the enumerated HTTP client factory; for connection-time enforcement, a validated proxy plus deployment-level direct-egress denial. | Phase 1 validation and connection resolve separately and are not secure against DNS rebinding. Unenumerated protocols, an allowed destination, or missing deployment isolation can bypass the intended boundary. | In the normal pilot, inspect configuration and run focused tests only. Do not claim connection-time enforcement unless the exact Docker reference profile is reproduced. |
| Docker Phase 2 egress reference profile | In the checked-in Docker topology, Interlock's enumerated HTTP(S) paths are forced through a pinned non-intercepting Squid proxy while the application network has isolated IPv4/IPv6 gateway modes and no default gateway route. [Profile](../deploy/phase2-docker/compose.yaml) [boundary](outbound-destination-security.md) | Disposable live Docker acceptance plus an independent retained-evidence verifier and CI job. [Profile tests](../tests/test_phase2_docker_profile.py) [verifier tests](../tests/test_phase2_evidence_verifier.py) | Clean source; Docker Engine 28+ and Compose 2.33.1+; exact profile, policy, images, source identity, and synthetic services. | Docker reference-profile evidence only. It is not universal SSRF or DNS-rebinding prevention, Render, Kubernetes, customer-network, unenumerated-protocol, or allowed-destination enforcement. A theoretical proxy-cache race remains outside tested conditions. | Reproduce only in a disposable local environment, retain the bounded report, run the independent verifier, and label any missing/skipped case as no evidence. |
| Kubernetes enforcement reference profile | The local lab proves the exact agent-to-gateway-to-test-server path is allowed while named direct pod/service paths are denied under restored NetworkPolicies, with policy-off reachability and evidence-integrity controls. [Profile and limits](../deploy/kubernetes-enforcement/README.md) | Disposable live kind acceptance, canonical live NetworkPolicy evidence, independent verification, and CI. [Profile tests](../tests/test_kubernetes_enforcement_profile.py) [evidence tests](../tests/test_kubernetes_enforcement_evidence.py) | Exactly kind v0.33.0, Kubernetes v1.36.4, Calico v3.32.2, pinned images/manifests, real pods, clean source, and the runner-owned cluster. | It does not prove production, managed Kubernetes, other CNIs, cloud firewalls, tenant isolation, mTLS, identity assurance, universal bypass prevention, or compliance. Packets blocked before the gateway create no Interlock audit event. | Reproduce only with the supplied runner in its uniquely named disposable cluster; require all live positive/restoration controls and independent verification. |
| MCP protocol and transport profile | Interlock exposes stateless `server/discover`, `tools/list`, and `tools/call` for the scoped `2026-07-28` Streamable HTTP tools profile and preserves a separate `/mcp/call` JSON gateway route. Explicit modern upstreams use JSON or bounded SSE; default upstream registration is legacy bare JSON-RPC. [Compatibility](mcp-2026-compatibility.md) | Core-profile, eligibility, upstream-profile, and integration tests, with optional version-pinned SDK probes. [Requirements](mcp-2026-requirements-matrix.md) [integration tests](../tests/test_streamable_mcp_integration.py) | Pin client, SDK, upstream profile, server identity, endpoint, and protocol version; absence of an optional SDK dependency is a skip, not interoperability evidence. | No full MCP conformance, inbound SSE/resumption, normal-profile sessions, pagination, MRTR, resources, prompts, subscriptions, Tasks, Apps, or protection of direct connections. | Run the focused compatibility gate for the exact client/upstream versions; record skips separately; also test unsupported lifecycle and pagination failure cases. |
| Runtime packaging and state backends | The repository provides Python/Uvicorn startup, a Docker image and local Compose stack, a Helm chart, SQLite for local/small evaluation, Postgres through `DATABASE_URL`, and optional Redis-backed shared rate limiting. [Install](../INSTALL.md) [production boundary](production-readiness.md) [CI](../.github/workflows/tests.yml) | CI build/render jobs and focused database, Postgres-schema, Redis-health, Docker, and Helm tests. [DB tests](../tests/test_db.py) [Postgres tests](../tests/test_postgres_schema.py) [Redis tests](../tests/test_redis_health.py) [Helm tests](../tests/test_helm_metadata.py) | Pin the source and runtime; keep a small pilot single-worker unless Redis is configured; use a disposable database or isolated schema/account. | Packaging and green CI do not prove a customer deployment, backup/restore, multi-replica correctness, high availability, managed-service equivalence, production support, or SLA. The chart is a production-oriented template, not managed Kubernetes evidence. | For the default pilot, use one isolated instance, verify health plus a real read/write/revoke smoke test, record the backend/rate-limit mode, and rehearse teardown. |
| OpenCode local adapter example | A local stdio adapter exposes selected Interlock REST operations as MCP tools for OpenCode and keeps the effective runtime role bound to the Interlock API key. [Guide](integrations/opencode.md) [adapter](../examples/opencode/interlock_mcp_adapter.py) | Focused unit tests for caller-role exclusion and separation of the admin audit key. [Tests](../tests/test_opencode_adapter_auth.py) | Local demo/integration environment, already registered and verified target server, separate runtime/admin keys, and the documented OpenCode configuration. | The tests do not establish end-to-end OpenCode interoperability, autonomous agent behavior, production hardening, or an approval guarantee beyond the underlying Interlock paths. | Default to not exercised unless OpenCode is the named client; then run only with synthetic tools and separately verify all downstream gateway receipts. |
| LiveKit Agents compatibility adapter proof | A local stdio compatibility adapter connects LiveKit Agents 1.6.10 and MCP SDK 1.28.1's real `MCPToolset`, attached to a real `Agent`, to `/mcp/call`; the harness directly invokes the discovered wrapper and demonstrates tool-scoped drift/hold against a synthetic upstream. [Proof boundary](../examples/livekit_agents/README.md) [pinned inputs](../examples/livekit_agents/requirements-pinned.txt) [adapter](../examples/livekit_agents/adapter.py) | Local synthetic end-to-end and failure-path tests. [Tests](../tests/test_livekit_agents_integration.py) | Exact pinned dependencies, loopback-only disposable services, synthetic data, runner sequencing, and the local adapter. | The proof does not start an `AgentSession`, use an LLM for selection, prove native LiveKit/Interlock interoperability, provide adapter-level approval enforcement, or constitute LiveKit endorsement/partnership/customer validation. | Run the supplied proof unchanged, verify execution counters and receipt context, clean up with the marker-guarded command, and preserve the limitations with the result. |
| SIEM and webhook alert delivery | Scan-result alerts can be sent to Slack, Datadog, Splunk HEC, Elastic, PagerDuty, Sumo Logic, or a generic webhook; content is redacted by default and dispatch failure does not raise into the scan path. [Integration boundary](siem-integrations.md) [source](../core/siem.py) | Formatter/redaction and dispatch tests. [Redaction tests](../tests/test_siem_redaction.py) | Per-key approved destination configuration, credentials, retention decision, network reachability, and a scoped `admin` test caller. | This is scan-alert dispatch, not a claim that every MCP audit/receipt is exported to SIEM. Enabling content previews is a sensitive-data export. Private/on-prem destinations conflict with the Phase 1 production URL guard unless an approved deployment relay is used. | Send one synthetic test event to a non-production sink, confirm default redaction and failure isolation, and export MCP receipts separately through the audit API. |

## Claims this pilot does not establish

No pilot result should be represented as proof of:

- production enforcement or production readiness;
- bypass resistance outside the tested gateway, Docker, or local kind path;
- managed Kubernetes behavior or equivalence across CNI/cloud/network stacks;
- prevention of every SSRF path or universal DNS-rebinding prevention;
- full provenance, causal attribution, or end-to-end taint tracking;
- universal prompt-injection prevention, comprehensive DLP, or full MCP security;
- compliance certification, independent attestation, or third-party audit;
- backend deployment-SHA provenance from an availability/health response;
- multi-tenant isolation, high availability, disaster recovery, SLA, or support
  response performance; or
- a production false-positive rate, detection rate, benchmark result, security
  percentage, compliance grade, or ROI.

These boundaries are consistent with the [Control Contract](control-contract.md),
[production-readiness checklist](production-readiness.md),
[compliance posture](compliance-posture.md), and
[outbound security limits](outbound-destination-security.md).

## Pilot runbook

No phase uses production credentials, customer data, irreversible actions, or
an existing production/managed cluster. Broad network-policy changes are out of
scope. Use synthetic or explicitly approved non-sensitive data throughout.

### Phase 1: Architecture and threat-model review

**Goal.** Decide whether there is one real, bounded tool-drift question worth
testing and whether the route can be evaluated safely.

**Inputs.** Completed [discovery questionnaire](design-partner-discovery.md),
current architecture diagram, tool inventory, exact protocol/client/server
versions, credential and identity model, data classification, incident owner,
rollback owner, and proposed success/stop criteria.

**Exact actions.**

1. Draw every known agent-to-tool path, including direct MCP, fallback, admin,
   adapter, and alternate-credential routes.
2. Select one server and the smallest meaningful tool set; classify each tool's
   reads, writes, external effects, and irreversible actions.
3. Pin the Interlock revision, protocol/transport, upstream profile, deployment
   profile, and evidence-retention location.
4. Choose one safe surface-drift case and, only if justified, one supported
   behavioral canary. Define the expected `held`, `detected only`,
   `inconclusive`, or `out of scope` outcome before testing.
5. Walk through traffic rollback, key revocation, state restoration, and the
   incident escalation path without changing live routing.

**Evidence collected.** Versioned diagram; path inventory; tool boundary;
threat cases; data/credential declaration; owner list; written success, stop,
and rollback criteria; GO/PARTIAL/NO-GO result.

**Exit criteria.** GO requires an accountable technical owner, bounded
non-production environment, known tool boundary, and safe rollback path. The
selected test must be reversible or have no external side effect.

**Stop conditions.** Unknown ownership; production-only reproduction; customer
data or production credentials required; unbounded direct paths; ambiguous CNI
or network ownership; irreversible test; no rollback owner; or a request to
turn technical evidence into an audit/certification claim.

**Rollback.** No runtime change should exist. Destroy any draft credentials or
temporary diagrams that contain sensitive details and record the decision.

**Owners.** The partner technical owner supplies and approves the architecture,
scope, and risk acceptance. The Interlock owner maps claims to repository
evidence and rejects unsupported scope. The rollback owner has final authority
to stop the pilot.

### Phase 2: Read-only and shadow observation

**Goal.** Establish visibility and operational fit without putting Interlock in
a blocking path for an active workflow.

**Inputs.** Phase 1 GO, isolated environment, synthetic/non-sensitive server and
tool inventory, separate least-privilege pilot keys, approved evidence store,
and baseline observation window.

**Exact actions.**

1. Deploy the pinned revision only in the bounded pilot environment; keep the
   existing workflow route unchanged.
2. Register and inspect the selected non-production server, run read-only
   discovery, and record the observed tool surface. Do not execute mutation or
   write-capable tools.
3. If operator-targeted shadow discovery is in scope, add only the exact
   approved targets and include one registered and one synthetic unregistered
   control. It does not scan the network generally.
4. Review generated audit records, receipt fields, storage, access, and
   redaction with the partner. Test export only with synthetic evidence.
5. Measure baseline discovery/inspection availability and review burden. Mark
   unknown paths rather than assuming coverage.

**Evidence collected.** Registered-versus-unmanaged path inventory; discovered
surface hashes; audit/receipt samples; redaction review; baseline timing;
failures and unknowns. No blocking outcome counts as Phase 2 success.

**Exit criteria.** The team can explain what Interlock observed, what it did not
observe, who can access evidence, and how the pilot components are removed.

**Stop conditions.** Any production credential or customer record appears;
unexpected write/tool execution; the gateway becomes a blocking dependency;
an unapproved target is probed; evidence contains unapproved sensitive content;
or availability degrades beyond the pre-agreed threshold.

**Rollback.** Disable shadow targets, stop the isolated deployment, revoke pilot
keys, restore the unchanged route if any test client was redirected, and retain
or delete artifacts according to the written handling agreement.

**Owners.** The partner operator controls targets and credentials and reviews
logs daily. The Interlock owner explains fields and limitations. The rollback
owner can terminate observation immediately.

### Phase 3: Controlled drift or policy exercise

**Goal.** Reproduce one material change with synthetic/non-sensitive data and
determine whether the selected control produces the pre-agreed evidence and
disposition.

**Inputs.** Phase 2 exit, written test case, disposable upstream or bundled
fixture, expected result, execution counter or equivalent positive control,
and artifact directory.

**Exact actions.**

1. Run the [offline evaluator](evaluator-quickstart.md) or an equivalently
   bounded synthetic server to approve one read-only boundary.
2. Make exactly one reversible surface change and explicitly refresh discovery.
3. Verify the drift finding and tool-scoped quarantine, then attempt a later
   gateway-mediated call to the same tool and confirm zero upstream execution
   delta. Exercise an unaffected tool as a positive control.
4. Export and verify the receipt and audit chain; mutate only a copied artifact
   to demonstrate verification failure.
5. If the team separately approved an effective-permission or readback case,
   run the non-production canary once and label the first call as forwarded.
   Never substitute an irreversible or sensitive action.

**Evidence collected.** Exact revision/config identity; before/after surface or
behavior evidence; discovery result; finding; quarantine state; upstream
counter; unaffected-tool control; receipts; verification outputs; timing;
operator review notes.

**Exit criteria.** Every expected fact is either evidenced or explicitly marked
failed, inconclusive, not exercised, or out of scope. The environment returns
to its pre-exercise tool state, and the operator can explain the first-call
boundary for behavioral observations.

**Stop conditions.** Unexpected external effect; loss of the execution counter
or positive control; failed discovery; missing audit/receipt; sensitive data in
an artifact; ambiguous tool identity; any skipped verifier case; or pressure to
generalize the result beyond the named path.

**Rollback.** Restore the synthetic upstream, keep the affected tool
quarantined until review, restore or explicitly re-approve only the known prior
boundary, revoke exercise credentials, and preserve original evidence
read-only. If state cannot be explained, destroy the disposable environment
and record no result.

**Owners.** The partner test owner authorizes the exact mutation and watches
external systems. The Interlock owner runs or observes the evidence checks. The
approval owner alone may change the stored baseline; the rollback owner can
abort before every action.

### Phase 4: Optional narrowly scoped enforcement

**Goal.** Decide whether one low-impact non-production tool path can use
Interlock as an enforcement dependency under written acceptance and tested
rollback.

**Inputs.** Written acceptance of Phase 3 findings and limitations, successful
rollback rehearsal, approved maintenance window, one read-only or otherwise
reversible tool, monitoring, and explicit stop thresholds.

**Exact actions.**

1. Reconfirm the route and direct-path inventory immediately before the window.
2. Route only the named non-production tool through Interlock; do not broaden
   network policy or credentials.
3. Verify a normal allowed call, one safe deny/quarantine case, an unaffected
   path, evidence creation, and the actual rollback command/path.
4. Measure availability and latency using the method declared in the
   [scorecard](design-partner-scorecard.md). Review every hold; do not automate
   baseline approval.
5. End the window, execute or rehearse rollback as agreed, and record the
   operator decision: stop, revise, repeat bounded evaluation, or consider a
   separately scoped next step.

**Evidence collected.** Written acceptance; route proof; allowed/held/positive
controls; latency and availability samples with denominators; review burden;
bypasses/unknowns; rollback result; final operator decision.

**Exit criteria.** The named path behaved within pre-agreed thresholds,
rollback passed, every required evidence item is present, and no result is generalized to
production or other paths.

**Stop conditions.** Any irreversible effect; customer data; production
credential; unexpected direct path; failed rollback; unreviewed quarantine;
broad network-policy change; missing audit evidence; or threshold breach.

**Rollback.** Restore the previous application route, revoke pilot keys, stop
the pilot deployment, verify the original non-production path, and preserve
evidence according to retention policy. Interlock approval-state changes do not
undo upstream work.

**Owners.** The partner change owner controls the window and route. The partner
security owner reviews holds and evidence. The rollback owner executes the
reversal. The Interlock owner supports diagnosis but does not approve partner
risk on the partner's behalf.

## Security, privacy, and evidence handling

Never send these to Interlock public demos, public issues, shared pilot chat, or
unapproved support channels:

- production, customer, employee, patient, payment, or regulated data;
- API keys, admin tokens, bearer tokens, cookies, private keys, database/Redis
  URLs, webhook credentials, recovery codes, or `.env` contents;
- raw tool arguments/results, prompts, message bodies, SQL, manifests, internal
  hostnames/IPs, private repository content, or screenshots containing them;
- unrestricted production logs, detailed network diagrams, incident evidence,
  or vulnerability details.

Treat tool definitions, audit logs, receipts, surface snapshots, test reports,
and screenshots as potentially sensitive even when the product uses hashes or
redaction. Store each partner's artifacts separately with least-privilege
access, encryption in transit and at rest, a named custodian, an agreed
retention/deletion date, and an immutable original for verification. Do not put
pilot artifacts in the public repository. A hash proves only that compared
bytes have or have not changed under the implemented scheme; it does not make
the bytes non-sensitive.

Before sharing a screenshot or support request, crop unrelated applications
and redact secrets, personal data, account/workspace IDs, private URLs and IPs,
tool arguments/results, headers, query strings, filenames, and partner names.
Supply the exact Interlock commit, sanitized endpoint/module, timestamps, safe
reproduction steps, expected/actual outcome, and receipt or log hashes instead
of raw values. Rotate any secret that was exposed.

Report a suspected vulnerability privately as directed by the
[Security Policy](../SECURITY.md): do not open a public issue; email
`maaz@getinterlock.dev` with the affected revision/endpoint, safe reproduction,
expected/actual behavior, and the possible data class involved. Do not include
live secrets or customer records.

Security Receipt and hash-chain verification provide evidence-integrity checks
inside the documented Interlock boundary. They are not external attestation,
independent anchoring, a trusted timestamp, legal assurance, an audit opinion,
or a certification.

## Founder-facing outreach handoff

### Pilot invitation

Interlock is an early-stage MCP runtime trust layer for teams already operating
agent workflows with tools that can affect real systems. We are looking for one
technical design partner willing to test a narrow question: whether Interlock
can surface a meaningful post-approval tool change and produce useful review
evidence in a route you can actually map. The first pilot begins in a bounded
non-production or shadow environment with synthetic or explicitly approved
non-sensitive data. We will document bypasses, inconclusive results, operator
cost, and limits alongside successful holds. This is a joint technical
evaluation, not an audit, endorsement, certification, production-readiness
claim, or public partnership.

### Asynchronous CTO checklist

A CTO or security lead should be able to answer these before a call:

- Which agent, MCP client, server, transport, and three to ten tools are in
  scope?
- Which tool change would trigger your incident review, and who owns it?
- Can every scoped call be routed through an observable non-production path,
  and which direct/fallback paths remain?
- Which identity issues the tool authority, where are credentials held, and
  what least-privilege pilot credentials can be created?
- What synthetic or non-sensitive dataset and reversible action can reproduce
  the risk?
- Who owns rollback, what is the exact rollback path, and how quickly must it
  work?
- What evidence may be retained, where, for how long, and who may access it?
- What result would mean stop, revise, repeat, or consider a separate next
  step?

Use the full [discovery questionnaire](design-partner-discovery.md) and record
outcomes in the [operator scorecard](design-partner-scorecard.md).
