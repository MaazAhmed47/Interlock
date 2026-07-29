# MCP 2026-07-28 requirement traceability

This matrix is generated from the immutable MCP `2026-07-28` release at commit
`5f5440bb26a62e2cf3440b92da5a667efa03b267`. It covers the protocol roles that
Interlock actually performs: a stateless Streamable HTTP tools server and an
HTTP client for explicitly registered upstream tool servers. It is not a claim
that Interlock implements every MCP feature or protects direct connections that
bypass its gateway.

Status values have these exact meanings:

- **Implemented and tested**: an implementation and a named positive or
  negative regression test exist.
- **Implemented but untested**: code appears to implement the requirement, but
  this release has no direct test. No row is intentionally left in this state.
- **Unsupported by design**: Interlock recognizes the boundary and rejects it
  without fallback.
- **Not applicable because Interlock exposes no corresponding feature**: the
  requirement is conditional on a capability Interlock does not advertise.
- **Blocked by a concrete architectural limitation**: implementing the feature
  safely requires a design change to the approved-boundary model.

## Mandatory core protocol and applicable transport requirements

| Requirement | Normative source | Interlock status | User/security impact and smallest safe implementation | Test traceability | Product-boundary effect |
|---|---|---|---|---|---|
| Messages are UTF-8 JSON; non-standard numeric constants are not valid JSON | [Base protocol](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/5f5440bb26a62e2cf3440b92da5a667efa03b267/docs/specification/2026-07-28/basic/index.mdx) | Implemented and tested | Inbound JSON, outbound JSON, and SSE event data use strict decoding. `NaN` and infinities fail closed; bounded body and streaming limits apply before a complete response is retained. | `test_mcp_2026_core_profile.py::test_non_finite_numbers_are_rejected_as_invalid_json`; `test_streamable_mcp_integration.py::test_non_standard_json_numbers_are_parse_errors`; modern oversized-SSE and non-finite-upstream tests | None. This closes parser differentials and memory-amplification paths. |
| JSON-RPC 2.0 requests use unique string/integer, non-null IDs; responses match IDs and have exactly a result or valid error | [Base protocol](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/5f5440bb26a62e2cf3440b92da5a667efa03b267/docs/specification/2026-07-28/basic/index.mdx) | Implemented and tested | Malformed envelopes fail closed; malformed attacker-controlled IDs are not reflected. | `test_streamable_mcp_integration.py::test_duplicate_required_headers_malformed_ids_and_unissued_cursors_fail_closed`; `test_mcp_upstream_profiles.py::test_declared_2026_rejects_missing_jsonrpc_without_downgrade` | None. This hardens the existing boundary. |
| Successful results contain a recognized `resultType`; unknown types are invalid | [Base protocol](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/5f5440bb26a62e2cf3440b92da5a667efa03b267/docs/specification/2026-07-28/basic/index.mdx) | Implemented and tested | Interlock emits and accepts only `complete`; `input_required` and extension result types fail closed without retry. | `test_mcp_upstream_profiles.py::test_declared_2026_tool_call_rejects_missing_result_type`; streamable integration identity/result tests | None; unsupported result types do not create mutable retry state. |
| Each request carries protocol version and client capabilities in `_meta`; `clientInfo` is recommended and optional | [Base `_meta`](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/5f5440bb26a62e2cf3440b92da5a667efa03b267/docs/specification/2026-07-28/basic/index.mdx) and [schema](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/5f5440bb26a62e2cf3440b92da5a667efa03b267/schema/2026-07-28/schema.ts) | Implemented and tested | Missing/malformed required fields return HTTP 400 and `-32602`; optional known fields and metadata-key grammar are validated. Interlock never uses self-reported client identity for authorization. | `test_mcp_2026_core_profile.py::test_known_request_meta_fields_and_capability_shapes_are_validated`; `test_streamable_mcp_integration.py::test_missing_or_conflicting_per_request_meta_is_rejected`; optional-client-info test | None. |
| Servers do not infer state or capabilities from earlier requests | [Stateless operation](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/5f5440bb26a62e2cf3440b92da5a667efa03b267/docs/specification/2026-07-28/basic/index.mdx) | Implemented and tested | Every call is independently authenticated and self-describing. No MCP session state exists. | `test_streamable_mcp_integration.py::test_discover_list_and_allowed_call_are_stateless` | None; this is the existing constrained profile. |
| Unsupported versions return HTTP 400 and `-32022`; version/header mismatch returns HTTP 400 and `-32020` | [Versioning](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/5f5440bb26a62e2cf3440b92da5a667efa03b267/docs/specification/2026-07-28/basic/versioning.mdx) and [HTTP transport](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/5f5440bb26a62e2cf3440b92da5a667efa03b267/docs/specification/2026-07-28/basic/transports/streamable-http.mdx) | Implemented and tested | A declared modern peer is never retried as legacy. Duplicate required headers also fail closed. | streamable standard-header tests; upstream no-downgrade parameterization | None. |
| A 2026 server implements `server/discover` | [`server/discover`](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/5f5440bb26a62e2cf3440b92da5a667efa03b267/docs/specification/2026-07-28/server/discover.mdx) | Implemented and tested | Interlock advertises only the pinned version and its tools surface, with identity in result `_meta`. | Python/TypeScript SDK integration tests and stateless discovery test | None. |
| Streamable HTTP uses a single POST endpoint, validates Origin, authenticates, and accepts one JSON-RPC message per POST | [Streamable HTTP](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/5f5440bb26a62e2cf3440b92da5a667efa03b267/docs/specification/2026-07-28/basic/transports/streamable-http.mdx) | Implemented and tested | Invalid Origin is 403; body, credential, scope, and rate checks occur before tool execution. | `test_streamable_mcp_integration.py::test_auth_origin_body_and_audit_containment` | None. Interlock retains its API-key authorization model. |
| HTTP clients send `Accept: application/json, text/event-stream`; clients support either JSON or SSE responses | [Streamable HTTP sending/receiving](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/5f5440bb26a62e2cf3440b92da5a667efa03b267/docs/specification/2026-07-28/basic/transports/streamable-http.mdx) | Implemented and tested | Modern outbound requests advertise both. SSE parsing is bounded, does not expose notification content, rejects server requests/unrelated responses, and requires one matching final response. Interlock's inbound server deliberately chooses JSON. | SSE parser tests; `test_declared_2026_accepts_bounded_sse_without_downgrade`; malicious-SSE upstream test | No new advertised feature and no resumability state. |
| Required `MCP-Protocol-Version`, `Mcp-Method`, and conditional `Mcp-Name` values match the body; unsafe values use the Base64 sentinel | [HTTP request metadata](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/5f5440bb26a62e2cf3440b92da5a667efa03b267/docs/specification/2026-07-28/basic/transports/streamable-http.mdx) | Implemented and tested | Missing, duplicate, undecodable, injected, or mismatched values return HTTP 400 and `-32020`. | standard-header, encoded-name, duplicate-header, and upstream header encoding tests | None. |
| Streamable HTTP clients validate valid `x-mcp-header` annotations, exclude invalid definitions, and mirror primitive values; body-processing servers validate header/body equality | [HTTP parameter headers](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/5f5440bb26a62e2cf3440b92da5a667efa03b267/docs/specification/2026-07-28/basic/transports/streamable-http.mdx) and [tool definitions](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/5f5440bb26a62e2cf3440b92da5a667efa03b267/docs/specification/2026-07-28/server/tools.mdx) | Implemented and tested | Only statically reachable string/boolean/safe-integer annotations are accepted. Interlock validates inbound values, then reconstructs downstream headers from approved schema plus body; it never forwards arbitrary raw client headers. Invalid modern definitions reject discovery; legacy profiles remain blocked. | parameter-header helper tests; eligibility tests; modern upstream mirroring test; live inbound/rebuild test | Narrow transport support only. It does not forward credentials or arbitrary headers. |
| Modern HTTP ignores old `Mcp-Session-Id`/`Last-Event-ID`, never mints sessions, and normally rejects GET/DELETE | [Legacy compatibility](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/5f5440bb26a62e2cf3440b92da5a667efa03b267/docs/specification/2026-07-28/basic/transports/streamable-http.mdx) | Implemented and tested | Session lifecycle cannot be activated; GET/DELETE return 405. | removed-lifecycle and non-POST integration tests | None. Legacy clients must use the documented migration path. |
| Tool servers declare `tools`, return the authorization-specific available set deterministically, and accept `tools/list`/`tools/call` | [Tools](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/5f5440bb26a62e2cf3440b92da5a667efa03b267/docs/specification/2026-07-28/server/tools.mdx) | Implemented and tested | Listing is the sorted intersection of verified, active, allowlisted, schema-valid stored definitions. Calls use the same eligibility decision before the real gateway path. | streamable stateless, ineligible-tool, eligibility, and gateway-control tests | None; this is Interlock's product boundary. |
| Tool input/output schemas use JSON Schema 2020-12 by default, declared dialects are honored or gracefully rejected, schemas are valid, and network references are not auto-fetched | [JSON Schema usage](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/5f5440bb26a62e2cf3440b92da5a667efa03b267/docs/specification/2026-07-28/basic/index.mdx) | Implemented and tested for JSON Schema 2020-12; other dialects explicitly unsupported | Modern discovery rejects invalid/unsupported schemas and all non-local references. Calls validate bounded arguments before execution and declared structured output before release. | core-profile schema tests; invalid modern schema tests; pre-execution argument test; output-schema test | No external schema retrieval or new network path. Supporting additional dialects remains future work. |
| Complete `tools/call` results have valid content-block structure; declared structured output conforms to `outputSchema` | [Tool results](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/5f5440bb26a62e2cf3440b92da5a667efa03b267/docs/specification/2026-07-28/server/tools.mdx) | Implemented and tested | Malformed content and schema-mismatched structured output are blocked before the response crosses Interlock's gateway. | `test_complete_tool_result_content_blocks_are_structurally_validated`; output-schema upstream test | None; response inspection and receipt behavior remain in path. |
| Protocol errors use integer codes/messages and defined reserved codes only; unavailable tools do not disclose capability state | [Errors](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/5f5440bb26a62e2cf3440b92da5a667efa03b267/docs/specification/2026-07-28/basic/index.mdx) | Implemented and tested | Interlock emits only defined JSON-RPC/MCP codes. Tool absence, block, quarantine, inactive state, and metadata exclusion share one generic error. | error-envelope upstream tests; ineligible-tools integration test | None. `-32021` is not emitted because no exposed operation requires a client capability. |
| HTTP authorization follows the MCP authorization framework when used; custom authentication may be negotiated | [Authorization](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/5f5440bb26a62e2cf3440b92da5a667efa03b267/docs/specification/2026-07-28/basic/authorization/index.mdx) | Unsupported by design for the OAuth framework; implemented and tested for Interlock's custom per-request API-key authentication | Adding OAuth discovery/registration would broaden identity and token attack surface. The smallest current-safe behavior is explicit API-key auth plus existing scopes, rate limits, and upstream credential separation. | auth/origin containment; upstream auth-header collision and credential non-logging tests | OAuth support would materially broaden the product surface and is not needed for the scoped claim. |

## Conditional core features and optional extensions

| Feature | Requirement class and source | Interlock status | Impact, remediation, and required tests before support | Product-boundary/attack-surface decision |
|---|---|---|---|---|
| Legacy `initialize` / `notifications/initialized` | Removed from 2026 negotiation; see [versioning](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/5f5440bb26a62e2cf3440b92da5a667efa03b267/docs/specification/2026-07-28/basic/versioning.mdx) | Unsupported by design | Returns method-not-found; no fallback. | Reintroducing sessions would contradict the selected stateless profile. |
| Client-to-server notifications | Transport mechanism exists, but this revision defines none for Streamable HTTP; see [transport note](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/5f5440bb26a62e2cf3440b92da5a667efa03b267/docs/specification/2026-07-28/basic/transports/streamable-http.mdx) | Not applicable because Interlock exposes no corresponding feature | Unsupported notification POSTs return an HTTP error and no state changes. | No reason to add a notification surface. |
| Pagination | Optional cursor fields; clients SHOULD paginate and MUST treat even `""` as a cursor; see [pagination](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/5f5440bb26a62e2cf3440b92da5a667efa03b267/docs/specification/2026-07-28/server/utilities/pagination.mdx) | Blocked by a concrete architectural limitation | Any present `nextCursor`, including empty or null, rejects the observation. Safe support requires bounded page traversal, cursor-loop detection, one authorization context, deterministic aggregation, and an atomic complete-surface baseline, plus timeout/loop/auth-change tests. | Necessary future work for multi-page upstreams; accepting page one would weaken the trust boundary. |
| Progress | Receiver is not obligated to emit progress; see [progress](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/5f5440bb26a62e2cf3440b92da5a667efa03b267/docs/specification/2026-07-28/basic/patterns/progress.mdx) | Not applicable because Interlock exposes no corresponding feature | Valid `progressToken` metadata is accepted, but Interlock emits no progress notifications. | Emitting progress requires inbound SSE and lifecycle work with no trust-boundary benefit. |
| Cancellation | Optional general pattern; Streamable HTTP cancellation is closing an SSE response; see [cancellation](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/5f5440bb26a62e2cf3440b92da5a667efa03b267/docs/specification/2026-07-28/basic/patterns/cancellation.mdx) | Not applicable because Interlock exposes no corresponding feature | Interlock emits JSON responses, not inbound SSE streams. Outbound HTTP timeout/disconnect closes the upstream transport. | Explicit cancellation state is avoidable mutable state for this surface. |
| MRTR / `input_required` | Optional result for applicable operations; see [MRTR](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/5f5440bb26a62e2cf3440b92da5a667efa03b267/docs/specification/2026-07-28/basic/patterns/mrtr.mdx) | Unsupported by design | Unknown/non-complete result types fail closed. Support would require bounded input-request validation, retry correlation, authorization re-checks, and receipt semantics. | Material new state and server-to-client authority surface; deliberately omitted. |
| Resources | Capability-conditional server feature; see [resources](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/5f5440bb26a62e2cf3440b92da5a667efa03b267/docs/specification/2026-07-28/server/resources.mdx) | Not applicable because Interlock exposes no corresponding feature | Not advertised; methods return method-not-found. | Would expand beyond the approved tool-boundary product scope. |
| Prompts | Capability-conditional server feature; see [prompts](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/5f5440bb26a62e2cf3440b92da5a667efa03b267/docs/specification/2026-07-28/server/prompts.mdx) | Not applicable because Interlock exposes no corresponding feature | Not advertised; methods return method-not-found. | Would expand beyond the tool boundary. |
| Logging | Capability-conditional and deprecated in 2026; see [logging](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/5f5440bb26a62e2cf3440b92da5a667efa03b267/docs/specification/2026-07-28/server/utilities/logging.mdx) | Not applicable because Interlock exposes no corresponding feature | No logging capability or SSE log notifications. Valid optional log-level metadata is structurally accepted. | Avoids leaking operational state to MCP clients. |
| Elicitation | Client capability, used only when a server asks for user input; see [elicitation](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/5f5440bb26a62e2cf3440b92da5a667efa03b267/docs/specification/2026-07-28/client/elicitation.mdx) | Not applicable because Interlock exposes no corresponding feature | Interlock advertises no client elicitation capability and rejects `input_required`. | Adds interactive authority and data-collection risk; omitted. |
| Roots and sampling | Client capabilities deprecated in 2026 | Not applicable because Interlock exposes no corresponding feature | Interlock does not act as an MCP host for either operation. | Outside product boundary. |
| Subscriptions/list-change streams | Capability-conditional core pattern; see [subscriptions](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/5f5440bb26a62e2cf3440b92da5a667efa03b267/docs/specification/2026-07-28/basic/patterns/subscriptions.mdx) | Not applicable because Interlock exposes no corresponding feature | `tools.listChanged` is false; no subscription method is advertised. | Long-lived state and notification delivery are unnecessary attack surface. |
| Tasks | Optional extension; see [extension overview](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/5f5440bb26a62e2cf3440b92da5a667efa03b267/docs/extensions/overview.mdx) | Unsupported by design | Not advertised; extension result types/methods fail closed. | Durable task handles and polling are new mutable state outside scope. |
| MCP Apps | Optional extension; see [extension overview](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/5f5440bb26a62e2cf3440b92da5a667efa03b267/docs/extensions/overview.mdx) | Unsupported by design | No UI resources, app capability, or app RPC dialect is advertised. | Adds browser/UI execution and resource-fetch attack surface; explicitly excluded. |
| Other extensions | Extensions are optional, disabled by default, and capability-negotiated; see [extension overview](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/5f5440bb26a62e2cf3440b92da5a667efa03b267/docs/extensions/overview.mdx) | Unsupported by design | Unrecognized result types and methods fail closed. | No extension is added solely to inflate a compatibility claim. |

## Reproducible focused gate

With the repository requirements installed in a clean Python 3.12 environment:

```bash
python -m pytest \
  tests/test_mcp_2026_core_profile.py \
  tests/test_mcp_upstream_profiles.py \
  tests/test_streamable_mcp_2026_eligibility.py \
  tests/test_streamable_mcp_integration.py -q
```

The SDK-marked tests additionally require the exact disposable environment
variables documented in `docs/mcp-2026-compatibility.md`; absent SDK tools are
reported as skips and therefore do not constitute interoperability evidence.

## Reproducible gateway, drift, receipt, and security gate

With the same pinned SDK environment variables, the exact broader selection is:

```bash
python -m pytest -q \
  tests/test_mcp_2026_core_profile.py \
  tests/test_mcp_upstream_profiles.py \
  tests/test_streamable_mcp_2026_eligibility.py \
  tests/test_streamable_mcp_integration.py \
  tests/test_mcp_gateway.py \
  tests/test_mcp_gateway_upstream_errors.py \
  tests/test_mcp_drift.py \
  tests/test_chain_drift.py \
  tests/test_chain_drift_route.py \
  tests/test_drift_evidence.py \
  tests/test_drift_description_exfil.py \
  tests/test_drift_depth.py \
  tests/test_drift_adversarial.py \
  tests/test_drift_record_schema.py \
  tests/test_effect_drift.py \
  tests/test_effect_drift_runtime.py \
  tests/test_response_drift.py \
  tests/test_response_drift_runtime.py \
  tests/test_external_reach_drift.py \
  tests/test_security_receipt.py \
  tests/test_receipt_replay.py \
  tests/test_receipt_claims.py
```

PR #41 follow-up result: `458 passed, 1 skipped, 6 xfailed`. The one skip is
the separately invoked alpha conformance evidence test; it is not counted as a
passing interoperability probe.
