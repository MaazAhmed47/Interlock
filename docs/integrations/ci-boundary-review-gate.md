# CI boundary-review gate (optional, self-hosted)

An optional self-hosted CI boundary-review gate. It lets a release pipeline ask
one question about an already-registered MCP server, without a reviewer opening
the Interlock dashboard:

> Is the server still serving the tool boundary this deployment has on record,
> and is Interlock currently holding anything for it?

The gate is **not** policy-as-code, **not** a full CI/CD integration, and
**not** production-proven. It is one read-only check with a stable exit code and
a sanitized artifact.

---

## What it does and does not do

**Does**

- Reads the server's approved boundary from Interlock's own registry state.
- Performs one read-only observation of the server's current tool surface
  through the same fetch path rebaseline staging uses.
- Classifies the difference with the same drift classifier the registry writes
  through.
- Reports what the gateway is already holding for that server.
- Appends exactly one hash-chained audit event and returns its receipt
  reference.
- Writes a sanitized JSON + Markdown artifact and exits with a stable code.

**Does not**

- Rebaseline, approve, quarantine, unquarantine, register, unregister, verify,
  or change policy.
- Accept a caller-supplied reviewer, baseline hash, decision, or receipt.
- Invoke MCP tools, or observe any URL other than the one the registry holds
  for that server id.
- Prove anything about traffic that does not pass through this Interlock
  deployment.

---

## Prerequisites

1. A self-hosted Interlock deployment reachable from your CI runner. An
   internal deployment usually means a self-hosted runner or a private network
   path.
2. The MCP server already **registered and verified** in that deployment
   (`POST /mcp/servers`, then `POST /mcp/servers/{server_id}/verify`, both
   `admin`).
3. At least one discovery already recorded for that server, so there is a
   persisted boundary to compare against.
4. Python 3.12 on the runner. The gate is stdlib-only — no `pip install`.

---

## Minimal CI credential

Mint a key holding **only** `mcp.review`:

```bash
curl -X POST http://localhost:8001/admin/keys \
  -H "Authorization: Bearer $ADMIN_SCOPED_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"plan":"developer","label":"ci-boundary-gate","scopes":["mcp.review"],"role":"readonly_agent"}'
```

`mcp.review` authorizes exactly one route:
`POST /mcp/servers/{server_id}/boundary-review`.
Interlock additionally treats a key whose effective scope set is exactly
`["mcp.review"]` as an isolated credential class: it receives `403` from every
other API-key-authenticated route, including legacy routes that otherwise only
check whether a key is valid. Do not add runtime, read, audit, or admin scopes
to the CI key; doing so intentionally makes it a different, non-isolated key.

| The CI key can | The CI key cannot |
|---|---|
| Read one registered server's boundary review | Approve or quarantine a tool (`admin`) |
| | Stage or promote a rebaseline (`admin`) |
| | Register, verify, unregister, or set environment on a server (`admin`) |
| | Read or change policy, keys, or users (`admin` / admin token) |
| | Call an MCP tool (`mcp.call`) or use the Streamable HTTP transport |
| | Discover an arbitrary URL (`mcp.discover`) |
| | Run effective-permission or readback probes (`mcp.probe`) |
| | Read the raw audit log (`admin`) or export receipts (`audit.export`) |

`admin` remains a deliberate super-scope for backward-compatible
administration, so do not hand an `admin` key to CI.

Store the key in **GitHub Secrets** (or your CI's secret store). The gate reads
it from `INTERLOCK_CI_API_KEY` and refuses to run if the value appears anywhere
in `argv`.

---

## Command

```bash
export INTERLOCK_BASE_URL=https://interlock.internal.example
export INTERLOCK_CI_API_KEY=...          # environment ONLY

python scripts/interlock_ci_gate.py \
  --server-id billing-mcp \
  --output-dir ./artifacts \
  --fail-policy material
```

| Input | Source | Notes |
|---|---|---|
| Base URL | `INTERLOCK_BASE_URL`, or `--base-url` | HTTPS required; plain HTTP only for loopback. No userinfo, query, or fragment. |
| Credential | `INTERLOCK_CI_API_KEY` | Environment only. Never an argument. |
| Server id | `--server-id` | Must already be registered. |
| Output directory | `--output-dir` | Created if missing. |
| Fail policy | `--fail-policy` | Optional. Default `material`. |
| Timeout | `--timeout-seconds` | Optional. Default 60s for the HTTP call. |

The deployment-side observation timeout is separate and set by the operator via
`INTERLOCK_BOUNDARY_REVIEW_TIMEOUT_S` (default 10s).

### Fail policies

| Policy | Fails on |
|---|---|
| `material` (default) | Severity `high`/`critical`, any `deny`/`quarantine` decision, or any tool already awaiting operator review |
| `any-finding` | Any finding at all, including `minor` |
| `quarantine-only` | Only a held boundary |

Four conditions fail under **every** policy, in this precedence order:

1. **Held or denied.** Any tool the gateway is refusing to forward right now
   (a `review_queue` entry with `enforced_now: true`), any quarantine-grade
   finding, or an unverified server.
2. **A breached cap.** See [Limits](#limits).
3. **An observation that did not complete** - timeout, unreachable, rate
   limited, oversized, or superseded by a concurrent registry change.
4. **An unverified evidence chain.** The gate will not certify a boundary
   whose own receipt does not verify.

A boundary that could not be observed is never reported as clean.

### `quarantine-only` is an enforcement-only mode, not a release gate

`quarantine-only` reports **only** what the gateway is refusing to forward at
this moment. A newly observed `deny`-grade finding is a prediction about the
next discovery, not enforced state, so under this policy it exits **0** as
`advisory`.

> **`quarantine-only` can pass non-enforced material drift.**
> **It must not be used as an approval or release gate.**
>
> It exists for monitoring a fleet's currently enforced holds — for example a
> dashboard job that should page only when traffic is actually being blocked.
> Any pipeline that decides whether a change ships must use the default
> `material` policy.

The default remains strict and is what the exit-code table describes.

---

## Exit codes

| Outcome | Exit | Meaning |
|---|---|---|
| `clean` | 0 | Observed surface matches the approved boundary; nothing awaiting review. |
| `advisory` | 0 | Only non-material findings under the active policy. |
| `review_required` | 20 | Material drift, or tools already awaiting operator review. |
| `quarantined` | 21 | The gateway is holding or denying this server or one of its tools (includes an unverified server). |
| `inconclusive` | 22 | Upstream timed out, was unreachable, was rate limited, breached a cap, was superseded by a concurrent registry change, or produced an unverified evidence chain. Also a concurrent review holding the same `Idempotency-Key`. |
| `config_error` | 2 | Missing or invalid configuration/arguments, a rejected base URL, or a server id that is not registered. |
| `auth_error` | 3 | Credential rejected, ambiguous, missing the `mcp.review` scope, or an `Idempotency-Key` already bound to another identity or server. |
| `protocol_error` | 4 | Response not understood: a refused redirect, a TLS failure, an oversized body, a schema violation, an unknown outcome name, a degenerate "clean" response missing its evidence, or an unexpected internal error. |

The three gate-invocation codes (2/3/4) are deliberately distinct from the
boundary codes (20/21/22), so a pipeline can tell "the gate is misconfigured"
from "the boundary changed". The gate never exits 1: an unexpected internal
error is reported as `protocol_error` with an artifact, not as a traceback.

---

## Transport

The client is deliberately restrictive, because a CI credential is at stake:

| Behavior | Rule |
|---|---|
| Redirects | **Never followed.** A 3xx is `protocol_error` (exit 4). Following one would re-send the credential to a host the operator never configured, and let that host dictate the result. |
| Proxies | `HTTP_PROXY` / `HTTPS_PROXY` / `ALL_PROXY` are ignored entirely. |
| TLS | Certificates and hostnames are verified. A verification failure is `protocol_error`. |
| Scheme | HTTPS required. Plain HTTP is permitted **only** for the exact loopback hosts `localhost`, `127.0.0.1`, and `[::1]`, for local development. |
| URL shape | A base URL carrying userinfo (`user:pass@host`), a query string, a fragment, percent-encoding or backslashes in the authority, whitespace, control characters, malformed IPv6, ambiguous numeric IPv4, a trailing DNS dot, or another non-canonical host representation is rejected as `config_error` before a request is built. |
| Path prefix | A single normalized reverse-proxy prefix is allowed (`https://host/interlock`). Percent-encoding, `\`, control characters, doubled slashes, and `.`/`..` segments are rejected. Segments are limited to `[A-Za-z0-9._~-]`. The review URL is built by concatenating validated parts — never `urljoin`. |
| Body size | The response is read under a 4 MiB budget; anything larger is `protocol_error`. |
| Method | `POST`. The endpoint has side effects and returns `Cache-Control: no-store`, `Pragma: no-cache`, `Expires: 0`, and `Vary: Authorization, X-API-Key, Idempotency-Key`. `no-store` is the storage prohibition; `Vary` names request selectors for compliant caches and is not an authorization control. |

The credential is only ever sent as an `x-api-key` request header to the
validated base URL. It never appears in a URL, an argument, a file, stdout,
stderr, or an artifact.

---

## Idempotency

Every invocation generates one cryptographically random `Idempotency-Key`.

- The deployment stores **only a SHA-256 digest** of the key, never the raw
  value.
- The digest is bound to the verified principal **and** the reviewed server id.
- A repeat with the same key, principal, and server replays the original
  sanitized result verbatim with `Idempotent-Replay: true`, and appends **no**
  additional audit row and **no** additional surface snapshots.
- A repeat under a different principal or server is refused with `409`
  (`idempotency_key_conflict`) and reported as `auth_error` (exit 3).
- A concurrent request holding the same key gets `409` (`review_in_progress`)
  and is reported as `inconclusive` (exit 22).
- The reservation is completed only after a verified receipt commits. Audit
  append, receipt verification, or commit failure deletes the unfinished
  reservation, so retrying the exact same key performs a fresh review rather
  than replaying an unverified failure artifact.
- Rows expire under `INTERLOCK_BOUNDARY_REVIEW_IDEMPOTENCY_TTL_S` (default 24h,
  ceiling 7 days); expired rows are pruned on the next reservation.
- Uniqueness is enforced by a primary key, so two Postgres replicas racing the
  same key cannot both reserve it.

A retry that omits the header is treated as a new review.

---

## Limits

Conservative defaults, each validated against a documented range.

**Unset (or empty) means "use the default". A setting that IS present but
unparsable or out of range stops startup** with a `ConfigurationError` naming
the variable — it is never silently replaced by a different limit, because an
operator who typed a number must never end up running under one they did not
choose. Validation runs before any database or network work.

| Setting | Floor | Default | Ceiling |
|---|---:|---:|---:|
| `INTERLOCK_BOUNDARY_REVIEW_TIMEOUT_S` | 0.1 | 10 | 120 |
| `INTERLOCK_BOUNDARY_REVIEW_MAX_RESPONSE_BYTES` | 1 KiB | 2 MiB | 20 MiB |
| `INTERLOCK_BOUNDARY_REVIEW_MAX_TOOLS` | 1 | 200 | 2000 |
| `INTERLOCK_BOUNDARY_REVIEW_MAX_FINDINGS` | 1 | 100 | 1000 |
| `INTERLOCK_BOUNDARY_REVIEW_IDEMPOTENCY_TTL_S` | 60 | 86400 | 604800 |
| `INTERLOCK_CI_BOUNDARY_REVIEW_MAX_REQUEST_BYTES` | 0 | 8192 | 1048576 |

Caps are enforced **before** any per-tool surface snapshot is retained and
before any artifact is serialized, so a hostile upstream cannot drive unbounded
evidence writes or artifact growth. A breached cap is reported in
`caps.exceeded` and is never clean. Findings are sorted worst-first, so
truncation can never hide the most severe finding.

`INTERLOCK_CI_BOUNDARY_REVIEW_MAX_REQUEST_BYTES` bounds the POST body. The
endpoint **ignores** the body entirely — nothing in it can influence the
server, baseline, reviewer, decision, or evidence — so the default is small.
The body is bounded only so an authenticated caller cannot push volume through
the endpoint. The request is authenticated first, then the declared
`Content-Length` and the streamed bytes are both checked, and an oversized body
is refused with `413` **before** any review, audit, snapshot, or idempotency
write occurs.

### Response headers

Every boundary-review response — `200`, `400`, `401`, `403`, `404`, `405`,
`409`, `413`, `429`, and `500` — carries:

```
Cache-Control: no-store
Pragma: no-cache
Expires: 0
Vary: Authorization, X-API-Key, Idempotency-Key
```

These are applied by ASGI middleware plus a server-error handler, not only
inside the route, because a `403` from the scope check, a `429` from the rate
limiter, a router-generated `405`, and the default `500` are all produced
elsewhere — and those are precisely the responses a shared caching proxy is
most likely to store and replay to a different credential. Other named `Vary`
selectors are preserved, while the three credential/idempotency selectors are
de-duplicated case-insensitively and emitted exactly once. A wildcard is
replaced because this endpoint's auditable contract names those selectors.

---

## Artifacts

Both files are always written, including on a failing or errored run:

- `<output-dir>/interlock-boundary-review.json`
- `<output-dir>/interlock-boundary-review.md`

### Field inventory (JSON)

| Field | Description |
|---|---|
| `format_version` | `interlock.ci-boundary-review/v1` |
| `generated_at` | UTC timestamp, second precision |
| `gate.name` / `gate.outcome` / `gate.exit_code` | Named final gate outcome and its exit code |
| `gate.boundary_review_semantic_outcome` | Substantive review result before receipt verification |
| `gate.boundary_review_final_outcome` / `gate.boundary_review_final_exit_code` | Final evidence-aware result after receipt verification; these agree with `gate.outcome` / `gate.exit_code` |
| `gate.fail_policy` / `gate.gateway_outcome` | Policy applied locally, and the outcome the deployment computed under its strict default |
| `server.server_ref` | Stable opaque `sha256:<16 hex>` reference. The raw registered id is never emitted, even for an ordinary value such as `billing-mcp`. |
| `server.verified` / `server.registry_class` / `server.environment` | Registry state |
| `boundary.approved_surface_hash` / `observed_surface_hash` | Content addresses of the approved and observed surfaces |
| `boundary.matches_approved_surface` | Whether the two hashes are equal |
| `boundary.approved_tool_count` / `observed_tool_count` | Tool counts |
| `boundary.snapshot_version` | Fingerprint of the coherent server-side snapshot the review concluded against |
| `caps` | Effective limits plus any `exceeded` entries |
| `observation.status` / `error_class` / `read_only` | `observed`, `observed_rejected`, `unavailable`, `superseded`, or `not_performed`, plus a safe error class |
| `findings[]` | `tool_ref`, `scope`, `change_types`, `diff_classification`, `threat_class`, `severity`, `decision`, and the per-tool approved/observed surface hashes |
| `review_queue[]` | `tool_ref`, `status`, `severity`, `decision`, `enforced_now` — what the gateway is holding now |
| `gateway_mediation` | Whether this review forwarded a call (always `false`), whether all calls are held, and how many tools are held |
| `severity_summary` | `max_severity`, `finding_count`, `review_queue_count`, `material` |
| `evidence.receipt` | `audit_id`, `receipt_path`, `hash_chained`, `chain_verified`, `tamper_evident`, `receipt_verification_state`, `externally_signed`, `independently_anchored` |
| `evidence.evidence_ref` | Digest of the canonical drift record for the highest-severity finding, under `json/jcs-rfc8785`. The record itself carries the raw server id, so it is fetched from the receipt rather than embedded here. |
| `limitations[]` | Stated limitations, carried in the artifact itself |
| `redaction` | The redaction profile and the categories excluded by construction |

### What is excluded by construction

The deployment builds this projection field by field. It never filters a richer
object, so the following can never appear:

`tool_descriptions`, `tool_input_output_schemas`, `tool_call_arguments`,
`request_and_upstream_headers`, `credentials_and_tokens`,
`upstream_response_bodies`, `customer_data`, `local_filesystem_paths`,
`registry_urls`, `raw_server_identifiers`,
`detector_reasons_and_thresholds`, `actor_identity`.

### Exported artifact vs internal audit record

These are two different records with two different audiences, and the
difference is deliberate:

| | Exported CI artifact | Internal audit record |
|---|---|---|
| Audience | Anyone who can read a CI job's artifacts | Operators holding `admin` / `audit.read` |
| Server id | Digest-only `server_ref` | Real registered id |
| Classifier detail | Finding types and severities only | Full drift reason strings |
| Reviewer | Absent | Derived key label and prefix |

The internal audit record intentionally keeps the operational context an
operator needs to triage — the real server id, the resolved reviewer, and the
classifier's reasons — and it is reachable only with `admin` or `audit.read`.
The CI credential holds neither, so `mcp.review` cannot read it back.

Boundary-review rows carry a hash-covered `boundary_review_metadata` object
with `boundary_review_semantic_outcome`, `boundary_review_final_outcome`,
`boundary_review_final_exit_code`, `fail_policy`, and
`receipt_verification_state`. The generic `expected_outcome` field is empty
because it represents a configured probe expectation and is not applicable to
this review. Content-addressed snapshots, audit append, receipt verification,
and commit occur in one transaction: the evidence set commits with
`receipt_verification_state: verified`, or any failure rolls every candidate
write back before it can claim a final gate result.

What the internal audit record **never** stores, on any path: API keys or any
other credential, request or upstream headers, tool-call arguments, raw
upstream response bodies, or idempotency keys (only a SHA-256 digest of an
idempotency key is persisted, in a separate table).

Classifier reason strings quote schema field names, so they stay in the
internal audit row and never reach the artifact. Tool names are treated as
untrusted text: anything outside
`[A-Za-z0-9._\-:]` is replaced - which removes `<`, `>`, `&`, quotes, pipes,
backticks, path separators, and every control character - traversal pairs are
neutralized, and the reference keeps a short digest so distinct names stay
distinguishable. Server identifiers are replaced with stable truncated SHA-256
references, never reversible sanitized text. The Markdown renderer additionally
strips `<`, `>`, and `&`
and escapes table separators, so a hostile identifier can neither forge table
rows nor inject raw HTML into a CI job summary.

### Example (synthetic placeholders)

```json
{
  "format_version": "interlock.ci-boundary-review/v1",
  "generated_at": "2026-01-01T00:00:00Z",
  "gate": {
    "name": "interlock-mcp-boundary-review",
    "outcome": "review_required",
    "exit_code": 20,
    "fail_policy": "material",
    "boundary_review_semantic_outcome": "review_required",
    "boundary_review_final_outcome": "review_required",
    "boundary_review_final_exit_code": 20,
    "gateway_outcome": "review_required"
  },
  "server": {
    "server_ref": "sha256:0000000000000000",
    "registered": true,
    "verified": true,
    "registry_class": "operator_registered",
    "environment": "non_production"
  },
  "boundary": {
    "approved_surface_hash": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
    "observed_surface_hash": "sha256:2222222222222222222222222222222222222222222222222222222222222222",
    "matches_approved_surface": false,
    "approved_tool_count": 2,
    "observed_tool_count": 2,
    "snapshot_version": "sha256:5555555555555555555555555555555555555555555555555555555555555555"
  },
  "observation": {"status": "observed", "error_class": "", "read_only": true, "mutated_state": false},
  "findings": [
    {
      "scope": "tool",
      "tool_ref": "read_document",
      "change_types": ["required_field_removed"],
      "diff_classification": "schema",
      "threat_class": "",
      "severity": "high",
      "decision": "deny",
      "approved_tool_surface_hash": "sha256:3333333333333333333333333333333333333333333333333333333333333333",
      "observed_tool_surface_hash": "sha256:4444444444444444444444444444444444444444444444444444444444444444"
    }
  ],
  "review_queue": [],
  "gateway_mediation": {"call_forwarded": false, "server_calls_held": false, "tool_calls_held": 0},
  "severity_summary": {"max_severity": "high", "finding_count": 1, "review_queue_count": 0, "material": true},
  "caps": {
    "timeout_seconds": 10.0,
    "max_response_bytes": 2097152,
    "max_request_bytes": 8192,
    "max_observed_tools": 200,
    "max_findings": 100,
    "idempotency_ttl_seconds": 86400,
    "exceeded": []
  },
  "evidence": {
    "receipt": {
      "audit_id": 1234,
      "receipt_path": "/audit/receipt/1234",
      "hash_chained": true,
      "chain_verified": true,
      "tamper_evident": true,
      "receipt_verification_state": "verified",
      "externally_signed": false,
      "independently_anchored": false
    },
    "canonicalization": "json/jcs-rfc8785",
    "evidence_ref": null
  },
  "limitations": ["Synthetic example; live artifacts carry the full limitations inventory."],
  "redaction": {"profile": "default", "excluded": ["credentials_and_tokens", "raw_server_identifiers"]}
}
```

The test suite parses this exact JSON block with the production CLI schema
validator and compares its top-level keys with a real artifact fixture, so the
example cannot silently drift from the artifact contract.

The Markdown file renders the same facts as an outcome line, a summary table, a
findings table, a review-queue table, the gateway-mediation counts, and the
limitations list.

---

## GitHub Actions

The template lives at
[`docs/integrations/github-actions/interlock-boundary-gate.yml`](github-actions/interlock-boundary-gate.yml).
It is stored outside `.github/workflows/` on purpose, so it is **not** active in
Interlock's own CI. Copy it into your repository's `.github/workflows/` to use
it.

It reads the credential from `secrets.INTERLOCK_CI_API_KEY`, echoes no secret
values, writes the Markdown file to `$GITHUB_STEP_SUMMARY`, and uploads both
artifacts with `if: always()` so a failing gate still publishes its evidence.

## Any other CI system

There is nothing GitHub-specific about the gate. The generic shape is:

```sh
set +e
INTERLOCK_BASE_URL="$INTERLOCK_BASE_URL" \
INTERLOCK_CI_API_KEY="$INTERLOCK_CI_API_KEY" \
python interlock_ci_gate.py --server-id "$SERVER_ID" --output-dir "$ARTIFACT_DIR"
gate_status=$?
set -e

# Publish/upload $ARTIFACT_DIR here, unconditionally.

exit "$gate_status"
```

Capture the exit code, publish the artifact directory whatever the result, then
exit with the captured code. Map 0 to pass, 20/21/22 to a boundary failure, and
2/3/4 to a pipeline configuration problem you should page yourself about rather
than treat as a security finding.

---

## Deployment responsibility and limitations

- **Routing is the operator's responsibility.** An agent that connects to the
  MCP server directly does not pass through Interlock, and the gate proves
  nothing about that traffic. Route agent traffic through the gateway and
  enforce egress controls so a direct connection is not reachable.
- **Receipts are hash-chained and tamper-evident inside this deployment.** They
  are not externally signed and not anchored to an independent timestamping
  authority.
- **`approved_surface_hash` is the boundary Interlock has persisted.** Tools
  listed in `review_queue` are already flagged and have not been re-approved by
  an operator.
- **A review is a point-in-time observation.** A server can serve a different
  surface after the gate runs.
- **A successful review appends evidence atomically.** Its only writes are
  content-addressed tool surface snapshots (capped) and one verified,
  hash-chained audit row, plus one completed idempotency row when a key is
  supplied. Receipt failure rolls back snapshots and audit evidence and
  releases the idempotency reservation. It changes no approval, baseline,
  quarantine, or policy state.
- **A server id containing `/` cannot be reviewed.** Every
  `/mcp/servers/{server_id}/...` route addresses the id as a single path
  segment, so an id with a slash is unreachable on this route exactly as on
  the existing ones.
- **Two failures produce no artifact:** unparsable command-line arguments,
  because the gate does not yet know the output directory. Every other
  failure - authentication, transport, schema, cap, and internal errors -
  writes both files.
- This is an optional self-hosted CI boundary-review gate — not policy-as-code,
  not a full CI/CD integration, and not production-proven.
