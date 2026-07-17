# Experimental EMA authority evidence

Status: isolated experiment. Disabled by default. This is not a public claim
of MCP Enterprise-Managed Authorization interoperability.

Interlock implements one narrow resource-server profile,
`interlock-experimental-ema-jwt-at-v1`, at an opt-in MCP Streamable HTTP
endpoint. It validates an exchanged MCP access token presented to that
endpoint. It does **not** accept or validate an ID-JAG and does not perform
token exchange.

The standards boundary follows the MCP
[Streamable HTTP transport](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports),
[authorization](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization),
[lifecycle](https://modelcontextprotocol.io/specification/2025-11-25/basic/lifecycle),
and [tools](https://modelcontextprotocol.io/specification/2025-11-25/server/tools)
specifications. Mock signed-JWT tests prove Interlock's validation code only.
An EMA interoperability claim remains blocked until a real EMA-capable client,
real IdP, real authorization server, and this Streamable HTTP endpoint pass an
end-to-end test.

## Deployment contract

`INTERLOCK_EXPERIMENTAL_EMA_ENABLED` must be explicitly true. When it is false
or absent, Interlock registers neither the resource endpoint nor its protected
resource metadata route. When it is true, incomplete or unsafe configuration
fails application startup.

Required deployment values:

- `INTERLOCK_EMA_RESOURCE_URI`: one exact HTTPS resource URI. Its path is the
  Streamable HTTP endpoint. The experimental profile requires lowercase ASCII
  DNS form, no default port, percent escapes, dot segments, query, or fragment,
  so signed `aud`/`resource` comparisons use one canonical string.
- `INTERLOCK_EMA_ISSUER_METADATA`: static JSON containing one exact HTTPS
  `issuer` and one exact HTTPS `jwks_uri`.
- `INTERLOCK_EMA_SERVER_ID`: one existing Interlock MCP server.
- `INTERLOCK_EMA_SERVICE_PRINCIPAL_ID`: the Interlock deployment/service
  principal, not an employee or OAuth client.
- `INTERLOCK_EMA_ROLE`: one existing local Interlock RBAC role.
- `INTERLOCK_EMA_ALLOWED_CLIENT_IDS`: a non-empty JSON list of exact OAuth
  client identifiers guaranteed by the issuer profile.
- `INTERLOCK_EMA_TOOL_SCOPES`: one exact mapping from the configured server ID
  and exact tool names to non-empty required-scope sets.
- `INTERLOCK_EMA_OAUTH_CLIENT_HMAC_KEYS`,
  `INTERLOCK_EMA_DELEGATED_SUBJECT_HMAC_KEYS`, and
  `INTERLOCK_EMA_TOKEN_HMAC_KEYS`: three independent key-ring JSON values.
  Each contains `active_key_id` and a `keys` map of key ID to base64url-encoded
  secret with at least 256 random bits. Key material cannot be reused between
  rings.

`INTERLOCK_EMA_DOWNSTREAM_SERVICE_PRINCIPAL_ID` is required in practice when
the selected MCP server uses a configured service credential, and must be
absent when it does not. A mismatch fails closed before downstream execution.
The optional origin list contains exact HTTPS origins; browser requests with
an unlisted `Origin` are rejected.

The optional `nbf` and `iat` requirements, maximum token age, session lifetime,
JWKS refresh cooldown, negative-cache lifetime, and negative-cache capacity
are deployment-level settings. There is no tenant configuration model.

## Access-token profile

The only accepted token is a compact JWT access token with:

- JOSE `typ` exactly `at+jwt`;
- `alg` exactly `RS256`;
- a bounded `kid` resolved only through the statically configured JWKS URI;
- exact `iss`, resource audience, `resource`, allowed `client_id`, `scope`,
  `sub`, and integer `exp` claims;
- optional integer `nbf` and `iat` claims, validated when present and required
  only when configured.

Token-provided `jku`, `x5u`, `jwk`, critical extensions, symmetric algorithms,
and unsigned tokens are rejected. JWKS redirects are disabled. Authorization
headers, JWT segments, decoded JOSE/claim documents, JWKS documents, JWK count,
and individual JWKs are bounded before expensive processing. Unknown key IDs
share a single-flight refresh, cooldown, bounded negative cache, and rate
limit.

Every protected POST, GET, and DELETE validates `Authorization: Bearer` before
body parsing, session lookup, discovery, policy evaluation, or downstream
work. GET returns 405 because server-to-client SSE is not implemented. The
existing proprietary `POST /mcp/call` remains API-key-only and cannot create
EMA authority evidence.

## Identity and session boundary

Interlock keeps these identities separate:

- OAuth-client binding: a versioned HMAC of the verified issuer/client ID;
- delegated-subject binding: an independently keyed versioned HMAC of the
  verified issuer/subject;
- Interlock service principal: a configured deployment identifier;
- downstream service principal: a separate configured identifier committed
  only when the downstream forward boundary is reached.

Raw client IDs, subjects, email, bearer tokens, full claims, upstream
credentials, and inbound request IDs are not persisted. Sessions are
server-generated opaque values, expire, and bind both identity HMACs, their
historical key IDs, the Interlock principal, exact MCP server ID, resource, and
profile. A refreshed token must reproduce both bindings with the session's
historical keys before the session atomically migrates to active keys. A key
still referenced by a live session cannot be retired unless those sessions are
explicitly terminated.

Expired in-memory sessions are purged during lookup, authorization, rotation,
and new session creation. Deployments still need edge request/rate limits
appropriate to their pilot size; the experimental in-memory session store is
single-process and is not a multi-replica session service.

Tool discovery filters out tools whose exact configured scopes are not
present. Calls repeat the same exact mapping check. There are no wildcard,
prefix, inferred-name, or valid-token-means-all-tools grants.

## Audit v4 and receipts

Only authority-aware endpoint decisions write `mcp_audit_log` hash version 4.
All legacy writers continue to write v3, and v1-v3 verification remains
unchanged. V4 commits the transport/resource/method, verified authorization
profile and algorithm, normalized authority values, separate identity HMACs
and key IDs, service principals, call-specific token HMAC and key ID,
downstream boundary, target, argument hash, and normal runtime decision
evidence. `principal_id` stays empty on v4 and is never used as an employee
identity.

The token binding is a deployment-secret HMAC over the resource, Interlock
service principal, server-generated call ID, and access token. It is
call-specific and cannot be used as a public token fingerprint. Historical
receipt verification uses the stored hash chain and does not require a bearer
token or any HMAC key. Retention checkpoints remain v3 anchors and can retain
or prune mixed legacy/v4 chains without rewriting records.

Allowed v4 receipt wording:

- Verified and no downstream call: “Interlock validated delegated authority
  at its gateway. No downstream tool call was made.”
- Verified and forwarded with a separate service identity: “Interlock
  validated delegated authority at its gateway. Interlock attempted the
  downstream call with a separately configured service identity; this receipt
  does not prove that the downstream server evaluated the employee's delegated
  scopes.”
- Unverified and denied: “Interlock did not verify delegated authority; the
  request was denied at its gateway.”

Legacy/API-key-only receipts make no delegated-authority claim. No receipt may
say “ID-JAG verified.” Inbound bearer tokens are never forwarded downstream.
