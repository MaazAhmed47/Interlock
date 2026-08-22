# Outbound destination security

Interlock's production URL guard validates URL syntax, rejects embedded URL
credentials, resolves hostnames through the system resolver, and rejects the
destination if any A or AAAA answer is not globally routable. Rejected classes
include loopback, private space, link-local and metadata space, unspecified,
multicast, reserved and shared/CGNAT space, IPv6 ULA, IPv6 link-local, IPv6
site-local, and IPv4-mapped IPv6 forms. Resolution failure, a bounded resolution
timeout, and an empty answer set fail closed. Async paths perform the system
lookup off the event-loop thread. A caller timeout does not prove that the
underlying operating-system resolver call was cancelled.

hostname resolution rejection is a partial mitigation; DNS rebinding requires connection pinning or an enforced egress proxy/firewall.

The URL check and HTTP connection are separate operations. The current Phase 1
control does not pin the HTTP connection to an approved address, so a changed DNS
answer between validation and connection remains possible. Redirects are
explicitly disabled for Interlock-controlled credential-bearing HTTP clients,
but redirect policy is separate from DNS rebinding.

Interlock-controlled guarded clients use `trust_env=False`. Ambient
`HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, and `NO_PROXY` settings are unsupported
for guarded egress and cannot silently change those clients' connection path.
An enforced proxy is a future explicit deployment boundary, not an environment
proxy that the application happens to inherit.

## Server-side egress inventory

| Path | Destination source | Sensitive material | Phase 1 control |
|---|---|---|---|
| MCP discovery and tool calls | Admin-registered MCP server URL | Optional configured upstream auth; tool definitions or call arguments | Shared guard; redirects disabled |
| Effective-permission and effect-readback probes | Registered MCP server URL | Optional upstream auth; controlled probe arguments | Shared guard; redirects disabled |
| Per-key webhook | Admin-configured API-key record | Alert evidence | Shared guard; redirects disabled |
| SIEM and generic webhook dispatch | Per-key or `/siem/test` configuration; some fixed provider templates | Provider tokens, custom headers, alert evidence | Shared guard; redirects disabled; `/siem/test` requires `admin` |
| Shadow scan | Admin-configured shadow target | No configured credential | Shared guard; redirects disabled |
| Experimental EMA JWKS | Deployment configuration | No outbound credential | Shared guard; redirects disabled |
| Admin OIDC JWKS | Deployment configuration | No outbound credential | Shared guard; controlled fetcher; redirects and ambient proxy trust disabled |
| OpenAI, Anthropic, Google, and Groq routing | Fixed source-code provider endpoints | Provider credential and caller request | Fixed destination; redirects explicitly disabled for the direct HTTP router |
| Groq judge SDK | Fixed SDK provider endpoint | Provider credential and prompt | Fixed destination; SDK transport behavior is outside the shared configurable-URL guard |
| Ollama routing | Fixed loopback endpoint | Prompt; no configured provider credential | Deliberate local infrastructure path, outside production configurable-destination handling |
| Redis and Postgres | Deployment infrastructure configuration | Database credentials and runtime state | Non-HTTP infrastructure; govern with deployment network policy |
| Browser dashboard requests and demo/CI clients | Browser or operator-side configuration | Depends on client | Not server-side Interlock egress |

The offline Compose proof keeps the guard enabled and narrowly allows only the
single-label `mcp-mock` service while `INTERLOCK_OFFLINE_DEMO=true` and the
deployment is not production. It does not allow arbitrary private destinations.

## Production requirement and Phase 2

Production should force HTTP and HTTPS egress through an authenticated egress
proxy or equivalent firewall policy that resolves destinations itself, rejects
all non-global address classes on every connection, rechecks redirects, and
limits destination ports and approved provider domains. Deny direct workload
egress so application code cannot bypass the policy.

Because guarded clients ignore ambient proxy variables, a future explicit proxy
design must be configured and validated deliberately, or enforcement must be
transparent at the workload network boundary.

Connection pinning is an alternative application-level defense, but it requires
an HTTP transport that connects to one validated address while preserving the
original HTTPS hostname for certificate verification, SNI, and the HTTP Host
header. It must also repeat validation for every redirect and address-family
fallback. Interlock does not implement that connector in Phase 1.
