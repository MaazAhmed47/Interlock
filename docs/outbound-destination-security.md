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
The same applies to their lower-case variants. Ambient proxy settings are never
Interlock security configuration.

## Application egress profiles

`INTERLOCK_EGRESS_PROFILE=phase1` is the default compatibility profile. It keeps
the Phase 1 URL checks and central client construction, but a missing explicit
proxy means HTTP clients connect directly. URL validation and connection still
resolve separately. This profile is not secure against DNS rebinding.

`INTERLOCK_EGRESS_PROFILE=enforced` is explicit Phase 2 application preparation.
It requires `INTERLOCK_OUTBOUND_HTTP_PROXY=http://host:port` before database or
network startup work. The parser rejects missing values, non-HTTP schemes,
embedded credentials, paths, queries, fragments, malformed or ambiguous hosts,
and missing/invalid ports without returning the configured value in the error.
Every enumerated runtime HTTP client is created with the explicit proxy,
`trust_env=False`, `follow_redirects=False`, and certificate verification on by
default. Disabled certificate verification and caller-supplied HTTP transports
are rejected in this profile. Proxy, DNS, CONNECT, TLS, HTTP, and redirect
failure has no direct fallback.

In Interlock’s explicit enforced egress profile, enumerated server-side HTTP(S) clients are configured to use a required forward proxy, ignore ambient proxy environment variables, and disable automatic redirects. Connection-time destination enforcement still requires the separately validated proxy and deployment-level direct-egress denial.

## Server-side egress inventory

| Path | Destination source | Sensitive material | Central plumbing in `enforced` |
|---|---|---|---|
| MCP discovery, candidate/rebaseline observation, and tool calls | Admin-registered MCP server URL | Optional configured upstream auth; tool definitions or call arguments | Async factory; required explicit proxy |
| Effective-permission and effect-readback probes | Registered MCP server URL | Optional upstream auth; controlled probe arguments | Async factory; required explicit proxy |
| Per-key webhook | Admin-configured API-key record | Alert evidence | Async factory; required explicit proxy |
| Datadog, Splunk, Elastic, Slack, PagerDuty, and generic SIEM webhook dispatch | Per-key or `/siem/test` configuration; some fixed provider templates | Provider tokens, custom headers, alert evidence | Async factory; required explicit proxy; `verify_ssl=false` rejected |
| Shadow scan | Admin-configured shadow target | No configured credential | Async factory; untrusted injected clients rejected |
| Experimental EMA JWKS | Deployment configuration | No outbound credential | Async factory; custom transports rejected |
| Admin OIDC JWKS | Deployment configuration | No outbound credential | Sync factory; required explicit proxy |
| OpenAI, Anthropic, Google, and Groq provider routing | Fixed source-code provider endpoints | Provider credential and caller request | Async factory; required explicit proxy |
| Groq judge SDK | Fixed SDK provider endpoint | Provider credential and prompt | SDK receives factory-created sync HTTPX client; SDK retries disabled |
| Ollama routing | Fixed loopback endpoint | Prompt; no configured provider credential | Disabled before network access |
| Redis and Postgres | Deployment infrastructure configuration | Database credentials and runtime state | Excluded: non-HTTP infrastructure governed by deployment network policy |
| Browser dashboard requests | Browser configuration | Depends on browser session | Excluded: not server-side Interlock egress |

The semantic inventory contract scans production modules using Python ASTs. It
fails on unapproved direct HTTPX, urllib, requests, aiohttp, raw-socket,
subprocess, or known SDK transport construction, and checks the exact expected
factory call-site counts. Its small allowlist records reasons for the central
factory, Phase 1 DNS resolver, controlled Groq adapter, and local Git evidence
subprocess. This source contract is a regression tripwire, not network
enforcement.

Local demos, examples, CI/operator scripts, live provider proof packs, and
database/kubectl helpers contain separate urllib, raw-socket, or subprocess
paths. They are not production runtime callers and are intentionally not routed
through the application factory. Phase 2 deployment policy must still contain
them if they are ever packaged or executed with the production workload.

The offline Compose proof keeps the Phase 1 guard enabled and narrowly allows only the
single-label `mcp-mock` service while `INTERLOCK_OFFLINE_DEMO=true` and the
deployment is not production. It does not allow arbitrary private destinations.

## Production requirement and Phase 2

PR 1 does not deploy or validate Squid and does not deny direct socket, DNS,
subprocess, PostgreSQL, Redis, or other protocol egress. PR 2 must deploy the
separately pinned and validated non-intercepting forward proxy, resolve and
classify every destination at connection time, preserve end-to-end Host/SNI/TLS
validation, enforce redirect destinations, and deny direct workload IPv4 and
IPv6 egress while allowing only proxy, DNS, PostgreSQL, and Redis dependencies.

No Render Phase 2 enforcement claim is permitted without independent evidence
that the workload cannot egress directly. A configured explicit proxy alone is
not that evidence.

Connection pinning is an alternative application-level defense, but it requires
an HTTP transport that connects to one validated address while preserving the
original HTTPS hostname for certificate verification, SNI, and the HTTP Host
header. It must also repeat validation for every redirect and address-family
fallback. Interlock does not implement that connector in Phase 1.

## Non-claims

- No complete SSRF prevention.
- No universal DNS-rebinding prevention.
- No direct-egress denial from application code alone.
- No Render Phase 2 claim.
- No protection for unenumerated protocols, future clients, or unmanaged SDK transports.
- No production or managed-provider certification.
