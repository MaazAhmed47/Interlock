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

## Tested Docker Phase 2 reference profile

`deploy/phase2-docker/compose.yaml` is separate from normal development and the
offline demo. The profile pins
`ghcr.io/cybozu/squid:7.6.0.1@sha256:b5fff668ddbf5738a779ada37893569e6640d2a2ac384a834095ac443d12d60a`,
mounts the Squid policy read-only, enables controlled DNS, PostgreSQL, and
Redis on one internal dual-stack application network, and gives Interlock no
IPv4 or IPv6 gateway or default route. The application network requires Docker
Engine 28 or newer and Compose 2.33.1 or newer, and sets both bridge gateway
modes to `isolated`. The acceptance runner rejects older runtimes, missing
rendered options, retained IPAM/container/route gateways, or an addressed host
bridge rather than falling back to ordinary `internal: true` behavior. Squid is
the only application-side service that
also joins the synthetic origin and denied-sink networks. No service publishes
a host port.

The lab keeps synthetic public-origin and private denied-sink segments separate
so an unsafe connection would be positively observable. Squid therefore has
three Docker network attachments: the client-facing application network and
two test-only upstream segments. They represent a two-sided proxy trust
boundary, but this instrumented profile is not a literal two-interface Squid
deployment. Interlock still has only the application-network attachment.
The Compose `x-phase2-boundaries` metadata separates the deployable two-sided
pattern (`app_net` -> Squid -> an operator-provided upstream network) from the
`origin_net`, `denied_net`, origin, sink, certificate generator, and acceptance
services used only by the hermetic suite.

Before cleanup, the runner also uses a uniquely named, short-lived test-only
host-network inspector to read the Docker bridge address table. It is not a
Compose service and is never available to Interlock. The retained proof includes
whitelisted fields from every owned container and network, the attachment map,
complete application IPv4/IPv6 route and address tables, neighbor tables, the
host bridge address table, runtime versions, effective gateway modes, Docker
alias resolution, and every direct HTTPX, urllib, requests, socket, and curl
gateway attempt. No environment, command, mount, arbitrary label, header, URL,
DSN, or credential field is retained.

Squid is an explicit non-intercepting forward proxy. The policy contains no
`ssl_bump`, `https_port`, certificate authority, or TLS key configuration.
CONNECT therefore preserves end-to-end client certificate and hostname
verification and SNI. Standards-compliant Via behavior remains enabled; Via is
observable on plain proxied HTTP and is not injected into the tunneled TLS
stream.

The acceptance runner hashes the source, policy, Compose source and rendered
configuration, test sources, results, and every retained artifact. Its verifier
requires every named case exactly once and rejects skipped, xfailed, xpassed,
failed, errored, malformed, partial, duplicate, stale, or counter-inconsistent
evidence. It also rejects any missing or malformed topology artifact, absent
IPv6 proof, non-isolated effective gateway mode, host bridge address, gateway
route, successful bypass attempt, or inconsistent topology hash. Run it only
from a clean checkout:

```bash
sha="$(git rev-parse HEAD)"
python scripts/run_phase2_docker_acceptance.py \
  --output "phase2-docker-evidence-$sha" \
  --source-sha "$sha"
python scripts/verify_phase2_docker_evidence.py \
  "phase2-docker-evidence-$sha"
```

Cleanup is scoped to the runner's validated, randomly generated Compose project
name. It does not prune or enumerate unrelated containers, networks, images, or
volumes.

In the tested Docker Phase 2 profile at the documented source SHA, Squid image digest, policy hash, and Compose configuration, Interlock’s enumerated server-side HTTP(S) paths are forced through a non-intercepting forward proxy. The profile rejects the tested private, metadata, raw-IP, mixed-answer, and rebinding destinations at proxy connection time while preserving end-to-end client TLS verification.

This is deployment-specific Docker evidence. It is not complete SSRF prevention, universal DNS-rebinding prevention, Render enforcement, Kubernetes enforcement, managed-database certification, protection for unenumerated protocols, or protection against an allowed destination.

Squid's address decision uses its shared DNS cache rather than a request-local
immutable approval token. The reference profile bounds positive and negative
TTL at 60 seconds (longer than the 15-second forward timeout), keeps the cache
larger than the complete permitted-host set, allows one forward attempt,
disables reconnects, and disables client/server persistent connections. The
adversarial suite covers expiry, pressure, retry, reconnect,
mixed answers, address-family ordering, and concurrent refresh. A theoretical
cache refresh or eviction race outside those tested conditions remains a
limitation; this profile is not universal DNS-rebinding prevention.

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

The Docker reference profile provides exact, deployment-specific evidence for
the enumerated server-side HTTP(S) paths and the tested bypass programs. It does
not change the default development, offline-demo, Render, Helm, or Kubernetes
topologies. An operator adopting the pattern elsewhere must independently prove
the pinned proxy policy, DNS behavior, direct IPv4/IPv6 denial, dependency
allowances, logs, and exact workload inventory for that deployment.

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
- No Kubernetes Phase 2 claim.
- No protection for unenumerated protocols, future clients, or unmanaged SDK transports.
- No protection against an allowed destination.
- No production or managed-provider certification.
