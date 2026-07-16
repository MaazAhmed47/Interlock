# Interlock Production Readiness

Interlock is prepared for controlled design-partner evaluation. This document separates what is already implemented from the remaining work required before broad enterprise production rollout.

## Executive Status

| Area | Current state | Enterprise target |
|---|---|---|
| Admin auth | Bootstrap `ADMIN_TOKEN`, scoped revocable admin tokens, OIDC JWT verification, dashboard PKCE login, and admin audit identity | SAML if required, tenant/team admin policy, and mature session controls |
| Customer auth | Hashed API keys, per-key plans, quotas, fail modes, policies, webhook/SIEM config | Customer/team tenancy, key rotation UX, service account lifecycle |
| Database | SQLite for local/pilot, Postgres/Supabase via `DATABASE_URL`, idempotent schema init | Managed Postgres, migration workflow, tested restore procedure |
| Rate limiting | Local fallback plus Redis-backed shared limit when `REDIS_URL` is set | Redis required for multi-replica deployments, alerts on fallback |
| Audit retention | Admin-managed retention policy for scan history, MCP audit, admin audit, and usage logs | Contract-specific retention, legal hold/export workflow |
| Observability | `/health`, structured logs, Prometheus/ServiceMonitor chart hooks | Dashboards, alerts, traces, SIEM export verified in target environment |
| Deployment | Docker, Helm, Vercel dashboard, production values example | Repeatable pilot runbook for Render/Vercel/AWS/Kubernetes |
| CI/CD | Backend, frontend, Helm, and Docker checks in GitHub Actions | Release tags, image signing/SBOM, environment promotion gates |

## CTO Trust Evidence

Show these during a design-partner call:

- Supabase/Postgres smoke test passes with schema verification.
- Write smoke test creates, looks up, and revokes one admin token and one customer API key.
- API keys and admin tokens are hashed at rest.
- Dashboard shows demo mode before a live key and live data after connecting a key.
- MCP gateway shows registered servers, tool baselines, drift/quarantine state, and audit events.
- `/health` reports DB/rate-limit readiness.
- Helm chart renders production values without secrets in the repo.
- CI builds backend, frontend, Helm manifests, and Docker image.

## Local Supabase Auth Redirect

For local dashboard testing, Supabase Auth must be allowed to redirect to:

```text
http://localhost:4173/dashboard/auth/callback
```

If a magic link opens `http://localhost:3000/#access_token=...`, the Supabase project Site URL is still set to the default development URL or the dashboard callback is not listed in Supabase Auth redirect URLs. Update it in Supabase Dashboard under Authentication -> URL Configuration:

- Site URL: `http://localhost:4173`
- Redirect URLs: `http://localhost:4173/dashboard/auth/callback`

The repository also includes `scripts/supabase_auth_redirect_server.py`, a local-only shim that listens on `localhost:3000` and forwards the token fragment into the Interlock dashboard callback. This is only for local development. Do not use it in production.

## SSO/OIDC/SAML Path

Implemented OIDC foundation:

- Admin endpoints accept `Authorization: Bearer <oidc-jwt>` when `OIDC_ADMIN_ENABLED=true`.
- Tokens are verified against issuer, audience, expiry, allowed signing algorithms, and JWKS.
- IdP groups or role claims map to Interlock roles: `owner`, `operator`, `security_reviewer`, `auditor`.
- Dashboard supports Supabase Auth login at `/dashboard/login` using OAuth provider redirect or email magic link, plus generic OIDC Authorization Code + PKCE for other IdPs.
- Admin Audit reads `/admin/audit` with the signed-in bearer token and shows actor identity, role, auth type, action, target, result, and reason.
- OIDC admin email/domain allowlists can restrict Supabase/social-login users to approved administrators.
- `ADMIN_TOKEN` remains the bootstrap/break-glass credential.
- Scoped admin tokens still work for service operations and emergency access.

Current safe pilot posture:

- Use OIDC for human admin access when the buyer has an IdP ready.
- Use `ADMIN_TOKEN` only as bootstrap or break-glass.
- Keep the bootstrap token in a secret manager and rotate it after setup.
- Configure dashboard Supabase Auth or generic OIDC values in `interlock-web/.env.example` or Settings.
- Keep the dashboard on HTTPS and restrict CORS to the deployed dashboard origin before public deployment.

Enterprise target still remaining:

- SAML if a design partner requires it.
- Tenant/team admin model and more granular customer admin boundaries.
- Session policy refinements such as refresh-token handling, idle timeout UX, and forced logout after role changes.

## Hosted Deployment Requirements

Minimum pilot environment:

- HTTPS endpoint for the API gateway.
- `ADMIN_TOKEN` in a secret manager.
- `DATABASE_URL` pointing to managed Postgres.
- `REDIS_URL` set before running more than one worker or replica.
- Provider keys only on the gateway host, never in browser code.
- Dashboard deployed separately with `VITE_INTERLOCK_API_URL` pointing at the gateway.
- CORS restricted to the dashboard origin before public deployment.

Kubernetes pilot:

- Use `helm/values-production.example.yaml`.
- Create `interlock-runtime-secrets` out of band.
- Enable NetworkPolicy and ingress TLS.
- Enable ServiceMonitor when Prometheus Operator is present.
- Keep persistent volume disabled when Postgres is configured.

## Rate Limiting

Interlock uses an in-memory sliding-window rate limiter by default. This works correctly with a single worker (the default). If you scale to multiple pods or workers, each instance maintains its own independent rate-limit window — meaning a single API key can exceed its configured limit by a factor equal to the number of replicas.

Before running more than one worker or pod, set `REDIS_URL` to enable distributed rate limiting:

```bash
REDIS_URL=redis://your-redis-host:6379/0
```

Without Redis, run with `--workers 1` (already the default in the Dockerfile). The `/health` endpoint reports whether Redis is configured and reachable. If Redis is configured but unavailable, Interlock falls back to in-memory mode and the health response reflects the degraded state.

## Redis Production Check

Redis is implemented as an optional shared rate-limit backend. Before scaling horizontally:

```bash
export REDIS_URL="redis://..."
python -m uvicorn proxy:app --host 0.0.0.0 --port 8001 --workers 1
curl http://localhost:8001/health
```

Expected: health output should show Redis configured and available. If Redis is configured but unavailable, Interlock falls back safely but the environment should be treated as degraded for multi-replica production.

## Observability Baseline

For pilots:

- collect container stdout/stderr logs
- scrape `/metrics` when metrics are enabled in Helm
- alert on `/health` failure
- alert on Redis fallback when `REDIS_URL` is configured
- alert on elevated block/quarantine rates
- review `/admin/audit` for human/operator control-plane actions
- send audit/security events to Slack, Datadog, Splunk, Elastic, PagerDuty, or generic webhook through key-level SIEM config

Production dashboards should include:

- scan volume and latency
- admin actions by actor/auth type
- allow/block/monitor/quarantine decision split
- threat level distribution
- MCP drift/quarantine count
- Redis availability
- DB availability
- webhook/SIEM dispatch failures

## Compliance Posture

Interlock is pre-certification and does not currently claim SOC 2, ISO 27001, HIPAA, GDPR certification, or an Interlock DPA. For design-partner reviews, use [compliance-posture.md](compliance-posture.md) to separate Interlock-owned security artifacts from Supabase/Vercel/Render vendor compliance references.

Do not present vendor SOC 2, ISO, DPA, TIA, or HIPAA documents as Interlock certifications. They support the selected deployment path, but Interlock still needs its own legal/security review before making product-level compliance claims.

## Backup And Restore

For Supabase/Postgres pilots:

- enable managed backups appropriate to the plan
- consider PITR for production-like pilots
- run a restore rehearsal before live customer traffic
- document RPO/RTO in the pilot agreement
- store exported audit logs outside the primary DB if the customer requires independent evidence retention

SQLite schema cleanup migrations use native `ALTER TABLE ... DROP COLUMN` and
require SQLite 3.35 or newer. Back up the database first, then run `db.init_db()`
through the supported Python 3.12 runtime; startup fails explicitly on an older
SQLite engine instead of rebuilding the table or risking loss of unknown columns.
The native SQLite operation rewrites the affected table and holds its schema/write
lock for the statement, so run it during a low-traffic local or pilot window.

Postgres obsolete-column cleanup uses `ALTER TABLE ... DROP COLUMN IF EXISTS`.
It is a catalog-only change rather than a heap rewrite, but it takes an
`ACCESS EXCLUSIVE` relation lock while the statement runs. The startup migration
checks the catalog first, so subsequent initializations do not reacquire that lock.

Supabase's current backup docs describe daily backups for hosted projects and optional Point-in-Time Recovery for finer restore granularity. See [Supabase Database Backups](https://supabase.com/docs/guides/platform/backups).

## Secret Rotation

Rotate immediately when a secret appears in chat, screenshots, logs, or support tickets:

- Supabase database password
- `ADMIN_TOKEN`
- Interlock customer API keys
- scoped admin tokens
- Redis password
- provider keys
- webhook or SIEM tokens

Use [secret-rotation.md](secret-rotation.md) as the runbook.

## Production Gates

Ready for design partner:

- demo dashboard deployed
- GitHub README/screenshots/quickstart polished
- Supabase smoke test passing
- CI passing
- one controlled API/MCP flow verified end-to-end

Ready for paid pilot:

- hosted gateway with HTTPS
- Postgres and Redis configured
- admin access protected by buyer-approved identity boundary
- retention policy agreed, including admin audit retention
- alerting and SIEM/webhook route tested
- backup restore rehearsal completed
- security hardening checklist accepted

Ready for broad enterprise rollout:

- SAML only if required by target customers
- migration process and rollback plan
- release process with signed images or SBOM
- tenant/team admin model
- formal incident response and support workflow
- documented SLA/SLO
