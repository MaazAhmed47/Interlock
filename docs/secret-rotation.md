# Secret Rotation Runbook

Use this whenever a secret is pasted into chat, appears in a screenshot, lands in logs, or is shared with someone who should not have long-term access.

## Immediate Rule

Do not try to "hide" an exposed secret. Rotate it. Assume it is no longer private.

## Supabase Database Password

1. Open the Supabase project dashboard.
2. Go to the database settings page and reset the database password.
3. Copy the new Postgres connection string.
4. URL-encode special password characters before putting it in `.env`:
   - `?` becomes `%3F`
   - `@` becomes `%40`
   - `#` becomes `%23`
   - `&` becomes `%26`
   - `:` becomes `%3A`
   - `/` becomes `%2F`
5. Update `DATABASE_URL` in the deployment secret manager.
6. Restart the gateway.
7. Run:

```bash
python3 scripts/supabase_smoke.py
python3 scripts/supabase_smoke.py --write-test
```

Expected: both smoke tests pass.

## Bootstrap Admin Token

Generate a new token:

```bash
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

Then:

1. Replace `ADMIN_TOKEN` in the secret manager.
2. Restart the gateway.
3. Issue fresh scoped admin tokens.
4. Revoke old scoped admin tokens through `/admin/tokens/{token_prefix}`.
5. Store the bootstrap token only in the secret manager.

## Scoped Admin Tokens

List active tokens:

```bash
curl -s "https://<interlock-api>/admin/tokens"   -H "x-admin-token: <bootstrap-or-owner-token>"
```

Revoke a token:

```bash
curl -s -X DELETE "https://<interlock-api>/admin/tokens/<token-prefix>"   -H "x-admin-token: <bootstrap-or-owner-token>"
```

Issue a replacement:

```bash
curl -s -X POST "https://<interlock-api>/admin/tokens"   -H "x-admin-token: <bootstrap-or-owner-token>"   -H "Content-Type: application/json"   -d '{"label":"operator-name","role":"operator"}'
```

## Customer API Keys

1. Create a replacement key with `/admin/keys`.
2. Update the customer's agent/dashboard/client configuration.
3. Confirm traffic is using the new key.
4. Revoke the old key by its immutable list-response ID with
   `/admin/keys/id/{key_id}`. The prefix route is legacy-only and rejects
   ambiguous matches.

Administrative updates and historical usage queries follow the same identity
rule: use `PATCH /admin/keys/id/{key_id}` and
`GET /admin/keys/id/{key_id}/usage`. Legacy prefix forms work only when the
prefix resolves to exactly one row, including inactive rows for usage history.

## Provider Keys

Rotate upstream provider keys in the provider dashboard:

- OpenAI
- Anthropic
- Groq
- Gemini

Then update the deployment secret manager and restart the gateway. Provider keys must stay on the Interlock host and must not be embedded in frontend code.

## Redis Credentials

1. Rotate the password in the managed Redis provider.
2. Update `REDIS_URL` in the secret manager.
3. Restart all Interlock gateway instances.
4. Confirm `/health` reports Redis available.

## Webhooks And SIEM Tokens

Rotate Slack, Datadog, Splunk, Elastic, PagerDuty, or generic webhook credentials in the provider system. Update the affected Interlock key's `siem_configs` or `webhook_url`, then send a test event.

## After Rotation

Record:

- what was rotated
- when it was rotated
- who performed the rotation
- smoke test results
- whether any old token was revoked or disabled
