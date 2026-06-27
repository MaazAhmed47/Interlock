# Interlock Drift Proof Suite Run

This is a generated run summary from `python3 demo/run_interlock_proof_suite.py`. It is meant to be attached to a design-partner or pilot conversation, not treated as a compliance certificate.

## Summary

- Passed packs: 11
- Skipped credential-gated packs: 5
- Failed packs: 0
- Scenarios observed: 70
- Receipts emitted: 52
- High/critical detections: 42

## Results

| Status | Proof | Drift class | Scenarios | Receipts | Why it matters |
| --- | --- | --- | ---: | ---: | --- |
| PASS | Surface and capability drift matrix | surface/capability/schema/metadata | 15 | 0 | Shows the core wedge: the same approved MCP tool becomes more dangerous and is held for review before continued use. |
| PASS | Behavioral effective-permission drift | auth-scope/effective permission | 1 | 12 | Catches the hard case where the manifest is unchanged but a call that used to be denied now succeeds. |
| PASS | Response/data-exposure drift | response/data exposure | 5 | 5 | Detects outputs that start exposing PII, secrets, or much larger result sets after approval. |
| PASS | Destination-aware external reach drift | external reach | 6 | 3 | Detects a trusted tool adding a new external destination, especially when secrets may ride along. |
| PASS | Terraform infra proof pack | deploy/destructive/chain | 5 | 4 | Proves plan-only workflows escalating to apply/destroy are quarantined or denied. |
| PASS | Email and messaging proof pack | external send/temporal/chain | 6 | 5 | Proves preview/draft-only messaging tools cannot silently become send/post tools without detection. |
| PASS | Real local SMTP readback proof | hidden side effect/readback | 3 | 1 | Shows hidden sends are caught by provider readback, not just by trusting the tool response. |
| PASS | Database/admin SaaS proof pack | database mutation/admin/chain | 9 | 7 | Proves read-only database/admin tools drifting to writes, drops, privilege changes, or secret-to-exec chains are caught. |
| PASS | Kubernetes/DevOps proof pack | deploy/destructive/secret-to-exec chain | 6 | 5 | Proves dry-run/inventory tools drifting to apply/delete/exec are quarantined or denied. |
| PASS | App Store/release automation proof pack | release/submission/temporal/chain | 7 | 5 | Proves metadata-preview workflows drifting to submit/release/tester invite are caught. |
| PASS | Payments/billing proof pack | money movement/temporal/chain | 7 | 5 | Proves quote/preview flows drifting to charge/refund/transfer are quarantined or denied. |
| SKIP | Credential-gated live Gmail/Slack/IMAP proof | live messaging provider readback | 0 | 0 | When sandbox credentials are configured, proves hidden send/post behavior against Gmail, Slack, or IMAP/SMTP readback. |
| SKIP | Credential-gated Docker Postgres proof | live local database readback | 0 | 0 | When explicitly enabled, proves hidden INSERT, DROP, role grant, and data-export/secret-exec chains against real Postgres SQL readback. |
| SKIP | Credential-gated Docker MySQL proof | live local database readback | 0 | 0 | When explicitly enabled, proves hidden INSERT, DROP, admin-user grant, and data-export/secret-exec chains against real MySQL SQL readback. |
| SKIP | Credential-gated kubectl sandbox proof | live Kubernetes provider readback | 0 | 0 | When configured, proves hidden apply/delete and risky chains against a real sandbox Kubernetes context. |
| SKIP | Credential-gated Stripe test-mode proof | live payment provider readback | 0 | 0 | When a test-mode key is configured, proves hidden charge/refund and payment chains against Stripe test-mode readback. |

## Honest Limits

- SKIP means the credential-gated provider was not configured and was not contacted.
- Local/mock proofs demonstrate Interlock's classifiers, receipts, and enforcement decisions without production credentials.
- Docker, Slack, Gmail, Kubernetes, Stripe, and Terraform CLI claims should only be made when the matching credential-gated harness produced PASS output in that environment.
- This suite is proof of drift detection behavior, not a compliance certification or guarantee that every provider edge case has been exhaustively tested.
