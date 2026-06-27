# Interlock Provider Proof Packs

These proof packs are the provider-specific demonstrations Interlock should use when speaking to design partners. They sit on top of the generic engines already in the gateway: surface drift, metadata drift, external reach drift, response/data-exposure drift, outcome/effect drift, temporal effect drift, effective-permission probes, provider readback canaries, and pre-execution chain analysis.

The rule: every proof pack must have a safe non-production baseline, a single simulated escalation, a false-positive control, and a Security Receipt.

## Terraform / Infra

Baseline: `terraform_plan` or equivalent preview-only tool.

Scenarios:
- Easy: description/schema adds optional field; monitor only.
- Medium: plan-only result changes to `applied: true`; quarantine with `effect_mutation_after_preview`.
- Hard: plan-only result changes to `deploy_at` / `delete_at`; quarantine with temporal deploy/destructive findings.
- Extreme: planned chain `terraform_plan -> terraform_apply -> cleanup_old_stack`; deny pre-execution with `chain_preview_to_deploy` / `chain_preview_to_destructive`.

Proof: no cloud credentials needed for the baseline proof; use a mock or sandbox workspace. Provider readback can check sandbox resource count before/after for hidden apply/delete.

Runnable local pack:

```bash
python3 demo/run_terraform_proof_pack.py
```

Current pack status: two Terraform proof levels exist:

1. Local mock/sandbox proof: exercises Interlock's real effect-drift, temporal-drift, readback-drift, chain-drift, receipt, and evidence-ref paths with Terraform-shaped payloads. It does not call Terraform CLI, Terraform Cloud, a cloud provider, or a production MCP server.

2. Real local Terraform CLI proof:

```bash
python3 demo/run_terraform_cli_proof_pack.py --terraform-bin /path/to/terraform
```

This runs real `terraform init`, `terraform plan`, `terraform apply`, and `terraform destroy` in a temporary local sandbox using Terraform's built-in `terraform_data` resource. It requires no cloud credentials, no Terraform Cloud account, no remote backend, and no external provider plugin. Interlock readback checks the local Terraform state before/after apply and destroy, then emits readback-effect receipts. The current verified run used Terraform CLI 1.9.8.

Do not claim this is AWS/GCP/Azure or Terraform Cloud coverage. It is real Terraform CLI local-state coverage. A future cloud proof should use a tightly scoped sandbox account/project and the same before/after readback pattern.

## Email / Messaging

Baseline: read, preview, or draft-only email/social message tool.

Scenarios:
- Easy: preview/dry-run stays preview/dry-run; allow with no false positive.
- Medium: new external recipient/domain appears with sensitive payload indicators; quarantine via `external_secret_destination_added`.
- Hard: response changes from preview/dry-run to `sent: true`; quarantine via `effect_external_send_after_preview`.
- Hard temporal: `send_at` appears after preview baseline; quarantine via `effect_temporal_external_after_preview`.
- Extreme hidden: target response says `dry_run: true`, but provider readback shows message state changed; quarantine via `silent_side_effect_drift`.
- Extreme chain: `read_inbox -> post_to_slack`; deny with `chain_sensitive_read_to_external_effect`.

Runnable local mock pack:

```bash
python3 demo/run_email_proof_pack.py
```

This exercises Interlock's real effect-drift, temporal-drift, external-reach, provider-readback, chain-drift, receipt, and evidence-ref paths with email/messaging-shaped payloads. It does not call Gmail, iCloud, Fastmail, SMTP, Slack, or a production MCP server.

Runnable real local SMTP pack:

```bash
python3 demo/run_email_smtp_proof_pack.py
```

This starts a local SMTP sandbox on `127.0.0.1`, sends a real SMTP message through Python's SMTP client, reads back the local captured outbox before/after, and emits a readback-effect Security Receipt for the hidden-send case. It requires no external email account, no OAuth tokens, no SMTP credentials, and no internet access.

Credential-gated live provider harness:

```bash
python3 demo/run_email_live_proof_pack.py
```

By default this exits as a safe skip and sends nothing. It runs only when `INTERLOCK_ALLOW_LIVE_PROVIDER_PROOFS=1` and a sandbox provider is configured through environment variables. Supported live harness targets are:

- Gmail API: `INTERLOCK_LIVE_PROVIDER=gmail`, `INTERLOCK_GMAIL_ACCESS_TOKEN`, `INTERLOCK_GMAIL_FROM`, `INTERLOCK_GMAIL_TO`.
- iCloud/Fastmail/IMAP+SMTP: `INTERLOCK_LIVE_PROVIDER=icloud`, `fastmail`, or `imap_smtp`, plus `INTERLOCK_IMAP_HOST`, `INTERLOCK_IMAP_USERNAME`, `INTERLOCK_IMAP_PASSWORD`, `INTERLOCK_SMTP_HOST`, `INTERLOCK_SMTP_USERNAME`, `INTERLOCK_SMTP_PASSWORD`, `INTERLOCK_EMAIL_FROM`, and `INTERLOCK_EMAIL_TO`.
- Slack: `INTERLOCK_LIVE_PROVIDER=slack`, `INTERLOCK_SLACK_BOT_TOKEN`, `INTERLOCK_SLACK_CHANNEL_ID`.

The live harness uses the same before/after provider-readback pattern: preview/no-send control, hidden send/post drift, and expected-send allowed control. Reports hash canary labels and provider objects; they do not store OAuth tokens, app passwords, SMTP passwords, raw message bodies, raw recipients, channel names, or full provider responses.

Verified live sandbox proof: Slack and Gmail provider-readback runs produced PASS output on 2026-06-27. Both runs detected hidden send/post side effects as `critical` / `quarantine` while preview/no-send and expected-send controls stayed allowed. See [`live-provider-readback-proof.md`](live-provider-readback-proof.md).

Do not claim a live iCloud/Fastmail/IMAP+SMTP proof has been run unless the credential-gated harness was actually executed against a sandbox account and produced PASS output. Current verified automated coverage proves the harness with injected providers and safe skip behavior; additional real provider execution still requires sandbox credentials.

## Database / Admin SaaS

Baseline: read-only SQL query, schema inspection, customer lookup, admin-directory inventory, or access-review preview.

Scenarios:
- Easy: SELECT/read-only output changes shape or row count; allow if the effect boundary stays read-only.
- Medium: read-only query starts reporting `updated: true` or affected rows; quarantine mutation drift.
- Hard: read-only/schema tool reports delete/drop/destroy effects; critical destructive drift.
- Hard temporal: access review schedules a role/privilege change later; quarantine temporal privilege drift.
- Extreme hidden: target response says read-only/dry-run, but provider readback shows a DB row changed; critical hidden side-effect drift.
- Extreme chain: `read_customer_rows -> export_customer_rows`, `read_database_secret -> run_sql_shell`, or `list_admin_users -> disable_user_account`; deny before execution.

Runnable local SQLite sandbox pack:

```bash
python3 demo/run_database_admin_proof_pack.py
```

Current local SQLite status: covers SELECT/read-only no-change, read-only -> UPDATE, read-only -> DROP/delete, scheduled privilege change, hidden DB write detected through real local SQLite before/after readback, expected DB write allowed, customer data -> external export chain drift, DB secret -> shell execution chain drift, and admin directory -> disable user chain drift. It exercises Interlock's real effect-drift, readback-drift, chain-drift, receipt, and evidence-ref paths with database/admin-SaaS-shaped payloads.

Do not claim live MySQL, Postgres, Snowflake, NetBox, Zabbix, Microsoft 365, or production database proof from this SQLite pack. It contacts no remote database or admin tenant; live buyer coverage should use a tightly scoped non-production database or admin-SaaS sandbox.

Credential-gated Docker Postgres sandbox harness:

```bash
python3 demo/run_database_docker_proof_pack.py
```

By default this exits as a safe skip and starts no container. It runs only when `INTERLOCK_ALLOW_DOCKER_DB_PROOFS=1` is set and a local `postgres:*` image is available. The harness creates a disposable Docker Postgres container, runs real SQL through `psql` inside that container, reads back aggregate SQL state before/after, emits readback-effect receipts, and stops the container.

Verified live local Docker Postgres proof: the credential-gated Docker harness produced PASS output on 2026-06-27. Hidden INSERT, DROP, and role-grant side effects were detected as `critical` / `quarantine`, SELECT and expected UPDATE controls stayed allowed, and customer-export / secret-exec chains were denied. Cleanup verification showed no `interlock-db-proof` container left running.

Do not claim live Snowflake, NetBox, Zabbix, Microsoft 365, hosted Postgres, or production database proof from this pack. This is real local Docker Postgres coverage only; live buyer coverage should use a tightly scoped non-production database or admin-SaaS sandbox.

Credential-gated Docker MySQL sandbox harness:

```bash
python3 demo/run_database_mysql_docker_proof_pack.py
```

By default this exits as a safe skip and starts no container. It runs only when `INTERLOCK_ALLOW_DOCKER_MYSQL_PROOFS=1` is set and a local `mysql:*` image is available. The harness creates a disposable Docker MySQL container, runs real SQL through `mysql` inside that container, reads back aggregate SQL state before/after, emits readback-effect receipts, and stops the container.

Verified live local Docker MySQL proof: the credential-gated Docker harness produced PASS output on 2026-06-27. Hidden INSERT, DROP, and admin-user grant side effects were detected as `critical` / `quarantine`, SELECT and expected UPDATE controls stayed allowed, and customer-export / secret-exec chains were denied. Cleanup verification showed no `interlock-mysql-proof` container left running.

Do not claim live MariaDB, Snowflake, NetBox, Zabbix, Microsoft 365, hosted MySQL, or production database proof from this pack. This is real local Docker MySQL coverage only; live buyer coverage should use a tightly scoped non-production database or admin-SaaS sandbox.


## App Store / Release Automation

Baseline: metadata/read-only app-version inspection or screenshot validation.

Scenarios:
- Easy: schema adds new metadata fields; monitor unless risk-bearing.
- Medium: tool gains screenshot upload or pricing/IAP fields; capability drift.
- Hard: preview/validate changes to `submitted: true` or `released: true`; critical effect drift.
- Hard temporal: `release_at` / phased release scheduling appears; critical temporal deploy/release drift.
- Extreme chain: `read_app_metadata -> update_pricing -> submit_for_review`; deny or quarantine based on money/release effect.

Runnable local mock pack:

```bash
python3 demo/run_app_store_proof_pack.py
```

Current local mock status: covers metadata preview no-change, preview -> submit, preview -> scheduled release, hidden release detected through provider-readback profiles, expected release allowed, metadata/pricing -> submit chain drift, and tester PII -> external invite chain drift. It exercises Interlock's real effect-drift, readback-drift, chain-drift, receipt, and evidence-ref paths with App Store / release-automation-shaped payloads.

Do not claim live App Store Connect or TestFlight proof has been run. This pack contacts no Apple API, uses no Apple account, and should only be replaced by live coverage with a dedicated sandbox app plus explicit operator approval.

## Kubernetes / DevOps

Baseline: read-only cluster inventory or dry-run manifest validation.

Scenarios:
- Easy: namespace/scope field widens; surface/auth-scope review.
- Medium: read-only tool gains `apply` or `patch`; capability/effect drift.
- Hard: dry-run result changes to `deployed: true`; critical deploy drift.
- Hard temporal: delayed rollout/delete job is scheduled; temporal deploy/destructive drift.
- Extreme chain: `get_secret -> run_exec` or `list_pods -> delete_namespace`; deny pre-execution with chain drift.

Runnable local mock pack:

```bash
python3 demo/run_kubernetes_proof_pack.py
```

Current local mock status: covers clean read-only inventory, dry-run -> apply, dry-run -> scheduled namespace delete, hidden apply detected through provider-readback profiles, secret read -> pod exec chain drift, and inventory -> namespace delete chain drift. It exercises Interlock's real effect-drift, readback-drift, chain-drift, receipt, and evidence-ref paths with Kubernetes-shaped payloads.

Credential-gated kubectl sandbox harness:

```bash
python3 demo/run_kubernetes_live_proof_pack.py
```

By default this exits as a safe skip and contacts no cluster. It runs only when `INTERLOCK_ALLOW_LIVE_KUBERNETES_PROOFS=1`, `INTERLOCK_KUBERNETES_CONTEXT`, and `INTERLOCK_KUBERNETES_NAMESPACE` are configured. The namespace must start with `interlock-`, and the harness never uses the current kubectl context implicitly.

The kubectl harness covers real before/after provider readback for inventory no-change, server-side dry-run no-change, hidden apply, expected apply, hidden delete, and pre-execution chain analysis. Reports hash the context, namespace, canary label, and object identities; they do not store kubeconfig contents, service-account tokens, cluster credentials, raw object names, manifests, or cloud credentials.

Verified live local Kubernetes proof: the credential-gated kubectl harness produced PASS output against a local Docker Desktop Kubernetes context on 2026-06-27. Hidden apply/delete side effects were detected as `critical` / `quarantine`, inventory and server-side dry-run controls stayed allowed, and secret -> exec / inventory -> namespace-delete chains were denied. See [`live-kubernetes-readback-proof.md`](live-kubernetes-readback-proof.md).

Do not claim kind/minikube/EKS/GKE/AKS live proof has been run unless the credential-gated kubectl harness was executed against that specific sandbox cluster and produced PASS output. The current automated coverage proves the harness with injected kubectl behavior and safe skip behavior.

## Payments / Billing

Baseline: quote, invoice preview, or balance read-only tool.

Scenarios:
- Easy: response starts exposing new financial/customer fields; response drift.
- Medium: tool gains refund/charge/transfer argument; surface/effect drift.
- Hard: preview result reports `charged`, `refunded`, or `transferred`; critical money-movement drift.
- Hard temporal: `charge_at` / `refund_at` is scheduled; critical temporal money drift.
- Extreme hidden: target says preview, but readback balance/ledger changes; readback hidden side-effect drift.
- Extreme chain: `read_customer_payment_method -> charge_customer`; deny pre-execution chain drift.

Runnable local mock pack:

```bash
python3 demo/run_payments_proof_pack.py
```

Current local mock status: covers quote/preview no-change, preview -> charge, preview -> scheduled refund, hidden charge detected through provider-readback profiles, expected charge allowed, payment-method -> charge chain drift, and quote -> transfer chain drift. It exercises Interlock's real effect-drift, readback-drift, chain-drift, receipt, and evidence-ref paths with payment-shaped payloads.

Credential-gated Stripe test-mode harness:

```bash
python3 demo/run_payments_live_proof_pack.py
```

By default this exits as a safe skip and contacts no payment provider. It runs only when `INTERLOCK_ALLOW_LIVE_PAYMENTS_PROOFS=1` and `INTERLOCK_STRIPE_SECRET_KEY` is configured with a Stripe test-mode key. Live-mode keys are rejected.

The Stripe test-mode harness covers quote no-change, hidden charge readback, expected charge allowed, hidden refund readback, and pre-execution chain analysis for payment-method -> charge and quote -> transfer. Reports hash canary labels and payment objects; it does not store Stripe secret keys, raw card data, customer ids, payment method ids, charge ids, refund ids, account ids, full provider responses, or webhook payloads.

Do not claim live Stripe test-mode proof has been run unless the credential-gated harness was actually executed with a Stripe test-mode key and produced PASS output. Current automated coverage proves the harness with injected Stripe behavior and safe skip behavior.

## Required Proof Artifacts

Each provider proof pack should produce:
- baseline profile hash
- drift/current profile hash
- finding type and severity
- allow/monitor/deny/quarantine decision
- audit row id
- Security Receipt with drift evidence ref
- false-positive control proving unchanged safe behavior stays allowed
- explicit limitation note: what was mocked, what was live, and whether provider readback was used
