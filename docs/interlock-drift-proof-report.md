# Interlock Drift Proof Report

Interlock is an MCP runtime trust layer for one specific failure mode: an agent keeps trusting a tool after the tool is no longer the same risk it approved.

The buyer question is simple:

> Is this still the approved tool, and is this call still allowed now?

This report packages the proof that Interlock answers that question across multiple drift classes: manifest/surface drift, metadata drift, behavioral effective-permission drift, response/data-exposure drift, external reach drift, hidden side-effect readback drift, provider-specific drift, and multi-step chain drift.

## Executive Summary

Interlock now has proof packs that exercise the real detection and receipt paths across safe local mocks, local protocol boundaries, credential-gated sandbox providers, disposable Docker databases, and local Kubernetes/Terraform-style workflows.

What matters to a buyer:

- Interlock does not only diff JSON schemas.
- It classifies materiality: read-only to destructive is different from description churn.
- It can quarantine or deny high-risk drift before continued use.
- It can catch opaque behavioral drift, such as previously denied calls becoming allowed while the manifest stays unchanged.
- It can catch hidden side effects through before/after provider readback when a tool response lies.
- It emits evidence-safe Security Receipts and hashes sensitive values instead of storing raw tokens, SQL, messages, rows, IDs, or provider payloads.

The strongest current proof categories are:

- Surface/capability drift through the gateway discovery path.
- Effective-permission drift: denied -> allowed behavior with unchanged manifest/schema/arguments.
- Hidden side-effect drift through Slack, Gmail, SMTP, Kubernetes, Docker Postgres, and Docker MySQL style readback.
- Chain drift: sensitive read -> external send, secret read -> execution, preview -> deploy/delete/charge.

## One-Command Proof Suite

Run the buyer-facing proof suite:

```bash
python3 demo/run_interlock_proof_suite.py
```

Optional outputs:

```bash
python3 demo/run_interlock_proof_suite.py --json
python3 demo/run_interlock_proof_suite.py --markdown-output interlock-proof-run.md
python3 demo/run_interlock_proof_suite.py --include-terraform-cli
```

The suite prints `PASS`, `SKIP`, or `FAIL` for each proof pack.

- `PASS` means the scenarios ran and the expected Interlock decision matched.
- `SKIP` means a credential-gated live provider was not configured, so no provider was contacted.
- `FAIL` means a proof pack did not produce the expected detection/control outcome.

A skip is deliberately not counted as live proof. It is there to keep the command safe by default.

## Proof Coverage Matrix

| Area | Proof pack | What it proves | Current status | Buyer relevance |
| --- | --- | --- | --- | --- |
| Surface/capability drift | `demo/run_drift_matrix.py` | Approved tools changing schema, effects, data classes, externality, annotations, or destructive behavior | Local HTTP mock through real gateway discovery path | Core MCP wedge: the approved tool is no longer the approved tool |
| Behavioral/effective-permission drift | `demo/run_effective_permission_probe_live.py` | Same tool, schema, and args; previously denied call becomes allowed | Local live-style HTTP probe through real probe route | Catches opaque upstream scope expansion that manifest diffing cannot see |
| Response/data-exposure drift | `demo/run_response_drift.py` | Tool output starts exposing PII, secrets, or much larger result sets | Local synthetic responses with evidence-safe records | Useful for data-leak and compliance-sensitive agent workflows |
| External-reach drift | `demo/run_external_reach_drift.py` | Trusted destination changes to a new external host, especially with secret indicators | Local destination-profile proof | Important for webhook, Slack, email, API, and exfiltration-like tool drift |
| Terraform/infra | `demo/run_terraform_proof_pack.py` | Plan-only workflows drift to apply/destroy/deploy chains | Local Terraform-shaped sandbox | Sharp DevOps proof: plan vs apply/destroy is an obvious buyer pain |
| Real Terraform CLI | `demo/run_terraform_cli_proof_pack.py` | Local `terraform plan/apply/destroy` state readback using `terraform_data` | Optional local CLI proof, no cloud provider | Stronger than mock, but still not AWS/GCP/Azure/Terraform Cloud proof |
| Email/messaging | `demo/run_email_proof_pack.py` | Preview/draft/read flows drift to send/post/schedule/export chains | Local message-shaped sandbox | Maps to Gmail, Slack, customer-support, sales, and notification agents |
| Real local SMTP | `demo/run_email_smtp_proof_pack.py` | Hidden send detected through an actual SMTP boundary on `127.0.0.1` | Local protocol proof | Shows Interlock is not just trusting the MCP server response |
| Live Gmail/Slack/IMAP | `demo/run_email_live_proof_pack.py` | Hidden send/post through real sandbox provider readback | Credential-gated; Slack and Gmail sandbox runs verified on 2026-06-27 | Strong messaging proof when sandbox credentials are available |
| Database/admin SaaS | `demo/run_database_admin_proof_pack.py` | SELECT/read-only drifts to UPDATE/DROP/privilege change/export/secret-exec chains | Local SQLite sandbox | Maps to MySQL, Postgres, Snowflake, admin tools, and CRM-like tools |
| Docker Postgres | `demo/run_database_docker_proof_pack.py` | Hidden INSERT, DROP, role grant, export chain, secret-exec chain via real Postgres SQL readback | Credential-gated; live local Docker Postgres run verified on 2026-06-27 | Strong database proof for Postgres/MCP database targets |
| Docker MySQL | `demo/run_database_mysql_docker_proof_pack.py` | Hidden INSERT, DROP, admin-user grant, export chain, secret-exec chain via real MySQL SQL readback | Credential-gated; live local Docker MySQL run verified on 2026-06-27 | Strong database proof for MySQL/MariaDB-adjacent MCP targets |
| Kubernetes/DevOps | `demo/run_kubernetes_proof_pack.py` | Inventory/dry-run drifts to apply/delete/exec/namespace-delete chains | Local Kubernetes-shaped sandbox | Maps to infra/admin MCP tools with real blast radius |
| Live kubectl sandbox | `demo/run_kubernetes_live_proof_pack.py` | Hidden apply/delete through real kubectl readback | Credential-gated; Docker Desktop sandbox verified on 2026-06-27 | Strong DevOps proof without touching production clusters |
| App Store/release automation | `demo/run_app_store_proof_pack.py` | Metadata preview drifts to submit/release/tester invite chains | Local release-automation sandbox | Maps to App Store Connect and release automation MCP tools |
| Payments/billing | `demo/run_payments_proof_pack.py` | Quote/preview drifts to charge/refund/transfer/payment-method chains | Local payment-shaped sandbox | Maps to Stripe/payment/workflow MCPs |
| Stripe test-mode | `demo/run_payments_live_proof_pack.py` | Hidden charge/refund and payment chains against test-mode readback | Credential-gated; safe skip unless test-mode key is configured | Strongest payment proof once a sandbox key is available |

## Buyer Interpretation

If you maintain or buy an MCP server with real blast radius, Interlock is relevant when a tool can:

- read customer data
- write to a database
- send email or Slack messages
- deploy, apply, destroy, or delete infrastructure
- change admin users, roles, or scopes
- submit releases or publish content
- charge, refund, transfer, or mutate financial state
- call a broad API where server-side authorization may silently expand

The important distinction is not whether the tool is dangerous today. It is whether the approved tool can become more dangerous tomorrow while keeping the same name and integration path.

## What Interlock Proves Today

### 1. It detects surface drift

Interlock baselines approved MCP tool surfaces and detects material changes to schemas, required fields, data classes, side effects, external reach, and metadata. It treats benign description churn differently from a read-only tool gaining write/export/delete behavior.

### 2. It detects behavioral drift

Effective-permission probes cover the Genesys-style case:

- same tool
- same schema
- same arguments
- same manifest
- previously returned `403 denied`
- later returns `200 allowed`

That is not visible to a manifest diff. Interlock labels it behavioral effective-permission drift and can quarantine the tool.

### 3. It detects hidden side effects

Provider readback packs catch cases where the MCP server says `dry_run: true` or `preview: true`, but the provider state changed anyway. This is proven through local SMTP, Slack/Gmail sandbox runs, Kubernetes/kubectl readback, Docker Postgres, and Docker MySQL.

### 4. It detects multi-step chains

Some risk only appears across calls:

- `read_customer_rows -> export_customer_rows`
- `read_database_secret -> run_sql_shell`
- `get_secret -> pod_exec`
- `preview_payment -> charge_customer`
- `terraform_plan -> terraform_apply -> terraform_destroy`

Interlock can deny those planned chains before execution when the orchestrator submits or exposes the chain.

### 5. It produces evidence-safe receipts

The proof packs are designed to avoid storing raw sensitive material. Reports and receipts store hashes/counts rather than raw:

- OAuth tokens
- app passwords
- SQL text
- row values
- customer emails
- Slack channel names
- message bodies
- card numbers
- provider object IDs
- kubeconfig contents
- Terraform workspace paths
- container IDs

## Enterprise Boundary Controls

The hard edge cases are documented in [`interlock-enterprise-boundary-controls.md`](interlock-enterprise-boundary-controls.md): unobserved chains, provider OAuth introspection limits, production proof requirements, rollback/remediation, and compliance posture. The short version: Interlock is strongest when it sees the surface, call, provider readback, or planned chain; when it sees none of those, the buyer needs routing enforcement or provider audit integration.

## What Not To Claim

Do not overstate this work.

Interlock does not claim:

- universal certification of every MCP server
- proof across every provider edge case
- production proof for a buyer until their own non-production workflow is tested
- OAuth/provider introspection unless a provider-specific integration exists
- automatic prediction of future chains that Interlock never sees
- rollback of a side effect that already happened in a canary proof

The honest claim is stronger:

> Interlock has broad, tested drift coverage across surface, behavioral, response, external-reach, hidden side-effect, provider-readback, and chain drift, with evidence-safe receipts and safe non-production proof packs.

## Best Pilot Ask

For a design partner or paid pilot, the clean ask is:

> I can run a scoped non-production drift check against one MCP workflow: baseline the approved tool surface, simulate one safe escalation, show whether Interlock catches it before continued use, and send you the receipt/evidence report. No production credentials, no sensitive data, no real customer environment.

Best first targets:

- database MCPs: MySQL, Postgres, Snowflake, BigQuery
- admin/infra MCPs: Kubernetes, Terraform, Zabbix, NetBox, Microsoft 365 admin
- messaging MCPs: Gmail, Slack, email automation, social publishing
- payment/release MCPs: Stripe, billing, App Store/release automation
- broad API gateways: tools with generic `call_api` behavior and OAuth scopes

## Enterprise Objections And Answers

**Why trust a solo-founder security tool?**

Because the first engagement does not require trust in production. It is scoped to a non-production workflow, uses safe canaries, stores hashes instead of secrets, and produces recomputable evidence. The goal is to prove or disprove one concrete drift boundary before any deeper deployment.

**Is this just schema diffing?**

No. Schema/surface drift is one layer. The suite also covers behavioral denied-to-allowed drift, response/data exposure, external destination drift, hidden side effects through provider readback, and chain drift.

**Can this block production?**

The correct early deployment is non-production or shadow/canary mode. Interlock can quarantine/deny based on policy, but a serious buyer should first run it against one bounded workflow and inspect the receipts.

**Do you have certifications?**

Not yet. The current proof is technical, not compliance. The right first step is a scoped technical evaluation with evidence-safe receipts. Compliance posture can follow buyer demand.

## Recommended Next Artifact

For every serious outreach target, attach or link:

1. this report
2. the one-command proof-suite output
3. one target-specific proof excerpt
4. the non-production pilot ask

That gives the buyer a reason to talk without asking them to believe a broad marketing claim.
