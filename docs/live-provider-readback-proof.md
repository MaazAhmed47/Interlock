# Live Provider Readback Proof

Date verified: 2026-06-27

This note records Interlock's credential-gated live provider readback proof for email/messaging tools. It is a proof artifact for non-production sandbox providers, not a provider certification or a claim that every provider edge case is covered.

## Claim

Interlock has live Slack and Gmail sandbox proof for provider-readback drift: when a tool response claims preview/no-effect but the external provider state changes, Interlock detects the contradiction, classifies it as critical, and quarantines, while clean controls stay allowed.

## Threat Model Proven

The tested scenario is hidden side-effect drift:

1. Interlock reads provider state before the target call.
2. The target call claims preview/no-send/no-effect semantics.
3. The provider state changes anyway.
4. Interlock reads provider state again.
5. Interlock compares evidence-safe before/after provider profiles.
6. If `expected_effect=no_change` and provider state changed, Interlock emits critical drift and quarantines the target tool.

This proves a class of drift that manifest/schema diffing cannot detect: same tool surface, same apparent response semantics, but a real external side effect happened.

## Verified Results

Command:

```bash
python3 demo/run_email_live_proof_pack.py
```

The live harness runs only when `INTERLOCK_ALLOW_LIVE_PROVIDER_PROOFS=1` and sandbox provider credentials are configured through environment variables.

### Slack Sandbox

Provider: Slack sandbox channel

Result:

```text
PASS live_provider_preview_no_send_control severity=none decision=allow findings=none
PASS live_provider_hidden_send_readback_drift severity=critical decision=quarantine findings=readback_state_changed_after_no_effect_expected,silent_side_effect_drift,effect_response_contradicted_by_readback
PASS live_provider_expected_send_allowed_control severity=none decision=allow findings=none
```

What passed:

- Preview/no-send control stayed clean.
- Hidden post/send side effect was detected through provider readback.
- Hidden side effect was classified `critical`.
- Decision was `quarantine`.
- Expected send control stayed allowed.

### Gmail Sandbox

Provider: Gmail API sandbox account

Result:

```text
PASS live_provider_preview_no_send_control severity=none decision=allow findings=none
PASS live_provider_hidden_send_readback_drift severity=critical decision=quarantine findings=readback_state_changed_after_no_effect_expected,silent_side_effect_drift,effect_response_contradicted_by_readback
PASS live_provider_expected_send_allowed_control severity=none decision=allow findings=none
```

What passed:

- Preview/no-send control stayed clean.
- Hidden email send side effect was detected through real Gmail provider readback.
- Hidden side effect was classified `critical`.
- Decision was `quarantine`.
- Expected send control stayed allowed.

## Evidence Safety

The live harness is designed to avoid storing provider secrets or sensitive message data.

It does not store:

- OAuth access tokens
- Slack bot tokens
- app passwords or SMTP passwords
- raw message bodies
- raw recipients
- raw channel names
- full provider responses

It stores or reports:

- provider names as labels
- canary labels as hashes
- provider objects as hashes
- before/after provider profile hashes
- finding types, severity, decision, and receipt metadata

## Honest Limitations

This proof does not claim:

- Slack certification
- Gmail certification
- production deployment validation
- complete coverage of every Slack or Gmail API edge case
- provider OAuth or permission introspection
- automatic rollback of the first sandbox canary side effect

This proof does claim:

- live sandbox execution against Slack and Gmail
- before/after provider readback behavior
- hidden side-effect drift detection
- critical/quarantine classification for no-effect-expected provider state change
- clean false-positive controls for preview/no-send and expected-send cases
- evidence-safe handling of provider data

## Safe Reproduction

Use only sandbox accounts/channels.

For Slack:

```powershell
$env:INTERLOCK_ALLOW_LIVE_PROVIDER_PROOFS = "1"
$env:INTERLOCK_LIVE_PROVIDER = "slack"
$env:INTERLOCK_SLACK_BOT_TOKEN = "xoxb-sandbox-token"
$env:INTERLOCK_SLACK_CHANNEL_ID = "C-sandbox-channel-id"
$env:INTERLOCK_LIVE_CANARY_LABEL = "interlock-slack-canary-001"
python demo\run_email_live_proof_pack.py
```

For Gmail:

```powershell
$env:INTERLOCK_ALLOW_LIVE_PROVIDER_PROOFS = "1"
$env:INTERLOCK_LIVE_PROVIDER = "gmail"
$env:INTERLOCK_GMAIL_ACCESS_TOKEN = "sandbox-access-token"
$env:INTERLOCK_GMAIL_FROM = "sandbox@example.com"
$env:INTERLOCK_GMAIL_TO = "sandbox@example.com"
$env:INTERLOCK_LIVE_CANARY_LABEL = "interlock-gmail-canary-001"
python demo\run_email_live_proof_pack.py
```

Never commit real tokens or sandbox credentials.

## Recommended Public Wording

Use:

> Interlock has live Slack and Gmail sandbox proof for provider-readback drift: when a tool claims preview/no-effect but the external provider state changes, Interlock detects the contradiction, classifies it as critical, and quarantines, while clean controls stay allowed. The proof is credential-gated, non-production, and stores hashes rather than tokens, raw messages, recipients, or full provider responses.

Do not use:

> Interlock is Slack/Gmail certified.

Do not use:

> Interlock proves every provider side effect for every API.
