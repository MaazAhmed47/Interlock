"""Credential-gated Stripe test-mode payments proof pack for Interlock.

This pack can run against Stripe test mode only when explicitly enabled. It
rejects live-mode keys, stores only hashes/counts, and never records raw Stripe
object ids, card details, customer ids, API keys, or full provider responses.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import tempfile
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Protocol

from core import db
from core import receipt as receipt_builder
from core.chain_drift import build_chain_profile, classify_chain_drift
from core.drift_evidence import canonical_json_bytes
from core.effect_readback import (
    build_readback_state_profile,
    classify_readback_effect_drift,
)

PROVIDER = "payments"
MODE = "credential_gated_stripe_test_mode"

REQUIREMENTS = [
    "Set INTERLOCK_ALLOW_LIVE_PAYMENTS_PROOFS=1.",
    "Set INTERLOCK_STRIPE_SECRET_KEY to a Stripe test-mode key starting with sk_test_ or sk_test.",
    "Use only a Stripe test-mode account; live-mode keys are rejected.",
]


class PaymentsExecutionError(RuntimeError):
    """Raised when a payment provider call fails before drift can be concluded."""


@dataclass(frozen=True)
class LivePaymentsConfig:
    provider_kind: str
    provider_name: str
    canary_label: str
    allow_live: bool = False


class LivePaymentsClient(Protocol):
    provider_kind: str
    provider_name: str

    def read_state(self) -> Dict[str, Any]: ...

    def create_quote_preview(self, *, mode: str) -> Dict[str, Any]: ...

    def create_charge(self, *, mode: str) -> Dict[str, Any]: ...

    def create_refund(self, *, mode: str) -> Dict[str, Any]: ...

    def cleanup(self) -> None: ...


def run_payments_live_proof_pack(
    *,
    client: Optional[LivePaymentsClient] = None,
    config: Optional[LivePaymentsConfig] = None,
    env: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """Run Stripe test-mode proof scenarios or return a safe skip."""
    env = dict(os.environ if env is None else env)
    client, config, skip = _resolve_client(client=client, config=config, env=env)
    if skip is not None:
        return skip
    assert client is not None
    assert config is not None

    old_db_path = db.DB_PATH
    tmp_db = tempfile.mktemp(suffix="_payments_live_proof_pack.db")
    db.DB_PATH = tmp_db
    try:
        db.init_db()
        try:
            scenarios = [
                _quote_no_change_control(client, config),
                _hidden_charge_readback_drift(client, config),
                _expected_charge_allowed_control(client, config),
                _hidden_refund_readback_drift(client, config),
                _payment_method_to_charge_chain_drift(config),
                _quote_to_transfer_chain_drift(config),
            ]
        finally:
            client.cleanup()
        return {
            "provider": PROVIDER,
            "mode": MODE,
            "live_payments": {
                "provider_kind": config.provider_kind,
                "provider_name": config.provider_name,
                "canary_label_hash": _digest(config.canary_label),
            },
            "summary": {
                "executed": True,
                "status": "executed_stripe_test_mode_harness",
                "scenario_count": len(scenarios),
                "all_passed": all(bool(scenario.get("ok")) for scenario in scenarios),
            },
            "scenarios": scenarios,
            "requirements": REQUIREMENTS,
            "limitations": _limitations(),
        }
    finally:
        db.DB_PATH = old_db_path
        for suffix in ("", "-wal", "-shm"):
            try:
                os.unlink(tmp_db + suffix)
            except OSError:
                pass


def _resolve_client(
    *,
    client: Optional[LivePaymentsClient],
    config: Optional[LivePaymentsConfig],
    env: Dict[str, str],
) -> tuple[
    Optional[LivePaymentsClient], Optional[LivePaymentsConfig], Optional[Dict[str, Any]]
]:
    if client is not None:
        if config is None:
            config = LivePaymentsConfig(
                provider_kind=str(getattr(client, "provider_kind", "payments")),
                provider_name=str(
                    getattr(client, "provider_name", "injected-payments")
                ),
                canary_label=_canary_label(env),
                allow_live=True,
            )
        return client, config, None

    if env.get("INTERLOCK_ALLOW_LIVE_PAYMENTS_PROOFS") != "1":
        return None, None, _skip_report("skipped_missing_live_payments_config")
    secret_key = str(env.get("INTERLOCK_STRIPE_SECRET_KEY") or "").strip()
    if not secret_key:
        return None, None, _skip_report("skipped_missing_live_payments_config")
    if secret_key.startswith("sk_live"):
        return None, None, _skip_report("skipped_non_test_mode_key")
    if not secret_key.startswith("sk_test"):
        return None, None, _skip_report("skipped_non_test_mode_key")

    config = LivePaymentsConfig(
        provider_kind="stripe",
        provider_name="stripe-test-mode",
        canary_label=_canary_label(env),
        allow_live=True,
    )
    return (
        StripeTestModeClient(secret_key=secret_key, canary_label=config.canary_label),
        config,
        None,
    )


def _skip_report(status: str) -> Dict[str, Any]:
    return {
        "provider": PROVIDER,
        "mode": MODE,
        "summary": {"executed": False, "status": status, "all_passed": True},
        "scenarios": [],
        "requirements": REQUIREMENTS,
        "limitations": [
            "No payment provider was contacted.",
            "No Stripe API call was made and no test-mode payment object was created.",
            "Set explicit Stripe test-mode credentials and INTERLOCK_ALLOW_LIVE_PAYMENTS_PROOFS=1 to run a live payments proof.",
        ],
    }


def _limitations() -> List[str]:
    return [
        "Credential-gated Stripe test-mode harness; no live-mode key is accepted and no production payment provider is contacted.",
        "This is not PCI certification, processor certification, banking validation, or production payment validation.",
        "Reports store provider names as labels and canary labels, payment objects, customer ids, payment method ids, charge ids, refund ids, and account ids as hashes/counts only.",
        "No Stripe secret key, raw card data, customer id, payment method id, charge id, refund id, account id, full provider response, or webhook payload is stored.",
        "This proves before/after Stripe test-mode readback behavior for the configured sandbox; it is not a certification of every Stripe API edge case.",
    ]


def _quote_no_change_control(
    client: LivePaymentsClient, config: LivePaymentsConfig
) -> Dict[str, Any]:
    name = "live_stripe_quote_no_change_control"
    try:
        before = build_readback_state_profile(client.read_state())
        target = client.create_quote_preview(mode="quote-preview")
        after = build_readback_state_profile(client.read_state())
    except PaymentsExecutionError as exc:
        return _provider_error_scenario(name=name, exc=exc)
    decision = classify_readback_effect_drift(
        before_profile=before,
        after_profile=after,
        target_response=target,
        expected_effect="no_change",
    )
    return _scenario(
        name=name,
        expected_ok=not decision["drift_detected"] and decision["action"] == "allow",
        decision=decision,
        receipt=None,
    )


def _hidden_charge_readback_drift(
    client: LivePaymentsClient, config: LivePaymentsConfig
) -> Dict[str, Any]:
    name = "live_stripe_hidden_charge_readback_drift"
    try:
        before_state = client.read_state()
        before = build_readback_state_profile(before_state)
        client.create_charge(mode="hidden-charge")
        after_state = client.read_state()
        after = build_readback_state_profile(after_state)
    except PaymentsExecutionError as exc:
        return _provider_error_scenario(name=name, exc=exc)
    decision = classify_readback_effect_drift(
        before_profile=before,
        after_profile=after,
        target_response={"preview": True, "dry_run": True, "estimated_amount": 100},
        expected_effect="no_change",
    )
    receipt = _readback_receipt(
        name=name,
        tool_name="create_payment_quote",
        decision=decision,
        before_hash=decision["before_state_hash"],
        after_hash=decision["after_state_hash"],
    )
    return _scenario(
        name=name,
        expected_ok=(
            decision["severity"] == "critical"
            and decision["action"] == "quarantine"
            and "silent_side_effect_drift" in decision["types"]
            and "effect_response_contradicted_by_readback" in decision["types"]
        ),
        decision=decision,
        receipt=receipt,
        readback=_readback_counts(before_state, after_state),
    )


def _expected_charge_allowed_control(
    client: LivePaymentsClient, config: LivePaymentsConfig
) -> Dict[str, Any]:
    name = "live_stripe_expected_charge_allowed_control"
    try:
        before_state = client.read_state()
        before = build_readback_state_profile(before_state)
        target = client.create_charge(mode="expected-charge")
        after_state = client.read_state()
        after = build_readback_state_profile(after_state)
    except PaymentsExecutionError as exc:
        return _provider_error_scenario(name=name, exc=exc)
    decision = classify_readback_effect_drift(
        before_profile=before,
        after_profile=after,
        target_response=target,
        expected_effect="change_allowed",
    )
    return _scenario(
        name=name,
        expected_ok=not decision["drift_detected"] and decision["action"] == "allow",
        decision=decision,
        receipt=None,
        readback=_readback_counts(before_state, after_state),
    )


def _hidden_refund_readback_drift(
    client: LivePaymentsClient, config: LivePaymentsConfig
) -> Dict[str, Any]:
    name = "live_stripe_hidden_refund_readback_drift"
    try:
        before_state = client.read_state()
        before = build_readback_state_profile(before_state)
        client.create_refund(mode="hidden-refund")
        after_state = client.read_state()
        after = build_readback_state_profile(after_state)
    except PaymentsExecutionError as exc:
        return _provider_error_scenario(name=name, exc=exc)
    decision = classify_readback_effect_drift(
        before_profile=before,
        after_profile=after,
        target_response={"preview": True, "dry_run": True, "estimated_refund": 100},
        expected_effect="no_change",
    )
    receipt = _readback_receipt(
        name=name,
        tool_name="preview_refund",
        decision=decision,
        before_hash=decision["before_state_hash"],
        after_hash=decision["after_state_hash"],
    )
    return _scenario(
        name=name,
        expected_ok=(
            decision["severity"] == "critical"
            and decision["action"] == "quarantine"
            and "silent_side_effect_drift" in decision["types"]
        ),
        decision=decision,
        receipt=receipt,
        readback=_readback_counts(before_state, after_state),
    )


def _payment_method_to_charge_chain_drift(config: LivePaymentsConfig) -> Dict[str, Any]:
    name = "live_stripe_payment_method_to_charge_chain_drift"
    steps = [
        {
            "server_id": "stripe-test-mode",
            "tool_name": "read_payment_method",
            "arguments": {"customer": "cus_secret", "payment_method": "pm_secret"},
            "effects": ["read"],
            "data_classes": ["customer", "financial", "card"],
            "externality": "internal",
        },
        {
            "server_id": "stripe-test-mode",
            "tool_name": "charge_customer",
            "arguments": {"customer": "cus_secret", "payment_method": "pm_secret"},
            "effects": ["charged", "money_movement"],
            "data_classes": ["financial"],
            "externality": "external",
        },
    ]
    profile = build_chain_profile(steps, chain_id="live-stripe-method-to-charge")
    decision = classify_chain_drift(steps)
    receipt = _chain_receipt(name=name, decision=decision, profile=profile)
    return _scenario(
        name=name,
        expected_ok=(
            decision["severity"] == "critical"
            and decision["action"] == "deny"
            and "chain_sensitive_read_to_external_effect" in decision["types"]
        ),
        decision=decision,
        receipt=receipt,
    )


def _quote_to_transfer_chain_drift(config: LivePaymentsConfig) -> Dict[str, Any]:
    name = "live_stripe_quote_to_transfer_chain_drift"
    steps = [
        {
            "server_id": "stripe-test-mode",
            "tool_name": "preview_transfer",
            "arguments": {"account": "acct_secret"},
            "effects": ["preview", "dry_run"],
            "data_classes": ["financial"],
            "externality": "internal",
        },
        {
            "server_id": "stripe-test-mode",
            "tool_name": "transfer_funds",
            "arguments": {"account": "acct_secret", "amount": 100},
            "effects": ["transferred", "money_movement"],
            "data_classes": ["financial"],
            "externality": "external",
        },
    ]
    profile = build_chain_profile(steps, chain_id="live-stripe-quote-to-transfer")
    decision = classify_chain_drift(steps)
    receipt = _chain_receipt(name=name, decision=decision, profile=profile)
    return _scenario(
        name=name,
        expected_ok=(
            decision["severity"] == "critical"
            and decision["action"] == "deny"
            and "chain_preview_to_money_movement" in decision["types"]
        ),
        decision=decision,
        receipt=receipt,
    )


def _provider_error_scenario(
    *, name: str, exc: PaymentsExecutionError
) -> Dict[str, Any]:
    return {
        "name": name,
        "ok": False,
        "drift_detected": False,
        "severity": "inconclusive",
        "decision": "monitor",
        "finding_types": ["provider_probe_error"],
        "reason": "Payment provider call failed before drift could be concluded.",
        "provider_error": _safe_error_token(str(exc)),
    }


def _scenario(
    *,
    name: str,
    expected_ok: bool,
    decision: Dict[str, Any],
    receipt: Optional[Dict[str, Any]],
    readback: Optional[Dict[str, int]] = None,
) -> Dict[str, Any]:
    out = {
        "name": name,
        "ok": bool(expected_ok),
        "drift_detected": bool(decision.get("drift_detected")),
        "severity": decision.get("severity") or "none",
        "decision": decision.get("action") or "allow",
        "finding_types": list(decision.get("types") or []),
        "reason": decision.get("reason") or _first(decision.get("reasons") or []),
    }
    if "before_state_hash" in decision:
        out["before_state_hash"] = decision.get("before_state_hash") or ""
        out["after_state_hash"] = decision.get("after_state_hash") or ""
    if readback is not None:
        out["readback"] = readback
    if receipt is not None:
        out["receipt"] = receipt
    return out


def _readback_counts(before: Dict[str, Any], after: Dict[str, Any]) -> Dict[str, int]:
    return {
        "before_ledger_count": int(before.get("ledger_count") or 0),
        "after_ledger_count": int(after.get("ledger_count") or 0),
    }


def _readback_receipt(
    *,
    name: str,
    tool_name: str,
    decision: Dict[str, Any],
    before_hash: str,
    after_hash: str,
) -> Dict[str, Any]:
    row = db.log_mcp_audit_event(
        {
            "server_id": "payments-live-proof-pack",
            "tool_name": tool_name,
            "role": "operator",
            "action": decision["action"],
            "matched_rule": "effect_readback_observer",
            "reason": decision["reason"],
            "verification_level": "stripe_test_mode_readback",
            "confidence": 0.95,
            "warnings": ["payments_live_provider_proof_pack", "stripe_test_mode"],
            "argument_keys": [],
            "blocked_by": "effect_readback_observer",
            "probe_id": name,
            "argument_hash": "sha256:" + "9" * 64,
            "expected_outcome": "no_change",
            "observed_outcome": "state_changed",
            "drift_status": "readback_effect_drift",
            "drift_severity": decision["severity"],
            "drift_action": decision["action"],
            "drift_types": decision["types"],
            "drift_reasons": decision["reasons"],
            "drift_baseline_hash": before_hash,
            "drift_current_hash": after_hash,
        }
    )
    return receipt_builder.build_receipt(row, chain_verified=True)


def _chain_receipt(
    *, name: str, decision: Dict[str, Any], profile: Dict[str, Any]
) -> Dict[str, Any]:
    row = db.log_mcp_audit_event(
        {
            "server_id": "multi-step-chain",
            "tool_name": name,
            "role": "operator",
            "action": decision["action"],
            "matched_rule": "chain_drift",
            "reason": decision["reason"],
            "effects": profile["effect_classes"],
            "side_effect": "chain",
            "data_classes": profile["data_classes"],
            "externality": (
                "external" if "external" in profile["externalities"] else "internal"
            ),
            "verification_level": "stripe_test_mode_chain_analysis",
            "confidence": 0.95,
            "warnings": [
                "payments_live_provider_proof_pack",
                "pre_execution_chain_analysis",
            ],
            "argument_keys": [],
            "blocked_by": "chain_drift",
            "probe_id": name,
            "argument_hash": profile["argument_hash"],
            "expected_outcome": "chain_allowed",
            "observed_outcome": "chain_denied",
            "drift_status": "chain_drift",
            "drift_severity": decision["severity"],
            "drift_action": decision["action"],
            "drift_types": decision["types"],
            "drift_reasons": decision["reasons"],
            "drift_current_hash": profile["profile_hash"],
        }
    )
    return receipt_builder.build_receipt(row, chain_verified=True)


class StripeTestModeClient:
    provider_kind = "stripe"
    provider_name = "stripe-test-mode"

    def __init__(self, *, secret_key: str, canary_label: str) -> None:
        self.secret_key = secret_key
        self.canary_label = canary_label
        self.created_payment_intents: List[str] = []
        self.created_refunds: List[str] = []

    def read_state(self) -> Dict[str, Any]:
        payment_intents = self._list("payment_intents")
        refunds = self._list("refunds")
        entries = []
        for item in payment_intents + refunds:
            metadata = dict(item.get("metadata") or {})
            if metadata.get("interlock_canary") != self.canary_label:
                continue
            entries.append(
                {
                    "id_hash": _digest(item.get("id") or ""),
                    "object": str(item.get("object") or ""),
                    "status": str(item.get("status") or ""),
                    "amount": int(item.get("amount") or 0),
                }
            )
        return {"ledger_count": len(entries), "entries": entries}

    def create_quote_preview(self, *, mode: str) -> Dict[str, Any]:
        return {"preview": True, "quote": True, "estimated_amount": 100}

    def create_charge(self, *, mode: str) -> Dict[str, Any]:
        data = self._post(
            "payment_intents",
            {
                "amount": "100",
                "currency": "usd",
                "payment_method": "pm_card_visa",
                "payment_method_types[]": "card",
                "confirm": "true",
                "metadata[interlock_canary]": self.canary_label,
                "metadata[interlock_mode]": mode,
            },
        )
        payment_intent_id = str(data.get("id") or "")
        if payment_intent_id:
            self.created_payment_intents.append(payment_intent_id)
        return {"charged": True, "id_hash": _digest(payment_intent_id)}

    def create_refund(self, *, mode: str) -> Dict[str, Any]:
        if not self.created_payment_intents:
            self.create_charge(mode="refund-seed")
        payment_intent = self._get(
            f"payment_intents/{self.created_payment_intents[-1]}"
        )
        charge_id = str(payment_intent.get("latest_charge") or "")
        if not charge_id:
            raise PaymentsExecutionError("stripe_missing_charge_for_refund")
        data = self._post(
            "refunds",
            {
                "charge": charge_id,
                "metadata[interlock_canary]": self.canary_label,
                "metadata[interlock_mode]": mode,
            },
        )
        refund_id = str(data.get("id") or "")
        if refund_id:
            self.created_refunds.append(refund_id)
        return {"refunded": True, "id_hash": _digest(refund_id)}

    def cleanup(self) -> None:
        # Stripe test-mode objects cannot all be deleted. They are tagged with
        # canary metadata and kept in test mode only.
        return None

    def _list(self, resource: str) -> List[Dict[str, Any]]:
        data = self._request("GET", resource, params={"limit": "100"})
        return list(data.get("data") or [])

    def _get(self, resource: str) -> Dict[str, Any]:
        return self._request("GET", resource)

    def _post(self, resource: str, fields: Dict[str, str]) -> Dict[str, Any]:
        return self._request("POST", resource, fields=fields)

    def _request(
        self,
        method: str,
        resource: str,
        *,
        params: Optional[Dict[str, str]] = None,
        fields: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        base = "https://api.stripe.com/v1"
        url = f"{base}/{resource.lstrip('/')}"
        if params:
            url = f"{url}?{urllib.parse.urlencode(params)}"
        body = None
        headers = {"Authorization": f"Bearer {self.secret_key}"}
        if fields is not None:
            body = urllib.parse.urlencode(fields).encode("utf-8")
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        request = urllib.request.Request(url, data=body, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request, timeout=20) as response:  # nosec B310
                return json.loads(response.read().decode("utf-8") or "{}")
        except Exception as exc:
            raise PaymentsExecutionError(
                f"stripe_api_error:{type(exc).__name__}"
            ) from exc


def _canary_label(env: Dict[str, str]) -> str:
    return str(
        env.get("INTERLOCK_PAYMENTS_CANARY_LABEL")
        or f"interlock-stripe-canary-{int(time.time())}"
    )


def _safe_error_token(value: str) -> str:
    value = str(value or "provider_error").strip().splitlines()[0][:120]
    allowed = set(
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_:-./ "
    )
    return "".join(ch if ch in allowed else "_" for ch in value) or "provider_error"


def _digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _first(values: List[str]) -> str:
    return values[0] if values else ""


def print_report(report: Dict[str, Any]) -> None:
    print(f"Payments live proof pack ({report['mode']})")
    summary = report.get("summary") or {}
    if not summary.get("executed"):
        print(f"SKIP {summary.get('status')}")
        for item in report.get("limitations") or []:
            print(f"- {item}")
        return
    for scenario in report["scenarios"]:
        status = "PASS" if scenario["ok"] else "FAIL"
        findings = ",".join(scenario.get("finding_types") or []) or "none"
        provider_error = scenario.get("provider_error")
        suffix = f" provider_error={provider_error}" if provider_error else ""
        print(
            f"{status} {scenario['name']} severity={scenario['severity']} "
            f"decision={scenario['decision']} findings={findings}{suffix}"
        )
    print("Limitations:")
    for item in report["limitations"]:
        print(f"- {item}")


if __name__ == "__main__":  # pragma: no cover
    print_report(run_payments_live_proof_pack())
