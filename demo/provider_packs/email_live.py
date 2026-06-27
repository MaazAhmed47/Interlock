"""Credential-gated live email/messaging provider proof pack.

This module is intentionally conservative. It can run against injected provider
clients in tests, and it can run against real Gmail, IMAP/SMTP (iCloud/Fastmail
style), or Slack sandboxes only when explicit environment gates and credentials
are present. It never stores provider tokens, message bodies, raw recipient
addresses, channel names, or full provider responses in the report.
"""

from __future__ import annotations

import base64
import hashlib
import imaplib
import json
import os
import smtplib
import ssl
import tempfile
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass
from email.message import EmailMessage
from typing import Any, Dict, List, Optional, Protocol

from core import db
from core import receipt as receipt_builder
from core.drift_evidence import canonical_json_bytes
from core.effect_readback import (
    build_readback_state_profile,
    classify_readback_effect_drift,
)

PROVIDER = "email_messaging"
MODE = "credential_gated_live_provider"


class ProviderExecutionError(RuntimeError):
    """Raised when a live provider call fails before drift can be concluded."""


REQUIREMENTS = [
    "Set INTERLOCK_ALLOW_LIVE_PROVIDER_PROOFS=1.",
    "Set INTERLOCK_LIVE_PROVIDER to gmail, icloud, fastmail, imap_smtp, or slack.",
    "Use only a sandbox mailbox, test recipient, or test Slack channel.",
    "Provide provider-specific sandbox credentials through environment variables.",
]


@dataclass(frozen=True)
class ProviderState:
    provider_kind: str
    provider_name: str
    item_count: int
    item_digests: List[str]


@dataclass(frozen=True)
class LiveProviderConfig:
    provider_kind: str
    provider_name: str
    canary_label: str
    allow_live: bool = False


class LiveProvider(Protocol):
    provider_name: str
    provider_kind: str

    def read_state(self) -> ProviderState: ...

    def send_canary(self, *, mode: str) -> Dict[str, Any]: ...


def run_email_live_proof_pack(
    *,
    provider: Optional[LiveProvider] = None,
    config: Optional[LiveProviderConfig] = None,
    env: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """Run credential-gated live-provider proof scenarios.

    Without an injected provider or explicit live env gate this returns a safe
    skip report. With a provider, it runs the same before/after readback
    classifier used by the local SMTP pack.
    """
    env = dict(os.environ if env is None else env)
    provider, config, skip = _resolve_provider(
        provider=provider, config=config, env=env
    )
    if skip is not None:
        return skip
    assert provider is not None
    assert config is not None

    old_db_path = db.DB_PATH
    tmp_db = tempfile.mktemp(suffix="_email_live_proof_pack.db")
    db.DB_PATH = tmp_db
    try:
        db.init_db()
        scenarios = [
            _preview_no_send_control(provider, config),
            _hidden_send_readback_drift(provider, config),
            _expected_send_allowed_control(provider, config),
        ]
        return {
            "provider": PROVIDER,
            "mode": MODE,
            "live_provider": {
                "provider_kind": config.provider_kind,
                "provider_name": config.provider_name,
                "canary_label_hash": _digest(config.canary_label),
            },
            "summary": {
                "executed": True,
                "status": "executed_live_provider_harness",
                "scenario_count": len(scenarios),
                "all_passed": all(bool(scenario.get("ok")) for scenario in scenarios),
            },
            "scenarios": scenarios,
            "requirements": REQUIREMENTS,
            "limitations": _limitations(config),
        }
    finally:
        db.DB_PATH = old_db_path
        for suffix in ("", "-wal", "-shm"):
            try:
                os.unlink(tmp_db + suffix)
            except OSError:
                pass


def _resolve_provider(
    *,
    provider: Optional[LiveProvider],
    config: Optional[LiveProviderConfig],
    env: Dict[str, str],
) -> tuple[
    Optional[LiveProvider], Optional[LiveProviderConfig], Optional[Dict[str, Any]]
]:
    if provider is not None:
        if config is None:
            config = LiveProviderConfig(
                provider_kind=str(getattr(provider, "provider_kind", "unknown")),
                provider_name=str(
                    getattr(provider, "provider_name", "injected-provider")
                ),
                canary_label=_canary_label(env),
                allow_live=True,
            )
        return provider, config, None

    allow_live = env.get("INTERLOCK_ALLOW_LIVE_PROVIDER_PROOFS") == "1"
    provider_kind = str(env.get("INTERLOCK_LIVE_PROVIDER") or "").strip().lower()
    if not allow_live or not provider_kind:
        return None, None, _skip_report("skipped_missing_live_provider_config")

    canary_label = _canary_label(env)
    if provider_kind == "gmail":
        provider = _build_gmail_provider(env, canary_label)
        provider_name = "gmail-sandbox"
    elif provider_kind in {"imap_smtp", "icloud", "fastmail"}:
        provider = _build_imap_smtp_provider(env, provider_kind, canary_label)
        provider_name = f"{provider_kind}-sandbox"
    elif provider_kind == "slack":
        provider = _build_slack_provider(env, canary_label)
        provider_name = "slack-sandbox"
    else:
        return None, None, _skip_report("skipped_unknown_live_provider")

    if provider is None:
        return None, None, _skip_report("skipped_missing_live_provider_credentials")

    config = LiveProviderConfig(
        provider_kind=provider_kind,
        provider_name=provider_name,
        canary_label=canary_label,
        allow_live=True,
    )
    return provider, config, None


def _skip_report(status: str) -> Dict[str, Any]:
    return {
        "provider": PROVIDER,
        "mode": MODE,
        "summary": {"executed": False, "status": status, "all_passed": True},
        "scenarios": [],
        "requirements": REQUIREMENTS,
        "limitations": [
            "No live Gmail/iCloud/Fastmail/Slack credentials were used.",
            "No provider call was made and no message was sent.",
            "Set explicit sandbox credentials and INTERLOCK_ALLOW_LIVE_PROVIDER_PROOFS=1 to run a live provider proof.",
        ],
    }


def _preview_no_send_control(
    provider: LiveProvider, config: LiveProviderConfig
) -> Dict[str, Any]:
    name = "live_provider_preview_no_send_control"
    try:
        before = build_readback_state_profile(_state_payload(provider.read_state()))
        after = build_readback_state_profile(_state_payload(provider.read_state()))
    except ProviderExecutionError as exc:
        return _provider_error_scenario(name=name, exc=exc)
    decision = classify_readback_effect_drift(
        before_profile=before,
        after_profile=after,
        target_response={"preview": True, "dry_run": True, "would_send": 1},
        expected_effect="no_change",
    )
    return _scenario(
        name=name,
        expected_ok=not decision["drift_detected"] and decision["action"] == "allow",
        decision=decision,
        receipt=None,
    )


def _hidden_send_readback_drift(
    provider: LiveProvider, config: LiveProviderConfig
) -> Dict[str, Any]:
    name = "live_provider_hidden_send_readback_drift"
    try:
        before = build_readback_state_profile(_state_payload(provider.read_state()))
        provider.send_canary(mode="hidden_send_drift")
        after = _readback_after_target(provider, before_profile=before)
    except ProviderExecutionError as exc:
        return _provider_error_scenario(name=name, exc=exc)
    decision = classify_readback_effect_drift(
        before_profile=before,
        after_profile=after,
        target_response={"preview": True, "dry_run": True, "would_send": 1},
        expected_effect="no_change",
    )
    receipt = _readback_receipt(
        name=name,
        decision=decision,
        before_hash=decision["before_state_hash"],
        after_hash=decision["after_state_hash"],
        config=config,
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
    )


def _expected_send_allowed_control(
    provider: LiveProvider, config: LiveProviderConfig
) -> Dict[str, Any]:
    name = "live_provider_expected_send_allowed_control"
    try:
        before = build_readback_state_profile(_state_payload(provider.read_state()))
        provider.send_canary(mode="expected_send_allowed")
        after = _readback_after_target(provider, before_profile=before)
    except ProviderExecutionError as exc:
        return _provider_error_scenario(name=name, exc=exc)
    decision = classify_readback_effect_drift(
        before_profile=before,
        after_profile=after,
        target_response={"sent": True, "provider": config.provider_kind},
        expected_effect="change_allowed",
    )
    return _scenario(
        name=name,
        expected_ok=not decision["drift_detected"] and decision["action"] == "allow",
        decision=decision,
        receipt=None,
    )


def _provider_error_scenario(
    *, name: str, exc: ProviderExecutionError
) -> Dict[str, Any]:
    return {
        "name": name,
        "ok": False,
        "drift_detected": False,
        "severity": "inconclusive",
        "decision": "monitor",
        "finding_types": ["provider_probe_error"],
        "reason": "Provider probe failed before a drift conclusion could be made.",
        "provider_error": _safe_provider_error(exc),
    }


def _readback_after_target(
    provider: LiveProvider, *, before_profile: Dict[str, Any]
) -> Dict[str, Any]:
    before_hash = before_profile.get("profile_hash") or ""
    latest = build_readback_state_profile(_state_payload(provider.read_state()))
    for _ in range(5):
        if latest.get("profile_hash") != before_hash:
            return latest
        time.sleep(0.4)
        latest = build_readback_state_profile(_state_payload(provider.read_state()))
    return latest


def _scenario(
    *,
    name: str,
    expected_ok: bool,
    decision: Dict[str, Any],
    receipt: Optional[Dict[str, Any]],
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
    if receipt is not None:
        out["receipt"] = receipt
    return out


def _readback_receipt(
    *,
    name: str,
    decision: Dict[str, Any],
    before_hash: str,
    after_hash: str,
    config: LiveProviderConfig,
) -> Dict[str, Any]:
    row = db.log_mcp_audit_event(
        {
            "server_id": "email-live-provider-proof-pack",
            "tool_name": f"{config.provider_kind}_canary_send",
            "role": "operator",
            "action": decision["action"],
            "matched_rule": "effect_readback_observer",
            "reason": decision["reason"],
            "verification_level": "provider_proof_pack_credential_gated_live_readback",
            "confidence": 0.95,
            "warnings": [
                "email_live_provider_proof_pack",
                config.provider_kind,
                f"canary_label_hash={_digest(config.canary_label)}",
                name,
            ],
            "argument_keys": [],
            "blocked_by": "effect_readback_observer",
            "probe_id": name,
            "argument_hash": _digest(
                {
                    "provider_kind": config.provider_kind,
                    "canary_label": config.canary_label,
                    "scenario": name,
                }
            ),
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


def _state_payload(state: ProviderState) -> Dict[str, Any]:
    return {
        "provider_kind": state.provider_kind,
        "provider_name_hash": _digest(state.provider_name),
        "item_count": int(state.item_count),
        "item_digests": [_digest(item) for item in state.item_digests],
    }


def _safe_provider_error(exc: ProviderExecutionError) -> str:
    value = str(exc or "provider_error")[:160]
    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_:-./")
    return "".join(ch if ch in allowed else "_" for ch in value) or "provider_error"


def _limitations(config: LiveProviderConfig) -> List[str]:
    return [
        f"Credential-gated provider harness for {config.provider_kind}; only run with a sandbox account/channel.",
        "Reports store provider names as labels and canary labels, objects, recipients, channels, and message bodies as hashes only.",
        "No OAuth token, app password, SMTP password, Slack token, raw message body, raw recipient, or full provider response is stored.",
        "This proves before/after provider-readback behavior for the configured sandbox; it is not a certification of every provider API edge case.",
    ]


def _build_gmail_provider(
    env: Dict[str, str], canary_label: str
) -> Optional[LiveProvider]:
    required = [
        "INTERLOCK_GMAIL_ACCESS_TOKEN",
        "INTERLOCK_GMAIL_FROM",
        "INTERLOCK_GMAIL_TO",
    ]
    if not all(env.get(key) for key in required):
        return None
    return GmailProvider(
        access_token=str(env["INTERLOCK_GMAIL_ACCESS_TOKEN"]),
        sender=str(env["INTERLOCK_GMAIL_FROM"]),
        recipient=str(env["INTERLOCK_GMAIL_TO"]),
        canary_label=canary_label,
    )


def _build_imap_smtp_provider(
    env: Dict[str, str], provider_kind: str, canary_label: str
) -> Optional[LiveProvider]:
    required = [
        "INTERLOCK_IMAP_HOST",
        "INTERLOCK_IMAP_USERNAME",
        "INTERLOCK_IMAP_PASSWORD",
        "INTERLOCK_SMTP_HOST",
        "INTERLOCK_SMTP_USERNAME",
        "INTERLOCK_SMTP_PASSWORD",
        "INTERLOCK_EMAIL_FROM",
        "INTERLOCK_EMAIL_TO",
    ]
    if not all(env.get(key) for key in required):
        return None
    return ImapSmtpProvider(
        provider_kind=provider_kind,
        imap_host=str(env["INTERLOCK_IMAP_HOST"]),
        imap_port=int(env.get("INTERLOCK_IMAP_PORT") or 993),
        imap_username=str(env["INTERLOCK_IMAP_USERNAME"]),
        imap_password=str(env["INTERLOCK_IMAP_PASSWORD"]),
        imap_mailbox=str(env.get("INTERLOCK_IMAP_MAILBOX") or "Sent"),
        smtp_host=str(env["INTERLOCK_SMTP_HOST"]),
        smtp_port=int(env.get("INTERLOCK_SMTP_PORT") or 465),
        smtp_username=str(env["INTERLOCK_SMTP_USERNAME"]),
        smtp_password=str(env["INTERLOCK_SMTP_PASSWORD"]),
        smtp_tls=str(env.get("INTERLOCK_SMTP_TLS") or "ssl"),
        sender=str(env["INTERLOCK_EMAIL_FROM"]),
        recipient=str(env["INTERLOCK_EMAIL_TO"]),
        canary_label=canary_label,
    )


def _build_slack_provider(
    env: Dict[str, str], canary_label: str
) -> Optional[LiveProvider]:
    required = ["INTERLOCK_SLACK_BOT_TOKEN", "INTERLOCK_SLACK_CHANNEL_ID"]
    if not all(env.get(key) for key in required):
        return None
    return SlackProvider(
        bot_token=str(env["INTERLOCK_SLACK_BOT_TOKEN"]),
        channel_id=str(env["INTERLOCK_SLACK_CHANNEL_ID"]),
        canary_label=canary_label,
    )


def _canary_label(env: Dict[str, str]) -> str:
    return str(
        env.get("INTERLOCK_LIVE_CANARY_LABEL") or f"interlock-canary-{int(time.time())}"
    )


def _digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _first(values: List[str]) -> str:
    return values[0] if values else ""


class GmailProvider:
    provider_kind = "gmail"
    provider_name = "gmail-sandbox"

    def __init__(
        self, *, access_token: str, sender: str, recipient: str, canary_label: str
    ) -> None:
        self.access_token = access_token
        self.sender = sender
        self.recipient = recipient
        self.canary_label = canary_label

    def read_state(self) -> ProviderState:
        query = urllib.parse.quote(f'subject:"{self.canary_label}" newer_than:7d')
        data = self._request_json(
            "GET", f"https://gmail.googleapis.com/gmail/v1/users/me/messages?q={query}"
        )
        messages = data.get("messages") or []
        return ProviderState(
            provider_kind=self.provider_kind,
            provider_name=self.provider_name,
            item_count=len(messages),
            item_digests=[_digest(message.get("id") or "") for message in messages],
        )

    def send_canary(self, *, mode: str) -> Dict[str, Any]:
        raw = (
            f"From: {self.sender}\r\n"
            f"To: {self.recipient}\r\n"
            f"Subject: {self.canary_label} {mode}\r\n"
            "\r\n"
            f"Interlock live Gmail sandbox canary {self.canary_label}"
        )
        encoded = base64.urlsafe_b64encode(raw.encode("utf-8")).decode("ascii")
        data = self._request_json(
            "POST",
            "https://gmail.googleapis.com/gmail/v1/users/me/messages/send",
            payload={"raw": encoded},
        )
        return {"provider": self.provider_kind, "sent": True, "id_hash": _digest(data)}

    def _request_json(
        self, method: str, url: str, payload: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        body = None
        headers = {"Authorization": f"Bearer {self.access_token}"}
        if payload is not None:
            body = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(url, data=body, headers=headers, method=method)
        with urllib.request.urlopen(request, timeout=20) as response:  # nosec B310
            return json.loads(response.read().decode("utf-8") or "{}")


class ImapSmtpProvider:
    def __init__(
        self,
        *,
        provider_kind: str,
        imap_host: str,
        imap_port: int,
        imap_username: str,
        imap_password: str,
        imap_mailbox: str,
        smtp_host: str,
        smtp_port: int,
        smtp_username: str,
        smtp_password: str,
        smtp_tls: str,
        sender: str,
        recipient: str,
        canary_label: str,
    ) -> None:
        self.provider_kind = provider_kind
        self.provider_name = f"{provider_kind}-sandbox"
        self.imap_host = imap_host
        self.imap_port = imap_port
        self.imap_username = imap_username
        self.imap_password = imap_password
        self.imap_mailbox = imap_mailbox
        self.smtp_host = smtp_host
        self.smtp_port = smtp_port
        self.smtp_username = smtp_username
        self.smtp_password = smtp_password
        self.smtp_tls = smtp_tls
        self.sender = sender
        self.recipient = recipient
        self.canary_label = canary_label

    def read_state(self) -> ProviderState:
        with imaplib.IMAP4_SSL(self.imap_host, self.imap_port) as imap:
            imap.login(self.imap_username, self.imap_password)
            imap.select(self.imap_mailbox, readonly=True)
            status, data = imap.search(None, "SUBJECT", f'"{self.canary_label}"')
            ids = []
            if status == "OK" and data:
                ids = data[0].decode("ascii", errors="ignore").split()
            return ProviderState(
                provider_kind=self.provider_kind,
                provider_name=self.provider_name,
                item_count=len(ids),
                item_digests=[_digest(item) for item in ids],
            )

    def send_canary(self, *, mode: str) -> Dict[str, Any]:
        message = EmailMessage()
        message["From"] = self.sender
        message["To"] = self.recipient
        message["Subject"] = f"{self.canary_label} {mode}"
        message.set_content(
            f"Interlock live IMAP/SMTP sandbox canary {self.canary_label}"
        )
        if self.smtp_tls == "starttls":
            with smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=20) as smtp:
                smtp.starttls(context=ssl.create_default_context())
                smtp.login(self.smtp_username, self.smtp_password)
                smtp.send_message(message)
        else:
            with smtplib.SMTP_SSL(self.smtp_host, self.smtp_port, timeout=20) as smtp:
                smtp.login(self.smtp_username, self.smtp_password)
                smtp.send_message(message)
        return {"provider": self.provider_kind, "sent": True, "id_hash": _digest(mode)}


class SlackProvider:
    provider_kind = "slack"
    provider_name = "slack-sandbox"

    def __init__(self, *, bot_token: str, channel_id: str, canary_label: str) -> None:
        self.bot_token = bot_token
        self.channel_id = channel_id
        self.canary_label = canary_label

    def read_state(self) -> ProviderState:
        query = urllib.parse.urlencode({"channel": self.channel_id, "limit": "100"})
        data = self._request_json(
            "GET", f"https://slack.com/api/conversations.history?{query}"
        )
        messages = [
            message
            for message in (data.get("messages") or [])
            if self.canary_label in str(message.get("text") or "")
        ]
        return ProviderState(
            provider_kind=self.provider_kind,
            provider_name=self.provider_name,
            item_count=len(messages),
            item_digests=[_digest(message.get("ts") or "") for message in messages],
        )

    def send_canary(self, *, mode: str) -> Dict[str, Any]:
        data = self._request_json(
            "POST",
            "https://slack.com/api/chat.postMessage",
            payload={
                "channel": self.channel_id,
                "text": f"Interlock live Slack sandbox canary {self.canary_label} {mode}",
            },
        )
        return {"provider": self.provider_kind, "sent": True, "id_hash": _digest(data)}

    def _request_json(
        self, method: str, url: str, payload: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        body = None
        headers = {"Authorization": f"Bearer {self.bot_token}"}
        if payload is not None:
            body = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(url, data=body, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request, timeout=20) as response:  # nosec B310
                data = json.loads(response.read().decode("utf-8") or "{}")
        except Exception as exc:
            raise ProviderExecutionError(
                f"slack_api_error:{type(exc).__name__}"
            ) from exc
        if data.get("ok") is False:
            error = str(data.get("error") or "unknown")
            raise ProviderExecutionError(f"slack_api_error:{error}")
        return data


def print_report(report: Dict[str, Any]) -> None:
    print(f"Email/messaging live provider proof pack ({report['mode']})")
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
    print_report(run_email_live_proof_pack())
