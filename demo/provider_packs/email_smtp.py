"""Real local SMTP email/messaging provider proof pack for Interlock.

This pack starts a local SMTP sandbox on 127.0.0.1, sends a real SMTP
message through Python's smtplib, then uses Interlock's provider-readback
classifier and receipt path to detect whether the mailbox/outbox changed. It
never contacts Gmail, iCloud, Fastmail, external SMTP, Slack, or production MCP
servers.
"""

from __future__ import annotations

import hashlib
import os
import smtplib
import socketserver
import tempfile
import threading
from typing import Any, Dict, List

from core import db
from core import receipt as receipt_builder
from core.drift_evidence import canonical_json_bytes
from core.effect_readback import (
    build_readback_state_profile,
    classify_readback_effect_drift,
)

PROVIDER = "email_messaging"
MODE = "real_local_smtp_sandbox"


def run_email_smtp_proof_pack() -> Dict[str, Any]:
    """Run email/messaging proof scenarios against a real local SMTP sandbox."""
    old_db_path = db.DB_PATH
    tmp_db = tempfile.mktemp(suffix="_email_smtp_proof_pack.db")
    server = _LocalSmtpSandbox()
    server.start()
    db.DB_PATH = tmp_db
    try:
        db.init_db()
        scenarios = [
            _smtp_preview_no_send_control(server),
            _smtp_hidden_send_readback_drift(server),
            _smtp_expected_send_allowed_control(server),
        ]
        return {
            "provider": PROVIDER,
            "mode": MODE,
            "summary": {
                "scenario_count": len(scenarios),
                "all_passed": all(bool(scenario.get("ok")) for scenario in scenarios),
            },
            "scenarios": scenarios,
            "limitations": [
                "Real local SMTP sandbox only; no Gmail, no iCloud, no Fastmail, no external email provider, and no production MCP server was contacted.",
                "No external email was delivered; all SMTP traffic stayed on 127.0.0.1 with synthetic sender/recipient values.",
                "No SMTP credentials, OAuth tokens, mailbox contents, message bodies, or real recipient addresses are required or loaded.",
            ],
        }
    finally:
        server.stop()
        db.DB_PATH = old_db_path
        for suffix in ("", "-wal", "-shm"):
            try:
                os.unlink(tmp_db + suffix)
            except OSError:
                pass


def _smtp_preview_no_send_control(server: "_LocalSmtpSandbox") -> Dict[str, Any]:
    before = build_readback_state_profile(_smtp_state(server.messages))
    after = build_readback_state_profile(_smtp_state(server.messages))
    decision = classify_readback_effect_drift(
        before_profile=before,
        after_profile=after,
        target_response={"preview": True, "dry_run": True, "would_send": 1},
        expected_effect="no_change",
    )
    return _scenario(
        name="smtp_preview_no_send_control",
        expected_ok=not decision["drift_detected"] and decision["action"] == "allow",
        decision=decision,
        receipt=None,
    )


def _smtp_hidden_send_readback_drift(server: "_LocalSmtpSandbox") -> Dict[str, Any]:
    before = build_readback_state_profile(_smtp_state(server.messages))
    _send_smtp_message(server.port)
    after = build_readback_state_profile(_smtp_state(server.messages))
    decision = classify_readback_effect_drift(
        before_profile=before,
        after_profile=after,
        target_response={"preview": True, "dry_run": True, "would_send": 1},
        expected_effect="no_change",
    )
    receipt = _readback_receipt(
        name="smtp_hidden_send_readback_drift",
        decision=decision,
        before_hash=decision["before_state_hash"],
        after_hash=decision["after_state_hash"],
    )
    return _scenario(
        name="smtp_hidden_send_readback_drift",
        expected_ok=(
            decision["severity"] == "critical"
            and decision["action"] == "quarantine"
            and "silent_side_effect_drift" in decision["types"]
            and "effect_response_contradicted_by_readback" in decision["types"]
        ),
        decision=decision,
        receipt=receipt,
    )


def _smtp_expected_send_allowed_control(server: "_LocalSmtpSandbox") -> Dict[str, Any]:
    before = build_readback_state_profile(_smtp_state(server.messages))
    _send_smtp_message(server.port)
    after = build_readback_state_profile(_smtp_state(server.messages))
    decision = classify_readback_effect_drift(
        before_profile=before,
        after_profile=after,
        target_response={"sent": True, "message_id": "smtp-message-secret"},
        expected_effect="change_allowed",
    )
    return _scenario(
        name="smtp_expected_send_allowed_control",
        expected_ok=not decision["drift_detected"] and decision["action"] == "allow",
        decision=decision,
        receipt=None,
    )


def _scenario(
    *,
    name: str,
    expected_ok: bool,
    decision: Dict[str, Any],
    receipt: Dict[str, Any] | None,
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
    *, name: str, decision: Dict[str, Any], before_hash: str, after_hash: str
) -> Dict[str, Any]:
    row = db.log_mcp_audit_event(
        {
            "server_id": "email-smtp-proof-pack",
            "tool_name": "smtp_preview_send",
            "role": "operator",
            "action": decision["action"],
            "matched_rule": "effect_readback_observer",
            "reason": decision["reason"],
            "verification_level": "provider_proof_pack_real_local_smtp_readback",
            "confidence": 0.95,
            "warnings": [
                "email_smtp_provider_proof_pack",
                "real_local_smtp_sandbox",
                name,
            ],
            "argument_keys": [],
            "blocked_by": "effect_readback_observer",
            "probe_id": name,
            "argument_hash": "sha256:" + "6" * 64,
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


def _smtp_state(messages: List[Dict[str, Any]]) -> Dict[str, Any]:
    return {
        "transport": "local_smtp",
        "message_count": len(messages),
        "message_digests": [_digest_message(message) for message in messages],
    }


def _digest_message(message: Dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json_bytes(message)).hexdigest()


def _send_smtp_message(port: int) -> None:
    body = (
        "From: sender@example.test\r\n"
        "To: recipient@example.test\r\n"
        "Subject: Interlock SMTP sandbox\r\n"
        "\r\n"
        "smtp-body-secret"
    )
    with smtplib.SMTP("127.0.0.1", port, timeout=5) as smtp:
        smtp.sendmail("sender@example.test", ["recipient@example.test"], body)


def _first(values: List[str]) -> str:
    return values[0] if values else ""


class _ThreadingSmtpServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True

    def __init__(self, server_address: tuple[str, int]):
        super().__init__(server_address, _SmtpHandler)
        self.messages: List[Dict[str, Any]] = []
        self.lock = threading.Lock()


class _SmtpHandler(socketserver.StreamRequestHandler):
    def handle(self) -> None:  # pragma: no cover - exercised through smtplib
        self._send("220 interlock-local-smtp ESMTP ready")
        mail_from = ""
        recipients: List[str] = []
        data_lines: List[str] = []
        in_data = False

        while True:
            raw = self.rfile.readline()
            if not raw:
                break
            line = raw.decode("utf-8", errors="replace").rstrip("\r\n")

            if in_data:
                if line == ".":
                    message = {
                        "mail_from": mail_from,
                        "recipients": recipients,
                        "data": "\n".join(data_lines),
                    }
                    with self.server.lock:
                        self.server.messages.append(message)
                    data_lines = []
                    in_data = False
                    self._send("250 2.0.0 queued")
                else:
                    data_lines.append(line)
                continue

            command = line.split(" ", 1)[0].upper()
            argument = line[len(command) :].strip()
            if command in {"EHLO", "HELO"}:
                self.wfile.write(b"250-localhost\r\n250 SIZE 10485760\r\n")
                self.wfile.flush()
            elif command == "MAIL":
                mail_from = argument
                recipients = []
                self._send("250 2.1.0 OK")
            elif command == "RCPT":
                recipients.append(argument)
                self._send("250 2.1.5 OK")
            elif command == "DATA":
                in_data = True
                self._send("354 End data with <CR><LF>.<CR><LF>")
            elif command == "RSET":
                mail_from = ""
                recipients = []
                data_lines = []
                in_data = False
                self._send("250 2.0.0 reset")
            elif command == "NOOP":
                self._send("250 2.0.0 OK")
            elif command == "QUIT":
                self._send("221 2.0.0 Bye")
                break
            else:
                self._send("250 2.0.0 OK")

    def _send(self, line: str) -> None:
        self.wfile.write((line + "\r\n").encode("utf-8"))
        self.wfile.flush()


class _LocalSmtpSandbox:
    def __init__(self) -> None:
        self._server = _ThreadingSmtpServer(("127.0.0.1", 0))
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    @property
    def port(self) -> int:
        return int(self._server.server_address[1])

    @property
    def messages(self) -> List[Dict[str, Any]]:
        with self._server.lock:
            return list(self._server.messages)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=5)


def print_report(report: Dict[str, Any]) -> None:
    print(f"Email/messaging SMTP proof pack ({report['mode']})")
    for scenario in report["scenarios"]:
        status = "PASS" if scenario["ok"] else "FAIL"
        findings = ",".join(scenario.get("finding_types") or []) or "none"
        print(
            f"{status} {scenario['name']} severity={scenario['severity']} "
            f"decision={scenario['decision']} findings={findings}"
        )
    print("Limitations:")
    for item in report["limitations"]:
        print(f"- {item}")


if __name__ == "__main__":  # pragma: no cover
    print_report(run_email_smtp_proof_pack())
