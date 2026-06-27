"""Database/admin-SaaS provider proof pack for Interlock.

This pack uses a local SQLite sandbox for real before/after database readback.
It does not contact MySQL, Postgres, Snowflake, NetBox, Zabbix, Microsoft 365,
or production MCP servers. The scenarios exercise Interlock's real
classifier/evidence paths with database/admin-shaped payloads.
"""

from __future__ import annotations

import os
import sqlite3
import tempfile
from typing import Any, Dict, List, Optional

from core import db
from core import receipt as receipt_builder
from core.chain_drift import build_chain_profile, classify_chain_drift
from core.effect_drift import (
    build_effect_profile,
    classify_effect_drift,
    effect_profile_hash,
)
from core.effect_readback import (
    build_readback_state_profile,
    classify_readback_effect_drift,
)

PROVIDER = "database_admin"
MODE = "local_sqlite_sandbox"


def run_database_admin_proof_pack() -> Dict[str, Any]:
    """Run database/admin drift scenarios and return evidence-safe results."""
    old_db_path = db.DB_PATH
    audit_db = tempfile.mktemp(suffix="_database_admin_proof_pack.db")
    sandbox_db = tempfile.mktemp(suffix="_database_admin_sqlite_sandbox.db")
    db.DB_PATH = audit_db
    try:
        db.init_db()
        scenarios = [
            _readonly_select_false_positive_control(),
            _select_to_update_effect_drift(),
            _select_to_drop_table_destructive_drift(),
            _readonly_to_scheduled_privilege_change_temporal_drift(),
            _hidden_db_write_readback_drift(sandbox_db),
            _expected_db_write_allowed_control(sandbox_db),
            _customer_data_to_external_export_chain_drift(),
            _db_secret_to_shell_exec_chain_drift(),
            _admin_directory_to_disable_user_chain_drift(),
        ]
        return {
            "provider": PROVIDER,
            "mode": MODE,
            "summary": {
                "scenario_count": len(scenarios),
                "all_passed": all(bool(s.get("ok")) for s in scenarios),
            },
            "scenarios": scenarios,
            "limitations": [
                "Local SQLite sandbox proof pack; no remote database, no MySQL, no Postgres, no Snowflake, no NetBox, no Zabbix, no Microsoft 365 tenant, and no production MCP server was contacted.",
                "No real customer table, admin tenant, connection string, password, token, query text, row value, user email, or production credential is stored in the report.",
                "Provider readback uses local SQLite aggregate counts and hashes only; a live buyer proof should replace this with a tightly scoped non-production database or admin-SaaS sandbox.",
            ],
        }
    finally:
        db.DB_PATH = old_db_path
        for path in (audit_db, sandbox_db):
            for suffix in ("", "-wal", "-shm"):
                try:
                    os.unlink(path + suffix)
                except OSError:
                    pass


def _readonly_select_false_positive_control() -> Dict[str, Any]:
    baseline = build_effect_profile(
        {"result": {"read_only": True, "preview": True, "row_count": 2}}
    )
    current = build_effect_profile(
        {"result": {"read_only": True, "preview": True, "row_count": 5}}
    )
    decision = classify_effect_drift(baseline, current)
    return _scenario(
        name="readonly_select_false_positive_control",
        expected_ok=not decision["drift_detected"] and decision["action"] == "allow",
        decision=decision,
        receipt=None,
    )


def _select_to_update_effect_drift() -> Dict[str, Any]:
    baseline = build_effect_profile(
        {"result": {"read_only": True, "preview": True, "row_count": 2}}
    )
    current = build_effect_profile({"result": {"updated": True, "rows_affected": 1}})
    decision = classify_effect_drift(baseline, current)
    receipt = _effect_receipt(
        tool_name="query_customers",
        decision=decision,
        baseline_hash=effect_profile_hash(baseline),
        current_hash=effect_profile_hash(current),
    )
    return _scenario(
        name="select_to_update_effect_drift",
        expected_ok=(
            decision["severity"] == "high"
            and decision["action"] == "quarantine"
            and "effect_mutation_after_preview" in decision["types"]
        ),
        decision=decision,
        receipt=receipt,
    )


def _select_to_drop_table_destructive_drift() -> Dict[str, Any]:
    baseline = build_effect_profile(
        {"result": {"read_only": True, "preview": True, "row_count": 2}}
    )
    current = build_effect_profile(
        {"result": {"deleted": True, "destroyed": True, "object_count": 1}}
    )
    decision = classify_effect_drift(baseline, current)
    receipt = _effect_receipt(
        tool_name="describe_table",
        decision=decision,
        baseline_hash=effect_profile_hash(baseline),
        current_hash=effect_profile_hash(current),
    )
    return _scenario(
        name="select_to_drop_table_destructive_drift",
        expected_ok=(
            decision["severity"] == "critical"
            and decision["action"] == "quarantine"
            and "effect_destructive_after_preview" in decision["types"]
        ),
        decision=decision,
        receipt=receipt,
    )


def _readonly_to_scheduled_privilege_change_temporal_drift() -> Dict[str, Any]:
    baseline = build_effect_profile(
        {"result": {"read_only": True, "preview": True, "role": "viewer"}}
    )
    current = build_effect_profile(
        {
            "result": {
                "scheduled_for": "2026-07-03T10:00:00Z",
                "updated": True,
                "role": "admin",
            }
        }
    )
    decision = classify_effect_drift(baseline, current)
    receipt = _effect_receipt(
        tool_name="preview_role_access",
        decision=decision,
        baseline_hash=effect_profile_hash(baseline),
        current_hash=effect_profile_hash(current),
    )
    return _scenario(
        name="readonly_to_scheduled_privilege_change_temporal_drift",
        expected_ok=(
            decision["severity"] == "high"
            and decision["action"] == "quarantine"
            and "effect_temporal_action_after_preview" in decision["types"]
        ),
        decision=decision,
        receipt=receipt,
    )


def _hidden_db_write_readback_drift(sandbox_db: str) -> Dict[str, Any]:
    _reset_sqlite_sandbox(sandbox_db)
    before = _read_sqlite_state(sandbox_db)
    _insert_hidden_customer(sandbox_db)
    after = _read_sqlite_state(sandbox_db)

    before_profile = build_readback_state_profile(before)
    after_profile = build_readback_state_profile(after)
    decision = classify_readback_effect_drift(
        before_profile=before_profile,
        after_profile=after_profile,
        target_response={"read_only": True, "dry_run": True, "preview": True},
        expected_effect="no_change",
    )
    receipt = _readback_receipt(
        name="hidden_db_write_readback_drift",
        tool_name="query_customers",
        decision=decision,
        before_hash=decision["before_state_hash"],
        after_hash=decision["after_state_hash"],
    )
    return _scenario(
        name="hidden_db_write_readback_drift",
        expected_ok=(
            decision["severity"] == "critical"
            and decision["action"] == "quarantine"
            and "silent_side_effect_drift" in decision["types"]
            and "effect_response_contradicted_by_readback" in decision["types"]
        ),
        decision=decision,
        receipt=receipt,
        readback={
            "before_customer_count": before["customer_count"],
            "after_customer_count": after["customer_count"],
        },
    )


def _expected_db_write_allowed_control(sandbox_db: str) -> Dict[str, Any]:
    _reset_sqlite_sandbox(sandbox_db)
    before = _read_sqlite_state(sandbox_db)
    _allowed_customer_update(sandbox_db)
    after = _read_sqlite_state(sandbox_db)
    decision = classify_readback_effect_drift(
        before_profile=build_readback_state_profile(before),
        after_profile=build_readback_state_profile(after),
        target_response={"updated": True, "rows_affected": 1},
        expected_effect="change_allowed",
    )
    return _scenario(
        name="expected_db_write_allowed_control",
        expected_ok=not decision["drift_detected"] and decision["action"] == "allow",
        decision=decision,
        receipt=None,
        readback={
            "before_customer_count": before["customer_count"],
            "after_customer_count": after["customer_count"],
        },
    )


def _customer_data_to_external_export_chain_drift() -> Dict[str, Any]:
    steps = [
        {
            "server_id": "database-admin",
            "tool_name": "read_customer_rows",
            "arguments": {"table": "customers", "limit": 100},
            "effects": ["read"],
            "data_classes": ["customer", "pii", "email"],
            "externality": "internal",
        },
        {
            "server_id": "database-admin",
            "tool_name": "export_customer_rows",
            "arguments": {"destination": "webhook-secret", "format": "csv"},
            "effects": ["exported"],
            "data_classes": ["customer", "pii", "email"],
            "externality": "external",
        },
    ]
    profile = build_chain_profile(steps, chain_id="database-customer-export")
    decision = classify_chain_drift(steps)
    receipt = _chain_receipt(
        name="customer_data_to_external_export_chain_drift",
        decision=decision,
        profile=profile,
    )
    return _scenario(
        name="customer_data_to_external_export_chain_drift",
        expected_ok=(
            decision["severity"] == "critical"
            and decision["action"] == "deny"
            and "chain_sensitive_read_to_external_effect" in decision["types"]
        ),
        decision=decision,
        receipt=receipt,
    )


def _db_secret_to_shell_exec_chain_drift() -> Dict[str, Any]:
    steps = [
        {
            "server_id": "database-admin",
            "tool_name": "read_database_secret",
            "arguments": {"secret_name": "db_password_secret"},
            "effects": ["read"],
            "data_classes": ["secret", "password", "credential"],
            "externality": "internal",
        },
        {
            "server_id": "database-admin",
            "tool_name": "run_sql_shell_command",
            "arguments": {"command": "rotate-secret-placeholder"},
            "effects": ["executed"],
            "data_classes": ["credential"],
            "externality": "internal",
        },
    ]
    profile = build_chain_profile(steps, chain_id="database-secret-to-shell")
    decision = classify_chain_drift(steps)
    receipt = _chain_receipt(
        name="db_secret_to_shell_exec_chain_drift",
        decision=decision,
        profile=profile,
    )
    return _scenario(
        name="db_secret_to_shell_exec_chain_drift",
        expected_ok=(
            decision["severity"] == "critical"
            and decision["action"] == "deny"
            and "chain_secret_to_execution" in decision["types"]
        ),
        decision=decision,
        receipt=receipt,
    )


def _admin_directory_to_disable_user_chain_drift() -> Dict[str, Any]:
    steps = [
        {
            "server_id": "admin-saas",
            "tool_name": "list_admin_users",
            "arguments": {"tenant": "tenant-secret"},
            "effects": ["read"],
            "data_classes": ["customer", "pii", "email"],
            "externality": "internal",
        },
        {
            "server_id": "admin-saas",
            "tool_name": "disable_user_account",
            "arguments": {"user": "alice@example.com", "token": "sk_admin_secret"},
            "effects": ["updated", "deleted"],
            "data_classes": ["customer", "pii"],
            "externality": "external",
        },
    ]
    profile = build_chain_profile(steps, chain_id="admin-directory-disable-user")
    decision = classify_chain_drift(steps)
    receipt = _chain_receipt(
        name="admin_directory_to_disable_user_chain_drift",
        decision=decision,
        profile=profile,
    )
    return _scenario(
        name="admin_directory_to_disable_user_chain_drift",
        expected_ok=(
            decision["severity"] == "critical"
            and decision["action"] == "deny"
            and "chain_sensitive_read_to_external_effect" in decision["types"]
        ),
        decision=decision,
        receipt=receipt,
    )


def _reset_sqlite_sandbox(path: str) -> None:
    try:
        os.unlink(path)
    except OSError:
        pass
    with sqlite3.connect(path) as conn:
        conn.execute(
            "CREATE TABLE customers (id INTEGER PRIMARY KEY, email TEXT, active INTEGER, version INTEGER)"
        )
        conn.executemany(
            "INSERT INTO customers(email, active, version) VALUES (?, ?, ?)",
            [("alice@example.com", 1, 1), ("bob@example.com", 1, 1)],
        )
        conn.commit()


def _read_sqlite_state(path: str) -> Dict[str, int]:
    with sqlite3.connect(path) as conn:
        row = conn.execute(
            "SELECT COUNT(*), SUM(active), SUM(version) FROM customers"
        ).fetchone()
    return {
        "provider": "sqlite-local-sandbox",
        "customer_count": int(row[0] or 0),
        "active_count": int(row[1] or 0),
        "version_total": int(row[2] or 0),
    }


def _insert_hidden_customer(path: str) -> None:
    with sqlite3.connect(path) as conn:
        conn.execute(
            "INSERT INTO customers(email, active, version) VALUES (?, ?, ?)",
            ("hidden@example.com", 1, 1),
        )
        conn.commit()


def _allowed_customer_update(path: str) -> None:
    with sqlite3.connect(path) as conn:
        conn.execute("UPDATE customers SET version = version + 1 WHERE id = 1")
        conn.commit()


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


def _effect_receipt(
    *,
    tool_name: str,
    decision: Dict[str, Any],
    baseline_hash: str,
    current_hash: str,
) -> Dict[str, Any]:
    row = db.log_mcp_audit_event(
        {
            "server_id": "database-admin-proof-pack",
            "tool_name": tool_name,
            "role": "data_admin",
            "action": decision["action"],
            "matched_rule": "effect_drift",
            "reason": _first(decision.get("reasons") or []),
            "effects": [],
            "side_effect": "database_admin",
            "data_classes": ["customer"],
            "externality": "internal",
            "verification_level": "database_admin_provider_proof_pack_local_sqlite",
            "confidence": 0.95,
            "warnings": ["database_admin_provider_proof_pack", "local_sqlite_sandbox"],
            "argument_keys": [],
            "blocked_by": "effect_drift" if decision["action"] == "quarantine" else "",
            "argument_hash": "sha256:" + "b" * 64,
            "drift_status": "effect_drift",
            "drift_severity": decision["severity"],
            "drift_action": decision["action"],
            "drift_types": decision["types"],
            "drift_reasons": decision["reasons"],
            "drift_baseline_hash": baseline_hash,
            "drift_current_hash": current_hash,
        }
    )
    return receipt_builder.build_receipt(row, chain_verified=True)


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
            "server_id": "database-admin-proof-pack",
            "tool_name": tool_name,
            "role": "data_admin",
            "action": decision["action"],
            "matched_rule": "effect_readback_observer",
            "reason": decision["reason"],
            "verification_level": "database_admin_provider_proof_pack_local_sqlite_readback",
            "confidence": 0.95,
            "warnings": ["database_admin_provider_proof_pack", "local_sqlite_sandbox"],
            "argument_keys": [],
            "blocked_by": "effect_readback_observer",
            "probe_id": name,
            "argument_hash": "sha256:" + "c" * 64,
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
            "role": "data_admin",
            "action": decision["action"],
            "matched_rule": "chain_drift",
            "reason": decision["reason"],
            "effects": profile["effect_classes"],
            "side_effect": "chain",
            "data_classes": profile["data_classes"],
            "externality": (
                "external" if "external" in profile["externalities"] else "internal"
            ),
            "verification_level": "database_admin_provider_proof_pack_chain",
            "confidence": 0.95,
            "warnings": ["database_admin_provider_proof_pack", "local_sqlite_sandbox"],
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


def _first(values: List[str]) -> str:
    return values[0] if values else ""


def print_report(report: Dict[str, Any]) -> None:
    print(f"Database/admin proof pack ({report['mode']})")
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
    print_report(run_database_admin_proof_pack())
