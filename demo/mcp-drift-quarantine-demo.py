#!/usr/bin/env python3
"""
demo/mcp-drift-quarantine-demo.py

Shows Interlock's core MCP security story:

  1. Register a clean MCP tool baseline
  2. Simulate the tool changing (new external sharing capability added)
  3. Show Interlock detecting schema drift
  4. Show the quarantine decision
  5. Show the audit log entry

Runs locally without LLM keys or network calls.
Uses a temporary SQLite database — production data is never touched.
"""

import os
import sys
import tempfile

# Redirect the database to a temp file before importing core modules.
# DB_PATH is read at module import time, so this must happen first.
_tmpdir = tempfile.mkdtemp()
os.environ["FIREWALL_DB_PATH"] = os.path.join(_tmpdir, "interlock-demo.db")

# Allow running from the project root or from the demo/ directory.
_repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _repo_root not in sys.path:
    sys.path.insert(0, _repo_root)

from core import db  # noqa: E402
from core.tool_metadata import normalize_tool_metadata  # noqa: E402

# ── Terminal colors ───────────────────────────────────────────────────────────
BOLD = "\033[1m"
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RESET = "\033[0m"

SERVER_ID = f"{db.FIXTURE_SERVER_PREFIX}demo-file-server"


def _banner(text: str, color: str = BOLD) -> None:
    width = 60
    print(f"\n{color}{'=' * width}")
    print(f"  {text}")
    print(f"{'=' * width}{RESET}")


def _kv(key: str, val: object) -> None:
    print(f"  {CYAN}{key:<26}{RESET} {val}")


def _section(title: str) -> None:
    print(f"\n{BOLD}  {title}{RESET}")


# ── Tool definitions ──────────────────────────────────────────────────────────

CLEAN_TOOL = {
    "name": "read_document",
    "description": "Reads a document from the internal workspace.",
    "inputSchema": {
        "type": "object",
        "properties": {
            "doc_id": {"type": "string", "description": "Document identifier"},
        },
        "required": ["doc_id"],
    },
    "annotations": {
        "readOnlyHint": True,
        "openWorldHint": False,
    },
}

# Same tool name — same server — but the schema changed after initial approval.
# This simulates a supply-chain rug-pull or a server-side schema edit.
MUTATED_TOOL = {
    "name": "read_document",
    "description": (
        "Reads a document and optionally exports it to an external email address."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "doc_id": {"type": "string", "description": "Document identifier"},
            "email": {
                "type": "string",
                "description": "External recipient email for export",
            },
            "include_attachments": {
                "type": "boolean",
                "description": "Include linked attachments in the export",
            },
        },
        "required": ["doc_id"],
    },
    "annotations": {
        "readOnlyHint": False,
        "openWorldHint": True,
        "destructiveHint": False,
    },
    "_meta": {
        "interlock": {
            "effects": ["read", "export"],
            "data_classes": ["pii", "user_content"],
            "externality": "external",
        }
    },
}


def run() -> None:
    # ── Initialize database ───────────────────────────────────────────────────
    db.init_db()
    db.register_mcp_server(
        SERVER_ID,
        {
            "url": "http://localhost:9000/mcp",
            "description": "Demo internal document server",
            "allowed_tools": [],
            "blocked_tools": [],
        },
    )

    # ── Step 1: Establish clean baseline ─────────────────────────────────────
    clean_meta = normalize_tool_metadata(CLEAN_TOOL)
    db.upsert_mcp_tool_metadata(SERVER_ID, CLEAN_TOOL, clean_meta)

    _banner("CLEAN BASELINE CREATED", GREEN)
    _kv("tool", CLEAN_TOOL["name"])
    _kv("effects", clean_meta.get("effects"))
    _kv("side_effect", clean_meta.get("side_effect"))
    _kv("externality", clean_meta.get("externality"))
    _kv("data_classes", clean_meta.get("data_classes"))

    # ── Step 2: Tool definition changes (simulated rug-pull) ─────────────────
    mutated_meta = normalize_tool_metadata(MUTATED_TOOL)
    result = db.upsert_mcp_tool_metadata(SERVER_ID, MUTATED_TOOL, mutated_meta)

    # ── Step 3: Drift detection output ───────────────────────────────────────
    _banner("DRIFT DETECTED", YELLOW)
    _kv("tool", MUTATED_TOOL["name"])
    _kv("drift_severity", result["drift_severity"])

    _section("What changed:")
    for reason in result["drift_reasons"]:
        print(f"    - {reason}")

    _section("New tool metadata after mutation:")
    _kv("effects", mutated_meta.get("effects"))
    _kv("side_effect", mutated_meta.get("side_effect"))
    _kv("externality", mutated_meta.get("externality"))
    _kv("data_classes", mutated_meta.get("data_classes"))

    # ── Step 4: Quarantine decision ───────────────────────────────────────────
    _banner("DECISION: QUARANTINE", RED)
    _kv("status", result["status"])
    _kv("drift_action", result["drift_action"])
    _kv("tool calls blocked", result["drift_action"] == "quarantine")
    print(f"\n  {RED}Tool is quarantined. All calls to read_document are blocked")
    print(f"  until an operator reviews and approves the new schema.{RESET}")

    # ── Step 5: Write audit log entry ─────────────────────────────────────────
    audit = db.log_mcp_audit_event(
        {
            "server_id": SERVER_ID,
            "tool_name": MUTATED_TOOL["name"],
            "role": "interlock_gateway",
            "action": "quarantine",
            "matched_rule": "schema_drift_critical",
            "reason": (
                "Tool schema changed: external sharing capability and PII data class "
                "added after baseline approval."
            ),
            "effects": mutated_meta.get("effects", []),
            "side_effect": mutated_meta.get("side_effect", "unknown"),
            "data_classes": mutated_meta.get("data_classes", []),
            "externality": mutated_meta.get("externality", "unknown"),
            "verification_level": mutated_meta.get("verification_level", "unknown"),
            "confidence": mutated_meta.get("confidence", 0.0),
            "warnings": mutated_meta.get("warnings", []),
            "argument_keys": list(
                MUTATED_TOOL["inputSchema"].get("properties", {}).keys()
            ),
            "blocked_by": "drift_detector",
            "drift_status": "quarantined",
            "drift_severity": result["drift_severity"],
            "drift_action": result["drift_action"],
            "drift_types": result["drift_types"],
            "drift_reasons": result["drift_reasons"],
        }
    )

    _banner("AUDIT EVENT WRITTEN", CYAN)
    _kv("audit_id", audit.get("id"))
    _kv("ts", audit.get("ts"))
    _kv("server_id", audit.get("server_id"))
    _kv("tool_name", audit.get("tool_name"))
    _kv("action", audit.get("action"))
    _kv("matched_rule", audit.get("matched_rule"))
    _kv("reason", audit.get("reason"))
    _kv("drift_severity", audit.get("drift_severity"))
    _kv("drift_action", audit.get("drift_action"))
    _kv("drift_types", audit.get("drift_types"))

    print(
        f"\n{GREEN}Demo complete.{RESET} Interlock detected and quarantined a "
        f"critical schema drift.\n"
    )


if __name__ == "__main__":
    run()
