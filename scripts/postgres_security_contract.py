"""Shared constants and serialization helpers for PostgreSQL CI evidence."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
from pathlib import Path

MANIFEST_FORMAT_VERSION = 1
EXECUTION_FORMAT_VERSION = 1
EVIDENCE_PROFILE = "interlock-postgres-security-v1"

SELECTED_FILES = (
    "tests/test_postgres_rebaseline_cas.py",
    "tests/test_postgres_ci_boundary_review_gate.py",
    "tests/test_audit_chain_concurrency.py",
)

CRITICAL_NODE_IDS = frozenset(
    {
        "tests/test_postgres_rebaseline_cas.py::"
        "test_server_advisory_lock_does_not_serialize_another_server_on_postgres",
        "tests/test_postgres_rebaseline_cas.py::"
        "test_discovery_wins_first_old_approval_is_stale_on_postgres",
        "tests/test_postgres_rebaseline_cas.py::"
        "test_promotion_wins_first_new_discovery_waits_and_is_not_lost_on_postgres",
        "tests/test_postgres_rebaseline_cas.py::"
        "test_concurrent_promotes_exactly_one_succeeds_on_postgres",
        "tests/test_postgres_rebaseline_cas.py::"
        "test_injected_failure_rolls_back_transactionally_on_postgres",
        "tests/test_postgres_rebaseline_cas.py::"
        "test_per_tool_approval_rejects_stale_surface_on_postgres",
        "tests/test_postgres_rebaseline_cas.py::"
        "test_per_tool_approval_and_audit_bind_matching_surface_on_postgres",
        "tests/test_postgres_rebaseline_cas.py::"
        "test_per_tool_approval_audit_failure_rolls_back_on_postgres",
        "tests/test_postgres_rebaseline_cas.py::"
        "test_per_tool_approval_timestamp_lifecycle_on_postgres",
        "tests/test_postgres_ci_boundary_review_gate.py::"
        "test_postgres_receipt_verification_failure_rolls_back_final_row[false]",
        "tests/test_postgres_ci_boundary_review_gate.py::"
        "test_postgres_receipt_verification_failure_rolls_back_final_row[exception]",
        "tests/test_postgres_ci_boundary_review_gate.py::"
        "test_clean_review_on_postgres_exits_zero_with_a_verified_chain",
        "tests/test_audit_chain_concurrency.py::"
        "test_concurrent_replica_appends_cannot_fork_the_chain[mcp]",
        "tests/test_audit_chain_concurrency.py::"
        "test_concurrent_replica_appends_cannot_fork_the_chain[admin]",
    }
)

_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_NONCE_RE = re.compile(r"^[A-Za-z0-9._:-]{8,200}$")


def validate_source_sha(value: str) -> str:
    candidate = str(value or "")
    if not _SHA_RE.fullmatch(candidate):
        raise ValueError("source SHA must be 40 lowercase hexadecimal characters")
    return candidate


def validate_run_nonce(value: str) -> str:
    candidate = str(value or "")
    if not _NONCE_RE.fullmatch(candidate):
        raise ValueError("run nonce is invalid")
    return candidate


def normalized_node_id(value: str) -> str:
    return str(value).replace("\\", "/")


def node_ids_digest(node_ids: list[str] | tuple[str, ...]) -> str:
    payload = "\n".join(node_ids).encode("utf-8")
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def file_sha256(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def checked_out_sha(root: Path) -> str:
    proc = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=root,
        capture_output=True,
        text=True,
        timeout=10,
    )
    if proc.returncode != 0:
        raise RuntimeError("unable to resolve checked-out source SHA")
    return validate_source_sha(proc.stdout.strip())


def load_json_object(path: Path, *, label: str) -> dict:
    if not path.is_file():
        raise ValueError(f"{label} does not exist")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label} is not valid JSON") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object")
    return value


def write_json_exclusive(path: Path, value: dict) -> None:
    if path.exists():
        raise FileExistsError(f"refusing to overwrite existing evidence: {path.name}")
    encoded = json.dumps(value, sort_keys=True, indent=2) + "\n"
    with path.open("x", encoding="utf-8", newline="\n") as handle:
        handle.write(encoded)
