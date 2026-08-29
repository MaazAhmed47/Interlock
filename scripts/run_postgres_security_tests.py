"""Run the selected PostgreSQL tests and bind JUnit to one manifest/run."""

from __future__ import annotations

import argparse
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from scripts.postgres_security_contract import (
    EVIDENCE_PROFILE,
    EXECUTION_FORMAT_VERSION,
    MANIFEST_FORMAT_VERSION,
    SELECTED_FILES,
    checked_out_sha,
    file_sha256,
    load_json_object,
    node_ids_digest,
    validate_run_nonce,
    validate_source_sha,
    write_json_exclusive,
)

ROOT = Path(__file__).resolve().parents[1]


def _validated_manifest(path: Path, source_sha: str, run_nonce: str) -> dict:
    manifest = load_json_object(path, label="collection manifest")
    if manifest.get("format_version") != MANIFEST_FORMAT_VERSION:
        raise ValueError("collection manifest version is unsupported")
    if (
        manifest.get("source_sha") != source_sha
        or manifest.get("run_nonce") != run_nonce
    ):
        raise ValueError("collection manifest provenance does not match this run")
    if manifest.get("selected_files") != list(SELECTED_FILES):
        raise ValueError("collection manifest selected files do not match")
    node_ids = manifest.get("node_ids")
    if not isinstance(node_ids, list) or not node_ids:
        raise ValueError("collection manifest node IDs are missing")
    if node_ids != sorted(node_ids) or len(node_ids) != len(set(node_ids)):
        raise ValueError("collection manifest node IDs must be sorted and unique")
    if manifest.get("node_ids_sha256") != node_ids_digest(node_ids):
        raise ValueError("collection manifest digest does not match node IDs")
    return manifest


def run_tests(
    *,
    manifest_path: Path,
    junit_path: Path,
    execution_path: Path,
    source_sha: str,
    run_nonce: str,
) -> int:
    source_sha = validate_source_sha(source_sha)
    run_nonce = validate_run_nonce(run_nonce)
    if checked_out_sha(ROOT) != source_sha:
        raise RuntimeError("checked-out source SHA does not match test request")
    if len({manifest_path.parent, junit_path.parent, execution_path.parent}) != 1:
        raise ValueError(
            "manifest, JUnit, and execution metadata must share one directory"
        )
    if junit_path.exists() or execution_path.exists():
        raise FileExistsError(
            "refusing to reuse existing PostgreSQL execution evidence"
        )
    manifest = _validated_manifest(manifest_path, source_sha, run_nonce)
    manifest_digest = str(manifest["node_ids_sha256"])

    started_at_ns = time.time_ns()
    started_at = datetime.now(timezone.utc).isoformat()
    command = [
        sys.executable,
        "-m",
        "pytest",
        *SELECTED_FILES,
        "-q",
        "-ra",
        "--tb=short",
        "-o",
        "xfail_strict=true",
        "-p",
        "scripts.postgres_security_pytest_plugin",
        "--interlock-source-sha",
        source_sha,
        "--interlock-run-nonce",
        run_nonce,
        "--interlock-manifest-digest",
        manifest_digest,
        f"--junitxml={junit_path}",
        "-p",
        "no:cacheprovider",
    ]
    proc = subprocess.run(command, cwd=ROOT)
    finished_at_ns = time.time_ns()
    execution = {
        "format_version": EXECUTION_FORMAT_VERSION,
        "profile": EVIDENCE_PROFILE,
        "source_sha": source_sha,
        "run_nonce": run_nonce,
        "selected_files": list(SELECTED_FILES),
        "manifest_digest": manifest_digest,
        "expected_count": len(manifest["node_ids"]),
        "pytest_exit_code": int(proc.returncode),
        "junit_file": junit_path.name,
        "junit_sha256": file_sha256(junit_path) if junit_path.is_file() else None,
        "started_at": started_at,
        "started_at_ns": started_at_ns,
        "finished_at": datetime.now(timezone.utc).isoformat(),
        "finished_at_ns": finished_at_ns,
    }
    write_json_exclusive(execution_path, execution)
    if proc.returncode != 0:
        print(
            f"PostgreSQL pytest failed with exit code {proc.returncode}",
            file=sys.stderr,
        )
    return int(proc.returncode)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--junit", type=Path, required=True)
    parser.add_argument("--execution", type=Path, required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--run-nonce", required=True)
    args = parser.parse_args(argv)
    try:
        return run_tests(
            manifest_path=args.manifest,
            junit_path=args.junit,
            execution_path=args.execution,
            source_sha=args.source_sha,
            run_nonce=args.run_nonce,
        )
    except (FileExistsError, RuntimeError, ValueError) as exc:
        print(f"PostgreSQL execution failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
