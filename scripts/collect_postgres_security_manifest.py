"""Collect the exact PostgreSQL security pytest inventory into JSON."""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

from scripts.postgres_security_contract import (
    EVIDENCE_PROFILE,
    MANIFEST_FORMAT_VERSION,
    SELECTED_FILES,
    checked_out_sha,
    node_ids_digest,
    normalized_node_id,
    validate_run_nonce,
    validate_source_sha,
    write_json_exclusive,
)

ROOT = Path(__file__).resolve().parents[1]


class CollectionRecorder:
    def __init__(self) -> None:
        self.node_ids: list[str] = []

    def pytest_collection_finish(self, session) -> None:
        self.node_ids = [normalized_node_id(item.nodeid) for item in session.items]


def collect_manifest(*, output: Path, source_sha: str, run_nonce: str) -> dict:
    source_sha = validate_source_sha(source_sha)
    run_nonce = validate_run_nonce(run_nonce)
    if checked_out_sha(ROOT) != source_sha:
        raise RuntimeError("checked-out source SHA does not match manifest request")
    if output.exists():
        raise FileExistsError(f"refusing to overwrite existing evidence: {output.name}")
    if not output.parent.is_dir():
        raise RuntimeError("manifest output directory does not exist")

    recorder = CollectionRecorder()
    exit_code = pytest.main(
        [
            *SELECTED_FILES,
            "--collect-only",
            "-p",
            "no:cacheprovider",
            "-p",
            "no:terminal",
        ],
        plugins=[recorder],
    )
    if int(exit_code) != int(pytest.ExitCode.OK):
        raise RuntimeError(f"pytest collection failed with exit code {int(exit_code)}")
    node_ids = sorted(recorder.node_ids)
    if not node_ids or len(node_ids) != len(set(node_ids)):
        raise RuntimeError("collected node IDs must be non-empty and unique")
    selected = set(SELECTED_FILES)
    collected_files = {node_id.split("::", 1)[0] for node_id in node_ids}
    if collected_files != selected:
        raise RuntimeError(
            "collected file set does not match selected PostgreSQL files"
        )

    manifest = {
        "format_version": MANIFEST_FORMAT_VERSION,
        "profile": EVIDENCE_PROFILE,
        "source_sha": source_sha,
        "run_nonce": run_nonce,
        "selected_files": list(SELECTED_FILES),
        "node_ids": node_ids,
        "node_ids_sha256": node_ids_digest(node_ids),
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
    write_json_exclusive(output, manifest)
    return manifest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--run-nonce", required=True)
    args = parser.parse_args(argv)
    try:
        manifest = collect_manifest(
            output=args.output,
            source_sha=args.source_sha,
            run_nonce=args.run_nonce,
        )
    except (FileExistsError, RuntimeError, ValueError) as exc:
        print(f"PostgreSQL collection failed: {exc}", file=sys.stderr)
        return 1
    print(
        "PostgreSQL collection passed: "
        f"sha={manifest['source_sha']} expected={len(manifest['node_ids'])} "
        f"digest={manifest['node_ids_sha256']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
