"""Generate offline Detection Quality Evidence v1 JSON and Markdown."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core.detection_quality_evidence import (  # noqa: E402
    CORPUS_PATH,
    EvidenceError,
    build_report,
    load_corpus,
    write_report,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Generate corpus-bound synthetic Interlock detection-quality evidence "
            "without network access."
        )
    )
    parser.add_argument(
        "--corpus",
        type=Path,
        default=CORPUS_PATH,
        help=f"versioned synthetic corpus (default: {CORPUS_PATH})",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        help="directory for JSON and Markdown (default: a new temporary directory)",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        corpus = load_corpus(args.corpus)
        report = build_report(corpus)
        json_path, markdown_path = write_report(report, args.output_dir)
    except (EvidenceError, OSError, ValueError) as exc:
        print(f"Detection Quality Evidence generation failed: {exc}", file=sys.stderr)
        return 1

    print(f"JSON: {json_path}")
    print(f"Markdown: {markdown_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
