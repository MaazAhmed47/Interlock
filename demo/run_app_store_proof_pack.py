"""Run the App Store / release automation provider proof pack.

This is a local mock/sandbox proof. It does not call App Store Connect, Apple
APIs, TestFlight, or production MCP servers.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from demo.provider_packs.app_store import print_report, run_app_store_proof_pack


def main() -> int:
    report = run_app_store_proof_pack()
    print_report(report)
    return 0 if report["summary"]["all_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
