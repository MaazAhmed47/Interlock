#!/usr/bin/env python3
"""Run the Kubernetes provider proof pack.

This is a local mock/sandbox proof. It does not call Kubernetes, kubectl, kind,
cloud providers, or real MCP servers.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from demo.provider_packs.kubernetes import print_report, run_kubernetes_proof_pack

if __name__ == "__main__":
    report = run_kubernetes_proof_pack()
    print_report(report)
    if not report["summary"]["all_passed"]:
        raise SystemExit(1)
