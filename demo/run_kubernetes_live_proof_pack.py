#!/usr/bin/env python3
"""Run the credential-gated live Kubernetes/kubectl proof pack."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from demo.provider_packs.kubernetes_live import (
    print_report,
    run_kubernetes_live_proof_pack,
)

if __name__ == "__main__":
    report = run_kubernetes_live_proof_pack()
    print_report(report)
    if report["summary"].get("executed") and not report["summary"].get("all_passed"):
        raise SystemExit(1)
