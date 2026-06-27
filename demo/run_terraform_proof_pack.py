#!/usr/bin/env python3
"""Run the Terraform provider proof pack.

This is a local mock/sandbox proof. It does not call Terraform CLI, Terraform
Cloud, cloud providers, or real MCP servers.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from demo.provider_packs.terraform import print_report, run_terraform_proof_pack

if __name__ == "__main__":
    report = run_terraform_proof_pack()
    print_report(report)
    if not report["summary"]["all_passed"]:
        raise SystemExit(1)
