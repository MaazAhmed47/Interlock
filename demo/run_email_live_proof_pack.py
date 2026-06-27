#!/usr/bin/env python3
"""Run the credential-gated live email/messaging provider proof pack."""

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from demo.provider_packs.email_live import print_report, run_email_live_proof_pack

if __name__ == "__main__":
    print_report(run_email_live_proof_pack())
