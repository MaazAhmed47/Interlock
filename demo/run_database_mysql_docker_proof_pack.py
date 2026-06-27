"""Run the credential-gated Docker MySQL database proof pack."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from demo.provider_packs.database_mysql_docker import (
    print_report,
    run_database_mysql_docker_proof_pack,
)


def main() -> int:
    report = run_database_mysql_docker_proof_pack()
    print_report(report)
    return 0 if report["summary"]["all_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
