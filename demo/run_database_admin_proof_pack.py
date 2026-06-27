"""Run the database/admin-SaaS provider proof pack.

This uses a local SQLite sandbox for DB readback. It does not contact MySQL,
Postgres, Snowflake, NetBox, Zabbix, Microsoft 365, or production MCP servers.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from demo.provider_packs.database_admin import (
    print_report,
    run_database_admin_proof_pack,
)


def main() -> int:
    report = run_database_admin_proof_pack()
    print_report(report)
    return 0 if report["summary"]["all_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
