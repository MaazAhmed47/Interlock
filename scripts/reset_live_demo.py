#!/usr/bin/env python3
"""Reset the live buyer demo registry to intended demo servers only."""

import argparse
import json
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parents[1]
load_dotenv(ROOT / ".env")
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core import db  # noqa: E402


def _with_v(url: str, version: int) -> str:
    sep = "&" if "?" in url else "?"
    return f"{url}{sep}v={version}"


def _fetch_delete_candidates() -> list[dict]:
    return [
        {"server_id": server["server_id"], "url": server["url"]}
        for server in db.list_mcp_servers()
        if server["server_id"] not in db.INTENDED_DEMO_SERVER_IDS
    ]


def _delete_non_intended(candidates: list[dict]) -> int:
    return sum(
        1
        for candidate in candidates
        if db.unregister_mcp_server(candidate["server_id"])
    )


def _ensure_clean_proof_docs(mock_url: str | None, dry_run: bool) -> None:
    if db.lookup_mcp_server("clean-proof-docs") or not mock_url:
        return
    url = _with_v(mock_url, 1)
    if dry_run:
        print(f"would register clean-proof-docs from {url}")
        return
    created = db.register_mcp_server(
        "clean-proof-docs",
        {
            "url": url,
            "description": "Buyer-facing clean document drift demo",
            "allowed_tools": ["read_document"],
            "blocked_tools": [],
            "rate_limit": 30,
        },
    )
    if created:
        db.verify_mcp_server("clean-proof-docs")


def _rederive_tool_metadata(dry_run: bool) -> list[dict]:
    changes: list[dict] = []
    tool_keys = [
        (server_id, tool["tool_name"])
        for server_id in sorted(db.INTENDED_DEMO_SERVER_IDS)
        for tool in db.list_mcp_tool_metadata(server_id)
    ]
    for server_id, tool_name in tool_keys:
        result = db.rederive_mcp_tool_metadata(server_id, tool_name, dry_run=dry_run)
        if not result.get("ok"):
            print("metadata_rederive_skipped=" + json.dumps(result, sort_keys=True))
            continue
        if not result["changed"]:
            continue
        old_meta = result["old_metadata"]
        new_meta = result["new_metadata"]
        changes.append(
            {
                "server_id": server_id,
                "tool_name": tool_name,
                "old_side_effect": old_meta.get("side_effect"),
                "new_side_effect": new_meta.get("side_effect"),
                "old_effects": old_meta.get("effects"),
                "new_effects": new_meta.get("effects"),
            }
        )
    return changes


def _review_queue() -> list[dict]:
    return db.list_drifted_mcp_tools(limit=500, demo_visible_only=True)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Reset live Supabase demo data to intended Interlock demo servers."
    )
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument(
        "--mock-url",
        default=os.getenv("INTERLOCK_DEMO_MOCK_URL", ""),
        help="Optional public mock URL used if clean-proof-docs is missing.",
    )
    args = parser.parse_args()

    if not db.USE_POSTGRES or not db.is_production_database_url():
        raise SystemExit(
            "Refusing to reset live demo: DATABASE_URL must point at Supabase/production Postgres."
        )

    print(f"intended_demo_servers={sorted(db.INTENDED_DEMO_SERVER_IDS)}")
    candidates = _fetch_delete_candidates()
    print(f"delete_candidates={len(candidates)}")
    for row in candidates:
        print(f"  remove {row['server_id']} {row['url']}")
    if not args.dry_run:
        deleted = _delete_non_intended(candidates)
        print(f"deleted_servers={deleted}")

    if args.dry_run:
        print("dry_run=true; seed/register/update skipped")
    else:
        db.seed_mcp_servers()
    _ensure_clean_proof_docs(args.mock_url or None, args.dry_run)

    changes = _rederive_tool_metadata(args.dry_run)
    print(f"metadata_rederived={len(changes)}")
    for change in changes:
        print("  " + json.dumps(change, sort_keys=True))

    queue = _review_queue()
    print(f"review_queue={len(queue)}")
    for tool in queue:
        print(
            "  "
            + json.dumps(
                {
                    "server_id": tool.get("server_id"),
                    "tool_name": tool.get("tool_name"),
                    "status": tool.get("status"),
                    "drift_severity": tool.get("drift_severity"),
                    "drift_action": tool.get("drift_action"),
                    "effects": tool.get("effects")
                    or (tool.get("normalized_metadata") or {}).get("effects"),
                    "side_effect": tool.get("side_effect")
                    or (tool.get("normalized_metadata") or {}).get("side_effect"),
                },
                sort_keys=True,
            )
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
