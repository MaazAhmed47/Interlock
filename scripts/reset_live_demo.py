#!/usr/bin/env python3
"""Reset the live buyer demo registry to intended demo servers only."""

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parents[1]
load_dotenv(ROOT / ".env")
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core import db  # noqa: E402
from core.tool_metadata import normalize_tool_metadata  # noqa: E402


def _with_v(url: str, version: int) -> str:
    sep = "&" if "?" in url else "?"
    return f"{url}{sep}v={version}"


def _json(value: Any) -> Any:
    if isinstance(value, (dict, list)):
        return value
    try:
        return json.loads(value or "{}")
    except (TypeError, json.JSONDecodeError):
        return {}


def _intended_placeholders() -> str:
    return ", ".join("?" for _ in db.INTENDED_DEMO_SERVER_IDS)


def _fetch_delete_candidates(conn) -> list[dict]:
    rows = conn.execute(
        f"""
        SELECT server_id, url
          FROM mcp_servers
         WHERE server_id NOT IN ({_intended_placeholders()})
         ORDER BY registered_at ASC
        """,
        tuple(sorted(db.INTENDED_DEMO_SERVER_IDS)),
    ).fetchall()
    return [dict(row) for row in rows]


def _delete_non_intended(conn) -> int:
    cursor = conn.execute(
        f"""
        DELETE FROM mcp_servers
         WHERE server_id NOT IN ({_intended_placeholders()})
        """,
        tuple(sorted(db.INTENDED_DEMO_SERVER_IDS)),
    )
    return int(cursor.rowcount or 0)


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
    with db.get_conn() as conn:
        rows = conn.execute(
            f"""
            SELECT server_id, tool_name, normalized_metadata, raw_tool_definition
              FROM mcp_tool_metadata
             WHERE server_id IN ({_intended_placeholders()})
             ORDER BY server_id ASC, tool_name ASC
            """,
            tuple(sorted(db.INTENDED_DEMO_SERVER_IDS)),
        ).fetchall()
        for row in rows:
            item = dict(row)
            raw_tool = _json(item.get("raw_tool_definition"))
            if not raw_tool:
                continue
            old_meta = _json(item.get("normalized_metadata"))
            new_meta = normalize_tool_metadata(raw_tool)
            if old_meta == new_meta:
                continue
            change = {
                "server_id": item["server_id"],
                "tool_name": item["tool_name"],
                "old_side_effect": old_meta.get("side_effect"),
                "new_side_effect": new_meta.get("side_effect"),
                "old_effects": old_meta.get("effects"),
                "new_effects": new_meta.get("effects"),
            }
            changes.append(change)
            if not dry_run:
                conn.execute(
                    """
                    UPDATE mcp_tool_metadata
                       SET normalized_metadata = ?
                     WHERE server_id = ? AND tool_name = ?
                    """,
                    (
                        json.dumps(new_meta, sort_keys=True),
                        item["server_id"],
                        item["tool_name"],
                    ),
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
    with db.get_conn() as conn:
        candidates = _fetch_delete_candidates(conn)
        print(f"delete_candidates={len(candidates)}")
        for row in candidates:
            print(f"  remove {row['server_id']} {row['url']}")
        if not args.dry_run:
            deleted = _delete_non_intended(conn)
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
