import logging
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone

import httpx

from core import db

logger = logging.getLogger("interlock.shadow_scanner")

_TIMEOUT = 5.0


@dataclass
class ProbeResult:
    url: str
    responded: bool
    looks_like_mcp: bool
    auth_required: bool
    tool_listing_available: bool
    status_code: int
    error: str = ""


@dataclass
class ShadowFinding:
    url: str
    is_registered: bool
    probe: ProbeResult
    risk_score: int


def _calculate_risk_score(probe: ProbeResult) -> int:
    if not probe.responded:
        return 0
    score = 10
    if probe.tool_listing_available:
        score += 40
        if not probe.auth_required:
            score += 30
    if probe.auth_required:
        score += 20
    return min(score, 100)


async def probe_target(
    url: str, probe_path: str = "/tools/list", client: httpx.AsyncClient | None = None
) -> ProbeResult:
    target = f"{url.rstrip('/')}{probe_path}"
    _client = client or httpx.AsyncClient(timeout=_TIMEOUT)
    try:
        resp = await _client.get(target)
        if resp.status_code in (401, 403):
            return ProbeResult(
                url=url,
                responded=True,
                looks_like_mcp=True,
                auth_required=True,
                tool_listing_available=False,
                status_code=resp.status_code,
            )
        if resp.status_code == 200:
            try:
                data = resp.json()
                if (
                    isinstance(data, dict)
                    and "tools" in data
                    and isinstance(data["tools"], list)
                ):
                    return ProbeResult(
                        url=url,
                        responded=True,
                        looks_like_mcp=True,
                        auth_required=False,
                        tool_listing_available=True,
                        status_code=200,
                    )
                if isinstance(data, dict) and "error" in data:
                    return ProbeResult(
                        url=url,
                        responded=True,
                        looks_like_mcp=True,
                        auth_required=False,
                        tool_listing_available=False,
                        status_code=200,
                    )
            except Exception:
                pass
            return ProbeResult(
                url=url,
                responded=True,
                looks_like_mcp=False,
                auth_required=False,
                tool_listing_available=False,
                status_code=200,
            )
        return ProbeResult(
            url=url,
            responded=True,
            looks_like_mcp=False,
            auth_required=False,
            tool_listing_available=False,
            status_code=resp.status_code,
        )
    except httpx.TimeoutException as e:
        return ProbeResult(
            url=url,
            responded=False,
            looks_like_mcp=False,
            auth_required=False,
            tool_listing_available=False,
            status_code=0,
            error=str(e),
        )
    except httpx.ConnectError as e:
        return ProbeResult(
            url=url,
            responded=False,
            looks_like_mcp=False,
            auth_required=False,
            tool_listing_available=False,
            status_code=0,
            error=str(e),
        )
    finally:
        if client is None:
            await _client.aclose()


async def run_shadow_scan(
    conn: sqlite3.Connection, client: httpx.AsyncClient | None = None
) -> list[ShadowFinding]:
    now = datetime.now(timezone.utc).isoformat()
    targets = conn.execute(
        "SELECT url, probe_path FROM shadow_scan_targets WHERE enabled = 1"
    ).fetchall()
    registered_urls = {
        db.row_value(row, "url", 0).rstrip("/")
        for row in conn.execute("SELECT url FROM mcp_servers").fetchall()
    }

    findings: list[ShadowFinding] = []
    for row in targets:
        url = db.row_value(row, "url", 0)
        probe_path = db.row_value(row, "probe_path", 1) or "/tools/list"
        probe = await probe_target(url, probe_path, client=client)
        if not (probe.responded and probe.looks_like_mcp):
            continue
        is_registered = url.rstrip("/") in registered_urls
        if is_registered:
            continue
        score = _calculate_risk_score(probe)
        existing = conn.execute(
            "SELECT id FROM shadow_mcp_servers WHERE url = ?", (url,)
        ).fetchone()
        if existing:
            conn.execute(
                "UPDATE shadow_mcp_servers SET last_seen=?, auth_required=?, "
                "tool_listing_available=?, risk_score=? WHERE url=?",
                (
                    now,
                    int(probe.auth_required),
                    int(probe.tool_listing_available),
                    score,
                    url,
                ),
            )
        else:
            conn.execute(
                "INSERT INTO shadow_mcp_servers "
                "(url, probe_path, status, first_seen, last_seen, auth_required, "
                "tool_listing_available, risk_score) VALUES (?,?,?,?,?,?,?,?)",
                (
                    url,
                    probe_path,
                    "unreviewed",
                    now,
                    now,
                    int(probe.auth_required),
                    int(probe.tool_listing_available),
                    score,
                ),
            )
            try:
                # Route through the single chained writer: a direct INSERT
                # would land without prev_hash/integrity_hash and poison the
                # audit hash chain.
                db.log_mcp_audit_event(
                    {
                        "ts": now,
                        "server_id": "0",
                        "tool_name": "",
                        "role": "system",
                        "action": "shadow_discovered",
                        "matched_rule": "shadow_scanner",
                        "reason": f"Unregistered MCP endpoint responded at {url}",
                        "confidence": 1.0,
                        "blocked_by": "shadow_scanner",
                    }
                )
            except Exception:
                logger.exception(
                    "Failed to write shadow discovery audit log for %s", url
                )
        # db.get_conn() connections are autocommit on both backends, and the
        # Postgres wrapper exposes no commit(); only plain sqlite3 connections
        # (tests) still need the explicit commit.
        if hasattr(conn, "commit"):
            conn.commit()
        findings.append(
            ShadowFinding(url=url, is_registered=False, probe=probe, risk_score=score)
        )
    return findings
