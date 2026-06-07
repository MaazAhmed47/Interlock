"""
Security Receipt endpoints.

  GET /audit/receipt/export       - batch of receipts for a time range as a
                                    single downloadable artifact (JSON now,
                                    CSV/PDF later).
  GET /audit/receipt/{audit_id}   - one tamper-evident receipt for one event.

Both require API-key auth (same surface as GET /mcp/audit, which serves the
underlying runtime audit log to the dashboard).

NOTE: /audit/receipt/export is declared before /audit/receipt/{audit_id} so the
literal "export" path is not parsed as an integer audit_id.
"""

from typing import Optional

from fastapi import APIRouter, Header, HTTPException, Query
from fastapi.responses import JSONResponse

import proxy
from core import db
from core.limits import clamp_limit
from core import receipt as receipt_builder

router = APIRouter()

MAX_RECEIPT_EXPORT_LIMIT = 1000


def _export_filename(from_ts: Optional[str], to_ts: Optional[str], fmt: str) -> str:
    def _stamp(ts: Optional[str]) -> str:
        if not ts:
            return "all"
        return "".join(c for c in ts[:10] if c.isdigit() or c == "-") or "all"

    return f"interlock-receipts-{_stamp(from_ts)}-to-{_stamp(to_ts)}.{fmt}"


@router.get("/audit/receipt/export")
async def export_receipts(
    from_ts: Optional[str] = Query(None, alias="from"),
    to_ts: Optional[str] = Query(None, alias="to"),
    format: str = "json",
    limit: int = 500,
    x_api_key: Optional[str] = Header(None),
):
    """Export a batch of Security Receipts for a time range as a download."""
    proxy.verify_key(x_api_key)

    fmt = (format or "json").lower()
    if fmt not in receipt_builder.SUPPORTED_FORMATS:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Unsupported export format '{format}'. "
                f"Supported: {', '.join(receipt_builder.SUPPORTED_FORMATS)}."
            ),
        )

    safe_limit = clamp_limit(limit, default=500, maximum=MAX_RECEIPT_EXPORT_LIMIT)
    rows = db.list_mcp_audit_logs_between(from_ts, to_ts, limit=safe_limit)
    chain = db.verify_audit_chain()
    batch = receipt_builder.build_batch(
        rows,
        per_record_verifier=lambda aid: db.verify_mcp_audit_record(aid)[
            "chain_verified"
        ],
        chain_verified=bool(chain.get("valid")),
        from_ts=from_ts,
        to_ts=to_ts,
    )

    filename = _export_filename(from_ts, to_ts, fmt)
    return JSONResponse(
        content=batch,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/audit/receipt/{audit_id}")
async def get_receipt(audit_id: int, x_api_key: Optional[str] = Header(None)):
    """Return a single tamper-evident Security Receipt for one audit event."""
    proxy.verify_key(x_api_key)

    row = db.get_mcp_audit_log(audit_id)
    if not row:
        raise HTTPException(status_code=404, detail="Audit event not found.")

    verification = db.verify_mcp_audit_record(audit_id)
    return receipt_builder.build_receipt(
        row, chain_verified=verification.get("chain_verified", False)
    )
