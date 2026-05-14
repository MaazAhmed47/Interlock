import httpx
import asyncio
import logging
from models.schemas import ScanResult
from typing import Optional

logger = logging.getLogger("interlock.webhook")

# Only fire webhooks for these threat levels
WEBHOOK_TRIGGER_LEVELS = {"HIGH", "CRITICAL"}

WEBHOOK_TIMEOUT = 5.0


def _resolve_webhook_url(api_key: str) -> Optional[str]:
    """Look up webhook_url from the DB record for this API key."""
    try:
        from core import db
        record = db.lookup_key(api_key)
        return (record or {}).get("webhook_url") or None
    except Exception as e:
        logger.warning("webhook URL lookup failed: %s", e)
        return None


def _build_payload(result: ScanResult) -> dict:
    """Slack-compatible payload (also works for generic webhooks)."""
    return {
        "text": "🚨 *Interlock Alert*",
        "attachments": [{
            "color": "#ff4757",
            "fields": [
                {"title": "Threat Level", "value": result.threat_level.value,             "short": True},
                {"title": "Type",         "value": result.threat_type or "Unknown",       "short": True},
                {"title": "Confidence",   "value": str(result.confidence),                "short": True},
                {"title": "Layer",        "value": result.layer_caught or "Unknown",      "short": True},
                {"title": "Risk Score",   "value": str(result.risk_score or "N/A"),       "short": True},
                {"title": "Scan Time",    "value": f"{result.scan_time_ms or 0} ms",      "short": True},
                {"title": "Reason",       "value": result.reason,                          "short": False},
                {"title": "Prompt",       "value": (result.original_prompt or "")[:200],  "short": False},
            ]
        }]
    }


async def fire_webhook(api_key: str, result: ScanResult) -> None:
    """
    Send the webhook. Always coroutine-based — caller decides how to schedule.
    Errors are logged but never re-raised; webhook delivery must NEVER break the scan path.
    """
    url = _resolve_webhook_url(api_key)
    if not url:
        return
    if result.threat_level.value not in WEBHOOK_TRIGGER_LEVELS:
        return

    payload = _build_payload(result)

    try:
        async with httpx.AsyncClient(timeout=WEBHOOK_TIMEOUT) as client:
            resp = await client.post(url, json=payload)
            if resp.status_code >= 400:
                logger.warning(
                    "Webhook returned non-2xx",
                    extra={"status": resp.status_code, "api_key_prefix": api_key[:8]},
                )
    except httpx.TimeoutException:
        logger.warning("Webhook timeout", extra={"api_key_prefix": api_key[:8]})
    except Exception as e:
        logger.warning("Webhook failed: %s", e, extra={"api_key_prefix": api_key[:8]})


def trigger_webhook(api_key: str, result: ScanResult) -> None:
    """
    Fire-and-forget webhook trigger.
    Safe to call from any async route — schedules on the running loop without blocking.

    If somehow called outside an async context (e.g. tests or sync scripts),
    falls back to running the coroutine to completion in a fresh loop.
    """
    try:
        loop = asyncio.get_running_loop()
        # Inside an async context (normal FastAPI path) — schedule and move on.
        loop.create_task(fire_webhook(api_key, result))
    except RuntimeError:
        # No running loop. Run synchronously in a fresh loop. Used by sync callers/tests.
        try:
            asyncio.run(fire_webhook(api_key, result))
        except Exception as e:
            logger.warning("Sync webhook fallback failed: %s", e)
