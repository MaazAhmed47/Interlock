import httpx
import asyncio
import logging
from models.schemas import ScanResult
from typing import Optional
from core.outbound_events import alert_reason, prompt_evidence
from core.outbound_http import (
    OutboundHTTPConfigurationError,
    classify_outbound_http_failure,
    create_async_client,
)
from core.url_security import OutboundUrlRejected, ensure_safe_outbound_url_async

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
    evidence = prompt_evidence(result)
    fields = [
        {
            "title": "Threat Level",
            "value": result.threat_level.value,
            "short": True,
        },
        {"title": "Type", "value": result.threat_type or "Unknown", "short": True},
        {"title": "Confidence", "value": str(result.confidence), "short": True},
        {"title": "Layer", "value": result.layer_caught or "Unknown", "short": True},
        {
            "title": "Risk Score",
            "value": str(result.risk_score or "N/A"),
            "short": True,
        },
        {
            "title": "Scan Time",
            "value": f"{result.scan_time_ms or 0} ms",
            "short": True,
        },
        {"title": "Reason", "value": alert_reason(result), "short": False},
        {"title": "Prompt SHA-256", "value": evidence["prompt_sha256"], "short": False},
        {
            "title": "Prompt bytes",
            "value": str(evidence["prompt_length_bytes"]),
            "short": True,
        },
    ]
    if evidence.get("prompt_preview") is not None:
        fields.append(
            {"title": "Prompt", "value": evidence["prompt_preview"], "short": False}
        )

    return {
        "text": "🚨 *Interlock Alert*",
        "attachments": [
            {
                "color": "#ff4757",
                "fields": fields,
            }
        ],
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

    try:
        url = await ensure_safe_outbound_url_async(url, context="Per-key webhook")
        payload = _build_payload(result)
        async with create_async_client(
            timeout=WEBHOOK_TIMEOUT, purpose="per-key webhook"
        ) as client:
            resp = await client.post(url, json=payload)
            if not 200 <= resp.status_code < 300:
                logger.warning(
                    "Webhook returned non-2xx",
                    extra={"status": resp.status_code, "api_key_prefix": api_key[:8]},
                )
    except OutboundUrlRejected:
        logger.warning(
            "Webhook destination rejected", extra={"api_key_prefix": api_key[:8]}
        )
    except httpx.TimeoutException:
        logger.warning("Webhook timeout", extra={"api_key_prefix": api_key[:8]})
    except httpx.ConnectError:
        logger.warning(
            "Webhook connection failed", extra={"api_key_prefix": api_key[:8]}
        )
    except OutboundHTTPConfigurationError:
        logger.warning(
            "Webhook outbound configuration rejected",
            extra={"api_key_prefix": api_key[:8]},
        )
    except Exception as exc:
        logger.warning(
            "Webhook failed",
            extra={
                "api_key_prefix": api_key[:8],
                "error_class": classify_outbound_http_failure(exc),
            },
        )


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
        except Exception as exc:
            logger.warning(
                "Sync webhook fallback failed",
                extra={"error_class": classify_outbound_http_failure(exc)},
            )
