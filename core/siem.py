import httpx
import asyncio
import os
from datetime import datetime, timezone
from typing import Any, List
from models.schemas import ScanResult
from core.url_security import OutboundUrlRejected, ensure_safe_outbound_url

# ── SIEM Provider Configurations ──────────────────────────────────────────────
SIEM_PROVIDERS: dict[str, dict[str, Any]] = {
    "datadog": {
        "url_template": "https://http-intake.logs.{region}.datadoghq.com/api/v2/logs",
        "auth_header": "DD-API-KEY",
        "format": "datadog",
        "default_region": "us",
    },
    "splunk_hec": {
        "url_template": "{url}/services/collector/event",
        "auth_header": "Authorization",
        "auth_prefix": "Splunk ",
        "format": "splunk",
    },
    "elastic": {
        "url_template": "{url}/_doc",
        "auth_header": "Authorization",
        "auth_prefix": "ApiKey ",
        "format": "elastic",
    },
    "sumologic": {
        "url_template": "{url}",
        "auth_header": None,
        "format": "json",
    },
    "slack": {
        "url_template": "{url}",
        "auth_header": None,
        "format": "slack",
    },
    "pagerduty": {
        "url_template": "https://events.pagerduty.com/v2/enqueue",
        "auth_header": None,
        "format": "pagerduty",
    },
    "webhook": {
        "url_template": "{url}",
        "auth_header": None,
        "format": "json",
    },
}

# ── Per-API-key SIEM configs ──────────────────────────────────────────────────
SIEM_CONFIGS: dict[str, Any] = {
    # Map api_key -> list of SIEM destinations
    # Loaded from .env or database in production
}


def _load_siem_configs():
    """Load SIEM configs from env vars."""
    global SIEM_CONFIGS
    # Format: SIEM_<KEY>_<PROVIDER>_<FIELD>
    # Example: SIEM_LF_DEV_KEY_456_DATADOG_API_KEY=xxx
    for env_key, env_val in os.environ.items():
        if env_key.startswith("SIEM_"):
            try:
                parts = env_key.replace("SIEM_", "").split("_")
                if len(parts) >= 3:
                    pass  # parsed in production setup
            except Exception:
                pass


# ── Severity Mapping ──────────────────────────────────────────────────────────
SEVERITY_MAP: dict[str, dict[str, Any]] = {
    "CRITICAL": {
        "datadog": "critical",
        "splunk": "critical",
        "elastic": "critical",
        "syslog": 2,
        "score": 4,
    },
    "HIGH": {
        "datadog": "error",
        "splunk": "high",
        "elastic": "high",
        "syslog": 3,
        "score": 3,
    },
    "MEDIUM": {
        "datadog": "warning",
        "splunk": "medium",
        "elastic": "medium",
        "syslog": 4,
        "score": 2,
    },
    "LOW": {
        "datadog": "info",
        "splunk": "low",
        "elastic": "low",
        "syslog": 6,
        "score": 1,
    },
    "SAFE": {
        "datadog": "info",
        "splunk": "info",
        "elastic": "info",
        "syslog": 7,
        "score": 0,
    },
}


# ── Format Builders ───────────────────────────────────────────────────────────
def build_datadog_event(
    result: ScanResult, api_key_prefix: str, source: str = "interlock"
) -> dict:
    sev = SEVERITY_MAP.get(result.threat_level.value, SEVERITY_MAP["MEDIUM"])
    return {
        "ddsource": source,
        "ddtags": f"env:production,service:interlock,threat:{result.threat_type or 'none'},level:{result.threat_level.value.lower()}",
        "hostname": "interlock",
        "service": "interlock",
        "status": sev["datadog"],
        "message": f"[{result.threat_level.value}] {result.threat_type or 'SCAN'}: {result.reason[:200]}",
        "timestamp": int(datetime.now(timezone.utc).timestamp() * 1000),
        "attributes": {
            "is_threat": result.is_threat,
            "threat_level": result.threat_level.value,
            "threat_type": result.threat_type,
            "confidence": result.confidence,
            "risk_score": getattr(result, "risk_score", None),
            "layer_caught": result.layer_caught,
            "scan_time_ms": result.scan_time_ms,
            "api_key_prefix": api_key_prefix,
            "prompt_preview": (result.original_prompt or "")[:200],
        },
    }


def build_splunk_event(result: ScanResult, api_key_prefix: str) -> dict:
    return {
        "time": int(datetime.now(timezone.utc).timestamp()),
        "host": "interlock",
        "source": "interlock",
        "sourcetype": "interlock:threat",
        "index": "main",
        "event": {
            "level": SEVERITY_MAP.get(
                result.threat_level.value, SEVERITY_MAP["MEDIUM"]
            )["splunk"],
            "is_threat": result.is_threat,
            "threat_level": result.threat_level.value,
            "threat_type": result.threat_type,
            "reason": result.reason,
            "confidence": result.confidence,
            "risk_score": getattr(result, "risk_score", None),
            "layer_caught": result.layer_caught,
            "scan_time_ms": result.scan_time_ms,
            "api_key_prefix": api_key_prefix,
            "prompt_preview": (result.original_prompt or "")[:200],
        },
    }


def build_elastic_event(result: ScanResult, api_key_prefix: str) -> dict:
    return {
        "@timestamp": datetime.now(timezone.utc).isoformat(),
        "service": {"name": "interlock", "version": "1.0.0"},
        "event": {
            "category": "intrusion_detection",
            "type": "denied" if result.is_threat else "allowed",
            "severity": SEVERITY_MAP.get(
                result.threat_level.value, SEVERITY_MAP["MEDIUM"]
            )["score"],
            "outcome": "failure" if result.is_threat else "success",
        },
        "threat": {
            "framework": "Interlock",
            "tactic": {"name": result.threat_type or "unknown"},
            "indicator": {"type": result.layer_caught or "unknown"},
        },
        "interlock": {
            "is_threat": result.is_threat,
            "threat_level": result.threat_level.value,
            "threat_type": result.threat_type,
            "reason": result.reason,
            "confidence": result.confidence,
            "risk_score": getattr(result, "risk_score", None),
            "layer_caught": result.layer_caught,
            "scan_time_ms": result.scan_time_ms,
            "api_key_prefix": api_key_prefix,
            "prompt_preview": (result.original_prompt or "")[:200],
        },
    }


def build_slack_event(result: ScanResult, api_key_prefix: str) -> dict:
    color = {
        "CRITICAL": "#ff3d5a",
        "HIGH": "#ff8c42",
        "MEDIUM": "#ffd166",
        "LOW": "#a78bfa",
        "SAFE": "#00e87a",
    }.get(result.threat_level.value, "#888888")

    emoji = {
        "CRITICAL": ":rotating_light:",
        "HIGH": ":warning:",
        "MEDIUM": ":exclamation:",
        "LOW": ":information_source:",
        "SAFE": ":white_check_mark:",
    }.get(result.threat_level.value, ":question:")

    return {
        "text": f"{emoji} *Interlock Alert — {result.threat_level.value}*",
        "attachments": [
            {
                "color": color,
                "fields": [
                    {
                        "title": "Threat Type",
                        "value": result.threat_type or "Unknown",
                        "short": True,
                    },
                    {
                        "title": "Risk Score",
                        "value": f"{getattr(result, 'risk_score', 0)}/100",
                        "short": True,
                    },
                    {
                        "title": "Confidence",
                        "value": f"{int((result.confidence or 0)*100)}%",
                        "short": True,
                    },
                    {
                        "title": "Layer Caught",
                        "value": result.layer_caught or "Unknown",
                        "short": True,
                    },
                    {"title": "Reason", "value": result.reason[:300], "short": False},
                    {
                        "title": "Prompt",
                        "value": f"```{(result.original_prompt or '')[:200]}```",
                        "short": False,
                    },
                    {"title": "API Key", "value": api_key_prefix, "short": True},
                    {
                        "title": "Time",
                        "value": datetime.now(timezone.utc).strftime(
                            "%Y-%m-%d %H:%M:%S UTC"
                        ),
                        "short": True,
                    },
                ],
                "footer": "Interlock",
                "ts": int(datetime.now(timezone.utc).timestamp()),
            }
        ],
    }


def build_pagerduty_event(
    result: ScanResult, integration_key: str, api_key_prefix: str
) -> dict:
    sev_map = {
        "CRITICAL": "critical",
        "HIGH": "error",
        "MEDIUM": "warning",
        "LOW": "info",
        "SAFE": "info",
    }
    return {
        "routing_key": integration_key,
        "event_action": "trigger",
        "dedup_key": f"llm-fw-{result.threat_type}-{api_key_prefix}",
        "payload": {
            "summary": f"[{result.threat_level.value}] {result.threat_type}: {result.reason[:120]}",
            "severity": sev_map.get(result.threat_level.value, "warning"),
            "source": "interlock",
            "component": "ai-security",
            "group": result.threat_type or "unknown",
            "class": "ai_threat",
            "custom_details": {
                "threat_level": result.threat_level.value,
                "threat_type": result.threat_type,
                "confidence": result.confidence,
                "risk_score": getattr(result, "risk_score", None),
                "layer_caught": result.layer_caught,
                "api_key_prefix": api_key_prefix,
                "prompt_preview": (result.original_prompt or "")[:200],
            },
        },
    }


# ── Provider Senders ─────────────────────────────────────────────────────────
async def send_to_siem(
    provider: str, config: dict, result: ScanResult, api_key_prefix: str
) -> dict:
    """
    Send a scan result to a SIEM provider.
    Returns success/failure status without crashing on error.
    """
    try:
        if provider == "datadog":
            region = config.get("region", "us")
            url = ensure_safe_outbound_url(
                SIEM_PROVIDERS["datadog"]["url_template"].format(region=region),
                context="Datadog SIEM",
            )
            event = build_datadog_event(
                result, api_key_prefix, config.get("source", "interlock")
            )
            headers = {
                "DD-API-KEY": config["api_key"],
                "Content-Type": "application/json",
            }
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.post(url, json=[event], headers=headers)
                return {
                    "provider": "datadog",
                    "status": resp.status_code,
                    "ok": resp.status_code < 300,
                }

        elif provider == "splunk_hec":
            url = ensure_safe_outbound_url(
                SIEM_PROVIDERS["splunk_hec"]["url_template"].format(
                    url=config["url"].rstrip("/")
                ),
                context="Splunk SIEM",
            )
            event = build_splunk_event(result, api_key_prefix)
            headers = {
                "Authorization": f"Splunk {config['token']}",
                "Content-Type": "application/json",
            }
            async with httpx.AsyncClient(
                timeout=5.0, verify=config.get("verify_ssl", True)
            ) as client:
                resp = await client.post(url, json=event, headers=headers)
                return {
                    "provider": "splunk",
                    "status": resp.status_code,
                    "ok": resp.status_code < 300,
                }

        elif provider == "elastic":
            index = config.get("index", "interlock-logs")
            url = ensure_safe_outbound_url(
                f"{config['url'].rstrip('/')}/{index}/_doc",
                context="Elastic SIEM",
            )
            event = build_elastic_event(result, api_key_prefix)
            headers = {
                "Authorization": f"ApiKey {config['api_key']}",
                "Content-Type": "application/json",
            }
            async with httpx.AsyncClient(
                timeout=5.0, verify=config.get("verify_ssl", True)
            ) as client:
                resp = await client.post(url, json=event, headers=headers)
                return {
                    "provider": "elastic",
                    "status": resp.status_code,
                    "ok": resp.status_code < 300,
                }

        elif provider == "slack":
            event = build_slack_event(result, api_key_prefix)
            async with httpx.AsyncClient(timeout=5.0) as client:
                url = ensure_safe_outbound_url(
                    config["webhook_url"], context="Slack webhook"
                )
                resp = await client.post(url, json=event)
                return {
                    "provider": "slack",
                    "status": resp.status_code,
                    "ok": resp.status_code < 300,
                }

        elif provider == "pagerduty":
            if not result.is_threat or result.threat_level.value not in [
                "HIGH",
                "CRITICAL",
            ]:
                return {
                    "provider": "pagerduty",
                    "status": "skipped",
                    "ok": True,
                    "reason": "below severity threshold",
                }
            event = build_pagerduty_event(
                result, config["integration_key"], api_key_prefix
            )
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.post(
                    ensure_safe_outbound_url(
                        SIEM_PROVIDERS["pagerduty"]["url_template"],
                        context="PagerDuty SIEM",
                    ),
                    json=event,
                )
                return {
                    "provider": "pagerduty",
                    "status": resp.status_code,
                    "ok": resp.status_code < 300,
                }

        elif provider == "webhook":
            payload = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "is_threat": result.is_threat,
                "threat_level": result.threat_level.value,
                "threat_type": result.threat_type,
                "reason": result.reason,
                "confidence": result.confidence,
                "risk_score": getattr(result, "risk_score", None),
                "layer_caught": result.layer_caught,
                "api_key_prefix": api_key_prefix,
                "prompt_preview": (result.original_prompt or "")[:200],
            }
            headers = config.get("headers", {})
            async with httpx.AsyncClient(timeout=5.0) as client:
                url = ensure_safe_outbound_url(config["url"], context="Webhook SIEM")
                resp = await client.post(url, json=payload, headers=headers)
                return {
                    "provider": "webhook",
                    "status": resp.status_code,
                    "ok": resp.status_code < 300,
                }

        else:
            return {"provider": provider, "ok": False, "error": "unknown_provider"}

    except OutboundUrlRejected as exc:
        return {
            "provider": provider,
            "ok": False,
            "error": "unsafe_outbound_url",
            "message": str(exc),
        }
    except httpx.TimeoutException:
        return {"provider": provider, "ok": False, "error": "timeout"}
    except httpx.ConnectError:
        return {"provider": provider, "ok": False, "error": "connection_failed"}
    except Exception as e:
        return {"provider": provider, "ok": False, "error": str(e)[:200]}


# ── Main Dispatcher ───────────────────────────────────────────────────────────
async def dispatch_to_siems(
    result: ScanResult, api_key: str, siem_configs: List[dict]
) -> List[dict]:
    """
    Send a scan result to ALL configured SIEMs in parallel.
    Failures in one don't affect others.
    """
    if not siem_configs:
        return []

    api_key_prefix = api_key[:8] + "..." if api_key else "unknown"

    # Filter by severity threshold
    tasks = []
    for cfg in siem_configs:
        min_severity = cfg.get("min_severity", "LOW")
        threshold = SEVERITY_MAP.get(min_severity, SEVERITY_MAP["LOW"])["score"]
        result_score = SEVERITY_MAP.get(
            result.threat_level.value, SEVERITY_MAP["MEDIUM"]
        )["score"]

        if result_score >= threshold:
            tasks.append(send_to_siem(cfg["provider"], cfg, result, api_key_prefix))

    if not tasks:
        return []

    try:
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return [
            r if not isinstance(r, Exception) else {"ok": False, "error": str(r)}  # type: ignore[misc]
            for r in results
        ]
    except Exception:
        return []


def trigger_siem_dispatch(result: ScanResult, api_key: str, siem_configs: List[dict]):
    """Fire-and-forget SIEM dispatch — never blocks the main scan flow."""
    if not siem_configs:
        return
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            asyncio.create_task(dispatch_to_siems(result, api_key, siem_configs))
        else:
            loop.run_until_complete(dispatch_to_siems(result, api_key, siem_configs))
    except Exception:
        pass  # Never let SIEM failures break the firewall
