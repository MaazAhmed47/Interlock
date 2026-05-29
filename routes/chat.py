import os
from typing import Optional

from fastapi import APIRouter, Header, HTTPException

import proxy
from core.history import save_scan
from core.router import PROVIDERS, detect_provider, forward_to_provider
from models.schemas import ChatRequest

router = APIRouter()


@router.post("/v1/chat/completions")
async def chat_completions(
    chat: ChatRequest,
    authorization: Optional[str] = Header(None),
    x_api_key: Optional[str] = Header(None),
):
    """
    Universal AI proxy: works with OpenAI, Anthropic, Gemini, Groq, Ollama.
    Just change base_url and use any model name from any provider.
    """
    api_key = x_api_key or authorization
    key_info, raw_key = proxy.verify_key(api_key)
    proxy.check_rate(raw_key, key_info["rate_per_min"])

    provider = detect_provider(chat.model)

    if provider == "openai" and not chat.model.lower().startswith("gpt-4"):
        provider = "groq"
        chat.model = "llama-3.3-70b-versatile"

    user_prompts = [m.content for m in chat.messages if m.role == "user"]
    for prompt in user_prompts:
        result = proxy.run_scan(prompt, raw_key, key_record=key_info)
        save_scan(raw_key, result, endpoint="/v1/chat/completions")
        if result.is_threat:
            proxy.trigger_all_alerts(result, raw_key, key_info)
            raise HTTPException(
                status_code=400,
                detail={
                    "error": "policy_violation",
                    "message": "Request blocked by Interlock.",
                    "threat_level": result.threat_level.value,
                    "threat_type": result.threat_type,
                    "reason": result.reason,
                    "confidence": result.confidence,
                    "layer_caught": result.layer_caught,
                    "scan_time_ms": result.scan_time_ms,
                    "provider": provider,
                    "safe_to_proceed": False,
                },
            )

    body = chat.model_dump(exclude_none=True)
    response = await forward_to_provider(provider, body)

    if isinstance(response, dict) and "error" not in response:
        response["firewall"] = {
            "status": "clean",
            "provider": provider,
            "scans": len(user_prompts),
            "model": chat.model,
        }

    return response


@router.get("/providers")
async def list_providers(x_api_key: Optional[str] = Header(None)):
    """List supported AI providers and their models."""
    proxy.verify_key(x_api_key)
    return {
        "providers": {
            name: {
                "model_prefixes": cfg["model_prefixes"],
                "format": cfg["format"],
                "configured": (
                    bool(os.getenv(cfg["key_env"])) if cfg["key_env"] else True
                ),
            }
            for name, cfg in PROVIDERS.items()
        },
        "auto_detection": "Provider is detected automatically from model name.",
    }
