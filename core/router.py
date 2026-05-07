import os
import httpx
from typing import Optional

# ── Provider configurations ──────────────────────────────────────────────────
PROVIDERS = {
    "openai": {
        "url": "https://api.openai.com/v1/chat/completions",
        "auth_header": "Authorization",
        "auth_prefix": "Bearer ",
        "key_env": "OPENAI_API_KEY",
        "model_prefixes": ["gpt-", "o1-", "o3-", "o4-", "chatgpt-"],
        "format": "openai",
    },
    "anthropic": {
        "url": "https://api.anthropic.com/v1/messages",
        "auth_header": "x-api-key",
        "auth_prefix": "",
        "key_env": "ANTHROPIC_API_KEY",
        "model_prefixes": ["claude-"],
        "format": "anthropic",
        "extra_headers": {"anthropic-version": "2023-06-01"},
    },
    "google": {
        "url": "https://generativelanguage.googleapis.com/v1beta/models",
        "auth_header": None,  # Google uses query param
        "auth_prefix": "",
        "key_env": "GOOGLE_API_KEY",
        "model_prefixes": ["gemini-"],
        "format": "google",
    },
    "groq": {
        "url": "https://api.groq.com/openai/v1/chat/completions",
        "auth_header": "Authorization",
        "auth_prefix": "Bearer ",
        "key_env": "GROQ_API_KEY",
        "model_prefixes": ["llama", "mixtral", "groq/"],
        "format": "openai",  # Groq is OpenAI-compatible
    },
    "ollama": {
        "url": "http://localhost:11434/api/chat",
        "auth_header": None,
        "auth_prefix": "",
        "key_env": None,
        "model_prefixes": ["local:", "ollama:"],
        "format": "ollama",
    },
}

# ── Model detection ──────────────────────────────────────────────────────────
def detect_provider(model: str) -> str:
    """Auto-detect provider from model name."""
    model_lower = model.lower()
    for provider_name, config in PROVIDERS.items():
        for prefix in config["model_prefixes"]:
            if model_lower.startswith(prefix):
                return provider_name
    return "openai"  # Default

def get_provider_config(provider: str) -> Optional[dict]:
    return PROVIDERS.get(provider)

# ── Format converters ────────────────────────────────────────────────────────
def to_anthropic_format(openai_body: dict) -> dict:
    """Convert OpenAI request to Anthropic format."""
    messages = openai_body.get("messages", [])
    system_msg = ""
    converted = []

    for msg in messages:
        if msg["role"] == "system":
            system_msg = msg["content"]
        else:
            converted.append({"role": msg["role"], "content": msg["content"]})

    body = {
        "model": openai_body.get("model"),
        "messages": converted,
        "max_tokens": openai_body.get("max_tokens", 4096),
    }
    if system_msg:
        body["system"] = system_msg
    if openai_body.get("temperature") is not None:
        body["temperature"] = openai_body["temperature"]
    if openai_body.get("stream"):
        body["stream"] = True
    return body

def from_anthropic_response(anthropic_resp: dict) -> dict:
    """Convert Anthropic response back to OpenAI format."""
    content = ""
    if "content" in anthropic_resp and isinstance(anthropic_resp["content"], list):
        for block in anthropic_resp["content"]:
            if block.get("type") == "text":
                content += block.get("text", "")

    return {
        "id": anthropic_resp.get("id", "fw-anthropic"),
        "object": "chat.completion",
        "model": anthropic_resp.get("model"),
        "choices": [{
            "message": {"role": "assistant", "content": content},
            "finish_reason": anthropic_resp.get("stop_reason", "stop"),
            "index": 0,
        }],
        "usage": anthropic_resp.get("usage", {}),
    }

def to_google_format(openai_body: dict) -> dict:
    """Convert OpenAI request to Google Gemini format."""
    contents = []
    for msg in openai_body.get("messages", []):
        if msg["role"] == "system":
            contents.append({"role": "user", "parts": [{"text": f"[System]: {msg['content']}"}]})
        else:
            role = "model" if msg["role"] == "assistant" else "user"
            contents.append({"role": role, "parts": [{"text": msg["content"]}]})

    body = {"contents": contents}
    if openai_body.get("temperature") is not None:
        body["generationConfig"] = {"temperature": openai_body["temperature"]}
    return body

def from_google_response(google_resp: dict) -> dict:
    """Convert Google response to OpenAI format."""
    content = ""
    candidates = google_resp.get("candidates", [])
    if candidates:
        parts = candidates[0].get("content", {}).get("parts", [])
        for part in parts:
            content += part.get("text", "")

    return {
        "id": "fw-google",
        "object": "chat.completion",
        "model": google_resp.get("modelVersion", "gemini"),
        "choices": [{
            "message": {"role": "assistant", "content": content},
            "finish_reason": "stop",
            "index": 0,
        }],
    }

def to_ollama_format(openai_body: dict) -> dict:
    """Convert to Ollama format."""
    model = openai_body.get("model", "").replace("local:", "").replace("ollama:", "")
    return {
        "model": model,
        "messages": openai_body.get("messages", []),
        "stream": openai_body.get("stream", False),
    }

def from_ollama_response(ollama_resp: dict) -> dict:
    """Convert Ollama response to OpenAI format."""
    return {
        "id": "fw-ollama",
        "object": "chat.completion",
        "model": ollama_resp.get("model"),
        "choices": [{
            "message": ollama_resp.get("message", {"role": "assistant", "content": ""}),
            "finish_reason": "stop",
            "index": 0,
        }],
    }

# ── Universal forwarder ──────────────────────────────────────────────────────
async def forward_to_provider(
    provider: str,
    openai_body: dict,
    api_key: Optional[str] = None
) -> dict:
    """
    Forward request to detected provider.
    Returns OpenAI-format response regardless of provider.
    """
    config = PROVIDERS.get(provider)
    if not config:
        return {"error": f"Unknown provider: {provider}"}

    # Get API key
    if not api_key and config["key_env"]:
        api_key = os.getenv(config["key_env"])

    if not api_key and config["key_env"]:
        return {
            "id": f"fw-{provider}-no-key",
            "object": "chat.completion",
            "model": openai_body.get("model"),
            "choices": [{
                "message": {
                    "role": "assistant",
                    "content": f"[LLM Firewall] Prompt scanned ✓ safe. Add {config['key_env']} to .env to forward to {provider}."
                },
                "finish_reason": "stop",
                "index": 0,
            }],
            "firewall": {"status": "clean", "provider": provider, "note": "no_upstream_key"}
        }

    # Build request
    headers = {"Content-Type": "application/json"}
    if config.get("auth_header"):
        headers[config["auth_header"]] = config["auth_prefix"] + (api_key or "")
    if config.get("extra_headers"):
        headers.update(config["extra_headers"])

    # Convert body to provider format
    if config["format"] == "anthropic":
        body = to_anthropic_format(openai_body)
    elif config["format"] == "google":
        body = to_google_format(openai_body)
    elif config["format"] == "ollama":
        body = to_ollama_format(openai_body)
    else:
        body = openai_body

    # Build URL (Google needs special handling)
    url = config["url"]
    if provider == "google":
        model = openai_body.get("model", "gemini-pro")
        url = f"{url}/{model}:generateContent?key={api_key}"

    # Make request
    try:
        async with httpx.AsyncClient(timeout=120.0) as client:
            resp = await client.post(url, json=body, headers=headers)
            data = resp.json()

            # Convert response back to OpenAI format
            if config["format"] == "anthropic":
                return from_anthropic_response(data)
            elif config["format"] == "google":
                return from_google_response(data)
            elif config["format"] == "ollama":
                return from_ollama_response(data)
            else:
                return data
    except Exception as e:
        return {
            "error": "upstream_error",
            "provider": provider,
            "message": str(e),
        }