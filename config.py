from dotenv import load_dotenv
import os

load_dotenv()

GROQ_API_KEY = (os.getenv("GROQ_API_KEY") or "").strip() or None
GEMINI_API_KEY = (os.getenv("GEMINI_API_KEY") or "").strip() or None

# Groq model to use (fast + free)
GROQ_MODEL = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")

# Threat levels
THREAT_LEVELS = {"SAFE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def _truthy(value: str | None) -> bool:
    return (value or "").strip().lower() in {"1", "true", "yes", "on"}


def interlock_env() -> str:
    """Return the configured runtime environment name."""
    return (
        (
            os.getenv("INTERLOCK_ENV")
            or os.getenv("APP_ENV")
            or os.getenv("ENVIRONMENT")
            or os.getenv("ENV")
            or ""
        )
        .strip()
        .lower()
    )


def is_production() -> bool:
    """Best-effort production detection while keeping local dev convenient."""
    env = interlock_env()
    if env in {"prod", "production"}:
        return True
    if env in {"dev", "development", "local", "test", "testing"}:
        return False
    return any(
        os.getenv(name)
        for name in (
            "RENDER",
            "VERCEL",
            "RAILWAY_ENVIRONMENT",
            "FLY_APP_NAME",
            "K_SERVICE",
        )
    )


def api_docs_enabled() -> bool:
    """Expose FastAPI docs by default only outside production."""
    raw = os.getenv("ENABLE_API_DOCS")
    if raw is not None:
        return _truthy(raw)
    return not is_production()


def cors_allowed_origins() -> list[str]:
    """Return CORS origins and fail closed on unsafe production config."""
    raw = os.getenv("ALLOWED_ORIGINS", "").strip()
    if not raw:
        if is_production():
            raise RuntimeError(
                "Production Interlock requires explicit ALLOWED_ORIGINS. "
                "Set ALLOWED_ORIGINS to your dashboard origin(s); '*' is not allowed."
            )
        return ["*"]

    origins = [origin.strip() for origin in raw.split(",") if origin.strip()]
    if is_production() and (not origins or "*" in origins):
        raise RuntimeError(
            "Production Interlock cannot use ALLOWED_ORIGINS='*'. "
            "Set explicit dashboard origin(s)."
        )
    return origins or ["*"]


def protect_outbound_urls() -> bool:
    """Enable SSRF-oriented outbound URL validation."""
    raw = os.getenv("INTERLOCK_PROTECT_OUTBOUND_URLS")
    if raw is not None:
        return _truthy(raw)
    return is_production()


def allow_private_outbound_urls() -> bool:
    """Emergency/local override for private outbound URLs."""
    return _truthy(os.getenv("INTERLOCK_ALLOW_PRIVATE_OUTBOUND"))


def offline_demo_enabled() -> bool:
    """
    Opt-in for the bundled docker-compose demo (demo/offline/). Seeds a fixed,
    clearly-labeled demo API key at startup. Never enable on hosted or
    production deployments.
    """
    return _truthy(os.getenv("INTERLOCK_OFFLINE_DEMO"))
