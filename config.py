from dotenv import load_dotenv
import math
import os

load_dotenv()

GROQ_API_KEY = (os.getenv("GROQ_API_KEY") or "").strip() or None
GEMINI_API_KEY = (os.getenv("GEMINI_API_KEY") or "").strip() or None

# Groq model to use (fast + free)
GROQ_MODEL = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")

MCP_REGISTRY_ALLOWED_HOSTS = os.getenv("MCP_REGISTRY_ALLOWED_HOSTS", "")
MCP_REGISTRY_ALLOWED_HOST_SUFFIXES = os.getenv("MCP_REGISTRY_ALLOWED_HOST_SUFFIXES", "")


def mcp_upstream_auth_allowed_env_vars() -> set[str]:
    """
    Explicit allowlist of environment-variable NAMES an MCP server may
    reference for upstream auth tokens (comma-separated). Read at call time
    so registration-time and call-time validation both see the current
    value. Default deny: empty allowlist rejects every authenticated
    upstream configuration.
    """
    raw = os.getenv("MCP_UPSTREAM_AUTH_ALLOWED_ENV_VARS", "")
    return {name.strip() for name in raw.split(",") if name.strip()}


class ConfigurationError(RuntimeError):
    """An explicitly configured value is unusable. Never silently substituted."""


def _bounded_number(name: str, default, minimum, maximum, cast):
    """
    Read one operator-tunable limit at call time and validate it.

    Unset (or empty, which is how the local test harness neutralizes a
    ``.env``) means "use the documented default". A value that IS set but
    cannot be parsed, or falls outside the supported range, raises rather
    than quietly substituting a different limit: an operator who typed a
    number must never end up running under a limit they did not choose, and
    must never discover it only by reading an artifact.
    """
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    try:
        value = cast(raw.strip())
    except (TypeError, ValueError):
        raise ConfigurationError(
            f"{name} is set to an unparsable value. Set a number between "
            f"{minimum} and {maximum}, or unset it to use the default "
            f"({default})."
        )
    if isinstance(value, float) and not math.isfinite(value):
        raise ConfigurationError(
            f"{name} must be finite. Unset it to use the default ({default})."
        )
    if value < minimum or value > maximum:
        raise ConfigurationError(
            f"{name} is set to {value}, outside the supported range "
            f"{minimum}..{maximum}. Unset it to use the default ({default})."
        )
    return value


# Documented upper bounds for the CI boundary-review limits below. These are
# transport/size limits, not detection thresholds, and are reported in the
# gate artifact so a truncated or refused review is never mistaken for a pass.
BOUNDARY_REVIEW_TIMEOUT_DEFAULT_S = 10.0
BOUNDARY_REVIEW_TIMEOUT_MIN_S = 0.1
BOUNDARY_REVIEW_TIMEOUT_MAX_S = 120.0
BOUNDARY_REVIEW_MAX_RESPONSE_BYTES_DEFAULT = 2 * 1024 * 1024
BOUNDARY_REVIEW_MAX_RESPONSE_BYTES_MIN = 1024
BOUNDARY_REVIEW_MAX_RESPONSE_BYTES_CEILING = 20 * 1024 * 1024
BOUNDARY_REVIEW_MAX_TOOLS_DEFAULT = 200
BOUNDARY_REVIEW_MAX_TOOLS_MIN = 1
BOUNDARY_REVIEW_MAX_TOOLS_CEILING = 2000
BOUNDARY_REVIEW_MAX_FINDINGS_DEFAULT = 100
BOUNDARY_REVIEW_MAX_FINDINGS_MIN = 1
BOUNDARY_REVIEW_MAX_FINDINGS_CEILING = 1000
BOUNDARY_REVIEW_IDEMPOTENCY_TTL_DEFAULT_S = 24 * 3600
BOUNDARY_REVIEW_IDEMPOTENCY_TTL_MIN_S = 60
BOUNDARY_REVIEW_IDEMPOTENCY_TTL_CEILING_S = 7 * 24 * 3600
CI_BOUNDARY_REVIEW_MAX_REQUEST_BYTES_DEFAULT = 8 * 1024
CI_BOUNDARY_REVIEW_MAX_REQUEST_BYTES_MIN = 0
CI_BOUNDARY_REVIEW_MAX_REQUEST_BYTES_CEILING = 1024 * 1024


def boundary_review_timeout_seconds() -> float:
    """
    Upstream timeout, in seconds, for the read-only observation a CI
    boundary review performs. Read at call time so an operator can tune it
    per deployment without a restart.
    """
    return _bounded_number(
        "INTERLOCK_BOUNDARY_REVIEW_TIMEOUT_S",
        BOUNDARY_REVIEW_TIMEOUT_DEFAULT_S,
        BOUNDARY_REVIEW_TIMEOUT_MIN_S,
        BOUNDARY_REVIEW_TIMEOUT_MAX_S,
        float,
    )


def boundary_review_max_response_bytes() -> int:
    """Hard cap on the upstream tools/list body one review will read."""
    return _bounded_number(
        "INTERLOCK_BOUNDARY_REVIEW_MAX_RESPONSE_BYTES",
        BOUNDARY_REVIEW_MAX_RESPONSE_BYTES_DEFAULT,
        BOUNDARY_REVIEW_MAX_RESPONSE_BYTES_MIN,
        BOUNDARY_REVIEW_MAX_RESPONSE_BYTES_CEILING,
        int,
    )


def boundary_review_max_tools() -> int:
    """Hard cap on the observed tool count a review will classify."""
    return _bounded_number(
        "INTERLOCK_BOUNDARY_REVIEW_MAX_TOOLS",
        BOUNDARY_REVIEW_MAX_TOOLS_DEFAULT,
        BOUNDARY_REVIEW_MAX_TOOLS_MIN,
        BOUNDARY_REVIEW_MAX_TOOLS_CEILING,
        int,
    )


def boundary_review_max_findings() -> int:
    """Hard cap on findings plus review-queue entries in one artifact."""
    return _bounded_number(
        "INTERLOCK_BOUNDARY_REVIEW_MAX_FINDINGS",
        BOUNDARY_REVIEW_MAX_FINDINGS_DEFAULT,
        BOUNDARY_REVIEW_MAX_FINDINGS_MIN,
        BOUNDARY_REVIEW_MAX_FINDINGS_CEILING,
        int,
    )


def boundary_review_idempotency_ttl_seconds() -> int:
    """How long a completed boundary review stays replayable by its key."""
    return _bounded_number(
        "INTERLOCK_BOUNDARY_REVIEW_IDEMPOTENCY_TTL_S",
        BOUNDARY_REVIEW_IDEMPOTENCY_TTL_DEFAULT_S,
        BOUNDARY_REVIEW_IDEMPOTENCY_TTL_MIN_S,
        BOUNDARY_REVIEW_IDEMPOTENCY_TTL_CEILING_S,
        int,
    )


def ci_boundary_review_max_request_bytes() -> int:
    """
    Hard cap on the boundary-review POST body.

    The route ignores the body entirely — nothing in it can influence the
    server, baseline, reviewer, decision, or evidence — so the default is
    deliberately small. It exists only so an authenticated caller cannot push
    unbounded volume through the endpoint.
    """
    return _bounded_number(
        "INTERLOCK_CI_BOUNDARY_REVIEW_MAX_REQUEST_BYTES",
        CI_BOUNDARY_REVIEW_MAX_REQUEST_BYTES_DEFAULT,
        CI_BOUNDARY_REVIEW_MAX_REQUEST_BYTES_MIN,
        CI_BOUNDARY_REVIEW_MAX_REQUEST_BYTES_CEILING,
        int,
    )


def assert_boundary_review_config_valid() -> None:
    """
    Validate every boundary-review limit at startup.

    Called before any database or network work so a misconfigured deployment
    refuses to start instead of discovering the problem mid-review.
    """
    boundary_review_timeout_seconds()
    boundary_review_max_response_bytes()
    boundary_review_max_tools()
    boundary_review_max_findings()
    boundary_review_idempotency_ttl_seconds()
    ci_boundary_review_max_request_bytes()


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


def is_hosted() -> bool:
    """Return True when a supported hosting platform marker is present."""
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


def is_production() -> bool:
    """Best-effort production detection while keeping local dev convenient."""
    env = interlock_env()
    if env in {"prod", "production"}:
        return True
    if env in {"dev", "development", "local", "test", "testing"}:
        return False
    return is_hosted()


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


def assert_offline_demo_startup_safe() -> None:
    """Refuse the fixed-key offline demo on production or hosted deployments."""
    if offline_demo_enabled() and (is_production() or is_hosted()):
        raise RuntimeError(
            "INTERLOCK_OFFLINE_DEMO cannot be enabled in production or hosted "
            "deployments."
        )


def siem_include_content() -> bool:
    """Opt in to exporting bounded prompt/reason previews to alert destinations."""
    return _truthy(os.getenv("SIEM_INCLUDE_CONTENT"))


_EXPERIMENTAL_EMA_ENV_NAMES = (
    "INTERLOCK_EXPERIMENTAL_EMA_ENABLED",
    "INTERLOCK_EMA_RESOURCE_URI",
    "INTERLOCK_EMA_ISSUER_METADATA",
    "INTERLOCK_EMA_SERVER_ID",
    "INTERLOCK_EMA_SERVICE_PRINCIPAL_ID",
    "INTERLOCK_EMA_DOWNSTREAM_SERVICE_PRINCIPAL_ID",
    "INTERLOCK_EMA_ROLE",
    "INTERLOCK_EMA_ALLOWED_CLIENT_IDS",
    "INTERLOCK_EMA_TOOL_SCOPES",
    "INTERLOCK_EMA_ALLOWED_ORIGINS",
    "INTERLOCK_EMA_OAUTH_CLIENT_HMAC_KEYS",
    "INTERLOCK_EMA_DELEGATED_SUBJECT_HMAC_KEYS",
    "INTERLOCK_EMA_TOKEN_HMAC_KEYS",
    "INTERLOCK_EMA_REQUIRE_NBF",
    "INTERLOCK_EMA_REQUIRE_IAT",
    "INTERLOCK_EMA_MAX_TOKEN_AGE_SECONDS",
    "INTERLOCK_EMA_SESSION_LIFETIME_SECONDS",
    "INTERLOCK_EMA_JSON_RPC_BODY_MAX_BYTES",
    "INTERLOCK_EMA_UNAUTHENTICATED_RATE_LIMIT",
    "INTERLOCK_EMA_AUTHENTICATED_RATE_LIMIT",
    "INTERLOCK_EMA_RATE_LIMIT_WINDOW_SECONDS",
    "INTERLOCK_EMA_RATE_LIMIT_MAX_KEYS",
    "INTERLOCK_EMA_JWKS_REFRESH_COOLDOWN_SECONDS",
    "INTERLOCK_EMA_JWKS_NEGATIVE_CACHE_TTL_SECONDS",
    "INTERLOCK_EMA_JWKS_NEGATIVE_CACHE_MAX_ENTRIES",
)


def experimental_ema_raw_config() -> dict[str, str]:
    """Return the complete opt-in EMA environment surface at call time."""
    return {name: os.getenv(name, "") for name in _EXPERIMENTAL_EMA_ENV_NAMES}
