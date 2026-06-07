"""Small request limit helpers for public API routes."""


def clamp_limit(value: int | None, *, default: int, maximum: int) -> int:
    try:
        limit = int(value if value is not None else default)
    except (TypeError, ValueError):
        limit = default
    if limit < 1:
        return 1
    return min(limit, maximum)
