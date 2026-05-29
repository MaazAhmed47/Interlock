import re
from typing import Any

_SECRET_PATTERN = re.compile(
    r"(api[_\-]?key|x[_\-]api[_\-]key|token|secret|password|credential|database[_\-]?url|jwt)",
    re.IGNORECASE,
)


def scrub_secrets(data: Any) -> Any:
    if isinstance(data, dict):
        return {
            k: "***" if _SECRET_PATTERN.search(str(k)) else scrub_secrets(v)
            for k, v in data.items()
        }
    if isinstance(data, list):
        return [scrub_secrets(item) for item in data]
    return data
