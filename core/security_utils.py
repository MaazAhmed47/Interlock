import re
from typing import Any

_SECRET_PATTERN = re.compile(
    r"""
    (?:^|[_\-\.])    # start of string OR preceded by separator
    (?:
        api[_\-]?key          # api_key, apikey, api-key
        | x[_\-]api[_\-]?key  # x-api-key, x_api_key
        | private[_\-]?key    # private_key, private-key, rsa_private_key
        | access[_\-]?key     # access_key, aws access key
        | signing[_\-]?key    # signing_key
        | secret              # secret, jwt_secret, client_secret
        | password            # password, db_password
        | credential          # credential
        | database[_\-]?url   # database_url, database-url
        | db[_\-]?url         # db_url
        | mongo[_\-]?uri      # mongo_uri
        | redis[_\-]?url      # redis_url
        | dsn                 # dsn (data source name)
        | connection[_\-]?str(?:ing)?  # connection_string
        | jwt                 # jwt
        | bearer              # bearer
        | authorization       # authorization
        | auth[_\-]token      # auth_token specifically (not plain "auth")
        | access[_\-]token    # access_token
        | refresh[_\-]token   # refresh_token
        | id[_\-]token        # id_token
        | api[_\-]token       # api_token
    )
    (?:$|[_\-\.])    # end of string OR followed by separator
    """,
    re.IGNORECASE | re.VERBOSE,
)

# Exact-match for bare standalone keys (e.g. {"token": ...}, {"jwt": ...})
_SECRET_EXACT = re.compile(
    r"^(?:token|jwt|secret|password|credential|bearer|authorization|auth)$",
    re.IGNORECASE,
)

_MAX_DEPTH = 50


def _is_secret_key(key: str) -> bool:
    s = str(key)
    return bool(_SECRET_PATTERN.search(s) or _SECRET_EXACT.fullmatch(s))


def scrub_secrets(data: Any, _depth: int = 0) -> Any:
    if _depth >= _MAX_DEPTH:
        return data  # stop recursing, return as-is
    if isinstance(data, dict):
        return {
            k: "***" if _is_secret_key(k) else scrub_secrets(v, _depth + 1)
            for k, v in data.items()
        }
    if isinstance(data, list):
        return [scrub_secrets(item, _depth + 1) for item in data]
    return data
