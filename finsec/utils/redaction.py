"""Secret redaction for HAR structures and normalized observations."""

import json
import re
from typing import Any
from urllib.parse import SplitResult, parse_qsl, quote, urlencode, urlsplit, urlunsplit

REDACTED = "[REDACTED]"

SENSITIVE_NAME = re.compile(
    r"(?:^|[-_])(?:authorization|proxy-authorization|cookie|set-cookie|password|passwd|"
    r"secret|otp|csrf|xsrf|api[-_]?key|access[-_]?token|refresh[-_]?token|id[-_]?token|"
    r"jwt|session(?:id)?|token)(?:$|[-_])",
    re.IGNORECASE,
)
JWT_PATTERN = re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b")
BEARER_PATTERN = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+")
SENSITIVE_PAIR_PATTERN = re.compile(
    r"(?i)(authorization|cookie|set-cookie|password|passwd|secret|otp|csrf|xsrf|"
    r"api[-_]?key|access[-_]?token|refresh[-_]?token|jwt|token)"
    r"(\s*[:=]\s*)([^\s,;}&]+)"
)
SENSITIVE_HEADER_LINE_PATTERN = re.compile(
    r"(?im)^(\s*(?:authorization|proxy-authorization|cookie|set-cookie|"
    r"x-api-key|api-key|x-csrf-token|csrf-token)\s*:\s*).*$"
)
SENSITIVE_CODE_NAME = re.compile(r"(?:^|[-_])(?:code|pin)(?:$|[-_])", re.IGNORECASE)
NUMERIC_CODE_PATTERN = re.compile(r"\d{4,10}")


def is_sensitive_name(name: str) -> bool:
    """Return whether a field or header name commonly contains a credential."""

    normalized = name.strip().replace(" ", "-")
    return bool(SENSITIVE_NAME.search(normalized))


def redact_named_value(name: str, value: str) -> str:
    """Redact a value based on its field name, then scrub token-like text."""

    if is_sensitive_name(name):
        return REDACTED
    return redact_text(value)


def _safe_urlsplit(value: str) -> SplitResult | None:
    """Treat malformed URL-like text as ordinary text instead of aborting redaction."""

    try:
        return urlsplit(value)
    except ValueError:
        return None


def redact_text(value: str) -> str:
    """Redact high-confidence secrets embedded in a string."""

    stripped = value.strip()
    if stripped.startswith(("{", "[")):
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError:
            pass
        else:
            return json.dumps(redact_data(parsed), separators=(",", ":"))

    if "://" in value:
        parsed_url = _safe_urlsplit(value)
        if parsed_url is not None and (parsed_url.username or parsed_url.password):
            host = parsed_url.hostname or ""
            if ":" in host and not host.startswith("["):
                host = f"[{host}]"
            try:
                parsed_port = parsed_url.port
            except ValueError:
                parsed_port = None
            port = f":{parsed_port}" if parsed_port is not None else ""
            value = urlunsplit(
                (
                    parsed_url.scheme,
                    f"{quote(REDACTED, safe='')}@{host}{port}",
                    parsed_url.path,
                    parsed_url.query,
                    parsed_url.fragment,
                )
            )
            parsed_url = _safe_urlsplit(value)
        if parsed_url is not None:
            query_pairs = parse_qsl(parsed_url.query, keep_blank_values=True)
            if query_pairs and any(is_sensitive_name(name) for name, _ in query_pairs):
                query = urlencode(
                    [(name, redact_named_value(name, item)) for name, item in query_pairs]
                )
                value = urlunsplit(
                    (
                        parsed_url.scheme,
                        parsed_url.netloc,
                        parsed_url.path,
                        query,
                        parsed_url.fragment,
                    )
                )

    if "://" not in value and "=" in value and not re.search(r"\s", value):
        pairs = parse_qsl(value, keep_blank_values=True)
        if pairs and any(is_sensitive_name(name) for name, _ in pairs):
            return urlencode([(name, redact_named_value(name, item)) for name, item in pairs])

    redacted = SENSITIVE_HEADER_LINE_PATTERN.sub(lambda match: f"{match.group(1)}{REDACTED}", value)
    redacted = JWT_PATTERN.sub(REDACTED, redacted)
    redacted = BEARER_PATTERN.sub(f"Bearer {REDACTED}", redacted)
    return SENSITIVE_PAIR_PATTERN.sub(
        lambda match: f"{match.group(1)}{match.group(2)}{REDACTED}", redacted
    )


def redact_data(value: Any) -> Any:
    """Recursively redact common HAR name/value objects and sensitive keys."""

    if isinstance(value, dict):
        result: dict[str, Any] = {}
        named_secret = isinstance(value.get("name"), str) and is_sensitive_name(value["name"])
        for key, item in value.items():
            numeric_code = (
                isinstance(item, str)
                and SENSITIVE_CODE_NAME.search(str(key))
                and NUMERIC_CODE_PATTERN.fullmatch(item)
            )
            if (key == "value" and named_secret) or is_sensitive_name(str(key)) or numeric_code:
                result[key] = REDACTED
            else:
                result[key] = redact_data(item)
        return result
    if isinstance(value, list):
        return [redact_data(item) for item in value]
    if isinstance(value, str):
        return redact_text(value)
    return value
