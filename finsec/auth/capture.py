"""Detect replay authentication from authorized HAR and raw-request captures."""

from __future__ import annotations

import base64
import hashlib
import json
from contextlib import suppress
from dataclasses import dataclass, field
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any, Literal, cast
from urllib.parse import parse_qsl, urlsplit

from finsec.config.models import (
    AuthenticationBaselineConfig,
    AuthenticationExpirationConfig,
    AuthenticationIdentityConfig,
)
from finsec.errors import FinsecError, HarFormatError
from finsec.ingest.common import parse_raw_http
from finsec.ingest.har_io import load_har_json
from finsec.ingest.traffic import load_burp_xml
from finsec.utils.redaction import is_sensitive_name

API_KEY_HEADERS = {"x-api-key", "api-key", "apikey", "x-client-secret"}
CSRF_NAMES = {"x-csrf-token", "x-xsrf-token", "csrf-token", "x-request-verification-token"}
SAFE_HEADERS = {"accept", "content-type", "accept-language"}


@dataclass(frozen=True, repr=False)
class CapturedSecret:
    """One in-memory credential component; repr intentionally omits its value."""

    name: str
    value: str = field(repr=False)
    purpose: str
    location: str = "header"
    value_prefix: str = ""
    cookie_domain: str | None = None
    cookie_path: str | None = None
    cookie_session_only: bool | None = None


@dataclass(frozen=True, repr=False)
class AuthenticationCandidate:
    """A complete observed replay profile from one request."""

    auth_type: str
    components: tuple[CapturedSecret, ...] = field(repr=False)
    expiration: AuthenticationExpirationConfig
    identity: AuthenticationIdentityConfig
    baseline: AuthenticationBaselineConfig | None
    captured_at: datetime | None
    source_index: int
    observed_host: str | None = None
    source_label: str = "HAR entry"

    def redacted_summary(self) -> str:
        names = ", ".join(item.name for item in self.components)
        details = [f"{self.source_label} {self.source_index + 1}"]
        if self.baseline is not None:
            details.insert(
                0,
                f"{self.baseline.method} {self.baseline.host}{self.baseline.path}",
            )
        elif self.observed_host is not None:
            details.insert(0, self.observed_host)
        if self.captured_at is not None:
            details.append(self.captured_at.isoformat())
        return f"{self.auth_type}: {names or 'no replay components'} | " + " | ".join(details)


def _b64url_json(value: str) -> dict[str, Any] | None:
    try:
        padded = value + "=" * (-len(value) % 4)
        decoded = base64.urlsafe_b64decode(padded.encode())
        document = json.loads(decoded.decode("utf-8"))
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    return document if isinstance(document, dict) else None


def decode_jwt_metadata(
    token: str, *, checked_at: datetime | None = None
) -> tuple[AuthenticationExpirationConfig, AuthenticationIdentityConfig]:
    """Read untrusted JWT lifetime and identity hints without retaining or verifying the token."""

    now = checked_at or datetime.now(UTC)
    parts = token.split(".")
    payload = _b64url_json(parts[1]) if len(parts) == 3 else None
    if payload is None:
        return (
            AuthenticationExpirationConfig(last_checked_at=now, source="unknown"),
            AuthenticationIdentityConfig(),
        )

    def instant(name: str) -> datetime | None:
        value = payload.get(name)
        if not isinstance(value, int | float):
            return None
        try:
            return datetime.fromtimestamp(float(value), tz=UTC)
        except (OverflowError, OSError, ValueError):
            return None

    roles_value = payload.get("roles", payload.get("role", []))
    if isinstance(roles_value, str):
        roles = [roles_value]
    elif isinstance(roles_value, list):
        roles = [str(item) for item in roles_value if isinstance(item, str | int)]
    else:
        roles = []
    subject = payload.get("sub")
    tenant = payload.get("tenant", payload.get("tenant_id", payload.get("tid")))
    expires_at = instant("exp")
    return (
        AuthenticationExpirationConfig(
            detectable=expires_at is not None,
            expires_at=expires_at,
            issued_at=instant("iat"),
            not_before=instant("nbf"),
            last_checked_at=now,
            source="jwt" if expires_at is not None else "unknown",
        ),
        AuthenticationIdentityConfig(
            subject=str(subject) if isinstance(subject, str | int) else None,
            roles=sorted(set(roles)),
            tenant=str(tenant) if isinstance(tenant, str | int) else None,
        ),
    )


def _headers(items: Any) -> list[tuple[str, str]]:
    if not isinstance(items, list):
        return []
    return [
        (str(item["name"]), str(item.get("value", "")))
        for item in items
        if isinstance(item, dict) and isinstance(item.get("name"), str)
    ]


def _cookie_expiration(
    cookies: Any, captured_at: datetime | None
) -> AuthenticationExpirationConfig:
    expirations: list[datetime] = []
    if isinstance(cookies, list):
        for cookie in cookies:
            if not isinstance(cookie, dict):
                continue
            raw = cookie.get("expires")
            if isinstance(raw, str) and raw:
                try:
                    parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
                except ValueError:
                    try:
                        parsed = parsedate_to_datetime(raw)
                    except (TypeError, ValueError):
                        continue
                expirations.append(parsed.astimezone(UTC))
    return AuthenticationExpirationConfig(
        detectable=bool(expirations),
        expires_at=min(expirations) if expirations else None,
        last_checked_at=captured_at or datetime.now(UTC),
        source="cookie" if expirations else "unknown",
    )


def _auth_type(components: list[CapturedSecret]) -> str:
    names = {item.name.lower() for item in components}
    authorization = next(
        (item.value for item in components if item.name.lower() == "authorization"), ""
    )
    primary = [item for item in components if item.purpose not in {"csrf"}]
    if len(primary) > 1:
        return "mixed"
    if authorization.lower().startswith("bearer "):
        token = authorization.split(None, 1)[1]
        return "bearer_jwt" if len(token.split(".")) == 3 else "bearer"
    if authorization.lower().startswith("basic "):
        return "basic"
    if "cookie" in names:
        return "cookie"
    if names & API_KEY_HEADERS:
        return "api_key"
    return "custom_header"


def _baseline(
    request: dict[str, Any], response: dict[str, Any]
) -> AuthenticationBaselineConfig | None:
    method = str(request.get("method", "")).upper()
    url = request.get("url")
    status = response.get("status")
    if method not in {"GET", "HEAD"} or not isinstance(url, str):
        return None
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or parsed.hostname is None:
        return None
    raw_headers = _headers(request.get("headers"))
    safe_headers = {name: value for name, value in raw_headers if name.lower() in SAFE_HEADERS}
    response_headers = {name.lower(): value for name, value in _headers(response.get("headers"))}
    query: dict[str, list[str]] = {}
    for name, value in parse_qsl(parsed.query, keep_blank_values=True):
        if is_sensitive_name(name):
            return None
        query.setdefault(name, []).append(value)
    try:
        port = parsed.port
    except ValueError:
        port = None
    return AuthenticationBaselineConfig(
        method=cast(Literal["GET", "HEAD"], method),
        scheme=cast(Literal["http", "https"], parsed.scheme),
        host=parsed.hostname.lower(),
        port=port,
        path=parsed.path or "/",
        query_parameters=query,
        safe_headers=safe_headers,
        expected_status=int(status) if isinstance(status, int) else None,
        expected_content_type=response_headers.get("content-type"),
    )


def _request_components(request: dict[str, Any]) -> list[CapturedSecret]:
    result: list[CapturedSecret] = []
    headers = _headers(request.get("headers"))
    has_primary = False
    for name, value in headers:
        normalized = name.lower().strip()
        if normalized == "authorization":
            purpose = "access"
            has_primary = True
        elif normalized == "cookie":
            purpose = "session"
            has_primary = True
        elif normalized in API_KEY_HEADERS:
            purpose = "api_key"
            has_primary = True
        elif normalized in CSRF_NAMES or "csrf" in normalized or "xsrf" in normalized:
            purpose = "csrf"
        elif is_sensitive_name(normalized) and any(
            marker in normalized for marker in ("auth", "token", "key", "session")
        ):
            purpose = "other"
            has_primary = True
        else:
            continue
        if value and not any(character in value for character in ("\r", "\n", "\0")):
            result.append(CapturedSecret(name=name, value=value, purpose=purpose))
    cookies = request.get("cookies")
    if isinstance(cookies, list):
        pairs = [
            f"{item['name']}={item.get('value', '')}"
            for item in cookies
            if isinstance(item, dict) and isinstance(item.get("name"), str) and item.get("value")
        ]
        domains = {
            str(item["domain"])
            for item in cookies
            if isinstance(item, dict) and isinstance(item.get("domain"), str)
        }
        paths = {
            str(item["path"])
            for item in cookies
            if isinstance(item, dict) and isinstance(item.get("path"), str)
        }
        session_only = all(
            not isinstance(item, dict) or not item.get("expires") for item in cookies
        )
        cookie_domain = next(iter(domains)) if len(domains) == 1 else None
        cookie_path = next(iter(paths)) if len(paths) == 1 else None
        for index, component in enumerate(result):
            if component.name.lower() == "cookie":
                result[index] = CapturedSecret(
                    name=component.name,
                    value=component.value,
                    purpose=component.purpose,
                    location="cookie",
                    cookie_domain=cookie_domain,
                    cookie_path=cookie_path,
                    cookie_session_only=session_only,
                )
        if not any(item.name.lower() == "cookie" for item in result) and pairs:
            result.append(
                CapturedSecret(
                    name="Cookie",
                    value="; ".join(pairs),
                    purpose="session",
                    location="cookie",
                    cookie_domain=cookie_domain,
                    cookie_path=cookie_path,
                    cookie_session_only=session_only,
                )
            )
            has_primary = True
    return result if has_primary else []


def detect_har_authentication(har_path: Path) -> list[AuthenticationCandidate]:
    """Return distinct complete authentication contexts without persisting secrets."""

    _source, _raw, document = load_har_json(har_path)
    log = document.get("log") if isinstance(document, dict) else None
    entries = log.get("entries") if isinstance(log, dict) else None
    if not isinstance(entries, list):
        raise HarFormatError("HAR must contain a log.entries array.")
    candidates: list[AuthenticationCandidate] = []
    seen: set[str] = set()
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            continue
        request = entry.get("request")
        response = entry.get("response")
        if not isinstance(request, dict) or not isinstance(response, dict):
            continue
        components = _request_components(request)
        if not components:
            continue
        signature = hashlib.sha256(
            "\0".join(f"{item.name.lower()}\0{item.value}" for item in components).encode()
        ).hexdigest()
        if signature in seen:
            continue
        seen.add(signature)
        captured_at: datetime | None = None
        timestamp = entry.get("startedDateTime")
        if isinstance(timestamp, str):
            with suppress(ValueError):
                captured_at = datetime.fromisoformat(timestamp.replace("Z", "+00:00")).astimezone(
                    UTC
                )
        expiration = _cookie_expiration(request.get("cookies"), captured_at)
        identity = AuthenticationIdentityConfig()
        authorization = next(
            (item.value for item in components if item.name.lower() == "authorization"), None
        )
        if authorization and authorization.lower().startswith("bearer "):
            jwt_expiration, identity = decode_jwt_metadata(
                authorization.split(None, 1)[1], checked_at=datetime.now(UTC)
            )
            if jwt_expiration.detectable:
                expiration = jwt_expiration
        parsed_request_url = urlsplit(str(request.get("url", "")))
        observed_host = (
            parsed_request_url.hostname.lower() if parsed_request_url.hostname is not None else None
        )
        candidates.append(
            AuthenticationCandidate(
                auth_type=_auth_type(components),
                components=tuple(components),
                expiration=expiration,
                identity=identity,
                baseline=_baseline(request, response),
                captured_at=captured_at,
                source_index=index,
                observed_host=observed_host,
            )
        )
    return candidates


def _burp_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    with suppress(ValueError):
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return (parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)).astimezone(UTC)
    with suppress(TypeError, ValueError):
        parsed = parsedate_to_datetime(value)
        return (parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)).astimezone(UTC)
    return None


def detect_burp_authentication(xml_path: Path) -> list[AuthenticationCandidate]:
    """Return distinct replay contexts from a validated Burp XML history export."""

    document = load_burp_xml(xml_path)
    candidates: list[AuthenticationCandidate] = []
    seen: set[str] = set()
    for exchange in document.exchanges:
        _request_line, request_headers, _request_body = parse_raw_http(exchange.request_text)
        _response_line, response_headers, _response_body = parse_raw_http(exchange.response_text)
        request = {
            "method": exchange.method,
            "url": exchange.url,
            "headers": [{"name": name, "value": value} for name, value in request_headers.items()],
        }
        response = {
            "status": exchange.status,
            "headers": [{"name": name, "value": value} for name, value in response_headers.items()],
        }
        components = _request_components(request)
        if not components:
            continue
        signature = hashlib.sha256(
            "\0".join(f"{item.name.lower()}\0{item.value}" for item in components).encode()
        ).hexdigest()
        if signature in seen:
            continue
        seen.add(signature)
        captured_at = _burp_timestamp(exchange.timestamp)
        expiration = _cookie_expiration(None, captured_at)
        identity = AuthenticationIdentityConfig()
        authorization = next(
            (item.value for item in components if item.name.lower() == "authorization"), None
        )
        if authorization and authorization.lower().startswith("bearer "):
            jwt_expiration, identity = decode_jwt_metadata(
                authorization.split(None, 1)[1], checked_at=datetime.now(UTC)
            )
            if jwt_expiration.detectable:
                expiration = jwt_expiration
        parsed_url = urlsplit(exchange.url)
        candidates.append(
            AuthenticationCandidate(
                auth_type=_auth_type(components),
                components=tuple(components),
                expiration=expiration,
                identity=identity,
                baseline=_baseline(request, response),
                captured_at=captured_at,
                source_index=exchange.index,
                observed_host=(
                    parsed_url.hostname.lower() if parsed_url.hostname is not None else None
                ),
                source_label="Burp item",
            )
        )
    return candidates


def candidate_from_raw_request(path: Path) -> AuthenticationCandidate:
    """Extract one replay profile from a raw HTTP request file."""

    try:
        text = path.expanduser().resolve().read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as error:
        raise FinsecError("Cannot read raw authentication request.") from error
    start, headers, _body = parse_raw_http(text)
    parts = start.split()
    if len(parts) < 2:
        raise FinsecError("Raw request must begin with an HTTP request line.")
    method, target = parts[0].upper(), parts[1]
    parsed = urlsplit(target)
    host_header = headers.get("host")
    if parsed.hostname is None:
        if not host_header:
            raise FinsecError("Raw request must include an absolute URL or Host header.")
        parsed = urlsplit(f"https://{host_header}{target}")
    request = {
        "method": method,
        "url": parsed.geturl(),
        "headers": [{"name": name, "value": value} for name, value in headers.items()],
    }
    components = _request_components(request)
    if not components:
        raise FinsecError("No replay authentication was detected in the raw request.")
    expiration = AuthenticationExpirationConfig(last_checked_at=datetime.now(UTC))
    identity = AuthenticationIdentityConfig()
    authorization = next(
        (item.value for item in components if item.name.lower() == "authorization"), None
    )
    if authorization and authorization.lower().startswith("bearer "):
        expiration, identity = decode_jwt_metadata(authorization.split(None, 1)[1])
    baseline = None
    if method in {"GET", "HEAD"} and parsed.hostname is not None:
        try:
            port = parsed.port
        except ValueError:
            port = None
        baseline = AuthenticationBaselineConfig(
            method=cast(Literal["GET", "HEAD"], method),
            scheme=cast(
                Literal["http", "https"],
                parsed.scheme if parsed.scheme in {"http", "https"} else "https",
            ),
            host=parsed.hostname.lower(),
            port=port,
            path=parsed.path or "/",
            query_parameters={},
            safe_headers={
                name: value for name, value in headers.items() if name.lower() in SAFE_HEADERS
            },
        )
    return AuthenticationCandidate(
        auth_type=_auth_type(components),
        components=tuple(components),
        expiration=expiration,
        identity=identity,
        baseline=baseline,
        captured_at=datetime.now(UTC),
        source_index=0,
        observed_host=parsed.hostname.lower() if parsed.hostname is not None else None,
    )
