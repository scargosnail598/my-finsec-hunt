"""Centralized sanitization and credential-fidelity helpers for MCP output."""

from __future__ import annotations

import hashlib
import hmac
import re
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit

from finsec.mcp.models import AuthenticationMetadata
from finsec.modeling.models import AuthenticationType, KnowledgeStatus, ObservationSource
from finsec.utils.redaction import REDACTED, redact_text

OMITTED = "<OMITTED>"
REDACTED_PATH = "<REDACTED_PATH>"

EMAIL_PATTERN = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
PHONE_PATTERN = re.compile(r"(?<![\w.])(?:\+?\d[\d ()-]{7,}\d)(?![\w.])")
PAYMENT_CARD_PATTERN = re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)")
IBAN_PATTERN = re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b", re.IGNORECASE)
BANK_VALUE_PATTERN = re.compile(
    r"(?i)\b(account(?:_number)?|routing(?:_number)?|sort_code|swift|bic|iban|pan|cvv|cvc)"
    r"\s*[:=]\s*[^\s,;]+"
)
QUERY_VALUE_PATTERN = re.compile(r"([?&][A-Za-z0-9_.~-]+)=([^&#\s]*)")
POSIX_PATH_PATTERN = re.compile(
    r"(?<![\w:])/(?:home|users|tmp|var|etc|opt|root|mnt|workspace|workspaces)/[^\s\"']+",
    re.IGNORECASE,
)
WINDOWS_PATH_PATTERN = re.compile(r"\b[A-Z]:\\(?:[^\\\s\"']+\\)*[^\s\"']+", re.IGNORECASE)
UUID_SEGMENT_PATTERN = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
OPAQUE_SEGMENT_PATTERN = re.compile(r"^[A-Za-z0-9_-]{16,}$")
CONTROL_PATTERN = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
SAFE_IDENTIFIER_PATTERN = re.compile(r"[^A-Za-z0-9_.:@/-]+")

SENSITIVE_KEYS = {
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-csrf-token",
    "csrf",
    "csrf-token",
    "xsrf-token",
    "x-api-key",
    "api-key",
    "apikey",
    "x-client-secret",
    "client-secret",
    "password",
    "passwd",
    "otp",
    "one-time-password",
    "session",
    "session-id",
    "sessionid",
    "access-token",
    "refresh-token",
    "token",
    "secret",
    "card-number",
    "credit-card",
    "cvv",
    "cvc",
    "iban",
    "routing-number",
    "account-number",
    "bank-account",
    "pan",
}
BODY_KEYS = {"body", "raw-body", "request-body", "response-body", "post-data", "content"}
SOURCE_PATH_KEYS = {
    "source-reference",
    "source-name",
    "source-path",
    "capture-path",
    "artifact-path",
    "file-path",
    "absolute-path",
}
EXAMPLE_KEYS = {"example", "examples", "original-examples", "parameter-examples"}
QUERY_KEYS = {"query", "query-string", "query-parameters"}


def _normalized_key(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")


class Sanitizer:
    """Sanitize all public MCP text and create workspace-scoped fingerprints."""

    def __init__(self, context: str) -> None:
        self._fingerprint_key = hashlib.sha256(f"finsec-mcp:{context}".encode()).digest()

    def credential_fingerprint(self, secret: str) -> str:
        """Return a one-way fingerprint scoped to this configured workspace context."""

        digest = hmac.new(self._fingerprint_key, secret.encode(), hashlib.sha256).hexdigest()
        return f"cred-fp-{digest[:20]}"

    def reference_fingerprint(self, reference: str) -> str:
        """Fingerprint a credential reference without implying access to its secret value."""

        return self.credential_fingerprint(f"reference:{reference}")

    def text(self, value: str | None, *, maximum: int = 1000) -> str | None:
        """Redact secrets, PII, financial data, query values, paths, and control bytes."""

        return self._text(value, maximum=maximum, redact_paths=True)

    def _text(self, value: str | None, *, maximum: int, redact_paths: bool) -> str | None:
        """Apply bounded text redaction with optional filesystem-path removal."""

        if value is None:
            return None
        result = CONTROL_PATTERN.sub(" ", value)
        result = redact_text(result)
        result = QUERY_VALUE_PATTERN.sub(lambda match: f"{match.group(1)}={REDACTED}", result)
        result = EMAIL_PATTERN.sub(REDACTED, result)
        result = PHONE_PATTERN.sub(REDACTED, result)
        result = PAYMENT_CARD_PATTERN.sub(REDACTED, result)
        result = IBAN_PATTERN.sub(REDACTED, result)
        result = BANK_VALUE_PATTERN.sub(lambda match: f"{match.group(1)}={REDACTED}", result)
        if redact_paths:
            result = POSIX_PATH_PATTERN.sub(REDACTED_PATH, result)
            result = WINDOWS_PATH_PATTERN.sub(REDACTED_PATH, result)
        if len(result) > maximum:
            return f"{result[:maximum]}...<TRUNCATED>"
        return result

    def identifier(self, value: str, *, maximum: int = 120) -> str:
        """Bound an identifier without allowing control or arbitrary free-form text."""

        sanitized = self.text(value, maximum=maximum) or ""
        return SAFE_IDENTIFIER_PATTERN.sub("-", sanitized).strip("-")[:maximum]

    def route(self, value: str) -> str:
        """Remove query values and unnecessary concrete object identifiers from a route."""

        candidate = CONTROL_PATTERN.sub(" ", value[:4000])
        if "://" in candidate:
            parsed = urlsplit(candidate)
            query = urlencode([(name, REDACTED) for name, _ in parse_qsl(parsed.query)])
            safe_path = self._text(parsed.path, maximum=1000, redact_paths=False) or ""
            candidate = f"{safe_path}?{query}" if query else safe_path
        elif "?" in candidate:
            path, _, query_text = candidate.partition("?")
            names = [name for name, _ in parse_qsl(query_text, keep_blank_values=True)]
            safe_path = self._text(path, maximum=1000, redact_paths=False) or ""
            candidate = f"{safe_path}?{urlencode([(name, REDACTED) for name in names])}"
        else:
            candidate = self._text(candidate, maximum=1000, redact_paths=False) or ""

        path, separator, query = candidate.partition("?")
        segments: list[str] = []
        for segment in path.split("/"):
            if self._object_identifier_segment(segment):
                segments.append("{id}")
            else:
                segments.append(segment)
        normalized_path = "/".join(segments)
        return f"{normalized_path}?{query}" if separator and query else normalized_path

    def mapping(self, value: Any) -> Any:
        """Recursively sanitize flexible data using one centralized key policy."""

        if isinstance(value, Mapping):
            result: dict[str, Any] = {}
            for raw_key, item in value.items():
                key = str(raw_key)
                normalized = _normalized_key(key)
                if normalized in SENSITIVE_KEYS:
                    result[key] = REDACTED
                elif normalized in BODY_KEYS:
                    result[key] = OMITTED
                elif normalized in SOURCE_PATH_KEYS:
                    result[key] = REDACTED_PATH
                elif normalized in EXAMPLE_KEYS:
                    result[key] = REDACTED
                elif normalized in QUERY_KEYS and isinstance(item, Mapping):
                    result[key] = {str(name): [REDACTED] for name in item}
                elif normalized == "path" and isinstance(item, str):
                    result[key] = self.route(item)
                else:
                    result[key] = self.mapping(item)
            return result
        if isinstance(value, Sequence) and not isinstance(value, str | bytes | bytearray):
            return [self.mapping(item) for item in value]
        if isinstance(value, Path):
            return REDACTED_PATH
        if isinstance(value, str):
            return self.text(value)
        return value

    def observation_authentication(
        self,
        *,
        present: bool,
        observed_type: AuthenticationType,
        source: ObservationSource,
        knowledge_status: KnowledgeStatus,
    ) -> AuthenticationMetadata:
        """Preserve tri-state semantics without treating redaction as anonymous access."""

        if present:
            return AuthenticationMetadata(
                state="PRESENT",
                type=observed_type,
                value="<REDACTED>",
                fingerprint=None,
                fidelity="MECHANISM_ONLY",
            )
        if source in {"HAR", "BURP_XML", "CAIDO_JSON"} and knowledge_status == "OBSERVED":
            return AuthenticationMetadata(
                state="ABSENT_CONFIRMED",
                type="none",
                fidelity="MECHANISM_ONLY",
            )
        return AuthenticationMetadata(
            state="UNKNOWN_OR_REDACTED",
            type=observed_type,
            fidelity="NOT_AVAILABLE",
        )

    def execution_authentication(
        self,
        *,
        runtime_references: list[tuple[str, str]],
        actor: str | None,
        plan_verified: bool,
    ) -> AuthenticationMetadata:
        """Describe executed authentication from a checksum-matched structured plan."""

        if not plan_verified:
            return AuthenticationMetadata(
                state="UNKNOWN_OR_REDACTED",
                type="unknown",
                fidelity="NOT_AVAILABLE",
            )
        if runtime_references:
            credential_type = "+".join(sorted({item[0].lower() for item in runtime_references}))
            reference = "|".join(
                [actor or "UNKNOWN", *(item[1] for item in sorted(runtime_references))]
            )
            return AuthenticationMetadata(
                state="PRESENT",
                type=credential_type,
                value="<REDACTED>",
                fingerprint=self.reference_fingerprint(reference),
                fidelity="EXECUTION_REFERENCE",
            )
        return AuthenticationMetadata(
            state="ABSENT_CONFIRMED",
            type="none",
            fidelity="EXECUTION_REFERENCE",
        )

    @staticmethod
    def _object_identifier_segment(segment: str) -> bool:
        if not segment or (segment.startswith("{") and segment.endswith("}")):
            return False
        if UUID_SEGMENT_PATTERN.fullmatch(segment):
            return True
        if segment.isdigit():
            return not (len(segment) == 4 and 1900 <= int(segment) <= 2100)
        return bool(
            OPAQUE_SEGMENT_PATTERN.fullmatch(segment) and not segment.lower().startswith("v")
        )
