"""Pure structured actor-identity assertion evaluation."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Literal

from finsec.config.models import AccountConfig, AuthenticationIdentityAssertionConfig
from finsec.modeling.merge import stable_fingerprint

IdentityAssertionStatus = Literal[
    "NOT_CONFIGURED",
    "NOT_CHECKED",
    "CONFIRMED",
    "STATUS_MISMATCH",
    "LOGIN_OR_ERROR_RESPONSE",
    "MALFORMED_BODY",
    "SELECTOR_MISSING",
    "SELECTOR_AMBIGUOUS",
    "EXPECTED_VALUE_MISSING",
    "VALUE_MISMATCH",
    "LEGACY_UNTRUSTED",
]


@dataclass(frozen=True)
class IdentityAssertionResult:
    """Secret-free outcome; extracted response values never leave the evaluator."""

    confirmed: bool
    status: IdentityAssertionStatus
    confirmation_reference: str | None = None


class _DuplicateJsonKey(ValueError):
    pass


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise _DuplicateJsonKey(key)
        value[key] = item
    return value


def _json_document(body: bytes) -> Any:
    return json.loads(body.decode("utf-8"), object_pairs_hook=_unique_object)


def _pointer_token(value: str) -> str | None:
    if re.search(r"~(?:[^01]|$)", value):
        return None
    return value.replace("~1", "/").replace("~0", "~")


def _resolve_json_pointer(document: Any, pointer: str) -> tuple[IdentityAssertionStatus, Any]:
    current = document
    for raw_part in pointer.removeprefix("/").split("/"):
        part = _pointer_token(raw_part)
        if part is None:
            return "SELECTOR_MISSING", None
        if isinstance(current, dict):
            if part not in current:
                return "SELECTOR_MISSING", None
            current = current[part]
            continue
        if isinstance(current, list):
            if not part.isdigit() or (len(part) > 1 and part.startswith("0")):
                return "SELECTOR_MISSING", None
            index = int(part)
            if index >= len(current):
                return "SELECTOR_MISSING", None
            current = current[index]
            continue
        return "SELECTOR_MISSING", None
    return "CONFIRMED", current


def _expected_value(
    assertion: AuthenticationIdentityAssertionConfig,
    account: AccountConfig,
) -> tuple[bool, Any]:
    if assertion.expected_value is not None:
        return True, assertion.expected_value
    reference = assertion.expected_actor_reference
    if reference == "account.id":
        return True, account.id
    authentication = account.authentication
    identity = authentication.identity if authentication is not None else None
    if reference == "identity.subject" and identity is not None and identity.subject is not None:
        return True, identity.subject
    if reference == "identity.tenant" and identity is not None and identity.tenant is not None:
        return True, identity.tenant
    return False, None


def _header_value(
    headers: list[tuple[str, str]], selector: str
) -> tuple[IdentityAssertionStatus, Any]:
    values = [value for name, value in headers if name.lower() == selector.lower()]
    if not values:
        return "SELECTOR_MISSING", None
    if len(values) != 1:
        return "SELECTOR_AMBIGUOUS", None
    return "CONFIRMED", values[0]


def evaluate_identity_assertion(
    assertion: AuthenticationIdentityAssertionConfig | None,
    account: AccountConfig,
    *,
    status_code: int,
    headers: list[tuple[str, str]],
    body: bytes,
    login_or_error_response: bool,
) -> IdentityAssertionResult:
    """Evaluate one exact assertion without logging or returning selected response content."""

    if assertion is None:
        return IdentityAssertionResult(False, "NOT_CONFIGURED")
    expected_status = assertion.expected_status
    if login_or_error_response or not 200 <= status_code < 300:
        return IdentityAssertionResult(False, "LOGIN_OR_ERROR_RESPONSE")
    if expected_status is not None and status_code != expected_status:
        return IdentityAssertionResult(False, "STATUS_MISMATCH")
    expected_available, expected = _expected_value(assertion, account)
    if not expected_available:
        return IdentityAssertionResult(False, "EXPECTED_VALUE_MISSING")

    if assertion.source == "RESPONSE_HEADER":
        selector_status, actual = _header_value(headers, assertion.selector)
    else:
        try:
            document = _json_document(body)
        except (UnicodeDecodeError, json.JSONDecodeError, _DuplicateJsonKey):
            return IdentityAssertionResult(False, "MALFORMED_BODY")
        selector_status, actual = _resolve_json_pointer(document, assertion.selector)
    if selector_status != "CONFIRMED":
        return IdentityAssertionResult(False, selector_status)
    if isinstance(actual, (dict, list)) or type(actual) is not type(expected) or actual != expected:
        return IdentityAssertionResult(False, "VALUE_MISMATCH")

    reference_payload: dict[str, Any] = {
        "actor": account.id,
        "source": assertion.source,
        "selector": assertion.selector,
        "expected_status": expected_status,
    }
    if assertion.redaction == "SHA256":
        reference_payload["value_fingerprint"] = stable_fingerprint({"value": actual})
    return IdentityAssertionResult(
        True,
        "CONFIRMED",
        f"identity-assertion:{stable_fingerprint(reference_payload)}",
    )
