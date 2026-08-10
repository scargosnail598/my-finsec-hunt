"""Shared deterministic HTTP path semantics for resources and subject selectors."""

from __future__ import annotations

import re
from dataclasses import dataclass

IDENTITY_SELECTORS = {"current", "me", "mine", "own", "self"}
GENERIC_SEGMENTS = {
    "api",
    "app",
    "data",
    "graphql",
    "internal",
    "public",
    "rest",
    "service",
}
ACTION_SEGMENTS = {
    "accept",
    "activate",
    "add",
    "apply",
    "approve",
    "cancel",
    "capture",
    "change",
    "claim",
    "close",
    "complete",
    "confirm",
    "consume",
    "create",
    "deactivate",
    "delete",
    "disable",
    "edit",
    "enable",
    "execute",
    "expire",
    "initiate",
    "invite",
    "login",
    "logout",
    "pay",
    "publish",
    "redeem",
    "refund",
    "reject",
    "remove",
    "replace",
    "request",
    "reset",
    "resend",
    "return",
    "revoke",
    "rotate",
    "settle",
    "ship",
    "signin",
    "signup",
    "submit",
    "suspend",
    "transfer",
    "update",
    "verify",
    "withdraw",
}
CREDENTIAL_COMPONENTS = {
    "api_key",
    "api_keys",
    "credential",
    "credentials",
    "passcode",
    "passcodes",
    "password",
    "passwords",
    "pin",
    "pins",
    "recovery_code",
    "recovery_codes",
    "secret",
    "secrets",
    "security_key",
    "security_keys",
}
BACKGROUND_COMPONENTS = {
    "analytics",
    "beacon",
    "heartbeat",
    "metrics",
    "ping",
    "telemetry",
    "tracking",
}


@dataclass(frozen=True)
class PathResourceSemantics:
    """Resource hierarchy and actor-subject meaning derived from a path."""

    resource: str
    parent_resource: str | None = None
    subject_selector: str | None = None
    semantic_component: str | None = None
    terminal_is_collection: bool = False
    normalized_operation_path: str = "/"


def snake_case(value: str) -> str:
    """Normalize a path or model token to stable snake case."""

    split_camel = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", value)
    return re.sub(r"[^a-z0-9]+", "_", split_camel.lower()).strip("_")


def singular(value: str) -> str:
    """Apply the project's intentionally small deterministic singularization rule."""

    if value.endswith("ies") and len(value) > 3:
        return f"{value[:-3]}y"
    if value.endswith("sses"):
        return value[:-2]
    if value.endswith("s") and not value.endswith(("ss", "us")):
        return value[:-1]
    return value


def _is_identifier(raw: str, normalized: str) -> bool:
    if raw.startswith("{") and raw.endswith("}"):
        return True
    if raw.isdigit():
        return True
    if re.fullmatch(r"[A-Fa-f0-9-]{8,}", raw):
        return True
    return any(character.isdigit() for character in normalized) and len(normalized) >= 4


def _path_parts(path: str) -> list[tuple[str, str, bool]]:
    parts: list[tuple[str, str, bool]] = []
    for raw_part in path.split("/"):
        raw = raw_part.strip()
        if not raw:
            continue
        normalized = snake_case(raw)
        if not normalized or normalized in GENERIC_SEGMENTS or re.fullmatch(r"v\d+", normalized):
            continue
        parts.append((raw, normalized, _is_identifier(raw, normalized)))
    return parts


def _operation_path(parts: list[tuple[str, str, bool]]) -> str:
    normalized: list[str] = []
    for _raw, token, identifier in parts:
        if token in IDENTITY_SELECTORS:
            normalized.append("{current_actor}")
        elif identifier:
            normalized.append("{id}")
        else:
            normalized.append(token)
    return "/" + "/".join(normalized) if normalized else "/"


def _resource_tokens(parts: list[tuple[str, str, bool]]) -> list[tuple[int, str]]:
    return [
        (index, token)
        for index, (_raw, token, identifier) in enumerate(parts)
        if not identifier and token not in ACTION_SEGMENTS
    ]


def _credential_resource(parent: str | None, component: str) -> tuple[str, str | None]:
    semantic_component = "credential" if component in CREDENTIAL_COMPONENTS else None
    if semantic_component is None:
        return singular(component), None
    if parent is None or parent == "unknown":
        return semantic_component, semantic_component
    return f"{singular(parent)}_{semantic_component}", semantic_component


def path_resource_semantics(path: str) -> PathResourceSemantics:
    """Resolve resources while treating identity aliases as subject selectors."""

    parts = _path_parts(path)
    operation_path = _operation_path(parts)
    tokens = _resource_tokens(parts)
    if not tokens:
        return PathResourceSemantics(resource="unknown", normalized_operation_path=operation_path)

    selector_indices = {
        index
        for index, (_raw, token, identifier) in enumerate(parts)
        if not identifier and token in IDENTITY_SELECTORS
    }
    selector_index = next(
        (
            index
            for index in sorted(selector_indices)
            if any(token_index < index for token_index, _token in tokens)
        ),
        None,
    )
    if selector_index is not None:
        before = [token for index, token in tokens if index < selector_index]
        after = [token for index, token in tokens if index > selector_index]
        parent = singular(before[-1]) if before else None
        if not after:
            return PathResourceSemantics(
                resource=parent or "unknown",
                subject_selector="current_actor",
                normalized_operation_path=operation_path,
            )
        terminal = after[-1]
        resource, semantic_component = _credential_resource(parent, terminal)
        return PathResourceSemantics(
            resource=resource,
            parent_resource=parent,
            subject_selector="current_actor",
            semantic_component=semantic_component,
            terminal_is_collection=terminal.endswith("s") and not terminal.endswith("ss"),
            normalized_operation_path=operation_path,
        )

    terminal_index, terminal = tokens[-1]
    parent = singular(tokens[-2][1]) if len(tokens) >= 2 else None
    resource, semantic_component = _credential_resource(parent, terminal)
    raw_terminal = parts[terminal_index][1]
    return PathResourceSemantics(
        resource=resource,
        parent_resource=parent,
        semantic_component=semantic_component,
        terminal_is_collection=raw_terminal.endswith("s") and not raw_terminal.endswith("ss"),
        normalized_operation_path=operation_path,
    )


def is_background_path(path: str) -> bool:
    """Return whether the path has an explicit protocol/telemetry support marker."""

    tokens = {
        component
        for _index, token in _resource_tokens(_path_parts(path))
        for component in (token, *token.split("_"))
    }
    return bool(tokens & BACKGROUND_COMPONENTS)
