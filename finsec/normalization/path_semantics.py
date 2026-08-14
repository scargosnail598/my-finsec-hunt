"""Shared deterministic HTTP path semantics for resources and subject selectors."""

from __future__ import annotations

import re
from dataclasses import dataclass

IDENTITY_SELECTORS = {"current", "me", "mine", "own", "self"}
GENERIC_SEGMENTS = {
    "api",
    "app",
    "cdn",
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
    "filter",
    "history",
    "initiate",
    "invite",
    "list",
    "login",
    "logout",
    "lookup",
    "pay",
    "preview",
    "publish",
    "read",
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
    "search",
    "settle",
    "ship",
    "signin",
    "signup",
    "submit",
    "suspend",
    "status",
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


@dataclass(frozen=True)
class PathHierarchyNode:
    """One collection and its optional concrete or parameterized resource instance."""

    resource_type: str
    collection_index: int
    value_index: int | None
    parameter: str | None
    value: str | None


@dataclass(frozen=True)
class PathHierarchy:
    """Canonical parent-aware route family used across modeling and hypotheses."""

    nodes: tuple[PathHierarchyNode, ...]
    subject: PathHierarchyNode | None
    parent: PathHierarchyNode | None
    route_family: str
    collection_route_family: str


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


def display_resource(value: str) -> str:
    """Return the stable PascalCase resource label used by modeled path nodes."""

    return "".join(item[:1].upper() + item[1:] for item in snake_case(value).split("_"))


def _is_identifier(raw: str, normalized: str) -> bool:
    if raw.startswith("{") and raw.endswith("}"):
        return True
    if raw.isdigit():
        return True
    if re.fullmatch(r"[A-Fa-f0-9-]{8,}", raw):
        return True
    return any(character.isdigit() for character in normalized) and len(normalized) >= 4


def is_concrete_resource_identifier(raw: str) -> bool:
    """Recognize conservative literal resource IDs without treating all slugs as IDs."""

    normalized = snake_case(raw)
    if not normalized or normalized in ACTION_SEGMENTS or normalized in IDENTITY_SELECTORS:
        return False
    if _is_identifier(raw, normalized):
        return True
    return bool(
        re.fullmatch(
            r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}",
            raw.lower(),
        )
    )


def _type_key(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", value.lower())


def _is_version(value: str) -> bool:
    return bool(re.fullmatch(r"v?\d+(?:\.\d+){0,2}", value.lower()))


def _placeholder(value: str) -> str | None:
    return value[1:-1] if value.startswith("{") and value.endswith("}") else None


def _is_collection(value: str, subject_key: str) -> bool:
    if _placeholder(value) is not None:
        return False
    normalized = snake_case(value)
    if (
        not normalized
        or normalized in GENERIC_SEGMENTS
        or normalized in ACTION_SEGMENTS
        or normalized in IDENTITY_SELECTORS
        or _is_version(normalized)
    ):
        return False
    singular_value = singular(normalized)
    return normalized.endswith("s") or _type_key(singular_value) == subject_key


def _parameter_name(resource_type: str) -> str:
    parts = snake_case(resource_type).split("_")
    return parts[0] + "".join(item.title() for item in parts[1:]) + "Id"


def path_hierarchy(
    template_path: str,
    concrete_path: str,
    subject_resource: str,
) -> PathHierarchy:
    """Reconstruct a resource chain without treating path structure as ownership proof."""

    template = [item for item in template_path.split("/") if item]
    concrete = [item for item in concrete_path.split("/") if item]
    if len(template) != len(concrete):
        concrete = template
    subject_key = _type_key(subject_resource)
    collection_indices = [
        index for index, item in enumerate(template) if _is_collection(item, subject_key)
    ]
    matching = [
        index
        for index in collection_indices
        if _type_key(singular(snake_case(template[index]))) == subject_key
    ]
    subject_index = (
        matching[-1] if matching else collection_indices[-1] if collection_indices else None
    )
    nodes: list[PathHierarchyNode] = []
    value_positions: dict[int, str] = {}
    for position, collection_index in enumerate(collection_indices):
        next_collection = (
            collection_indices[position + 1]
            if position + 1 < len(collection_indices)
            else len(template)
        )
        resource_type = display_resource(singular(snake_case(template[collection_index])))
        candidate = collection_index + 1
        value_index: int | None = None
        parameter: str | None = None
        value: str | None = None
        if candidate < len(template) and candidate < next_collection:
            candidate_token = snake_case(template[candidate])
            candidate_parameter = _placeholder(template[candidate])
            candidate_is_action = (
                candidate_token in ACTION_SEGMENTS
                or candidate_token in IDENTITY_SELECTORS
                or _is_version(candidate_token)
            )
            if candidate_parameter is not None or (
                not candidate_is_action and is_concrete_resource_identifier(template[candidate])
            ):
                value_index = candidate
                parameter = candidate_parameter or _parameter_name(resource_type)
                candidate_value = concrete[candidate]
                value = None if _placeholder(candidate_value) is not None else candidate_value
                value_positions[candidate] = snake_case(resource_type)
        nodes.append(
            PathHierarchyNode(
                resource_type=resource_type,
                collection_index=collection_index,
                value_index=value_index,
                parameter=parameter,
                value=value,
            )
        )

    family_segments: list[str] = []
    for index, item in enumerate(template):
        if index in value_positions:
            family_segments.append("{" + value_positions[index] + "}")
        elif _placeholder(item) is not None:
            previous = template[index - 1] if index else "resource"
            family_segments.append("{" + singular(snake_case(previous)) + "}")
        else:
            family_segments.append(item)
    route_family = "/" + "/".join(family_segments)
    if template_path.endswith("/") and route_family != "/":
        route_family += "/"

    subject = next((item for item in nodes if item.collection_index == subject_index), None)
    parent = None
    if subject is not None:
        parent = next(
            (
                item
                for item in reversed(nodes)
                if item.collection_index < subject.collection_index and item.value_index is not None
            ),
            None,
        )
    collection_end = subject.collection_index + 1 if subject is not None else len(family_segments)
    collection_route_family = "/" + "/".join(family_segments[:collection_end])
    return PathHierarchy(
        nodes=tuple(nodes),
        subject=subject,
        parent=parent,
        route_family=route_family,
        collection_route_family=collection_route_family,
    )


def structural_parent_resource(path: str, subject_resource: str) -> str | None:
    """Return the immediate structural parent type for a nested subject route."""

    parent = path_hierarchy(path, path, subject_resource).parent
    return parent.resource_type if parent is not None else None


def _path_parts(path: str) -> list[tuple[str, str, bool]]:
    parts: list[tuple[str, str, bool]] = []
    for raw_part in path.split("/"):
        raw = raw_part.strip()
        if not raw:
            continue
        normalized = snake_case(raw)
        if not normalized or normalized in GENERIC_SEGMENTS or re.fullmatch(r"v\d+", normalized):
            continue
        parts.append((raw, normalized, is_concrete_resource_identifier(raw)))
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
