"""Redacted factual signal extraction for deterministic behavior reconstruction."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from pathlib import Path
from typing import Any, Literal

from finsec.config.workspace import WorkspacePaths
from finsec.ingest.common import headers_from_any, parse_raw_http
from finsec.modeling.merge import stable_fingerprint
from finsec.modeling.models import Endpoint, EndpointStore, Observation
from finsec.modeling.semantics import (
    IdentifierResourceRole,
    IdentifierSemanticAssessment,
    IdentifierSemanticClass,
    OwnershipState,
)
from finsec.utils.redaction import REDACTED

SignalKind = Literal[
    "RESOURCE_IDENTIFIER",
    "WORKFLOW_TOKEN",
    "CORRELATION_ID",
    "IDEMPOTENCY_KEY",
    "BUSINESS_VALUE",
]
PrimitiveType = Literal["STRING", "INTEGER", "FLOAT", "BOOLEAN", "NULL"]
ResourceRole = Literal["PRIMARY", "RELATED", "SCOPE", "UNKNOWN"]

STATE_FIELDS = {
    "status",
    "state",
    "phase",
    "lifecycle",
    "lifecyclestate",
    "paymentstatus",
    "orderstatus",
    "transferstatus",
    "subscriptionstatus",
}
VALUE_FIELDS = {
    "amount",
    "balance",
    "cumulativeamount",
    "cumulativevalue",
    "credit",
    "debit",
    "discount",
    "fee",
    "inventory",
    "limit",
    "price",
    "quantity",
    "refundamount",
    "subtotal",
    "total",
}
TOKEN_HINTS = {
    "challenge",
    "code",
    "coupon",
    "idempotency",
    "invitation",
    "nonce",
    "reference",
    "reward",
    "ticket",
    "token",
}


@dataclass(frozen=True)
class ScalarSignal:
    """One redacted, typed scalar retained only for local correlation."""

    field: str
    value: str = dataclass_field(repr=False)
    fingerprint: str
    kind: SignalKind
    resource_type: str | None = None
    semantic_role: str = "unknown"
    resource_role: ResourceRole = "UNKNOWN"
    semantic_class: IdentifierSemanticClass = IdentifierSemanticClass.OPAQUE_UNKNOWN
    ownership_state: OwnershipState = OwnershipState.UNKNOWN
    location: str = "BODY"
    primitive_type: PrimitiveType = "STRING"
    distinctive: bool = False
    suppression_reason: str | None = None
    direction: Literal["REQUEST", "RESPONSE"] = "REQUEST"


@dataclass(frozen=True)
class StateSignal:
    """One explicit response state field."""

    field: str
    value: str
    resource_type: str


@dataclass(frozen=True)
class ExchangeFacts:
    """Factual signals for one observation plus existing endpoint inference."""

    observation: Observation
    endpoint: Endpoint | None
    action_name: str
    action_reasons: tuple[str, ...]
    request_signals: tuple[ScalarSignal, ...]
    response_signals: tuple[ScalarSignal, ...]
    states: tuple[StateSignal, ...]

    @property
    def signals(self) -> tuple[ScalarSignal, ...]:
        return (*self.request_signals, *self.response_signals)


def _normalized_name(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", value.lower())


def _primitive_type(value: Any) -> PrimitiveType:
    if value is None:
        return "NULL"
    if isinstance(value, bool):
        return "BOOLEAN"
    if isinstance(value, int):
        return "INTEGER"
    if isinstance(value, float):
        return "FLOAT"
    return "STRING"


def _terminal_field(path: str) -> str:
    return path.rsplit(".", 1)[-1].replace("[]", "")


def _flatten(value: Any, prefix: str = "$") -> list[tuple[str, Any]]:
    scalars: list[tuple[str, Any]] = []
    if isinstance(value, dict):
        for key in sorted(value):
            child = f"{prefix}.{key}"
            scalars.extend(_flatten(value[key], child))
    elif isinstance(value, list):
        for item in value:
            scalars.extend(_flatten(item, f"{prefix}[]"))
    elif isinstance(value, str | int | float | bool) or value is None:
        scalars.append((prefix, value))
    return scalars


def _json_value(value: Any) -> Any | None:
    if isinstance(value, dict | list):
        return value
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return None


def _capture_index(reference: str) -> int | None:
    match = re.search(r"#(?:entry|item)-(\d+)$", reference)
    return int(match.group(1)) if match else None


def _capture_path(workspace: WorkspacePaths, observation: Observation) -> Path | None:
    relative = observation.source_reference.split("#", 1)[0]
    path = workspace.root / relative
    try:
        path.resolve().relative_to(workspace.root.resolve())
    except ValueError:
        return None
    return path if path.is_file() else None


class RedactedCaptureReader:
    """Read only already-redacted workspace captures and cache parsed JSON documents."""

    def __init__(self, workspace: WorkspacePaths) -> None:
        self.workspace = workspace
        self._cache: dict[Path, Any] = {}

    def _document(self, path: Path) -> Any | None:
        if path in self._cache:
            return self._cache[path]
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            document = None
        self._cache[path] = document
        return document

    def exchange(
        self, observation: Observation
    ) -> tuple[Any | None, Any | None, dict[str, str], dict[str, str]]:
        path = _capture_path(self.workspace, observation)
        index = _capture_index(observation.source_reference)
        if path is None or index is None:
            return None, None, {}, {}
        document = self._document(path)
        if not isinstance(document, dict):
            return None, None, {}, {}

        log = document.get("log")
        if isinstance(log, dict) and isinstance(log.get("entries"), list):
            entries = log["entries"]
            if index >= len(entries) or not isinstance(entries[index], dict):
                return None, None, {}, {}
            entry = entries[index]
            request = entry.get("request") if isinstance(entry.get("request"), dict) else {}
            response = entry.get("response") if isinstance(entry.get("response"), dict) else {}
            post_data = request.get("postData") if isinstance(request, dict) else None
            content = response.get("content") if isinstance(response, dict) else None
            request_body = (
                _json_value(post_data.get("text")) if isinstance(post_data, dict) else None
            )
            response_body = _json_value(content.get("text")) if isinstance(content, dict) else None
            return (
                request_body,
                response_body,
                headers_from_any(request.get("headers")),
                headers_from_any(response.get("headers")),
            )

        items = document.get("items")
        if isinstance(items, list) and index < len(items) and isinstance(items[index], dict):
            item = items[index]
            request_text = item.get("request")
            response_text = item.get("response")
            if isinstance(request_text, str) and isinstance(response_text, str):
                _request_line, request_headers, request_body_text = parse_raw_http(request_text)
                _response_line, response_headers, response_body_text = parse_raw_http(response_text)
                return (
                    _json_value(request_body_text),
                    _json_value(response_body_text),
                    request_headers,
                    response_headers,
                )

        entries = document.get("entries", document.get("requests"))
        if isinstance(entries, list) and index < len(entries) and isinstance(entries[index], dict):
            entry = entries[index]
            request = entry.get("request") if isinstance(entry.get("request"), dict) else entry
            response = entry.get("response") if isinstance(entry.get("response"), dict) else {}
            request_body = request.get("body") if isinstance(request, dict) else None
            response_body = response.get("body") if isinstance(response, dict) else None
            return (
                _json_value(request_body),
                _json_value(response_body),
                headers_from_any(request.get("headers")),
                headers_from_any(response.get("headers")),
            )
        return None, None, {}, {}


def _singular(value: str) -> str:
    return value[:-1] if value.endswith("s") and not value.endswith("ss") else value


def _path_parent_type(field_path: str) -> str | None:
    parts = [
        re.sub(r"[^a-z0-9_-]", "", item.lower().replace("[]", ""))
        for item in field_path.replace("$", "").split(".")[:-1]
    ]
    for part in reversed(parts):
        if part and part not in {
            "body",
            "data",
            "header",
            "item",
            "items",
            "path",
            "query",
            "result",
            "results",
        }:
            return _singular(part.replace("_", "-"))
    return None


def _resource_type(field_path: str, endpoint: Endpoint | None) -> str:
    field_name = _terminal_field(field_path)
    normalized = re.sub(r"(?:_?id|_?identifier|_?reference)$", "", field_name, flags=re.I)
    if (
        normalized.lower()
        in {
            "",
            "hash",
            "id",
            "integer",
            "long",
            "numeric",
            "object",
            "opaque",
            "parameter",
            "resource",
            "uuid",
            "value",
        }
        and endpoint is not None
    ):
        return _path_parent_type(field_path) or endpoint.resource.type.lower()
    return normalized.replace("_", "-").lower() or "resource"


def _state_resource_type(field_path: str, endpoint: Endpoint | None) -> str:
    field_name = _normalized_name(_terminal_field(field_path))
    for suffix in ("status", "state", "phase", "lifecycle"):
        if field_name.endswith(suffix) and field_name != suffix:
            prefix = field_name[: -len(suffix)]
            if prefix:
                return _singular(prefix)
    return _path_parent_type(field_path) or (
        endpoint.resource.type.lower() if endpoint is not None else "resource"
    )


def _value_resource_type(field_path: str, endpoint: Endpoint | None) -> str:
    parent = _path_parent_type(field_path)
    field_name = _normalized_name(_terminal_field(field_path))
    if parent is not None:
        return parent
    if field_name.endswith(("balance", "credit", "debit")):
        return "account"
    return endpoint.resource.type.lower() if endpoint is not None else "resource"


def _resource_role(
    resource_type: str | None,
    endpoint: Endpoint | None,
    semantics: IdentifierSemanticAssessment | None = None,
) -> ResourceRole:
    if semantics is not None and semantics.semantic_class in {
        IdentifierSemanticClass.REGION,
        IdentifierSemanticClass.SHARED_SCOPE,
        IdentifierSemanticClass.TENANT_CONTAINER,
        IdentifierSemanticClass.PARENT_CONTAINER,
        IdentifierSemanticClass.ACTOR_IDENTIFIER,
    }:
        return "SCOPE"
    if resource_type is None:
        return "UNKNOWN"
    lowered = resource_type.lower()
    if lowered in {"account", "actor", "owner", "tenant", "user", "userid"}:
        return "SCOPE"
    if endpoint is not None and lowered == endpoint.resource.type.lower():
        return "PRIMARY"
    return "RELATED"


def _parameter_semantics(
    endpoint: Endpoint | None,
    field_name: str,
    location: str,
    direction: Literal["REQUEST", "RESPONSE"],
    field_path: str | None = None,
) -> IdentifierSemanticAssessment | None:
    if endpoint is None:
        return None
    normalized = _normalized_name(field_name)
    expected_locations = {
        "PATH_PARAMETER": {"path"},
        "QUERY_PARAMETER": {"query"},
        "HEADER": {"header"},
        "BODY": {"body"} if direction == "REQUEST" else {"response_body"},
    }.get(location, set())
    candidates = [
        item
        for item in endpoint.parameters
        if _normalized_name(item.name) == normalized
        and item.source == direction.lower()
        and (not expected_locations or item.location in expected_locations)
    ]
    if field_path is not None and location == "BODY":
        exact_path = [
            item
            for item in candidates
            if item.json_path is not None
            and item.json_path.replace("[*]", "[]") == field_path.replace("[*]", "[]")
        ]
        if exact_path:
            candidates = exact_path
    if candidates:
        return sorted(candidates, key=lambda item: (item.location, item.name))[
            0
        ].identifier_semantics
    if location == "PATH_PARAMETER" and normalized == _normalized_name(
        f"{endpoint.resource.type}Id"
    ):
        return IdentifierSemanticAssessment(
            semantic_class=IdentifierSemanticClass.OBJECT_IDENTIFIER,
            resource_role=IdentifierResourceRole.SUBJECT,
            resource_type=endpoint.resource.type,
            ownership_state=OwnershipState.UNKNOWN,
            confidence="medium",
            evidence=[
                "A literal path segment selects the endpoint subject; ownership remains unknown."
            ],
            sources=["PATH_STRUCTURE"],
            explanation=(
                "The path scalar is an object-identifier candidate, but no ownership evidence "
                "is inferred from its shape or position."
            ),
        )
    return None


def _business_role(field_name: str) -> str:
    normalized = _normalized_name(field_name)
    aliases = (
        ("refundamount", "refund-amount"),
        ("cumulativeamount", "cumulative-amount"),
        ("cumulativevalue", "cumulative-value"),
        ("quantity", "quantity"),
        ("amount", "amount"),
        ("balance", "balance"),
        ("credit", "credit"),
        ("debit", "debit"),
        ("discount", "discount"),
        ("subtotal", "subtotal"),
        ("total", "total"),
        ("price", "price"),
        ("limit", "limit"),
        ("fee", "fee"),
        ("inventory", "inventory"),
    )
    for suffix, role in aliases:
        if normalized == suffix or normalized.endswith(suffix):
            return role
    return normalized or "value"


def _semantic_role(
    field_name: str,
    kind: SignalKind,
    resource_type: str | None,
) -> str:
    normalized = _normalized_name(field_name)
    if kind == "RESOURCE_IDENTIFIER":
        return f"resource:{resource_type or 'unknown'}:identifier"
    if kind == "BUSINESS_VALUE":
        return f"business:{_business_role(field_name)}"
    if kind == "IDEMPOTENCY_KEY":
        return "protocol:idempotency-key"
    if kind == "CORRELATION_ID":
        return f"protocol:{normalized.replace('id', '-id')}"
    stem = re.sub(r"(?:workflow)?(?:token|reference|challenge|code|nonce|ticket)$", "", normalized)
    return f"token:{stem or 'workflow'}"


def _timestamp_like(field_name: str, value: str) -> bool:
    normalized = _normalized_name(field_name)
    if normalized.endswith(("at", "date", "time", "timestamp")):
        return True
    return bool(
        re.fullmatch(
            r"\d{4}-\d{2}-\d{2}[Tt ]\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:Z|[+-]\d{2}:?\d{2})?",
            value,
        )
    )


def _distinctive_value(field_name: str, value: str, kind: SignalKind) -> tuple[bool, str | None]:
    lowered = value.strip().lower()
    if _timestamp_like(field_name, value):
        return False, "Timestamp-like values are not causal identifiers."
    if lowered in {
        "0",
        "1",
        "active",
        "cancelled",
        "closed",
        "complete",
        "completed",
        "created",
        "false",
        "failed",
        "none",
        "null",
        "ok",
        "paid",
        "pending",
        "published",
        "refunded",
        "success",
        "true",
        "unknown",
    }:
        return False, "Low-entropy or common protocol value."
    if kind in {"WORKFLOW_TOKEN", "CORRELATION_ID", "IDEMPOTENCY_KEY"} and len(value) < 8:
        return False, "Token-like value is too short to establish distinctive continuity."
    return True, None


def _opaque_token_candidate(field_name: str, value: Any, location: str) -> bool:
    if location not in {"BODY", "HEADER"} or not isinstance(value, str):
        return False
    normalized = _normalized_name(field_name)
    if normalized in STATE_FIELDS or normalized in VALUE_FIELDS:
        return False
    candidate = value.strip()
    if not 12 <= len(candidate) <= 128 or any(character.isspace() for character in candidate):
        return False
    if _timestamp_like(field_name, candidate) or len(set(candidate.lower())) < 8:
        return False
    return any(character.isalpha() for character in candidate) and any(
        character.isdigit() for character in candidate
    )


def _signal_kind(field_name: str, location: str, value: Any) -> SignalKind | None:
    normalized = _normalized_name(field_name)
    if normalized in {"page", "pagenumber", "pagesize", "offset", "cursor"} or (
        normalized == "limit" and location == "QUERY_PARAMETER"
    ):
        return None
    if normalized == "idempotencykey":
        return "IDEMPOTENCY_KEY"
    if normalized in {"correlationid", "requestid", "traceid"} or (
        location == "HEADER"
        and any(token in normalized for token in ("correlation", "requestid", "traceid"))
    ):
        return "CORRELATION_ID"
    if normalized in VALUE_FIELDS or any(normalized.endswith(item) for item in VALUE_FIELDS):
        return "BUSINESS_VALUE"
    if normalized.endswith(("id", "identifier")) or location == "PATH_PARAMETER":
        return "RESOURCE_IDENTIFIER"
    if any(hint in normalized for hint in TOKEN_HINTS):
        return "WORKFLOW_TOKEN"
    if _opaque_token_candidate(field_name, value, location):
        return "WORKFLOW_TOKEN"
    return None


def _signal(
    field_path: str,
    raw_value: Any,
    direction: Literal["REQUEST", "RESPONSE"],
    endpoint: Endpoint | None,
    *,
    location: str = "BODY",
) -> ScalarSignal | None:
    if raw_value is None or isinstance(raw_value, bool):
        return None
    value = str(raw_value).strip()
    if not value or value == REDACTED or len(value) > 256:
        return None
    field_name = _terminal_field(field_path)
    parameter_semantics = _parameter_semantics(
        endpoint,
        field_name,
        location,
        direction,
        field_path=field_path,
    )
    kind = _signal_kind(field_name, location, raw_value)
    if kind is None:
        return None
    resource_type = (
        parameter_semantics.resource_type
        if kind == "RESOURCE_IDENTIFIER"
        and parameter_semantics is not None
        and parameter_semantics.resource_type is not None
        else _resource_type(field_path, endpoint)
        if kind == "RESOURCE_IDENTIFIER"
        else _value_resource_type(field_path, endpoint)
        if kind == "BUSINESS_VALUE"
        else None
    )
    distinctive, suppression_reason = _distinctive_value(field_name, value, kind)
    return ScalarSignal(
        field=field_path,
        value=value,
        fingerprint=stable_fingerprint({"value": value}),
        kind=kind,
        resource_type=resource_type,
        semantic_role=_semantic_role(field_name, kind, resource_type),
        resource_role=_resource_role(resource_type, endpoint, parameter_semantics),
        semantic_class=(
            parameter_semantics.semantic_class
            if parameter_semantics is not None
            else IdentifierSemanticClass.OPAQUE_UNKNOWN
        ),
        ownership_state=(
            parameter_semantics.ownership_state
            if parameter_semantics is not None
            else OwnershipState.UNKNOWN
        ),
        location=location,
        primitive_type=_primitive_type(raw_value),
        distinctive=distinctive,
        suppression_reason=suppression_reason,
        direction=direction,
    )


def _path_signals(observation: Observation, endpoint: Endpoint | None) -> list[ScalarSignal]:
    if endpoint is None:
        return []
    observed = [item for item in observation.path.split("/") if item]
    template = [item for item in endpoint.path.split("/") if item]
    if len(observed) != len(template):
        return []
    signals: list[ScalarSignal] = []
    endpoint_resource = re.sub(r"[^a-z0-9]", "", endpoint.resource.type.lower())
    for index, (concrete, segment) in enumerate(zip(observed, template, strict=True)):
        if segment.startswith("{") and segment.endswith("}"):
            parameter = segment[1:-1]
        else:
            previous = observed[index - 1].lower() if index else ""
            previous_resource = _singular(re.sub(r"[^a-z0-9]", "", previous))
            literal_resource_identifier = (
                previous.endswith("s")
                and previous_resource == endpoint_resource
                and any(character.isdigit() for character in concrete)
            )
            if not literal_resource_identifier:
                continue
            parameter = f"{previous_resource}Id"
        item = _signal(
            f"path.{parameter}",
            concrete,
            "REQUEST",
            endpoint,
            location="PATH_PARAMETER",
        )
        if item is not None:
            signals.append(item)
    return signals


def _semantic_action(endpoint: Endpoint | None, observation: Observation) -> tuple[str, list[str]]:
    resource = endpoint.resource.type if endpoint is not None else "resource"
    inferred = endpoint.action.name if endpoint is not None else "unknown"
    route_tokens = [
        token.replace("-", "_")
        for token in observation.path.strip("/").split("/")
        if token
        and not token.startswith("{")
        and not re.fullmatch(r"[A-Za-z]*\d[A-Za-z0-9-]*", token)
    ]
    custom = route_tokens[-1].lower() if route_tokens else ""
    if inferred == "unknown" and custom not in {"api", "v1", "v2", "v3"}:
        inferred = custom
    if inferred == "unknown":
        inferred = {
            "POST": "execute",
            "PUT": "replace",
            "PATCH": "update",
            "DELETE": "delete",
        }.get(observation.method, "read")
    normalized_resource = re.sub(r"[^A-Za-z0-9]+", "_", resource).strip("_").upper()
    normalized_action = re.sub(r"[^A-Za-z0-9]+", "_", inferred).strip("_").upper()
    name = (
        f"{normalized_action}_{normalized_resource}" if normalized_resource else normalized_action
    )
    reasons = [f"endpoint action is {inferred}", f"endpoint resource is {resource}"]
    return name, reasons


def extract_exchange_facts(
    workspace: WorkspacePaths,
    observations: list[Observation],
    endpoints: EndpointStore,
) -> list[ExchangeFacts]:
    """Extract deterministic redacted signals without changing factual observation records."""

    reader = RedactedCaptureReader(workspace)
    endpoint_by_observation = {
        observation_id: endpoint
        for endpoint in endpoints.endpoints
        for observation_id in endpoint.sources
    }
    results: list[ExchangeFacts] = []
    for observation in observations:
        endpoint = endpoint_by_observation.get(observation.id)
        action_name, action_reasons = _semantic_action(endpoint, observation)
        request_body, response_body, request_headers, response_headers = reader.exchange(
            observation
        )
        request_signals = _path_signals(observation, endpoint)
        for name in sorted(observation.query_parameters):
            for value in observation.query_parameters[name]:
                item = _signal(
                    f"query.{name}", value, "REQUEST", endpoint, location="QUERY_PARAMETER"
                )
                if item is not None:
                    request_signals.append(item)
        for path, value in _flatten(request_body):
            item = _signal(path, value, "REQUEST", endpoint, location="BODY")
            if item is not None:
                request_signals.append(item)
        for name, value in sorted(request_headers.items()):
            item = _signal(f"header.{name}", value, "REQUEST", endpoint, location="HEADER")
            if item is not None:
                request_signals.append(item)

        response_signals: list[ScalarSignal] = []
        states: list[StateSignal] = []
        for path, value in _flatten(response_body):
            field_name = _normalized_name(_terminal_field(path))
            if (
                field_name in STATE_FIELDS
                or field_name.endswith("status")
                or field_name.endswith("state")
            ) and isinstance(value, str | int):
                states.append(
                    StateSignal(
                        field=path,
                        value=str(value).strip().upper(),
                        resource_type=_state_resource_type(path, endpoint),
                    )
                )
            item = _signal(path, value, "RESPONSE", endpoint, location="BODY")
            if item is not None:
                response_signals.append(item)
        for name, value in sorted(response_headers.items()):
            item = _signal(f"header.{name}", value, "RESPONSE", endpoint, location="HEADER")
            if item is not None:
                response_signals.append(item)
        results.append(
            ExchangeFacts(
                observation=observation,
                endpoint=endpoint,
                action_name=action_name,
                action_reasons=tuple(action_reasons),
                request_signals=tuple(
                    sorted(request_signals, key=lambda item: (item.field, item.fingerprint))
                ),
                response_signals=tuple(
                    sorted(response_signals, key=lambda item: (item.field, item.fingerprint))
                ),
                states=tuple(sorted(states, key=lambda item: (item.field, item.value))),
            )
        )
    return results
