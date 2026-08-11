"""Evidence-backed resource ownership, control, sharing, and boundary reconstruction."""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from finsec.behavior.extraction import ExchangeFacts, ScalarSignal, extract_exchange_facts
from finsec.captures.domain import observation_supports_normal_behavior
from finsec.config.models import TargetDocument
from finsec.config.workspace import WorkspacePaths
from finsec.errors import FinsecError
from finsec.modeling.merge import stable_fingerprint
from finsec.modeling.models import (
    ActorObjectBaseline,
    Confidence,
    Endpoint,
    EndpointParameter,
    EndpointStore,
    KnowledgeStatus,
    ObjectAccessEvidence,
    ObservationStore,
)
from finsec.normalization.ownership import classify_ownership_scope_parameter
from finsec.utils.redaction import REDACTED
from finsec.utils.yaml_store import load_yaml, write_yaml


class BoundaryModel(BaseModel):
    """Reject drift in the canonical controlled-boundary artifact."""

    model_config = ConfigDict(extra="forbid")


class BoundaryEntityKind(StrEnum):
    ACTOR = "ACTOR"
    RESOURCE = "RESOURCE"
    TENANT = "TENANT"
    SESSION = "SESSION"
    CAPTURE = "CAPTURE"
    OPERATION = "OPERATION"
    STATE = "STATE"
    BOUNDARY = "BOUNDARY"


class BoundaryRelationshipType(StrEnum):
    ACTOR_OBSERVED_RESOURCE = "ACTOR_OBSERVED_RESOURCE"
    ACTOR_CREATED_RESOURCE = "ACTOR_CREATED_RESOURCE"
    ACTOR_CONTROLS_RESOURCE = "ACTOR_CONTROLS_RESOURCE"
    ACTOR_OWNS_RESOURCE = "ACTOR_OWNS_RESOURCE"
    RESOURCE_PARENT_OF = "RESOURCE_PARENT_OF"
    RESOURCE_CHILD_OF = "RESOURCE_CHILD_OF"
    RESOURCE_CONTAINS = "RESOURCE_CONTAINS"
    TENANT_CONTAINS_RESOURCE = "TENANT_CONTAINS_RESOURCE"
    RESOURCE_BOUND_TO_TENANT = "RESOURCE_BOUND_TO_TENANT"
    RESOURCE_BOUND_TO_ACTOR = "RESOURCE_BOUND_TO_ACTOR"
    RESOURCE_BOUND_TO_SESSION = "RESOURCE_BOUND_TO_SESSION"
    PRODUCED_OBJECT_ID = "PRODUCED_OBJECT_ID"
    CONSUMED_OBJECT_ID = "CONSUMED_OBJECT_ID"
    SHARED_RESOURCE = "SHARED_RESOURCE"
    PUBLIC_RESOURCE = "PUBLIC_RESOURCE"
    UNKNOWN_BINDING = "UNKNOWN_BINDING"


class RelationshipEvidenceType(StrEnum):
    NORMAL_BEHAVIOR_OBSERVATION = "NORMAL_BEHAVIOR_OBSERVATION"
    SUCCESSFUL_CREATE_RESPONSE = "SUCCESSFUL_CREATE_RESPONSE"
    PRODUCER_CONSUMER_CONTINUITY = "PRODUCER_CONSUMER_CONTINUITY"
    EXPLICIT_TENANT_METADATA = "EXPLICIT_TENANT_METADATA"
    EXPLICIT_ACTOR_METADATA = "EXPLICIT_ACTOR_METADATA"
    PATH_STRUCTURE = "PATH_STRUCTURE"
    OBSERVED_PARENT_CONTINUITY = "OBSERVED_PARENT_CONTINUITY"
    MULTI_ACTOR_NORMAL_ACCESS = "MULTI_ACTOR_NORMAL_ACCESS"
    ANONYMOUS_NORMAL_ACCESS = "ANONYMOUS_NORMAL_ACCESS"
    CONFIGURED_PUBLIC_SHARED_SCOPE = "CONFIGURED_PUBLIC_SHARED_SCOPE"
    NO_STRONG_BINDING_EVIDENCE = "NO_STRONG_BINDING_EVIDENCE"


class RelationshipEntity(BoundaryModel):
    """Secret-free stable reference to one relationship endpoint."""

    kind: BoundaryEntityKind
    id: str
    type: str | None = None
    reference: str


class TemporalSupport(BoundaryModel):
    """Retain the exact ordering basis used by a cross-observation inference."""

    source_observation_id: str
    target_observation_id: str
    basis: Literal["TIMESTAMP", "CAPTURE_SEQUENCE"]
    source_timestamp: datetime | None = None
    target_timestamp: datetime | None = None


class EvidenceBackedRelationship(BoundaryModel):
    """One typed relationship with support, provenance, ambiguity, and counterevidence."""

    id: str
    relationship_type: BoundaryRelationshipType
    source: RelationshipEntity
    target: RelationshipEntity
    supporting_observation_ids: list[str] = Field(default_factory=list)
    supporting_capture_ids: list[str] = Field(default_factory=list)
    supporting_actor_ids: list[str] = Field(default_factory=list)
    evidence_types: list[RelationshipEvidenceType] = Field(default_factory=list)
    provenance: list[str] = Field(default_factory=list)
    confidence: Confidence = Confidence.LOW
    direct: bool = False
    inference_rule: str
    inference_version: Literal[1] = 1
    counterevidence: list[str] = Field(default_factory=list)
    ambiguity: list[str] = Field(default_factory=list)
    capture_boundaries: list[str] = Field(default_factory=list)
    session_boundaries: list[str] = Field(default_factory=list)
    temporal_support: list[TemporalSupport] = Field(default_factory=list)
    knowledge_status: KnowledgeStatus = KnowledgeStatus.INFERRED


class ResourceIdentity(BoundaryModel):
    """Parent-aware concrete resource identity reconstructed from redacted evidence."""

    id: str
    resource_type: str
    identifier_fingerprint: str
    identifier_value: str = Field(repr=False)
    reference: str
    parent_resource_id: str | None = None
    parent_resource_type: str | None = None
    parent_identifier_fingerprint: str | None = None
    route_family: str
    collection_route_family: str
    observations: list[str] = Field(default_factory=list)
    capture_ids: list[str] = Field(default_factory=list)
    session_ids: list[str] = Field(default_factory=list)
    actors: list[str] = Field(default_factory=list)
    identity_assumptions: list[str] = Field(default_factory=list)
    global_uniqueness_confirmed: bool = False


class ControlledBaseline(BoundaryModel):
    """A successful actor/subject operation backed by explicit control evidence."""

    id: str
    actor_id: str
    subject_resource_id: str
    subject_resource_type: str
    subject_identifier: str = Field(repr=False)
    parent_resource_id: str | None = None
    parent_resource_type: str | None = None
    parent_identifier: str | None = Field(default=None, repr=False)
    operation: Literal["READ", "CREATE", "UPDATE", "DELETE", "ACTION"]
    endpoint_id: str
    route_family: str
    collection_route_family: str
    host: str
    observation_id: str
    expected_status: int
    response_object_path: str | None = None
    authentication_present: bool
    authentication_type: str
    relationship_ids: list[str] = Field(default_factory=list)
    supporting_observation_ids: list[str] = Field(default_factory=list)
    capture_ids: list[str] = Field(default_factory=list)
    session_ids: list[str] = Field(default_factory=list)
    confidence: Confidence = Confidence.HIGH
    direct: bool = False
    inference_rule: str = "controlled-baseline-from-resource-control"
    inference_version: Literal[1] = 1
    counterevidence: list[str] = Field(default_factory=list)
    ambiguity: list[str] = Field(default_factory=list)
    eligible_for_authorization: bool = True


class ControlledOwnershipStore(BoundaryModel):
    """Versioned canonical ownership, boundary, and controlled-baseline artifact."""

    version: Literal[1] = 1
    generator: Literal["controlled-ownership-boundary-v1"] = (
        "controlled-ownership-boundary-v1"
    )
    source_fingerprint: str = ""
    resources: list[ResourceIdentity] = Field(default_factory=list)
    relationships: list[EvidenceBackedRelationship] = Field(default_factory=list)
    controlled_baselines: list[ControlledBaseline] = Field(default_factory=list)
    identity_assumptions: list[str] = Field(
        default_factory=lambda: [
            "Resource identifiers are parent-scoped whenever a concrete structural parent is "
            "observed; global uniqueness is never assumed from scalar equality alone.",
            "Cross-capture continuity requires the same controlled actor, resource type, "
            "parent-aware identity, compatible authentication type, endpoint family, and "
            "temporal ordering.",
        ]
    )


@dataclass(frozen=True)
class RelationshipBuildResult:
    resources: int
    relationships: int
    controlled_baselines: int


@dataclass(frozen=True)
class _PathNode:
    resource_type: str
    collection_index: int
    value_index: int | None
    parameter: str | None
    value: str | None


@dataclass(frozen=True)
class _PathHierarchy:
    nodes: tuple[_PathNode, ...]
    subject: _PathNode | None
    parent: _PathNode | None
    route_family: str
    collection_route_family: str


@dataclass(frozen=True)
class _Occurrence:
    facts: ExchangeFacts
    resource_id: str
    resource_type: str
    value: str
    fingerprint: str
    parent_resource_id: str | None
    parent_resource_type: str | None
    parent_value: str | None
    field: str
    direction: Literal["REQUEST", "RESPONSE"]
    response_object_path: str | None
    route_family: str
    collection_route_family: str


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
    "approve",
    "cancel",
    "change",
    "claim",
    "close",
    "complete",
    "confirm",
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
    "list",
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
    "resend",
    "return",
    "revoke",
    "rotate",
    "search",
    "settle",
    "status",
    "submit",
    "suspend",
    "transfer",
    "update",
    "verify",
    "withdraw",
}
IDENTITY_SELECTORS = {"current", "me", "mine", "own", "self"}
SCOPE_RESOURCE_TYPES = {"account", "customer", "organization", "owner", "tenant", "user"}
CONFIDENCE_RANK = {Confidence.LOW: 0, Confidence.MEDIUM: 1, Confidence.HIGH: 2}


def _type_key(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", value.lower())


def _snake(value: str) -> str:
    split = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", value)
    return re.sub(r"[^a-z0-9]+", "_", split.lower()).strip("_")


def _singular(value: str) -> str:
    if value.endswith("ies") and len(value) > 3:
        return f"{value[:-3]}y"
    if value.endswith("sses"):
        return value[:-2]
    if value.endswith("s") and not value.endswith(("ss", "us")):
        return value[:-1]
    return value


def _display_resource(value: str) -> str:
    return "".join(item[:1].upper() + item[1:] for item in _snake(value).split("_"))


def _is_version(value: str) -> bool:
    normalized = value.lower()
    return bool(re.fullmatch(r"v?\d+(?:\.\d+){0,2}", normalized))


def _placeholder(value: str) -> str | None:
    return value[1:-1] if value.startswith("{") and value.endswith("}") else None


def _is_collection(value: str, subject_key: str) -> bool:
    if _placeholder(value) is not None:
        return False
    normalized = _snake(value)
    if (
        not normalized
        or normalized in GENERIC_SEGMENTS
        or normalized in ACTION_SEGMENTS
        or normalized in IDENTITY_SELECTORS
        or _is_version(normalized)
    ):
        return False
    singular = _singular(normalized)
    return normalized.endswith("s") or _type_key(singular) == subject_key


def _parameter_name(resource_type: str) -> str:
    snake = _snake(resource_type)
    parts = snake.split("_")
    return parts[0] + "".join(item.title() for item in parts[1:]) + "Id"


def path_hierarchy(
    template_path: str,
    concrete_path: str,
    subject_resource: str,
) -> _PathHierarchy:
    """Reconstruct a structural resource chain without promoting it to ownership."""

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
        if _type_key(_singular(_snake(template[index]))) == subject_key
    ]
    subject_index = matching[-1] if matching else collection_indices[-1] if collection_indices else None
    nodes: list[_PathNode] = []
    value_positions: dict[int, str] = {}
    for position, collection_index in enumerate(collection_indices):
        next_collection = (
            collection_indices[position + 1]
            if position + 1 < len(collection_indices)
            else len(template)
        )
        resource_token = _singular(_snake(template[collection_index]))
        resource_type = _display_resource(resource_token)
        candidate = collection_index + 1
        value_index: int | None = None
        parameter: str | None = None
        value: str | None = None
        if candidate < len(template) and candidate < next_collection:
            candidate_token = _snake(template[candidate])
            candidate_parameter = _placeholder(template[candidate])
            candidate_is_action = (
                candidate_token in ACTION_SEGMENTS
                or candidate_token in IDENTITY_SELECTORS
                or _is_version(candidate_token)
            )
            if candidate_parameter is not None or not candidate_is_action:
                value_index = candidate
                parameter = candidate_parameter or _parameter_name(resource_type)
                candidate_value = concrete[candidate]
                value = None if _placeholder(candidate_value) is not None else candidate_value
                value_positions[candidate] = _snake(resource_type)
        nodes.append(
            _PathNode(
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
            family_segments.append("{" + _singular(_snake(previous)) + "}")
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
                if item.collection_index < subject.collection_index and item.value is not None
            ),
            None,
        )
    collection_end = subject.collection_index + 1 if subject is not None else len(family_segments)
    collection_route_family = "/" + "/".join(family_segments[:collection_end])
    return _PathHierarchy(
        nodes=tuple(nodes),
        subject=subject,
        parent=parent,
        route_family=route_family,
        collection_route_family=collection_route_family,
    )


def structural_parent_resource(endpoint: Endpoint) -> str | None:
    """Return the nested structural parent type, without asserting a control boundary."""

    hierarchy = path_hierarchy(endpoint.path, endpoint.path, endpoint.resource.type)
    return hierarchy.parent.resource_type if hierarchy.parent is not None else None


def _entity(
    kind: BoundaryEntityKind, identifier: str, reference: str, entity_type: str | None = None
) -> RelationshipEntity:
    return RelationshipEntity(kind=kind, id=identifier, type=entity_type, reference=reference)


def _actor_entity(actor: str) -> RelationshipEntity:
    return _entity(BoundaryEntityKind.ACTOR, f"ACTOR:{actor}", actor, "Actor")


def _operation_entity(facts: ExchangeFacts) -> RelationshipEntity:
    endpoint = facts.endpoint
    action = endpoint.action.name if endpoint is not None else facts.observation.method.lower()
    return _entity(
        BoundaryEntityKind.OPERATION,
        facts.observation.id,
        facts.observation.id,
        f"{facts.observation.method} {action}",
    )


def _resource_entity(resource: ResourceIdentity) -> RelationshipEntity:
    return _entity(
        BoundaryEntityKind.RESOURCE,
        resource.id,
        resource.reference,
        resource.resource_type,
    )


def _boundary_entity(name: str) -> RelationshipEntity:
    return _entity(BoundaryEntityKind.BOUNDARY, f"BOUNDARY:{name}", name, name)


def _capture_id(facts: ExchangeFacts) -> str | None:
    observation = facts.observation
    return observation.capture_id or observation.capture_identity


def _session_id(facts: ExchangeFacts) -> str | None:
    return facts.observation.session_identity


def _successful(facts: ExchangeFacts) -> bool:
    status = facts.observation.status_code
    return status is not None and 200 <= status < 300


def _operation(facts: ExchangeFacts) -> Literal["READ", "CREATE", "UPDATE", "DELETE", "ACTION"]:
    endpoint = facts.endpoint
    method = facts.observation.method
    if method in {"GET", "HEAD", "OPTIONS"} and not (endpoint and endpoint.state_change):
        return "READ"
    if method == "DELETE":
        return "DELETE"
    if method in {"PUT", "PATCH"}:
        return "UPDATE"
    if method == "POST" and endpoint is not None and endpoint.action.name in {"add", "create"}:
        return "CREATE"
    if facts.observation.status_code == 201 and method not in {"GET", "HEAD", "OPTIONS"}:
        return "CREATE"
    return "ACTION"


def _is_create(facts: ExchangeFacts, signal: ScalarSignal) -> bool:
    endpoint = facts.endpoint
    if endpoint is None or not _successful(facts) or signal.direction != "RESPONSE":
        return False
    if "[]" in signal.field or "[*]" in signal.field:
        return False
    if signal.fingerprint in {item.fingerprint for item in facts.request_signals}:
        return False
    if not signal.distinctive or signal.kind != "RESOURCE_IDENTIFIER":
        return False
    if facts.observation.status_code == 201 and facts.observation.method not in {
        "GET",
        "HEAD",
        "OPTIONS",
    }:
        return True
    return (
        facts.observation.method == "POST"
        and endpoint.state_change
        and endpoint.action.name in {"add", "create"}
    )


def _auth_compatible(source: ExchangeFacts, target: ExchangeFacts) -> bool:
    source_auth = source.observation.authentication
    target_auth = target.observation.authentication
    if not source_auth.present or not target_auth.present:
        return False
    return (
        source_auth.observed_type == target_auth.observed_type
        or "mixed" in {source_auth.observed_type, target_auth.observed_type}
    )


def _temporal_support(source: ExchangeFacts, target: ExchangeFacts) -> TemporalSupport | None:
    left = source.observation
    right = target.observation
    if left.timestamp is not None and right.timestamp is not None and right.timestamp >= left.timestamp:
        return TemporalSupport(
            source_observation_id=left.id,
            target_observation_id=right.id,
            basis="TIMESTAMP",
            source_timestamp=left.timestamp,
            target_timestamp=right.timestamp,
        )
    left_capture = _capture_id(source)
    right_capture = _capture_id(target)
    if (
        left_capture is not None
        and left_capture == right_capture
        and left.sequence_position is not None
        and right.sequence_position is not None
        and right.sequence_position > left.sequence_position
    ):
        return TemporalSupport(
            source_observation_id=left.id,
            target_observation_id=right.id,
            basis="CAPTURE_SEQUENCE",
            source_timestamp=left.timestamp,
            target_timestamp=right.timestamp,
        )
    return None


def _matching_signals(
    facts: ExchangeFacts, resource_type: str, direction: Literal["REQUEST", "RESPONSE"]
) -> list[ScalarSignal]:
    signals = facts.request_signals if direction == "REQUEST" else facts.response_signals
    wanted = _type_key(resource_type)
    return [
        item
        for item in signals
        if item.kind == "RESOURCE_IDENTIFIER"
        and item.resource_type is not None
        and _type_key(item.resource_type) == wanted
        and item.resource_role == "PRIMARY"
    ]


def _relationship_id(
    relationship_type: BoundaryRelationshipType,
    source: RelationshipEntity,
    target: RelationshipEntity,
) -> str:
    return "REL-" + stable_fingerprint(
        {"type": relationship_type, "source": source.id, "target": target.id}
    )[:16].upper()


def _resource_id(resource_type: str, fingerprint: str, parent_resource_id: str | None) -> str:
    return "RSC-" + stable_fingerprint(
        {"type": _type_key(resource_type), "value": fingerprint, "parent": parent_resource_id}
    )[:16].upper()


def _baseline_id(actor: str, resource_id: str, operation: str, observation_id: str) -> str:
    return "BASE-" + stable_fingerprint(
        {
            "actor": actor,
            "resource": resource_id,
            "operation": operation,
            "observation": observation_id,
        }
    )[:16].upper()


def _merge_confidence(left: Confidence, right: Confidence) -> Confidence:
    return left if CONFIDENCE_RANK[left] >= CONFIDENCE_RANK[right] else right


def reconstruct_controlled_ownership(
    workspace: WorkspacePaths,
    *,
    target: TargetDocument | None = None,
    observations: ObservationStore | None = None,
    endpoints: EndpointStore | None = None,
) -> tuple[ControlledOwnershipStore, EndpointStore, RelationshipBuildResult]:
    """Build canonical parent-aware relationships and deterministic endpoint projections."""

    try:
        target = target or TargetDocument.model_validate(load_yaml(workspace.target))
        observations = observations or ObservationStore.model_validate(load_yaml(workspace.observations))
        endpoints = endpoints or EndpointStore.model_validate(load_yaml(workspace.endpoints))
    except (OSError, ValidationError) as error:
        raise FinsecError(f"Cannot reconstruct controlled ownership evidence: {error}") from error

    facts = extract_exchange_facts(workspace, observations.observations, endpoints)
    controlled_actors = {
        item.id for item in target.accounts if item.ownership == "researcher"
    }
    resources: dict[str, dict[str, object]] = {}
    relationships: dict[tuple[str, str, str], dict[str, object]] = {}
    occurrences: list[_Occurrence] = []
    creates: list[_Occurrence] = []
    uses_by_resource: dict[str, list[_Occurrence]] = defaultdict(list)
    observed_actors: dict[str, set[str]] = defaultdict(set)
    anonymous_resources: set[str] = set()
    public_shared_resources: set[str] = set()

    def ensure_resource(
        resource_type: str,
        value: str,
        *,
        parent_resource_id: str | None,
        parent_resource_type: str | None,
        route_family: str,
        collection_route_family: str,
        facts_item: ExchangeFacts,
    ) -> str:
        fingerprint = stable_fingerprint({"value": value})
        identifier = _resource_id(resource_type, fingerprint, parent_resource_id)
        capture = _capture_id(facts_item)
        session = _session_id(facts_item)
        entry = resources.setdefault(
            identifier,
            {
                "id": identifier,
                "resource_type": resource_type,
                "identifier_fingerprint": fingerprint,
                "identifier_value": value,
                "reference": f"{resource_type}:{fingerprint[:12]}",
                "parent_resource_id": parent_resource_id,
                "parent_resource_type": parent_resource_type,
                "parent_identifier_fingerprint": (
                    resources[parent_resource_id]["identifier_fingerprint"]
                    if parent_resource_id in resources
                    else None
                ),
                "route_family": route_family,
                "collection_route_family": collection_route_family,
                "observations": set(),
                "capture_ids": set(),
                "session_ids": set(),
                "actors": set(),
                "identity_assumptions": {
                    (
                        "Composite identity includes the observed structural parent; the child "
                        "identifier is not assumed globally unique."
                        if parent_resource_id is not None
                        else "No structural parent was observed; scalar identity remains local "
                        "to the resource type."
                    )
                },
                "global_uniqueness_confirmed": False,
            },
        )
        entry["observations"].add(facts_item.observation.id)  # type: ignore[union-attr]
        entry["actors"].add(facts_item.observation.actor)  # type: ignore[union-attr]
        if capture is not None:
            entry["capture_ids"].add(capture)  # type: ignore[union-attr]
        if session is not None:
            entry["session_ids"].add(session)  # type: ignore[union-attr]
        return identifier

    def add_relationship(
        relationship_type: BoundaryRelationshipType,
        source: RelationshipEntity,
        target_entity: RelationshipEntity,
        *,
        facts_items: list[ExchangeFacts],
        evidence_type: RelationshipEvidenceType,
        provenance: str,
        confidence: Confidence,
        direct: bool,
        inference_rule: str,
        temporal: list[TemporalSupport] | None = None,
        ambiguity: list[str] | None = None,
        counterevidence: list[str] | None = None,
    ) -> str:
        key = (relationship_type.value, source.id, target_entity.id)
        identifier = _relationship_id(relationship_type, source, target_entity)
        entry = relationships.setdefault(
            key,
            {
                "id": identifier,
                "relationship_type": relationship_type,
                "source": source,
                "target": target_entity,
                "supporting_observation_ids": set(),
                "supporting_capture_ids": set(),
                "supporting_actor_ids": set(),
                "evidence_types": set(),
                "provenance": set(),
                "confidence": confidence,
                "direct": direct,
                "inference_rule": inference_rule,
                "inference_version": 1,
                "counterevidence": set(),
                "ambiguity": set(),
                "capture_boundaries": set(),
                "session_boundaries": set(),
                "temporal_support": {},
                "knowledge_status": (
                    KnowledgeStatus.OBSERVED if direct else KnowledgeStatus.INFERRED
                ),
            },
        )
        entry["confidence"] = _merge_confidence(entry["confidence"], confidence)  # type: ignore[arg-type]
        entry["direct"] = bool(entry["direct"]) or direct
        entry["evidence_types"].add(evidence_type)  # type: ignore[union-attr]
        entry["provenance"].add(provenance)  # type: ignore[union-attr]
        entry["ambiguity"].update(ambiguity or [])  # type: ignore[union-attr]
        entry["counterevidence"].update(counterevidence or [])  # type: ignore[union-attr]
        for facts_item in facts_items:
            observation = facts_item.observation
            entry["supporting_observation_ids"].add(observation.id)  # type: ignore[union-attr]
            entry["supporting_actor_ids"].add(observation.actor)  # type: ignore[union-attr]
            capture = _capture_id(facts_item)
            session = _session_id(facts_item)
            if capture is not None:
                entry["supporting_capture_ids"].add(capture)  # type: ignore[union-attr]
                entry["capture_boundaries"].add(capture)  # type: ignore[union-attr]
            if session is not None:
                entry["session_boundaries"].add(session)  # type: ignore[union-attr]
        for item in temporal or []:
            temporal_key = (item.source_observation_id, item.target_observation_id, item.basis)
            entry["temporal_support"][temporal_key] = item  # type: ignore[index]
        return identifier

    eligible_facts = [
        item
        for item in facts
        if item.endpoint is not None
        and item.endpoint.disposition == "ACTIVE"
        and item.observation.source != "OPENAPI"
        and observation_supports_normal_behavior(item.observation)
    ]
    for facts_item in eligible_facts:
        endpoint = facts_item.endpoint
        assert endpoint is not None
        hierarchy = path_hierarchy(endpoint.path, facts_item.observation.path, endpoint.resource.type)
        parent_id: str | None = None
        parent_type: str | None = None
        parent_value: str | None = None
        node_ids: dict[int, str] = {}
        for node in hierarchy.nodes:
            if node.value is None or node.value == REDACTED:
                continue
            node_id = ensure_resource(
                node.resource_type,
                node.value,
                parent_resource_id=parent_id,
                parent_resource_type=parent_type,
                route_family=hierarchy.route_family,
                collection_route_family=hierarchy.collection_route_family,
                facts_item=facts_item,
            )
            node_ids[node.collection_index] = node_id
            if parent_id is not None:
                parent_resource = ResourceIdentity.model_validate(
                    {
                        **resources[parent_id],
                        "observations": sorted(resources[parent_id]["observations"]),
                        "capture_ids": sorted(resources[parent_id]["capture_ids"]),
                        "session_ids": sorted(resources[parent_id]["session_ids"]),
                        "actors": sorted(resources[parent_id]["actors"]),
                        "identity_assumptions": sorted(resources[parent_id]["identity_assumptions"]),
                    }
                )
                child_resource = ResourceIdentity.model_validate(
                    {
                        **resources[node_id],
                        "observations": sorted(resources[node_id]["observations"]),
                        "capture_ids": sorted(resources[node_id]["capture_ids"]),
                        "session_ids": sorted(resources[node_id]["session_ids"]),
                        "actors": sorted(resources[node_id]["actors"]),
                        "identity_assumptions": sorted(resources[node_id]["identity_assumptions"]),
                    }
                )
                add_relationship(
                    BoundaryRelationshipType.RESOURCE_PARENT_OF,
                    _resource_entity(parent_resource),
                    _resource_entity(child_resource),
                    facts_items=[facts_item],
                    evidence_type=RelationshipEvidenceType.PATH_STRUCTURE,
                    provenance="nested route structure",
                    confidence=Confidence.MEDIUM,
                    direct=False,
                    inference_rule="structural-parent-from-nested-route",
                    ambiguity=["Nested route structure establishes scope, not ownership."],
                )
                add_relationship(
                    BoundaryRelationshipType.RESOURCE_CHILD_OF,
                    _resource_entity(child_resource),
                    _resource_entity(parent_resource),
                    facts_items=[facts_item],
                    evidence_type=RelationshipEvidenceType.PATH_STRUCTURE,
                    provenance="nested route structure",
                    confidence=Confidence.MEDIUM,
                    direct=False,
                    inference_rule="structural-child-from-nested-route",
                    ambiguity=["Nested route structure establishes scope, not ownership."],
                )
            parent_id = node_id
            parent_type = node.resource_type
            parent_value = node.value

        subject_type = (
            hierarchy.subject.resource_type if hierarchy.subject is not None else endpoint.resource.type
        )
        immediate_parent_id = (
            node_ids.get(hierarchy.parent.collection_index)
            if hierarchy.parent is not None
            else None
        )
        immediate_parent_type = hierarchy.parent.resource_type if hierarchy.parent else None
        immediate_parent_value = hierarchy.parent.value if hierarchy.parent else None
        signal_occurrences: list[_Occurrence] = []
        for direction in ("REQUEST", "RESPONSE"):
            for signal in _matching_signals(facts_item, subject_type, direction):
                resource_id = ensure_resource(
                    subject_type,
                    signal.value,
                    parent_resource_id=immediate_parent_id,
                    parent_resource_type=immediate_parent_type,
                    route_family=hierarchy.route_family,
                    collection_route_family=hierarchy.collection_route_family,
                    facts_item=facts_item,
                )
                response_path = signal.field if direction == "RESPONSE" else None
                occurrence = _Occurrence(
                    facts=facts_item,
                    resource_id=resource_id,
                    resource_type=subject_type,
                    value=signal.value,
                    fingerprint=signal.fingerprint,
                    parent_resource_id=immediate_parent_id,
                    parent_resource_type=immediate_parent_type,
                    parent_value=immediate_parent_value,
                    field=signal.field,
                    direction=direction,
                    response_object_path=response_path,
                    route_family=hierarchy.route_family,
                    collection_route_family=hierarchy.collection_route_family,
                )
                occurrences.append(occurrence)
                signal_occurrences.append(occurrence)
                if direction == "REQUEST":
                    uses_by_resource[resource_id].append(occurrence)
                    resource = ResourceIdentity.model_validate(
                        {
                            **resources[resource_id],
                            "observations": sorted(resources[resource_id]["observations"]),
                            "capture_ids": sorted(resources[resource_id]["capture_ids"]),
                            "session_ids": sorted(resources[resource_id]["session_ids"]),
                            "actors": sorted(resources[resource_id]["actors"]),
                            "identity_assumptions": sorted(resources[resource_id]["identity_assumptions"]),
                        }
                    )
                    add_relationship(
                        BoundaryRelationshipType.CONSUMED_OBJECT_ID,
                        _resource_entity(resource),
                        _operation_entity(facts_item),
                        facts_items=[facts_item],
                        evidence_type=RelationshipEvidenceType.NORMAL_BEHAVIOR_OBSERVATION,
                        provenance=signal.field,
                        confidence=Confidence.HIGH,
                        direct=True,
                        inference_rule="request-consumed-typed-object-id",
                    )
                elif _is_create(facts_item, signal):
                    creates.append(occurrence)

        if not _successful(facts_item):
            continue
        actor = facts_item.observation.actor
        for resource_id in sorted({item.resource_id for item in signal_occurrences} | set(node_ids.values())):
            resource = ResourceIdentity.model_validate(
                {
                    **resources[resource_id],
                    "observations": sorted(resources[resource_id]["observations"]),
                    "capture_ids": sorted(resources[resource_id]["capture_ids"]),
                    "session_ids": sorted(resources[resource_id]["session_ids"]),
                    "actors": sorted(resources[resource_id]["actors"]),
                    "identity_assumptions": sorted(resources[resource_id]["identity_assumptions"]),
                }
            )
            add_relationship(
                BoundaryRelationshipType.ACTOR_OBSERVED_RESOURCE,
                _actor_entity(actor),
                _resource_entity(resource),
                facts_items=[facts_item],
                evidence_type=RelationshipEvidenceType.NORMAL_BEHAVIOR_OBSERVATION,
                provenance="successful normal-behavior operation",
                confidence=Confidence.LOW,
                direct=True,
                inference_rule="actor-observed-resource",
                ambiguity=["Observation does not establish ownership or exclusive control."],
            )
            observed_actors[resource_id].add(actor)
            if actor.upper() in {"ANONYMOUS", "UNKNOWN"} or not facts_item.observation.authentication.present:
                anonymous_resources.add(resource_id)

        if hierarchy.subject is not None and hierarchy.subject.parameter is not None:
            classification = classify_ownership_scope_parameter(
                hierarchy.subject.parameter, target.analysis.ownership_inference
            )
            if classification == "PUBLIC_SHARED_SCOPE":
                public_shared_resources.update(
                    item.resource_id for item in signal_occurrences
                )

        response_scopes = [
            item
            for item in facts_item.response_signals
            if item.kind == "RESOURCE_IDENTIFIER"
            and item.resource_type is not None
            and _type_key(item.resource_type) in SCOPE_RESOURCE_TYPES
            and item.resource_role == "SCOPE"
        ]
        subject_resources = sorted({item.resource_id for item in signal_occurrences})
        for scope_signal in response_scopes:
            tenant_type = _display_resource(scope_signal.resource_type or "tenant")
            tenant_id = ensure_resource(
                tenant_type,
                scope_signal.value,
                parent_resource_id=None,
                parent_resource_type=None,
                route_family=hierarchy.route_family,
                collection_route_family=hierarchy.collection_route_family,
                facts_item=facts_item,
            )
            tenant_resource = ResourceIdentity.model_validate(
                {
                    **resources[tenant_id],
                    "observations": sorted(resources[tenant_id]["observations"]),
                    "capture_ids": sorted(resources[tenant_id]["capture_ids"]),
                    "session_ids": sorted(resources[tenant_id]["session_ids"]),
                    "actors": sorted(resources[tenant_id]["actors"]),
                    "identity_assumptions": sorted(resources[tenant_id]["identity_assumptions"]),
                }
            )
            for resource_id in subject_resources:
                subject_resource = ResourceIdentity.model_validate(
                    {
                        **resources[resource_id],
                        "observations": sorted(resources[resource_id]["observations"]),
                        "capture_ids": sorted(resources[resource_id]["capture_ids"]),
                        "session_ids": sorted(resources[resource_id]["session_ids"]),
                        "actors": sorted(resources[resource_id]["actors"]),
                        "identity_assumptions": sorted(resources[resource_id]["identity_assumptions"]),
                    }
                )
                add_relationship(
                    BoundaryRelationshipType.RESOURCE_BOUND_TO_TENANT,
                    _resource_entity(subject_resource),
                    _entity(
                        BoundaryEntityKind.TENANT,
                        tenant_resource.id,
                        tenant_resource.reference,
                        tenant_resource.resource_type,
                    ),
                    facts_items=[facts_item],
                    evidence_type=RelationshipEvidenceType.EXPLICIT_TENANT_METADATA,
                    provenance=scope_signal.field,
                    confidence=Confidence.HIGH,
                    direct=True,
                    inference_rule="explicit-tenant-field-binding",
                    ambiguity=[
                        "Tenant metadata does not map to an actor unless actor-to-tenant identity "
                        "is independently established."
                    ],
                )
                if scope_signal.value.casefold() == actor.casefold():
                    add_relationship(
                        BoundaryRelationshipType.ACTOR_OWNS_RESOURCE,
                        _actor_entity(actor),
                        _resource_entity(subject_resource),
                        facts_items=[facts_item],
                        evidence_type=RelationshipEvidenceType.EXPLICIT_ACTOR_METADATA,
                        provenance=scope_signal.field,
                        confidence=Confidence.HIGH,
                        direct=True,
                        inference_rule="explicit-owner-field-matches-controlled-actor",
                    )

    baseline_entries: dict[str, ControlledBaseline] = {}
    for created in sorted(creates, key=lambda item: item.facts.observation.id):
        actor = created.facts.observation.actor
        if actor not in controlled_actors or not created.facts.observation.authentication.present:
            continue
        resource = ResourceIdentity.model_validate(
            {
                **resources[created.resource_id],
                "observations": sorted(resources[created.resource_id]["observations"]),
                "capture_ids": sorted(resources[created.resource_id]["capture_ids"]),
                "session_ids": sorted(resources[created.resource_id]["session_ids"]),
                "actors": sorted(resources[created.resource_id]["actors"]),
                "identity_assumptions": sorted(resources[created.resource_id]["identity_assumptions"]),
            }
        )
        produced_id = add_relationship(
            BoundaryRelationshipType.PRODUCED_OBJECT_ID,
            _operation_entity(created.facts),
            _resource_entity(resource),
            facts_items=[created.facts],
            evidence_type=RelationshipEvidenceType.SUCCESSFUL_CREATE_RESPONSE,
            provenance=created.field,
            confidence=Confidence.HIGH,
            direct=True,
            inference_rule="successful-mutation-produced-output-only-resource-id",
        )
        created_id = add_relationship(
            BoundaryRelationshipType.ACTOR_CREATED_RESOURCE,
            _actor_entity(actor),
            _resource_entity(resource),
            facts_items=[created.facts],
            evidence_type=RelationshipEvidenceType.SUCCESSFUL_CREATE_RESPONSE,
            provenance=created.field,
            confidence=Confidence.HIGH,
            direct=True,
            inference_rule="controlled-actor-created-output-only-resource",
            ambiguity=[
                "Created-by evidence establishes production, not permanent legal or business "
                "ownership."
            ],
        )
        for used in sorted(
            uses_by_resource.get(created.resource_id, []),
            key=lambda item: item.facts.observation.id,
        ):
            if used.facts.observation.id == created.facts.observation.id:
                continue
            if used.facts.observation.actor != actor or not _successful(used.facts):
                continue
            if used.collection_route_family != created.collection_route_family:
                continue
            temporal = _temporal_support(created.facts, used.facts)
            if temporal is None or not _auth_compatible(created.facts, used.facts):
                continue
            cross_capture = _capture_id(created.facts) != _capture_id(used.facts)
            ambiguity = []
            if cross_capture:
                ambiguity.append(
                    "Cross-capture continuity is inferred from the same controlled actor, "
                    "parent-aware resource identity, authentication type, route family, and "
                    "timestamp ordering; capture boundaries remain explicit."
                )
            control_id = add_relationship(
                BoundaryRelationshipType.ACTOR_CONTROLS_RESOURCE,
                _actor_entity(actor),
                _resource_entity(resource),
                facts_items=[created.facts, used.facts],
                evidence_type=RelationshipEvidenceType.PRODUCER_CONSUMER_CONTINUITY,
                provenance=f"{created.field} -> {used.field}",
                confidence=Confidence.HIGH,
                direct=False,
                inference_rule="create-produced-id-followed-by-same-actor-use",
                temporal=[temporal],
                ambiguity=ambiguity,
            )
            add_relationship(
                BoundaryRelationshipType.RESOURCE_BOUND_TO_ACTOR,
                _resource_entity(resource),
                _actor_entity(actor),
                facts_items=[created.facts, used.facts],
                evidence_type=RelationshipEvidenceType.PRODUCER_CONSUMER_CONTINUITY,
                provenance=f"{created.field} -> {used.field}",
                confidence=Confidence.HIGH,
                direct=False,
                inference_rule="resource-control-continuity-binds-actor",
                temporal=[temporal],
                ambiguity=ambiguity,
            )
            if created.parent_resource_id is not None:
                parent_resource = ResourceIdentity.model_validate(
                    {
                        **resources[created.parent_resource_id],
                        "observations": sorted(resources[created.parent_resource_id]["observations"]),
                        "capture_ids": sorted(resources[created.parent_resource_id]["capture_ids"]),
                        "session_ids": sorted(resources[created.parent_resource_id]["session_ids"]),
                        "actors": sorted(resources[created.parent_resource_id]["actors"]),
                        "identity_assumptions": sorted(resources[created.parent_resource_id]["identity_assumptions"]),
                    }
                )
                add_relationship(
                    BoundaryRelationshipType.RESOURCE_PARENT_OF,
                    _resource_entity(parent_resource),
                    _resource_entity(resource),
                    facts_items=[created.facts, used.facts],
                    evidence_type=RelationshipEvidenceType.OBSERVED_PARENT_CONTINUITY,
                    provenance="create and subsequent use retained the same parent identity",
                    confidence=Confidence.HIGH,
                    direct=False,
                    inference_rule="parent-binding-retained-across-lifecycle",
                    temporal=[temporal],
                )
            response_path = next(
                (
                    item.field
                    for item in occurrences
                    if item.facts.observation.id == used.facts.observation.id
                    and item.resource_id == used.resource_id
                    and item.direction == "RESPONSE"
                ),
                None,
            )
            operation = _operation(used.facts)
            baseline_identifier = _baseline_id(
                actor, used.resource_id, operation, used.facts.observation.id
            )
            capture_ids = sorted(
                {
                    value
                    for value in (_capture_id(created.facts), _capture_id(used.facts))
                    if value is not None
                }
            )
            session_ids = sorted(
                {
                    value
                    for value in (_session_id(created.facts), _session_id(used.facts))
                    if value is not None
                }
            )
            baseline_entries[baseline_identifier] = ControlledBaseline(
                id=baseline_identifier,
                actor_id=actor,
                subject_resource_id=used.resource_id,
                subject_resource_type=used.resource_type,
                subject_identifier=used.value,
                parent_resource_id=used.parent_resource_id,
                parent_resource_type=used.parent_resource_type,
                parent_identifier=used.parent_value,
                operation=operation,
                endpoint_id=used.facts.endpoint.id if used.facts.endpoint is not None else "UNKNOWN",
                route_family=used.route_family,
                collection_route_family=used.collection_route_family,
                host=used.facts.observation.host,
                observation_id=used.facts.observation.id,
                expected_status=used.facts.observation.status_code or 0,
                response_object_path=response_path,
                authentication_present=used.facts.observation.authentication.present,
                authentication_type=used.facts.observation.authentication.observed_type,
                relationship_ids=sorted({produced_id, created_id, control_id}),
                supporting_observation_ids=sorted(
                    {created.facts.observation.id, used.facts.observation.id}
                ),
                capture_ids=capture_ids,
                session_ids=session_ids,
                ambiguity=ambiguity,
            )

    strong_by_resource = {
        entry["target"].id
        for entry in relationships.values()
        if entry["relationship_type"]
        in {
            BoundaryRelationshipType.ACTOR_CREATED_RESOURCE,
            BoundaryRelationshipType.ACTOR_CONTROLS_RESOURCE,
            BoundaryRelationshipType.ACTOR_OWNS_RESOURCE,
            BoundaryRelationshipType.RESOURCE_BOUND_TO_TENANT,
        }
    }
    shared_resources: set[str] = set(public_shared_resources)
    for resource_id, actors in observed_actors.items():
        controlled = sorted(actors & controlled_actors)
        if len(controlled) >= 2:
            shared_resources.add(resource_id)
            resource = ResourceIdentity.model_validate(
                {
                    **resources[resource_id],
                    "observations": sorted(resources[resource_id]["observations"]),
                    "capture_ids": sorted(resources[resource_id]["capture_ids"]),
                    "session_ids": sorted(resources[resource_id]["session_ids"]),
                    "actors": sorted(resources[resource_id]["actors"]),
                    "identity_assumptions": sorted(resources[resource_id]["identity_assumptions"]),
                }
            )
            supporting = [
                item
                for item in eligible_facts
                if item.observation.actor in controlled
                and item.observation.id in resources[resource_id]["observations"]
            ]
            add_relationship(
                BoundaryRelationshipType.SHARED_RESOURCE,
                _resource_entity(resource),
                _boundary_entity("SHARED"),
                facts_items=supporting,
                evidence_type=RelationshipEvidenceType.MULTI_ACTOR_NORMAL_ACCESS,
                provenance="same parent-aware resource observed by multiple controlled actors",
                confidence=Confidence.HIGH,
                direct=False,
                inference_rule="multi-actor-normal-access-counterevidence",
                counterevidence=[
                    "Normal access by multiple controlled actors is counterevidence against "
                    "exclusive actor ownership."
                ],
            )
    for resource_id in sorted(public_shared_resources - set(observed_actors)):
        shared_resources.add(resource_id)
    for resource_id in sorted(public_shared_resources):
        resource = ResourceIdentity.model_validate(
            {
                **resources[resource_id],
                "observations": sorted(resources[resource_id]["observations"]),
                "capture_ids": sorted(resources[resource_id]["capture_ids"]),
                "session_ids": sorted(resources[resource_id]["session_ids"]),
                "actors": sorted(resources[resource_id]["actors"]),
                "identity_assumptions": sorted(resources[resource_id]["identity_assumptions"]),
            }
        )
        supporting = [
            item
            for item in eligible_facts
            if item.observation.id in resources[resource_id]["observations"]
        ]
        add_relationship(
            BoundaryRelationshipType.SHARED_RESOURCE,
            _resource_entity(resource),
            _boundary_entity("SHARED"),
            facts_items=supporting,
            evidence_type=RelationshipEvidenceType.CONFIGURED_PUBLIC_SHARED_SCOPE,
            provenance="target ownership-inference public/shared parameter classification",
            confidence=Confidence.HIGH,
            direct=False,
            inference_rule="configured-public-shared-scope",
            counterevidence=["Configured public/shared scope cannot establish actor ownership."],
        )
    for resource_id in sorted(anonymous_resources):
        resource = ResourceIdentity.model_validate(
            {
                **resources[resource_id],
                "observations": sorted(resources[resource_id]["observations"]),
                "capture_ids": sorted(resources[resource_id]["capture_ids"]),
                "session_ids": sorted(resources[resource_id]["session_ids"]),
                "actors": sorted(resources[resource_id]["actors"]),
                "identity_assumptions": sorted(resources[resource_id]["identity_assumptions"]),
            }
        )
        supporting = [
            item
            for item in eligible_facts
            if item.observation.id in resources[resource_id]["observations"]
            and (
                item.observation.actor.upper() in {"ANONYMOUS", "UNKNOWN"}
                or not item.observation.authentication.present
            )
        ]
        add_relationship(
            BoundaryRelationshipType.PUBLIC_RESOURCE,
            _resource_entity(resource),
            _boundary_entity("PUBLIC"),
            facts_items=supporting,
            evidence_type=RelationshipEvidenceType.ANONYMOUS_NORMAL_ACCESS,
            provenance="successful normal access without request authentication",
            confidence=Confidence.MEDIUM,
            direct=True,
            inference_rule="anonymous-normal-access-counterevidence",
            ambiguity=["Observed anonymous reachability does not prove intended public policy."],
        )

    for key, entry in relationships.items():
        target_id = entry["target"].id
        if target_id not in shared_resources and target_id not in anonymous_resources:
            continue
        if entry["relationship_type"] in {
            BoundaryRelationshipType.ACTOR_CREATED_RESOURCE,
            BoundaryRelationshipType.ACTOR_CONTROLS_RESOURCE,
            BoundaryRelationshipType.ACTOR_OWNS_RESOURCE,
            BoundaryRelationshipType.RESOURCE_BOUND_TO_ACTOR,
        }:
            entry["counterevidence"].add(  # type: ignore[union-attr]
                "The same resource has shared/public normal-access evidence; exclusive actor "
                "binding is not established."
            )
    for baseline_id, baseline in list(baseline_entries.items()):
        if baseline.subject_resource_id in shared_resources | anonymous_resources:
            baseline_entries[baseline_id] = baseline.model_copy(
                update={
                    "eligible_for_authorization": False,
                    "counterevidence": [
                        "Shared or public normal-access evidence prevents exclusive actor-baseline "
                        "use."
                    ],
                }
            )

    for resource_id in sorted(resources):
        if resource_id in strong_by_resource | shared_resources | anonymous_resources:
            continue
        resource = ResourceIdentity.model_validate(
            {
                **resources[resource_id],
                "observations": sorted(resources[resource_id]["observations"]),
                "capture_ids": sorted(resources[resource_id]["capture_ids"]),
                "session_ids": sorted(resources[resource_id]["session_ids"]),
                "actors": sorted(resources[resource_id]["actors"]),
                "identity_assumptions": sorted(resources[resource_id]["identity_assumptions"]),
            }
        )
        supporting = [
            item
            for item in eligible_facts
            if item.observation.id in resources[resource_id]["observations"]
        ]
        add_relationship(
            BoundaryRelationshipType.UNKNOWN_BINDING,
            _resource_entity(resource),
            _boundary_entity("UNKNOWN"),
            facts_items=supporting,
            evidence_type=RelationshipEvidenceType.NO_STRONG_BINDING_EVIDENCE,
            provenance="no strong ownership, control, sharing, or public rule matched",
            confidence=Confidence.LOW,
            direct=False,
            inference_rule="fail-closed-unknown-binding",
            ambiguity=["Observed access alone is insufficient to establish ownership."],
        )

    resource_models = [
        ResourceIdentity.model_validate(
            {
                **entry,
                "observations": sorted(entry["observations"]),
                "capture_ids": sorted(entry["capture_ids"]),
                "session_ids": sorted(entry["session_ids"]),
                "actors": sorted(entry["actors"]),
                "identity_assumptions": sorted(entry["identity_assumptions"]),
            }
        )
        for _identifier, entry in sorted(resources.items())
    ]
    relationship_models = [
        EvidenceBackedRelationship.model_validate(
            {
                **entry,
                "supporting_observation_ids": sorted(entry["supporting_observation_ids"]),
                "supporting_capture_ids": sorted(entry["supporting_capture_ids"]),
                "supporting_actor_ids": sorted(entry["supporting_actor_ids"]),
                "evidence_types": sorted(entry["evidence_types"]),
                "provenance": sorted(entry["provenance"]),
                "counterevidence": sorted(entry["counterevidence"]),
                "ambiguity": sorted(entry["ambiguity"]),
                "capture_boundaries": sorted(entry["capture_boundaries"]),
                "session_boundaries": sorted(entry["session_boundaries"]),
                "temporal_support": [
                    value for _key, value in sorted(entry["temporal_support"].items())
                ],
            }
        )
        for _key, entry in sorted(relationships.items())
    ]
    source_fingerprint = stable_fingerprint(
        {
            "target": {
                "accounts": [
                    {"id": item.id, "ownership": item.ownership}
                    for item in target.accounts
                ],
                "ownership_inference": target.analysis.ownership_inference.model_dump(mode="json"),
            },
            "observations": observations.model_dump(mode="json", exclude_none=True),
            "endpoints": endpoints.model_dump(mode="json", exclude_none=True),
        }
    )
    store = ControlledOwnershipStore(
        source_fingerprint=source_fingerprint,
        resources=resource_models,
        relationships=relationship_models,
        controlled_baselines=sorted(baseline_entries.values(), key=lambda item: item.id),
    )
    projected = project_controlled_ownership(endpoints, store)
    write_yaml(workspace.controlled_ownership, store.model_dump(mode="json", exclude_none=True))
    return (
        store,
        projected,
        RelationshipBuildResult(
            resources=len(store.resources),
            relationships=len(store.relationships),
            controlled_baselines=len(store.controlled_baselines),
        ),
    )


def _endpoint_subject_parameter(endpoint: Endpoint) -> EndpointParameter | None:
    hierarchy = path_hierarchy(endpoint.path, endpoint.path, endpoint.resource.type)
    parameter = hierarchy.subject.parameter if hierarchy.subject is not None else None
    if parameter is None:
        return None
    return next(
        (
            item
            for item in endpoint.parameters
            if item.location == "path"
            and item.name == parameter
            and item.semantic_type == "object_identifier"
            and item.client_controlled
        ),
        None,
    )


def controlled_binding_for_endpoint(
    store: ControlledOwnershipStore,
    endpoint: Endpoint,
    identifier: str | None = None,
) -> ObjectAccessEvidence | None:
    """Project canonical controlled baselines onto one endpoint authorization surface."""

    subject_parameter = _endpoint_subject_parameter(endpoint)
    wanted_identifier = identifier or (subject_parameter.name if subject_parameter else None)
    if wanted_identifier is None:
        return None
    hierarchy = path_hierarchy(endpoint.path, endpoint.path, endpoint.resource.type)
    operation = {
        "GET": "READ",
        "HEAD": "READ",
        "PUT": "UPDATE",
        "PATCH": "UPDATE",
        "DELETE": "DELETE",
    }.get(endpoint.method, "ACTION")
    candidates = [
        item
        for item in store.controlled_baselines
        if item.eligible_for_authorization
        and _type_key(item.subject_resource_type) == _type_key(endpoint.resource.type)
        and item.operation == operation
        and item.collection_route_family == hierarchy.collection_route_family
        and item.host in endpoint.hosts
        and item.authentication_present
    ]
    actors = {item.actor_id for item in candidates}
    resources = {item.subject_resource_id for item in candidates}
    if len(actors) < 2 or len(resources) < 2:
        return None
    baselines = [
        ActorObjectBaseline(
            actor=item.actor_id,
            requested_value=item.subject_identifier,
            response_object_path=item.response_object_path,
            subject_resource_id=item.subject_resource_id,
            parent_resource_id=item.parent_resource_id,
            parent_resource_type=item.parent_resource_type,
            parent_value=item.parent_identifier,
            endpoint_id=item.endpoint_id,
            observations=[item.observation_id],
            baseline_id=item.id,
            relationship_ids=item.relationship_ids,
            capture_ids=item.capture_ids,
            session_ids=item.session_ids,
            operation=item.operation,
            authentication_type=item.authentication_type,
        )
        for item in sorted(
            candidates,
            key=lambda value: (
                0 if value.endpoint_id == endpoint.id else 1,
                value.actor_id,
                value.subject_resource_id,
                value.id,
            ),
        )
    ]
    relationship_ids = sorted(
        {relationship_id for item in candidates for relationship_id in item.relationship_ids}
    )
    parent_ids = {item.parent_resource_id for item in candidates if item.parent_resource_id}
    return ObjectAccessEvidence(
        identifier=wanted_identifier,
        source="CONTROLLED_LIFECYCLE",
        confidence=Confidence.HIGH,
        baselines=baselines,
        distinct_actors=len(actors),
        distinct_objects=len(resources),
        distinct_parent_values=len(parent_ids),
        actor_object_binding_observed=True,
        relationship_ids=relationship_ids,
        baseline_ids=sorted(item.id for item in candidates),
        ambiguity=(
            [
                "Controlled objects span distinct parent instances; subject-only, parent-only, "
                "and combined substitutions are separate authorization questions."
            ]
            if len(parent_ids) >= 2
            else []
        ),
    )


def project_controlled_ownership(
    endpoints: EndpointStore, store: ControlledOwnershipStore
) -> EndpointStore:
    """Persist a deterministic, relationship-ID-bound projection for existing consumers."""

    projected: list[Endpoint] = []
    for endpoint in endpoints.endpoints:
        retained = [item for item in endpoint.object_access if item.source != "CONTROLLED_LIFECYCLE"]
        parameter = _endpoint_subject_parameter(endpoint)
        binding = controlled_binding_for_endpoint(
            store, endpoint, parameter.name if parameter is not None else None
        )
        if binding is not None:
            retained.append(binding)
        projected.append(
            endpoint.model_copy(
                update={
                    "object_access": sorted(
                        retained, key=lambda item: (item.identifier, item.source)
                    )
                }
            )
        )
    return EndpointStore(version=2, endpoints=projected)


def load_controlled_ownership(workspace: WorkspacePaths) -> ControlledOwnershipStore:
    """Load the canonical store; legacy workspaces fail closed with an empty model."""

    if not workspace.controlled_ownership.is_file():
        return ControlledOwnershipStore()
    try:
        return ControlledOwnershipStore.model_validate(load_yaml(workspace.controlled_ownership))
    except (OSError, ValidationError) as error:
        raise FinsecError(
            f"Cannot load controlled ownership model {workspace.controlled_ownership}: {error}"
        ) from error


def relationships_for_resource_type(
    store: ControlledOwnershipStore, resource_type: str
) -> list[EvidenceBackedRelationship]:
    """Return canonical relationships touching one resource type."""

    wanted = _type_key(resource_type)
    return [
        item
        for item in store.relationships
        if (
            item.source.kind == BoundaryEntityKind.RESOURCE
            and _type_key(item.source.type or "") == wanted
        )
        or (
            item.target.kind == BoundaryEntityKind.RESOURCE
            and _type_key(item.target.type or "") == wanted
        )
    ]


def controlled_baselines_for_resource_type(
    store: ControlledOwnershipStore, resource_type: str
) -> list[ControlledBaseline]:
    """Return authorization-eligible baselines for one resource type."""

    wanted = _type_key(resource_type)
    return [
        item
        for item in store.controlled_baselines
        if item.eligible_for_authorization and _type_key(item.subject_resource_type) == wanted
    ]
