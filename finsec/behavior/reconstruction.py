"""Deterministic workflow reconstruction, state inference, and graph persistence."""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from statistics import median
from typing import Any, Literal

from pydantic import ValidationError

from finsec.behavior.domain import (
    ActionRecord,
    ActionStore,
    CausalBasis,
    CausalEvidence,
    EpistemicStatus,
    GraphEdge,
    GraphNode,
    InferenceConfidence,
    PropagationLink,
    PropagationStore,
    RelationshipType,
    ResourceInstance,
    ResourceInstanceStore,
    ResourceRelationship,
    StateRecord,
    StateStore,
    TransitionRecord,
    TransitionStore,
    WorkflowBusinessValue,
    WorkflowFamily,
    WorkflowFamilyStore,
    WorkflowGraph,
    WorkflowInstance,
    WorkflowInstanceStore,
    WorkflowPrerequisite,
    WorkflowStateObservation,
    WorkflowStep,
)
from finsec.behavior.extraction import ExchangeFacts, ScalarSignal, extract_exchange_facts
from finsec.captures.domain import (
    observation_is_probe_evidence,
    observation_supports_normal_behavior,
)
from finsec.config.workspace import WorkspacePaths
from finsec.errors import FinsecError
from finsec.modeling.merge import stable_fingerprint
from finsec.modeling.models import EndpointStore, ObservationStore
from finsec.modeling.semantics import IdentifierSemanticClass
from finsec.utils.yaml_store import load_yaml, write_yaml

TERMINAL_STATES = {
    "CANCELLED",
    "CLOSED",
    "COMPLETED",
    "CONSUMED",
    "DELETED",
    "EXPIRED",
    "FAILED",
    "REFUNDED",
    "REJECTED",
    "SHIPPED",
}
SCOPE_RESOURCE_TYPES = {"account", "actor", "owner", "user", "userid", "tenant"}
PRODUCER_VERBS = {
    "CLAIM",
    "CREATE",
    "GENERATE",
    "INITIATE",
    "INVITE",
    "ISSUE",
    "OPEN",
    "RESERVE",
    "START",
}
ACTION_STATE_HINTS: dict[str, tuple[str, ...]] = {
    "ACCEPT": ("ACCEPTED",),
    "ACTIVATE": ("ACTIVE", "ACTIVATED"),
    "ADD": ("ADDED", "ITEM_ADDED"),
    "APPLY": ("APPLIED", "DISCOUNTED"),
    "APPROVE": ("APPROVED",),
    "CANCEL": ("CANCELLED", "CANCELED"),
    "CLAIM": ("CLAIMED",),
    "CLOSE": ("CLOSED",),
    "COMPLETE": ("COMPLETED",),
    "CONFIRM": ("CONFIRMED",),
    "CONSUME": ("CONSUMED",),
    "CREATE": ("CREATED",),
    "DELETE": ("DELETED",),
    "EXPIRE": ("EXPIRED",),
    "FAIL": ("FAILED",),
    "INITIATE": ("INITIATED", "PENDING"),
    "PAY": ("PAID",),
    "REFUND": ("REFUNDED",),
    "REJECT": ("REJECTED",),
    "RETURN": ("RETURNED", "RETURN_PENDING"),
    "REVERSE": ("REVERSED",),
    "SHIP": ("SHIPPED",),
    "SUSPEND": ("SUSPENDED",),
    "VERIFY": ("VERIFIED",),
}


@dataclass(frozen=True)
class BehaviorBuildResult:
    """Counts and paths produced by one offline reconstruction."""

    observations_considered: int
    actions: int
    resource_instances: int
    propagation_links: int
    workflow_instances: int
    workflow_families: int
    states: int
    transitions: int
    suppressed_noise: int


class _UnionFind:
    def __init__(self, size: int) -> None:
        self.parent = list(range(size))

    def find(self, item: int) -> int:
        while self.parent[item] != item:
            self.parent[item] = self.parent[self.parent[item]]
            item = self.parent[item]
        return item

    def union(self, left: int, right: int) -> None:
        left_root = self.find(left)
        right_root = self.find(right)
        if left_root != right_root:
            self.parent[max(left_root, right_root)] = min(left_root, right_root)


def _identifier(prefix: str, value: Any, length: int = 16) -> str:
    return f"{prefix}-{stable_fingerprint(value)[:length].upper()}"


def _timestamp(value: datetime | None) -> float | None:
    return value.timestamp() if value is not None else None


def _order_key(facts: ExchangeFacts) -> tuple[float, str, int, str]:
    observation = facts.observation
    timestamp = _timestamp(observation.timestamp)
    return (
        timestamp if timestamp is not None else float("inf"),
        observation.capture_id
        or observation.capture_identity
        or observation.source_reference.split("#", 1)[0],
        observation.sequence_position if observation.sequence_position is not None else 10**9,
        observation.id,
    )


def _capture_scope(facts: ExchangeFacts) -> str:
    observation = facts.observation
    return (
        observation.session_identity
        or observation.capture_id
        or observation.capture_identity
        or observation.source_reference.split("#", 1)[0]
    )


def _capture_identity(facts: ExchangeFacts) -> str:
    observation = facts.observation
    return (
        observation.capture_id
        or observation.capture_identity
        or observation.source_reference.split("#", 1)[0]
    )


def _session_identity(facts: ExchangeFacts) -> str | None:
    return facts.observation.session_identity


def _is_read(facts: ExchangeFacts) -> bool:
    if facts.endpoint is None:
        return False
    if facts.observation.method in {"GET", "HEAD", "OPTIONS"}:
        return True
    return (
        facts.endpoint.action.type == "read"
        and facts.observation.status_code != 201
        and not facts.endpoint.state_change
    )


def _noise_observations(facts: list[ExchangeFacts]) -> set[str]:
    grouped: dict[tuple[str, str, str, str], list[ExchangeFacts]] = defaultdict(list)
    for item in facts:
        grouped[
            (
                item.observation.actor,
                _capture_identity(item),
                item.observation.path,
                item.action_name,
            )
        ].append(item)
    noise: set[str] = set()
    for (_actor, _capture, path, _action), items in grouped.items():
        ordered = sorted(items, key=_order_key)
        if len(ordered) < 3 or not all(_is_read(item) for item in ordered):
            continue
        timestamps = [_timestamp(item.observation.timestamp) for item in ordered]
        close = all(
            left is not None and right is not None and 0 <= right - left <= 120
            for left, right in zip(timestamps, timestamps[1:], strict=False)
        )
        same_state = (
            len({tuple((state.field, state.value) for state in item.states) for item in ordered})
            <= 1
        )
        polling_route = any(token in path.lower() for token in ("/poll", "/status", "/progress"))
        if close and (same_state or polling_route):
            noise.update(item.observation.id for item in ordered)
    return noise


def _active_facts(all_facts: list[ExchangeFacts]) -> tuple[list[ExchangeFacts], int]:
    eligible = [
        item
        for item in all_facts
        if item.endpoint is not None
        and item.endpoint.disposition == "ACTIVE"
        and item.endpoint.classification.primary.value
        not in {"STATIC_ASSET", "TELEMETRY", "ANALYTICS", "THIRD_PARTY"}
        and item.observation.source != "OPENAPI"
    ]
    noise = _noise_observations(eligible)
    return [item for item in eligible if item.observation.id not in noise], len(noise)


def _normal_behavior_facts(facts: list[ExchangeFacts]) -> list[ExchangeFacts]:
    """Select baseline facts without discarding probe evidence from other artifacts."""

    return [item for item in facts if observation_supports_normal_behavior(item.observation)]


def _actions(facts: list[ExchangeFacts]) -> tuple[list[ActionRecord], dict[str, str]]:
    grouped: dict[tuple[str, str, str, tuple[str, ...]], list[ExchangeFacts]] = defaultdict(list)
    for item in facts:
        endpoint = item.endpoint
        assert endpoint is not None
        grouped[
            (
                item.action_name,
                item.observation.method,
                endpoint.path,
                (endpoint.resource.type,),
            )
        ].append(item)
    actions: list[ActionRecord] = []
    observation_actions: dict[str, str] = {}
    for signature, items in sorted(grouped.items()):
        name, method, route, resource_types = signature
        action_id = _identifier(
            "ACTN",
            {"name": name, "method": method, "route": route, "resources": resource_types},
        )
        endpoint_ids = sorted({item.endpoint.id for item in items if item.endpoint is not None})
        observation_ids = sorted(item.observation.id for item in items)
        state_changing = any(item.endpoint and item.endpoint.state_change for item in items)
        confidence = (
            InferenceConfidence.HIGH_EVIDENCE
            if all(item.endpoint and item.endpoint.action.name != "unknown" for item in items)
            else InferenceConfidence.MODERATE_EVIDENCE
            if method in {"GET", "HEAD", "PUT", "PATCH", "DELETE"}
            else InferenceConfidence.WEAK_EVIDENCE
        )
        reasons = sorted({reason for item in items for reason in item.action_reasons})
        action = ActionRecord(
            id=action_id,
            name=name,
            method=method,
            route=route,
            endpoint_ids=endpoint_ids,
            observation_ids=observation_ids,
            resource_types=list(resource_types),
            state_changing=state_changing,
            confidence=confidence,
            reasons=reasons,
        )
        actions.append(action)
        observation_actions.update(
            {observation_id: action_id for observation_id in observation_ids}
        )
    return sorted(actions, key=lambda item: item.id), observation_actions


def _resource_signals(facts: ExchangeFacts) -> list[ScalarSignal]:
    return [item for item in facts.signals if item.kind == "RESOURCE_IDENTIFIER"]


def _primary_resource_identifiers(facts: ExchangeFacts) -> set[tuple[str | None, str]]:
    if facts.endpoint is None:
        return set()
    primary_type = facts.endpoint.resource.type.lower()
    return {
        (signal.resource_type, signal.fingerprint)
        for signal in _resource_signals(facts)
        if (signal.resource_type or "").lower() == primary_type
        and signal.semantic_class
        not in {
            IdentifierSemanticClass.REGION,
            IdentifierSemanticClass.SHARED_SCOPE,
            IdentifierSemanticClass.TENANT_CONTAINER,
            IdentifierSemanticClass.PARENT_CONTAINER,
            IdentifierSemanticClass.COLLECTION,
            IdentifierSemanticClass.ACTOR_IDENTIFIER,
            IdentifierSemanticClass.AUTH_IDENTIFIER,
            IdentifierSemanticClass.NON_SECURITY_RELEVANT,
        }
    }


def _request_primary_resource_identifiers(
    facts: ExchangeFacts,
) -> set[tuple[str | None, str]]:
    if facts.endpoint is None:
        return set()
    primary_type = facts.endpoint.resource.type.lower()
    return {
        (signal.resource_type, signal.fingerprint)
        for signal in facts.request_signals
        if signal.kind == "RESOURCE_IDENTIFIER"
        and (signal.resource_type or "").lower() == primary_type
        and signal.semantic_class
        not in {
            IdentifierSemanticClass.REGION,
            IdentifierSemanticClass.SHARED_SCOPE,
            IdentifierSemanticClass.TENANT_CONTAINER,
            IdentifierSemanticClass.PARENT_CONTAINER,
            IdentifierSemanticClass.COLLECTION,
            IdentifierSemanticClass.ACTOR_IDENTIFIER,
            IdentifierSemanticClass.AUTH_IDENTIFIER,
            IdentifierSemanticClass.NON_SECURITY_RELEVANT,
        }
    }


def _resources(
    facts: list[ExchangeFacts],
) -> tuple[list[ResourceInstance], dict[str, list[str]], dict[tuple[str, str, str], str]]:
    grouped: dict[tuple[str, str, str], list[tuple[ExchangeFacts, ScalarSignal]]] = defaultdict(
        list
    )
    normal_observations = {
        item.observation.id
        for item in facts
        if observation_supports_normal_behavior(item.observation)
    }
    for item in facts:
        for signal in _resource_signals(item):
            resource_type = signal.resource_type or "resource"
            actor_scope = item.observation.actor
            if signal.semantic_class in {
                IdentifierSemanticClass.REGION,
                IdentifierSemanticClass.SHARED_SCOPE,
                IdentifierSemanticClass.COLLECTION,
                IdentifierSemanticClass.NON_SECURITY_RELEVANT,
            }:
                actor_scope = "SHARED"
            if item.observation.actor == "UNKNOWN":
                actor_scope = f"UNKNOWN:{_capture_identity(item)}"
            elif not observation_supports_normal_behavior(item.observation):
                actor_scope = (
                    f"{item.observation.actor}:{item.observation.capture_mode.value}:"
                    f"{_capture_identity(item)}"
                )
            grouped[(resource_type, signal.fingerprint, actor_scope)].append((item, signal))
    observation_resources: dict[str, list[str]] = defaultdict(list)
    fingerprint_resources: dict[tuple[str, str, str], str] = {}
    resources: list[ResourceInstance] = []
    raw_relationships: dict[str, list[ResourceRelationship]] = defaultdict(list)
    for (resource_type, fingerprint, actor_scope), items in sorted(grouped.items()):
        resource_id = _identifier(
            "RINST", {"type": resource_type, "value": fingerprint, "scope": actor_scope}
        )
        fingerprint_resources[(resource_type, fingerprint, actor_scope)] = resource_id
        observations = sorted({item.observation.id for item, _signal in items})
        actors = sorted({item.observation.actor for item, _signal in items})
        capture_modes = sorted({item.observation.capture_mode for item, _signal in items})
        semantic_classes = sorted({signal.semantic_class for _item, signal in items})
        ownership_states = sorted({signal.ownership_state for _item, signal in items})
        normal_behavior_observations = sorted(
            observation_id
            for observation_id in observations
            if observation_id in normal_observations
        )
        probe_observations = sorted(
            {
                item.observation.id
                for item, _signal in items
                if observation_is_probe_evidence(item.observation)
            }
        )
        for observation_id in observations:
            observation_resources[observation_id].append(resource_id)
        resources.append(
            ResourceInstance(
                id=resource_id,
                resource_type=resource_type,
                value_fingerprint=fingerprint,
                reference=f"{resource_type}:{fingerprint[:12]}",
                observations=observations,
                actors=actors,
                capture_modes=capture_modes,
                semantic_classes=semantic_classes,
                ownership_states=ownership_states,
                normal_behavior_observations=normal_behavior_observations,
                probe_observations=probe_observations,
                confidence=InferenceConfidence.HIGH_EVIDENCE,
            )
        )

    resource_by_id = {item.id: item for item in resources}
    for observation_id, resource_ids in sorted(observation_resources.items()):
        if observation_id not in normal_observations:
            continue
        unique = sorted(set(resource_ids))
        for source_id in unique:
            for target_id in unique:
                if source_id == target_id:
                    continue
                target = resource_by_id[target_id]
                relation: Literal["scoped_to", "linked_to"] = (
                    "scoped_to"
                    if target.resource_type in SCOPE_RESOURCE_TYPES
                    or any(
                        item
                        in {
                            IdentifierSemanticClass.REGION,
                            IdentifierSemanticClass.SHARED_SCOPE,
                            IdentifierSemanticClass.TENANT_CONTAINER,
                            IdentifierSemanticClass.PARENT_CONTAINER,
                        }
                        for item in target.semantic_classes
                    )
                    else "linked_to"
                )
                raw_relationships[source_id].append(
                    ResourceRelationship(
                        relation=relation,
                        target_resource_id=target_id,
                        evidence=[observation_id],
                        confidence=InferenceConfidence.MODERATE_EVIDENCE,
                    )
                )
    finalized: list[ResourceInstance] = []
    for resource in resources:
        merged: dict[tuple[str, str], list[str]] = defaultdict(list)
        for relationship in raw_relationships[resource.id]:
            merged[(relationship.relation, relationship.target_resource_id)].extend(
                relationship.evidence
            )
        relationships = [
            ResourceRelationship(
                relation=relation,  # type: ignore[arg-type]
                target_resource_id=target,
                evidence=sorted(set(evidence)),
                confidence=InferenceConfidence.MODERATE_EVIDENCE,
            )
            for (relation, target), evidence in sorted(merged.items())
        ]
        finalized.append(resource.model_copy(update={"relationships": relationships}))
    return (
        sorted(finalized, key=lambda item: item.id),
        {key: sorted(set(value)) for key, value in observation_resources.items()},
        fingerprint_resources,
    )


def _temporal_order_known(source: ExchangeFacts, destination: ExchangeFacts) -> bool:
    source_time = _timestamp(source.observation.timestamp)
    destination_time = _timestamp(destination.observation.timestamp)
    if source_time is not None and destination_time is not None:
        return destination_time >= source_time
    if _capture_identity(source) != _capture_identity(destination):
        return False
    source_position = source.observation.sequence_position
    destination_position = destination.observation.sequence_position
    return (
        source_position is not None
        and destination_position is not None
        and destination_position > source_position
    )


def _request_contains_response_value(source: ExchangeFacts, signal: ScalarSignal) -> bool:
    return any(
        request.fingerprint == signal.fingerprint
        and request.kind == signal.kind
        and request.semantic_role == signal.semantic_role
        and request.resource_type == signal.resource_type
        for request in source.request_signals
    )


def _states_for_resource(facts: ExchangeFacts, resource_type: str | None) -> list[str]:
    if resource_type is None:
        return []
    normalized = resource_type.lower()
    return sorted(
        {state.value for state in facts.states if state.resource_type.lower() == normalized}
    )


def _action_matches_state(action_name: str, state: str) -> bool:
    hints = ACTION_STATE_HINTS.get(action_name.split("_", 1)[0])
    if hints is None:
        return False
    normalized = state.upper()
    return any(normalized == hint or normalized.endswith(f"_{hint}") for hint in hints)


def _state_transition_evidence(
    source: ExchangeFacts,
    destination: ExchangeFacts,
    signal: ScalarSignal,
    destination_signal: ScalarSignal,
    *,
    direct_transition: bool,
) -> str | None:
    if (
        source.endpoint is None
        or destination.endpoint is None
        or not _consumer_advances_workflow(source)
        or not _consumer_advances_workflow(destination)
        or signal.kind != "RESOURCE_IDENTIFIER"
        or destination_signal.kind != "RESOURCE_IDENTIFIER"
        or signal.resource_type is None
        or signal.resource_type != destination_signal.resource_type
        or not direct_transition
    ):
        return None
    source_states = [
        state
        for state in source.states
        if state.resource_type.lower() == signal.resource_type.lower()
    ]
    destination_states = [
        state
        for state in destination.states
        if state.resource_type.lower() == destination_signal.resource_type.lower()
    ]
    for source_state in source_states:
        for destination_state in destination_states:
            if (
                _normalized_state_field(source_state.field)
                != _normalized_state_field(destination_state.field)
                or source_state.value == destination_state.value
            ):
                continue
            return (
                f"STATE_TRANSITION_PRODUCED: the same typed {signal.resource_type} identity "
                f"changed {source_state.field} from {source_state.value} to "
                f"{destination_state.value} across consecutive mutations."
            )
    return None


def _normalized_state_field(value: str) -> str:
    return value.rsplit(".", 1)[-1].replace("[]", "").lower()


def _successful_response(facts: ExchangeFacts) -> bool:
    status = facts.observation.status_code
    return status is not None and 200 <= status < 300


def _resource_creation_evidence(source: ExchangeFacts, signal: ScalarSignal) -> bool:
    if (
        source.endpoint is None
        or signal.kind != "RESOURCE_IDENTIFIER"
        or not _successful_response(source)
    ):
        return False
    if source.observation.status_code == 201 and source.observation.method not in {
        "GET",
        "HEAD",
        "OPTIONS",
    }:
        return True
    if _is_read(source):
        return False
    if not source.endpoint.state_change:
        return False
    verb = source.action_name.split("_", 1)[0]
    if verb in PRODUCER_VERBS:
        return True
    primary_type = source.endpoint.resource.type.lower()
    related_output = signal.resource_type is not None and signal.resource_type != primary_type
    return related_output and any(
        _action_matches_state(source.action_name, state.value) for state in source.states
    )


def _signals_compatible(source: ScalarSignal, destination: ScalarSignal) -> bool:
    if source.kind == destination.kind == "RESOURCE_IDENTIFIER":
        return source.resource_type == destination.resource_type
    if source.kind == destination.kind == "WORKFLOW_TOKEN":
        return source.primitive_type == destination.primitive_type == "STRING"
    if source.primitive_type != destination.primitive_type:
        return False
    return (
        source.kind == destination.kind
        and source.semantic_role == destination.semantic_role
        and source.resource_type == destination.resource_type
    )


def _persistent_resource_identity(
    source: ExchangeFacts,
    signal: ScalarSignal,
    destination_signal: ScalarSignal,
) -> bool:
    if signal.kind != "RESOURCE_IDENTIFIER":
        return False
    source_resource = source.endpoint.resource.type.lower() if source.endpoint is not None else None
    return (
        source.observation.status_code == 201
        or destination_signal.location == "PATH_PARAMETER"
        or (signal.resource_type or "").lower() == source_resource
    )


def _capability_semantics(
    source: ExchangeFacts,
    destination: ExchangeFacts,
    signal: ScalarSignal,
    destination_signal: ScalarSignal,
    *,
    output_only: bool,
    persistent_resource_identity: bool,
) -> bool:
    if (
        not output_only
        or not signal.distinctive
        or not destination_signal.distinctive
        or not _successful_response(source)
        or not _consumer_advances_workflow(destination)
        or persistent_resource_identity
    ):
        return False
    if signal.kind == destination_signal.kind == "WORKFLOW_TOKEN":
        return True
    if signal.kind == destination_signal.kind == "RESOURCE_IDENTIFIER":
        source_resource = (
            source.endpoint.resource.type.lower() if source.endpoint is not None else None
        )
        return (
            destination_signal.location != "PATH_PARAMETER"
            and signal.resource_type is not None
            and signal.resource_type != source_resource
        )
    return False


def _consumer_advances_workflow(facts: ExchangeFacts) -> bool:
    return bool(
        facts.endpoint
        and (
            facts.endpoint.state_change
            or (
                facts.observation.method in {"POST", "PUT", "PATCH", "DELETE"}
                and not _is_read(facts)
            )
        )
    )


def _causal_evidence(
    source: ExchangeFacts,
    destination: ExchangeFacts,
    signal: ScalarSignal,
    destination_signal: ScalarSignal,
    *,
    previously_observed: bool,
    direct_state_transition: bool,
) -> tuple[CausalEvidence, str | None]:
    same_actor = (
        source.observation.actor != "UNKNOWN"
        and source.observation.actor == destination.observation.actor
    )
    same_session = _session_identity(source) is not None and _session_identity(
        source
    ) == _session_identity(destination)
    same_capture = _capture_identity(source) == _capture_identity(destination)
    normal_behavior = observation_supports_normal_behavior(
        source.observation
    ) and observation_supports_normal_behavior(destination.observation)
    same_host = source.observation.host == destination.observation.host
    output_only = not _request_contains_response_value(source, signal)
    persistent_identity = _persistent_resource_identity(source, signal, destination_signal)
    state_reason = _state_transition_evidence(
        source,
        destination,
        signal,
        destination_signal,
        direct_transition=direct_state_transition,
    )
    evidence = CausalEvidence(
        output_only=output_only,
        later_consumed=True,
        compatible_resource_type=_signals_compatible(signal, destination_signal),
        temporal_order=_temporal_order_known(source, destination),
        same_controlled_actor=same_actor,
        distinctive_value=signal.distinctive and destination_signal.distinctive,
        same_session=same_session,
        same_capture=same_capture,
        same_host=same_host,
        session_compatible=same_session and normal_behavior,
        capture_compatible=(same_capture or same_session) and normal_behavior,
        host_compatible=same_host
        or (
            same_session
            and source.endpoint is not None
            and destination.endpoint is not None
            and source.endpoint.disposition == "ACTIVE"
            and destination.endpoint.disposition == "ACTIVE"
        ),
        request_echo=not output_only,
        previously_observed=previously_observed,
        source_is_read=_is_read(source),
        source_successful=_successful_response(source),
        source_created_resource=output_only and _resource_creation_evidence(source, signal),
        consumer_state_changing=_consumer_advances_workflow(destination),
        consumed_as_path_identifier=destination_signal.location == "PATH_PARAMETER",
        persistent_resource_identity=persistent_identity,
        collection_member="[]" in signal.field,
        direct_state_transition=direct_state_transition,
        capability_semantics=_capability_semantics(
            source,
            destination,
            signal,
            destination_signal,
            output_only=output_only,
            persistent_resource_identity=persistent_identity,
        ),
        state_transition_evidence=state_reason is not None,
        distinctive_semantic_role=signal.semantic_role == destination_signal.semantic_role,
        field_alias_compatible=(
            signal.kind == destination_signal.kind == "WORKFLOW_TOKEN"
            and signal.semantic_role != destination_signal.semantic_role
        ),
    )
    return evidence, state_reason


def _producer_semantics(
    signal: ScalarSignal,
    evidence: CausalEvidence,
    state_reason: str | None,
) -> tuple[CausalBasis, str]:
    if evidence.collection_member:
        return (
            CausalBasis.EXISTING_VALUE_OBSERVED,
            "OBSERVED_EXISTING_VALUE: a response collection exposed an existing member value.",
        )
    if evidence.request_echo:
        if evidence.state_transition_evidence and state_reason is not None:
            return CausalBasis.STATE_TRANSITION_PRODUCED, state_reason
        return (
            CausalBasis.REQUEST_VALUE_ECHOED,
            "ECHOED_REQUEST_VALUE: the response repeated a value supplied by the source request.",
        )
    if evidence.source_created_resource:
        return (
            CausalBasis.RESOURCE_CREATED,
            "RESOURCE_CREATED: a successful producer returned an output-only typed resource "
            "identifier consumed by the later request.",
        )
    if evidence.state_transition_evidence and state_reason is not None:
        return CausalBasis.STATE_TRANSITION_PRODUCED, state_reason
    if evidence.capability_semantics:
        return (
            CausalBasis.CAPABILITY_ISSUED,
            "CAPABILITY_ISSUED: an output-only distinctive value is later consumed by a "
            "workflow-advancing action without persistent-resource behavior.",
        )
    if evidence.source_is_read or evidence.previously_observed:
        return (
            CausalBasis.EXISTING_VALUE_OBSERVED,
            "OBSERVED_EXISTING_VALUE: passive evidence shows observation rather than production.",
        )
    return (
        CausalBasis.AMBIGUOUS_ORIGIN,
        "AMBIGUOUS_PRODUCER: matching context does not establish a produced prerequisite.",
    )


def _relationship_type(
    source: ExchangeFacts,
    destination: ExchangeFacts,
    signal: ScalarSignal,
    destination_signal: ScalarSignal,
    *,
    previously_observed: bool,
    direct_state_transition: bool,
) -> tuple[RelationshipType, bool, CausalBasis, str, CausalEvidence, list[str]]:
    evidence, state_reason = _causal_evidence(
        source,
        destination,
        signal,
        destination_signal,
        previously_observed=previously_observed,
        direct_state_transition=direct_state_transition,
    )
    causal_basis, producer_reason = _producer_semantics(signal, evidence, state_reason)
    same_capture = evidence.same_capture
    same_action_replay = (
        source.action_name == destination.action_name
        and source.endpoint is not None
        and source.endpoint.state_change
    )
    if not evidence.same_controlled_actor:
        return (
            RelationshipType.CROSS_ACTOR_COMPARISON,
            False,
            causal_basis,
            "Typed values cross actor boundaries and are retained only for controlled comparison.",
            evidence,
            ["controlled_actor_mismatch"],
        )
    if observation_is_probe_evidence(source.observation) or observation_is_probe_evidence(
        destination.observation
    ):
        return (
            RelationshipType.REPLAY_RELATED,
            False,
            causal_basis,
            "Researcher-probe traffic is retained as testing evidence and cannot establish a "
            "normal application prerequisite.",
            evidence,
            ["researcher_probe_not_normal_workflow"],
        )
    if (
        same_action_replay
        and causal_basis
        not in {
            CausalBasis.RESOURCE_CREATED,
            CausalBasis.CAPABILITY_ISSUED,
            CausalBasis.STATE_TRANSITION_PRODUCED,
        }
    ) or signal.kind == "IDEMPOTENCY_KEY":
        return (
            RelationshipType.REPLAY_RELATED,
            same_capture,
            CausalBasis.EXISTING_VALUE_OBSERVED,
            "Repeated action or idempotency evidence is replay-related, not a prerequisite edge.",
            evidence,
            ["replay_relationship_display_only"],
        )
    if signal.kind == "CORRELATION_ID":
        return (
            RelationshipType.CONTEXT_SOFT,
            same_capture,
            causal_basis,
            "Correlation identifiers provide context but do not prove producer-consumer causality.",
            evidence,
            ["correlation_identifier_display_only"],
        )
    if evidence.collection_member:
        return (
            RelationshipType.CONTEXT_SOFT,
            same_capture,
            causal_basis,
            "An identifier observed inside a response collection is selection context and does "
            "not prove one workflow boundary.",
            evidence,
            ["response_collection_member_observed"],
        )
    merge_capable_basis = causal_basis in {
        CausalBasis.RESOURCE_CREATED,
        CausalBasis.CAPABILITY_ISSUED,
        CausalBasis.STATE_TRANSITION_PRODUCED,
    }
    if merge_capable_basis and evidence.hard_causal_admissibility(causal_basis):
        return (
            RelationshipType.CAUSAL_HARD,
            evidence.capture_compatible,
            causal_basis,
            producer_reason,
            evidence,
            [],
        )
    rejection_reasons = evidence.rejection_reasons(causal_basis)
    return (
        RelationshipType.CONTEXT_SOFT,
        same_capture,
        causal_basis,
        producer_reason
        if rejection_reasons
        else "The candidate is retained as display-only context.",
        evidence,
        rejection_reasons or ["hard_causal_admissibility_not_met"],
    )


def _relationship_link(
    source: ExchangeFacts,
    destination: ExchangeFacts,
    signal: ScalarSignal,
    destination_signal: ScalarSignal,
    relationship_type: RelationshipType,
    causal_basis: CausalBasis,
    capture_continuity: bool,
    reason: str,
    causal_evidence: CausalEvidence | None = None,
    rejection_reasons: list[str] | None = None,
) -> PropagationLink:
    payload = {
        "relationship": relationship_type,
        "causal_basis": causal_basis,
        "value": signal.fingerprint,
        "source": source.observation.id,
        "source_field": signal.field,
        "destination": destination.observation.id,
        "destination_field": destination_signal.field,
    }
    return PropagationLink(
        id=_identifier("PROP", payload),
        relationship_type=relationship_type,
        causal_basis=causal_basis,
        value_fingerprint=signal.fingerprint,
        value_kind=signal.kind,
        destination_value_kind=destination_signal.kind,
        source_resource_type=signal.resource_type,
        destination_resource_type=destination_signal.resource_type,
        source_semantic_role=signal.semantic_role,
        destination_semantic_role=destination_signal.semantic_role,
        source_resource_role=signal.resource_role,
        destination_resource_role=destination_signal.resource_role,
        source_location=signal.location,
        destination_location=destination_signal.location,
        source_primitive_type=signal.primitive_type,
        destination_primitive_type=destination_signal.primitive_type,
        source_observation_id=source.observation.id,
        source_field=signal.field,
        source_actor=source.observation.actor,
        source_session=_session_identity(source),
        source_capture=_capture_identity(source),
        source_capture_mode=source.observation.capture_mode,
        source_host=source.observation.host,
        destination_observation_id=destination.observation.id,
        destination_field=destination_signal.field,
        destination_actor=destination.observation.actor,
        destination_session=_session_identity(destination),
        destination_capture=_capture_identity(destination),
        destination_capture_mode=destination.observation.capture_mode,
        destination_host=destination.observation.host,
        temporal_order_known=_temporal_order_known(source, destination),
        capture_continuity=capture_continuity,
        distinctive_value=signal.distinctive and destination_signal.distinctive,
        causal_evidence=causal_evidence or CausalEvidence(),
        rejection_reasons=rejection_reasons or [],
        evidence_reason=reason,
        evidence=[source.observation.id, destination.observation.id],
        confidence=(
            InferenceConfidence.HIGH_EVIDENCE
            if relationship_type == RelationshipType.CAUSAL_HARD and signal.kind == "WORKFLOW_TOKEN"
            else InferenceConfidence.MODERATE_EVIDENCE
            if relationship_type == RelationshipType.CAUSAL_HARD
            else InferenceConfidence.WEAK_EVIDENCE
        ),
    )


def _replay_relationships(facts: list[ExchangeFacts]) -> list[PropagationLink]:
    grouped: dict[tuple[str, str, str, tuple[tuple[str | None, str], ...]], list[ExchangeFacts]] = (
        defaultdict(list)
    )
    for item in facts:
        if item.endpoint is None or not item.endpoint.state_change:
            continue
        identifiers = tuple(sorted(_request_primary_resource_identifiers(item)))
        if not identifiers:
            continue
        grouped[
            (
                item.observation.actor,
                _capture_scope(item),
                item.action_name,
                identifiers,
            )
        ].append(item)
    links: list[PropagationLink] = []
    for items in grouped.values():
        ordered = sorted(items, key=_order_key)
        for source, destination in zip(ordered, ordered[1:], strict=False):
            source_signal = next(
                signal
                for signal in source.request_signals
                if (signal.resource_type, signal.fingerprint)
                in _request_primary_resource_identifiers(source)
            )
            destination_signal = next(
                signal
                for signal in destination.request_signals
                if (signal.resource_type, signal.fingerprint)
                in _request_primary_resource_identifiers(destination)
            )
            causal_evidence, _state_reason = _causal_evidence(
                source,
                destination,
                source_signal,
                destination_signal,
                previously_observed=True,
                direct_state_transition=False,
            )
            links.append(
                _relationship_link(
                    source,
                    destination,
                    source_signal,
                    destination_signal,
                    RelationshipType.REPLAY_RELATED,
                    CausalBasis.EXISTING_VALUE_OBSERVED,
                    _capture_identity(source) == _capture_identity(destination),
                    "The same state-changing action reused the same typed primary resource.",
                    causal_evidence,
                    ["replay_relationship_display_only"],
                )
            )
    return links


def _cross_actor_relationships(facts: list[ExchangeFacts]) -> list[PropagationLink]:
    grouped: dict[
        tuple[str, str, str, str | None], dict[str, list[tuple[ExchangeFacts, ScalarSignal]]]
    ] = defaultdict(lambda: defaultdict(list))
    for item in facts:
        if item.endpoint is None or item.observation.actor == "UNKNOWN":
            continue
        primary_resource_types = {
            (signal.resource_type or "").lower()
            for signal in item.request_signals
            if signal.kind == "RESOURCE_IDENTIFIER" and signal.resource_role == "PRIMARY"
        }
        typed_path_values = {
            signal.value
            for signal in item.request_signals
            if signal.kind == "RESOURCE_IDENTIFIER" and signal.location == "PATH_PARAMETER"
        }
        route_segments = item.observation.path.split("/")
        normalized_segments: list[str] = []
        for index, segment in enumerate(route_segments):
            previous = route_segments[index - 1].lower() if index else ""
            previous_resource = previous[:-1] if previous.endswith("s") else previous
            typed_resource_position = (
                segment.isdigit()
                and previous.endswith("s")
                and previous_resource in primary_resource_types
            )
            normalized_segments.append(
                "{typed-identifier}"
                if segment in typed_path_values or typed_resource_position
                else segment
            )
        comparison_route = "/".join(normalized_segments)
        for signal in item.request_signals:
            if signal.kind != "RESOURCE_IDENTIFIER" or signal.resource_role == "SCOPE":
                continue
            grouped[
                (
                    f"{item.observation.method}:{comparison_route}",
                    item.action_name,
                    signal.semantic_role,
                    signal.resource_type,
                )
            ][item.observation.actor].append((item, signal))
    links: list[PropagationLink] = []
    for actors in grouped.values():
        representatives = [
            sorted(items, key=lambda value: _order_key(value[0]))[0]
            for _actor, items in sorted(actors.items())
        ]
        for index, (left_facts, left_signal) in enumerate(representatives):
            for right_facts, right_signal in representatives[index + 1 :]:
                source, source_signal, destination, destination_signal = (
                    (left_facts, left_signal, right_facts, right_signal)
                    if _order_key(left_facts) <= _order_key(right_facts)
                    else (right_facts, right_signal, left_facts, left_signal)
                )
                causal_evidence, _state_reason = _causal_evidence(
                    source,
                    destination,
                    source_signal,
                    destination_signal,
                    previously_observed=True,
                    direct_state_transition=False,
                )
                links.append(
                    _relationship_link(
                        source,
                        destination,
                        source_signal,
                        destination_signal,
                        RelationshipType.CROSS_ACTOR_COMPARISON,
                        CausalBasis.EXISTING_VALUE_OBSERVED,
                        False,
                        "Different controlled actors supplied compatible typed resource fields on "
                        "the same normalized action; journeys remain separate.",
                        causal_evidence,
                        ["controlled_actor_mismatch"],
                    )
                )
    return links


def _propagation(facts: list[ExchangeFacts]) -> list[PropagationLink]:
    ordered = sorted(facts, key=_order_key)
    request_by_value: dict[str, list[tuple[int, ExchangeFacts, ScalarSignal]]] = defaultdict(list)
    for index, item in enumerate(ordered):
        for signal in item.request_signals:
            if signal.kind == "BUSINESS_VALUE":
                continue
            request_by_value[signal.fingerprint].append((index, item, signal))
    links: list[PropagationLink] = []
    for source_index, source in enumerate(ordered):
        for signal in source.response_signals:
            if signal.kind == "BUSINESS_VALUE":
                continue
            for destination_index, destination, destination_signal in request_by_value.get(
                signal.fingerprint, []
            ):
                if destination_index <= source_index:
                    continue
                if not _signals_compatible(signal, destination_signal):
                    continue
                elapsed = _elapsed(source, destination)
                if elapsed is not None and elapsed < 0:
                    continue
                if elapsed is not None and elapsed > 86400:
                    continue
                previously_observed = any(
                    earlier.observation.actor == source.observation.actor
                    and any(
                        earlier_signal.fingerprint == signal.fingerprint
                        and _signals_compatible(earlier_signal, signal)
                        for earlier_signal in earlier.signals
                    )
                    for earlier in ordered[:source_index]
                )
                intervening_mutation = any(
                    item.observation.actor == source.observation.actor
                    and _session_identity(item) == _session_identity(source)
                    and _consumer_advances_workflow(item)
                    and any(
                        item_signal.fingerprint == signal.fingerprint
                        and item_signal.kind == "RESOURCE_IDENTIFIER"
                        and item_signal.resource_type == signal.resource_type
                        for item_signal in item.signals
                    )
                    for item in ordered[source_index + 1 : destination_index]
                )
                (
                    relationship_type,
                    continuity,
                    causal_basis,
                    reason,
                    causal_evidence,
                    rejection_reasons,
                ) = _relationship_type(
                    source,
                    destination,
                    signal,
                    destination_signal,
                    previously_observed=previously_observed,
                    direct_state_transition=not intervening_mutation,
                )
                links.append(
                    _relationship_link(
                        source,
                        destination,
                        signal,
                        destination_signal,
                        relationship_type,
                        causal_basis,
                        continuity,
                        reason,
                        causal_evidence,
                        rejection_reasons,
                    )
                )
    links.extend(_replay_relationships(facts))
    links.extend(_cross_actor_relationships(facts))
    deduplicated: dict[tuple[str, ...], PropagationLink] = {}
    location_rank = {"PATH_PARAMETER": 0, "BODY": 1, "HEADER": 2, "QUERY_PARAMETER": 3}
    for link in sorted(links, key=lambda item: item.id):
        key = (
            link.relationship_type.value,
            link.causal_basis.value,
            link.value_fingerprint,
            link.source_observation_id,
            link.destination_observation_id,
            link.source_semantic_role or "",
            link.destination_semantic_role or "",
        )
        current = deduplicated.get(key)
        if current is None or location_rank.get(
            link.destination_location or "", 9
        ) < location_rank.get(current.destination_location or "", 9):
            deduplicated[key] = link
    return sorted(deduplicated.values(), key=lambda item: item.id)


def _elapsed(left: ExchangeFacts, right: ExchangeFacts) -> float | None:
    left_timestamp = _timestamp(left.observation.timestamp)
    right_timestamp = _timestamp(right.observation.timestamp)
    if left_timestamp is None or right_timestamp is None:
        return None
    return right_timestamp - left_timestamp


def is_merge_capable_relationship(link: PropagationLink) -> bool:
    """Return whether a persisted relationship may union workflow components."""

    return (
        link.relationship_type == RelationshipType.CAUSAL_HARD
        and link.causal_basis
        in {
            CausalBasis.RESOURCE_CREATED,
            CausalBasis.CAPABILITY_ISSUED,
            CausalBasis.STATE_TRANSITION_PRODUCED,
        }
        and link.causal_evidence.hard_causal_admissibility(link.causal_basis)
    )


def _components(
    facts: list[ExchangeFacts], propagation: list[PropagationLink]
) -> list[list[ExchangeFacts]]:
    ordered = sorted(facts, key=_order_key)
    index_by_observation = {item.observation.id: index for index, item in enumerate(ordered)}
    union = _UnionFind(len(ordered))
    for link in propagation:
        if not is_merge_capable_relationship(link):
            continue
        source_index = index_by_observation.get(link.source_observation_id)
        destination_index = index_by_observation.get(link.destination_observation_id)
        if (
            source_index is not None
            and destination_index is not None
            and link.source_actor is not None
            and link.source_actor != "UNKNOWN"
            and link.source_actor == link.destination_actor
        ):
            union.union(source_index, destination_index)
    grouped: dict[int, list[ExchangeFacts]] = defaultdict(list)
    for index, item in enumerate(ordered):
        grouped[union.find(index)].append(item)
    return [sorted(items, key=_order_key) for _root, items in sorted(grouped.items())]


def _family_name(actions: list[str], resources: list[str]) -> str:
    joined = " ".join(actions).lower()
    if "cart" in joined and any(token in joined for token in ("pay", "payment", "ship")):
        return "checkout"
    if "order" in joined:
        return "order lifecycle"
    candidates = (
        ("invitation", "team invitation"),
        ("invite", "team invitation"),
        ("refund", "refund"),
        ("transfer", "money transfer"),
        ("withdraw", "withdrawal"),
        ("reward", "reward claim"),
        ("subscription", "subscription lifecycle"),
        ("payment", "payment lifecycle"),
        ("order", "order lifecycle"),
        ("coupon", "coupon lifecycle"),
        ("auth", "authentication challenge"),
    )
    for token, name in candidates:
        if token in joined or token in {item.lower() for item in resources}:
            return name
    return f"{resources[0].replace('-', ' ')} lifecycle" if resources else "application workflow"


def _state_from_action(action: str) -> str | None:
    verb = action.split("_", 1)[0]
    return {
        "ACCEPT": "ACCEPTED",
        "ACTIVATE": "ACTIVE",
        "APPROVE": "APPROVED",
        "CANCEL": "CANCELLED",
        "CLAIM": "CLAIMED",
        "CLOSE": "CLOSED",
        "COMPLETE": "COMPLETED",
        "CONFIRM": "CONFIRMED",
        "CONSUME": "CONSUMED",
        "CREATE": "CREATED",
        "DELETE": "DELETED",
        "EXPIRE": "EXPIRED",
        "FAIL": "FAILED",
        "PAY": "PAID",
        "REFUND": "REFUNDED",
        "REJECT": "REJECTED",
        "RETURN": "RETURN_PENDING",
        "SHIP": "SHIPPED",
        "SUSPEND": "SUSPENDED",
        "VERIFY": "VERIFIED",
    }.get(verb)


def _structural_signature(
    steps: list[WorkflowStep], propagation: list[PropagationLink]
) -> tuple[str, list[str], list[str], list[str]]:
    position_by_observation = {step.observation_id: step.position for step in steps}
    ordered = [
        ":".join(
            [
                str(step.position),
                step.method,
                step.route,
                step.action_name,
                step.resource_role,
                "MUTATING" if step.state_changing else "READ_ONLY",
                f"{step.state_before or 'UNRESOLVED'}->{step.state_after or 'UNRESOLVED'}",
            ]
        )
        for step in steps
    ]
    topology = sorted(
        {
            f"{position_by_observation[link.source_observation_id]}->"
            f"{position_by_observation[link.destination_observation_id]}:"
            f"{link.source_semantic_role or 'unknown'}"
            for link in propagation
            if is_merge_capable_relationship(link)
            and link.source_observation_id in position_by_observation
            and link.destination_observation_id in position_by_observation
        }
    )
    terminal_or_mutating = [
        f"{step.position}:{step.action_name}:{step.state_after or 'UNRESOLVED'}"
        for step in steps
        if step.state_changing or step.state_after in TERMINAL_STATES
    ]
    payload = {
        "ordered_steps": ordered,
        "causal_topology": topology,
        "terminal_or_mutating": terminal_or_mutating,
    }
    return stable_fingerprint(payload), ordered, topology, terminal_or_mutating


def _workflow_instances(
    components: list[list[ExchangeFacts]],
    observation_actions: dict[str, str],
    observation_resources: dict[str, list[str]],
    resources: list[ResourceInstance],
    propagation: list[PropagationLink],
) -> list[WorkflowInstance]:
    resource_types_by_id = {item.id: item.resource_type.lower() for item in resources}
    instances: list[WorkflowInstance] = []
    for items in sorted(components, key=lambda value: [_order_key(item) for item in value]):
        resource_types = sorted(
            {
                item.endpoint.resource.type
                for item in items
                if item.endpoint is not None and item.endpoint.resource.type != "Unknown"
            }
            | {
                signal.resource_type
                for item in items
                for signal in _resource_signals(item)
                if signal.resource_type is not None
            }
        )
        resource_ids = sorted(
            {
                resource_id
                for item in items
                for resource_id in observation_resources.get(item.observation.id, [])
            }
        )
        actors = sorted({item.observation.actor for item in items})
        current_states: dict[str, str] = {}
        current_type_states: dict[str, str] = {}
        steps: list[WorkflowStep] = []
        explicit_states = 0
        for position, item in enumerate(items, start=1):
            observation_id = item.observation.id
            resource_ids = observation_resources.get(observation_id, [])
            state_observations: list[WorkflowStateObservation] = []
            if item.states:
                explicit_states += len(item.states)
                for state in item.states:
                    resource_type = state.resource_type.lower()
                    state_resource_ids = sorted(
                        resource_id
                        for resource_id in resource_ids
                        if resource_types_by_id.get(resource_id) == resource_type
                    )
                    previous_state = next(
                        (
                            current_states[resource_id]
                            for resource_id in state_resource_ids
                            if resource_id in current_states
                        ),
                        current_type_states.get(resource_type),
                    )
                    state_observations.append(
                        WorkflowStateObservation(
                            field=state.field,
                            resource_type=resource_type,
                            resource_instance_ids=state_resource_ids,
                            state_before=previous_state,
                            state_after=state.value,
                            derivation="EXPLICIT_FIELD",
                        )
                    )
                    current_type_states[resource_type] = state.value
                    for resource_id in state_resource_ids:
                        current_states[resource_id] = state.value
            else:
                inferred_state = _state_from_action(item.action_name)
                if inferred_state:
                    resource_type = (
                        item.endpoint.resource.type.lower()
                        if item.endpoint is not None
                        else item.action_name.rsplit("_", 1)[-1].lower()
                    )
                    state_resource_ids = sorted(
                        resource_id
                        for resource_id in resource_ids
                        if resource_types_by_id.get(resource_id) == resource_type
                    )
                    previous_state = next(
                        (
                            current_states[resource_id]
                            for resource_id in state_resource_ids
                            if resource_id in current_states
                        ),
                        current_type_states.get(resource_type),
                    )
                    state_observations.append(
                        WorkflowStateObservation(
                            field=f"action.{item.action_name.lower()}",
                            resource_type=resource_type,
                            resource_instance_ids=state_resource_ids,
                            state_before=previous_state,
                            state_after=inferred_state,
                            derivation="ACTION_SEMANTICS",
                        )
                    )
                    current_type_states[resource_type] = inferred_state
                    for resource_id in state_resource_ids:
                        current_states[resource_id] = inferred_state
            endpoint_resource = (
                item.endpoint.resource.type.lower() if item.endpoint is not None else None
            )
            representative = next(
                (state for state in state_observations if state.resource_type == endpoint_resource),
                state_observations[0] if state_observations else None,
            )
            business_values = [
                WorkflowBusinessValue(
                    field=signal.field,
                    value=signal.value,
                    direction=signal.direction,
                    resource_type=signal.resource_type or endpoint_resource or "resource",
                    resource_instance_ids=sorted(
                        resource_id
                        for resource_id in resource_ids
                        if resource_types_by_id.get(resource_id)
                        == (signal.resource_type or endpoint_resource or "resource").lower()
                    ),
                    semantic_role=signal.semantic_role,
                    location=signal.location,
                    primitive_type=signal.primitive_type,
                    client_controlled=signal.direction == "REQUEST",
                )
                for signal in item.signals
                if signal.kind == "BUSINESS_VALUE"
            ]
            steps.append(
                WorkflowStep(
                    position=position,
                    action_id=observation_actions[observation_id],
                    action_name=item.action_name,
                    observation_id=observation_id,
                    capture_id=item.observation.capture_id,
                    capture_mode=item.observation.capture_mode,
                    capture_relevance=item.observation.capture_relevance,
                    endpoint_ids=[item.endpoint.id] if item.endpoint is not None else [],
                    actor=item.observation.actor,
                    method=item.observation.method,
                    route=item.endpoint.path
                    if item.endpoint is not None
                    else item.observation.path,
                    resource_role=(
                        f"PRIMARY:{item.endpoint.resource.type.lower()}"
                        if item.endpoint is not None
                        else "UNKNOWN"
                    ),
                    state_changing=bool(item.endpoint and item.endpoint.state_change),
                    timestamp=item.observation.timestamp.isoformat()
                    if item.observation.timestamp
                    else None,
                    resource_instance_ids=resource_ids,
                    client_controlled_resource_fields=sorted(
                        {
                            signal.field
                            for signal in item.request_signals
                            if signal.kind == "RESOURCE_IDENTIFIER"
                            and signal.resource_role != "SCOPE"
                        }
                    ),
                    client_controlled_binding_fields=sorted(
                        {
                            signal.field
                            for signal in item.request_signals
                            if (
                                signal.kind == "RESOURCE_IDENTIFIER"
                                and signal.resource_role != "SCOPE"
                            )
                            or (signal.kind == "WORKFLOW_TOKEN" and signal.distinctive)
                        }
                    ),
                    state_observations=state_observations,
                    business_values=business_values,
                    state_before=representative.state_before if representative else None,
                    state_after=representative.state_after if representative else None,
                    state_derivation=(
                        representative.derivation if representative else "UNRESOLVED"
                    ),
                )
            )
        structural_hash, _ordered, _topology, _terminal_steps = _structural_signature(
            steps, propagation
        )
        family_id = _identifier("WFAM", {"structural_signature": structural_hash})
        workflow_id = _identifier(
            "WFINST",
            {
                "family": family_id,
                "actors": actors,
                "resources": resource_ids,
                "evidence": [step.observation_id for step in steps],
            },
        )
        internal_hard_links = [
            link
            for link in propagation
            if is_merge_capable_relationship(link)
            and link.source_observation_id in {step.observation_id for step in steps}
            and link.destination_observation_id in {step.observation_id for step in steps}
        ]
        ambiguities: list[str] = []
        if len(items) == 1:
            ambiguities.append("Only one meaningful observation was available for this journey.")
        if len(items) > 1 and not internal_hard_links:
            ambiguities.append("No hard producer-consumer edge links the observations.")
        if not any(observation_resources.get(item.observation.id) for item in items):
            ambiguities.append("No concrete resource identifier linked the observations.")
        if any(
            item.observation.timestamp is None and item.observation.sequence_position is None
            for item in items
        ):
            ambiguities.append("Temporal order is unavailable for at least one observation.")
        if any(item.observation.actor == "UNKNOWN" for item in items):
            ambiguities.append("Missing actor identity prevents strong workflow segmentation.")
        if any(item.observation.capture_mode.value == "UNKNOWN" for item in items):
            ambiguities.append(
                "Capture mode is unknown; the journey remains usable with conservative confidence."
            )
        confidence = (
            InferenceConfidence.HIGH_EVIDENCE
            if len(items) >= 3
            and len(internal_hard_links) >= len(items) - 1
            and not ambiguities
            and explicit_states >= 1
            else InferenceConfidence.MODERATE_EVIDENCE
            if len(items) >= 2 and internal_hard_links
            else InferenceConfidence.WEAK_EVIDENCE
            if len(items) >= 1
            else InferenceConfidence.SPECULATIVE
        )
        terminal = next(
            (step.state_after for step in reversed(steps) if step.state_after is not None),
            None,
        )
        instances.append(
            WorkflowInstance(
                id=workflow_id,
                family_id=family_id,
                actors=actors,
                sessions=sorted(
                    {
                        item.observation.session_identity or f"MISSING:{_capture_identity(item)}"
                        for item in items
                    }
                ),
                captures=sorted({_capture_identity(item) for item in items}),
                capture_modes=sorted({item.observation.capture_mode for item in items}),
                resource_instance_ids=resource_ids,
                resource_types=resource_types,
                steps=steps,
                started_at=steps[0].timestamp if steps else None,
                ended_at=steps[-1].timestamp if steps else None,
                terminal_outcome=terminal,
                evidence=[step.observation_id for step in steps],
                segmentation_confidence=confidence,
                ambiguities=ambiguities,
            )
        )
    return sorted(instances, key=lambda item: item.id)


def _has_alternative_causal_path(
    candidate: PropagationLink,
    links: list[PropagationLink],
) -> bool:
    adjacency: dict[str, set[str]] = defaultdict(set)
    for link in links:
        if link.id != candidate.id and is_merge_capable_relationship(link):
            adjacency[link.source_observation_id].add(link.destination_observation_id)
    pending = list(
        sorted(
            adjacency.get(candidate.source_observation_id, set())
            - {candidate.destination_observation_id}
        )
    )
    visited: set[str] = set()
    while pending:
        observation_id = pending.pop()
        if observation_id == candidate.destination_observation_id:
            return True
        if observation_id in visited:
            continue
        visited.add(observation_id)
        pending.extend(sorted(adjacency.get(observation_id, set()) - visited))
    return False


def _workflow_families(
    instances: list[WorkflowInstance], propagation: list[PropagationLink]
) -> list[WorkflowFamily]:
    grouped: dict[str, list[WorkflowInstance]] = defaultdict(list)
    for item in instances:
        grouped[item.family_id].append(item)
    families: list[WorkflowFamily] = []
    for family_id, items in sorted(grouped.items()):
        paths = [tuple(step.action_name for step in item.steps) for item in items]
        evidence_items = [
            item
            for item in items
            if item.segmentation_confidence
            in {InferenceConfidence.HIGH_EVIDENCE, InferenceConfidence.MODERATE_EVIDENCE}
        ]
        evidence_paths = [tuple(step.action_name for step in item.steps) for item in evidence_items]
        canonical_paths = evidence_paths or paths
        path_counts = Counter(canonical_paths)
        common_path = list(sorted(path_counts, key=lambda path: (-path_counts[path], path))[0])
        union_actions = set().union(*(set(path) for path in paths)) if paths else set()
        observation_steps = {
            step.observation_id: (instance, step) for instance in items for step in instance.steps
        }
        prerequisite_evidence: dict[tuple[str, str, int, int], dict[str, set[str]]] = defaultdict(
            lambda: {"instances": set(), "links": set(), "observations": set(), "bases": set()}
        )
        for link in propagation:
            if not is_merge_capable_relationship(link):
                continue
            source = observation_steps.get(link.source_observation_id)
            destination = observation_steps.get(link.destination_observation_id)
            if source is None or destination is None or source[0].id != destination[0].id:
                continue
            source_instance, source_step = source
            _destination_instance, destination_step = destination
            if (
                source_step.position >= destination_step.position
                or destination_step.method in {"GET", "HEAD", "OPTIONS"}
                or _has_alternative_causal_path(link, propagation)
            ):
                continue
            key = (
                source_step.action_name,
                destination_step.action_name,
                source_step.position,
                destination_step.position,
            )
            prerequisite_evidence[key]["instances"].add(source_instance.id)
            prerequisite_evidence[key]["links"].add(link.id)
            prerequisite_evidence[key]["observations"].update(link.evidence)
            prerequisite_evidence[key]["bases"].add(link.causal_basis.value)
        prerequisites: list[WorkflowPrerequisite] = []
        for key, evidence in sorted(prerequisite_evidence.items()):
            prerequisite_action, dependent_action, prerequisite_position, dependent_position = key
            comparable = [
                instance
                for instance in items
                if len(instance.steps) >= dependent_position
                and instance.steps[prerequisite_position - 1].action_name == prerequisite_action
                and instance.steps[dependent_position - 1].action_name == dependent_action
            ]
            support_count = len(evidence["instances"])
            comparable_count = max(len(comparable), support_count, 1)
            counterexamples = sorted(
                instance.id for instance in comparable if instance.id not in evidence["instances"]
            )
            support_ratio = support_count / comparable_count
            prerequisites.append(
                WorkflowPrerequisite(
                    prerequisite_action=prerequisite_action,
                    dependent_action=dependent_action,
                    prerequisite_position=prerequisite_position,
                    dependent_position=dependent_position,
                    support_count=support_count,
                    comparable_instances=comparable_count,
                    support_ratio=support_ratio,
                    causal_link_ids=sorted(evidence["links"]),
                    causal_bases=[CausalBasis(value) for value in sorted(evidence["bases"])],
                    supporting_observations=sorted(evidence["observations"]),
                    counterexamples=counterexamples,
                    confidence=(
                        InferenceConfidence.HIGH_EVIDENCE
                        if support_ratio == 1.0 and not counterexamples
                        else InferenceConfidence.MODERATE_EVIDENCE
                    ),
                    reason=(
                        "Merge-capable producer evidence supports this prerequisite: "
                        + ", ".join(sorted(evidence["bases"]))
                        + "."
                    ),
                )
            )
        required = {
            action
            for prerequisite in prerequisites
            if prerequisite.support_ratio == 1.0
            for action in (prerequisite.prerequisite_action, prerequisite.dependent_action)
        }
        optional = sorted(union_actions - required)
        branch_points: set[str] = set()
        next_actions: dict[str, set[str]] = defaultdict(set)
        for path in paths:
            for left, right in zip(path, path[1:], strict=False):
                next_actions[left].add(right)
        branch_points.update(action for action, targets in next_actions.items() if len(targets) > 1)
        transitions = Counter(
            f"{left} -> {right}"
            for path in paths
            for left, right in zip(path, path[1:], strict=False)
        )
        outcomes = Counter(item.terminal_outcome or "UNRESOLVED" for item in items)
        resource_types = sorted(
            {resource_type for item in items for resource_type in item.resource_types}
        )
        actors = sorted({actor for item in items for actor in item.actors})
        capture_modes = sorted({mode for item in items for mode in item.capture_modes})
        evidence_instances = len(evidence_items)
        confidence = (
            InferenceConfidence.HIGH_EVIDENCE
            if evidence_instances >= 3
            else InferenceConfidence.MODERATE_EVIDENCE
            if evidence_instances >= 2
            else InferenceConfidence.WEAK_EVIDENCE
        )
        family_name = _family_name(common_path, resource_types)
        structural_hash, ordered_signature, causal_topology, terminal_steps = _structural_signature(
            items[0].steps, propagation
        )
        supported_position_pairs = {
            (item.prerequisite_position, item.dependent_position) for item in prerequisites
        }
        research_clues = [
            f"Adjacent positions {left.position}->{right.position} "
            f"({left.action_name} -> {right.action_name}) lack hard causal evidence."
            for left, right in zip(items[0].steps, items[0].steps[1:], strict=False)
            if (left.position, right.position) not in supported_position_pairs
        ]
        explanation = [
            f"Derived from {len(items)} workflow instance(s), including "
            f"{evidence_instances} with moderate-or-better segmentation evidence."
        ]
        if len(items) < 2:
            explanation.append(
                "A single instance cannot establish mandatory steps or authorization policy."
            )
        if prerequisites:
            explanation.append(
                "Required-looking steps come only from typed hard producer-consumer evidence."
            )
        families.append(
            WorkflowFamily(
                id=family_id,
                name=family_name,
                entry_actions=sorted({path[0] for path in paths if path}),
                terminal_actions=sorted({path[-1] for path in paths if path}),
                observed_paths=[list(path) for path in sorted(set(paths))],
                common_path=common_path,
                optional_steps=optional,
                required_looking_steps=sorted(required),
                branch_points=sorted(branch_points),
                actors=actors,
                capture_modes=capture_modes,
                resource_types=resource_types,
                transition_frequencies=dict(sorted(transitions.items())),
                outcome_distribution=dict(sorted(outcomes.items())),
                structural_signature=structural_hash,
                ordered_step_signature=ordered_signature,
                causal_topology=causal_topology,
                terminal_or_mutating_steps=terminal_steps,
                causal_prerequisites=prerequisites,
                research_clues=research_clues,
                workflow_instance_ids=sorted(item.id for item in items),
                inference_confidence=confidence,
                confidence_explanation=explanation,
            )
        )
    return families


def _states_and_transitions(
    instances: list[WorkflowInstance], families: list[WorkflowFamily]
) -> tuple[list[StateRecord], list[TransitionRecord]]:
    state_evidence: dict[tuple[str, str, str], set[str]] = defaultdict(set)
    transition_evidence: dict[
        tuple[str, str, str, str, tuple[str, ...]],
        list[tuple[WorkflowInstance, WorkflowStep, WorkflowStateObservation]],
    ] = defaultdict(list)
    for instance in instances:
        for step in instance.steps:
            for state in step.state_observations:
                resource_types = (state.resource_type,)
                state_evidence[(state.resource_type, state.state_after, state.derivation)].add(
                    step.observation_id
                )
                transition_evidence[
                    (
                        instance.family_id,
                        state.state_before or "UNRESOLVED",
                        step.action_name,
                        state.state_after,
                        resource_types,
                    )
                ].append((instance, step, state))
    states = [
        StateRecord(
            id=_identifier("STATE", {"resource": resource, "name": name, "derivation": derivation}),
            resource_type=resource,
            name=name,
            derivation=derivation,  # type: ignore[arg-type]
            observations=sorted(evidence),
            confidence=(
                InferenceConfidence.HIGH_EVIDENCE
                if derivation == "EXPLICIT_FIELD" and len(evidence) >= 2
                else InferenceConfidence.MODERATE_EVIDENCE
                if derivation == "EXPLICIT_FIELD"
                else InferenceConfidence.WEAK_EVIDENCE
            ),
            epistemic_status=(
                EpistemicStatus.OBSERVED_FACT
                if derivation == "EXPLICIT_FIELD"
                else EpistemicStatus.INFERRED_PATTERN
            ),
        )
        for (resource, name, derivation), evidence in sorted(state_evidence.items())
    ]
    transitions: list[TransitionRecord] = []
    for key, examples in sorted(transition_evidence.items()):
        family_id, source, action, destination, resources = key
        action_id = examples[0][1].action_id
        evidence = sorted({step.observation_id for _instance, step, _state in examples})
        explicit = sum(state.derivation == "EXPLICIT_FIELD" for _instance, _step, state in examples)
        transitions.append(
            TransitionRecord(
                id=_identifier(
                    "TRANS",
                    {
                        "family": family_id,
                        "source": source,
                        "action": action,
                        "destination": destination,
                        "resources": resources,
                    },
                ),
                workflow_family_id=family_id,
                source_state=source,
                action_id=action_id,
                action_name=action,
                destination_state=destination,
                actors=sorted({step.actor for _instance, step, _state in examples}),
                preconditions=[f"Resource state is {source}"] if source != "UNRESOLVED" else [],
                resource_types=list(resources),
                frequency=len(examples),
                examples=sorted(instance.id for instance, _step, _state in examples),
                contradictions=[],
                confidence=(
                    InferenceConfidence.HIGH_EVIDENCE
                    if explicit >= 2
                    else InferenceConfidence.MODERATE_EVIDENCE
                    if explicit == 1 or len(examples) >= 2
                    else InferenceConfidence.WEAK_EVIDENCE
                ),
                evidence=evidence,
            )
        )
    family_ids = {item.id for item in families}
    return sorted(states, key=lambda item: item.id), sorted(
        (item for item in transitions if item.workflow_family_id in family_ids),
        key=lambda item: item.id,
    )


def _transition_timing(
    transition: TransitionRecord, instances: dict[str, WorkflowInstance]
) -> float | None:
    timings: list[float] = []
    for instance_id in transition.examples:
        instance = instances.get(instance_id)
        if instance is None:
            continue
        for index, step in enumerate(instance.steps):
            if (
                index == 0
                or step.action_name != transition.action_name
                or (step.state_before or "UNRESOLVED") != transition.source_state
                or (step.state_after or "UNRESOLVED") != transition.destination_state
            ):
                continue
            previous = instance.steps[index - 1]
            if previous.timestamp is None or step.timestamp is None:
                continue
            try:
                elapsed = (
                    datetime.fromisoformat(step.timestamp).timestamp()
                    - datetime.fromisoformat(previous.timestamp).timestamp()
                )
            except ValueError:
                continue
            if elapsed >= 0:
                timings.append(elapsed)
    return float(median(timings)) if timings else None


def _graphs(
    families: list[WorkflowFamily],
    transitions: list[TransitionRecord],
    instances: list[WorkflowInstance],
) -> list[WorkflowGraph]:
    grouped: dict[str, list[TransitionRecord]] = defaultdict(list)
    for transition in transitions:
        grouped[transition.workflow_family_id].append(transition)
    instance_by_id = {item.id: item for item in instances}
    graphs: list[WorkflowGraph] = []
    for family in families:
        items = grouped.get(family.id, [])
        outgoing = {item.source_state for item in items}
        state_names = sorted(
            {state for item in items for state in (item.source_state, item.destination_state)}
        )
        nodes = [
            GraphNode(
                id=_identifier("NODE", {"family": family.id, "state": state}),
                label=state,
                kind=(
                    "TERMINAL"
                    if state in TERMINAL_STATES or state not in outgoing
                    else "CHECKPOINT"
                    if state == "UNRESOLVED"
                    else "STATE"
                ),
            )
            for state in state_names
        ]
        node_ids = {item.label: item.id for item in nodes}
        denominator = max(len(family.workflow_instance_ids), 1)
        edges = [
            GraphEdge(
                id=_identifier("EDGE", {"family": family.id, "transition": item.id}),
                source=node_ids[item.source_state],
                destination=node_ids[item.destination_state],
                action=item.action_name,
                observation_ids=item.evidence,
                workflow_instance_ids=item.examples,
                actors=item.actors,
                resource_types=item.resource_types,
                count=item.frequency,
                relative_frequency=min(item.frequency / denominator, 1.0),
                median_timing_seconds=_transition_timing(item, instance_by_id),
                response_outcomes=[item.destination_state],
                confidence=item.confidence,
                derivation=(
                    "DIRECTLY_OBSERVED"
                    if item.confidence
                    in {
                        InferenceConfidence.HIGH_EVIDENCE,
                        InferenceConfidence.MODERATE_EVIDENCE,
                    }
                    and item.destination_state != "UNRESOLVED"
                    else "INFERRED"
                ),
            )
            for item in items
        ]
        graphs.append(
            WorkflowGraph(
                id=_identifier("GRAPH", {"family": family.id}),
                workflow_family_id=family.id,
                nodes=sorted(nodes, key=lambda item: item.id),
                edges=sorted(edges, key=lambda item: item.id),
            )
        )
    return graphs


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    temporary.replace(path)


def build_behavior_model(workspace: WorkspacePaths) -> BehaviorBuildResult:
    """Reconstruct structured workflows using only passive, already-redacted evidence."""

    try:
        observations = ObservationStore.model_validate(load_yaml(workspace.observations))
        endpoints = EndpointStore.model_validate(load_yaml(workspace.endpoints))
    except (OSError, ValidationError) as error:
        raise FinsecError(f"Cannot load behavior-analysis inputs: {error}") from error
    if not observations.observations:
        raise FinsecError("No observations are available; ingest passive captures first.")
    if not endpoints.endpoints:
        raise FinsecError("Endpoint inventory is empty; run 'hunt inventory' first.")

    extracted = extract_exchange_facts(workspace, observations.observations, endpoints)
    facts, suppressed_noise = _active_facts(extracted)
    normal_facts = _normal_behavior_facts(facts)
    actions, observation_actions = _actions(facts)
    resources, observation_resources, _fingerprint_resources = _resources(facts)
    propagation = _propagation(facts)
    components = _components(normal_facts, propagation)
    instances = _workflow_instances(
        components, observation_actions, observation_resources, resources, propagation
    )
    families = _workflow_families(instances, propagation)
    states, transitions = _states_and_transitions(instances, families)
    graphs = _graphs(families, transitions, instances)

    write_yaml(workspace.behavior_actions, ActionStore(actions=actions).model_dump(mode="json"))
    write_yaml(
        workspace.behavior_resources,
        ResourceInstanceStore(resource_instances=resources).model_dump(mode="json"),
    )
    write_yaml(
        workspace.propagation_links,
        PropagationStore(propagation_links=propagation).model_dump(mode="json"),
    )
    write_yaml(
        workspace.workflow_instances,
        WorkflowInstanceStore(workflow_instances=instances).model_dump(mode="json"),
    )
    write_yaml(
        workspace.workflow_families,
        WorkflowFamilyStore(workflow_families=families).model_dump(mode="json"),
    )
    write_yaml(workspace.behavior_states, StateStore(states=states).model_dump(mode="json"))
    write_yaml(
        workspace.behavior_transitions,
        TransitionStore(transitions=transitions).model_dump(mode="json"),
    )
    for graph in graphs:
        _write_json(
            workspace.workflow_graphs / f"{graph.workflow_family_id}.json",
            graph.model_dump(mode="json"),
        )
    return BehaviorBuildResult(
        observations_considered=len(facts),
        actions=len(actions),
        resource_instances=len(resources),
        propagation_links=len(propagation),
        workflow_instances=len(instances),
        workflow_families=len(families),
        states=len(states),
        transitions=len(transitions),
        suppressed_noise=suppressed_noise,
    )


def load_workflow_instances(workspace: WorkspacePaths) -> WorkflowInstanceStore:
    try:
        return WorkflowInstanceStore.model_validate(load_yaml(workspace.workflow_instances))
    except (OSError, ValidationError) as error:
        raise FinsecError(f"Cannot load workflow instances: {error}") from error


def load_workflow_families(workspace: WorkspacePaths) -> WorkflowFamilyStore:
    try:
        return WorkflowFamilyStore.model_validate(load_yaml(workspace.workflow_families))
    except (OSError, ValidationError) as error:
        raise FinsecError(f"Cannot load workflow families: {error}") from error


def load_transitions(workspace: WorkspacePaths) -> TransitionStore:
    try:
        return TransitionStore.model_validate(load_yaml(workspace.behavior_transitions))
    except (OSError, ValidationError) as error:
        raise FinsecError(f"Cannot load behavior transitions: {error}") from error


def load_propagation(workspace: WorkspacePaths) -> PropagationStore:
    try:
        return PropagationStore.model_validate(load_yaml(workspace.propagation_links))
    except (OSError, ValidationError) as error:
        raise FinsecError(f"Cannot load propagation links: {error}") from error


def load_workflow_graph(workspace: WorkspacePaths, workflow_id: str) -> WorkflowGraph:
    path = workspace.workflow_graphs / f"{workflow_id.upper()}.json"
    if not path.is_file():
        path = workspace.workflow_graphs / f"{workflow_id}.json"
    try:
        return WorkflowGraph.model_validate_json(path.read_text(encoding="utf-8"))
    except (OSError, ValidationError) as error:
        raise FinsecError(f"Cannot load workflow graph {workflow_id}: {error}") from error


def find_workflow_family(workspace: WorkspacePaths, workflow_id: str) -> WorkflowFamily:
    wanted = workflow_id.upper()
    for family in load_workflow_families(workspace).workflow_families:
        if family.id.upper() == wanted:
            return family
    raise FinsecError(f"Workflow family not found: {workflow_id}")


def median_transition_timing(steps: Iterable[WorkflowStep]) -> float | None:
    """Return a deterministic median for callers that have adjacent timestamped steps."""

    ordered = list(steps)
    values: list[float] = []
    for left, right in zip(ordered, ordered[1:], strict=False):
        if left.timestamp is None or right.timestamp is None:
            continue
        try:
            values.append(
                datetime.fromisoformat(right.timestamp).timestamp()
                - datetime.fromisoformat(left.timestamp).timestamp()
            )
        except ValueError:
            continue
    return float(median(values)) if values else None
