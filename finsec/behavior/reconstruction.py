"""Deterministic workflow reconstruction, state inference, and graph persistence."""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from statistics import median
from typing import Any, Literal, cast

from pydantic import ValidationError

from finsec.behavior.domain import (
    ActionRecord,
    ActionStore,
    EpistemicStatus,
    GraphEdge,
    GraphNode,
    InferenceConfidence,
    PropagationLink,
    PropagationStore,
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
    WorkflowStateObservation,
    WorkflowStep,
)
from finsec.behavior.extraction import ExchangeFacts, ScalarSignal, extract_exchange_facts
from finsec.config.workspace import WorkspacePaths
from finsec.errors import FinsecError
from finsec.modeling.merge import stable_fingerprint
from finsec.modeling.models import EndpointStore, ObservationStore
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
        observation.capture_identity or observation.source_reference.split("#", 1)[0],
        observation.sequence_position if observation.sequence_position is not None else 10**9,
        observation.id,
    )


def _capture_scope(facts: ExchangeFacts) -> str:
    observation = facts.observation
    return (
        observation.session_identity
        or observation.capture_identity
        or observation.source_reference.split("#", 1)[0]
    )


def _is_read(facts: ExchangeFacts) -> bool:
    return facts.endpoint is not None and facts.endpoint.action.type == "read"


def _noise_observations(facts: list[ExchangeFacts]) -> set[str]:
    grouped: dict[tuple[str, str, str], list[ExchangeFacts]] = defaultdict(list)
    for item in facts:
        grouped[(item.observation.actor, item.observation.path, item.action_name)].append(item)
    noise: set[str] = set()
    for (_actor, path, _action), items in grouped.items():
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
    }


def _resources(
    facts: list[ExchangeFacts],
) -> tuple[list[ResourceInstance], dict[str, list[str]], dict[tuple[str, str], str]]:
    grouped: dict[tuple[str, str], list[tuple[ExchangeFacts, ScalarSignal]]] = defaultdict(list)
    for item in facts:
        for signal in _resource_signals(item):
            resource_type = signal.resource_type or "resource"
            grouped[(resource_type, signal.fingerprint)].append((item, signal))
    observation_resources: dict[str, list[str]] = defaultdict(list)
    fingerprint_resources: dict[tuple[str, str], str] = {}
    resources: list[ResourceInstance] = []
    raw_relationships: dict[str, list[ResourceRelationship]] = defaultdict(list)
    for (resource_type, fingerprint), items in sorted(grouped.items()):
        resource_id = _identifier("RINST", {"type": resource_type, "value": fingerprint})
        fingerprint_resources[(resource_type, fingerprint)] = resource_id
        observations = sorted({item.observation.id for item, _signal in items})
        actors = sorted({item.observation.actor for item, _signal in items})
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
                confidence=InferenceConfidence.HIGH_EVIDENCE,
            )
        )

    resource_by_id = {item.id: item for item in resources}
    for observation_id, resource_ids in sorted(observation_resources.items()):
        unique = sorted(set(resource_ids))
        for source_id in unique:
            source = resource_by_id[source_id]
            for target_id in unique:
                if source_id == target_id:
                    continue
                target = resource_by_id[target_id]
                relation: Literal["owned_by", "linked_to"] = (
                    "owned_by"
                    if target.resource_type in SCOPE_RESOURCE_TYPES
                    and source.resource_type not in SCOPE_RESOURCE_TYPES
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


def _propagation(facts: list[ExchangeFacts]) -> list[PropagationLink]:
    ordered = sorted(facts, key=_order_key)
    request_by_value: dict[
        tuple[str, str | None, str], list[tuple[int, ExchangeFacts, ScalarSignal]]
    ] = defaultdict(list)
    for index, item in enumerate(ordered):
        for signal in item.request_signals:
            if signal.kind == "BUSINESS_VALUE":
                continue
            request_by_value[(signal.kind, signal.resource_type, signal.fingerprint)].append(
                (index, item, signal)
            )
    links: list[PropagationLink] = []
    for source_index, source in enumerate(ordered):
        for signal in source.response_signals:
            if signal.kind == "BUSINESS_VALUE":
                continue
            compatible: list[tuple[int, ExchangeFacts, ScalarSignal]] = []
            for destination_index, destination, destination_signal in request_by_value.get(
                (signal.kind, signal.resource_type, signal.fingerprint), []
            ):
                if destination_index <= source_index:
                    continue
                elapsed = _elapsed(source, destination)
                if elapsed is not None and elapsed < 0:
                    continue
                if signal.kind == "RESOURCE_IDENTIFIER" and (
                    source.observation.actor != destination.observation.actor
                    or (elapsed is not None and elapsed > 86400)
                ):
                    continue
                compatible.append((destination_index, destination, destination_signal))
            if not compatible:
                continue
            destination_index, destination, destination_signal = min(
                compatible, key=lambda item: item[0]
            )
            payload = {
                "value": signal.fingerprint,
                "source": source.observation.id,
                "source_field": signal.field,
                "destination": destination.observation.id,
                "destination_field": destination_signal.field,
            }
            links.append(
                PropagationLink(
                    id=_identifier("PROP", payload),
                    value_fingerprint=signal.fingerprint,
                    value_kind=signal.kind,
                    destination_value_kind=destination_signal.kind,
                    source_resource_type=signal.resource_type,
                    destination_resource_type=destination_signal.resource_type,
                    source_observation_id=source.observation.id,
                    source_field=signal.field,
                    destination_observation_id=destination.observation.id,
                    destination_field=destination_signal.field,
                    evidence=[source.observation.id, destination.observation.id],
                    confidence=(
                        InferenceConfidence.HIGH_EVIDENCE
                        if signal.kind in {"WORKFLOW_TOKEN", "CORRELATION_ID", "IDEMPOTENCY_KEY"}
                        else InferenceConfidence.MODERATE_EVIDENCE
                    ),
                )
            )
    return sorted({item.id: item for item in links}.values(), key=lambda item: item.id)


def _elapsed(left: ExchangeFacts, right: ExchangeFacts) -> float | None:
    left_timestamp = _timestamp(left.observation.timestamp)
    right_timestamp = _timestamp(right.observation.timestamp)
    if left_timestamp is None or right_timestamp is None:
        return None
    return right_timestamp - left_timestamp


def _components(
    facts: list[ExchangeFacts], propagation: list[PropagationLink]
) -> list[list[ExchangeFacts]]:
    ordered = sorted(facts, key=_order_key)
    index_by_observation = {item.observation.id: index for index, item in enumerate(ordered)}
    union = _UnionFind(len(ordered))
    shared: dict[tuple[str, str | None, str, str | None], list[int]] = defaultdict(list)
    for index, item in enumerate(ordered):
        for signal in item.signals:
            if (
                signal.kind == "RESOURCE_IDENTIFIER"
                and (signal.resource_type or "") in SCOPE_RESOURCE_TYPES
            ):
                continue
            if signal.kind in {"CORRELATION_ID", "IDEMPOTENCY_KEY"}:
                actor_scope = None
                shared[(signal.kind, signal.resource_type, signal.fingerprint, actor_scope)].append(
                    index
                )
    for indexes in shared.values():
        for left_shared, right_shared in zip(indexes, indexes[1:], strict=False):
            union.union(left_shared, right_shared)
    for link in propagation:
        source_index = index_by_observation.get(link.source_observation_id)
        destination_index = index_by_observation.get(link.destination_observation_id)
        if source_index is not None and destination_index is not None:
            union.union(source_index, destination_index)
    for left_index, right_index in zip(range(len(ordered)), range(1, len(ordered)), strict=False):
        left_facts = ordered[left_index]
        right_facts = ordered[right_index]
        same_session = (
            left_facts.observation.actor == right_facts.observation.actor
            and _capture_scope(left_facts) == _capture_scope(right_facts)
        )
        elapsed = _elapsed(left_facts, right_facts)
        close = elapsed is None or 0 <= elapsed <= 300
        left_identifiers = _primary_resource_identifiers(left_facts)
        right_identifiers = _primary_resource_identifiers(right_facts)
        shared_identifier = bool(left_identifiers & right_identifiers)
        direct_sequence = (
            left_facts.endpoint is not None
            and right_facts.endpoint is not None
            and left_facts.endpoint.resource.type == right_facts.endpoint.resource.type
            and (left_facts.endpoint.state_change or right_facts.endpoint.state_change)
            and not left_identifiers
            and not right_identifiers
        )
        if same_session and close and (shared_identifier or direct_sequence):
            union.union(left_index, right_index)
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


def _workflow_instances(
    components: list[list[ExchangeFacts]],
    observation_actions: dict[str, str],
    observation_resources: dict[str, list[str]],
    resources: list[ResourceInstance],
) -> list[WorkflowInstance]:
    drafts: list[tuple[str, dict[str, Any], list[ExchangeFacts]]] = []
    for items in components:
        action_names = [item.action_name for item in items]
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
        family_name = _family_name(action_names, resource_types)
        endpoint_resources = sorted(
            {
                item.endpoint.resource.type.lower()
                for item in items
                if item.endpoint is not None and item.endpoint.resource.type != "Unknown"
            }
        )
        mutation_resources = sorted(
            {
                item.endpoint.resource.type.lower()
                for item in items
                if item.endpoint is not None
                and item.endpoint.resource.type != "Unknown"
                and item.endpoint.state_change
            }
        )
        family_resources = mutation_resources or endpoint_resources
        family_id = _identifier("WFAM", {"name": family_name, "resources": family_resources})
        resource_ids = sorted(
            {
                resource_id
                for item in items
                for resource_id in observation_resources.get(item.observation.id, [])
            }
        )
        actors = sorted({item.observation.actor for item in items})
        signature = {
            "family": family_id,
            "actors": actors,
            "resources": resource_ids,
            "resource_types": resource_types,
            "actions": action_names,
            "start": items[0].observation.timestamp.isoformat()
            if items[0].observation.timestamp
            else None,
        }
        drafts.append((stable_fingerprint(signature), signature, items))

    duplicate_numbers: dict[str, int] = defaultdict(int)
    resource_types_by_id = {item.id: item.resource_type.lower() for item in resources}
    instances: list[WorkflowInstance] = []
    for signature_hash, signature, items in sorted(drafts, key=lambda item: item[0]):
        duplicate_numbers[signature_hash] += 1
        workflow_id = _identifier(
            "WFINST",
            {"signature": signature, "duplicate": duplicate_numbers[signature_hash]},
        )
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
                    endpoint_ids=[item.endpoint.id] if item.endpoint is not None else [],
                    actor=item.observation.actor,
                    timestamp=item.observation.timestamp.isoformat()
                    if item.observation.timestamp
                    else None,
                    resource_instance_ids=resource_ids,
                    state_observations=state_observations,
                    business_values=business_values,
                    state_before=representative.state_before if representative else None,
                    state_after=representative.state_after if representative else None,
                    state_derivation=(
                        representative.derivation if representative else "UNRESOLVED"
                    ),
                )
            )
        ambiguities: list[str] = []
        if len(items) == 1:
            ambiguities.append("Only one meaningful observation was available for this journey.")
        if not any(observation_resources.get(item.observation.id) for item in items):
            ambiguities.append("No concrete resource identifier linked the observations.")
        if any(item.observation.timestamp is None for item in items):
            ambiguities.append("At least one observation had no timestamp; capture order was used.")
        confidence = (
            InferenceConfidence.HIGH_EVIDENCE
            if len(items) >= 3 and not ambiguities and explicit_states >= 1
            else InferenceConfidence.MODERATE_EVIDENCE
            if len(items) >= 2 and (explicit_states or not ambiguities)
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
                family_id=str(signature["family"]),
                actors=cast(list[str], signature["actors"]),
                sessions=sorted(
                    {
                        item.observation.session_identity
                        or item.observation.capture_identity
                        or item.observation.source_reference.split("#", 1)[0]
                        for item in items
                    }
                ),
                resource_instance_ids=cast(list[str], signature["resources"]),
                resource_types=cast(list[str], signature["resource_types"]),
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


def _workflow_families(instances: list[WorkflowInstance]) -> list[WorkflowFamily]:
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
        required = (
            set.intersection(*(set(path) for path in evidence_paths))
            if len(evidence_paths) >= 2
            else set()
        )
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
        evidence_instances = len(evidence_items)
        confidence = (
            InferenceConfidence.HIGH_EVIDENCE
            if evidence_instances >= 3
            else InferenceConfidence.MODERATE_EVIDENCE
            if evidence_instances >= 2
            else InferenceConfidence.WEAK_EVIDENCE
        )
        family_name = _family_name(common_path, resource_types)
        explanation = [
            f"Derived from {len(items)} workflow instance(s), including "
            f"{evidence_instances} with moderate-or-better segmentation evidence."
        ]
        if len(items) < 2:
            explanation.append(
                "A single instance cannot establish mandatory steps or authorization policy."
            )
        if required:
            explanation.append(
                "Required-looking steps are the intersection of at least two observed paths."
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
                resource_types=resource_types,
                transition_frequencies=dict(sorted(transitions.items())),
                outcome_distribution=dict(sorted(outcomes.items())),
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
    actions, observation_actions = _actions(facts)
    resources, observation_resources, _fingerprint_resources = _resources(facts)
    propagation = _propagation(facts)
    components = _components(facts, propagation)
    instances = _workflow_instances(
        components, observation_actions, observation_resources, resources
    )
    families = _workflow_families(instances)
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
