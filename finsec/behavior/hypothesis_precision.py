"""Canonical semantics, evidence qualification, clustering, and queue ranking."""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass

from finsec.behavior.domain import (
    ActionStore,
    BusinessInvariant,
    HypothesisCluster,
    HypothesisConfidence,
    HypothesisEvidence,
    HypothesisEvidenceStrength,
    HypothesisPromotion,
    HypothesisQualification,
    HypothesisReadiness,
    HypothesisSemantics,
    HypothesisSupportContext,
    IndependentHypothesisSupport,
    InferenceConfidence,
    LogicHypothesis,
    PropagationStore,
    RelationshipType,
    SemanticLabel,
    SemanticLabelBasis,
    SemanticLabelConfidence,
    TransitionStore,
    WorkflowFamily,
    WorkflowFamilyStore,
    WorkflowInstance,
    WorkflowInstanceStore,
)
from finsec.captures.domain import CaptureMode
from finsec.config.models import TargetDocument
from finsec.modeling.merge import stable_fingerprint
from finsec.modeling.models import (
    Endpoint,
    EndpointPrimaryClassification,
    EndpointStore,
    Observation,
    ObservationStore,
)

_ORDERING_FAMILIES = {"OUT_OF_ORDER_EXECUTION", "STEP_SKIPPING"}
_NOISE_CLASSIFICATIONS = {
    EndpointPrimaryClassification.STATIC_ASSET,
    EndpointPrimaryClassification.TELEMETRY,
    EndpointPrimaryClassification.ANALYTICS,
    EndpointPrimaryClassification.THIRD_PARTY,
}
_TRACKING_MARKERS = {
    "analytics",
    "beacon",
    "collect",
    "event",
    "metrics",
    "pixel",
    "telemetry",
    "track",
    "tracking",
}
_STATIC_SUFFIXES = {
    "css",
    "gif",
    "ico",
    "jpeg",
    "jpg",
    "js",
    "json",
    "map",
    "png",
    "svg",
    "txt",
    "webp",
    "woff",
    "woff2",
}
_GENERIC_TOKENS = {
    "api",
    "app",
    "data",
    "endpoint",
    "object",
    "operation",
    "resource",
    "unknown",
    "v1",
    "v2",
    "v3",
}
_KNOWN_VERBS = {
    "ACCEPT",
    "ACTIVATE",
    "ADD",
    "APPROVE",
    "CANCEL",
    "CAPTURE",
    "CLAIM",
    "CLOSE",
    "COMPLETE",
    "CONFIRM",
    "CONSUME",
    "CREATE",
    "DELETE",
    "EXECUTE",
    "EXPIRE",
    "GET",
    "INITIATE",
    "INVITE",
    "LIST",
    "PAY",
    "READ",
    "REDEEM",
    "REFUND",
    "REJECT",
    "REPLACE",
    "REQUEST",
    "RETURN",
    "REVERSE",
    "REVIEW",
    "SETTLE",
    "SHIP",
    "SUBMIT",
    "TRANSFER",
    "UPDATE",
    "WITHDRAW",
}
_PROMOTION_RANK = {
    HypothesisPromotion.SUPPRESSED: 0,
    HypothesisPromotion.RESEARCH_LOW: 1,
    HypothesisPromotion.RESEARCH_MEDIUM: 2,
    HypothesisPromotion.RESEARCH_HIGH: 3,
    HypothesisPromotion.REVIEW_REQUIRED: 4,
    HypothesisPromotion.TEST_READY: 5,
}
_CONFIDENCE_RANK = {
    HypothesisConfidence.LOW: 1,
    HypothesisConfidence.MEDIUM: 2,
    HypothesisConfidence.HIGH: 3,
}
_EVIDENCE_RANK = {
    HypothesisEvidenceStrength.INSUFFICIENT: 0,
    HypothesisEvidenceStrength.WEAK: 1,
    HypothesisEvidenceStrength.MODERATE: 2,
    HypothesisEvidenceStrength.STRONG: 3,
}


@dataclass(frozen=True)
class HypothesisPrecisionInputs:
    """Read-only inputs needed to qualify raw business-logic candidates."""

    target: TargetDocument
    observations: ObservationStore
    endpoints: EndpointStore
    actions: ActionStore
    instances: WorkflowInstanceStore
    families: WorkflowFamilyStore
    transitions: TransitionStore
    propagation: PropagationStore
    invariants: list[BusinessInvariant]


@dataclass(frozen=True)
class HypothesisPrecisionResult:
    """Qualified raw candidates plus their researcher-facing semantic clusters."""

    hypotheses: list[LogicHypothesis]
    clusters: list[HypothesisCluster]


def _score_total(item: LogicHypothesis) -> int:
    score = item.score
    return score.impact + score.likelihood + score.confidence + score.test_readiness


def _human(value: str) -> str:
    return value.replace("_", " ").strip().lower()


def _normalized_word(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9]+", "_", value).strip("_").upper()


def _utf8_byte_fragment(tokens: list[str]) -> bool:
    for index, token in enumerate(tokens):
        if not re.fullmatch(r"[0-9A-Fa-f]{2}", token):
            continue
        first = int(token, 16)
        if not 0xC2 <= first <= 0xF4:
            continue
        continuation = 1 if first <= 0xDF else 2 if first <= 0xEF else 3
        following = tokens[index + 1 : index + 1 + continuation]
        if len(following) == continuation and all(
            re.fullmatch(r"[0-9A-Fa-f]{2}", item) and 0x80 <= int(item, 16) <= 0xBF
            for item in following
        ):
            return True
    return False


def _opaque_token(value: str) -> bool:
    compact = value.replace("-", "")
    if re.fullmatch(r"[0-9a-fA-F]{16,}", compact):
        return True
    if len(compact) >= 24 and compact.isalnum() and any(char.isdigit() for char in compact):
        return True
    return bool(
        re.fullmatch(
            r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
            r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
            value,
        )
    )


def _route_hygiene(endpoints: list[Endpoint]) -> list[str]:
    reasons: set[str] = set()
    for endpoint in endpoints:
        path = endpoint.path
        lowered = path.lower()
        if re.search(r"%[0-9a-f]{2}", lowered):
            reasons.add("PERCENT_ENCODED_FRAGMENT")
        if any(ord(character) > 127 for character in path):
            reasons.add("NON_ASCII_ROUTE_FRAGMENT")
        segments = [segment for segment in path.strip("/").split("/") if segment]
        if _utf8_byte_fragment(re.split(r"[_\-\s]+", "_".join(segments))):
            reasons.add("UTF8_BYTE_FRAGMENT")
        if any(marker in lowered for marker in _TRACKING_MARKERS):
            reasons.add("TRACKING_OR_TELEMETRY_ROUTE")
        for segment in segments:
            suffix = segment.rsplit(".", 1)[-1].lower() if "." in segment else ""
            if suffix in _STATIC_SUFFIXES:
                reasons.add("STATIC_OR_MIME_FILENAME")
            if _opaque_token(segment):
                reasons.add("OPAQUE_ROUTE_FRAGMENT")
        if endpoint.classification.primary in _NOISE_CLASSIFICATIONS:
            reasons.add("NON_BUSINESS_ENDPOINT_CLASSIFICATION")
    return sorted(reasons)


def _method_verb(endpoints: list[Endpoint]) -> str:
    methods = {endpoint.method for endpoint in endpoints}
    if len(methods) != 1:
        return "OPERATION"
    method = next(iter(methods))
    return {
        "DELETE": "DELETE",
        "GET": "READ",
        "HEAD": "READ",
        "PATCH": "UPDATE",
        "POST": "EXECUTE",
        "PUT": "REPLACE",
    }.get(method, "OPERATION")


def _valid_semantic_token(value: str) -> bool:
    return bool(
        value
        and re.fullmatch(r"[A-Za-z][A-Za-z0-9-]{1,31}", value)
        and not _opaque_token(value)
        and value.lower() not in _STATIC_SUFFIXES
    )


def semantic_label(
    raw_action: str,
    endpoints: list[Endpoint],
    resource_types: list[str],
) -> SemanticLabel:
    """Return a deterministic safe label without changing the retained raw action."""

    action_tokens = [token for token in re.split(r"[_\-\s]+", raw_action) if token]
    hygiene = set(_route_hygiene(endpoints))
    if _utf8_byte_fragment(action_tokens):
        hygiene.add("UTF8_BYTE_FRAGMENT")
    if re.search(r"%[0-9a-fA-F]{2}", raw_action):
        hygiene.add("PERCENT_ENCODED_FRAGMENT")
    if any(_opaque_token(token) for token in action_tokens):
        hygiene.add("OPAQUE_ACTION_FRAGMENT")

    raw_verb = _normalized_word(action_tokens[0]) if action_tokens else ""
    verb = (
        raw_verb
        if raw_verb in _KNOWN_VERBS or (action_tokens and _valid_semantic_token(action_tokens[0]))
        else _method_verb(endpoints)
    )
    action_resources = [
        token.lower()
        for token in action_tokens[1:]
        if _valid_semantic_token(token)
        and token.lower() not in _GENERIC_TOKENS
        and not re.fullmatch(r"[0-9A-Fa-f]{2}", token)
    ]
    modeled_resources = [
        value.lower().replace("-", "_")
        for value in resource_types
        if _valid_semantic_token(value)
        and value.lower() not in _GENERIC_TOKENS
        and not _utf8_byte_fragment([token for token in re.split(r"[_\-\s]+", value) if token])
    ]
    resource = next(iter(action_resources), None) or next(iter(modeled_resources), None)
    if resource is None:
        resource = "resource"

    if hygiene:
        confidence = SemanticLabelConfidence.LOW
        basis = SemanticLabelBasis.NEUTRAL_FALLBACK
        if not action_resources and not modeled_resources:
            resource = "resource"
    elif endpoints and all(
        endpoint.action.name != "unknown" and endpoint.resource.type != "resource"
        for endpoint in endpoints
    ):
        confidence = SemanticLabelConfidence.HIGH
        basis = SemanticLabelBasis.ENDPOINT_MODEL
    elif endpoints:
        confidence = SemanticLabelConfidence.MEDIUM
        basis = SemanticLabelBasis.ROUTE_AND_METHOD
    elif raw_verb in _KNOWN_VERBS and resource != "resource":
        confidence = SemanticLabelConfidence.MEDIUM
        basis = SemanticLabelBasis.ACTION_STRUCTURE
    else:
        confidence = SemanticLabelConfidence.LOW
        basis = SemanticLabelBasis.NEUTRAL_FALLBACK

    normalized = f"{verb}_{_normalized_word(resource) or 'RESOURCE'}"
    return SemanticLabel(
        value=_human(normalized).capitalize(),
        normalized_value=normalized,
        confidence=confidence,
        basis=basis,
        hygiene_reasons=sorted(hygiene),
    )


def _semantic_route(path: str) -> str:
    segments: list[str] = []
    for raw in path.strip("/").split("/"):
        if not raw:
            continue
        if raw.startswith("{") and raw.endswith("}"):
            segments.append("{id}")
            continue
        if (
            any(ord(character) > 127 for character in raw)
            or re.search(r"%[0-9a-fA-F]{2}", raw)
            or _opaque_token(raw)
        ):
            segments.append("{opaque}")
            continue
        normalized = re.sub(r"[^a-z0-9.-]+", "-", raw.lower()).strip("-")
        segments.append(normalized or "{opaque}")
    return "/" + "/".join(segments)


def _roles(target: TargetDocument, actors: list[str]) -> list[str]:
    roles = {account.id: account.role for account in target.accounts}
    return sorted(
        {
            f"role:{roles[actor].strip().lower()}"
            if actor in roles and roles[actor].strip()
            else f"actor:{actor.lower()}"
            for actor in actors
            if actor not in {"ANONYMOUS", "UNKNOWN"}
        }
    )


def _controlled_fields(instances: list[WorkflowInstance], affected_action: str) -> list[str]:
    return sorted(
        {
            _normalized_word(field)
            for instance in instances
            for step in instance.steps
            if step.action_name == affected_action
            for field in step.client_controlled_resource_fields
            if _normalized_word(field)
        }
    )


def _semantics(
    inputs: HypothesisPrecisionInputs,
    item: LogicHypothesis,
    invariant: BusinessInvariant,
    family: WorkflowFamily,
    endpoints: list[Endpoint],
    instances: list[WorkflowInstance],
) -> HypothesisSemantics:
    resources = sorted(
        set(invariant.resource_types)
        | {endpoint.resource.type for endpoint in endpoints}
        | set(family.resource_types)
        | {item.domain_intent.subject_resource}
        | (
            {item.domain_intent.parent_resource}
            if item.domain_intent.parent_resource is not None
            else set()
        )
    )
    semantic_action = item.affected_action
    if item.domain_intent.operation.value == "READ":
        semantic_action = f"READ_{item.domain_intent.subject_resource}"
    elif item.domain_intent.operation.value == "CREATE_CHILD":
        semantic_action = f"CREATE_{item.domain_intent.subject_resource}"
    label = semantic_label(semantic_action, endpoints, resources)
    subject_resource = item.domain_intent.subject_resource.lower()
    endpoint_dimension = sorted(
        {f"{endpoint.method} {_semantic_route(endpoint.path)}" for endpoint in endpoints}
        | {
            f"{method} {_semantic_route(path)}"
            for method in invariant.candidate_methods
            for path in invariant.candidate_paths
        }
    )
    actor_dimension = (
        _roles(inputs.target, family.actors)
        if item.family in {"ACTOR_SWITCH", "ROLE_APPROVAL_BYPASS"}
        else []
    )
    resource_dimension = sorted(
        {_normalized_word(resource).lower() for resource in resources if _normalized_word(resource)}
    )
    controlled_fields = _controlled_fields(instances, item.affected_action)
    if item.family not in {
        "RESOURCE_SWITCH",
        "CROSS_WORKFLOW_TOKEN_REUSE",
        "PARTIAL_ROLLBACK",
    }:
        resource_dimension = [subject_resource]
    elif controlled_fields:
        resource_dimension.extend(f"field:{field.lower()}" for field in controlled_fields)
        resource_dimension = sorted(set(resource_dimension))

    prerequisite_dimension: list[str] = []
    if item.family in _ORDERING_FAMILIES:
        if invariant.prerequisite_action is not None:
            prerequisite_dimension.append(
                semantic_label(invariant.prerequisite_action, [], []).normalized_value
            )
        if invariant.dependent_action is not None:
            prerequisite_dimension.append(
                semantic_label(invariant.dependent_action, endpoints, resources).normalized_value
            )

    transition_by_id = {transition.id: transition for transition in inputs.transitions.transitions}
    transition = (
        transition_by_id.get(item.affected_transition_id)
        if item.affected_transition_id is not None
        else None
    )
    state_dimension = (
        [transition.source_state, transition.destination_state] if transition is not None else []
    )
    if item.family == "PARTIAL_ROLLBACK":
        state_dimension.extend(f"resource:{value}" for value in resource_dimension)
    state_dimension = sorted(set(state_dimension))

    value_dimension = []
    if item.family == "SHADOW_ENDPOINT":
        value_dimension = sorted(
            {
                _normalized_word(field).lower()
                for field in (
                    *invariant.mutable_value_fields,
                    *invariant.authoritative_value_fields,
                    *invariant.candidate_fields,
                )
                if _normalized_word(field)
            }
        )

    payload = {
        "vulnerability_family": item.family,
        "subject_action": label.normalized_value,
        "subject_resource": subject_resource,
        "parent_resource": item.domain_intent.parent_resource,
        "operation": item.domain_intent.operation,
        "visibility": item.domain_intent.visibility,
        "binding": item.domain_intent.binding,
        "violated_property": invariant.invariant_type,
        "mutation_type": item.family,
        "actor_dimension": actor_dimension,
        "resource_dimension": resource_dimension,
        "state_dimension": state_dimension,
        "prerequisite_dimension": prerequisite_dimension,
        "endpoint_dimension": endpoint_dimension,
        "value_dimension": value_dimension,
    }
    fingerprint = stable_fingerprint(payload)
    return HypothesisSemantics(
        vulnerability_family=item.family,
        subject_action=label.normalized_value,
        subject_resource=subject_resource,
        parent_resource=(
            item.domain_intent.parent_resource.lower()
            if item.domain_intent.parent_resource is not None
            else None
        ),
        operation=item.domain_intent.operation,
        visibility=item.domain_intent.visibility,
        binding=item.domain_intent.binding,
        violated_property=invariant.invariant_type,
        mutation_type=item.family,
        actor_dimension=actor_dimension,
        resource_dimension=resource_dimension,
        state_dimension=state_dimension,
        prerequisite_dimension=prerequisite_dimension,
        endpoint_dimension=endpoint_dimension,
        value_dimension=value_dimension,
        label=label,
        fingerprint=fingerprint,
        canonical_id=f"HCL-{fingerprint[:16].upper()}",
    )


def _relevant_endpoints(inputs: HypothesisPrecisionInputs, item: LogicHypothesis) -> list[Endpoint]:
    selected = set(item.endpoint_ids)
    endpoints = [endpoint for endpoint in inputs.endpoints.endpoints if endpoint.id in selected]
    if endpoints:
        return sorted(endpoints, key=lambda endpoint: endpoint.id)
    candidate_pairs = set(zip(item.candidate_methods, item.candidate_paths, strict=False))
    return sorted(
        [
            endpoint
            for endpoint in inputs.endpoints.endpoints
            if (endpoint.method, endpoint.path) in candidate_pairs
        ],
        key=lambda endpoint: endpoint.id,
    )


def _support_units(
    inputs: HypothesisPrecisionInputs,
    item: LogicHypothesis,
    family_instances: list[WorkflowInstance],
) -> list[IndependentHypothesisSupport]:
    evidence = set(item.observation_ids)
    units: dict[str, IndependentHypothesisSupport] = {}
    for instance in family_instances:
        related_steps = [
            step
            for step in instance.steps
            if step.observation_id in evidence or step.action_name == item.affected_action
        ]
        if not related_steps:
            continue
        actors = sorted(
            {
                actor
                for actor in [*instance.actors, *(step.actor for step in related_steps)]
                if actor not in {"ANONYMOUS", "UNKNOWN"}
            }
        )
        captures = sorted(set(instance.captures))
        resources = sorted(set(instance.resource_instance_ids))
        causal_path = [step.action_name for step in related_steps]
        observations = sorted(step.observation_id for step in related_steps)
        basis: list[str] = []
        if captures:
            basis.append("CAPTURE")
        if actors:
            basis.append("CONTROLLED_ACTOR")
        if resources:
            basis.append("RESOURCE_INSTANCE")
        if causal_path:
            basis.append("CAUSAL_PATH")
        payload: dict[str, object] = {
            "captures": captures,
            "actors": actors,
            "resource_instances": resources,
            "causal_path": causal_path,
        }
        if not basis:
            basis.append("WORKFLOW_INSTANCE_FALLBACK")
            payload["workflow_instance"] = instance.id
        fingerprint = stable_fingerprint(payload)
        support_id = f"HSUP-{fingerprint[:16].upper()}"
        current = units.get(support_id)
        if current is None:
            units[support_id] = IndependentHypothesisSupport(
                id=support_id,
                basis=basis,  # type: ignore[arg-type]
                workflow_instance_ids=[instance.id],
                actors=actors,
                captures=captures,
                resource_instance_ids=resources,
                causal_path=causal_path,
                observation_ids=observations,
            )
        else:
            units[support_id] = current.model_copy(
                update={
                    "workflow_instance_ids": sorted(
                        set(current.workflow_instance_ids) | {instance.id}
                    ),
                    "observation_ids": sorted(set(current.observation_ids) | set(observations)),
                }
            )

    if units:
        return sorted(units.values(), key=lambda support: support.id)

    fallback_observations = [
        observation
        for observation in inputs.observations.observations
        if observation.id in evidence
    ]
    actors = sorted(
        {
            observation.actor
            for observation in fallback_observations
            if observation.actor != "UNKNOWN"
        }
    )
    captures = sorted(
        {
            observation.capture_identity
            for observation in fallback_observations
            if observation.capture_identity is not None
        }
    )
    payload = {
        "captures": captures,
        "actors": actors,
        "action": item.affected_action,
        "endpoints": sorted(item.endpoint_ids),
    }
    fingerprint = stable_fingerprint(payload)
    fallback_basis: list[str] = []
    if captures:
        fallback_basis.append("CAPTURE")
    if actors:
        fallback_basis.append("CONTROLLED_ACTOR")
    fallback_basis.append("CAUSAL_PATH")
    return [
        IndependentHypothesisSupport(
            id=f"HSUP-{fingerprint[:16].upper()}",
            basis=fallback_basis,  # type: ignore[arg-type]
            actors=actors,
            captures=captures,
            causal_path=[item.affected_action],
            observation_ids=sorted(observation.id for observation in fallback_observations),
        )
    ]


def _observations_by_id(inputs: HypothesisPrecisionInputs) -> dict[str, Observation]:
    return {observation.id: observation for observation in inputs.observations.observations}


def _evidence(
    inputs: HypothesisPrecisionInputs,
    item: LogicHypothesis,
    invariant: BusinessInvariant,
    endpoints: list[Endpoint],
    family_instances: list[WorkflowInstance],
    independent_support_count: int,
) -> HypothesisEvidence:
    observation_by_id = _observations_by_id(inputs)
    relevant_observations = [
        observation_by_id[observation_id]
        for observation_id in item.observation_ids
        if observation_id in observation_by_id
    ]
    relevant_steps = [
        step
        for instance in family_instances
        for step in instance.steps
        if step.action_name == item.affected_action
    ]
    authenticated = any(observation.authentication.present for observation in relevant_observations)
    authenticated = authenticated or any(endpoint.authentication.required for endpoint in endpoints)
    state_changing = any(step.state_changing for step in relevant_steps) or any(
        endpoint.state_change for endpoint in endpoints
    )
    endpoint_identifier_names = {
        _normalized_word(parameter.name)
        for endpoint in endpoints
        for parameter in endpoint.parameters
        if parameter.source == "request"
        and parameter.client_controlled
        and parameter.semantic_type == "object_identifier"
    }
    step_identifier_names = {
        _normalized_word(field.rsplit(".", 1)[-1])
        for step in relevant_steps
        for field in step.client_controlled_resource_fields
    }
    controlled_identifier = bool(endpoint_identifier_names) or bool(
        not endpoints and step_identifier_names
    )
    ownership_known = any(
        access.actor_object_binding_observed
        for endpoint in endpoints
        for access in endpoint.object_access
    )
    family_observations = {
        step.observation_id for instance in family_instances for step in instance.steps
    }
    comparison_links = [
        link
        for link in inputs.propagation.propagation_links
        if link.relationship_type == RelationshipType.CROSS_ACTOR_COMPARISON
        and link.source_capture_mode not in {CaptureMode.RESEARCHER_PROBE, CaptureMode.MIXED}
        and link.destination_capture_mode not in {CaptureMode.RESEARCHER_PROBE, CaptureMode.MIXED}
        and family_observations.intersection(link.evidence)
    ]
    comparison_actors = {
        actor
        for link in comparison_links
        for actor in (link.source_actor, link.destination_actor)
        if actor not in {None, "ANONYMOUS", "UNKNOWN"}
    }
    cross_actor_baseline = bool(comparison_links) and len(comparison_actors) >= 2
    causal_prerequisites = bool(invariant.causal_evidence) and bool(
        invariant.prerequisite_action
        and invariant.dependent_action
        and semantic_label(invariant.prerequisite_action, [], []).normalized_value
        != semantic_label(
            invariant.dependent_action, endpoints, invariant.resource_types
        ).normalized_value
    )
    noise = any(endpoint.classification.primary in _NOISE_CLASSIFICATIONS for endpoint in endpoints)
    resource_names = {
        _normalized_word(value).lower()
        for value in [
            *invariant.resource_types,
            *(endpoint.resource.type for endpoint in endpoints),
        ]
        if _normalized_word(value)
    }
    business_resource = not noise and bool(resource_names - _GENERIC_TOKENS)
    resource_instances = {
        resource for instance in family_instances for resource in instance.resource_instance_ids
    }
    instances_with_resources = sum(
        bool(instance.resource_instance_ids) for instance in family_instances
    )
    independently_identifiable = controlled_identifier and bool(resource_instances)
    cross_workflow_resource = (
        controlled_identifier and len(resource_instances) >= 2 and instances_with_resources >= 2
    )
    sensitive_read = (
        not state_changing
        and any(endpoint.method in {"GET", "HEAD"} for endpoint in endpoints)
        and authenticated
        and (ownership_known or any(endpoint.security_relevance >= 4 for endpoint in endpoints))
    )
    sensitive_operation = (
        state_changing
        or sensitive_read
        or item.safety_classification.value not in {"READ_ONLY", "LOW_RISK_STATE_CHANGE"}
        or any(endpoint.security_relevance >= 5 for endpoint in endpoints)
    )
    roles = _roles(
        inputs.target,
        sorted({actor for instance in family_instances for actor in instance.actors}),
    )
    privileged = (
        item.family == "ROLE_APPROVAL_BYPASS"
        or item.affected_action.split("_", 1)[0] in {"APPROVE", "REVIEW"}
        or any(role not in {"role:user", "role:customer", "role:requester"} for role in roles)
    )
    return HypothesisEvidence(
        authenticated=authenticated,
        sensitive_operation=sensitive_operation,
        sensitive_read=sensitive_read,
        state_changing=state_changing,
        controlled_identifier=controlled_identifier,
        ownership_known=ownership_known,
        cross_actor_baseline=cross_actor_baseline,
        causal_prerequisites_proven=causal_prerequisites,
        business_relevant_resource=business_resource,
        independently_identifiable_resource=independently_identifiable,
        cross_workflow_resource=cross_workflow_resource,
        privileged_or_approval_context=privileged,
        independent_support_count=independent_support_count,
    )


def _evidence_strength(
    item: LogicHypothesis, evidence: HypothesisEvidence
) -> HypothesisEvidenceStrength:
    named_count = sum(
        int(value)
        for value in (
            evidence.authenticated,
            evidence.sensitive_operation,
            evidence.state_changing,
            evidence.controlled_identifier,
            evidence.ownership_known,
            evidence.cross_actor_baseline,
            evidence.causal_prerequisites_proven,
            evidence.business_relevant_resource,
            evidence.independently_identifiable_resource,
            evidence.cross_workflow_resource,
            evidence.privileged_or_approval_context,
        )
    )
    if item.family == "ACTOR_SWITCH":
        core = (
            evidence.cross_actor_baseline
            and evidence.controlled_identifier
            and evidence.business_relevant_resource
            and evidence.ownership_known
            and evidence.sensitive_operation
        )
    elif item.family == "RESOURCE_SWITCH":
        core = (
            evidence.controlled_identifier
            and evidence.business_relevant_resource
            and evidence.independently_identifiable_resource
            and evidence.cross_workflow_resource
            and evidence.sensitive_operation
            and (evidence.ownership_known or evidence.causal_prerequisites_proven)
        )
    elif item.family in _ORDERING_FAMILIES:
        core = evidence.causal_prerequisites_proven and evidence.sensitive_operation
    else:
        core = evidence.business_relevant_resource and (
            evidence.sensitive_operation or evidence.privileged_or_approval_context
        )
    if core and evidence.independent_support_count >= 2 and named_count >= 5:
        return HypothesisEvidenceStrength.STRONG
    if core and named_count >= 3:
        return HypothesisEvidenceStrength.MODERATE
    if evidence.business_relevant_resource and evidence.sensitive_operation:
        return HypothesisEvidenceStrength.WEAK
    return HypothesisEvidenceStrength.INSUFFICIENT


def _security_confidence(
    invariant: BusinessInvariant, strength: HypothesisEvidenceStrength
) -> HypothesisConfidence:
    if strength == HypothesisEvidenceStrength.STRONG and invariant.confidence in {
        InferenceConfidence.HIGH_EVIDENCE,
        InferenceConfidence.MODERATE_EVIDENCE,
    }:
        return HypothesisConfidence.HIGH
    if (
        strength
        in {
            HypothesisEvidenceStrength.STRONG,
            HypothesisEvidenceStrength.MODERATE,
        }
        and invariant.confidence != InferenceConfidence.SPECULATIVE
    ):
        return HypothesisConfidence.MEDIUM
    return HypothesisConfidence.LOW


def _self_referential(
    item: LogicHypothesis, invariant: BusinessInvariant, endpoints: list[Endpoint]
) -> bool:
    if item.family not in _ORDERING_FAMILIES:
        return False
    if invariant.prerequisite_action is None or invariant.dependent_action is None:
        return False
    prerequisite = semantic_label(invariant.prerequisite_action, [], []).normalized_value
    dependent = semantic_label(
        invariant.dependent_action, endpoints, invariant.resource_types
    ).normalized_value
    return prerequisite == dependent


def _research_score(
    item: LogicHypothesis,
    label: SemanticLabel,
    evidence: HypothesisEvidence,
    strength: HypothesisEvidenceStrength,
    confidence: HypothesisConfidence,
) -> tuple[int, list[str]]:
    score = _score_total(item) * 3
    reasons = [f"Legacy transparent score contributes {_score_total(item) * 3} points."]
    predicates = {
        "Authenticated operation": evidence.authenticated,
        "Sensitive operation": evidence.sensitive_operation,
        "Controlled identifier": evidence.controlled_identifier,
        "Ownership baseline": evidence.ownership_known,
        "Cross-actor baseline": evidence.cross_actor_baseline,
        "Causal prerequisite": evidence.causal_prerequisites_proven,
        "Business-relevant resource": evidence.business_relevant_resource,
        "Cross-workflow resource": evidence.cross_workflow_resource,
    }
    for reason, present in predicates.items():
        if present:
            score += 3
            reasons.append(f"{reason} contributes 3 points.")
    score += min(evidence.independent_support_count, 3) * 2
    if evidence.independent_support_count:
        reasons.append(
            f"{evidence.independent_support_count} independent support(s) contribute "
            f"{min(evidence.independent_support_count, 3) * 2} points."
        )
    score += _EVIDENCE_RANK[strength] * 3 + _CONFIDENCE_RANK[confidence] * 2
    if label.confidence == SemanticLabelConfidence.HIGH:
        score += 3
        reasons.append("High-confidence semantic naming contributes 3 points.")
    elif label.confidence == SemanticLabelConfidence.LOW:
        score = max(0, score - 4)
        reasons.append("Low-confidence semantic naming reduces presentation score by 4 points.")
    return score, reasons


def _qualification(
    item: LogicHypothesis,
    invariant: BusinessInvariant,
    semantics: HypothesisSemantics,
    evidence: HypothesisEvidence,
    endpoints: list[Endpoint],
) -> HypothesisQualification:
    suppression: list[str] = []
    reasons: list[str] = []
    if _self_referential(item, invariant, endpoints):
        suppression.append("SELF_REFERENTIAL_ORDERING")
        reasons.append(
            "Prerequisite and dependent actions resolve to the same normalized semantic action."
        )
    if any(endpoint.classification.primary in _NOISE_CLASSIFICATIONS for endpoint in endpoints):
        suppression.append("LOW_SECURITY_RELEVANCE")
        reasons.append("The source endpoint is static, telemetry, analytics, or third-party data.")
    if item.family == "ACTOR_SWITCH" and not (
        evidence.cross_actor_baseline
        and evidence.controlled_identifier
        and evidence.business_relevant_resource
        and evidence.sensitive_operation
        and evidence.ownership_known
    ):
        suppression.append("INSUFFICIENT_ACTOR_BINDING_EVIDENCE")
        reasons.append(
            "Actor binding lacks explicit ownership, initiating-actor, session, tenant, role, "
            "or producer-consumer evidence; authentication alone is insufficient."
        )
    if item.family == "RESOURCE_SWITCH" and not (
        evidence.controlled_identifier
        and evidence.business_relevant_resource
        and evidence.independently_identifiable_resource
        and evidence.cross_workflow_resource
        and evidence.sensitive_operation
        and (evidence.ownership_known or evidence.causal_prerequisites_proven)
    ):
        suppression.append("INSUFFICIENT_RESOURCE_SWITCH_EVIDENCE")
        reasons.append(
            "Resource substitution lacks independently identifiable cross-workflow resources "
            "consumed by a sensitive operation."
        )
    if any(
        "stronger endpoint-level object-authorization hypothesis" in reason.lower()
        for reason in item.suppression_reasons
    ):
        suppression.append("OVERLAPS_STRONGER_ENDPOINT_HYPOTHESIS")
        reasons.append(
            "A stronger endpoint-level object-authorization hypothesis already covers this "
            "resource mutation."
        )
    if semantics.label.hygiene_reasons:
        reasons.append(
            "Malformed or opaque naming evidence was replaced with neutral semantic terminology."
        )
        if not (
            evidence.sensitive_operation
            and (
                evidence.ownership_known
                or evidence.cross_actor_baseline
                or evidence.causal_prerequisites_proven
            )
        ):
            suppression.append("MALFORMED_SEMANTIC_LABEL")

    strength = _evidence_strength(item, evidence)
    confidence = _security_confidence(invariant, strength)
    research_score, score_reasons = _research_score(
        item, semantics.label, evidence, strength, confidence
    )
    reasons.extend(score_reasons)
    suppression = sorted(set(suppression))
    if suppression:
        promotion = HypothesisPromotion.SUPPRESSED
    elif (
        item.kind == "SECURITY_HYPOTHESIS"
        and item.readiness == HypothesisReadiness.TEST_READY
        and strength
        not in {
            HypothesisEvidenceStrength.INSUFFICIENT,
            HypothesisEvidenceStrength.WEAK,
        }
        and confidence != HypothesisConfidence.LOW
    ):
        promotion = HypothesisPromotion.TEST_READY
    elif (
        item.kind == "SECURITY_HYPOTHESIS"
        and item.readiness == HypothesisReadiness.REVIEW_REQUIRED
        and strength
        not in {
            HypothesisEvidenceStrength.INSUFFICIENT,
            HypothesisEvidenceStrength.WEAK,
        }
    ):
        promotion = HypothesisPromotion.REVIEW_REQUIRED
    elif strength == HypothesisEvidenceStrength.STRONG and confidence == HypothesisConfidence.HIGH:
        promotion = HypothesisPromotion.RESEARCH_HIGH
    elif strength in {
        HypothesisEvidenceStrength.STRONG,
        HypothesisEvidenceStrength.MODERATE,
    }:
        promotion = HypothesisPromotion.RESEARCH_MEDIUM
    else:
        promotion = HypothesisPromotion.RESEARCH_LOW
    return HypothesisQualification(
        evidence=evidence,
        hypothesis_confidence=confidence,
        evidence_strength=strength,
        promotion=promotion,
        research_score=research_score,
        qualification_reasons=sorted(set(reasons)),
        suppression_reasons=suppression,
    )


def _canonical_title(semantics: HypothesisSemantics) -> str:
    action = semantics.label.value
    prerequisite = (
        _human(semantics.prerequisite_dimension[0])
        if semantics.prerequisite_dimension
        else "the required prerequisite"
    )
    return {
        "STEP_SKIPPING": f"{action} may succeed without {prerequisite}",
        "OUT_OF_ORDER_EXECUTION": f"{action} may be accepted before {prerequisite}",
        "REPLAY": f"{action} may remain replayable after its first successful effect",
        "DUPLICATE_ACTION": (
            f"Immediate duplicate {action.lower()} may create two business effects"
        ),
        "CONCURRENT_EXECUTION": (
            f"Concurrent {action.lower()} may bypass single-execution protection"
        ),
        "TERMINAL_STATE_BYPASS": (f"{action} may remain available after a terminal workflow state"),
        "ACTOR_SWITCH": f"{action} may not remain bound to the initiating actor",
        "RESOURCE_SWITCH": (f"{action} may accept a resource from another controlled workflow"),
        "CROSS_WORKFLOW_TOKEN_REUSE": (f"{action} reference may be reusable across workflows"),
        "PARTIAL_ROLLBACK": f"{action} may leave linked resource state partially active",
        "QUANTITY_VALUE_INVARIANT": (
            f"Refund credit for {action.lower()} may exceed the immutable order value"
            if semantics.subject_action.startswith(("REFUND_", "RETURN_"))
            else f"{action} may accept an amount or quantity inconsistent with the baseline"
        ),
        "ROLE_APPROVAL_BYPASS": f"{action} may be performed by the original requester",
        "SHADOW_ENDPOINT": (
            f"Undocumented {action.lower()} method may expose server-controlled fields"
        ),
    }[semantics.vulnerability_family]


def _context(
    item: LogicHypothesis,
    invariant: BusinessInvariant,
    family: WorkflowFamily,
    instances: list[WorkflowInstance],
    supports: list[IndependentHypothesisSupport],
) -> HypothesisSupportContext:
    prerequisite_actions = [
        value
        for value in (invariant.prerequisite_action, invariant.dependent_action)
        if value is not None
    ]
    return HypothesisSupportContext(
        hypothesis_id=item.id,
        workflow_family_id=item.workflow_family_id,
        workflow_instance_ids=sorted(instance.id for instance in instances),
        invariant_id=item.invariant_id,
        mutation_family=item.family,
        affected_action=item.affected_action,
        observation_ids=sorted(item.observation_ids),
        causal_evidence=sorted(invariant.causal_evidence),
        prerequisite_actions=prerequisite_actions,
        actors=sorted(family.actors),
        captures=sorted({capture for instance in instances for capture in instance.captures}),
        resource_types=sorted(set(item.controlled_resources_required) | set(family.resource_types)),
        resource_instance_ids=sorted(
            {resource for instance in instances for resource in instance.resource_instance_ids}
        ),
        endpoint_ids=sorted(item.endpoint_ids),
        score=item.score,
        readiness=item.readiness,
        blockers=sorted(item.readiness_blockers),
        independent_support_ids=sorted(support.id for support in supports),
    )


def _aggregate_supports(
    support_groups: list[list[IndependentHypothesisSupport]],
) -> list[IndependentHypothesisSupport]:
    aggregated: dict[str, IndependentHypothesisSupport] = {}
    for support in (support for group in support_groups for support in group):
        current = aggregated.get(support.id)
        if current is None:
            aggregated[support.id] = support
            continue
        aggregated[support.id] = current.model_copy(
            update={
                "workflow_instance_ids": sorted(
                    set(current.workflow_instance_ids) | set(support.workflow_instance_ids)
                ),
                "actors": sorted(set(current.actors) | set(support.actors)),
                "captures": sorted(set(current.captures) | set(support.captures)),
                "resource_instance_ids": sorted(
                    set(current.resource_instance_ids) | set(support.resource_instance_ids)
                ),
                "observation_ids": sorted(
                    set(current.observation_ids) | set(support.observation_ids)
                ),
            }
        )
    return sorted(aggregated.values(), key=lambda support: support.id)


def _cluster_readiness(items: list[LogicHypothesis]) -> HypothesisReadiness:
    visible = [
        item
        for item in items
        if item.qualification is not None
        and item.qualification.promotion != HypothesisPromotion.SUPPRESSED
    ]
    if visible and all(
        item.readiness == HypothesisReadiness.TEST_READY and not item.readiness_blockers
        for item in visible
    ):
        return HypothesisReadiness.TEST_READY
    if any(item.readiness != HypothesisReadiness.RESEARCH_ONLY for item in visible):
        return HypothesisReadiness.REVIEW_REQUIRED
    return HypothesisReadiness.RESEARCH_ONLY


def _cluster(
    members: list[LogicHypothesis],
    contexts: dict[str, HypothesisSupportContext],
    supports: dict[str, list[IndependentHypothesisSupport]],
) -> HypothesisCluster:
    ordered = sorted(members, key=lambda item: item.id)
    semantics = ordered[0].semantics
    assert semantics is not None
    visible = [
        item
        for item in ordered
        if item.qualification is not None
        and item.qualification.promotion != HypothesisPromotion.SUPPRESSED
    ]
    representative_pool = visible or ordered
    representative = sorted(
        representative_pool,
        key=lambda item: (
            -_PROMOTION_RANK[
                item.qualification.promotion
                if item.qualification is not None
                else HypothesisPromotion.SUPPRESSED
            ],
            -(item.qualification.research_score if item.qualification is not None else 0),
            -_score_total(item),
            item.id,
        ),
    )[0]
    independent = _aggregate_supports([supports[item.id] for item in ordered])
    strengths = [
        item.qualification.evidence_strength for item in visible if item.qualification is not None
    ]
    confidences = [
        item.qualification.hypothesis_confidence
        for item in visible
        if item.qualification is not None
    ]
    strength = (
        max(strengths, key=lambda value: _EVIDENCE_RANK[value])
        if strengths
        else HypothesisEvidenceStrength.INSUFFICIENT
    )
    confidence = (
        max(confidences, key=lambda value: _CONFIDENCE_RANK[value])
        if confidences
        else HypothesisConfidence.LOW
    )
    promotions = [
        item.qualification.promotion for item in visible if item.qualification is not None
    ]
    promotion = (
        max(promotions, key=lambda value: _PROMOTION_RANK[value])
        if promotions
        else HypothesisPromotion.SUPPRESSED
    )
    ranking_reasons = [
        f"Aggregates {len(ordered)} provenance context(s).",
        f"Counts {len(independent)} independent support(s).",
    ]
    if (
        promotion
        in {
            HypothesisPromotion.RESEARCH_LOW,
            HypothesisPromotion.RESEARCH_MEDIUM,
        }
        and len(independent) >= 2
    ):
        promotion = (
            HypothesisPromotion.RESEARCH_HIGH
            if confidence == HypothesisConfidence.HIGH
            else HypothesisPromotion.RESEARCH_MEDIUM
        )
        ranking_reasons.append(
            "Independent contexts strengthen research confidence without changing readiness."
        )
    suppression = sorted(
        {
            reason
            for item in ordered
            if item.qualification is not None
            for reason in item.qualification.suppression_reasons
        }
    )
    if visible:
        suppression = []
    research_score = (
        max(
            (item.qualification.research_score if item.qualification is not None else 0)
            for item in ordered
        )
        + min(max(len(independent) - 1, 0), 3) * 3
    )
    readiness = _cluster_readiness(ordered)
    readiness_blockers = sorted(
        {blocker for item in visible for blocker in item.readiness_blockers}
    )
    if readiness == HypothesisReadiness.TEST_READY:
        readiness_blockers = []
    cluster_contexts = [contexts[item.id] for item in ordered]
    return HypothesisCluster(
        id=semantics.canonical_id,
        semantic_fingerprint=semantics.fingerprint,
        semantics=semantics,
        title=_canonical_title(semantics),
        representative_hypothesis_id=representative.id,
        member_hypothesis_ids=[item.id for item in ordered],
        support_contexts=cluster_contexts,
        independent_supports=independent,
        context_count=len(ordered),
        independent_support_count=len(independent),
        highest_score=max(_score_total(item) for item in ordered),
        research_score=research_score,
        hypothesis_confidence=confidence,
        evidence_strength=strength,
        promotion=promotion,
        readiness=readiness,
        readiness_blockers=readiness_blockers,
        ranking_reasons=ranking_reasons,
        suppression_reasons=suppression,
        workflow_family_ids=sorted({item.workflow_family_id for item in ordered}),
        workflow_instance_ids=sorted(
            {
                instance_id
                for context in cluster_contexts
                for instance_id in context.workflow_instance_ids
            }
        ),
        invariant_ids=sorted({item.invariant_id for item in ordered}),
        observation_ids=sorted(
            {observation for item in ordered for observation in item.observation_ids}
        ),
    )


def calibrate_hypotheses(
    inputs: HypothesisPrecisionInputs, hypotheses: list[LogicHypothesis]
) -> HypothesisPrecisionResult:
    """Qualify retained raw candidates and aggregate identical security questions."""

    invariant_by_id = {invariant.id: invariant for invariant in inputs.invariants}
    family_by_id = {family.id: family for family in inputs.families.workflow_families}
    instances_by_family: dict[str, list[WorkflowInstance]] = defaultdict(list)
    for instance in inputs.instances.workflow_instances:
        instances_by_family[instance.family_id].append(instance)
    calibrated: list[LogicHypothesis] = []
    supports: dict[str, list[IndependentHypothesisSupport]] = {}
    contexts: dict[str, HypothesisSupportContext] = {}
    for item in sorted(hypotheses, key=lambda candidate: candidate.id):
        if item.readiness == HypothesisReadiness.TEST_READY and item.readiness_blockers:
            item = item.model_copy(update={"readiness": HypothesisReadiness.REVIEW_REQUIRED})
        invariant = invariant_by_id.get(item.invariant_id)
        family = family_by_id.get(item.workflow_family_id)
        if invariant is None or family is None:
            calibrated.append(item)
            supports[item.id] = []
            continue
        endpoints = _relevant_endpoints(inputs, item)
        family_instances = sorted(
            instances_by_family.get(family.id, []), key=lambda instance: instance.id
        )
        item_supports = _support_units(inputs, item, family_instances)
        semantics = _semantics(inputs, item, invariant, family, endpoints, family_instances)
        evidence = _evidence(
            inputs,
            item,
            invariant,
            endpoints,
            family_instances,
            len(item_supports),
        )
        qualification = _qualification(item, invariant, semantics, evidence, endpoints)
        updated = item.model_copy(update={"semantics": semantics, "qualification": qualification})
        calibrated.append(updated)
        supports[item.id] = item_supports
        contexts[item.id] = _context(updated, invariant, family, family_instances, item_supports)

    grouped: dict[str, list[LogicHypothesis]] = defaultdict(list)
    for item in calibrated:
        if item.semantics is None:
            continue
        grouped[item.semantics.fingerprint].append(item)
    clusters = [
        _cluster(members, contexts, supports) for _fingerprint, members in sorted(grouped.items())
    ]
    return HypothesisPrecisionResult(
        hypotheses=sorted(calibrated, key=lambda item: item.id),
        clusters=rank_hypothesis_clusters(clusters, include_suppressed=True, include_low=True),
    )


def cluster_is_visible(cluster: HypothesisCluster, *, include_low: bool = False) -> bool:
    """Return whether a cluster belongs in the default researcher queue."""

    if cluster.promotion == HypothesisPromotion.SUPPRESSED:
        return False
    return include_low or cluster.promotion != HypothesisPromotion.RESEARCH_LOW


def _base_cluster_key(cluster: HypothesisCluster) -> tuple[int, int, int, int, str]:
    return (
        -_PROMOTION_RANK[cluster.promotion],
        -cluster.research_score,
        -cluster.independent_support_count,
        -cluster.highest_score,
        cluster.id,
    )


def rank_hypothesis_clusters(
    clusters: list[HypothesisCluster],
    *,
    include_suppressed: bool = False,
    include_low: bool = False,
) -> list[HypothesisCluster]:
    """Round-robin mutation families so one dimension cannot monopolize the top queue."""

    selected = [
        cluster
        for cluster in clusters
        if (include_suppressed or cluster.promotion != HypothesisPromotion.SUPPRESSED)
        and (include_low or cluster.promotion != HypothesisPromotion.RESEARCH_LOW)
    ]
    buckets: dict[str, list[HypothesisCluster]] = defaultdict(list)
    for cluster in selected:
        buckets[cluster.semantics.vulnerability_family].append(cluster)
    for family in buckets:
        buckets[family].sort(key=_base_cluster_key)
    ranked: list[HypothesisCluster] = []
    subject_counts: dict[str, int] = defaultdict(int)
    while buckets:
        family_order = sorted(
            buckets,
            key=lambda family: (*_base_cluster_key(buckets[family][0]), family),
        )
        for family in family_order:
            candidates = buckets.get(family)
            if not candidates:
                continue
            candidates.sort(
                key=lambda cluster: (
                    subject_counts[cluster.semantics.subject_action],
                    *_base_cluster_key(cluster),
                )
            )
            chosen = candidates.pop(0)
            ranked.append(chosen)
            subject_counts[chosen.semantics.subject_action] += 1
            if not candidates:
                del buckets[family]
    return ranked


def find_cluster(clusters: list[HypothesisCluster], cluster_id: str) -> HypothesisCluster:
    """Resolve one canonical cluster ID case-insensitively."""

    wanted = cluster_id.upper()
    for cluster in clusters:
        if cluster.id.upper() == wanted:
            return cluster
    raise LookupError(cluster_id)
