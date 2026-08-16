"""One authoritative hypothesis-readiness evaluator used by generation and planning."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Protocol

from finsec.config.models import CleanupControlRule, TargetDocument
from finsec.config.scope import hosts_are_covered
from finsec.hypotheses.baselines import canonical_baseline_identity, opaque_reference
from finsec.hypotheses.constructability import (
    ConstructabilityContext,
    IdentityConstructabilityFact,
    assess_execution_constructability,
)
from finsec.hypotheses.contracts import (
    BlockerStage,
    CapabilityAssessment,
    CapabilityKind,
    ClaimStrengthAssessment,
    ComparisonBaseline,
    ComparisonCoverage,
    DecisionEvidence,
    DomainIntentAssessment,
    DomainOperation,
    ExecutionConstructabilityAssessment,
    HypothesisReadinessAssessment,
    HypothesisReadinessValue,
    MutationTargetAssessment,
    ReadinessIssue,
    VisibilityIntent,
)
from finsec.modeling.domain import ResourceRecord, ResourceStore
from finsec.modeling.liveness import ControlledObjectLiveness
from finsec.modeling.merge import stable_fingerprint
from finsec.modeling.models import (
    ActorObjectBaseline,
    Endpoint,
    KnowledgeStatus,
    Observation,
    ObservationStore,
)
from finsec.modeling.parameter_identity import parameter_identities_match
from finsec.modeling.semantics import (
    IdentifierSemanticClass,
    OwnershipState,
    execution_ownership_supported,
)
from finsec.normalization.path_semantics import PathHierarchy, path_hierarchy

RUNTIME_SOURCES = {"HAR", "BURP_XML", "CAIDO_JSON"}


class HypothesisSourceLike(Protocol):
    @property
    def endpoints(self) -> Sequence[str]: ...

    @property
    def observations(self) -> Sequence[str]: ...


class HypothesisLike(Protocol):
    @property
    def id(self) -> str: ...

    @property
    def kind(self) -> str: ...

    @property
    def category(self) -> str: ...

    @property
    def source(self) -> HypothesisSourceLike: ...

    @property
    def observations(self) -> Sequence[str]: ...

    @property
    def mutation_dimensions(self) -> Sequence[str]: ...

    @property
    def evidence_to_collect(self) -> Sequence[str]: ...

    @property
    def generation_rule(self) -> Mapping[str, str]: ...

    @property
    def logic_details(self) -> Mapping[str, object] | None: ...


@dataclass(frozen=True)
class ReadinessContext:
    """Typed facts supplied to the canonical evaluator."""

    hypothesis_id: str
    kind: str
    capabilities: tuple[CapabilityAssessment, ...]
    comparison_coverage: ComparisonCoverage = field(default_factory=ComparisonCoverage)
    constructability: ExecutionConstructabilityAssessment = field(
        default_factory=ExecutionConstructabilityAssessment
    )
    warnings: tuple[ReadinessIssue, ...] = ()


def _evidence(reference: str, source: str, detail: str) -> DecisionEvidence:
    return DecisionEvidence(reference=reference, source=source, detail=detail)  # type: ignore[arg-type]


def _capability(
    capability: CapabilityKind,
    *,
    satisfied: bool,
    stage: BlockerStage,
    summary: str,
    required: bool = True,
    evidence: list[DecisionEvidence] | None = None,
    missing: list[str] | None = None,
    next_action: str | None = None,
    blocker_code: str | None = None,
) -> CapabilityAssessment:
    return CapabilityAssessment(
        capability=capability,
        required=required,
        satisfied=satisfied,
        stage=stage,
        summary=summary,
        evidence=sorted(evidence or [], key=lambda item: (item.reference, item.detail)),
        missing=sorted(set(missing or [])),
        next_action=next_action,
        blocker_code=blocker_code,
    )


def evaluate_readiness(context: ReadinessContext) -> HypothesisReadinessAssessment:
    """Evaluate identical capability facts identically for producers and the planner."""

    capabilities = sorted(context.capabilities, key=lambda item: item.capability.value)
    capability_blockers = [
        ReadinessIssue(
            code=item.blocker_code or f"MISSING_{item.capability.value}",
            stage=item.stage,
            capability=item.capability,
            summary="; ".join(item.missing) if item.missing else item.summary,
            evidence=item.evidence,
            next_action=item.next_action,
        )
        for item in capabilities
        if item.required and not item.satisfied
    ]
    blockers_by_code = {item.code: item for item in capability_blockers}
    blockers_by_code.update(
        {item.code: item for item in context.constructability.blockers}
    )
    blockers = list(blockers_by_code.values())
    concrete = next(
        (item for item in capabilities if item.capability == CapabilityKind.CONCRETE_TEST),
        None,
    )
    if context.kind != "SECURITY_HYPOTHESIS" or concrete is None or not concrete.satisfied:
        readiness: HypothesisReadinessValue = "RESEARCH_ONLY"
        reasons = [
            "The record is a discovery or coverage question without one fully concrete bounded "
            "test."
        ]
    elif blockers:
        readiness = "REVIEW_REQUIRED"
        reasons = [
            "The security question is specific, but evidence or plan-construction prerequisites "
            "remain unresolved."
        ]
    else:
        readiness = "TEST_READY"
        reasons = [
            "Current evidence supports a concrete bounded plan; human approval and execution "
            "policy remain separate gates."
        ]
    missing = sorted(
        {
            missing
            for capability in capabilities
            if capability.required and not capability.satisfied
            for missing in capability.missing
        }
        | set(context.constructability.missing_requirements)
    )
    references = sorted(
        {evidence.reference for capability in capabilities for evidence in capability.evidence}
        | set(context.constructability.evidence_references)
    )
    return HypothesisReadinessAssessment(
        readiness=readiness,
        actionable_plan=readiness == "TEST_READY" and context.constructability.supported,
        reasons=reasons,
        missing_prerequisites=missing,
        blockers=sorted(blockers, key=lambda item: (item.stage.value, item.code, item.summary)),
        warnings=sorted(
            context.warnings, key=lambda item: (item.stage.value, item.code, item.summary)
        ),
        capabilities=capabilities,
        constructability=context.constructability,
        comparison_coverage=context.comparison_coverage,
        evidence_references=references,
    )


def readiness_blocking_issues(
    assessment: HypothesisReadinessAssessment,
) -> list[ReadinessIssue]:
    """Return only evidence and constructability blockers, never approval/policy gates."""

    return [
        item
        for item in assessment.blockers
        if item.stage in {BlockerStage.HYPOTHESIS_EVIDENCE, BlockerStage.PLAN_CONSTRUCTABILITY}
    ]


def _logic_capability(
    record: HypothesisLike, capability: CapabilityKind
) -> CapabilityAssessment | None:
    details = record.logic_details
    if not isinstance(details, Mapping):
        return None
    raw = details.get("readiness_assessment")
    if not isinstance(raw, Mapping):
        return None
    try:
        assessment = HypothesisReadinessAssessment.model_validate(raw)
    except ValueError:
        return None
    return next((item for item in assessment.capabilities if item.capability == capability), None)


def _source_endpoints(record: HypothesisLike, endpoints: list[Endpoint]) -> list[Endpoint]:
    selected = set(record.source.endpoints)
    return sorted((item for item in endpoints if item.id in selected), key=lambda item: item.id)


def _runtime_observation_ids(record: HypothesisLike, observations: ObservationStore) -> set[str]:
    selected = set(record.source.observations) | set(record.observations)
    return {
        item.id
        for item in observations.observations
        if item.id in selected and item.source in RUNTIME_SOURCES
    }


def _required_actors(record: HypothesisLike) -> int:
    if record.logic_details is not None:
        value = record.logic_details.get("controlled_actors_required")
        if isinstance(value, int):
            return value
    rule = record.generation_rule.get("id", "")
    if record.category == "authorization" and rule != "FUNCTION_AUTHORIZATION":
        return 2
    return 1


def _type_key(value: str | None) -> str:
    return (
        ""
        if value is None
        else "".join(character for character in value.casefold() if character.isalnum())
    )


def _source_hierarchies(
    source: Sequence[Endpoint], subject_resource: str
) -> dict[str, PathHierarchy]:
    return {
        endpoint.id: path_hierarchy(endpoint.path, endpoint.path, subject_resource)
        for endpoint in source
    }


def _baseline_with_derived_provenance(
    baseline: ActorObjectBaseline,
    endpoints: Mapping[str, Endpoint],
) -> ActorObjectBaseline:
    """Fill legacy typed context only when its referenced endpoint is available."""

    endpoint = endpoints.get(baseline.endpoint_id or "")
    if endpoint is None:
        return baseline
    hierarchy = path_hierarchy(endpoint.path, endpoint.path, endpoint.resource.type)
    return baseline.model_copy(
        update={
            "subject_resource_type": baseline.subject_resource_type or endpoint.resource.type,
            "route_family": baseline.route_family or hierarchy.route_family,
            "collection_route_family": (
                baseline.collection_route_family or hierarchy.collection_route_family
            ),
            "parent_resource_type": (
                baseline.parent_resource_type
                or (hierarchy.parent.resource_type if hierarchy.parent is not None else None)
            ),
            "parent_value": (
                baseline.parent_value
                or (hierarchy.parent.value if hierarchy.parent is not None else None)
            ),
        }
    )


def _baseline_matches_exact_target_context(
    baseline: ActorObjectBaseline,
    hierarchies: Mapping[str, PathHierarchy],
    target_parent_values: set[str],
) -> bool:
    """Match the exact route and literal parent context of the hypothesis target."""

    route_families = {hierarchy.route_family for hierarchy in hierarchies.values()}
    return baseline.route_family in route_families and (
        not target_parent_values or baseline.parent_value in target_parent_values
    )


@dataclass(frozen=True, order=True)
class _ComparisonContext:
    """Runtime service/auth context shared by comparison-compatible baselines."""

    host: str
    scheme: str
    authentication_type: str
    collection_route_family: str


@dataclass(frozen=True)
class _ComparisonCandidate:
    baseline: ActorObjectBaseline
    context: _ComparisonContext
    matches_target_parent: bool


def _unique_endpoint_index(endpoints: Sequence[Endpoint]) -> dict[str, Endpoint]:
    grouped: dict[str, list[Endpoint]] = {}
    for endpoint in endpoints:
        grouped.setdefault(endpoint.id, []).append(endpoint)
    return {identifier: values[0] for identifier, values in grouped.items() if len(values) == 1}


def _unique_observation_index(
    observations: ObservationStore,
) -> tuple[dict[str, Observation], set[str]]:
    grouped: dict[str, list[Observation]] = {}
    for observation in observations.observations:
        grouped.setdefault(observation.id, []).append(observation)
    return (
        {identifier: values[0] for identifier, values in grouped.items() if len(values) == 1},
        {identifier for identifier, values in grouped.items() if len(values) != 1},
    )


def _runtime_comparison_context(
    endpoint: Endpoint,
    observation: Observation,
) -> tuple[_ComparisonContext, PathHierarchy] | None:
    """Resolve one unambiguous runtime endpoint/service context."""

    observation_authentication = observation.authentication.observed_type
    authentication_compatible = (
        observation_authentication != "mixed"
        and endpoint.authentication.observed_type in {observation_authentication, "mixed"}
        and (
            (observation.authentication.present and observation_authentication != "none")
            or (
                not endpoint.authentication.required
                and not observation.authentication.present
                and observation_authentication == "none"
            )
        )
    )
    if (
        observation.source not in RUNTIME_SOURCES
        or observation.id not in endpoint.sources
        or observation.method != endpoint.method
        or not observation.host
        or observation.host not in endpoint.hosts
        or not authentication_compatible
    ):
        return None
    hierarchy = path_hierarchy(endpoint.path, observation.path, endpoint.resource.type)
    endpoint_hierarchy = path_hierarchy(endpoint.path, endpoint.path, endpoint.resource.type)
    if hierarchy.collection_route_family != endpoint_hierarchy.collection_route_family:
        return None
    if (
        endpoint_hierarchy.parent is not None
        and endpoint_hierarchy.parent.value is not None
        and (hierarchy.parent is None or hierarchy.parent.value != endpoint_hierarchy.parent.value)
    ):
        return None
    return (
        _ComparisonContext(
            host=observation.host.casefold(),
            scheme=(observation.scheme or "").casefold(),
            authentication_type=observation_authentication,
            collection_route_family=hierarchy.collection_route_family,
        ),
        hierarchy,
    )


def _source_comparison_contexts(
    source: Sequence[Endpoint],
    observations: Mapping[str, Observation],
    ambiguous_observation_ids: set[str],
    runtime_ids: set[str],
) -> tuple[set[_ComparisonContext], set[str]]:
    contexts: set[_ComparisonContext] = set()
    parent_values: set[str] = set()
    for endpoint in sorted(source, key=lambda item: item.id):
        for observation_id in sorted(set(endpoint.sources).intersection(runtime_ids)):
            if observation_id in ambiguous_observation_ids:
                continue
            observation = observations.get(observation_id)
            if observation is None:
                continue
            resolved = _runtime_comparison_context(endpoint, observation)
            if resolved is None:
                continue
            context, hierarchy = resolved
            contexts.add(context)
            if hierarchy.parent is not None and hierarchy.parent.value is not None:
                parent_values.add(hierarchy.parent.value)
    return contexts, parent_values


def _baseline_runtime_provenance(
    baseline: ActorObjectBaseline,
    endpoint: Endpoint,
    observations: Mapping[str, Observation],
    ambiguous_observation_ids: set[str],
    intent: DomainIntentAssessment,
) -> tuple[ActorObjectBaseline, _ComparisonContext] | None:
    """Derive typed baseline context only from current actor-bound runtime evidence."""

    observation_ids = sorted(set(baseline.observations))
    if not observation_ids or any(
        identifier in ambiguous_observation_ids
        or identifier not in observations
        or identifier not in endpoint.sources
        for identifier in observation_ids
    ):
        return None
    contexts: set[_ComparisonContext] = set()
    parent_types: set[str] = set()
    parent_values: set[str] = set()
    subject_values: set[str] = set()
    for observation_id in observation_ids:
        observation = observations[observation_id]
        if observation.actor != baseline.actor:
            return None
        resolved = _runtime_comparison_context(endpoint, observation)
        if resolved is None:
            return None
        context, hierarchy = resolved
        if (
            baseline.authentication_type is not None
            and baseline.authentication_type.casefold() != context.authentication_type.casefold()
        ):
            return None
        contexts.add(context)
        if hierarchy.subject is not None and hierarchy.subject.value is not None:
            subject_values.add(hierarchy.subject.value)
        if hierarchy.parent is not None:
            parent_types.add(_type_key(hierarchy.parent.resource_type))
            if hierarchy.parent.value is not None:
                parent_values.add(hierarchy.parent.value)
    if (
        len(contexts) != 1
        or len(parent_types) > 1
        or len(parent_values) > 1
        or len(subject_values) > 1
    ):
        return None
    observed_subject_value = next(iter(subject_values), None)
    if observed_subject_value is not None and baseline.requested_value != observed_subject_value:
        return None
    endpoint_hierarchy = path_hierarchy(endpoint.path, endpoint.path, endpoint.resource.type)
    endpoint_parent_type = (
        endpoint_hierarchy.parent.resource_type if endpoint_hierarchy.parent is not None else None
    )
    observed_parent_type = next(iter(parent_types), _type_key(endpoint_parent_type))
    if observed_parent_type != _type_key(intent.parent_resource):
        return None
    observed_parent_value = next(iter(parent_values), None)
    if (
        baseline.parent_value is not None
        and observed_parent_value is not None
        and baseline.parent_value != observed_parent_value
    ):
        return None
    derived = baseline.model_copy(
        update={
            "subject_resource_type": baseline.subject_resource_type or endpoint.resource.type,
            "route_family": baseline.route_family or endpoint_hierarchy.route_family,
            "collection_route_family": (
                baseline.collection_route_family or endpoint_hierarchy.collection_route_family
            ),
            "parent_resource_type": baseline.parent_resource_type or endpoint_parent_type,
            "parent_value": baseline.parent_value or observed_parent_value,
            "authentication_type": baseline.authentication_type
            or next(iter(contexts)).authentication_type,
        }
    )
    if (
        _type_key(endpoint.resource.type) != _type_key(intent.subject_resource)
        or _type_key(derived.subject_resource_type) != _type_key(intent.subject_resource)
        or derived.route_family != endpoint_hierarchy.route_family
        or derived.collection_route_family != endpoint_hierarchy.collection_route_family
        or _type_key(derived.parent_resource_type) != _type_key(intent.parent_resource)
        or (
            intent.parent_resource is not None
            and derived.parent_resource_id is None
            and derived.parent_value is None
        )
    ):
        return None
    return derived, next(iter(contexts))


def _baseline_matches_comparison_context(
    baseline: ActorObjectBaseline,
    context: _ComparisonContext,
    source_contexts: set[_ComparisonContext],
    source_hierarchies: Mapping[str, PathHierarchy],
    intent: DomainIntentAssessment,
) -> bool:
    """Match semantic family and runtime provenance without equating literal parents."""

    return (
        context in source_contexts
        and _type_key(baseline.subject_resource_type) == _type_key(intent.subject_resource)
        and baseline.collection_route_family
        in {item.collection_route_family for item in source_hierarchies.values()}
        and _type_key(baseline.parent_resource_type) == _type_key(intent.parent_resource)
    )


def _comparison_candidate(
    baseline: ActorObjectBaseline,
    *,
    controlled_actor_ids: set[str],
    endpoints: Mapping[str, Endpoint],
    observations: Mapping[str, Observation],
    ambiguous_observation_ids: set[str],
    source_contexts: set[_ComparisonContext],
    source_hierarchies: Mapping[str, PathHierarchy],
    target_parent_values: set[str],
    intent: DomainIntentAssessment,
) -> _ComparisonCandidate | None:
    if baseline.actor not in controlled_actor_ids or baseline.endpoint_id is None:
        return None
    endpoint = endpoints.get(baseline.endpoint_id)
    if endpoint is None or endpoint.disposition != "ACTIVE":
        return None
    resolved = _baseline_runtime_provenance(
        baseline,
        endpoint,
        observations,
        ambiguous_observation_ids,
        intent,
    )
    if resolved is None:
        return None
    derived, context = resolved
    if not _baseline_matches_comparison_context(
        derived,
        context,
        source_contexts,
        source_hierarchies,
        intent,
    ):
        return None
    return _ComparisonCandidate(
        baseline=derived,
        context=context,
        matches_target_parent=_baseline_matches_exact_target_context(
            derived,
            source_hierarchies,
            target_parent_values,
        ),
    )


@dataclass
class _ComparisonBaselineAccumulator:
    canonical_reference: str
    actor_id: str
    object_reference: str
    parent_reference: str | None
    matches_target_parent: bool
    resource_type: str | None
    parent_resource_type: str | None
    route_family: str | None
    collection_route_family: str | None
    operation: str | None
    liveness_states: set[ControlledObjectLiveness] = field(default_factory=set)
    liveness_evidence_references: set[str] = field(default_factory=set)
    baseline_ids: set[str] = field(default_factory=set)
    endpoint_ids: set[str] = field(default_factory=set)
    supporting_relationship_ids: set[str] = field(default_factory=set)
    observation_ids: set[str] = field(default_factory=set)


def _canonical_comparison_baselines(
    candidates: Sequence[_ComparisonCandidate],
) -> list[ComparisonBaseline]:
    """Merge corroborating edges without treating them as independent baselines."""

    merged: dict[
        tuple[str, str, str | None, str | None, str | None],
        _ComparisonBaselineAccumulator,
    ] = {}
    for candidate in candidates:
        baseline = candidate.baseline
        canonical_reference, object_reference, parent_reference = canonical_baseline_identity(
            baseline
        )
        key = (
            baseline.actor,
            object_reference,
            parent_reference,
            baseline.route_family,
            baseline.collection_route_family,
        )
        entry = merged.setdefault(
            key,
            _ComparisonBaselineAccumulator(
                canonical_reference=canonical_reference,
                actor_id=baseline.actor,
                object_reference=object_reference,
                parent_reference=parent_reference,
                matches_target_parent=candidate.matches_target_parent,
                resource_type=baseline.subject_resource_type,
                parent_resource_type=baseline.parent_resource_type,
                route_family=baseline.route_family,
                collection_route_family=baseline.collection_route_family,
                operation=baseline.operation,
            ),
        )
        entry.matches_target_parent = entry.matches_target_parent or candidate.matches_target_parent
        entry.liveness_states.add(baseline.liveness)
        entry.liveness_evidence_references.update(baseline.liveness_evidence)
        if baseline.baseline_id is not None:
            entry.baseline_ids.add(baseline.baseline_id)
        if baseline.endpoint_id is not None:
            entry.endpoint_ids.add(baseline.endpoint_id)
        entry.supporting_relationship_ids.update(baseline.relationship_ids)
        entry.observation_ids.update(baseline.observations)
    return [
        ComparisonBaseline(
            canonical_reference=entry.canonical_reference,
            actor_id=entry.actor_id,
            object_reference=entry.object_reference,
            parent_reference=entry.parent_reference,
            matches_target_parent=entry.matches_target_parent,
            resource_type=entry.resource_type,
            parent_resource_type=entry.parent_resource_type,
            route_family=entry.route_family,
            collection_route_family=entry.collection_route_family,
            operation=entry.operation,
            liveness=(
                next(iter(entry.liveness_states))
                if len(entry.liveness_states) == 1
                else ControlledObjectLiveness.UNKNOWN
            ),
            liveness_evidence_references=sorted(entry.liveness_evidence_references),
            baseline_ids=sorted(entry.baseline_ids),
            endpoint_ids=sorted(entry.endpoint_ids),
            supporting_relationship_ids=sorted(entry.supporting_relationship_ids),
            observation_ids=sorted(entry.observation_ids),
        )
        for _, entry in sorted(
            merged.items(),
            key=lambda item: tuple("" if value is None else value for value in item[0]),
        )
    ]


def _comparison_witness(
    baselines: Sequence[ComparisonBaseline],
    required_actors: int,
    *,
    target_parent_required: bool,
) -> tuple[ComparisonBaseline, ...]:
    """Select one deterministic actor/object witness set anchored to the target parent."""

    if required_actors <= 0:
        return ()
    ordered = sorted(baselines, key=lambda item: item.canonical_reference)
    targets = (
        [item for item in ordered if item.matches_target_parent]
        if target_parent_required
        else list(reversed(ordered))
    )

    def extend(selected: tuple[ComparisonBaseline, ...]) -> tuple[ComparisonBaseline, ...]:
        if len(selected) >= required_actors:
            return selected
        actors = {item.actor_id for item in selected}
        objects = {item.object_reference for item in selected}
        for candidate in ordered:
            if candidate.actor_id in actors or candidate.object_reference in objects:
                continue
            result = extend((*selected, candidate))
            if result:
                return result
        return ()

    for target in targets:
        result = extend((target,))
        if result:
            return result
    return ()


def _select_comparison_group(
    candidates: Sequence[_ComparisonCandidate],
    required_actors: int,
    *,
    target_parent_required: bool,
) -> tuple[list[ComparisonBaseline], tuple[ComparisonBaseline, ...]]:
    grouped: dict[_ComparisonContext, list[_ComparisonCandidate]] = {}
    for candidate in candidates:
        grouped.setdefault(candidate.context, []).append(candidate)
    choices: list[
        tuple[
            _ComparisonContext,
            list[ComparisonBaseline],
            tuple[ComparisonBaseline, ...],
        ]
    ] = []
    for context, values in grouped.items():
        baselines = _canonical_comparison_baselines(values)
        witness = _comparison_witness(
            baselines,
            required_actors,
            target_parent_required=target_parent_required,
        )
        choices.append((context, baselines, witness))
    if target_parent_required:
        choices = [
            item for item in choices if any(baseline.matches_target_parent for baseline in item[1])
        ]
    if not choices:
        return [], ()
    _, selected, witness = min(
        choices,
        key=lambda item: (
            0 if item[2] else 1,
            0
            if not target_parent_required
            or any(baseline.matches_target_parent for baseline in item[1])
            else 1,
            -len({baseline.actor_id for baseline in item[1]}),
            -len({baseline.object_reference for baseline in item[1]}),
            item[0],
        ),
    )
    return selected, witness


def _mutation_target(record: HypothesisLike) -> MutationTargetAssessment:
    value = getattr(record, "mutation_target", None)
    return value if isinstance(value, MutationTargetAssessment) else MutationTargetAssessment()


def cleanup_control_fingerprint(
    record: HypothesisLike,
    intent: DomainIntentAssessment,
    mutation_target: MutationTargetAssessment,
    source: Sequence[Endpoint],
) -> str:
    """Return the stable semantic identity used to bind reviewed cleanup controls."""

    return stable_fingerprint(
        {
            "category": record.category,
            "generation_rule": record.generation_rule.get("id", ""),
            "methods": sorted(endpoint.method for endpoint in source),
            "routes": sorted(endpoint.path for endpoint in source),
            "subject": intent.subject_resource,
            "parent": intent.parent_resource,
            "operation": intent.operation,
            "mutation_parameter": mutation_target.parameter,
            "mutation_location": mutation_target.location,
            "mutation_json_path": mutation_target.json_path,
        }
    )


def _cleanup_checksum_endpoint(endpoint: Endpoint) -> dict[str, object]:
    """Canonicalize set-like ownership provenance before checksum binding."""

    payload = endpoint.model_dump(mode="json", exclude_none=True)
    raw_access = payload.get("object_access")
    if not isinstance(raw_access, list):
        return payload
    normalized_access: list[dict[str, object]] = []
    for value in raw_access:
        if not isinstance(value, dict):
            continue
        access = dict(value)
        for key in ("relationship_ids", "baseline_ids", "counterevidence", "ambiguity"):
            raw_values = access.get(key)
            if isinstance(raw_values, list):
                access[key] = sorted(raw_values, key=str)
        raw_baselines = access.get("baselines")
        if isinstance(raw_baselines, list):
            baselines: list[dict[str, object]] = []
            for raw_baseline in raw_baselines:
                if not isinstance(raw_baseline, dict):
                    continue
                baseline = dict(raw_baseline)
                for key in (
                    "relationship_ids",
                    "capture_ids",
                    "session_ids",
                    "observations",
                ):
                    raw_values = baseline.get(key)
                    if isinstance(raw_values, list):
                        baseline[key] = sorted(raw_values, key=str)
                baselines.append(baseline)
            access["baselines"] = sorted(baselines, key=stable_fingerprint)
        normalized_access.append(access)
    payload["object_access"] = sorted(normalized_access, key=stable_fingerprint)
    return payload


def cleanup_control_source_checksum(
    target: TargetDocument,
    observations: ObservationStore,
    record: HypothesisLike,
    intent: DomainIntentAssessment,
    mutation_target: MutationTargetAssessment,
    source: Sequence[Endpoint],
) -> str:
    """Bind a cleanup review to the current semantic target and relevant inputs."""

    target_payload = target.model_dump(mode="json", exclude_none=True)
    analysis = target_payload.get("analysis")
    if isinstance(analysis, dict):
        analysis["cleanup_controls"] = []
    accounts = target_payload.get("accounts")
    if isinstance(accounts, list):
        target_payload["accounts"] = sorted(
            accounts,
            key=lambda item: str(item.get("id", "")) if isinstance(item, dict) else str(item),
        )
    relevant_observation_ids = set(record.source.observations) | set(record.observations)
    relevant_observation_ids.update(
        observation_id for endpoint in source for observation_id in endpoint.sources
    )
    return stable_fingerprint(
        {
            "semantic_fingerprint": cleanup_control_fingerprint(
                record, intent, mutation_target, source
            ),
            "target": target_payload,
            "observations": [
                item.model_dump(mode="json", exclude_none=True)
                for item in sorted(
                    (
                        value
                        for value in observations.observations
                        if value.id in relevant_observation_ids
                    ),
                    key=lambda value: value.id,
                )
            ],
            "endpoints": [
                _cleanup_checksum_endpoint(item)
                for item in sorted(source, key=lambda endpoint: endpoint.id)
            ],
        }
    )


def _state_changing(intent: DomainIntentAssessment) -> bool:
    return intent.operation in {
        DomainOperation.CREATE,
        DomainOperation.CREATE_CHILD,
        DomainOperation.UPDATE,
        DomainOperation.DELETE,
        DomainOperation.TRANSITION,
        DomainOperation.ACTION,
    }


def _parent_collection_route(hierarchy: PathHierarchy) -> str | None:
    if hierarchy.parent is None:
        return None
    segments = [item for item in hierarchy.route_family.split("/") if item]
    return "/" + "/".join(segments[: hierarchy.parent.collection_index + 1])


def _oracle_compatible(
    endpoint: Endpoint,
    source_hierarchies: Mapping[str, PathHierarchy],
    intent: DomainIntentAssessment,
) -> bool:
    hierarchy = path_hierarchy(endpoint.path, endpoint.path, endpoint.resource.type)
    endpoint_type = _type_key(endpoint.resource.type)
    subject_type = _type_key(intent.subject_resource)
    parent_type = _type_key(intent.parent_resource)
    source_parent_values = {
        item.parent.value
        for item in source_hierarchies.values()
        if item.parent is not None and item.parent.value is not None
    }
    if endpoint_type == subject_type:
        if hierarchy.collection_route_family not in {
            item.collection_route_family for item in source_hierarchies.values()
        }:
            return False
        if (
            _type_key(hierarchy.parent.resource_type if hierarchy.parent is not None else None)
            != parent_type
        ):
            return False
        return not (
            source_parent_values
            and (hierarchy.parent is None or hierarchy.parent.value not in source_parent_values)
        )
    if not parent_type or endpoint_type != parent_type:
        return False
    parent_collections = {
        route
        for item in source_hierarchies.values()
        if (route := _parent_collection_route(item)) is not None
    }
    if hierarchy.collection_route_family not in parent_collections:
        return False
    return not (
        source_parent_values
        and (hierarchy.subject is None or hierarchy.subject.value not in source_parent_values)
    )


def _oracle_endpoints(
    source: list[Endpoint], all_endpoints: list[Endpoint], intent: DomainIntentAssessment
) -> list[Endpoint]:
    source_hierarchies = _source_hierarchies(source, intent.subject_resource)
    return sorted(
        (
            endpoint
            for endpoint in all_endpoints
            if endpoint.method in {"GET", "HEAD"}
            and not endpoint.state_change
            and _oracle_compatible(endpoint, source_hierarchies, intent)
        ),
        key=lambda item: item.id,
    )


def _request_budget(record: HypothesisLike, intent: DomainIntentAssessment) -> int:
    if record.logic_details is not None:
        value = record.logic_details.get("estimated_request_budget")
        if isinstance(value, int):
            return value
    rule = record.generation_rule.get("id", "")
    if rule.startswith("JWT_ALGORITHM_VALIDATION"):
        return 2
    if _state_changing(intent):
        return 4
    return 2


def _source_parent_values(hierarchies: Mapping[str, PathHierarchy]) -> set[str]:
    return {
        item.parent.value
        for item in hierarchies.values()
        if item.parent is not None and item.parent.value is not None
    }


def _subject_endpoint_context_issue(
    endpoint: Endpoint,
    source_hierarchies: Mapping[str, PathHierarchy],
    intent: DomainIntentAssessment,
) -> str | None:
    hierarchy = path_hierarchy(endpoint.path, endpoint.path, endpoint.resource.type)
    if _type_key(endpoint.resource.type) != _type_key(intent.subject_resource):
        return "cleanup resource belongs to another resource type"
    if hierarchy.collection_route_family not in {
        item.collection_route_family for item in source_hierarchies.values()
    }:
        return "cleanup resource belongs to another route family"
    if _type_key(
        hierarchy.parent.resource_type if hierarchy.parent is not None else None
    ) != _type_key(intent.parent_resource):
        return "cleanup resource belongs to another parent context"
    parent_values = _source_parent_values(source_hierarchies)
    if parent_values and (hierarchy.parent is None or hierarchy.parent.value not in parent_values):
        return "cleanup resource belongs to another parent context"
    return None


def _runtime_endpoint_provenance(
    endpoint: Endpoint,
    observations: ObservationStore,
) -> list[str]:
    observation_by_id = {item.id: item for item in observations.observations}
    return sorted(
        observation_id
        for observation_id in endpoint.sources
        if observation_id in observation_by_id
        and observation_by_id[observation_id].source in RUNTIME_SOURCES
    )


def _baseline_cleanup_resolution(
    baseline: ActorObjectBaseline,
    *,
    control: CleanupControlRule,
    controlled_actor_ids: set[str],
    endpoints: Mapping[str, Endpoint],
    observations: ObservationStore,
    source_hierarchies: Mapping[str, PathHierarchy],
    intent: DomainIntentAssessment,
) -> tuple[tuple[str, str, str, str] | None, list[DecisionEvidence], list[str]]:
    endpoint = endpoints.get(baseline.endpoint_id or "")
    if endpoint is None:
        return None, [], ["cleanup resource reference has stale endpoint provenance"]
    derived = _baseline_with_derived_provenance(baseline, endpoints)
    reasons: list[str] = []
    if derived.actor not in controlled_actor_ids or derived.actor not in set(control.actor_ids):
        reasons.append("cleanup resource is not controlled by the configured actor")
    if _type_key(derived.subject_resource_type) != _type_key(control.resource_type):
        reasons.append("cleanup resource belongs to another resource type")
    if _type_key(derived.parent_resource_type) != _type_key(control.parent_resource_type):
        reasons.append("cleanup resource belongs to another parent context")
    parent_values = _source_parent_values(source_hierarchies)
    if parent_values and derived.parent_value not in parent_values:
        reasons.append("cleanup resource belongs to another parent context")
    route_families = {derived.route_family, derived.collection_route_family}
    if control.route_family not in route_families:
        reasons.append("cleanup resource belongs to another route family")
    context_issue = _subject_endpoint_context_issue(endpoint, source_hierarchies, intent)
    if context_issue is not None:
        reasons.append(context_issue)
    observation_by_id = {item.id: item for item in observations.observations}
    supporting_runtime = sorted(
        observation_id
        for observation_id in derived.observations
        if observation_id in observation_by_id
        and observation_by_id[observation_id].source in RUNTIME_SOURCES
        and observation_by_id[observation_id].actor == derived.actor
    )
    if not supporting_runtime:
        reasons.append("cleanup resource lacks current runtime provenance")
    if reasons:
        return None, [], sorted(set(reasons))
    reference = derived.baseline_id or derived.subject_resource_id or endpoint.id
    evidence = [
        _evidence(
            reference,
            "WORKFLOW",
            "Controlled cleanup resource resolves to a compatible actor-bound baseline.",
        ),
        *[
            _evidence(
                observation_id,
                "OBSERVATION",
                "Runtime observation supports the controlled cleanup resource.",
            )
            for observation_id in supporting_runtime
        ],
    ]
    return (
        (
            derived.actor,
            _type_key(derived.subject_resource_type),
            _type_key(derived.parent_resource_type),
            control.route_family,
        ),
        evidence,
        [],
    )


def _modeled_cleanup_resolution(
    resource: ResourceRecord,
    *,
    control: CleanupControlRule,
    controlled_actor_ids: set[str],
    endpoints: Mapping[str, Endpoint],
    observations: ObservationStore,
    source_hierarchies: Mapping[str, PathHierarchy],
    intent: DomainIntentAssessment,
) -> tuple[tuple[str, str, str, str] | None, list[DecisionEvidence], list[str]]:
    reasons: list[str] = []
    owner = resource.owner
    owner_id = owner.value or ""
    if resource.disposition != "ACTIVE" or _type_key(resource.name) != _type_key(
        control.resource_type
    ):
        reasons.append("cleanup resource belongs to another resource type")
    if (
        owner_id not in controlled_actor_ids
        or owner_id not in set(control.actor_ids)
        or owner.knowledge_status not in {KnowledgeStatus.OBSERVED, KnowledgeStatus.CONFIRMED}
        or not owner.evidence
    ):
        reasons.append("cleanup resource is not controlled by the configured actor")
    operation_endpoints = [
        endpoints[item.endpoint] for item in resource.operations if item.endpoint in endpoints
    ]
    compatible = [
        endpoint
        for endpoint in operation_endpoints
        if control.route_family
        in {
            path_hierarchy(endpoint.path, endpoint.path, endpoint.resource.type).route_family,
            path_hierarchy(
                endpoint.path, endpoint.path, endpoint.resource.type
            ).collection_route_family,
        }
        and _subject_endpoint_context_issue(endpoint, source_hierarchies, intent) is None
        and _runtime_endpoint_provenance(endpoint, observations)
    ]
    if not compatible:
        context_issues = [
            _subject_endpoint_context_issue(endpoint, source_hierarchies, intent)
            for endpoint in operation_endpoints
        ]
        if "cleanup resource belongs to another parent context" in context_issues:
            reasons.append("cleanup resource belongs to another parent context")
        else:
            reasons.append("cleanup resource belongs to another route family")
    if not resource.evidence:
        reasons.append("cleanup resource lacks canonical evidence provenance")
    if reasons:
        return None, [], sorted(set(reasons))
    endpoint = sorted(compatible, key=lambda item: item.id)[0]
    return (
        (
            owner_id,
            _type_key(resource.name),
            _type_key(control.parent_resource_type),
            control.route_family,
        ),
        [
            _evidence(
                resource.id,
                "WORKFLOW",
                "Canonical modeled resource is actor-controlled and route-compatible.",
            ),
            *[
                _evidence(
                    observation_id,
                    "OBSERVATION",
                    "Runtime observation supports the modeled cleanup resource.",
                )
                for observation_id in _runtime_endpoint_provenance(endpoint, observations)
            ],
        ],
        [],
    )


def _resolve_cleanup_resource_ref(
    reference: str,
    *,
    control: CleanupControlRule,
    controlled_actor_ids: set[str],
    resources: ResourceStore,
    baselines: Sequence[ActorObjectBaseline],
    endpoints: Mapping[str, Endpoint],
    observations: ObservationStore,
    source_hierarchies: Mapping[str, PathHierarchy],
    intent: DomainIntentAssessment,
) -> tuple[list[DecisionEvidence], list[str]]:
    modeled = [item for item in resources.resources if item.id == reference]
    controlled = [
        item for item in baselines if reference in {item.baseline_id, item.subject_resource_id}
    ]
    if not modeled and not controlled:
        return [], [f"cleanup resource reference does not resolve: {reference}"]
    resolutions = [
        _modeled_cleanup_resolution(
            item,
            control=control,
            controlled_actor_ids=controlled_actor_ids,
            endpoints=endpoints,
            observations=observations,
            source_hierarchies=source_hierarchies,
            intent=intent,
        )
        for item in modeled
    ] + [
        _baseline_cleanup_resolution(
            item,
            control=control,
            controlled_actor_ids=controlled_actor_ids,
            endpoints=endpoints,
            observations=observations,
            source_hierarchies=source_hierarchies,
            intent=intent,
        )
        for item in controlled
    ]
    reasons = sorted({reason for _, _, issues in resolutions for reason in issues})
    signatures = {signature for signature, _, _ in resolutions if signature is not None}
    if reasons:
        return [], reasons
    if len(signatures) != 1:
        return [], [f"cleanup resource reference is ambiguous: {reference}"]
    return [
        _evidence(
            reference,
            "WORKFLOW",
            "Cleanup resource reference resolves to compatible canonical evidence.",
        ),
        *[evidence for _, items, _ in resolutions for evidence in items],
    ], []


def _resolve_cleanup_oracle_ref(
    reference: str,
    *,
    endpoints: list[Endpoint],
    observations: ObservationStore,
    source_hierarchies: Mapping[str, PathHierarchy],
    intent: DomainIntentAssessment,
) -> tuple[list[DecisionEvidence], list[str]]:
    matches = [item for item in endpoints if item.id == reference]
    if not matches:
        return [], [f"cleanup oracle reference does not resolve: {reference}"]
    if len(matches) != 1:
        return [], [f"cleanup oracle reference is ambiguous: {reference}"]
    endpoint = matches[0]
    if endpoint.method not in {"GET", "HEAD"}:
        return [], [f"cleanup oracle endpoint is not GET or HEAD: {reference}"]
    if endpoint.state_change:
        return [], [f"cleanup oracle endpoint is state-changing: {reference}"]
    if not _oracle_compatible(endpoint, source_hierarchies, intent):
        return [], [f"cleanup oracle belongs to another route or parent context: {reference}"]
    runtime = _runtime_endpoint_provenance(endpoint, observations)
    if not runtime:
        return [], [f"cleanup oracle lacks runtime provenance: {reference}"]
    return [
        _evidence(endpoint.id, "ENDPOINT", "Safe authoritative cleanup oracle resolved."),
        *[
            _evidence(
                observation_id,
                "OBSERVATION",
                "Runtime observation supports the authoritative cleanup oracle.",
            )
            for observation_id in runtime
        ],
    ], []


def _resolve_cleanup_control(
    *,
    target: TargetDocument,
    observations: ObservationStore,
    endpoints: list[Endpoint],
    resources: ResourceStore,
    intent: DomainIntentAssessment,
    source_hierarchies: Mapping[str, PathHierarchy],
    candidate_baselines: Sequence[ActorObjectBaseline],
    baseline_actors: set[str],
    cleanup_fingerprint: str,
    cleanup_source_checksum: str,
) -> tuple[CleanupControlRule | None, list[DecisionEvidence], list[str]]:
    candidates = [
        item
        for item in target.analysis.cleanup_controls
        if item.semantic_fingerprint == cleanup_fingerprint
    ]
    if not candidates:
        return None, [], ["Define a rollback, cleanup, or disposable-resource strategy."]
    control = candidates[0]
    controlled_actor_ids = {
        account.id for account in target.accounts if account.ownership == "researcher"
    }
    cleanup_route_families = {
        hierarchy.route_family for hierarchy in source_hierarchies.values()
    } | {hierarchy.collection_route_family for hierarchy in source_hierarchies.values()}
    reasons: list[str] = []
    if control.source_checksum != cleanup_source_checksum:
        reasons.append("cleanup control source checksum does not match current evidence")
    if _type_key(control.resource_type) != _type_key(intent.subject_resource):
        reasons.append("cleanup control belongs to another resource type")
    if control.route_family not in cleanup_route_families:
        reasons.append("cleanup control belongs to another route family")
    if _type_key(control.parent_resource_type) != _type_key(intent.parent_resource):
        reasons.append("cleanup control belongs to another parent context")
    if not set(control.actor_ids).issubset(controlled_actor_ids):
        reasons.append("cleanup control names an actor that is not researcher-controlled")
    if not baseline_actors.issubset(set(control.actor_ids)):
        reasons.append("cleanup resource is not controlled by the configured actor")
    endpoint_by_id = {item.id: item for item in endpoints}
    evidence: list[DecisionEvidence] = []
    for reference in control.resource_refs:
        resolved, issues = _resolve_cleanup_resource_ref(
            reference,
            control=control,
            controlled_actor_ids=controlled_actor_ids,
            resources=resources,
            baselines=candidate_baselines,
            endpoints=endpoint_by_id,
            observations=observations,
            source_hierarchies=source_hierarchies,
            intent=intent,
        )
        evidence.extend(resolved)
        reasons.extend(issues)
    for reference in control.oracle_refs:
        resolved, issues = _resolve_cleanup_oracle_ref(
            reference,
            endpoints=endpoints,
            observations=observations,
            source_hierarchies=source_hierarchies,
            intent=intent,
        )
        evidence.extend(resolved)
        reasons.extend(issues)
    if reasons:
        return None, [], sorted(set(reasons))
    return (
        control,
        [
            _evidence(
                control.semantic_fingerprint,
                "TARGET_POLICY",
                f"Reviewed cleanup strategy is {control.strategy}.",
            ),
            *evidence,
        ],
        [],
    )


def build_record_readiness_context(
    target: TargetDocument,
    observations: ObservationStore,
    endpoints: list[Endpoint],
    resources: ResourceStore,
    record: HypothesisLike,
    intent: DomainIntentAssessment,
    claim_strength: ClaimStrengthAssessment,
) -> ReadinessContext:
    """Derive shared prerequisite facts from one persisted HYP or BLH record."""

    source = _source_endpoints(record, endpoints)
    runtime_ids = _runtime_observation_ids(record, observations)
    source_ids = {observation for endpoint in source for observation in endpoint.sources}
    runtime_source_ids = runtime_ids & source_ids
    rule = record.generation_rule.get("id", "")
    mutation_target = _mutation_target(record)
    actor_count = sum(account.ownership == "researcher" for account in target.accounts)
    actors_required = _required_actors(record)
    actor_evidence = [
        _evidence(account.id, "TARGET_POLICY", "Researcher-controlled actor is configured.")
        for account in target.accounts
        if account.ownership == "researcher"
    ]

    concrete = record.kind == "SECURITY_HYPOTHESIS" and bool(
        record.mutation_dimensions or rule.startswith("JWT_ALGORITHM_VALIDATION")
    )
    concrete_capability = _capability(
        CapabilityKind.CONCRETE_TEST,
        satisfied=concrete,
        stage=BlockerStage.HYPOTHESIS_EVIDENCE,
        summary="One concrete mutation and security oracle must be defined.",
        evidence=[
            _evidence(record.id, "GENERATOR", "The generator emitted a concrete test mutation.")
        ]
        if concrete
        else [],
        missing=["Define one bounded mutation with a meaningful secure and vulnerable oracle."],
        next_action="Refine the discovery question into one concrete bounded test.",
    )
    semantic_target_required = record.category == "authorization" and rule.startswith(
        "AUTH_OBJECT_ACCESS"
    )
    semantic_target_satisfied = (
        mutation_target.parameter is not None
        and (mutation_target.location != "body" or mutation_target.json_path is not None)
        and mutation_target.semantics.semantic_class == IdentifierSemanticClass.OWNED_OBJECT
        and mutation_target.semantics.ownership_state
        not in {OwnershipState.SHARED, OwnershipState.CONTRADICTED}
    )
    semantic_target_capability = _capability(
        CapabilityKind.SEMANTIC_TARGET,
        required=semantic_target_required,
        satisfied=semantic_target_satisfied,
        stage=BlockerStage.HYPOTHESIS_EVIDENCE,
        summary="The mutation target must represent an ownership-relevant object.",
        evidence=[
            _evidence(
                mutation_target.parameter or record.id,
                "ENDPOINT",
                (
                    f"Identifier class is "
                    f"{mutation_target.semantics.semantic_class.value}; resource role is "
                    f"{mutation_target.semantics.resource_role.value}."
                ),
            )
        ]
        if mutation_target.parameter is not None
        else [],
        missing=[
            (
                "Ownership evidence for the owned-object mutation target is contradicted by "
                "shared or public counterevidence."
                if mutation_target.semantics.semantic_class == IdentifierSemanticClass.OWNED_OBJECT
                and mutation_target.semantics.ownership_state == OwnershipState.CONTRADICTED
                else (
                    f"Identifier is classified as "
                    f"{mutation_target.semantics.semantic_class.value}, therefore an "
                    "owned-object cross-account mutation is not constructable."
                    if mutation_target.parameter is not None
                    else "Identify the exact ownership-relevant mutation parameter."
                )
            )
        ],
        next_action=(
            "Collect object lifecycle or explicit owner evidence; do not reinterpret shared "
            "scope as ownership."
        ),
        blocker_code="MISSING_SEMANTIC_TARGET",
    )
    actor_capability = _capability(
        CapabilityKind.ACTOR,
        satisfied=actor_count >= actors_required,
        stage=BlockerStage.HYPOTHESIS_EVIDENCE,
        summary=f"At least {actors_required} researcher-controlled actor(s) are required.",
        evidence=actor_evidence,
        missing=[
            f"Configure at least {actors_required} researcher-controlled account(s) or actor(s)."
        ],
        next_action="Configure the required controlled actors without adding real-user accounts.",
    )

    binding_family = rule.startswith("BUSINESS_LOGIC_ACTOR_SWITCH") or rule.startswith(
        "BUSINESS_LOGIC_RESOURCE_SWITCH"
    )
    ownership_required = record.category == "authorization" or binding_family
    ownership_satisfied = (
        execution_ownership_supported(mutation_target.semantics)
        and intent.visibility
        in {
            VisibilityIntent.OWNER_SCOPED,
            VisibilityIntent.ACTOR_BOUND,
        }
        and intent.binding.value != "UNKNOWN"
    )
    if binding_family:
        ownership_satisfied = (
            intent.visibility
            in {
                VisibilityIntent.OWNER_SCOPED,
                VisibilityIntent.ROLE_SCOPED,
                VisibilityIntent.ACTOR_BOUND,
            }
            and intent.binding.value != "UNKNOWN"
        )
    if rule == "FUNCTION_AUTHORIZATION":
        ownership_satisfied = intent.visibility == VisibilityIntent.ROLE_SCOPED
    ownership_capability = _capability(
        CapabilityKind.OWNERSHIP,
        required=ownership_required,
        satisfied=ownership_satisfied,
        stage=BlockerStage.HYPOTHESIS_EVIDENCE,
        summary="The claimed owner, tenant, role, session, or actor binding must be evidenced.",
        evidence=intent.positive_evidence,
        missing=[
            "Collect explicit owner, tenant, role, session, producer-consumer, or initiating-actor "
            "binding evidence for the protected subject."
        ],
        next_action=(
            "Capture two controlled subject/boundary baselines or add an explicit reviewed policy "
            "annotation."
        ),
    )

    source_hierarchies = _source_hierarchies(source, intent.subject_resource)
    matching_access = [
        access
        for endpoint in source
        for access in endpoint.object_access
        if mutation_target.parameter is None
        or parameter_identities_match(
            evidence_location=access.parameter_location,
            evidence_json_path=access.parameter_json_path,
            evidence_name=access.identifier,
            target_location=mutation_target.location,
            target_json_path=mutation_target.json_path,
            target_name=mutation_target.parameter,
        )
    ]
    endpoint_by_id = _unique_endpoint_index(endpoints)
    observation_by_id, ambiguous_observation_ids = _unique_observation_index(observations)
    controlled_actor_ids = {
        account.id
        for account in target.accounts
        if account.ownership == "researcher" and account.authenticated
    }
    global_controlled_baselines = [
        baseline
        for endpoint in endpoints
        for access in endpoint.object_access
        if access.actor_object_binding_observed
        and access.source in {"CONTROLLED_LIFECYCLE", "RESPONSE_BODY"}
        for baseline in access.baselines
    ]
    candidate_baselines = [
        baseline
        for access in matching_access
        if access.actor_object_binding_observed
        and access.source in {"CONTROLLED_LIFECYCLE", "RESPONSE_BODY"}
        for baseline in access.baselines
    ]
    source_contexts, target_parent_values = _source_comparison_contexts(
        source,
        observation_by_id,
        ambiguous_observation_ids,
        runtime_ids,
    )
    comparison_candidates = [
        candidate
        for baseline in candidate_baselines
        if (
            candidate := _comparison_candidate(
                baseline,
                controlled_actor_ids=controlled_actor_ids,
                endpoints=endpoint_by_id,
                observations=observation_by_id,
                ambiguous_observation_ids=ambiguous_observation_ids,
                source_contexts=source_contexts,
                source_hierarchies=source_hierarchies,
                target_parent_values=target_parent_values,
                intent=intent,
            )
        )
        is not None
    ]
    canonical_baselines, comparison_witness = _select_comparison_group(
        comparison_candidates,
        actors_required,
        target_parent_required=bool(target_parent_values),
    )
    baseline_actors = {baseline.actor_id for baseline in canonical_baselines}
    baseline_objects = {baseline.object_reference for baseline in canonical_baselines}
    baseline_parents = {
        baseline.parent_reference
        for baseline in canonical_baselines
        if baseline.parent_reference is not None
    }
    distinct_baselines = len(comparison_witness) >= actors_required
    missing_baseline_actors = sorted(controlled_actor_ids - baseline_actors)
    target_parent_baseline: ComparisonBaseline | None = None
    if target_parent_values:
        target_parent_baseline = (
            comparison_witness[0]
            if comparison_witness
            else next(
                (baseline for baseline in canonical_baselines if baseline.matches_target_parent),
                None,
            )
        )
    comparison_baselines = list(comparison_witness[1:]) if comparison_witness else []
    cross_parent_comparison = bool(
        target_parent_baseline is not None
        and any(
            baseline.parent_reference != target_parent_baseline.parent_reference
            for baseline in comparison_baselines
        )
    )
    if not ownership_required:
        comparison_explanation = "No cross-actor comparison coverage is required."
    elif target_parent_values and target_parent_baseline is None:
        comparison_explanation = (
            "No canonical controlled baseline matches the hypothesis's validated literal "
            "target parent; foreign-parent baselines alone cannot establish comparison coverage."
        )
    elif distinct_baselines and cross_parent_comparison:
        comparison_explanation = (
            "Different literal parents are intentionally retained as separate controlled "
            "contexts and accepted only for cross-actor comparison coverage; exact cleanup "
            "and subject-only mutation parent matching remain unchanged."
        )
    elif distinct_baselines:
        comparison_explanation = (
            "The selected controlled actor/object baselines satisfy comparison coverage within "
            "the retained target-parent context."
        )
    else:
        comparison_explanation = (
            "Canonical controlled baselines do not yet provide the required distinct "
            "actor/object comparison witness."
        )
    controlled_baseline_evidence = [
        _evidence(
            (
                baseline.baseline_ids
                or baseline.observation_ids
                or baseline.endpoint_ids
                or [baseline.canonical_reference]
            )[0],
            "WORKFLOW" if baseline.baseline_ids else "ENDPOINT",
            (
                f"Controlled {baseline.operation or 'resource'} baseline for "
                f"{baseline.actor_id} is backed by explicit lifecycle or owner-binding "
                f"evidence with {len(baseline.supporting_relationship_ids)} supporting "
                f"relationship{'s' if len(baseline.supporting_relationship_ids) != 1 else ''}; "
                f"liveness is {baseline.liveness.value}; its parent context remains distinct "
                "and opaque."
            ),
        )
        for baseline in canonical_baselines
    ]
    comparison_coverage = ComparisonCoverage(
        required_distinct_actors=actors_required if ownership_required else 0,
        observed_distinct_actors=len(baseline_actors),
        distinct_controlled_objects=len(baseline_objects),
        distinct_parent_references=len(baseline_parents),
        baseline_actor_ids=sorted(baseline_actors),
        missing_actor_ids=missing_baseline_actors,
        resource_type=intent.subject_resource,
        route_families=sorted(
            {hierarchy.collection_route_family for hierarchy in source_hierarchies.values()}
        ),
        parent_resource_type=intent.parent_resource,
        parent_references=sorted(baseline_parents),
        target_parent_references=sorted(
            opaque_reference("PARENT", value) for value in target_parent_values
        ),
        target_parent_baseline_reference=(
            target_parent_baseline.canonical_reference
            if target_parent_baseline is not None
            else None
        ),
        comparison_baseline_references=[
            baseline.canonical_reference for baseline in comparison_baselines
        ],
        witness_baseline_references=[
            baseline.canonical_reference for baseline in comparison_witness
        ],
        cross_parent_comparison=cross_parent_comparison,
        explanation=comparison_explanation,
        baseline_ids=sorted(
            {
                baseline_id
                for baseline in canonical_baselines
                for baseline_id in baseline.baseline_ids
            }
        ),
        evidence_references=sorted(
            {
                reference
                for baseline in canonical_baselines
                for reference in [
                    *baseline.baseline_ids,
                    *baseline.endpoint_ids,
                    *baseline.supporting_relationship_ids,
                    *baseline.observation_ids,
                    *baseline.liveness_evidence_references,
                ]
            }
        ),
        baselines=canonical_baselines,
    )
    all_runtime_ids = {
        item.id for item in observations.observations if item.source in RUNTIME_SOURCES
    }
    safe_oracles = [
        endpoint
        for endpoint in _oracle_endpoints(source, endpoints, intent)
        if set(endpoint.sources).intersection(all_runtime_ids)
    ]
    state_changing = _state_changing(intent)
    capture_strategy = " ".join(record.evidence_to_collect).lower()
    before_strategy = any(
        marker in capture_strategy
        for marker in ("before", "pre-state", "pre state", "initial state", "baseline state")
    )
    after_strategy = any(
        marker in capture_strategy
        for marker in ("after", "post-state", "post state", "state delta", "resulting state")
    )
    logic_baseline = _logic_capability(record, CapabilityKind.BASELINE)
    baseline_required = (
        record.category in {"authentication", "authorization"} or state_changing or binding_family
    )
    if rule == "FUNCTION_AUTHORIZATION":
        baseline_satisfied = (
            bool(runtime_source_ids)
            and actor_count >= 1
            and (not state_changing or before_strategy)
        )
    elif record.category == "authorization" or binding_family:
        baseline_satisfied = distinct_baselines and (not state_changing or before_strategy)
    elif state_changing:
        baseline_satisfied = bool(safe_oracles and runtime_ids and before_strategy)
        if logic_baseline is not None:
            baseline_satisfied = baseline_satisfied and logic_baseline.satisfied
    else:
        baseline_satisfied = bool(runtime_source_ids)
    baseline_capability = _capability(
        CapabilityKind.BASELINE,
        required=baseline_required,
        satisfied=baseline_satisfied,
        stage=BlockerStage.HYPOTHESIS_EVIDENCE,
        summary="Controlled baselines must establish the comparison or pre-state.",
        evidence=[
            _evidence(endpoint.id, "ENDPOINT", "A safe baseline/oracle endpoint is available.")
            for endpoint in safe_oracles
        ]
        + controlled_baseline_evidence,
        missing=(
            (
                (
                    [
                        "No canonical controlled baseline matches the hypothesis's validated "
                        "literal target parent."
                    ]
                    if target_parent_values and target_parent_baseline is None
                    else [
                        "No controlled ownership baseline exists."
                    ]
                    if not global_controlled_baselines
                    else [
                        "Controlled baselines exist globally, but not within this workflow family."
                    ]
                    if not canonical_baselines
                    else [
                        f"Missing controlled object baseline for {actor}."
                        for actor in missing_baseline_actors
                    ]
                )
                or ["No controlled ownership baseline exists for the required comparison."]
            )
            if record.category == "authorization" or binding_family
            else ["Capture a controlled pre-state through an authoritative safe read."]
        ),
        next_action=("Capture the missing controlled ownership evidence for this workflow family."),
        blocker_code="MISSING_CONTROLLED_BASELINE",
    )

    source_hosts = {host for endpoint in source for host in endpoint.hosts}
    scope_satisfied = bool(target.scope.hosts) and (
        not source_hosts or hosts_are_covered(source_hosts, target.scope.hosts)
    )
    request_template_satisfied = (
        len(source) == len(set(record.source.endpoints))
        and bool(source and runtime_source_ids)
        and scope_satisfied
        and (
            not semantic_target_required
            or (
                mutation_target.location == "path"
                and mutation_target.json_path is None
                and mutation_target.parameter is not None
            )
        )
    )
    if rule.startswith("BUSINESS_LOGIC_SHADOW_ENDPOINT"):
        request_template_satisfied = False
    request_missing: list[str] = []
    if not source or len(source) != len(set(record.source.endpoints)):
        request_missing.append("One or more source endpoints cannot be resolved from inventory.")
    if not runtime_source_ids:
        request_missing.append(
            "Capture a runtime request matching the exact method, route, and mutation input."
        )
    if not target.scope.hosts:
        request_missing.append("No in-scope hosts are configured.")
    elif not scope_satisfied:
        request_missing.append("Source endpoint hosts are not fully covered by target scope.")
    if rule.startswith("BUSINESS_LOGIC_SHADOW_ENDPOINT"):
        request_missing.append("The candidate method has not been observed at runtime.")
    if semantic_target_required and mutation_target.parameter is None:
        request_missing.append("The exact semantic mutation target could not be resolved.")
    elif semantic_target_required and mutation_target.location != "path":
        request_missing.append(
            "The bounded runner supports exact path substitutions only; preserve this target "
            "for manual review without guessing a request mutation."
        )
    request_capability = _capability(
        CapabilityKind.REQUEST_TEMPLATE,
        satisfied=request_template_satisfied,
        stage=BlockerStage.PLAN_CONSTRUCTABILITY,
        summary="A redacted observed request template must support the exact bounded mutation.",
        evidence=[
            _evidence(endpoint.id, "ENDPOINT", "Endpoint has runtime request provenance.")
            for endpoint in source
            if set(endpoint.sources).intersection(runtime_source_ids)
        ],
        missing=request_missing,
        next_action="Collect one authorized runtime baseline request for the exact operation.",
        blocker_code="MISSING_RUNTIME_TEMPLATE",
    )

    if intent.operation == DomainOperation.VERIFY_CREDENTIAL:
        oracle_satisfied = bool(source and runtime_source_ids)
        oracle_summary = "A verifier decision can classify the bounded credential claim."
    elif state_changing:
        oracle_satisfied = bool(safe_oracles and runtime_ids and after_strategy)
        oracle_summary = (
            "A concrete post-state oracle plus before/immediate/delayed capture strategy is "
            "required."
        )
    else:
        oracle_satisfied = bool(
            source
            and runtime_source_ids
            and any(
                parameter.source == "response"
                for endpoint in source
                for parameter in endpoint.parameters
            )
        )
        oracle_summary = "A meaningful response or protected-resource oracle is required."
    oracle_capability = _capability(
        CapabilityKind.ORACLE,
        satisfied=oracle_satisfied,
        stage=BlockerStage.PLAN_CONSTRUCTABILITY,
        summary=oracle_summary,
        evidence=[
            _evidence(endpoint.id, "ENDPOINT", "Endpoint supports the planned oracle strategy.")
            for endpoint in safe_oracles or source
        ],
        missing=[
            "Define and capture an authoritative post-state or protected-response oracle, "
            "including "
            "before/immediate/delayed state when the operation changes state."
        ],
        next_action="Capture the independent safe oracle required to classify the result.",
    )

    segmentation = _logic_capability(record, CapabilityKind.SEGMENTATION)
    segmentation_capability = segmentation or _capability(
        CapabilityKind.SEGMENTATION,
        required=record.category == "business_logic",
        satisfied=record.category != "business_logic",
        stage=BlockerStage.HYPOTHESIS_EVIDENCE,
        summary="Workflow segmentation must be strong enough to isolate the tested sequence.",
        missing=["Collect typed causal evidence that resolves workflow segmentation ambiguity."],
        next_action="Capture the producer-consumer evidence needed to isolate the workflow.",
    )

    cleanup_required = state_changing
    cleanup_fingerprint = cleanup_control_fingerprint(record, intent, mutation_target, source)
    cleanup_source_checksum = cleanup_control_source_checksum(
        target,
        observations,
        record,
        intent,
        mutation_target,
        source,
    )
    matching_cleanup: CleanupControlRule | None = None
    cleanup_evidence: list[DecisionEvidence] = []
    cleanup_missing = ["Define a rollback, cleanup, or disposable-resource strategy."]
    if cleanup_required and not target.testing.synthetic and not target.testing.local_lab:
        matching_cleanup, cleanup_evidence, cleanup_missing = _resolve_cleanup_control(
            target=target,
            observations=observations,
            endpoints=endpoints,
            resources=resources,
            intent=intent,
            source_hierarchies=source_hierarchies,
            candidate_baselines=candidate_baselines,
            baseline_actors=baseline_actors,
            cleanup_fingerprint=cleanup_fingerprint,
            cleanup_source_checksum=cleanup_source_checksum,
        )
    cleanup_satisfied = (
        not cleanup_required
        or target.testing.synthetic
        or target.testing.local_lab
        or matching_cleanup is not None
    )
    logic_cleanup = _logic_capability(record, CapabilityKind.CLEANUP)
    if logic_cleanup is not None and cleanup_required:
        cleanup_satisfied = cleanup_satisfied and logic_cleanup.satisfied
    if (target.testing.synthetic or target.testing.local_lab) and cleanup_required:
        cleanup_evidence.append(
            _evidence(
                "target.testing",
                "TARGET_POLICY",
                "The target is configured as a synthetic or local-lab environment.",
            )
        )
    cleanup_capability = _capability(
        CapabilityKind.CLEANUP,
        required=cleanup_required,
        satisfied=cleanup_satisfied,
        stage=BlockerStage.PLAN_CONSTRUCTABILITY,
        summary="State-changing tests require rollback, cleanup, or disposable-resource controls.",
        evidence=cleanup_evidence,
        missing=cleanup_missing,
        next_action=(
            "Add analysis.cleanup_controls with semantic_fingerprint "
            f"{cleanup_fingerprint} and source_checksum {cleanup_source_checksum}."
        ),
        blocker_code="MISSING_CLEANUP",
    )

    execution_actor_ids = {item.actor_id for item in comparison_witness}
    if not execution_actor_ids:
        execution_actor_ids = {
            observation.actor
            for observation in observations.observations
            if observation.id in runtime_source_ids
            and observation.actor not in {"UNKNOWN", "ANONYMOUS"}
        }
    identity_facts: list[IdentityConstructabilityFact] = []
    for account in target.accounts:
        if account.id not in execution_actor_ids:
            continue
        authentication = account.authentication
        identity_facts.append(
            IdentityConstructabilityFact(
                actor_id=account.id,
                credential_accepted=(
                    authentication.credential_accepted if authentication is not None else False
                ),
                scope_validated=(
                    authentication.scope_validated if authentication is not None else False
                ),
                identity_confirmed=(
                    authentication.identity.confirmed if authentication is not None else False
                ),
                evidence_reference=f"actor:{account.id}",
            )
        )
    constructability = assess_execution_constructability(
        ConstructabilityContext(
            hypothesis_id=record.id,
            category=record.category,
            generation_rule_id=rule,
            methods=tuple(sorted({endpoint.method for endpoint in source})),
            state_changing=state_changing or any(endpoint.state_change for endpoint in source),
            runtime_template_satisfied=request_template_satisfied,
            runtime_evidence=tuple(request_capability.evidence),
            semantic_target_required=semantic_target_required,
            semantic_target_satisfied=semantic_target_satisfied,
            semantic_evidence=tuple(semantic_target_capability.evidence),
            controlled_baseline_required=(
                record.category == "authorization" and rule.startswith("AUTH_OBJECT_ACCESS")
            ),
            controlled_baseline_satisfied=distinct_baselines,
            selected_baselines=tuple(comparison_witness),
            cleanup_required=cleanup_required,
            cleanup_satisfied=cleanup_satisfied,
            cleanup_evidence=tuple(cleanup_evidence),
            cleanup_missing=tuple(cleanup_missing),
            cleanup_next_action=cleanup_capability.next_action,
            maximum_requests_per_plan=target.testing.maximum_requests_per_plan,
            identity_facts=tuple(identity_facts),
        )
    )
    budget_required = constructability.request_count is not None
    budget_satisfied = (
        not budget_required
        or constructability.request_count is not None
        and target.testing.maximum_requests_per_plan >= constructability.request_count
    )
    budget_capability = _capability(
        CapabilityKind.BUDGET,
        required=budget_required,
        satisfied=budget_satisfied,
        stage=BlockerStage.PLAN_CONSTRUCTABILITY,
        summary=(
            "Request budget is evaluated only after a concrete canonical template exists."
            if constructability.request_count is None
            else (
                f"The concrete template requires {constructability.request_count} request(s); "
                f"target policy permits {target.testing.maximum_requests_per_plan}."
            )
        ),
        evidence=(
            [
                _evidence(
                    "target.testing.maximum_requests_per_plan",
                    "TARGET_POLICY",
                    f"Configured request budget is {target.testing.maximum_requests_per_plan}.",
                )
            ]
            if budget_required
            else []
        ),
        missing=(
            [
                f"The concrete template requires {constructability.request_count} request(s), "
                f"but policy permits {target.testing.maximum_requests_per_plan}."
            ]
            if budget_required and not budget_satisfied
            else []
        ),
        next_action=(
            "Review target.testing.maximum_requests_per_plan; do not change execution policy "
            "automatically."
        ),
        blocker_code="MISSING_BUDGET",
    )

    warnings = [
        ReadinessIssue(
            code="HUMAN_APPROVAL_REQUIRED",
            stage=BlockerStage.HUMAN_APPROVAL,
            summary="Human approval remains mandatory after the plan is reviewed.",
        )
    ]
    if not target.testing.active_execution_enabled:
        warnings.append(
            ReadinessIssue(
                code="ACTIVE_EXECUTION_DISABLED",
                stage=BlockerStage.EXECUTION_POLICY,
                summary="Active execution is disabled; this does not change hypothesis readiness.",
            )
        )
    if state_changing and target.testing.read_only_only:
        warnings.append(
            ReadinessIssue(
                code="READ_ONLY_RUNNER_UNSUPPORTED",
                stage=BlockerStage.EXECUTION_POLICY,
                summary=(
                    "The bounded runner remains read-only; any approved collection is manual-only."
                ),
            )
        )
    logic_safety = (
        str(record.logic_details.get("safety_classification", ""))
        if record.logic_details is not None
        else ""
    )
    if logic_safety == "CONCURRENT" or "CONCURRENCY" in record.mutation_dimensions:
        warnings.append(
            ReadinessIssue(
                code="CONCURRENCY_EXECUTION_UNSUPPORTED",
                stage=BlockerStage.EXECUTION_POLICY,
                summary="Concurrency testing remains manual-only and outside the bounded runner.",
            )
        )
    if claim_strength.target_level.value.startswith("5_"):
        warnings.append(
            ReadinessIssue(
                code="AUTHORITATIVE_EFFECT_EVIDENCE_REQUIRED",
                stage=BlockerStage.HUMAN_APPROVAL,
                summary="A status code alone cannot establish the targeted backend-effect claim.",
            )
        )
    return ReadinessContext(
        hypothesis_id=record.id,
        kind=record.kind,
        capabilities=(
            concrete_capability,
            semantic_target_capability,
            actor_capability,
            ownership_capability,
            baseline_capability,
            request_capability,
            oracle_capability,
            budget_capability,
            segmentation_capability,
            cleanup_capability,
        ),
        constructability=constructability,
        comparison_coverage=comparison_coverage,
        warnings=tuple(warnings),
    )


def assess_record_readiness(
    target: TargetDocument,
    observations: ObservationStore,
    endpoints: list[Endpoint],
    resources: ResourceStore,
    record: HypothesisLike,
    intent: DomainIntentAssessment,
    claim_strength: ClaimStrengthAssessment,
) -> HypothesisReadinessAssessment:
    """Build and evaluate the canonical record context in one deterministic call."""

    return evaluate_readiness(
        build_record_readiness_context(
            target,
            observations,
            endpoints,
            resources,
            record,
            intent,
            claim_strength,
        )
    )
