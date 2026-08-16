"""Precision regressions for unified readiness, intent, claims, and clustering."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pytest

from finsec.behavior.queue_evaluation import compare_workspace_queues
from finsec.config.models import CleanupControlRule, TargetDocument
from finsec.config.workspace import WorkspacePaths, create_workspace
from finsec.hypotheses.clustering import finalize_hypothesis_store, presentation_visible
from finsec.hypotheses.contracts import (
    BlockerStage,
    CapabilityKind,
    ClaimStrengthAssessment,
    ClaimStrengthLevel,
    DomainIntentAssessment,
    HypothesisReadinessAssessment,
    MutationTargetAssessment,
)
from finsec.hypotheses.domain import (
    HypothesisRecord,
    HypothesisScores,
    HypothesisSource,
    HypothesisStore,
    PotentialImpact,
)
from finsec.hypotheses.generator import load_hypotheses
from finsec.hypotheses.readiness import (
    assess_record_readiness,
    cleanup_control_fingerprint,
    cleanup_control_source_checksum,
)
from finsec.hypotheses.semantics import assess_claim_strength, assess_domain_intent
from finsec.modeling.domain import GenerationMetadata, ResourceStore
from finsec.modeling.liveness import ControlledObjectLiveness
from finsec.modeling.models import (
    ActorObjectBaseline,
    AuthenticationObservation,
    Confidence,
    Endpoint,
    EndpointAction,
    EndpointAuthentication,
    EndpointClassification,
    EndpointParameter,
    EndpointPrimaryClassification,
    EndpointResource,
    EndpointStore,
    KnowledgeStatus,
    NormalizationEvidence,
    ObjectAccessEvidence,
    Observation,
    ObservationStore,
    SideEffectEvidence,
)
from finsec.modeling.semantics import (
    IdentifierResourceRole,
    IdentifierSemanticAssessment,
    IdentifierSemanticClass,
    OwnershipState,
)
from finsec.normalization.inventory import _action
from finsec.normalization.path_semantics import path_hierarchy
from finsec.testing.planner import inspect_plan_alignment, inspect_plan_alignment_from_inputs
from finsec.testing.templates import build_execution_templates
from finsec.utils.yaml_store import write_yaml


def _target(
    *,
    accounts: int = 2,
    domain_intent_rules: list[dict[str, object]] | None = None,
) -> TargetDocument:
    return TargetDocument.model_validate(
        {
            "target": {"name": "unified-tests", "slug": "unified-tests"},
            "scope": {"hosts": ["api.unified.test"]},
            "accounts": [
                {"id": f"ACCOUNT_{index}", "ownership": "researcher"}
                for index in range(1, accounts + 1)
            ],
            "testing": {
                "synthetic": True,
                "local_lab": True,
                "maximum_requests_per_plan": 6,
            },
            "analysis": {"domain_intent_rules": domain_intent_rules or []},
        }
    )


def _observation(
    identifier: str,
    *,
    method: str,
    path: str,
    actor: str = "ACCOUNT_1",
    authenticated: bool = True,
) -> Observation:
    return Observation(
        id=identifier,
        source="HAR",
        source_reference=f"{identifier}.har",
        source_fingerprint=f"fingerprint-{identifier}",
        actor=actor,
        channel="WEB",
        host="api.unified.test",
        scheme="https",
        method=method,
        path=path,
        response_fields=["$.id"],
        status_code=200,
        content_type="application/json",
        authentication=AuthenticationObservation(
            present=authenticated,
            observed_type="bearer" if authenticated else "none",
        ),
    )


def _endpoint(
    identifier: str,
    *,
    method: str = "GET",
    path: str = "/api/orders/{orderId}",
    resource: str = "Order",
    action: str = "read",
    state_change: bool = False,
    observations: tuple[str, ...] = ("OBS-1",),
    ownership_known: bool = False,
    authenticated: bool = True,
    child_response: str | None = None,
) -> Endpoint:
    request_parameter = EndpointParameter(
        name=f"{resource[0].lower() + resource[1:]}Id",
        location="path",
        source="request",
        inferred_type="string",
        confidence=Confidence.HIGH,
        evidence=list(observations),
        knowledge_status=KnowledgeStatus.INFERRED,
        semantic_type="object_identifier",
        client_controlled=True,
    )
    response_parameter = EndpointParameter(
        name="id",
        location="response_body",
        source="response",
        inferred_type="string",
        confidence=Confidence.HIGH,
        evidence=list(observations),
        knowledge_status=KnowledgeStatus.OBSERVED,
        json_path=child_response or "$.id",
        semantic_type="object_identifier",
        client_controlled=False,
    )
    object_access = []
    if ownership_known:
        object_access = [
            ObjectAccessEvidence(
                identifier=request_parameter.name,
                baselines=[
                    ActorObjectBaseline(
                        actor="ACCOUNT_1",
                        requested_value="redacted-a",
                        endpoint_id=identifier,
                        observations=[observations[0]],
                    ),
                    ActorObjectBaseline(
                        actor="ACCOUNT_2",
                        requested_value="redacted-b",
                        endpoint_id=identifier,
                        observations=[observations[-1]],
                    ),
                ],
                distinct_actors=2,
                distinct_objects=2,
                distinct_owner_values=2,
                actor_object_binding_observed=True,
            )
        ]
    return Endpoint(
        id=identifier,
        method=method,
        path=path,
        hosts=["api.unified.test"],
        channels=["WEB"],
        authentication=EndpointAuthentication(
            required=authenticated,
            observed_type="bearer" if authenticated else "none",
        ),
        classification=EndpointClassification(
            primary=EndpointPrimaryClassification.FIRST_PARTY_API,
            confidence=Confidence.HIGH,
        ),
        resource=EndpointResource(type=resource, confidence=Confidence.HIGH),
        action=EndpointAction(
            name=action,
            type="mutation" if state_change else "read",
            confidence=Confidence.HIGH,
        ),
        parameters=[request_parameter, response_parameter],
        object_access=object_access,
        state_change=state_change,
        state_change_reasons=["synthetic explicit state change"] if state_change else [],
        security_relevance=8,
        observed_by=["ACCOUNT_1", "ACCOUNT_2"] if ownership_known else ["ACCOUNT_1"],
        sources=list(observations),
        confidence=Confidence.HIGH,
        normalization=NormalizationEvidence(observed_paths=[path]),
    )


def _typed_baseline(
    endpoint: Endpoint,
    *,
    actor: str,
    object_id: str,
    subject_resource_type: str | None = None,
    collection_route_family: str | None = None,
    parent_resource_type: str | None = None,
    parent_value: str | None = None,
    endpoint_id: str | None = None,
    observation_id: str | None = None,
) -> ActorObjectBaseline:
    hierarchy = path_hierarchy(endpoint.path, endpoint.path, endpoint.resource.type)
    return ActorObjectBaseline(
        actor=actor,
        requested_value=object_id,
        subject_resource_id=f"RSC-{object_id}",
        subject_resource_type=subject_resource_type or endpoint.resource.type,
        parent_resource_type=(
            parent_resource_type
            if parent_resource_type is not None
            else hierarchy.parent.resource_type
            if hierarchy.parent is not None
            else None
        ),
        parent_value=(
            parent_value
            if parent_value is not None
            else hierarchy.parent.value
            if hierarchy.parent is not None
            else None
        ),
        endpoint_id=endpoint_id or endpoint.id,
        route_family=hierarchy.route_family,
        collection_route_family=(collection_route_family or hierarchy.collection_route_family),
        baseline_id=f"BASE-{actor}-{object_id}",
        observations=[observation_id or endpoint.sources[0]],
    )


def _authorization_assessment(
    endpoint: Endpoint,
    baselines: list[ActorObjectBaseline],
    *,
    provenance_endpoints: list[Endpoint] | None = None,
) -> HypothesisReadinessAssessment:
    access = ObjectAccessEvidence(
        identifier=endpoint.parameters[0].name,
        source="CONTROLLED_LIFECYCLE",
        baselines=baselines,
        distinct_actors=len({item.actor for item in baselines}),
        distinct_objects=len(
            {item.subject_resource_id or item.requested_value for item in baselines}
        ),
        actor_object_binding_observed=True,
    )
    endpoint = endpoint.model_copy(update={"object_access": [access]})
    record = _record("HYP-001", endpoint)
    all_endpoints = [endpoint, *(provenance_endpoints or [])]
    actors_by_observation: dict[str, set[str]] = {}
    for baseline in baselines:
        for observation_id in baseline.observations:
            actors_by_observation.setdefault(observation_id, set()).add(baseline.actor)
    observation_records: list[Observation] = []
    seen_observations: set[str] = set()
    for provenance_endpoint in sorted(all_endpoints, key=lambda item: item.id):
        for observation_id in provenance_endpoint.sources:
            if observation_id in seen_observations:
                continue
            seen_observations.add(observation_id)
            actors = actors_by_observation.get(observation_id, {"ACCOUNT_1"})
            actor = next(iter(actors)) if len(actors) == 1 else "UNKNOWN"
            observation_records.append(
                _observation(
                    observation_id,
                    method=provenance_endpoint.method,
                    path=provenance_endpoint.path,
                    actor=actor,
                )
            )
    observations = ObservationStore(observations=observation_records)
    target = _target()
    intent = assess_domain_intent(
        target,
        [endpoint],
        category=record.category,
        generation_rule_id=record.generation_rule["id"],
        mutation_target=record.mutation_target,
    )
    claim = assess_claim_strength(
        generation_rule_id=record.generation_rule["id"],
        category=record.category,
        intent=intent,
        eligibility_evidence=[],
    )
    return assess_record_readiness(
        target,
        observations,
        all_endpoints,
        ResourceStore(),
        record,
        intent,
        claim,
    )


def _record(
    identifier: str,
    endpoint: Endpoint,
    *,
    category: str = "authorization",
    rule: str = "AUTH_OBJECT_ACCESS",
    kind: str = "SECURITY_HYPOTHESIS",
    disposition: str = "ACTIVE",
    mutation_dimensions: list[str] | None = None,
    logic_details: dict[str, object] | None = None,
    eligibility_evidence: list[str] | None = None,
    generation: str | None = None,
) -> HypothesisRecord:
    return HypothesisRecord.model_validate(
        {
            "id": identifier,
            "key": f"key:{identifier}",
            "title": f"Raw hypothesis {identifier}",
            "kind": kind,
            "disposition": disposition,
            "category": category,
            "component": "WFAM-UNIFIED" if category == "business_logic" else endpoint.resource.type,
            "source": HypothesisSource(
                endpoints=[endpoint.id], observations=list(endpoint.sources)
            ).model_dump(mode="json"),
            "observations": list(endpoint.sources),
            "mutation_dimensions": mutation_dimensions or ["ACTOR", "OBJECT"],
            "evidence_status": "INFERRED",
            "hypothesis": "Apply one controlled mutation.",
            "reasoning": "Synthetic evidence-backed regression record.",
            "preconditions": ["Use only researcher-controlled actors and resources."],
            "expected_secure_behavior": "The boundary is enforced.",
            "possible_vulnerable_behavior": "The controlled mutation crosses the boundary.",
            "potential_impact": PotentialImpact().model_dump(mode="json"),
            "evidence_to_collect": [
                "Record authoritative state before the mutation.",
                "Record authoritative state after the mutation.",
            ],
            "eligibility_evidence": eligibility_evidence or [],
            "missing_evidence": [],
            "generation_rule": {"id": rule, "version": "1"},
            "scores": HypothesisScores(
                impact=3,
                likelihood=3,
                confidence=3,
                testability=3,
                total=12,
            ).model_dump(mode="json"),
            "priority": "P2",
            "logic_details": logic_details,
            "generation": (
                GenerationMetadata(
                    generator=generation,
                    generated_checksum=f"checksum-{identifier}",
                    source_fingerprint="source-unified",
                ).model_dump(mode="json")
                if generation is not None
                else None
            ),
        }
    )


@dataclass(frozen=True)
class _CrossParentCase:
    target: TargetDocument
    observations: ObservationStore
    endpoints: tuple[Endpoint, ...]
    record: HypothesisRecord
    baselines: tuple[ActorObjectBaseline, ...]


def _comparison_endpoint(
    identifier: str,
    *,
    parent: str,
    object_value: str,
    observation_id: str,
    method: str = "GET",
    collection: str = "dns-records",
    host: str = "api.unified.test",
    authentication_type: str = "bearer",
) -> tuple[Endpoint, Observation]:
    state_change = method not in {"GET", "HEAD"}
    endpoint = _endpoint(
        identifier,
        method=method,
        path=f"/cdn/4.0/domains/{parent}/{collection}/{{dnsRecordId}}",
        resource="DnsRecord",
        action="delete" if method == "DELETE" else "read",
        state_change=state_change,
        observations=(observation_id,),
    ).model_copy(
        update={
            "hosts": [host],
            "authentication": EndpointAuthentication(
                required=True,
                observed_type=authentication_type,
            ),
        }
    )
    observation = _observation(
        observation_id,
        method=method,
        path=f"/cdn/4.0/domains/{parent}/{collection}/{object_value}",
        actor="ACCOUNT_A" if object_value in {"RECORD_A", "RECORD_C"} else "ACCOUNT_B",
    ).model_copy(
        update={
            "host": host,
            "authentication": AuthenticationObservation(
                present=True,
                observed_type=authentication_type,
            ),
        }
    )
    return endpoint, observation


def _comparison_baseline(
    endpoint: Endpoint,
    *,
    actor: str,
    parent: str,
    object_value: str,
    observation_id: str,
    parent_resource_type: str = "Domain",
) -> ActorObjectBaseline:
    hierarchy = path_hierarchy(endpoint.path, endpoint.path, endpoint.resource.type)
    return ActorObjectBaseline(
        actor=actor,
        requested_value=object_value,
        subject_resource_id=f"RSC-{object_value}",
        subject_resource_type="DnsRecord",
        parent_resource_id=f"RSC-{parent.upper().replace('.', '-')}",
        parent_resource_type=parent_resource_type,
        parent_value=parent,
        endpoint_id=endpoint.id,
        route_family=hierarchy.route_family,
        collection_route_family=hierarchy.collection_route_family,
        baseline_id=f"BASE-{actor}-{object_value}",
        relationship_ids=[
            f"REL-{actor}-{object_value}-CREATED",
            f"REL-{actor}-{object_value}-CONSUMED",
        ],
        liveness="DELETED" if endpoint.method == "DELETE" else "LIVE",
        liveness_evidence=[observation_id],
        operation="DELETE" if endpoint.method == "DELETE" else "READ",
        authentication_type=endpoint.authentication.observed_type,
        observations=[observation_id],
    )


def _cross_parent_case(
    *,
    method: str = "GET",
    maximum_requests_per_plan: int = 6,
    synthetic: bool = True,
    local_lab: bool = True,
) -> _CrossParentCase:
    endpoint_a, observation_a = _comparison_endpoint(
        "EP-DNS-A",
        parent="domain-a.test",
        object_value="RECORD_A",
        observation_id="OBS-A",
        method=method,
    )
    endpoint_b, observation_b = _comparison_endpoint(
        "EP-DNS-B",
        parent="domain-b.test",
        object_value="RECORD_B",
        observation_id="OBS-B",
        method=method,
    )
    baseline_a = _comparison_baseline(
        endpoint_a,
        actor="ACCOUNT_A",
        parent="domain-a.test",
        object_value="RECORD_A",
        observation_id="OBS-A",
    )
    baseline_b = _comparison_baseline(
        endpoint_b,
        actor="ACCOUNT_B",
        parent="domain-b.test",
        object_value="RECORD_B",
        observation_id="OBS-B",
    )
    access = ObjectAccessEvidence(
        identifier="dnsRecordId",
        parameter_location="path",
        source="CONTROLLED_LIFECYCLE",
        baselines=[baseline_a, baseline_b],
        distinct_actors=2,
        distinct_objects=2,
        distinct_parent_values=2,
        actor_object_binding_observed=True,
        relationship_ids=sorted({*baseline_a.relationship_ids, *baseline_b.relationship_ids}),
        baseline_ids=[baseline_a.baseline_id or "", baseline_b.baseline_id or ""],
    )
    endpoint_a = endpoint_a.model_copy(update={"object_access": [access]})
    target = TargetDocument.model_validate(
        {
            "target": {"name": "cross-parent-tests", "slug": "cross-parent-tests"},
            "scope": {"hosts": ["api.unified.test"]},
            "accounts": [
                {
                    "id": actor,
                    "ownership": "researcher",
                    "authentication": {
                        "auth_type": "bearer",
                        "source": {"type": "manual"},
                        "identity": {
                            "confirmed": True,
                            "confirmation_reference": f"identity-assertion:{actor.lower()}",
                            "last_assertion_status": "CONFIRMED",
                        },
                        "status": "READY",
                        "target_hosts": ["api.unified.test"],
                        "credential_accepted": True,
                        "scope_validated": True,
                    },
                }
                for actor in ("ACCOUNT_A", "ACCOUNT_B")
            ],
            "testing": {
                "synthetic": synthetic,
                "local_lab": local_lab,
                "maximum_requests_per_plan": maximum_requests_per_plan,
            },
        }
    )
    mutation_target = MutationTargetAssessment(
        parameter="dnsRecordId",
        location="path",
        endpoint_ids=[endpoint_a.id],
        semantics=IdentifierSemanticAssessment(
            semantic_class=IdentifierSemanticClass.OWNED_OBJECT,
            resource_role=IdentifierResourceRole.CHILD_OBJECT,
            resource_type="DnsRecord",
            parent_resource_type="Domain",
            ownership_state=OwnershipState.STRONG_INFERRED,
            confidence="high",
            evidence=[baseline_a.baseline_id or "", baseline_b.baseline_id or ""],
            explanation="Two controlled actor/object lifecycles establish ownership.",
        ),
        expected_authorization_relationship="OWNER_SCOPED",
    )
    record = _record("HYP-CROSS-PARENT", endpoint_a).model_copy(
        update={"mutation_target": mutation_target}
    )
    return _CrossParentCase(
        target=target,
        observations=ObservationStore(observations=[observation_a, observation_b]),
        endpoints=(endpoint_a, endpoint_b),
        record=record,
        baselines=(baseline_a, baseline_b),
    )


def _assessment_for_cross_parent_case(
    case: _CrossParentCase,
    *,
    target: TargetDocument | None = None,
    observations: ObservationStore | None = None,
    endpoints: list[Endpoint] | tuple[Endpoint, ...] | None = None,
    baselines: list[ActorObjectBaseline] | tuple[ActorObjectBaseline, ...] | None = None,
) -> HypothesisReadinessAssessment:
    selected_target = target or case.target
    selected_observations = observations or case.observations
    selected_endpoints = list(endpoints or case.endpoints)
    selected_baselines = list(baselines or case.baselines)
    source_index = next(
        index
        for index, endpoint in enumerate(selected_endpoints)
        if endpoint.id == case.record.source.endpoints[0]
    )
    source = selected_endpoints[source_index]
    access = source.object_access[0].model_copy(
        update={
            "baselines": selected_baselines,
            "distinct_actors": len({item.actor for item in selected_baselines}),
            "distinct_objects": len(
                {item.subject_resource_id or item.requested_value for item in selected_baselines}
            ),
            "distinct_parent_values": len(
                {
                    item.parent_resource_id or item.parent_value
                    for item in selected_baselines
                    if item.parent_resource_id is not None or item.parent_value is not None
                }
            ),
            "relationship_ids": sorted(
                {
                    relationship
                    for item in selected_baselines
                    for relationship in item.relationship_ids
                }
            ),
            "baseline_ids": sorted(
                item.baseline_id for item in selected_baselines if item.baseline_id is not None
            ),
        }
    )
    source = source.model_copy(update={"object_access": [access]})
    selected_endpoints[source_index] = source
    intent = assess_domain_intent(
        selected_target,
        [source],
        category=case.record.category,
        generation_rule_id=case.record.generation_rule["id"],
        mutation_target=case.record.mutation_target,
    )
    claim = assess_claim_strength(
        generation_rule_id=case.record.generation_rule["id"],
        category=case.record.category,
        intent=intent,
        eligibility_evidence=[],
    )
    return assess_record_readiness(
        selected_target,
        selected_observations,
        selected_endpoints,
        ResourceStore(),
        case.record,
        intent,
        claim,
    )


def test_cross_parent_baselines_satisfy_two_actor_comparison_coverage() -> None:
    assessment = _assessment_for_cross_parent_case(_cross_parent_case())
    coverage = assessment.comparison_coverage

    assert coverage.required_distinct_actors == 2
    assert coverage.observed_distinct_actors == 2
    assert coverage.distinct_controlled_objects == 2
    assert coverage.distinct_parent_references == 2
    assert coverage.baseline_actor_ids == ["ACCOUNT_A", "ACCOUNT_B"]
    assert coverage.missing_actor_ids == []
    assert coverage.cross_parent_comparison is True
    assert "different literal parents" in coverage.explanation.lower()
    assert not any(item.code == "MISSING_CONTROLLED_BASELINE" for item in assessment.blockers)


def test_read_only_get_object_substitution_is_canonically_constructable() -> None:
    assessment = _assessment_for_cross_parent_case(_cross_parent_case())

    assert assessment.readiness == "TEST_READY"
    assert assessment.constructability.supported is True
    assert assessment.constructability.execution_mode == "OBJECT_SUBSTITUTION"
    assert assessment.constructability.request_count == 2
    assert assessment.constructability.blocker_code is None
    assert {item.liveness for item in assessment.constructability.baselines} == {"LIVE"}


def test_cross_parent_coverage_is_anchored_to_the_source_target_parent() -> None:
    assessment = _assessment_for_cross_parent_case(_cross_parent_case())
    coverage = assessment.comparison_coverage
    target = next(
        item
        for item in coverage.baselines
        if item.canonical_reference == coverage.target_parent_baseline_reference
    )
    comparisons = {item.canonical_reference: item for item in coverage.baselines}

    assert sum(item.matches_target_parent for item in coverage.baselines) == 1
    assert target.actor_id == "ACCOUNT_A"
    assert target.parent_reference == "RSC-DOMAIN-A-TEST"
    assert coverage.target_parent_references
    assert [comparisons[item].actor_id for item in coverage.comparison_baseline_references] == [
        "ACCOUNT_B"
    ]


def test_cross_parent_comparison_is_order_independent() -> None:
    case = _cross_parent_case()
    forward = _assessment_for_cross_parent_case(case)
    reversed_baselines = [
        item.model_copy(update={"relationship_ids": list(reversed(item.relationship_ids))})
        for item in reversed(case.baselines)
    ]
    reversed_target = case.target.model_copy(
        update={"accounts": list(reversed(case.target.accounts))}
    )
    reversed_assessment = _assessment_for_cross_parent_case(
        case,
        target=reversed_target,
        observations=case.observations.model_copy(
            update={"observations": list(reversed(case.observations.observations))}
        ),
        endpoints=list(reversed(case.endpoints)),
        baselines=reversed_baselines,
    )

    assert forward.model_dump(mode="json") == reversed_assessment.model_dump(mode="json")


def test_two_objects_owned_by_one_actor_do_not_satisfy_two_actor_coverage() -> None:
    case = _cross_parent_case()
    baseline_b = case.baselines[1].model_copy(update={"actor": "ACCOUNT_A"})
    observations = case.observations.model_copy(
        update={
            "observations": [
                case.observations.observations[0],
                case.observations.observations[1].model_copy(update={"actor": "ACCOUNT_A"}),
            ]
        }
    )
    assessment = _assessment_for_cross_parent_case(
        case,
        observations=observations,
        baselines=[case.baselines[0], baseline_b],
    )

    assert assessment.comparison_coverage.observed_distinct_actors == 1
    assert assessment.comparison_coverage.distinct_controlled_objects == 2
    assert any(item.code == "MISSING_CONTROLLED_BASELINE" for item in assessment.blockers)


def test_corroborating_cross_parent_edges_merge_into_one_baseline() -> None:
    case = _cross_parent_case()
    corroborating = case.baselines[0].model_copy(
        update={
            "baseline_id": "BASE-ACCOUNT_A-RECORD_A-CORROBORATING",
            "relationship_ids": ["REL-A-CORROBORATING"],
        }
    )
    assessment = _assessment_for_cross_parent_case(
        case,
        baselines=[case.baselines[0], corroborating, case.baselines[1]],
    )
    account_a = next(
        item for item in assessment.comparison_coverage.baselines if item.actor_id == "ACCOUNT_A"
    )

    assert len(assessment.comparison_coverage.baselines) == 2
    assert account_a.baseline_ids == [
        "BASE-ACCOUNT_A-RECORD_A",
        "BASE-ACCOUNT_A-RECORD_A-CORROBORATING",
    ]
    assert "REL-A-CORROBORATING" in account_a.supporting_relationship_ids


def test_same_object_under_duplicated_evidence_counts_once() -> None:
    case = _cross_parent_case()
    duplicated_object = case.baselines[1].model_copy(
        update={"subject_resource_id": case.baselines[0].subject_resource_id}
    )
    assessment = _assessment_for_cross_parent_case(
        case,
        baselines=[case.baselines[0], duplicated_object],
    )

    assert assessment.comparison_coverage.observed_distinct_actors == 2
    assert assessment.comparison_coverage.distinct_controlled_objects == 1
    assert any(item.code == "MISSING_CONTROLLED_BASELINE" for item in assessment.blockers)


def test_baseline_object_must_match_its_runtime_subject() -> None:
    case = _cross_parent_case()
    inconsistent = case.baselines[1].model_copy(update={"requested_value": "RECORD_OTHER"})
    assessment = _assessment_for_cross_parent_case(
        case,
        baselines=[case.baselines[0], inconsistent],
    )

    assert assessment.comparison_coverage.baseline_actor_ids == ["ACCOUNT_A"]
    assert assessment.comparison_coverage.missing_actor_ids == ["ACCOUNT_B"]


@pytest.mark.parametrize(
    ("update", "missing_actor"),
    [
        ({"subject_resource_type": "Firewall"}, "ACCOUNT_B"),
        ({"parent_resource_type": "Account"}, "ACCOUNT_B"),
    ],
)
def test_cross_parent_type_mismatches_fail_closed(
    update: dict[str, str],
    missing_actor: str,
) -> None:
    case = _cross_parent_case()
    incompatible = case.baselines[1].model_copy(update=update)
    assessment = _assessment_for_cross_parent_case(
        case,
        baselines=[case.baselines[0], incompatible],
    )

    assert assessment.comparison_coverage.baseline_actor_ids == ["ACCOUNT_A"]
    assert assessment.comparison_coverage.missing_actor_ids == [missing_actor]
    assert any(item.code == "MISSING_CONTROLLED_BASELINE" for item in assessment.blockers)


def test_incompatible_collection_route_family_fails_closed() -> None:
    case = _cross_parent_case()
    endpoint_b, observation_b = _comparison_endpoint(
        "EP-DNS-B",
        parent="domain-b.test",
        object_value="RECORD_B",
        observation_id="OBS-B",
        collection="certificates",
    )
    baseline_b = _comparison_baseline(
        endpoint_b,
        actor="ACCOUNT_B",
        parent="domain-b.test",
        object_value="RECORD_B",
        observation_id="OBS-B",
    )
    assessment = _assessment_for_cross_parent_case(
        case,
        observations=ObservationStore(
            observations=[case.observations.observations[0], observation_b]
        ),
        endpoints=[case.endpoints[0], endpoint_b],
        baselines=[case.baselines[0], baseline_b],
    )

    assert assessment.comparison_coverage.baseline_actor_ids == ["ACCOUNT_A"]
    assert assessment.comparison_coverage.missing_actor_ids == ["ACCOUNT_B"]


@pytest.mark.parametrize("ambiguous", [False, True])
def test_missing_or_ambiguous_endpoint_provenance_fails_closed(ambiguous: bool) -> None:
    case = _cross_parent_case()
    baseline_b = case.baselines[1]
    endpoints = list(case.endpoints)
    if ambiguous:
        endpoints.append(case.endpoints[1].model_copy(deep=True))
    else:
        baseline_b = baseline_b.model_copy(update={"endpoint_id": "EP-MISSING"})
    assessment = _assessment_for_cross_parent_case(
        case,
        endpoints=endpoints,
        baselines=[case.baselines[0], baseline_b],
    )

    assert assessment.comparison_coverage.baseline_actor_ids == ["ACCOUNT_A"]
    assert assessment.comparison_coverage.missing_actor_ids == ["ACCOUNT_B"]


@pytest.mark.parametrize("ambiguous", [False, True])
def test_missing_or_ambiguous_runtime_provenance_fails_closed(ambiguous: bool) -> None:
    case = _cross_parent_case()
    baseline_b = case.baselines[1]
    observations = list(case.observations.observations)
    if ambiguous:
        observations.append(case.observations.observations[1].model_copy(deep=True))
    else:
        baseline_b = baseline_b.model_copy(update={"observations": []})
    assessment = _assessment_for_cross_parent_case(
        case,
        observations=ObservationStore(observations=observations),
        baselines=[case.baselines[0], baseline_b],
    )

    assert assessment.comparison_coverage.baseline_actor_ids == ["ACCOUNT_A"]
    assert assessment.comparison_coverage.missing_actor_ids == ["ACCOUNT_B"]


@pytest.mark.parametrize("mismatch", ["authentication", "service"])
def test_incompatible_authentication_or_service_provenance_fails_closed(
    mismatch: str,
) -> None:
    case = _cross_parent_case()
    endpoint_b, observation_b = _comparison_endpoint(
        "EP-DNS-B",
        parent="domain-b.test",
        object_value="RECORD_B",
        observation_id="OBS-B",
        host="api.other.test" if mismatch == "service" else "api.unified.test",
        authentication_type="cookie" if mismatch == "authentication" else "bearer",
    )
    baseline_b = _comparison_baseline(
        endpoint_b,
        actor="ACCOUNT_B",
        parent="domain-b.test",
        object_value="RECORD_B",
        observation_id="OBS-B",
    )
    assessment = _assessment_for_cross_parent_case(
        case,
        observations=ObservationStore(
            observations=[case.observations.observations[0], observation_b]
        ),
        endpoints=[case.endpoints[0], endpoint_b],
        baselines=[case.baselines[0], baseline_b],
    )

    assert assessment.comparison_coverage.baseline_actor_ids == ["ACCOUNT_A"]
    assert assessment.comparison_coverage.missing_actor_ids == ["ACCOUNT_B"]


def test_two_foreign_parent_baselines_without_target_parent_match_fail_closed() -> None:
    case = _cross_parent_case()
    endpoint_c, observation_c = _comparison_endpoint(
        "EP-DNS-C",
        parent="domain-c.test",
        object_value="RECORD_C",
        observation_id="OBS-C",
    )
    baseline_c = _comparison_baseline(
        endpoint_c,
        actor="ACCOUNT_A",
        parent="domain-c.test",
        object_value="RECORD_C",
        observation_id="OBS-C",
    )
    assessment = _assessment_for_cross_parent_case(
        case,
        observations=ObservationStore(
            observations=[*case.observations.observations, observation_c]
        ),
        endpoints=[*case.endpoints, endpoint_c],
        baselines=[case.baselines[1], baseline_c],
    )

    assert assessment.comparison_coverage.observed_distinct_actors == 0
    assert assessment.comparison_coverage.target_parent_baseline_reference is None
    assert "validated literal target parent" in assessment.comparison_coverage.explanation
    assert any(item.code == "MISSING_CONTROLLED_BASELINE" for item in assessment.blockers)


def test_cross_parent_coverage_preserves_subject_only_mutation(
    tmp_path: Path,
) -> None:
    case = _cross_parent_case()
    assessment = _assessment_for_cross_parent_case(case)
    workspace = create_workspace("cross-parent-plan", tmp_path / "workspaces")
    templates = build_execution_templates(
        workspace,
        case.target,
        case.record,
        [case.endpoints[0]],
        case.observations,
        assessment.constructability,
    )
    mutation = templates.requests[1].mutations[0]

    assert not any(item.code == "MISSING_CONTROLLED_BASELINE" for item in assessment.blockers)
    assert case.record.mutation_target.parameter == "dnsRecordId"
    assert case.record.mutation_target.location == "path"
    assert templates.requests[0].path.endswith("/domain-a.test/dns-records/RECORD_A")
    assert templates.requests[1].path.endswith("/domain-a.test/dns-records/RECORD_B")
    assert mutation.parameter == "dnsRecordId"
    assert mutation.substitution_scope == "SUBJECT_ONLY"
    assert mutation.source_parent_resource_id == "RSC-DOMAIN-A-TEST"
    assert mutation.target_parent_resource_id == "RSC-DOMAIN-B-TEST"


def test_public_and_in_memory_alignment_are_identical_and_read_only(
    tmp_path: Path,
) -> None:
    case = _cross_parent_case()
    assessment = _assessment_for_cross_parent_case(case)
    persisted = case.record.model_copy(
        update={
            "readiness": assessment.readiness,
            "readiness_assessment": assessment,
        }
    )
    workspace = create_workspace("cross-parent-alignment", tmp_path / "workspaces")
    write_yaml(workspace.target, case.target.model_dump(mode="json", exclude_none=True))
    write_yaml(
        workspace.observations,
        case.observations.model_dump(mode="json", exclude_none=True),
    )
    write_yaml(
        workspace.endpoints,
        EndpointStore(endpoints=list(case.endpoints)).model_dump(mode="json", exclude_none=True),
    )
    write_yaml(workspace.resources, ResourceStore().model_dump(mode="json", exclude_none=True))
    write_yaml(
        workspace.hypotheses,
        HypothesisStore(hypotheses=[persisted]).model_dump(mode="json", exclude_none=True),
    )
    before = {
        path.relative_to(workspace.root): path.read_bytes()
        for path in workspace.root.rglob("*")
        if path.is_file()
    }

    public = inspect_plan_alignment(workspace, persisted.id)
    in_memory = inspect_plan_alignment_from_inputs(
        case.target,
        case.observations,
        EndpointStore(endpoints=list(case.endpoints)),
        ResourceStore(),
        persisted,
    )
    after = {
        path.relative_to(workspace.root): path.read_bytes()
        for path in workspace.root.rglob("*")
        if path.is_file()
    }

    assert public.readiness.model_dump(mode="json") == in_memory.readiness.model_dump(mode="json")
    assert public.plan_status == in_memory.plan_status
    assert public.agrees == in_memory.agrees
    assert public.violation == in_memory.violation
    assert public.plan_status == "READY_FOR_REVIEW"
    assert public.agrees is True
    assert after == before


def test_valid_cross_parent_coverage_removes_only_baseline_blocker() -> None:
    case = _cross_parent_case(
        method="DELETE",
        maximum_requests_per_plan=3,
        synthetic=False,
        local_lab=False,
    )
    oracle, oracle_observation = _comparison_endpoint(
        "EP-DNS-ORACLE",
        parent="domain-a.test",
        object_value="RECORD_A",
        observation_id="OBS-ORACLE",
    )
    observations = ObservationStore(
        observations=[*case.observations.observations, oracle_observation]
    )
    endpoints = [*case.endpoints, oracle]
    assessment = _assessment_for_cross_parent_case(
        case,
        observations=observations,
        endpoints=endpoints,
    )
    blocker_codes = {item.code for item in assessment.blockers}
    warning_codes = {item.code for item in assessment.warnings}
    persisted = case.record.model_copy(
        update={
            "readiness": assessment.readiness,
            "readiness_assessment": assessment,
        }
    )
    alignment = inspect_plan_alignment_from_inputs(
        case.target,
        observations,
        EndpointStore(endpoints=endpoints),
        ResourceStore(),
        persisted,
    )

    assert "MISSING_CONTROLLED_BASELINE" not in blocker_codes
    assert "UNSUPPORTED_EXECUTION_TEMPLATE" in blocker_codes
    assert "MISSING_CLEANUP" in blocker_codes
    assert "STALE_EXECUTION_BASELINE" in blocker_codes
    assert "MISSING_BUDGET" not in blocker_codes
    assert {
        "HUMAN_APPROVAL_REQUIRED",
        "ACTIVE_EXECUTION_DISABLED",
        "READ_ONLY_RUNNER_UNSUPPORTED",
    }.issubset(warning_codes)
    assert case.target.testing.maximum_requests_per_plan == 3
    assert case.target.testing.active_execution_enabled is False
    assert case.target.testing.human_approval_required is True
    assert alignment.plan_status == "BLOCKED"
    assert alignment.agrees is True
    assert (
        alignment.readiness.constructability.blocker_code
        == "UNSUPPORTED_EXECUTION_TEMPLATE"
    )


def test_historical_ownership_baseline_does_not_satisfy_execution_liveness() -> None:
    case = _cross_parent_case()
    historical = [
        item.model_copy(update={"liveness": ControlledObjectLiveness.HISTORICAL_ONLY})
        for item in case.baselines
    ]

    assessment = _assessment_for_cross_parent_case(case, baselines=historical)

    assert assessment.comparison_coverage.observed_distinct_actors == 2
    assert not any(item.code == "MISSING_CONTROLLED_BASELINE" for item in assessment.blockers)
    assert any(item.code == "STALE_EXECUTION_BASELINE" for item in assessment.blockers)
    assert assessment.constructability.supported is False


def test_unknown_liveness_never_silently_becomes_live() -> None:
    case = _cross_parent_case()
    unknown = [
        item.model_copy(
            update={
                "liveness": ControlledObjectLiveness.UNKNOWN,
                "liveness_evidence": [],
            }
        )
        for item in case.baselines
    ]

    assessment = _assessment_for_cross_parent_case(case, baselines=unknown)

    assert assessment.comparison_coverage.observed_distinct_actors == 2
    assert any(item.code == "MISSING_LIVE_CONTROLLED_OBJECT" for item in assessment.blockers)
    assert assessment.constructability.supported is False


def test_authoritative_live_evidence_restores_execution_binding_without_erasing_history() -> None:
    case = _cross_parent_case()
    restored = [
        item.model_copy(
            update={
                "liveness": ControlledObjectLiveness.LIVE,
                "liveness_evidence": [*item.liveness_evidence, f"LIVE-{item.actor}"],
            }
        )
        for item in case.baselines
    ]

    assessment = _assessment_for_cross_parent_case(case, baselines=restored)

    assert assessment.constructability.supported is True
    assert all(
        any(reference.startswith("BASE-") for reference in item.evidence_references)
        for item in assessment.constructability.baselines
    )
    assert all(
        any(reference.startswith("LIVE-") for reference in item.evidence_references)
        for item in assessment.constructability.baselines
    )


@pytest.mark.parametrize("token", ["requests", "return", "change", "delete", "update"])
def test_safe_method_route_vocabulary_does_not_create_mutation(token: str) -> None:
    action, state_change, reasons = _action(f"/api/{token}/{{objectId}}", "GET")

    assert action.type == "read"
    assert action.name == "read"
    assert state_change is False
    assert "safe HTTP method" in " ".join(reasons)


def test_explicit_safe_method_state_delta_can_override_and_explain_default() -> None:
    evidence = SideEffectEvidence(
        kind="CORRELATED_STATE_DELTA",
        action="refresh",
        references=["OBS-BEFORE", "OBS-AFTER"],
        reason="A correlated authoritative state field changed after the request.",
    )

    action, state_change, reasons = _action(
        "/api/cache/update",
        "GET",
        side_effect_evidence=[evidence],
    )

    assert action.type == "mutation"
    assert action.name == "refresh"
    assert state_change is True
    assert "correlated state delta" in " ".join(reasons)


def test_controllable_identifier_without_binding_is_not_owner_scoped_or_ready() -> None:
    endpoint = _endpoint("EP-1")
    record = _record("HYP-001", endpoint)
    observations = ObservationStore(
        observations=[_observation("OBS-1", method=endpoint.method, path=endpoint.path)]
    )
    intent = assess_domain_intent(
        _target(),
        [endpoint],
        category=record.category,
        generation_rule_id=record.generation_rule["id"],
    )
    claim = assess_claim_strength(
        generation_rule_id=record.generation_rule["id"],
        category=record.category,
        intent=intent,
        eligibility_evidence=[],
    )
    assessment = assess_record_readiness(
        _target(), observations, [endpoint], ResourceStore(), record, intent, claim
    )

    assert intent.visibility == "UNKNOWN"
    assert intent.binding == "UNKNOWN"
    assert assessment.readiness == "REVIEW_REQUIRED"
    assert any(item.capability == CapabilityKind.OWNERSHIP for item in assessment.blockers)


def test_comparison_coverage_counts_actors_not_objects() -> None:
    endpoint = _endpoint("EP-1")
    baselines = [
        _typed_baseline(endpoint, actor="ACCOUNT_1", object_id="order-a"),
        _typed_baseline(endpoint, actor="ACCOUNT_1", object_id="order-b"),
    ]

    assessment = _authorization_assessment(endpoint, baselines)

    assert assessment.comparison_coverage.observed_distinct_actors == 1
    assert assessment.comparison_coverage.distinct_controlled_objects == 2
    assert assessment.comparison_coverage.missing_actor_ids == ["ACCOUNT_2"]
    assert any(item.capability == CapabilityKind.BASELINE for item in assessment.blockers)


@pytest.mark.parametrize(
    ("resource_type", "collection_route_family", "parent_resource_type"),
    [
        ("Firewall", None, "Domain"),
        ("DnsRecord", "/v1/firewalls", "Domain"),
        ("DnsRecord", None, "Account"),
    ],
)
def test_incompatible_baseline_provenance_does_not_satisfy_dns_readiness(
    resource_type: str,
    collection_route_family: str | None,
    parent_resource_type: str,
) -> None:
    endpoint = _endpoint(
        "EP-DNS",
        path="/cdn/4.0/domains/example-a.test/dns-records/{dnsRecordId}",
        resource="DnsRecord",
        observations=("OBS-1", "OBS-2"),
    )
    valid = _typed_baseline(
        endpoint,
        actor="ACCOUNT_1",
        object_id="record-a",
        observation_id="OBS-1",
    )
    incompatible = _typed_baseline(
        endpoint,
        actor="ACCOUNT_2",
        object_id="record-b",
        subject_resource_type=resource_type,
        collection_route_family=collection_route_family,
        parent_resource_type=parent_resource_type,
        observation_id="OBS-2",
    )

    assessment = _authorization_assessment(endpoint, [valid, incompatible])

    assert assessment.comparison_coverage.observed_distinct_actors == 1
    assert assessment.comparison_coverage.baseline_actor_ids == ["ACCOUNT_1"]
    assert assessment.comparison_coverage.missing_actor_ids == ["ACCOUNT_2"]


def test_matching_typed_provenance_satisfies_two_actor_comparison_coverage() -> None:
    endpoint = _endpoint(
        "EP-DNS",
        path="/cdn/4.0/domains/example-a.test/dns-records/{dnsRecordId}",
        resource="DnsRecord",
        observations=("OBS-1", "OBS-2"),
    )
    baselines = [
        _typed_baseline(
            endpoint,
            actor="ACCOUNT_1",
            object_id="record-a",
            observation_id="OBS-1",
        ),
        _typed_baseline(
            endpoint,
            actor="ACCOUNT_2",
            object_id="record-b",
            observation_id="OBS-2",
        ),
    ]

    assessment = _authorization_assessment(endpoint, baselines)

    assert assessment.comparison_coverage.observed_distinct_actors == 2
    assert assessment.comparison_coverage.distinct_controlled_objects == 2
    assert assessment.comparison_coverage.missing_actor_ids == []
    baseline = next(
        item for item in assessment.capabilities if item.capability == CapabilityKind.BASELINE
    )
    assert baseline.satisfied is True


def test_legacy_baseline_from_another_controlled_parent_fails_closed() -> None:
    endpoint = _endpoint(
        "EP-DNS-A",
        path="/cdn/4.0/domains/example-a.test/dns-records/{dnsRecordId}",
        resource="DnsRecord",
    )
    provenance_endpoint = _endpoint(
        "EP-DNS-B",
        path="/cdn/4.0/domains/example-b.test/dns-records/{dnsRecordId}",
        resource="DnsRecord",
        observations=("OBS-2",),
    )
    legacy_baseline = ActorObjectBaseline(
        actor="ACCOUNT_1",
        requested_value="record-a",
        endpoint_id=provenance_endpoint.id,
        observations=[provenance_endpoint.sources[0]],
    )

    assessment = _authorization_assessment(
        endpoint,
        [legacy_baseline],
        provenance_endpoints=[provenance_endpoint],
    )

    assert assessment.comparison_coverage.observed_distinct_actors == 0
    assert assessment.comparison_coverage.baseline_actor_ids == []
    assert assessment.comparison_coverage.missing_actor_ids == ["ACCOUNT_1", "ACCOUNT_2"]


def test_baseline_parent_value_must_match_its_provenance_endpoint() -> None:
    endpoint = _endpoint(
        "EP-DNS-A",
        path="/cdn/4.0/domains/example-a.test/dns-records/{dnsRecordId}",
        resource="DnsRecord",
    )
    provenance_endpoint = _endpoint(
        "EP-DNS-B",
        path="/cdn/4.0/domains/example-b.test/dns-records/{dnsRecordId}",
        resource="DnsRecord",
        observations=("OBS-2",),
    )
    valid = _typed_baseline(endpoint, actor="ACCOUNT_1", object_id="record-a")
    inconsistent_parent = _typed_baseline(
        provenance_endpoint,
        actor="ACCOUNT_2",
        object_id="record-b",
        parent_value="example-c.test",
    )

    assessment = _authorization_assessment(
        endpoint,
        [valid, inconsistent_parent],
        provenance_endpoints=[provenance_endpoint],
    )

    assert assessment.comparison_coverage.baseline_actor_ids == ["ACCOUNT_1"]
    assert assessment.comparison_coverage.missing_actor_ids == ["ACCOUNT_2"]


def test_corroborating_relationships_remain_one_canonical_baseline() -> None:
    endpoint = _endpoint("EP-1", observations=("OBS-1", "OBS-2"))
    first = _typed_baseline(endpoint, actor="ACCOUNT_1", object_id="order-a").model_copy(
        update={"relationship_ids": ["REL-A", "REL-B"]}
    )
    corroborating = first.model_copy(
        update={
            "baseline_id": "BASE-ACCOUNT_1-order-a-corroborating",
            "relationship_ids": ["REL-C"],
        }
    )
    second = _typed_baseline(
        endpoint,
        actor="ACCOUNT_2",
        object_id="order-b",
        observation_id="OBS-2",
    ).model_copy(update={"relationship_ids": ["REL-D"]})

    assessment = _authorization_assessment(endpoint, [first, corroborating, second])
    account_one = next(
        item for item in assessment.comparison_coverage.baselines if item.actor_id == "ACCOUNT_1"
    )

    assert assessment.comparison_coverage.observed_distinct_actors == 2
    assert assessment.comparison_coverage.distinct_controlled_objects == 2
    assert len(assessment.comparison_coverage.baselines) == 2
    assert account_one.baseline_ids == [
        "BASE-ACCOUNT_1-order-a",
        "BASE-ACCOUNT_1-order-a-corroborating",
    ]
    assert account_one.supporting_relationship_ids == ["REL-A", "REL-B", "REL-C"]


def test_legacy_baseline_requires_exact_source_endpoint() -> None:
    endpoint = _endpoint("EP-1")
    exact = ActorObjectBaseline(
        actor="ACCOUNT_1",
        requested_value="order-a",
        endpoint_id=endpoint.id,
        observations=[endpoint.sources[0]],
    )
    unrelated = ActorObjectBaseline(
        actor="ACCOUNT_2",
        requested_value="order-b",
        endpoint_id="EP-OTHER",
        observations=["OBS-OTHER"],
    )

    assessment = _authorization_assessment(endpoint, [exact, unrelated])

    assert assessment.comparison_coverage.baseline_actor_ids == ["ACCOUNT_1"]
    assert assessment.comparison_coverage.missing_actor_ids == ["ACCOUNT_2"]


def test_authentication_alone_does_not_satisfy_actor_switch_binding() -> None:
    endpoint = _endpoint("EP-1", method="POST", action="comment", state_change=True)
    record = _record(
        "BLH-AAAAAAAAAAAAAAAA",
        endpoint,
        category="business_logic",
        rule="BUSINESS_LOGIC_ACTOR_SWITCH",
        mutation_dimensions=["WORKFLOW", "ACTOR"],
        logic_details={
            "family": "ACTOR_SWITCH",
            "controlled_actors_required": 2,
            "qualification": {"evidence": {"ownership_known": False}},
        },
    )
    observations = ObservationStore(
        observations=[_observation("OBS-1", method=endpoint.method, path=endpoint.path)]
    )
    intent = assess_domain_intent(
        _target(),
        [endpoint],
        category=record.category,
        generation_rule_id=record.generation_rule["id"],
        logic_details=record.logic_details,
    )
    claim = assess_claim_strength(
        generation_rule_id=record.generation_rule["id"],
        category=record.category,
        intent=intent,
        eligibility_evidence=[],
    )
    assessment = assess_record_readiness(
        _target(), observations, [endpoint], ResourceStore(), record, intent, claim
    )

    assert endpoint.authentication.required is True
    assert intent.binding == "UNKNOWN"
    assert any(item.capability == CapabilityKind.OWNERSHIP for item in assessment.blockers)


def test_create_child_resolves_child_subject_and_avoids_parent_modification_title() -> None:
    endpoint = _endpoint(
        "EP-1",
        method="POST",
        path="/api/posts/{postId}/comments",
        resource="Post",
        action="comment",
        state_change=True,
        child_response="$.comments[*].id",
    )
    record = _record("HYP-001", endpoint)
    store = finalize_hypothesis_store(
        _target(),
        ObservationStore(
            observations=[_observation("OBS-1", method=endpoint.method, path=endpoint.path)]
        ),
        EndpointStore(endpoints=[endpoint]),
        ResourceStore(),
        HypothesisStore(hypotheses=[record]),
    )
    result = store.hypotheses[0]

    assert result.domain_intent.operation == "CREATE_CHILD"
    assert result.domain_intent.subject_resource == "Comment"
    assert result.domain_intent.parent_resource == "Post"
    assert "Comment creation under Post" in result.title
    assert "Post modification" not in result.title


def test_unsigned_jwt_verifier_claim_upgrades_only_with_downstream_identity_evidence() -> None:
    endpoint = _endpoint(
        "EP-1",
        method="POST",
        path="/identity/api/auth/verify",
        resource="Credential",
        action="verify",
        state_change=False,
    )
    baseline = _record(
        "HYP-001",
        endpoint,
        category="authentication",
        rule="JWT_ALGORITHM_VALIDATION",
        mutation_dimensions=["VALUE"],
    )
    upgraded = baseline.model_copy(
        update={
            "id": "HYP-002",
            "key": "key:HYP-002",
            "eligibility_evidence": ["The altered token established an authenticated identity."],
        }
    )
    store = finalize_hypothesis_store(
        _target(accounts=1),
        ObservationStore(
            observations=[_observation("OBS-1", method=endpoint.method, path=endpoint.path)]
        ),
        EndpointStore(endpoints=[endpoint]),
        ResourceStore(),
        HypothesisStore(hypotheses=[baseline, upgraded]),
    )
    by_id = {item.id: item for item in store.hypotheses}

    assert by_id["HYP-001"].claim_strength.target_level == ClaimStrengthLevel.VALIDATOR_ACCEPTED
    assert "verifier" in by_id["HYP-001"].title.lower()
    assert "authentication bypass" not in by_id["HYP-001"].title.lower()
    assert by_id["HYP-002"].claim_strength.current_level == (
        ClaimStrengthLevel.IDENTITY_OR_SESSION_ESTABLISHED
    )
    assert "bypass authentication" in by_id["HYP-002"].title.lower()


@pytest.mark.parametrize("visibility", ["PUBLIC", "SHARED"])
def test_reviewed_public_and_shared_intents_remain_distinct_research_questions(
    visibility: str,
) -> None:
    endpoint = _endpoint("EP-1")
    target = _target(
        domain_intent_rules=[
            {
                "method": endpoint.method,
                "path": endpoint.path,
                "subject_resource": "Order",
                "operation": "READ",
                "visibility": visibility,
                "binding": "UNKNOWN",
                "rationale": "Reviewed product policy permits this visibility.",
                "evidence_refs": ["POLICY-1"],
            }
        ]
    )
    store = finalize_hypothesis_store(
        target,
        ObservationStore(
            observations=[_observation("OBS-1", method=endpoint.method, path=endpoint.path)]
        ),
        EndpointStore(endpoints=[endpoint]),
        ResourceStore(),
        HypothesisStore(hypotheses=[_record("HYP-001", endpoint)]),
    )
    result = store.hypotheses[0]

    assert result.domain_intent.visibility == visibility
    assert result.kind == "RESEARCH_TASK"
    assert result.readiness == "RESEARCH_ONLY"
    assert result.title.startswith(f"Validate {visibility.lower()}")


def test_state_change_requires_strategy_but_not_a_future_after_snapshot() -> None:
    mutation = _endpoint(
        "EP-1",
        method="POST",
        path="/api/orders",
        resource="Order",
        action="create",
        state_change=True,
        observations=("OBS-1",),
    )
    oracle = _endpoint(
        "EP-2",
        method="GET",
        path="/api/orders/{orderId}",
        resource="Order",
        observations=("OBS-2",),
    )
    record = _record(
        "HYP-001",
        mutation,
        category="value_validation",
        rule="VALUE_VALIDATION",
        mutation_dimensions=["VALUE"],
    )
    observations = ObservationStore(
        observations=[
            _observation("OBS-1", method=mutation.method, path=mutation.path),
            _observation("OBS-2", method=oracle.method, path=oracle.path),
        ]
    )
    intent = assess_domain_intent(
        _target(accounts=1),
        [mutation],
        category=record.category,
        generation_rule_id=record.generation_rule["id"],
    )
    claim = assess_claim_strength(
        generation_rule_id=record.generation_rule["id"],
        category=record.category,
        intent=intent,
        eligibility_evidence=[],
    )
    ready = assess_record_readiness(
        _target(accounts=1),
        observations,
        [mutation, oracle],
        ResourceStore(),
        record,
        intent,
        claim,
    )
    missing_strategy = assess_record_readiness(
        _target(accounts=1),
        observations,
        [mutation, oracle],
        ResourceStore(),
        record.model_copy(update={"evidence_to_collect": ["Retain the response."]}),
        intent,
        claim,
    )

    assert ready.readiness == "REVIEW_REQUIRED"
    assert ready.actionable_plan is False
    assert ready.constructability.blocker_code == "UNSUPPORTED_EXECUTION_TEMPLATE"
    assert any(item.code == "UNSUPPORTED_EXECUTION_TEMPLATE" for item in ready.blockers)
    assert missing_strategy.readiness == "REVIEW_REQUIRED"
    assert {item.capability for item in missing_strategy.blockers}.issuperset(
        {CapabilityKind.BASELINE, CapabilityKind.ORACLE}
    )


def test_typed_cleanup_control_matches_canonical_family_and_stales_on_source_change() -> None:
    mutation = _endpoint(
        "EP-1",
        method="DELETE",
        path="/cdn/4.0/domains/example.test/dns-records/{dnsRecordId}",
        resource="DnsRecord",
        action="delete",
        state_change=True,
        observations=("OBS-1",),
    )
    oracle = _endpoint(
        "EP-2",
        method="GET",
        path="/cdn/4.0/domains/example.test/dns-records/{dnsRecordId}",
        resource="DnsRecord",
        observations=("OBS-2",),
    )
    controlled_baseline = _typed_baseline(
        mutation,
        actor="ACCOUNT_1",
        object_id="CONTROLLED",
    )
    mutation = mutation.model_copy(
        update={
            "object_access": [
                ObjectAccessEvidence(
                    identifier=mutation.parameters[0].name,
                    parameter_location="path",
                    source="CONTROLLED_LIFECYCLE",
                    baselines=[controlled_baseline],
                    distinct_actors=1,
                    distinct_objects=1,
                    actor_object_binding_observed=True,
                )
            ]
        }
    )
    record = _record(
        "HYP-001",
        mutation,
        category="value_validation",
        rule="VALUE_VALIDATION",
        mutation_dimensions=["VALUE"],
    )
    observations = ObservationStore(
        observations=[
            _observation("OBS-1", method=mutation.method, path=mutation.path),
            _observation("OBS-2", method=oracle.method, path=oracle.path),
        ]
    )
    target = _target(accounts=1).model_copy(
        update={
            "testing": _target(accounts=1).testing.model_copy(
                update={
                    "synthetic": False,
                    "local_lab": False,
                    "maximum_requests_per_plan": 3,
                }
            )
        }
    )
    intent = assess_domain_intent(
        target,
        [mutation],
        category=record.category,
        generation_rule_id=record.generation_rule["id"],
    )
    claim = assess_claim_strength(
        generation_rule_id=record.generation_rule["id"],
        category=record.category,
        intent=intent,
        eligibility_evidence=[],
    )
    missing = assess_record_readiness(
        target,
        observations,
        [mutation, oracle],
        ResourceStore(),
        record,
        intent,
        claim,
    )
    cleanup = next(
        item for item in missing.capabilities if item.capability == CapabilityKind.CLEANUP
    )
    budget = next(item for item in missing.capabilities if item.capability == CapabilityKind.BUDGET)
    assert cleanup.satisfied is False
    assert budget.required is False
    assert budget.satisfied is True
    assert budget.missing == []
    assert missing.constructability.blocker_code == "UNSUPPORTED_EXECUTION_TEMPLATE"
    hierarchy = path_hierarchy(mutation.path, mutation.path, intent.subject_resource)
    fingerprint = cleanup_control_fingerprint(record, intent, record.mutation_target, [mutation])
    checksum = cleanup_control_source_checksum(
        target,
        observations,
        record,
        intent,
        record.mutation_target,
        [mutation],
    )
    control = CleanupControlRule(
        semantic_fingerprint=fingerprint,
        strategy="MANUAL_CONTROLLED_RESTORE",
        actor_ids=["ACCOUNT_1"],
        resource_type=intent.subject_resource,
        route_family=hierarchy.collection_route_family,
        parent_resource_type=intent.parent_resource,
        resource_refs=["RSC-CONTROLLED"],
        oracle_refs=[oracle.id],
        source_checksum=checksum,
        rationale="Restore the controlled record and verify it through the safe read oracle.",
    )
    configured = target.model_copy(
        update={"analysis": target.analysis.model_copy(update={"cleanup_controls": [control]})}
    )

    matched = assess_record_readiness(
        configured,
        observations,
        [mutation, oracle],
        ResourceStore(),
        record,
        intent,
        claim,
    )
    matched_cleanup = next(
        item for item in matched.capabilities if item.capability == CapabilityKind.CLEANUP
    )
    matched_budget = next(
        item for item in matched.capabilities if item.capability == CapabilityKind.BUDGET
    )
    assert matched_cleanup.satisfied is True
    assert matched_budget.required is False
    assert matched_budget.satisfied is True
    assert {item.reference for item in matched_cleanup.evidence}.issuperset(
        {fingerprint, "RSC-CONTROLLED", oracle.id}
    )
    assert configured.testing.maximum_requests_per_plan == 3
    assert configured.testing.active_execution_enabled is False
    assert configured.testing.human_approval_required is True

    changed_observations = observations.model_copy(
        update={
            "observations": [
                *observations.observations,
                _observation("OBS-3", method=mutation.method, path=mutation.path),
            ]
        }
    )
    stale = assess_record_readiness(
        configured,
        changed_observations,
        [mutation, oracle],
        ResourceStore(),
        record.model_copy(update={"observations": ["OBS-1", "OBS-3"]}),
        intent,
        claim,
    )
    stale_cleanup = next(
        item for item in stale.capabilities if item.capability == CapabilityKind.CLEANUP
    )
    assert stale_cleanup.satisfied is False


@dataclass(frozen=True)
class _CleanupCase:
    target: TargetDocument
    observations: ObservationStore
    endpoints: list[Endpoint]
    record: HypothesisRecord
    intent: DomainIntentAssessment
    claim: ClaimStrengthAssessment


def _cleanup_case(
    *,
    resource_ref: str = "RSC-CONTROLLED",
    oracle_ref: str = "EP-ORACLE",
    oracle_method: str = "GET",
    oracle_state_change: bool = False,
    oracle_source: str = "HAR",
    baseline_actor: str = "ACCOUNT_1",
    control_actor_ids: tuple[str, ...] = ("ACCOUNT_1",),
    resource_path: str | None = None,
    oracle_path: str | None = None,
) -> _CleanupCase:
    mutation = _endpoint(
        "EP-MUTATION",
        method="DELETE",
        path="/cdn/4.0/domains/example.test/dns-records/{dnsRecordId}",
        resource="DnsRecord",
        action="delete",
        state_change=True,
        observations=("OBS-MUTATION",),
    )
    oracle = _endpoint(
        "EP-ORACLE",
        method=oracle_method,
        path=(oracle_path or "/cdn/4.0/domains/example.test/dns-records/{dnsRecordId}"),
        resource="DnsRecord",
        state_change=oracle_state_change,
        observations=("OBS-ORACLE",),
    )
    resource_endpoint = mutation
    extra_endpoints: list[Endpoint] = []
    if resource_path is not None:
        resource_endpoint = _endpoint(
            "EP-RESOURCE",
            path=resource_path,
            resource="DnsRecord",
            observations=("OBS-RESOURCE",),
        )
        extra_endpoints.append(resource_endpoint)
    controlled_baseline = _typed_baseline(
        resource_endpoint,
        actor=baseline_actor,
        object_id="CONTROLLED",
    )
    mutation = mutation.model_copy(
        update={
            "object_access": [
                ObjectAccessEvidence(
                    identifier=mutation.parameters[0].name,
                    parameter_location="path",
                    source="CONTROLLED_LIFECYCLE",
                    baselines=[controlled_baseline],
                    distinct_actors=1,
                    distinct_objects=1,
                    actor_object_binding_observed=True,
                )
            ]
        }
    )
    observations = ObservationStore(
        observations=[
            _observation(
                "OBS-MUTATION",
                method=mutation.method,
                path=mutation.path,
            ),
            _observation("OBS-ORACLE", method=oracle.method, path=oracle.path).model_copy(
                update={"source": oracle_source}
            ),
            *(
                [
                    _observation(
                        "OBS-RESOURCE",
                        method=resource_endpoint.method,
                        path=resource_endpoint.path,
                        actor=baseline_actor,
                    )
                ]
                if extra_endpoints
                else []
            ),
        ]
    )
    target = _target(accounts=2).model_copy(
        update={
            "testing": _target(accounts=2).testing.model_copy(
                update={"synthetic": False, "local_lab": False}
            )
        }
    )
    record = _record(
        "HYP-CLEANUP",
        mutation,
        category="value_validation",
        rule="VALUE_VALIDATION",
        mutation_dimensions=["VALUE"],
    )
    intent = assess_domain_intent(
        target,
        [mutation],
        category=record.category,
        generation_rule_id=record.generation_rule["id"],
    )
    claim = assess_claim_strength(
        generation_rule_id=record.generation_rule["id"],
        category=record.category,
        intent=intent,
        eligibility_evidence=[],
    )
    hierarchy = path_hierarchy(mutation.path, mutation.path, intent.subject_resource)
    control = CleanupControlRule(
        semantic_fingerprint=cleanup_control_fingerprint(
            record, intent, record.mutation_target, [mutation]
        ),
        strategy="MANUAL_CONTROLLED_RESTORE",
        actor_ids=list(control_actor_ids),
        resource_type=intent.subject_resource,
        route_family=hierarchy.collection_route_family,
        parent_resource_type=intent.parent_resource,
        resource_refs=[resource_ref],
        oracle_refs=[oracle_ref],
        source_checksum=cleanup_control_source_checksum(
            target,
            observations,
            record,
            intent,
            record.mutation_target,
            [mutation],
        ),
        rationale="Restore the controlled object and verify it through the safe runtime oracle.",
    )
    configured = target.model_copy(
        update={"analysis": target.analysis.model_copy(update={"cleanup_controls": [control]})}
    )
    return _CleanupCase(
        configured,
        observations,
        [mutation, oracle, *extra_endpoints],
        record,
        intent,
        claim,
    )


def _cleanup_assessment(case: _CleanupCase) -> HypothesisReadinessAssessment:
    return assess_record_readiness(
        case.target,
        case.observations,
        case.endpoints,
        ResourceStore(),
        case.record,
        case.intent,
        case.claim,
    )


@pytest.mark.parametrize(
    ("options", "expected"),
    [
        ({"resource_ref": "ARBITRARY"}, "resource reference does not resolve"),
        ({"oracle_ref": "EP-UNKNOWN"}, "oracle reference does not resolve"),
        ({"oracle_state_change": True}, "oracle endpoint is state-changing"),
        ({"oracle_source": "OPENAPI"}, "oracle lacks runtime provenance"),
        (
            {"baseline_actor": "ACCOUNT_2", "control_actor_ids": ("ACCOUNT_1",)},
            "resource is not controlled by the configured actor",
        ),
        (
            {"resource_path": ("/cdn/4.0/domains/other.test/dns-records/{dnsRecordId}")},
            "resource belongs to another parent context",
        ),
        (
            {"resource_path": ("/cdn/4.0/domains/example.test/certificates/{dnsRecordId}")},
            "resource belongs to another route family",
        ),
        (
            {"oracle_path": "/cdn/4.0/domains/other.test/dns-records/{dnsRecordId}"},
            "oracle belongs to another route or parent context",
        ),
        (
            {"oracle_path": "/cdn/4.0/domains/example.test/certificates/{dnsRecordId}"},
            "oracle belongs to another route or parent context",
        ),
    ],
)
def test_cleanup_references_fail_closed_with_specific_causes(
    options: dict[str, object],
    expected: str,
) -> None:
    assessment = _cleanup_assessment(_cleanup_case(**options))  # type: ignore[arg-type]
    cleanup = next(
        item for item in assessment.capabilities if item.capability == CapabilityKind.CLEANUP
    )
    blocker = next(
        item for item in assessment.blockers if item.capability == CapabilityKind.CLEANUP
    )

    assert cleanup.satisfied is False
    assert any(expected in item for item in cleanup.missing)
    assert blocker.code == "MISSING_CLEANUP"
    assert blocker.stage == BlockerStage.PLAN_CONSTRUCTABILITY


def test_cleanup_references_resolve_only_with_controlled_resource_and_runtime_oracle() -> None:
    assessment = _cleanup_assessment(_cleanup_case())
    cleanup = next(
        item for item in assessment.capabilities if item.capability == CapabilityKind.CLEANUP
    )

    assert cleanup.satisfied is True
    assert {item.reference for item in cleanup.evidence}.issuperset({"RSC-CONTROLLED", "EP-ORACLE"})


def test_canonical_readiness_records_align_with_planner(
    phase4_workspace: WorkspacePaths,
) -> None:
    generated = [
        item
        for item in load_hypotheses(phase4_workspace).hypotheses
        if item.kind == "SECURITY_HYPOTHESIS" and item.disposition == "ACTIVE"
    ]
    assert generated
    assert all(
        item.readiness_assessment.evaluator == "unified-hypothesis-readiness-v1"
        for item in generated
    )
    for item in generated:
        alignment = inspect_plan_alignment(phase4_workspace, item.id)
        assert alignment.agrees is True
        assert alignment.plan_status == (
            "READY_FOR_REVIEW" if item.readiness == "TEST_READY" else "BLOCKED"
        )


def test_cross_generator_exact_duplicates_are_order_independent_and_keep_provenance() -> None:
    endpoint = _endpoint(
        "EP-1",
        observations=("OBS-1", "OBS-2"),
        ownership_known=True,
    )
    observations = ObservationStore(
        observations=[
            _observation("OBS-1", method=endpoint.method, path=endpoint.path, actor="ACCOUNT_1"),
            _observation("OBS-2", method=endpoint.method, path=endpoint.path, actor="ACCOUNT_2"),
        ]
    )
    hyp = _record("HYP-001", endpoint, generation="phase3-hypothesis-generator")
    blh = _record("BLH-BBBBBBBBBBBBBBBB", endpoint, generation="business-logic-analysis")

    first = finalize_hypothesis_store(
        _target(),
        observations,
        EndpointStore(endpoints=[endpoint]),
        ResourceStore(),
        HypothesisStore(hypotheses=[hyp, blh]),
    )
    second = finalize_hypothesis_store(
        _target(),
        observations,
        EndpointStore(endpoints=[endpoint]),
        ResourceStore(),
        HypothesisStore(hypotheses=[blh, hyp]),
    )

    assert first.model_dump(mode="json") == second.model_dump(mode="json")
    assert sum(presentation_visible(item) for item in first.hypotheses) == 1
    assert {item.grouping.relationship for item in first.hypotheses} == {"EXACT_DUPLICATE"}
    assert all(
        item.grouping.cluster_member_ids == ["BLH-BBBBBBBBBBBBBBBB", "HYP-001"]
        for item in first.hypotheses
    )
    assert first.hypotheses[0].grouping.member_generators == [
        "business-logic-analysis",
        "phase3-hypothesis-generator",
    ]
    assert all(
        item.readiness_assessment.evaluator == "unified-hypothesis-readiness-v1"
        for item in first.hypotheses
    )


def test_replay_duplicate_and_concurrency_share_campaign_but_remain_distinct() -> None:
    endpoint = _endpoint(
        "EP-1",
        method="POST",
        path="/api/orders/{orderId}/return",
        action="return",
        state_change=True,
    )
    records = [
        _record(
            identifier,
            endpoint,
            category="business_logic",
            rule=f"BUSINESS_LOGIC_{family}",
            mutation_dimensions=[
                "WORKFLOW",
                *(["TIME", "CONCURRENCY"] if family == "CONCURRENT_EXECUTION" else []),
            ],
            logic_details={"family": family, "estimated_request_budget": 5},
        )
        for identifier, family in (
            ("BLH-1111111111111111", "REPLAY"),
            ("BLH-2222222222222222", "DUPLICATE_ACTION"),
            ("BLH-3333333333333333", "CONCURRENT_EXECUTION"),
        )
    ]
    store = finalize_hypothesis_store(
        _target(),
        ObservationStore(
            observations=[_observation("OBS-1", method=endpoint.method, path=endpoint.path)]
        ),
        EndpointStore(endpoints=[endpoint]),
        ResourceStore(),
        HypothesisStore(hypotheses=records),
    )

    assert len(store.campaigns) == 1
    campaign = store.campaigns[0]
    assert campaign.relationship == "OVERLAPPING_TEST_CAMPAIGN"
    assert campaign.member_ids == [
        "BLH-1111111111111111",
        "BLH-2222222222222222",
        "BLH-3333333333333333",
    ]
    assert len({item.grouping.cluster_id for item in store.hypotheses}) == 3
    assert all(presentation_visible(item) for item in store.hypotheses)


def test_campaign_cluster_ids_are_unique_when_one_member_cluster_has_duplicates() -> None:
    endpoint = _endpoint(
        "EP-1",
        method="POST",
        path="/api/orders",
        resource="Order",
        action="create",
        state_change=True,
    )
    records = [
        _record(
            "HYP-001",
            endpoint,
            category="value_validation",
            rule="VALUE_VALIDATION",
            mutation_dimensions=["VALUE"],
            generation="phase3-hypothesis-generator",
        ),
        *[
            _record(
                identifier,
                endpoint,
                category="business_logic",
                rule="BUSINESS_LOGIC_QUANTITY_VALUE_INVARIANT",
                mutation_dimensions=["WORKFLOW", "VALUE"],
                logic_details={"family": "QUANTITY_VALUE_INVARIANT"},
                generation="business-logic-analysis",
            )
            for identifier in ("BLH-1111111111111111", "BLH-2222222222222222")
        ],
    ]
    store = finalize_hypothesis_store(
        _target(accounts=1),
        ObservationStore(
            observations=[_observation("OBS-1", method=endpoint.method, path=endpoint.path)]
        ),
        EndpointStore(endpoints=[endpoint]),
        ResourceStore(),
        HypothesisStore(hypotheses=records),
    )

    assert len(store.campaigns) == 1
    campaign = store.campaigns[0]
    assert campaign.member_ids == [
        "BLH-1111111111111111",
        "BLH-2222222222222222",
        "HYP-001",
    ]
    assert len(campaign.cluster_ids) == 2
    assert campaign.cluster_ids == sorted(set(campaign.cluster_ids))


def test_authentication_coverage_campaign_consolidates_presentation_only() -> None:
    endpoints = [
        _endpoint(
            "EP-1",
            path="/api/accounts/{accountId}",
            resource="Account",
            observations=("OBS-1",),
        ),
        _endpoint(
            "EP-2",
            path="/api/orders/{orderId}",
            resource="Order",
            observations=("OBS-2",),
        ),
    ]
    records = [
        _record(
            f"HYP-00{index}",
            endpoint,
            category="research",
            rule="AUTH_ENFORCEMENT_RESEARCH",
            kind="RESEARCH_TASK",
            disposition="NEEDS_RESEARCH",
            mutation_dimensions=[],
        )
        for index, endpoint in enumerate(endpoints, start=1)
    ]
    store = finalize_hypothesis_store(
        _target(accounts=1),
        ObservationStore(
            observations=[
                _observation("OBS-1", method=endpoints[0].method, path=endpoints[0].path),
                _observation("OBS-2", method=endpoints[1].method, path=endpoints[1].path),
            ]
        ),
        EndpointStore(endpoints=endpoints),
        ResourceStore(),
        HypothesisStore(hypotheses=records),
    )

    assert len(store.hypotheses) == 2
    assert len(store.campaigns) == 1
    assert store.campaigns[0].authentication_schemes == ["bearer"]
    assert store.campaigns[0].missing_controls
    assert sum(presentation_visible(item) for item in store.hypotheses) == 1
    assert all(item.id in store.campaigns[0].member_ids for item in store.hypotheses)


def test_legacy_records_load_with_conservative_readiness() -> None:
    endpoint = _endpoint("EP-1")
    payload = _record("HYP-001", endpoint).model_dump(mode="json", exclude_none=True)
    payload.pop("readiness_assessment")
    payload["readiness"] = "TEST_READY"

    record = HypothesisRecord.model_validate(payload)

    assert record.readiness == "REVIEW_REQUIRED"
    assert record.readiness_assessment.actionable_plan is False
    assert record.readiness_assessment.evaluator == "unified-hypothesis-readiness-v1"


def test_queue_comparison_uses_identical_populations_and_reports_zero_provenance_loss(
    tmp_path: Path,
) -> None:
    baseline = create_workspace("queue-before", tmp_path / "workspaces")
    current = create_workspace("queue-after", tmp_path / "workspaces")
    endpoint = _endpoint("EP-1")
    records = [
        _record("HYP-001", endpoint),
        _record("BLH-CCCCCCCCCCCCCCCC", endpoint),
    ]
    for record in records:
        record.readiness = "TEST_READY"
    write_yaml(
        baseline.hypotheses,
        HypothesisStore(hypotheses=records).model_dump(mode="json", exclude_none=True),
    )
    finalized = finalize_hypothesis_store(
        _target(),
        ObservationStore(
            observations=[_observation("OBS-1", method=endpoint.method, path=endpoint.path)]
        ),
        EndpointStore(endpoints=[endpoint]),
        ResourceStore(),
        HypothesisStore(hypotheses=records),
    )
    write_yaml(current.hypotheses, finalized.model_dump(mode="json", exclude_none=True))

    comparison = compare_workspace_queues(baseline, current)

    assert comparison.before.population_policy == comparison.after.population_policy
    assert comparison.before.total_generated_records == 2
    assert comparison.after.total_generated_records == 2
    assert comparison.after.exact_duplicates_collapsed == 1
    assert comparison.provenance_loss_count == 0
    assert comparison.removed_record_ids == []
    assert {item.hypothesis_id for item in comparison.readiness_transitions} == {
        "BLH-CCCCCCCCCCCCCCCC",
        "HYP-001",
    }
