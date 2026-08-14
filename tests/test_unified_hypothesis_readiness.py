"""Precision regressions for unified readiness, intent, claims, and clustering."""

from __future__ import annotations

from pathlib import Path

import pytest

from finsec.behavior.queue_evaluation import compare_workspace_queues
from finsec.config.models import CleanupControlRule, TargetDocument
from finsec.config.workspace import WorkspacePaths, create_workspace
from finsec.hypotheses.clustering import finalize_hypothesis_store, presentation_visible
from finsec.hypotheses.contracts import (
    CapabilityKind,
    ClaimStrengthLevel,
    HypothesisReadinessAssessment,
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
from finsec.normalization.inventory import _action
from finsec.normalization.path_semantics import path_hierarchy
from finsec.testing.planner import inspect_plan_alignment
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
        observations=[endpoint.sources[0]],
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
    observations = ObservationStore(
        observations=[
            _observation(
                endpoint.sources[0],
                method=endpoint.method,
                path=endpoint.path,
            )
        ]
    )
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
    all_endpoints = [endpoint, *(provenance_endpoints or [])]
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
        path="/cdn/4.0/domains/{domain}/dns-records/{dnsRecordId}",
        resource="DnsRecord",
    )
    valid = _typed_baseline(endpoint, actor="ACCOUNT_1", object_id="record-a")
    incompatible = _typed_baseline(
        endpoint,
        actor="ACCOUNT_2",
        object_id="record-b",
        subject_resource_type=resource_type,
        collection_route_family=collection_route_family,
        parent_resource_type=parent_resource_type,
    )

    assessment = _authorization_assessment(endpoint, [valid, incompatible])

    assert assessment.comparison_coverage.observed_distinct_actors == 1
    assert assessment.comparison_coverage.baseline_actor_ids == ["ACCOUNT_1"]
    assert assessment.comparison_coverage.missing_actor_ids == ["ACCOUNT_2"]


def test_matching_typed_provenance_satisfies_two_actor_comparison_coverage() -> None:
    endpoint = _endpoint(
        "EP-DNS",
        path="/cdn/4.0/domains/{domain}/dns-records/{dnsRecordId}",
        resource="DnsRecord",
    )
    baselines = [
        _typed_baseline(endpoint, actor="ACCOUNT_1", object_id="record-a"),
        _typed_baseline(endpoint, actor="ACCOUNT_2", object_id="record-b"),
    ]

    assessment = _authorization_assessment(endpoint, baselines)

    assert assessment.comparison_coverage.observed_distinct_actors == 2
    assert assessment.comparison_coverage.distinct_controlled_objects == 2
    assert assessment.comparison_coverage.missing_actor_ids == []
    baseline = next(
        item for item in assessment.capabilities if item.capability == CapabilityKind.BASELINE
    )
    assert baseline.satisfied is True


def test_legacy_baseline_from_another_controlled_parent_in_same_family_counts() -> None:
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

    assert assessment.comparison_coverage.observed_distinct_actors == 1
    assert assessment.comparison_coverage.baseline_actor_ids == ["ACCOUNT_1"]
    assert assessment.comparison_coverage.missing_actor_ids == ["ACCOUNT_2"]
    baseline = assessment.comparison_coverage.baselines[0]
    assert baseline.resource_type == "DnsRecord"
    assert baseline.parent_resource_type == "Domain"
    assert baseline.parent_reference is not None


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
    endpoint = _endpoint("EP-1")
    first = _typed_baseline(endpoint, actor="ACCOUNT_1", object_id="order-a").model_copy(
        update={"relationship_ids": ["REL-A", "REL-B"]}
    )
    corroborating = first.model_copy(
        update={
            "baseline_id": "BASE-ACCOUNT_1-order-a-corroborating",
            "relationship_ids": ["REL-C"],
        }
    )
    second = _typed_baseline(endpoint, actor="ACCOUNT_2", object_id="order-b").model_copy(
        update={"relationship_ids": ["REL-D"]}
    )

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
        observations=[endpoint.sources[0]],
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

    assert ready.readiness == "TEST_READY"
    assert ready.actionable_plan is True
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
    assert budget.satisfied is False
    assert "requires 4 request(s), but policy permits 3" in budget.missing[0]
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
    assert matched_budget.satisfied is False
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


def test_test_ready_records_align_with_actionable_planner(
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
    ready = [item for item in generated if item.readiness == "TEST_READY"]

    assert ready
    for item in ready:
        alignment = inspect_plan_alignment(phase4_workspace, item.id)
        assert alignment.agrees is True
        assert alignment.plan_status == "READY_FOR_REVIEW"


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
