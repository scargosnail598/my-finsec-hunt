"""Regression coverage for canonical BLH semantics and research presentation."""

from __future__ import annotations

from dataclasses import dataclass

from finsec.behavior.analysis import _backlog_draft
from finsec.behavior.domain import (
    ActionRecord,
    ActionStore,
    BusinessInvariant,
    EpistemicStatus,
    HypothesisPromotion,
    HypothesisReadiness,
    InferenceConfidence,
    LogicHypothesis,
    LogicHypothesisStore,
    LogicScore,
    PropagationLink,
    PropagationStore,
    RelationshipType,
    SafetyClassification,
    TransitionStore,
    WorkflowFamily,
    WorkflowFamilyStore,
    WorkflowInstance,
    WorkflowInstanceStore,
    WorkflowStep,
)
from finsec.behavior.hypothesis_precision import (
    HypothesisPrecisionInputs,
    calibrate_hypotheses,
    cluster_is_visible,
    rank_hypothesis_clusters,
)
from finsec.config.models import TargetDocument
from finsec.modeling.merge import stable_fingerprint
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
)


@dataclass(frozen=True)
class _Case:
    hypothesis: LogicHypothesis
    invariant: BusinessInvariant
    family: WorkflowFamily
    instances: list[WorkflowInstance]
    action: ActionRecord
    endpoint: Endpoint
    observations: list[Observation]
    links: list[PropagationLink]


def _target() -> TargetDocument:
    return TargetDocument.model_validate(
        {
            "target": {"name": "semantic-tests", "slug": "semantic-tests"},
            "scope": {"hosts": ["api.semantic.test"]},
            "accounts": [
                {"id": "ACCOUNT_A", "ownership": "researcher", "role": "requester"},
                {"id": "ACCOUNT_B", "ownership": "researcher", "role": "requester"},
                {"id": "MERCHANT_A", "ownership": "researcher", "role": "merchant"},
                {"id": "APPROVER_A", "ownership": "researcher", "role": "approver"},
            ],
            "testing": {"synthetic": True, "local_lab": True},
        }
    )


def _observation(
    identifier: str,
    *,
    actor: str,
    capture: str,
    method: str,
    path: str,
    authenticated: bool,
) -> Observation:
    return Observation(
        id=identifier,
        source_reference=f"synthetic:{identifier}",
        source_fingerprint=stable_fingerprint(identifier),
        capture_identity=capture,
        actor=actor,
        channel="WEB",
        host="api.semantic.test",
        scheme="https",
        method=method,
        path=path,
        status_code=200,
        content_type="application/json",
        authentication=AuthenticationObservation(
            present=authenticated,
            observed_type="bearer" if authenticated else "none",
        ),
    )


def _endpoint(
    identifier: str,
    observation_ids: list[str],
    *,
    action: str,
    resource: str,
    method: str,
    path: str,
    state_changing: bool,
    authenticated: bool,
    object_identifier: bool,
    ownership_known: bool,
    classification: EndpointPrimaryClassification,
) -> Endpoint:
    parameter = EndpointParameter(
        name=f"{resource}Id" if object_identifier else "value",
        location="path" if object_identifier else "body",
        source="request",
        inferred_type="string",
        confidence=Confidence.HIGH,
        evidence=observation_ids,
        knowledge_status=KnowledgeStatus.INFERRED,
        semantic_type="object_identifier" if object_identifier else "unknown",
        client_controlled=True,
    )
    object_access = (
        [
            ObjectAccessEvidence(
                identifier=parameter.name,
                baselines=[
                    ActorObjectBaseline(
                        actor="ACCOUNT_A",
                        requested_value="redacted-a",
                        observations=observation_ids[:1],
                    ),
                    ActorObjectBaseline(
                        actor="ACCOUNT_B",
                        requested_value="redacted-b",
                        observations=observation_ids[1:2],
                    ),
                ],
                distinct_actors=2,
                distinct_objects=2,
                distinct_owner_values=2,
                actor_object_binding_observed=True,
            )
        ]
        if ownership_known
        else []
    )
    return Endpoint(
        id=identifier,
        method=method,
        path=path,
        hosts=["api.semantic.test"],
        channels=["WEB"],
        authentication=EndpointAuthentication(
            required=authenticated,
            observed_type="bearer" if authenticated else "none",
        ),
        classification=EndpointClassification(
            primary=classification,
            confidence=Confidence.HIGH,
        ),
        resource=EndpointResource(type=resource, confidence=Confidence.HIGH),
        action=EndpointAction(
            name=action.split("_", 1)[0].lower(),
            type="mutation" if state_changing else "read",
            confidence=Confidence.HIGH,
        ),
        parameters=[parameter],
        object_access=object_access,
        state_change=state_changing,
        security_relevance=8 if state_changing or ownership_known else 1,
        sources=observation_ids,
        confidence=Confidence.HIGH,
        normalization=NormalizationEvidence(observed_paths=[path]),
    )


def _case(
    suffix: str,
    *,
    mutation: str = "REPLAY",
    action: str = "RETURN_ORDER",
    resource: str = "order",
    path: str = "/api/orders/{orderId}/return",
    method: str = "POST",
    invariant_type: str = "SINGLE_EXECUTION",
    contexts: tuple[tuple[str, str, str], ...] = (("ACCOUNT_A", "capture-a", "R-1"),),
    state_changing: bool = True,
    authenticated: bool = True,
    object_identifier: bool = True,
    ownership_known: bool = False,
    classification: EndpointPrimaryClassification = EndpointPrimaryClassification.FIRST_PARTY_API,
    prerequisite: str | None = None,
    dependent: str | None = None,
    suppression_reasons: tuple[str, ...] = (),
    readiness: HypothesisReadiness = HypothesisReadiness.REVIEW_REQUIRED,
    blockers: tuple[str, ...] = ("Human review remains required.",),
) -> _Case:
    family_id = f"WF-{suffix}"
    invariant_id = f"INV-{suffix}"
    endpoint_id = f"EP-{suffix}"
    observations = [
        _observation(
            f"OBS-{suffix}-{index}",
            actor=actor,
            capture=capture,
            method=method,
            path=path,
            authenticated=authenticated,
        )
        for index, (actor, capture, _resource_id) in enumerate(contexts, start=1)
    ]
    endpoint = _endpoint(
        endpoint_id,
        [item.id for item in observations],
        action=action,
        resource=resource,
        method=method,
        path=path,
        state_changing=state_changing,
        authenticated=authenticated,
        object_identifier=object_identifier,
        ownership_known=ownership_known,
        classification=classification,
    )
    instances: list[WorkflowInstance] = []
    for index, ((actor, capture, resource_id), observation) in enumerate(
        zip(contexts, observations, strict=True), start=1
    ):
        instances.append(
            WorkflowInstance(
                id=f"WINST-{suffix}-{index}",
                family_id=family_id,
                actors=[actor],
                captures=[capture],
                resource_instance_ids=[resource_id],
                resource_types=[resource],
                steps=[
                    WorkflowStep(
                        position=1,
                        action_id=f"ACT-{suffix}",
                        action_name=action,
                        observation_id=observation.id,
                        endpoint_ids=[endpoint_id],
                        actor=actor,
                        method=method,
                        route=path,
                        state_changing=state_changing,
                        resource_instance_ids=[resource_id],
                        client_controlled_resource_fields=[f"path.{resource}Id"],
                    )
                ],
                evidence=[observation.id],
                segmentation_confidence=InferenceConfidence.MODERATE_EVIDENCE,
            )
        )
    family = WorkflowFamily(
        id=family_id,
        name=f"{resource} lifecycle",
        observed_paths=[[action]],
        common_path=[action],
        actors=sorted({actor for actor, _capture, _resource_id in contexts}),
        resource_types=[resource],
        workflow_instance_ids=[item.id for item in instances],
        inference_confidence=InferenceConfidence.MODERATE_EVIDENCE,
    )
    invariant = BusinessInvariant(
        id=invariant_id,
        statement=f"{action} challenges {invariant_type}.",
        invariant_type=invariant_type,  # type: ignore[arg-type]
        workflow_family_id=family_id,
        resource_types=[resource],
        supporting_observations=[item.id for item in observations],
        source_of_inference=["synthetic precision fixture"],
        prerequisite_action=prerequisite,
        dependent_action=dependent,
        prerequisite_position=1 if prerequisite is not None else None,
        dependent_position=1 if dependent is not None else None,
        support_count=len(contexts),
        support_ratio=1.0,
        causal_evidence=[f"PROP-{suffix}"] if prerequisite is not None else [],
        confidence=InferenceConfidence.MODERATE_EVIDENCE,
        state_changing_validation=state_changing,
    )
    links: list[PropagationLink] = []
    actors = {actor for actor, _capture, _resource_id in contexts}
    if len(observations) >= 2 and len(actors) >= 2:
        links.append(
            PropagationLink(
                id=f"PROP-{suffix}",
                relationship_type=RelationshipType.CROSS_ACTOR_COMPARISON,
                value_fingerprint=stable_fingerprint(f"resource-{suffix}"),
                value_kind="RESOURCE_IDENTIFIER",
                source_observation_id=observations[0].id,
                source_field=f"path.{resource}Id",
                source_actor=observations[0].actor,
                destination_observation_id=observations[1].id,
                destination_field=f"path.{resource}Id",
                destination_actor=observations[1].actor,
                evidence=[observations[0].id, observations[1].id],
                confidence=InferenceConfidence.MODERATE_EVIDENCE,
            )
        )
    fingerprint = stable_fingerprint(
        {"family": family_id, "mutation": mutation, "action": action, "invariant": invariant_id}
    )
    hypothesis = LogicHypothesis(
        id=f"BLH-{fingerprint[:16].upper()}",
        fingerprint=fingerprint,
        title=f"Raw {action} {mutation}",
        family=mutation,  # type: ignore[arg-type]
        workflow_family_id=family_id,
        affected_action=action,
        invariant_id=invariant_id,
        invariant_statement=invariant.statement,
        canonical_behavior=f"canonical {action}",
        mutated_behavior=f"mutated {action}",
        supporting_evidence=[item.id for item in observations],
        controlled_actors_required=2 if mutation in {"ACTOR_SWITCH", "RESOURCE_SWITCH"} else 1,
        controlled_resources_required=[resource],
        authentication_requirements=["Use reviewed controlled credentials."],
        state_evidence_requirements=["Record authoritative state."],
        expected_safe_baseline="The controlled baseline succeeds.",
        expected_vulnerable_outcome="The mutation creates an unintended effect.",
        expected_secure_outcome="The mutation is rejected or has no unintended effect.",
        impact_rationale="The mutation may violate a business security property.",
        score=LogicScore(
            likelihood=4,
            impact=4,
            test_readiness=3,
            safety_cost=3,
            confidence=4,
        ),
        confidence_explanation=["Synthetic reviewed evidence."],
        uncertainty=["Backend enforcement remains unconfirmed."],
        safety_classification=(
            SafetyClassification.READ_ONLY
            if not state_changing
            else SafetyClassification.REVERSIBLE_STATE_CHANGE
        ),
        estimated_request_budget=3,
        readiness_blockers=list(blockers),
        suggested_validation_strategy=["Use the minimum approved mutation."],
        suppression_reasons=list(suppression_reasons),
        endpoint_ids=[endpoint_id],
        observation_ids=[item.id for item in observations],
        kind="SECURITY_HYPOTHESIS",
        readiness=readiness,
        epistemic_status=EpistemicStatus.TEST_CANDIDATE,
    )
    action_record = ActionRecord(
        id=f"ACT-{suffix}",
        name=action,
        method=method,
        route=path,
        endpoint_ids=[endpoint_id],
        observation_ids=[item.id for item in observations],
        resource_types=[resource],
        state_changing=state_changing,
        confidence=InferenceConfidence.MODERATE_EVIDENCE,
    )
    return _Case(
        hypothesis=hypothesis,
        invariant=invariant,
        family=family,
        instances=instances,
        action=action_record,
        endpoint=endpoint,
        observations=observations,
        links=links,
    )


def _run(*cases: _Case):
    inputs = HypothesisPrecisionInputs(
        target=_target(),
        observations=ObservationStore(
            observations=[item for case in cases for item in case.observations]
        ),
        endpoints=EndpointStore(endpoints=[case.endpoint for case in cases]),
        actions=ActionStore(actions=[case.action for case in cases]),
        instances=WorkflowInstanceStore(
            workflow_instances=[item for case in cases for item in case.instances]
        ),
        families=WorkflowFamilyStore(workflow_families=[case.family for case in cases]),
        transitions=TransitionStore(),
        propagation=PropagationStore(
            propagation_links=[item for case in cases for item in case.links]
        ),
        invariants=[case.invariant for case in cases],
    )
    return calibrate_hypotheses(inputs, [case.hypothesis for case in cases])


def test_identical_semantic_replay_clusters_and_retains_provenance() -> None:
    first = _case("REPLAY-A")
    second = _case("REPLAY-B")

    result = _run(first, second)

    assert len(result.clusters) == 1
    cluster = result.clusters[0]
    assert cluster.context_count == 2
    assert set(cluster.member_hypothesis_ids) == {
        first.hypothesis.id,
        second.hypothesis.id,
    }
    assert {item.workflow_family_id for item in cluster.support_contexts} == {
        first.family.id,
        second.family.id,
    }
    assert {item.invariant_id for item in cluster.support_contexts} == {
        first.invariant.id,
        second.invariant.id,
    }
    assert set(cluster.observation_ids) == {
        item.id for case in (first, second) for item in case.observations
    }


def test_duplicate_derivations_do_not_inflate_independent_support() -> None:
    first = _case("DUP-A", contexts=(("ACCOUNT_A", "same-capture", "R-1"),))
    second = _case("DUP-B", contexts=(("ACCOUNT_A", "same-capture", "R-1"),))

    cluster = _run(first, second).clusters[0]

    assert cluster.context_count == 2
    assert cluster.independent_support_count == 1


def test_independent_capture_and_resource_contexts_strengthen_support() -> None:
    first = _case("IND-A", contexts=(("ACCOUNT_A", "capture-a", "R-1"),))
    second = _case("IND-B", contexts=(("ACCOUNT_A", "capture-b", "R-2"),))

    cluster = _run(first, second).clusters[0]

    assert cluster.context_count == 2
    assert cluster.independent_support_count == 2
    assert {tuple(item.basis) for item in cluster.independent_supports}


def test_distinct_mutation_families_are_not_over_deduplicated() -> None:
    cases = [
        _case("FAM-REPLAY", mutation="REPLAY"),
        _case("FAM-CONCURRENT", mutation="CONCURRENT_EXECUTION"),
        _case("FAM-DUPLICATE", mutation="DUPLICATE_ACTION"),
        _case("FAM-ROLLBACK", mutation="PARTIAL_ROLLBACK"),
        _case(
            "FAM-SKIP",
            mutation="STEP_SKIPPING",
            invariant_type="ORDERING",
            prerequisite="PAY_ORDER",
            dependent="RETURN_ORDER",
        ),
        _case(
            "FAM-ORDER",
            mutation="OUT_OF_ORDER_EXECUTION",
            invariant_type="ORDERING",
            prerequisite="PAY_ORDER",
            dependent="RETURN_ORDER",
        ),
    ]

    result = _run(*cases)

    assert {cluster.semantics.vulnerability_family for cluster in result.clusters} == {
        "REPLAY",
        "CONCURRENT_EXECUTION",
        "DUPLICATE_ACTION",
        "PARTIAL_ROLLBACK",
        "STEP_SKIPPING",
        "OUT_OF_ORDER_EXECUTION",
    }


def test_actor_and_resource_switch_remain_distinct() -> None:
    contexts = (
        ("ACCOUNT_A", "capture-a", "R-1"),
        ("ACCOUNT_B", "capture-b", "R-2"),
    )
    actor = _case(
        "ACTOR",
        mutation="ACTOR_SWITCH",
        invariant_type="ACTOR_BINDING",
        contexts=contexts,
        ownership_known=True,
    )
    resource = _case(
        "RESOURCE",
        mutation="RESOURCE_SWITCH",
        invariant_type="RESOURCE_BINDING",
        contexts=contexts,
        ownership_known=True,
    )

    result = _run(actor, resource)

    assert len(result.clusters) == 2
    assert all(cluster_is_visible(cluster) for cluster in result.clusters)


def test_different_actor_role_domains_remain_distinct() -> None:
    requester = _case(
        "ROLE-REQUESTER",
        mutation="ACTOR_SWITCH",
        invariant_type="ACTOR_BINDING",
        contexts=(
            ("ACCOUNT_A", "capture-a", "R-1"),
            ("ACCOUNT_B", "capture-b", "R-2"),
        ),
        ownership_known=True,
    )
    approval = _case(
        "ROLE-APPROVAL",
        mutation="ACTOR_SWITCH",
        invariant_type="ACTOR_BINDING",
        contexts=(
            ("MERCHANT_A", "capture-c", "R-3"),
            ("APPROVER_A", "capture-d", "R-4"),
        ),
        ownership_known=True,
    )

    result = _run(requester, approval)

    assert len(result.clusters) == 2
    assert {tuple(item.semantics.actor_dimension) for item in result.clusters} == {
        ("role:requester",),
        ("role:approver", "role:merchant"),
    }


def test_self_referential_ordering_is_suppressed_but_raw_candidate_is_retained() -> None:
    case = _case(
        "SELF",
        mutation="OUT_OF_ORDER_EXECUTION",
        invariant_type="ORDERING",
        action="READ_DASHBOARD",
        resource="dashboard",
        path="/api/dashboard",
        method="GET",
        state_changing=False,
        authenticated=False,
        object_identifier=False,
        prerequisite="READ_DASHBOARD",
        dependent="READ_DASHBOARD",
    )

    result = _run(case)

    assert result.hypotheses[0].affected_action == "READ_DASHBOARD"
    assert result.clusters[0].promotion == HypothesisPromotion.SUPPRESSED
    assert result.clusters[0].suppression_reasons == ["SELF_REFERENTIAL_ORDERING"]


def test_same_action_replay_is_not_represented_as_ordering() -> None:
    case = _case("SAME-REPLAY", mutation="REPLAY")

    cluster = _run(case).clusters[0]

    assert cluster.semantics.vulnerability_family == "REPLAY"
    assert not cluster.semantics.prerequisite_dimension
    assert "replayable" in cluster.title.lower()


def test_malformed_semantic_label_is_neutralized_and_hidden() -> None:
    case = _case(
        "GARBAGE",
        mutation="ACTOR_SWITCH",
        action="READ_F0_9F_A4_96",
        resource="f0-9f-a4-96",
        path="/api/%F0%9F%A4%96",
        method="GET",
        invariant_type="ACTOR_BINDING",
        contexts=(
            ("ACCOUNT_A", "capture-a", "R-1"),
            ("ACCOUNT_B", "capture-b", "R-2"),
        ),
        state_changing=False,
        authenticated=False,
        object_identifier=False,
    )

    result = _run(case)
    candidate = result.hypotheses[0]
    cluster = result.clusters[0]

    assert candidate.affected_action == "READ_F0_9F_A4_96"
    assert "F0" not in cluster.title.upper()
    assert cluster.promotion == HypothesisPromotion.SUPPRESSED
    assert "MALFORMED_SEMANTIC_LABEL" in cluster.suppression_reasons


def test_static_resource_actor_binding_is_suppressed() -> None:
    case = _case(
        "STATIC",
        mutation="ACTOR_SWITCH",
        action="READ_MANIFEST",
        resource="manifest",
        path="/static/manifest.json",
        method="GET",
        invariant_type="ACTOR_BINDING",
        contexts=(
            ("ACCOUNT_A", "capture-a", "R-1"),
            ("ACCOUNT_B", "capture-b", "R-2"),
        ),
        state_changing=False,
        authenticated=False,
        object_identifier=False,
        classification=EndpointPrimaryClassification.STATIC_ASSET,
    )

    cluster = _run(case).clusters[0]

    assert cluster.promotion == HypothesisPromotion.SUPPRESSED
    assert "LOW_SECURITY_RELEVANCE" in cluster.suppression_reasons


def test_sensitive_owned_resource_actor_binding_remains_visible() -> None:
    case = _case(
        "OWNED-ACTOR",
        mutation="ACTOR_SWITCH",
        invariant_type="ACTOR_BINDING",
        contexts=(
            ("ACCOUNT_A", "capture-a", "R-1"),
            ("ACCOUNT_B", "capture-b", "R-2"),
        ),
        ownership_known=True,
    )

    cluster = _run(case).clusters[0]

    assert cluster_is_visible(cluster)
    assert cluster.promotion != HypothesisPromotion.SUPPRESSED
    assert cluster.support_contexts[0].actors


def test_generic_scalar_does_not_surface_resource_switch() -> None:
    case = _case(
        "SCALAR",
        mutation="RESOURCE_SWITCH",
        invariant_type="RESOURCE_BINDING",
        contexts=(
            ("ACCOUNT_A", "capture-a", "R-1"),
            ("ACCOUNT_B", "capture-b", "R-2"),
        ),
        object_identifier=False,
        ownership_known=False,
    )

    result = _run(case)

    assert result.hypotheses[0].qualification is not None
    assert not result.hypotheses[0].qualification.evidence.controlled_identifier
    assert result.clusters[0].promotion == HypothesisPromotion.SUPPRESSED


def test_genuine_controlled_identifier_surfaces_resource_switch() -> None:
    case = _case(
        "CONTROLLED-RESOURCE",
        mutation="RESOURCE_SWITCH",
        invariant_type="RESOURCE_BINDING",
        contexts=(
            ("ACCOUNT_A", "capture-a", "R-1"),
            ("ACCOUNT_B", "capture-b", "R-2"),
        ),
        object_identifier=True,
        ownership_known=True,
    )

    result = _run(case)

    assert result.hypotheses[0].qualification is not None
    assert result.hypotheses[0].qualification.evidence.cross_workflow_resource
    assert cluster_is_visible(result.clusters[0])


def test_stronger_endpoint_hypothesis_suppresses_redundant_resource_switch() -> None:
    case = _case(
        "OVERLAP",
        mutation="RESOURCE_SWITCH",
        invariant_type="RESOURCE_BINDING",
        contexts=(
            ("ACCOUNT_A", "capture-a", "R-1"),
            ("ACCOUNT_B", "capture-b", "R-2"),
        ),
        ownership_known=True,
        suppression_reasons=(
            "A stronger endpoint-level object-authorization hypothesis already covers this "
            "mutation.",
        ),
    )

    cluster = _run(case).clusters[0]

    assert cluster.promotion == HypothesisPromotion.SUPPRESSED
    assert cluster.suppression_reasons == ["OVERLAPS_STRONGER_ENDPOINT_HYPOTHESIS"]


def test_blocker_bearing_candidate_is_never_presented_test_ready() -> None:
    case = _case(
        "BLOCKED",
        readiness=HypothesisReadiness.TEST_READY,
        blockers=("Ownership baseline is missing.",),
    )

    result = _run(case)

    assert result.hypotheses[0].readiness == HypothesisReadiness.REVIEW_REQUIRED
    assert result.clusters[0].readiness != HypothesisReadiness.TEST_READY


def test_weak_security_candidate_retains_technical_readiness_without_test_ready_promotion() -> None:
    case = _case(
        "WEAK-READY",
        method="GET",
        state_changing=False,
        authenticated=False,
        object_identifier=False,
        readiness=HypothesisReadiness.TEST_READY,
        blockers=(),
    )
    case.endpoint.security_relevance = 8

    result = _run(case)
    qualification = result.hypotheses[0].qualification

    assert qualification is not None
    assert qualification.promotion == HypothesisPromotion.RESEARCH_LOW
    assert result.hypotheses[0].readiness == HypothesisReadiness.TEST_READY
    assert result.clusters[0].readiness == HypothesisReadiness.TEST_READY
    assert result.clusters[0].promotion == HypothesisPromotion.RESEARCH_LOW


def test_diversity_ranking_round_robins_mutation_families() -> None:
    contexts = (
        ("ACCOUNT_A", "capture-a", "R-1"),
        ("ACCOUNT_B", "capture-b", "R-2"),
    )
    replay_cases = [
        _case(
            f"REPLAY-{index}",
            action=f"RETURN_ORDER_{index}",
            path=f"/api/orders/{{orderId}}/return-{index}",
        )
        for index in range(5)
    ]
    other_cases = [
        _case("DIVERSE-CONCURRENT", mutation="CONCURRENT_EXECUTION"),
        _case(
            "DIVERSE-ACTOR",
            mutation="ACTOR_SWITCH",
            invariant_type="ACTOR_BINDING",
            contexts=contexts,
            ownership_known=True,
        ),
        _case(
            "DIVERSE-RESOURCE",
            mutation="RESOURCE_SWITCH",
            invariant_type="RESOURCE_BINDING",
            contexts=contexts,
            ownership_known=True,
        ),
    ]

    ranked = rank_hypothesis_clusters(_run(*replay_cases, *other_cases).clusters)

    assert len({item.semantics.vulnerability_family for item in ranked[:4]}) == 4


def test_semantic_clustering_and_ranking_are_deterministic() -> None:
    cases = [
        _case("DET-A"),
        _case("DET-B"),
        _case("DET-C", mutation="CONCURRENT_EXECUTION"),
    ]

    first = _run(*cases)
    second = _run(*reversed(cases))

    assert [item.model_dump(mode="json") for item in first.clusters] == [
        item.model_dump(mode="json") for item in second.clusters
    ]
    assert [item.id for item in rank_hypothesis_clusters(first.clusters)] == [
        item.id for item in rank_hypothesis_clusters(second.clusters)
    ]


def test_no_candidate_or_provenance_is_lost() -> None:
    cases = [
        _case("LOSS-A"),
        _case("LOSS-B"),
        _case("LOSS-C", mutation="DUPLICATE_ACTION"),
    ]

    result = _run(*cases)

    member_ids = {
        member_id for cluster in result.clusters for member_id in cluster.member_hypothesis_ids
    }
    assert member_ids == {case.hypothesis.id for case in cases}
    assert sum(cluster.context_count for cluster in result.clusters) == len(cases)
    assert all(
        context.observation_ids
        for cluster in result.clusters
        for context in cluster.support_contexts
    )


def test_v1_and_v2_logic_stores_remain_readable() -> None:
    hypothesis = _case("LEGACY").hypothesis.model_dump(mode="json")

    v1 = LogicHypothesisStore.model_validate({"version": 1, "hypotheses": [hypothesis]})
    v2 = LogicHypothesisStore.model_validate(
        {"version": 2, "hypotheses": [hypothesis], "rejections": []}
    )

    assert v1.hypotheses[0].semantics is None
    assert v2.clusters == []


def test_backlog_emits_one_representative_and_suppresses_duplicate_rows() -> None:
    first = _case("BACKLOG-A")
    second = _case("BACKLOG-B")
    result = _run(first, second)
    cluster = result.clusters[0]
    by_id = {item.id: item for item in result.hypotheses}

    drafts = {
        member_id: _backlog_draft(
            by_id[member_id],
            cluster,
            representative=member_id == cluster.representative_hypothesis_id,
        )
        for member_id in cluster.member_hypothesis_ids
    }

    assert sum(item["disposition"] == "ACTIVE" for item in drafts.values()) == 1
    assert sum(item["disposition"] == "SUPPRESSED_DUPLICATE" for item in drafts.values()) == 1
    suppressed = next(
        item for item in drafts.values() if item["disposition"] == "SUPPRESSED_DUPLICATE"
    )
    assert suppressed["readiness"] == HypothesisReadiness.REVIEW_REQUIRED
    assert all(
        item["logic_details"]["presentation"]["canonical_id"] == cluster.id
        for item in drafts.values()
    )
