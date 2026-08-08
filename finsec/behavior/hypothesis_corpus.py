"""Fully labeled corpus and metrics for business-logic hypothesis precision."""

from __future__ import annotations

import json
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from finsec.behavior.domain import (
    ActionRecord,
    ActionStore,
    BusinessInvariant,
    EpistemicStatus,
    HypothesisCluster,
    HypothesisPromotion,
    HypothesisReadiness,
    InferenceConfidence,
    LogicHypothesis,
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
from finsec.utils.yaml_store import load_yaml


class CorpusModel(BaseModel):
    """Reject accidental drift in the reviewed hypothesis corpus contract."""

    model_config = ConfigDict(extra="forbid")


class CorpusContext(CorpusModel):
    actor: str
    capture: str
    resource_instance: str


class CorpusCandidate(CorpusModel):
    id: str
    mutation: str
    action: str
    resource: str
    invariant_type: str
    method: str = "POST"
    path: str
    contexts: list[CorpusContext] = Field(min_length=1)
    authenticated: bool = True
    state_changing: bool = True
    object_identifier: bool = True
    ownership_known: bool = False
    classification: EndpointPrimaryClassification = EndpointPrimaryClassification.FIRST_PARTY_API
    prerequisite: str | None = None
    dependent: str | None = None
    overlap_stronger_endpoint_hypothesis: bool = False


class CorpusClusterLabel(CorpusModel):
    key: str
    mutation: str
    subject_action: str
    context_count: int | None = Field(default=None, ge=1)
    independent_support_count: int | None = Field(default=None, ge=0)
    suppression_reason: str | None = None


class CorpusDataset(CorpusModel):
    id: str
    host: str
    accounts: dict[str, str]
    candidates: list[CorpusCandidate]
    expected_clusters: list[CorpusClusterLabel]
    forbidden_clusters: list[CorpusClusterLabel]


class HypothesisCorpusDefinition(CorpusModel):
    version: Literal[1] = 1
    datasets: list[CorpusDataset]


class HypothesisCorpusMetrics(CorpusModel):
    dataset: str
    raw_candidates: int
    unique_semantic_hypotheses: int
    visible_research_items: int
    expected_semantic_hypotheses: int
    recovered_expected_hypotheses: int
    unexpected_hypotheses: int
    forbidden_visible_hypotheses: int
    duplicate_semantic_hypotheses: int
    suppressed_low_value_candidates: int
    semantic_precision: float
    semantic_recall: float
    suppression_precision: float
    research_queue_compression_ratio: float
    evidence_provenance_loss: int
    self_referential_visible: int
    malformed_label_visible: int
    test_ready_with_blockers: int
    clusters_produced: int
    top_10_family_distribution: dict[str, int]
    top_20_family_distribution: dict[str, int]
    cluster_summaries: list[dict[str, Any]]


class HypothesisCorpusReport(CorpusModel):
    version: Literal[1] = 1
    datasets: list[HypothesisCorpusMetrics]
    aggregate: HypothesisCorpusMetrics


class HypothesisCorpusGateThresholds(CorpusModel):
    min_semantic_precision: float = Field(default=1.0, ge=0, le=1)
    min_semantic_recall: float = Field(default=1.0, ge=0, le=1)
    min_suppression_precision: float = Field(default=1.0, ge=0, le=1)
    max_duplicate_semantic_hypotheses: int = Field(default=0, ge=0)
    max_self_referential_visible: int = Field(default=0, ge=0)
    max_malformed_label_visible: int = Field(default=0, ge=0)
    max_evidence_provenance_loss: int = Field(default=0, ge=0)
    max_test_ready_with_blockers: int = Field(default=0, ge=0)
    require_deterministic_output: bool = True


class HypothesisCorpusGateConfiguration(CorpusModel):
    version: Literal[1] = 1
    fixture: str
    thresholds: HypothesisCorpusGateThresholds


class HypothesisCorpusLabelError(ValueError):
    """Raised when reviewed labels are ambiguous, duplicated, or incomplete."""


class HypothesisCorpusQualityGateError(AssertionError):
    """Raised when a reviewed BLH quality threshold regresses."""


@dataclass(frozen=True)
class _BuiltCandidate:
    hypothesis: LogicHypothesis
    invariant: BusinessInvariant
    family: WorkflowFamily
    instances: list[WorkflowInstance]
    action: ActionRecord
    endpoint: Endpoint
    observations: list[Observation]
    links: list[PropagationLink]


def load_hypothesis_corpus(path: Path) -> HypothesisCorpusDefinition:
    """Load and statically validate a reviewed BLH corpus."""

    definition = HypothesisCorpusDefinition.model_validate(load_yaml(path))
    for dataset in definition.datasets:
        candidate_ids = [item.id for item in dataset.candidates]
        if len(candidate_ids) != len(set(candidate_ids)):
            raise HypothesisCorpusLabelError(f"{dataset.id}: duplicate candidate IDs")
        labels = [*dataset.expected_clusters, *dataset.forbidden_clusters]
        label_keys = [item.key for item in labels]
        if len(label_keys) != len(set(label_keys)):
            raise HypothesisCorpusLabelError(f"{dataset.id}: duplicate cluster label keys")
        selectors = [(item.mutation, item.subject_action) for item in labels]
        if len(selectors) != len(set(selectors)):
            raise HypothesisCorpusLabelError(f"{dataset.id}: duplicate semantic cluster selectors")
    return definition


def load_hypothesis_corpus_gate_configuration(
    path: Path,
) -> HypothesisCorpusGateConfiguration:
    """Load reviewed BLH quality thresholds."""

    return HypothesisCorpusGateConfiguration.model_validate(load_yaml(path))


def _target(dataset: CorpusDataset) -> TargetDocument:
    return TargetDocument.model_validate(
        {
            "target": {"name": dataset.id, "slug": dataset.id},
            "scope": {"hosts": [dataset.host]},
            "accounts": [
                {"id": actor, "ownership": "researcher", "role": role}
                for actor, role in sorted(dataset.accounts.items())
            ],
            "testing": {"synthetic": True, "local_lab": True},
        }
    )


def _observation(
    dataset: CorpusDataset,
    candidate: CorpusCandidate,
    context: CorpusContext,
    index: int,
) -> Observation:
    identifier = f"OBS-{candidate.id}-{index}"
    return Observation(
        id=identifier,
        source_reference=f"hypothesis-corpus:{dataset.id}:{candidate.id}:{index}",
        source_fingerprint=stable_fingerprint(identifier),
        capture_identity=context.capture,
        actor=context.actor,
        channel="WEB",
        host=dataset.host,
        scheme="https",
        method=candidate.method,
        path=candidate.path,
        status_code=200,
        content_type="application/json",
        authentication=AuthenticationObservation(
            present=candidate.authenticated,
            observed_type="bearer" if candidate.authenticated else "none",
        ),
    )


def _endpoint(
    dataset: CorpusDataset,
    candidate: CorpusCandidate,
    observations: list[Observation],
) -> Endpoint:
    identifier = f"EP-{candidate.id}"
    parameter = EndpointParameter(
        name=f"{candidate.resource}Id" if candidate.object_identifier else "value",
        location="path" if candidate.object_identifier else "body",
        source="request",
        inferred_type="string",
        confidence=Confidence.HIGH,
        evidence=[item.id for item in observations],
        knowledge_status=KnowledgeStatus.INFERRED,
        semantic_type="object_identifier" if candidate.object_identifier else "unknown",
        client_controlled=True,
    )
    baselines = [
        ActorObjectBaseline(
            actor=context.actor,
            requested_value=f"redacted-{index}",
            observations=[observation.id],
        )
        for index, (context, observation) in enumerate(
            zip(candidate.contexts, observations, strict=True), start=1
        )
    ]
    object_access = (
        [
            ObjectAccessEvidence(
                identifier=parameter.name,
                baselines=baselines,
                distinct_actors=len({item.actor for item in candidate.contexts}),
                distinct_objects=len({item.resource_instance for item in candidate.contexts}),
                distinct_owner_values=len({item.actor for item in candidate.contexts}),
                actor_object_binding_observed=True,
            )
        ]
        if candidate.ownership_known
        else []
    )
    return Endpoint(
        id=identifier,
        method=candidate.method,
        path=candidate.path,
        hosts=[dataset.host],
        channels=["WEB"],
        authentication=EndpointAuthentication(
            required=candidate.authenticated,
            observed_type="bearer" if candidate.authenticated else "none",
        ),
        classification=EndpointClassification(
            primary=candidate.classification,
            confidence=Confidence.HIGH,
        ),
        resource=EndpointResource(type=candidate.resource, confidence=Confidence.HIGH),
        action=EndpointAction(
            name=candidate.action.split("_", 1)[0].lower(),
            type="mutation" if candidate.state_changing else "read",
            confidence=Confidence.HIGH,
        ),
        parameters=[parameter],
        object_access=object_access,
        state_change=candidate.state_changing,
        security_relevance=(8 if candidate.state_changing or candidate.ownership_known else 1),
        sources=[item.id for item in observations],
        confidence=Confidence.HIGH,
        normalization=NormalizationEvidence(observed_paths=[candidate.path]),
    )


def _build_candidate(dataset: CorpusDataset, candidate: CorpusCandidate) -> _BuiltCandidate:
    observations = [
        _observation(dataset, candidate, context, index)
        for index, context in enumerate(candidate.contexts, start=1)
    ]
    endpoint = _endpoint(dataset, candidate, observations)
    family_id = f"WF-{candidate.id}"
    invariant_id = f"INV-{candidate.id}"
    action_id = f"ACT-{candidate.id}"
    instances: list[WorkflowInstance] = []
    for index, (context, observation) in enumerate(
        zip(candidate.contexts, observations, strict=True), start=1
    ):
        instances.append(
            WorkflowInstance(
                id=f"WINST-{candidate.id}-{index}",
                family_id=family_id,
                actors=[context.actor],
                captures=[context.capture],
                resource_instance_ids=[context.resource_instance],
                resource_types=[candidate.resource],
                steps=[
                    WorkflowStep(
                        position=1,
                        action_id=action_id,
                        action_name=candidate.action,
                        observation_id=observation.id,
                        endpoint_ids=[endpoint.id],
                        actor=context.actor,
                        method=candidate.method,
                        route=candidate.path,
                        state_changing=candidate.state_changing,
                        resource_instance_ids=[context.resource_instance],
                        client_controlled_resource_fields=[f"path.{candidate.resource}Id"],
                    )
                ],
                evidence=[observation.id],
                segmentation_confidence=InferenceConfidence.MODERATE_EVIDENCE,
            )
        )
    family = WorkflowFamily(
        id=family_id,
        name=f"{candidate.resource} lifecycle",
        observed_paths=[[candidate.action]],
        common_path=[candidate.action],
        actors=sorted({item.actor for item in candidate.contexts}),
        resource_types=[candidate.resource],
        workflow_instance_ids=[item.id for item in instances],
        inference_confidence=InferenceConfidence.MODERATE_EVIDENCE,
    )
    invariant = BusinessInvariant(
        id=invariant_id,
        statement=f"{candidate.action} challenges {candidate.invariant_type}.",
        invariant_type=candidate.invariant_type,  # type: ignore[arg-type]
        workflow_family_id=family_id,
        resource_types=[candidate.resource],
        supporting_observations=[item.id for item in observations],
        source_of_inference=["reviewed hypothesis precision corpus"],
        prerequisite_action=candidate.prerequisite,
        dependent_action=candidate.dependent,
        prerequisite_position=1 if candidate.prerequisite is not None else None,
        dependent_position=1 if candidate.dependent is not None else None,
        support_count=len(instances),
        support_ratio=1.0,
        causal_evidence=([f"PROP-{candidate.id}"] if candidate.prerequisite is not None else []),
        confidence=InferenceConfidence.MODERATE_EVIDENCE,
        state_changing_validation=candidate.state_changing,
        mutable_value_fields=(
            ["quantity"] if candidate.mutation == "QUANTITY_VALUE_INVARIANT" else []
        ),
        authoritative_value_fields=(
            ["credit"] if candidate.mutation == "QUANTITY_VALUE_INVARIANT" else []
        ),
    )
    links: list[PropagationLink] = []
    if len(observations) >= 2 and len({item.actor for item in candidate.contexts}) >= 2:
        links.append(
            PropagationLink(
                id=f"PROP-{candidate.id}",
                relationship_type=RelationshipType.CROSS_ACTOR_COMPARISON,
                value_fingerprint=stable_fingerprint(f"resource:{candidate.id}"),
                value_kind="RESOURCE_IDENTIFIER",
                source_observation_id=observations[0].id,
                source_field=f"path.{candidate.resource}Id",
                source_actor=observations[0].actor,
                destination_observation_id=observations[1].id,
                destination_field=f"path.{candidate.resource}Id",
                destination_actor=observations[1].actor,
                evidence=[observations[0].id, observations[1].id],
                confidence=InferenceConfidence.MODERATE_EVIDENCE,
            )
        )
    fingerprint = stable_fingerprint(
        {
            "candidate": candidate.id,
            "family": family_id,
            "mutation": candidate.mutation,
            "action": candidate.action,
        }
    )
    suppression_reasons = (
        ["A stronger endpoint-level object-authorization hypothesis already covers this mutation."]
        if candidate.overlap_stronger_endpoint_hypothesis
        else []
    )
    hypothesis = LogicHypothesis(
        id=f"BLH-{fingerprint[:16].upper()}",
        fingerprint=fingerprint,
        title=f"Raw {candidate.action} {candidate.mutation}",
        family=candidate.mutation,  # type: ignore[arg-type]
        workflow_family_id=family_id,
        affected_action=candidate.action,
        invariant_id=invariant_id,
        invariant_statement=invariant.statement,
        canonical_behavior=f"canonical {candidate.action}",
        mutated_behavior=f"mutated {candidate.action}",
        supporting_evidence=[item.id for item in observations],
        controlled_actors_required=(
            2 if candidate.mutation in {"ACTOR_SWITCH", "RESOURCE_SWITCH"} else 1
        ),
        controlled_resources_required=[candidate.resource],
        authentication_requirements=["Use reviewed controlled credentials."],
        state_evidence_requirements=["Record authoritative state."],
        mutable_value_fields=invariant.mutable_value_fields,
        authoritative_value_fields=invariant.authoritative_value_fields,
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
        confidence_explanation=["Reviewed synthetic evidence."],
        uncertainty=["Backend enforcement remains unconfirmed."],
        safety_classification=(
            SafetyClassification.REVERSIBLE_STATE_CHANGE
            if candidate.state_changing
            else SafetyClassification.READ_ONLY
        ),
        estimated_request_budget=3,
        readiness_blockers=["Human review remains required."],
        suggested_validation_strategy=["Use the minimum approved mutation."],
        suppression_reasons=suppression_reasons,
        endpoint_ids=[endpoint.id],
        observation_ids=[item.id for item in observations],
        kind="SECURITY_HYPOTHESIS",
        readiness=HypothesisReadiness.REVIEW_REQUIRED,
        epistemic_status=EpistemicStatus.TEST_CANDIDATE,
    )
    action = ActionRecord(
        id=action_id,
        name=candidate.action,
        method=candidate.method,
        route=candidate.path,
        endpoint_ids=[endpoint.id],
        observation_ids=[item.id for item in observations],
        resource_types=[candidate.resource],
        state_changing=candidate.state_changing,
        confidence=InferenceConfidence.MODERATE_EVIDENCE,
    )
    return _BuiltCandidate(
        hypothesis=hypothesis,
        invariant=invariant,
        family=family,
        instances=instances,
        action=action,
        endpoint=endpoint,
        observations=observations,
        links=links,
    )


def _selector_matches(label: CorpusClusterLabel, cluster: HypothesisCluster) -> bool:
    return (
        label.mutation == cluster.semantics.vulnerability_family
        and label.subject_action == cluster.semantics.subject_action
    )


def _malformed_title(title: str) -> bool:
    return bool(
        re.search(r"(?:^|\s)(?:f0|e[0-9a-f])(?:\s+[0-9a-f]{2}){2,}", title.lower())
        or re.search(r"%[0-9a-f]{2}", title.lower())
    )


def _evaluate_dataset(dataset: CorpusDataset) -> HypothesisCorpusMetrics:
    built = [_build_candidate(dataset, candidate) for candidate in dataset.candidates]
    inputs = HypothesisPrecisionInputs(
        target=_target(dataset),
        observations=ObservationStore(
            observations=[item for candidate in built for item in candidate.observations]
        ),
        endpoints=EndpointStore(endpoints=[item.endpoint for item in built]),
        actions=ActionStore(actions=[item.action for item in built]),
        instances=WorkflowInstanceStore(
            workflow_instances=[item for candidate in built for item in candidate.instances]
        ),
        families=WorkflowFamilyStore(workflow_families=[item.family for item in built]),
        transitions=TransitionStore(),
        propagation=PropagationStore(
            propagation_links=[item for candidate in built for item in candidate.links]
        ),
        invariants=[item.invariant for item in built],
    )
    result = calibrate_hypotheses(inputs, [item.hypothesis for item in built])
    visible = rank_hypothesis_clusters(result.clusters)

    def classification(cluster: HypothesisCluster) -> str:
        expected = [
            label for label in dataset.expected_clusters if _selector_matches(label, cluster)
        ]
        forbidden = [
            label for label in dataset.forbidden_clusters if _selector_matches(label, cluster)
        ]
        if len(expected) + len(forbidden) > 1:
            raise HypothesisCorpusLabelError(
                f"{dataset.id}: {cluster.id} matches multiple reviewed labels"
            )
        if expected:
            label = expected[0]
            if label.context_count is not None and cluster.context_count != label.context_count:
                raise HypothesisCorpusLabelError(
                    f"{dataset.id}: {label.key} context count is {cluster.context_count}, "
                    f"expected {label.context_count}"
                )
            if (
                label.independent_support_count is not None
                and cluster.independent_support_count != label.independent_support_count
            ):
                raise HypothesisCorpusLabelError(
                    f"{dataset.id}: {label.key} independent support count is "
                    f"{cluster.independent_support_count}, expected "
                    f"{label.independent_support_count}"
                )
            return "expected"
        if forbidden:
            label = forbidden[0]
            if (
                label.suppression_reason is not None
                and label.suppression_reason not in cluster.suppression_reasons
            ):
                raise HypothesisCorpusLabelError(
                    f"{dataset.id}: {label.key} lacks suppression {label.suppression_reason}"
                )
            return "forbidden"
        return "unexpected"

    classified = {cluster.id: classification(cluster) for cluster in result.clusters}
    for label in [*dataset.expected_clusters, *dataset.forbidden_clusters]:
        matches = [cluster for cluster in result.clusters if _selector_matches(label, cluster)]
        if len(matches) != 1:
            raise HypothesisCorpusLabelError(
                f"{dataset.id}: label {label.key!r} matched {len(matches)} clusters"
            )
    visible_expected = sum(classified[item.id] == "expected" for item in visible)
    visible_forbidden = sum(classified[item.id] == "forbidden" for item in visible)
    visible_unexpected = sum(classified[item.id] == "unexpected" for item in visible)
    suppressed = [
        cluster
        for cluster in result.clusters
        if cluster.promotion == HypothesisPromotion.SUPPRESSED
    ]
    correctly_suppressed = sum(classified[item.id] == "forbidden" for item in suppressed)
    member_ids = {
        member_id for cluster in result.clusters for member_id in cluster.member_hypothesis_ids
    }
    raw_ids = {item.hypothesis.id for item in built}
    visible_fingerprints = [item.semantic_fingerprint for item in visible]
    duplicate_semantics = len(visible_fingerprints) - len(set(visible_fingerprints))
    top_10 = Counter(item.semantics.vulnerability_family for item in visible[:10])
    top_20 = Counter(item.semantics.vulnerability_family for item in visible[:20])
    precision_denominator = visible_expected + visible_forbidden + visible_unexpected
    return HypothesisCorpusMetrics(
        dataset=dataset.id,
        raw_candidates=len(result.hypotheses),
        unique_semantic_hypotheses=len(result.clusters),
        visible_research_items=len(visible),
        expected_semantic_hypotheses=len(dataset.expected_clusters),
        recovered_expected_hypotheses=visible_expected,
        unexpected_hypotheses=visible_unexpected,
        forbidden_visible_hypotheses=visible_forbidden,
        duplicate_semantic_hypotheses=duplicate_semantics,
        suppressed_low_value_candidates=sum(
            item.qualification is not None
            and item.qualification.promotion == HypothesisPromotion.SUPPRESSED
            for item in result.hypotheses
        ),
        semantic_precision=(
            visible_expected / precision_denominator if precision_denominator else 1.0
        ),
        semantic_recall=(
            visible_expected / len(dataset.expected_clusters) if dataset.expected_clusters else 1.0
        ),
        suppression_precision=(correctly_suppressed / len(suppressed) if suppressed else 1.0),
        research_queue_compression_ratio=(
            len(visible) / len(result.hypotheses) if result.hypotheses else 0.0
        ),
        evidence_provenance_loss=len(raw_ids - member_ids),
        self_referential_visible=sum(
            item.semantics.vulnerability_family in {"OUT_OF_ORDER_EXECUTION", "STEP_SKIPPING"}
            and len(item.semantics.prerequisite_dimension) == 2
            and item.semantics.prerequisite_dimension[0] == item.semantics.prerequisite_dimension[1]
            for item in visible
        ),
        malformed_label_visible=sum(_malformed_title(item.title) for item in visible),
        test_ready_with_blockers=sum(
            item.readiness == HypothesisReadiness.TEST_READY and bool(item.readiness_blockers)
            for item in visible
        ),
        clusters_produced=len(result.clusters),
        top_10_family_distribution=dict(sorted(top_10.items())),
        top_20_family_distribution=dict(sorted(top_20.items())),
        cluster_summaries=[
            {
                "id": item.id,
                "family": item.semantics.vulnerability_family,
                "subject_action": item.semantics.subject_action,
                "promotion": item.promotion,
                "context_count": item.context_count,
                "independent_support_count": item.independent_support_count,
                "classification": classified[item.id],
                "title": item.title,
            }
            for item in rank_hypothesis_clusters(
                result.clusters, include_suppressed=True, include_low=True
            )
        ],
    )


def _aggregate(metrics: list[HypothesisCorpusMetrics]) -> HypothesisCorpusMetrics:
    raw = sum(item.raw_candidates for item in metrics)
    visible = sum(item.visible_research_items for item in metrics)
    expected = sum(item.expected_semantic_hypotheses for item in metrics)
    recovered = sum(item.recovered_expected_hypotheses for item in metrics)
    unexpected = sum(item.unexpected_hypotheses for item in metrics)
    forbidden = sum(item.forbidden_visible_hypotheses for item in metrics)
    suppressed = sum(item.suppressed_low_value_candidates for item in metrics)
    total_clusters = sum(item.clusters_produced for item in metrics)
    correctly_suppressed = sum(
        round(
            item.suppression_precision
            * sum(
                summary["promotion"] == HypothesisPromotion.SUPPRESSED
                for summary in item.cluster_summaries
            )
        )
        for item in metrics
    )
    suppressed_clusters = sum(
        summary["promotion"] == HypothesisPromotion.SUPPRESSED
        for item in metrics
        for summary in item.cluster_summaries
    )
    precision_denominator = recovered + unexpected + forbidden
    return HypothesisCorpusMetrics(
        dataset="aggregate",
        raw_candidates=raw,
        unique_semantic_hypotheses=sum(item.unique_semantic_hypotheses for item in metrics),
        visible_research_items=visible,
        expected_semantic_hypotheses=expected,
        recovered_expected_hypotheses=recovered,
        unexpected_hypotheses=unexpected,
        forbidden_visible_hypotheses=forbidden,
        duplicate_semantic_hypotheses=sum(item.duplicate_semantic_hypotheses for item in metrics),
        suppressed_low_value_candidates=suppressed,
        semantic_precision=recovered / precision_denominator if precision_denominator else 1.0,
        semantic_recall=recovered / expected if expected else 1.0,
        suppression_precision=(
            correctly_suppressed / suppressed_clusters if suppressed_clusters else 1.0
        ),
        research_queue_compression_ratio=visible / raw if raw else 0.0,
        evidence_provenance_loss=sum(item.evidence_provenance_loss for item in metrics),
        self_referential_visible=sum(item.self_referential_visible for item in metrics),
        malformed_label_visible=sum(item.malformed_label_visible for item in metrics),
        test_ready_with_blockers=sum(item.test_ready_with_blockers for item in metrics),
        clusters_produced=total_clusters,
        top_10_family_distribution=dict(
            sorted(
                sum(
                    (Counter(item.top_10_family_distribution) for item in metrics), Counter()
                ).items()
            )
        ),
        top_20_family_distribution=dict(
            sorted(
                sum(
                    (Counter(item.top_20_family_distribution) for item in metrics), Counter()
                ).items()
            )
        ),
        cluster_summaries=[],
    )


def evaluate_hypothesis_corpus(
    definition: HypothesisCorpusDefinition,
) -> HypothesisCorpusReport:
    """Evaluate every reviewed candidate set through semantic qualification and clustering."""

    metrics = [_evaluate_dataset(dataset) for dataset in definition.datasets]
    return HypothesisCorpusReport(datasets=metrics, aggregate=_aggregate(metrics))


def hypothesis_corpus_gate_failures(
    report: HypothesisCorpusReport,
    thresholds: HypothesisCorpusGateThresholds,
    *,
    repeated_report: HypothesisCorpusReport | None = None,
) -> tuple[str, ...]:
    """Return stable failure codes for reviewed BLH quality regressions."""

    aggregate = report.aggregate
    failures: list[str] = []
    if aggregate.semantic_precision < thresholds.min_semantic_precision:
        failures.append("SEMANTIC_PRECISION")
    if aggregate.semantic_recall < thresholds.min_semantic_recall:
        failures.append("SEMANTIC_RECALL")
    if aggregate.suppression_precision < thresholds.min_suppression_precision:
        failures.append("SUPPRESSION_PRECISION")
    if aggregate.duplicate_semantic_hypotheses > thresholds.max_duplicate_semantic_hypotheses:
        failures.append("VISIBLE_SEMANTIC_DUPLICATES")
    if aggregate.self_referential_visible > thresholds.max_self_referential_visible:
        failures.append("SELF_REFERENTIAL_VISIBLE")
    if aggregate.malformed_label_visible > thresholds.max_malformed_label_visible:
        failures.append("MALFORMED_LABEL_VISIBLE")
    if aggregate.evidence_provenance_loss > thresholds.max_evidence_provenance_loss:
        failures.append("EVIDENCE_PROVENANCE_LOSS")
    if aggregate.test_ready_with_blockers > thresholds.max_test_ready_with_blockers:
        failures.append("TEST_READY_WITH_BLOCKERS")
    if thresholds.require_deterministic_output and (
        repeated_report is None
        or report.model_dump(mode="json") != repeated_report.model_dump(mode="json")
    ):
        failures.append("NON_DETERMINISTIC_OUTPUT")
    return tuple(failures)


def evaluate_hypothesis_corpus_gate_configuration(
    configuration_path: Path,
) -> tuple[HypothesisCorpusReport, HypothesisCorpusReport]:
    """Run the reviewed BLH corpus twice and enforce deterministic quality gates."""

    configuration = load_hypothesis_corpus_gate_configuration(configuration_path)
    fixture = (configuration_path.parent / configuration.fixture).resolve()
    definition = load_hypothesis_corpus(fixture)
    first = evaluate_hypothesis_corpus(definition)
    second = evaluate_hypothesis_corpus(definition)
    failures = hypothesis_corpus_gate_failures(
        first,
        configuration.thresholds,
        repeated_report=second,
    )
    if failures:
        raise HypothesisCorpusQualityGateError(
            "BLH precision corpus quality gates failed: " + ", ".join(failures)
        )
    return first, second


def render_hypothesis_corpus_markdown(report: HypothesisCorpusReport) -> str:
    """Render deterministic BLH precision and compression metrics."""

    lines = [
        "# BLH Precision Corpus",
        "",
        "| Dataset | Raw | Semantic | Visible | Precision | Recall | Suppression | "
        "Compression | Evidence loss |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for item in [*report.datasets, report.aggregate]:
        lines.append(
            f"| {item.dataset} | {item.raw_candidates} | "
            f"{item.unique_semantic_hypotheses} | {item.visible_research_items} | "
            f"{item.semantic_precision:.3f} | {item.semantic_recall:.3f} | "
            f"{item.suppression_precision:.3f} | "
            f"{item.research_queue_compression_ratio:.3f} | "
            f"{item.evidence_provenance_loss} |"
        )
    return "\n".join(lines) + "\n"


def write_hypothesis_corpus_report(
    report: HypothesisCorpusReport,
    json_path: Path,
    markdown_path: Path,
) -> None:
    """Write byte-stable JSON and Markdown BLH benchmark artifacts."""

    json_path.parent.mkdir(parents=True, exist_ok=True)
    markdown_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(
        json.dumps(report.model_dump(mode="json"), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    markdown_path.write_text(
        render_hypothesis_corpus_markdown(report), encoding="utf-8", newline="\n"
    )
