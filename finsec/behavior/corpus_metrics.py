"""Deterministic metrics and diagnostics for the production-backed realistic corpus."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from finsec.behavior.domain import CausalBasis, CausalEvidence, RelationshipType


class CorpusMetricModel(BaseModel):
    """Reject accidental report drift so repeated runs remain byte-comparable."""

    model_config = ConfigDict(extra="forbid")


class ClassificationMetrics(CorpusMetricModel):
    expected: int = Field(ge=0)
    actual: int = Field(ge=0)
    true_positive: int = Field(ge=0)
    false_positive: int = Field(ge=0)
    false_negative: int = Field(ge=0)
    precision: float = Field(ge=0, le=1)
    recall: float = Field(ge=0, le=1)
    f1: float = Field(ge=0, le=1)


class MissedEdgeDiagnostic(CorpusMetricModel):
    edge_id: str
    journey: str
    producer: str
    consumer: str
    producer_field: str
    consumer_field: str
    expected_basis: CausalBasis
    expected_relationship: RelationshipType
    actual_basis: CausalBasis | None = None
    actual_relationship: RelationshipType | None = None
    evidence: CausalEvidence = Field(default_factory=CausalEvidence)
    rejection_reasons: list[str] = Field(default_factory=list)


class FragmentationBreak(CorpusMetricModel):
    producer: str
    consumer: str
    expected_basis: CausalBasis | None = None
    actual_basis: CausalBasis | None = None
    actual_relationship: RelationshipType | None = None
    evidence: CausalEvidence = Field(default_factory=CausalEvidence)
    rejection_reasons: list[str] = Field(default_factory=list)


class FragmentationDiagnostic(CorpusMetricModel):
    journey: str
    expected_components: int
    actual_components: int
    breaks: list[FragmentationBreak] = Field(default_factory=list)


class JourneyEvaluation(CorpusMetricModel):
    journey_id: str
    name: str
    category: str
    difficulty: str
    observation_count: int
    causal_edges: ClassificationMetrics
    forbidden_hard_edges: int = Field(ge=0)
    unexpected_hard_edges: int = Field(ge=0)
    labeled_precision: float = Field(ge=0, le=1)
    label_coverage: float = Field(ge=0, le=1)
    unknown_rate: float = Field(ge=0, le=1)
    precision_lower_bound: float = Field(ge=0, le=1)
    expected_components: int = Field(ge=0)
    actual_components: int = Field(ge=0)
    component_membership: ClassificationMetrics
    expected_component_groups: int = Field(ge=0)
    retained_component_groups: int = Field(ge=0)
    fragmented: bool
    incorrect_merges: int = Field(ge=0)
    order_pairs_expected: int = Field(ge=0)
    order_pairs_recovered: int = Field(ge=0)
    order_retention: float = Field(ge=0, le=1)
    prerequisites: ClassificationMetrics
    forbidden_prerequisites: int = Field(ge=0)
    unexpected_prerequisites: int = Field(ge=0)
    state_transitions: ClassificationMetrics
    hard_link_count: int = Field(ge=0)
    soft_link_count: int = Field(ge=0)
    workflow_instance_count: int = Field(ge=0)
    workflow_family_count: int = Field(ge=0)
    singleton_count: int = Field(ge=0)
    singleton_rate: float = Field(ge=0, le=1)
    invariant_count: int = Field(ge=0)
    hypothesis_count: int = Field(ge=0)
    test_ready_with_blockers: int = Field(ge=0)
    missed_edges: list[MissedEdgeDiagnostic] = Field(default_factory=list)
    fragmentation: FragmentationDiagnostic | None = None


class CorpusStatistics(CorpusMetricModel):
    journey_count: int = Field(ge=0)
    observation_count: int = Field(ge=0)
    expected_hard_edges: int = Field(ge=0)
    expected_soft_edges: int = Field(ge=0)
    forbidden_edges: int = Field(ge=0)
    expected_prerequisites: int = Field(ge=0)
    expected_state_transitions: int = Field(ge=0)


class AggregateMetrics(CorpusMetricModel):
    causal_edges: ClassificationMetrics
    recovered_hard_edges: int = Field(ge=0)
    missed_hard_edges: int = Field(ge=0)
    forbidden_hard_edges: int = Field(ge=0)
    unexpected_hard_edges: int = Field(ge=0)
    labeled_precision: float = Field(ge=0, le=1)
    label_coverage: float = Field(ge=0, le=1)
    unknown_rate: float = Field(ge=0, le=1)
    precision_lower_bound: float = Field(ge=0, le=1)
    metrics_by_causal_category: dict[str, ClassificationMetrics]
    expected_components: int = Field(ge=0)
    actual_components: int = Field(ge=0)
    component_membership: ClassificationMetrics
    expected_component_groups: int = Field(ge=0)
    retained_component_groups: int = Field(ge=0)
    journey_retention: float = Field(ge=0, le=1)
    fragmented_journeys: int = Field(ge=0)
    incorrect_merges: int = Field(ge=0)
    forbidden_merges: int = Field(ge=0)
    order_pairs_expected: int = Field(ge=0)
    order_pairs_recovered: int = Field(ge=0)
    order_retention: float = Field(ge=0, le=1)
    prerequisites: ClassificationMetrics
    forbidden_prerequisites: int = Field(ge=0)
    unexpected_prerequisites: int = Field(ge=0)
    state_transitions: ClassificationMetrics
    singleton_count: int = Field(ge=0)
    workflow_instance_count: int = Field(ge=0)
    singleton_rate: float = Field(ge=0, le=1)
    hard_link_count: int = Field(ge=0)
    soft_link_count: int = Field(ge=0)
    invariant_count: int = Field(ge=0)
    hypothesis_count: int = Field(ge=0)
    test_ready_with_blockers: int = Field(ge=0)
    cross_actor_violations: int = Field(ge=0)
    cross_session_violations: int = Field(ge=0)
    request_echo_violations: int = Field(ge=0)
    read_existing_id_violations: int = Field(ge=0)
    deterministic_output: bool = False


class CorpusEvaluation(CorpusMetricModel):
    version: int = 1
    statistics: CorpusStatistics
    journeys: list[JourneyEvaluation]
    aggregate: AggregateMetrics


class RealisticQualityGateThresholds(CorpusMetricModel):
    min_causal_edge_precision: float = Field(default=1.0, ge=0, le=1)
    min_causal_edge_recall: float = Field(default=1.0, ge=0, le=1)
    min_label_coverage: float = Field(default=1.0, ge=0, le=1)
    min_component_precision: float = Field(default=1.0, ge=0, le=1)
    min_component_recall: float = Field(default=1.0, ge=0, le=1)
    min_prerequisite_precision: float = Field(default=1.0, ge=0, le=1)
    min_prerequisite_recall: float = Field(default=1.0, ge=0, le=1)
    min_state_transition_precision: float = Field(default=1.0, ge=0, le=1)
    min_state_transition_recall: float = Field(default=1.0, ge=0, le=1)
    min_order_retention: float = Field(default=1.0, ge=0, le=1)
    max_forbidden_hard_edges: int = Field(default=0, ge=0)
    max_forbidden_merges: int = Field(default=0, ge=0)
    max_forbidden_prerequisites: int = Field(default=0, ge=0)
    max_fragmented_journeys: int = Field(default=0, ge=0)
    max_test_ready_with_blockers: int = Field(default=0, ge=0)
    max_cross_actor_violations: int = Field(default=0, ge=0)
    max_cross_session_violations: int = Field(default=0, ge=0)
    max_request_echo_violations: int = Field(default=0, ge=0)
    max_read_existing_id_violations: int = Field(default=0, ge=0)
    require_deterministic_output: bool = True


class RealisticQualityGateConfiguration(CorpusMetricModel):
    version: int = 1
    corpus: str = "."
    thresholds: RealisticQualityGateThresholds = Field(
        default_factory=RealisticQualityGateThresholds
    )
