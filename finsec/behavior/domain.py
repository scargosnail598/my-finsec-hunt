"""Typed behavior, workflow, invariant, and business-logic hypothesis contracts."""

from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class BehaviorModel(BaseModel):
    """Reject accidental schema drift in canonical behavior artifacts."""

    model_config = ConfigDict(extra="forbid")


class EpistemicStatus(StrEnum):
    """Keep offline inference separate from empirical confirmation."""

    OBSERVED_FACT = "OBSERVED_FACT"
    INFERRED_PATTERN = "INFERRED_PATTERN"
    RESEARCH_TASK = "RESEARCH_TASK"
    TEST_CANDIDATE = "TEST_CANDIDATE"
    TEST_PLANNED = "TEST_PLANNED"
    NEEDS_EVIDENCE = "NEEDS_EVIDENCE"
    REJECTED_BY_BACKEND = "REJECTED_BY_BACKEND"
    CONFIRMED = "CONFIRMED"


class InferenceConfidence(StrEnum):
    """Evidence-oriented confidence labels for deterministic inference."""

    HIGH_EVIDENCE = "HIGH_EVIDENCE"
    MODERATE_EVIDENCE = "MODERATE_EVIDENCE"
    WEAK_EVIDENCE = "WEAK_EVIDENCE"
    SPECULATIVE = "SPECULATIVE"


class SafetyClassification(StrEnum):
    """Static validation cost; this classification never grants authority."""

    READ_ONLY = "READ_ONLY"
    LOW_RISK_STATE_CHANGE = "LOW_RISK_STATE_CHANGE"
    REVERSIBLE_STATE_CHANGE = "REVERSIBLE_STATE_CHANGE"
    FINANCIAL_STATE_CHANGE = "FINANCIAL_STATE_CHANGE"
    DESTRUCTIVE = "DESTRUCTIVE"
    CONCURRENT = "CONCURRENT"
    EXTERNAL_SIDE_EFFECT = "EXTERNAL_SIDE_EFFECT"
    UNSAFE_OR_UNBOUNDED = "UNSAFE_OR_UNBOUNDED"


HypothesisFamily = Literal[
    "STEP_SKIPPING",
    "OUT_OF_ORDER_EXECUTION",
    "REPLAY",
    "DUPLICATE_ACTION",
    "CONCURRENT_EXECUTION",
    "TERMINAL_STATE_BYPASS",
    "ACTOR_SWITCH",
    "RESOURCE_SWITCH",
    "CROSS_WORKFLOW_TOKEN_REUSE",
    "PARTIAL_ROLLBACK",
    "QUANTITY_VALUE_INVARIANT",
    "ROLE_APPROVAL_BYPASS",
    "SHADOW_ENDPOINT",
]


class ActionRecord(BehaviorModel):
    """A deterministic semantic operation inferred from factual observations."""

    id: str
    name: str
    method: str
    route: str
    endpoint_ids: list[str] = Field(default_factory=list)
    observation_ids: list[str] = Field(default_factory=list)
    resource_types: list[str] = Field(default_factory=list)
    state_changing: bool = False
    confidence: InferenceConfidence
    reasons: list[str] = Field(default_factory=list)
    epistemic_status: Literal[EpistemicStatus.INFERRED_PATTERN] = EpistemicStatus.INFERRED_PATTERN


class ResourceRelationship(BehaviorModel):
    """An evidence-backed relationship between two concrete resource fingerprints."""

    relation: Literal[
        "owned_by",
        "created_by",
        "belongs_to",
        "paid_by",
        "linked_to",
        "parent_of",
        "derived_from",
        "consumed_by",
        "scoped_to",
    ]
    target_resource_id: str
    evidence: list[str] = Field(default_factory=list)
    confidence: InferenceConfidence


class ResourceInstance(BehaviorModel):
    """A redacted concrete resource identity reconstructed from passive evidence."""

    id: str
    resource_type: str
    value_fingerprint: str
    reference: str
    observations: list[str] = Field(default_factory=list)
    actors: list[str] = Field(default_factory=list)
    relationships: list[ResourceRelationship] = Field(default_factory=list)
    confidence: InferenceConfidence
    epistemic_status: Literal[EpistemicStatus.OBSERVED_FACT] = EpistemicStatus.OBSERVED_FACT


class PropagationLink(BehaviorModel):
    """A redacted value created or observed once and consumed by a later request."""

    id: str
    value_fingerprint: str
    value_kind: Literal[
        "RESOURCE_IDENTIFIER",
        "WORKFLOW_TOKEN",
        "CORRELATION_ID",
        "IDEMPOTENCY_KEY",
        "BUSINESS_VALUE",
    ]
    destination_value_kind: (
        Literal[
            "RESOURCE_IDENTIFIER",
            "WORKFLOW_TOKEN",
            "CORRELATION_ID",
            "IDEMPOTENCY_KEY",
            "BUSINESS_VALUE",
        ]
        | None
    ) = None
    source_resource_type: str | None = None
    destination_resource_type: str | None = None
    source_observation_id: str
    source_field: str
    destination_observation_id: str
    destination_field: str
    evidence: list[str] = Field(default_factory=list)
    confidence: InferenceConfidence
    epistemic_status: Literal[EpistemicStatus.OBSERVED_FACT] = EpistemicStatus.OBSERVED_FACT


class WorkflowStateObservation(BehaviorModel):
    """One resource-scoped state observed or inferred at a workflow step."""

    field: str
    resource_type: str
    resource_instance_ids: list[str] = Field(default_factory=list)
    state_before: str | None = None
    state_after: str
    derivation: Literal["EXPLICIT_FIELD", "ACTION_SEMANTICS", "SUBSEQUENT_BEHAVIOR", "UNRESOLVED"]


class WorkflowBusinessValue(BehaviorModel):
    """One redacted-capture business value associated with a resource and step."""

    field: str
    value: str
    direction: Literal["REQUEST", "RESPONSE"]
    resource_type: str
    resource_instance_ids: list[str] = Field(default_factory=list)


class WorkflowStep(BehaviorModel):
    """One ordered semantic action inside a workflow instance."""

    position: int = Field(ge=1)
    action_id: str
    action_name: str
    observation_id: str
    endpoint_ids: list[str] = Field(default_factory=list)
    actor: str
    timestamp: str | None = None
    resource_instance_ids: list[str] = Field(default_factory=list)
    state_observations: list[WorkflowStateObservation] = Field(default_factory=list)
    business_values: list[WorkflowBusinessValue] = Field(default_factory=list)
    state_before: str | None = None
    state_after: str | None = None
    state_derivation: Literal[
        "EXPLICIT_FIELD", "ACTION_SEMANTICS", "SUBSEQUENT_BEHAVIOR", "UNRESOLVED"
    ] = "UNRESOLVED"


class WorkflowInstance(BehaviorModel):
    """A conservative ordered grouping of related observations and actions."""

    id: str
    family_id: str
    actors: list[str] = Field(default_factory=list)
    sessions: list[str] = Field(default_factory=list)
    resource_instance_ids: list[str] = Field(default_factory=list)
    resource_types: list[str] = Field(default_factory=list)
    steps: list[WorkflowStep] = Field(default_factory=list)
    started_at: str | None = None
    ended_at: str | None = None
    terminal_outcome: str | None = None
    evidence: list[str] = Field(default_factory=list)
    segmentation_confidence: InferenceConfidence
    ambiguities: list[str] = Field(default_factory=list)
    epistemic_status: Literal[EpistemicStatus.INFERRED_PATTERN] = EpistemicStatus.INFERRED_PATTERN


class StateRecord(BehaviorModel):
    """An aggregated inferred or directly observed state."""

    id: str
    resource_type: str
    name: str
    derivation: Literal["EXPLICIT_FIELD", "ACTION_SEMANTICS", "SUBSEQUENT_BEHAVIOR", "UNRESOLVED"]
    observations: list[str] = Field(default_factory=list)
    confidence: InferenceConfidence
    epistemic_status: EpistemicStatus


class TransitionRecord(BehaviorModel):
    """An evidence-linked source-state/action/destination-state transition."""

    id: str
    workflow_family_id: str
    source_state: str
    action_id: str
    action_name: str
    destination_state: str
    actors: list[str] = Field(default_factory=list)
    preconditions: list[str] = Field(default_factory=list)
    resource_types: list[str] = Field(default_factory=list)
    frequency: int = Field(ge=1)
    examples: list[str] = Field(default_factory=list)
    contradictions: list[str] = Field(default_factory=list)
    confidence: InferenceConfidence
    evidence: list[str] = Field(default_factory=list)
    epistemic_status: Literal[EpistemicStatus.INFERRED_PATTERN] = EpistemicStatus.INFERRED_PATTERN


class WorkflowFamily(BehaviorModel):
    """A canonical abstraction over similar observed workflow instances."""

    id: str
    name: str
    entry_actions: list[str] = Field(default_factory=list)
    terminal_actions: list[str] = Field(default_factory=list)
    observed_paths: list[list[str]] = Field(default_factory=list)
    common_path: list[str] = Field(default_factory=list)
    optional_steps: list[str] = Field(default_factory=list)
    required_looking_steps: list[str] = Field(default_factory=list)
    branch_points: list[str] = Field(default_factory=list)
    actors: list[str] = Field(default_factory=list)
    resource_types: list[str] = Field(default_factory=list)
    transition_frequencies: dict[str, int] = Field(default_factory=dict)
    outcome_distribution: dict[str, int] = Field(default_factory=dict)
    workflow_instance_ids: list[str] = Field(default_factory=list)
    inference_confidence: InferenceConfidence
    confidence_explanation: list[str] = Field(default_factory=list)
    epistemic_status: Literal[EpistemicStatus.INFERRED_PATTERN] = EpistemicStatus.INFERRED_PATTERN


class GraphNode(BehaviorModel):
    """One canonical state node in a workflow graph."""

    id: str
    label: str
    kind: Literal["STATE", "CHECKPOINT", "TERMINAL"]


class GraphEdge(BehaviorModel):
    """One observed or inferred transition edge."""

    id: str
    source: str
    destination: str
    action: str
    observation_ids: list[str] = Field(default_factory=list)
    workflow_instance_ids: list[str] = Field(default_factory=list)
    actors: list[str] = Field(default_factory=list)
    resource_types: list[str] = Field(default_factory=list)
    count: int = Field(ge=1)
    relative_frequency: float = Field(ge=0, le=1)
    median_timing_seconds: float | None = Field(default=None, ge=0)
    response_outcomes: list[str] = Field(default_factory=list)
    confidence: InferenceConfidence
    derivation: Literal["DIRECTLY_OBSERVED", "INFERRED"]


class WorkflowGraph(BehaviorModel):
    """Stable graph serialization for one workflow family."""

    version: Literal[1] = 1
    id: str
    workflow_family_id: str
    nodes: list[GraphNode] = Field(default_factory=list)
    edges: list[GraphEdge] = Field(default_factory=list)


class BusinessInvariant(BehaviorModel):
    """An inferred business rule that remains unconfirmed offline."""

    id: str
    statement: str
    invariant_type: Literal[
        "ORDERING",
        "SINGLE_EXECUTION",
        "TERMINAL_STATE",
        "ACTOR_BINDING",
        "RESOURCE_BINDING",
        "TOKEN_SCOPE",
        "ROLLBACK_CONSISTENCY",
        "VALUE_CONSERVATION",
        "ROLE_SEPARATION",
        "SERVER_CONTROLLED_FIELDS",
    ]
    workflow_family_id: str
    resource_types: list[str] = Field(default_factory=list)
    supporting_observations: list[str] = Field(default_factory=list)
    contradicting_observations: list[str] = Field(default_factory=list)
    source_of_inference: list[str] = Field(default_factory=list)
    mutable_value_fields: list[str] = Field(default_factory=list)
    authoritative_value_fields: list[str] = Field(default_factory=list)
    source_endpoint_ids: list[str] = Field(default_factory=list)
    candidate_methods: list[str] = Field(default_factory=list)
    candidate_paths: list[str] = Field(default_factory=list)
    candidate_fields: list[str] = Field(default_factory=list)
    confidence: InferenceConfidence
    confidence_explanation: list[str] = Field(default_factory=list)
    validation_requirements: list[str] = Field(default_factory=list)
    state_changing_validation: bool
    epistemic_status: Literal[EpistemicStatus.INFERRED_PATTERN] = EpistemicStatus.INFERRED_PATTERN


class ScoreContribution(BehaviorModel):
    """One transparent contribution to a deterministic score dimension."""

    reason: str
    points: int


class LogicScore(BehaviorModel):
    """Separate likelihood, impact, readiness, and safety-cost dimensions."""

    likelihood: int = Field(ge=1, le=5)
    impact: int = Field(ge=1, le=5)
    test_readiness: int = Field(ge=1, le=5)
    safety_cost: int = Field(ge=1, le=5)
    confidence: int = Field(ge=1, le=5)
    breakdown: list[ScoreContribution] = Field(default_factory=list)


class LogicHypothesis(BehaviorModel):
    """An explainable minimal deviation from observed canonical behavior."""

    id: str
    fingerprint: str
    title: str
    family: HypothesisFamily
    workflow_family_id: str
    affected_action: str
    affected_transition_id: str | None = None
    invariant_id: str
    invariant_statement: str
    canonical_behavior: str
    mutated_behavior: str
    supporting_evidence: list[str] = Field(default_factory=list)
    contradicting_evidence: list[str] = Field(default_factory=list)
    controlled_actors_required: int = Field(ge=0)
    controlled_resources_required: list[str] = Field(default_factory=list)
    authentication_requirements: list[str] = Field(default_factory=list)
    state_evidence_requirements: list[str] = Field(default_factory=list)
    mutable_value_fields: list[str] = Field(default_factory=list)
    authoritative_value_fields: list[str] = Field(default_factory=list)
    candidate_methods: list[str] = Field(default_factory=list)
    candidate_paths: list[str] = Field(default_factory=list)
    candidate_fields: list[str] = Field(default_factory=list)
    expected_safe_baseline: str
    expected_vulnerable_outcome: str
    expected_secure_outcome: str
    impact_rationale: str
    score: LogicScore
    confidence_explanation: list[str] = Field(default_factory=list)
    uncertainty: list[str] = Field(default_factory=list)
    safety_classification: SafetyClassification
    estimated_request_budget: int = Field(ge=0, le=10)
    readiness_blockers: list[str] = Field(default_factory=list)
    suggested_validation_strategy: list[str] = Field(default_factory=list)
    suppression_reasons: list[str] = Field(default_factory=list)
    endpoint_ids: list[str] = Field(default_factory=list)
    observation_ids: list[str] = Field(default_factory=list)
    kind: Literal["SECURITY_HYPOTHESIS", "RESEARCH_TASK"]
    epistemic_status: EpistemicStatus


class ActionStore(BehaviorModel):
    version: Literal[1] = 1
    actions: list[ActionRecord] = Field(default_factory=list)


class ResourceInstanceStore(BehaviorModel):
    version: Literal[1] = 1
    resource_instances: list[ResourceInstance] = Field(default_factory=list)


class PropagationStore(BehaviorModel):
    version: Literal[1] = 1
    propagation_links: list[PropagationLink] = Field(default_factory=list)


class WorkflowInstanceStore(BehaviorModel):
    version: Literal[1] = 1
    workflow_instances: list[WorkflowInstance] = Field(default_factory=list)


class WorkflowFamilyStore(BehaviorModel):
    version: Literal[1] = 1
    workflow_families: list[WorkflowFamily] = Field(default_factory=list)


class StateStore(BehaviorModel):
    version: Literal[1] = 1
    states: list[StateRecord] = Field(default_factory=list)


class TransitionStore(BehaviorModel):
    version: Literal[1] = 1
    transitions: list[TransitionRecord] = Field(default_factory=list)


class BusinessInvariantStore(BehaviorModel):
    version: Literal[1] = 1
    business_invariants: list[BusinessInvariant] = Field(default_factory=list)


class LogicHypothesisStore(BehaviorModel):
    version: Literal[1] = 1
    hypotheses: list[LogicHypothesis] = Field(default_factory=list)
