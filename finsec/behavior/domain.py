"""Typed behavior, workflow, invariant, and business-logic hypothesis contracts."""

from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from finsec.captures.domain import CaptureMode, CaptureRelevance
from finsec.hypotheses.contracts import (
    BindingType,
    ClaimStrengthAssessment,
    DomainIntentAssessment,
    DomainOperation,
    HypothesisGrouping,
    HypothesisReadinessAssessment,
    VisibilityIntent,
)
from finsec.modeling.semantics import IdentifierSemanticClass, OwnershipState


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


class RelationshipType(StrEnum):
    """Typed relationships with explicit component-merging semantics."""

    CAUSAL_HARD = "CAUSAL_HARD"
    CONTEXT_SOFT = "CONTEXT_SOFT"
    REPLAY_RELATED = "REPLAY_RELATED"
    CROSS_ACTOR_COMPARISON = "CROSS_ACTOR_COMPARISON"


class CausalBasis(StrEnum):
    """Explain whether a matched value was produced or merely observed."""

    RESOURCE_CREATED = "RESOURCE_CREATED"
    CAPABILITY_ISSUED = "CAPABILITY_ISSUED"
    STATE_TRANSITION_PRODUCED = "STATE_TRANSITION_PRODUCED"
    EXISTING_VALUE_OBSERVED = "EXISTING_VALUE_OBSERVED"
    REQUEST_VALUE_ECHOED = "REQUEST_VALUE_ECHOED"
    AMBIGUOUS_ORIGIN = "AMBIGUOUS_ORIGIN"
    LEGACY_UNTYPED = "LEGACY_UNTYPED"


class CausalEvidence(BehaviorModel):
    """Evidence-based predicate set for deterministic causal reasoning.

    Tracks which evidence conditions are met for a candidate causal edge.
    Used to explain why a relationship was or was not classified as CAUSAL_HARD.
    All fields are boolean predicates; final causal basis is deterministically derived.
    """

    output_only: bool = False
    """Value appears in response but not in producing request."""

    later_consumed: bool = False
    """Value is explicitly supplied in a later request."""

    compatible_resource_type: bool = False
    """Source and destination resources have compatible types."""

    temporal_order: bool = False
    """Temporal precedence is established via timestamps or sequence."""

    same_controlled_actor: bool = False
    """Producer and consumer share the same authenticated principal."""

    distinctive_value: bool = False
    """Value is distinctive rather than low-entropy or a generic enum."""

    same_session: bool = False
    """Producer and consumer share explicit session identity."""

    same_capture: bool = False
    """Producer and consumer observations are in the same traffic capture."""

    same_host: bool = False
    """Producer and consumer are on the same service endpoint."""

    session_compatible: bool = False
    """Session metadata permits this producer-consumer continuation."""

    capture_compatible: bool = False
    """Capture boundaries are identical or joined by an explicit logical session."""

    host_compatible: bool = False
    """Hosts are identical or are explicit first-party services in one logical session."""

    request_echo: bool = False
    """Value was supplied in the producer's request (not produced)."""

    previously_observed: bool = False
    """Value was observed in prior operations (read, not produced)."""

    source_is_read: bool = False
    """The candidate producer is a read-only observation."""

    source_successful: bool = False
    """The source response has a successful HTTP status."""

    source_created_resource: bool = False
    """Structural response evidence proves creation of a persistent resource identity."""

    consumer_state_changing: bool = False
    """The consumer advances or authorizes workflow state."""

    consumed_as_path_identifier: bool = False
    """The destination uses the value as a persistent path-scoped resource identifier."""

    persistent_resource_identity: bool = False
    """Observed behavior is consistent with a durable resource rather than a capability."""

    collection_member: bool = False
    """The response exposed the value as an existing member of a collection."""

    direct_state_transition: bool = False
    """No intervening mutation supersedes the source state before the destination."""

    capability_semantics: bool = False
    """Evidence suggests the value is a workflow token/capability."""

    state_transition_evidence: bool = False
    """Evidence of state change in a lifecycle field."""

    distinctive_semantic_role: bool = False
    """Field semantic role (e.g., WORKFLOW_TOKEN) is distinctive."""

    field_alias_compatible: bool = False
    """Different field names carry the same structurally admissible capability value."""

    def hard_causal_admissibility(self, basis: CausalBasis | None = None) -> bool:
        """Deterministically derive whether this evidence supports CAUSAL_HARD."""
        if not (
            self.later_consumed
            and self.temporal_order
            and self.same_controlled_actor
            and self.distinctive_value
            and self.session_compatible
            and self.capture_compatible
            and self.host_compatible
        ):
            return False
        if basis == CausalBasis.RESOURCE_CREATED:
            return (
                self.output_only
                and self.source_created_resource
                and self.compatible_resource_type
                and not self.request_echo
                and not self.previously_observed
                and not self.collection_member
            )
        if basis == CausalBasis.CAPABILITY_ISSUED:
            return (
                self.output_only
                and self.capability_semantics
                and self.consumer_state_changing
                and not self.request_echo
                and not self.previously_observed
                and not self.persistent_resource_identity
            )
        if basis == CausalBasis.STATE_TRANSITION_PRODUCED:
            return self.state_transition_evidence and self.direct_state_transition
        return (
            self.output_only
            and not self.request_echo
            and not self.previously_observed
            and (
                self.source_created_resource
                or self.capability_semantics
                or self.state_transition_evidence
            )
        )

    def rejection_reasons(self, basis: CausalBasis | None = None) -> list[str]:
        """Return stable structural reasons preventing a hard causal relationship."""

        reasons: list[str] = []
        if self.request_echo:
            reasons.append("request_value_echoed")
        if self.collection_member:
            reasons.append("response_collection_member_observed")
        if self.source_is_read:
            reasons.append("source_is_read_only")
        if self.previously_observed and basis != CausalBasis.STATE_TRANSITION_PRODUCED:
            reasons.append("value_previously_observed")
        if not self.output_only and basis != CausalBasis.STATE_TRANSITION_PRODUCED:
            reasons.append("output_only_production_not_proven")
        if not self.later_consumed:
            reasons.append("later_request_consumption_not_observed")
        if not self.distinctive_value:
            reasons.append("value_not_distinctive")
        if not self.same_controlled_actor:
            reasons.append("controlled_actor_mismatch")
        if not self.temporal_order:
            reasons.append("temporal_order_not_proven")
        if not self.session_compatible:
            reasons.append("session_incompatible")
        if not self.capture_compatible:
            reasons.append("capture_incompatible")
        if not self.host_compatible:
            reasons.append("host_incompatible")
        if basis == CausalBasis.RESOURCE_CREATED:
            if not self.compatible_resource_type:
                reasons.append("resource_type_incompatible")
            if not self.source_created_resource:
                reasons.append("resource_creation_semantics_not_proven")
        elif basis == CausalBasis.CAPABILITY_ISSUED:
            if not self.consumer_state_changing:
                reasons.append("consumer_does_not_advance_workflow")
            if self.persistent_resource_identity:
                reasons.append("persistent_resource_behavior_observed")
            if not self.capability_semantics:
                reasons.append("capability_semantics_not_proven")
        elif basis == CausalBasis.STATE_TRANSITION_PRODUCED:
            if not self.state_transition_evidence:
                reasons.append("state_transition_structure_not_proven")
            if not self.direct_state_transition:
                reasons.append("intervening_resource_mutation_observed")
        elif not (
            self.source_created_resource
            or self.capability_semantics
            or self.state_transition_evidence
        ):
            reasons.append("admissible_producer_semantics_not_proven")
        return list(dict.fromkeys(reasons))

    def context_soft_reason(self) -> str:
        """Explain why this edge is CONTEXT_SOFT, if not admissible for CAUSAL_HARD."""
        reasons = self.rejection_reasons()
        return reasons[0].replace("_", " ") if reasons else "hard causal evidence is incomplete"


class HypothesisReadiness(StrEnum):
    """Separate plausibility from whether unresolved blockers remain."""

    RESEARCH_ONLY = "RESEARCH_ONLY"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"
    TEST_READY = "TEST_READY"


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


class SemanticLabelConfidence(StrEnum):
    """Deterministic quality level for researcher-facing semantic names."""

    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class SemanticLabelBasis(StrEnum):
    """Evidence used to derive a researcher-facing action or resource label."""

    ENDPOINT_MODEL = "ENDPOINT_MODEL"
    ROUTE_AND_METHOD = "ROUTE_AND_METHOD"
    ACTION_STRUCTURE = "ACTION_STRUCTURE"
    NEUTRAL_FALLBACK = "NEUTRAL_FALLBACK"


class HypothesisConfidence(StrEnum):
    """Security-question confidence, kept separate from test readiness."""

    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class HypothesisEvidenceStrength(StrEnum):
    """Named-evidence sufficiency independent from the legacy numeric score."""

    STRONG = "STRONG"
    MODERATE = "MODERATE"
    WEAK = "WEAK"
    INSUFFICIENT = "INSUFFICIENT"


class HypothesisPromotion(StrEnum):
    """Research presentation tier; this never grants execution authority."""

    SUPPRESSED = "SUPPRESSED"
    RESEARCH_LOW = "RESEARCH_LOW"
    RESEARCH_MEDIUM = "RESEARCH_MEDIUM"
    RESEARCH_HIGH = "RESEARCH_HIGH"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"
    TEST_READY = "TEST_READY"


class SemanticLabel(BehaviorModel):
    """A normalized display label with deterministic quality provenance."""

    value: str
    normalized_value: str
    confidence: SemanticLabelConfidence
    basis: SemanticLabelBasis
    hygiene_reasons: list[str] = Field(default_factory=list)


class HypothesisSemantics(BehaviorModel):
    """Canonical identity for one distinct researcher security question."""

    vulnerability_family: HypothesisFamily
    subject_action: str
    subject_resource: str
    parent_resource: str | None = None
    operation: DomainOperation = DomainOperation.UNKNOWN
    visibility: VisibilityIntent = VisibilityIntent.UNKNOWN
    binding: BindingType = BindingType.UNKNOWN
    violated_property: str
    mutation_type: HypothesisFamily
    actor_dimension: list[str] = Field(default_factory=list)
    resource_dimension: list[str] = Field(default_factory=list)
    state_dimension: list[str] = Field(default_factory=list)
    prerequisite_dimension: list[str] = Field(default_factory=list)
    endpoint_dimension: list[str] = Field(default_factory=list)
    value_dimension: list[str] = Field(default_factory=list)
    label: SemanticLabel
    fingerprint: str
    canonical_id: str


class HypothesisEvidence(BehaviorModel):
    """Named predicates explaining why a hypothesis deserves visibility."""

    authenticated: bool = False
    sensitive_operation: bool = False
    sensitive_read: bool = False
    state_changing: bool = False
    controlled_identifier: bool = False
    ownership_known: bool = False
    cross_actor_baseline: bool = False
    capability_binding_observed: bool = False
    causal_prerequisites_proven: bool = False
    business_relevant_resource: bool = False
    independently_identifiable_resource: bool = False
    cross_workflow_resource: bool = False
    privileged_or_approval_context: bool = False
    independent_support_count: int = Field(default=0, ge=0)


class HypothesisQualification(BehaviorModel):
    """Evidence-driven presentation decision for a retained raw candidate."""

    evidence: HypothesisEvidence
    hypothesis_confidence: HypothesisConfidence
    evidence_strength: HypothesisEvidenceStrength
    promotion: HypothesisPromotion
    research_score: int = Field(ge=0)
    qualification_reasons: list[str] = Field(default_factory=list)
    suppression_reasons: list[str] = Field(default_factory=list)


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
    capture_modes: list[CaptureMode] = Field(default_factory=list)
    semantic_classes: list[IdentifierSemanticClass] = Field(default_factory=list)
    ownership_states: list[OwnershipState] = Field(default_factory=list)
    normal_behavior_observations: list[str] = Field(default_factory=list)
    probe_observations: list[str] = Field(default_factory=list)
    relationships: list[ResourceRelationship] = Field(default_factory=list)
    confidence: InferenceConfidence
    epistemic_status: Literal[EpistemicStatus.OBSERVED_FACT] = EpistemicStatus.OBSERVED_FACT


class PropagationLink(BehaviorModel):
    """An explainable typed relationship between two passive observations."""

    id: str
    relationship_type: RelationshipType = RelationshipType.CONTEXT_SOFT
    causal_basis: CausalBasis = CausalBasis.LEGACY_UNTYPED
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
    source_semantic_role: str | None = None
    destination_semantic_role: str | None = None
    source_resource_role: str | None = None
    destination_resource_role: str | None = None
    source_location: str | None = None
    destination_location: str | None = None
    source_primitive_type: str | None = None
    destination_primitive_type: str | None = None
    source_observation_id: str
    source_field: str
    source_actor: str | None = None
    source_session: str | None = None
    source_capture: str | None = None
    source_capture_mode: CaptureMode = CaptureMode.UNKNOWN
    source_host: str | None = None
    destination_observation_id: str
    destination_field: str
    destination_actor: str | None = None
    destination_session: str | None = None
    destination_capture: str | None = None
    destination_capture_mode: CaptureMode = CaptureMode.UNKNOWN
    destination_host: str | None = None
    temporal_order_known: bool = False
    capture_continuity: bool = False
    distinctive_value: bool = False
    causal_evidence: CausalEvidence = Field(default_factory=CausalEvidence)
    rejection_reasons: list[str] = Field(default_factory=list)
    evidence_reason: str = (
        "LEGACY_UNTYPED: causal provenance is unavailable; rebuild workflows from factual "
        "observations to obtain typed producer evidence."
    )
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
    semantic_role: str = "business:value"
    location: str = "BODY"
    primitive_type: str = "string"
    client_controlled: bool = False


class WorkflowStep(BehaviorModel):
    """One ordered semantic action inside a workflow instance."""

    position: int = Field(ge=1)
    action_id: str
    action_name: str
    observation_id: str
    capture_id: str | None = None
    capture_mode: CaptureMode = CaptureMode.UNKNOWN
    capture_relevance: CaptureRelevance = CaptureRelevance.UNKNOWN
    endpoint_ids: list[str] = Field(default_factory=list)
    actor: str
    method: str = "UNKNOWN"
    route: str = ""
    resource_role: str = "UNKNOWN"
    state_changing: bool = False
    timestamp: str | None = None
    resource_instance_ids: list[str] = Field(default_factory=list)
    client_controlled_resource_fields: list[str] = Field(default_factory=list)
    client_controlled_binding_fields: list[str] = Field(default_factory=list)
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
    captures: list[str] = Field(default_factory=list)
    capture_modes: list[CaptureMode] = Field(default_factory=list)
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


class WorkflowPrerequisite(BehaviorModel):
    """A producer-consumer prerequisite retained with support and counterexamples."""

    prerequisite_action: str
    dependent_action: str
    prerequisite_position: int = Field(ge=1)
    dependent_position: int = Field(ge=1)
    support_count: int = Field(ge=1)
    comparable_instances: int = Field(ge=1)
    support_ratio: float = Field(ge=0, le=1)
    causal_link_ids: list[str] = Field(default_factory=list)
    causal_bases: list[CausalBasis] = Field(default_factory=list)
    supporting_observations: list[str] = Field(default_factory=list)
    counterexamples: list[str] = Field(default_factory=list)
    confidence: InferenceConfidence
    reason: str


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
    capture_modes: list[CaptureMode] = Field(default_factory=list)
    resource_types: list[str] = Field(default_factory=list)
    transition_frequencies: dict[str, int] = Field(default_factory=dict)
    outcome_distribution: dict[str, int] = Field(default_factory=dict)
    structural_signature: str = ""
    ordered_step_signature: list[str] = Field(default_factory=list)
    causal_topology: list[str] = Field(default_factory=list)
    terminal_or_mutating_steps: list[str] = Field(default_factory=list)
    causal_prerequisites: list[WorkflowPrerequisite] = Field(default_factory=list)
    research_clues: list[str] = Field(default_factory=list)
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
    prerequisite_action: str | None = None
    dependent_action: str | None = None
    prerequisite_position: int | None = Field(default=None, ge=1)
    dependent_position: int | None = Field(default=None, ge=1)
    support_count: int = Field(default=0, ge=0)
    support_ratio: float = Field(default=0, ge=0, le=1)
    causal_evidence: list[str] = Field(default_factory=list)
    counterexamples: list[str] = Field(default_factory=list)
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
    readiness: HypothesisReadiness = HypothesisReadiness.REVIEW_REQUIRED
    readiness_assessment: HypothesisReadinessAssessment = Field(
        default_factory=HypothesisReadinessAssessment
    )
    domain_intent: DomainIntentAssessment = Field(default_factory=DomainIntentAssessment)
    claim_strength: ClaimStrengthAssessment = Field(default_factory=ClaimStrengthAssessment)
    grouping: HypothesisGrouping = Field(default_factory=HypothesisGrouping)
    epistemic_status: EpistemicStatus
    semantics: HypothesisSemantics | None = None
    qualification: HypothesisQualification | None = None


class HypothesisSupportContext(BehaviorModel):
    """Complete provenance retained for one member of a semantic cluster."""

    hypothesis_id: str
    workflow_family_id: str
    workflow_instance_ids: list[str] = Field(default_factory=list)
    invariant_id: str
    mutation_family: HypothesisFamily
    affected_action: str
    observation_ids: list[str] = Field(default_factory=list)
    causal_evidence: list[str] = Field(default_factory=list)
    prerequisite_actions: list[str] = Field(default_factory=list)
    actors: list[str] = Field(default_factory=list)
    captures: list[str] = Field(default_factory=list)
    resource_types: list[str] = Field(default_factory=list)
    resource_instance_ids: list[str] = Field(default_factory=list)
    endpoint_ids: list[str] = Field(default_factory=list)
    score: LogicScore
    readiness: HypothesisReadiness
    blockers: list[str] = Field(default_factory=list)
    independent_support_ids: list[str] = Field(default_factory=list)


class IndependentHypothesisSupport(BehaviorModel):
    """One non-duplicative support unit and the boundary used to count it."""

    id: str
    basis: list[
        Literal[
            "CAPTURE",
            "CONTROLLED_ACTOR",
            "RESOURCE_INSTANCE",
            "CAUSAL_PATH",
            "WORKFLOW_INSTANCE_FALLBACK",
        ]
    ] = Field(default_factory=list)
    workflow_instance_ids: list[str] = Field(default_factory=list)
    actors: list[str] = Field(default_factory=list)
    captures: list[str] = Field(default_factory=list)
    resource_instance_ids: list[str] = Field(default_factory=list)
    causal_path: list[str] = Field(default_factory=list)
    observation_ids: list[str] = Field(default_factory=list)


class HypothesisCluster(BehaviorModel):
    """Research-facing aggregation of raw candidates sharing one semantic identity."""

    id: str
    semantic_fingerprint: str
    semantics: HypothesisSemantics
    title: str
    representative_hypothesis_id: str
    member_hypothesis_ids: list[str] = Field(default_factory=list)
    support_contexts: list[HypothesisSupportContext] = Field(default_factory=list)
    independent_supports: list[IndependentHypothesisSupport] = Field(default_factory=list)
    context_count: int = Field(ge=1)
    independent_support_count: int = Field(ge=0)
    highest_score: int = Field(ge=4, le=20)
    research_score: int = Field(ge=0)
    hypothesis_confidence: HypothesisConfidence
    evidence_strength: HypothesisEvidenceStrength
    promotion: HypothesisPromotion
    readiness: HypothesisReadiness
    readiness_blockers: list[str] = Field(default_factory=list)
    ranking_reasons: list[str] = Field(default_factory=list)
    suppression_reasons: list[str] = Field(default_factory=list)
    workflow_family_ids: list[str] = Field(default_factory=list)
    workflow_instance_ids: list[str] = Field(default_factory=list)
    invariant_ids: list[str] = Field(default_factory=list)
    observation_ids: list[str] = Field(default_factory=list)


class MutationRejection(BehaviorModel):
    """A mutation considered by the engine but rejected by semantic eligibility gates."""

    id: str
    workflow_family_id: str
    mutation_family: HypothesisFamily
    affected_action: str
    invariant_id: str | None = None
    reasons: list[str] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)


class ActionStore(BehaviorModel):
    version: Literal[1] = 1
    actions: list[ActionRecord] = Field(default_factory=list)


class ResourceInstanceStore(BehaviorModel):
    version: Literal[1] = 1
    resource_instances: list[ResourceInstance] = Field(default_factory=list)


class PropagationStore(BehaviorModel):
    version: Literal[1, 2] = 2
    propagation_links: list[PropagationLink] = Field(default_factory=list)

    @model_validator(mode="before")
    @classmethod
    def _downgrade_untyped_legacy_links(cls, value: object) -> object:
        if not isinstance(value, dict):
            return value
        version = value.get("version", 2)
        links = value.get("propagation_links")
        if version != 1 or not isinstance(links, list):
            return value
        normalized = dict(value)
        normalized_links: list[object] = []
        for link in links:
            if not isinstance(link, dict) or "relationship_type" in link:
                normalized_links.append(link)
                continue
            legacy = dict(link)
            legacy["relationship_type"] = RelationshipType.CONTEXT_SOFT
            legacy["causal_basis"] = CausalBasis.LEGACY_UNTYPED
            legacy["evidence_reason"] = (
                "LEGACY_UNTYPED: v1 propagation did not persist producer semantics; "
                "the link is display-only and cannot merge workflows. Rebuild from factual "
                "observations to obtain v2 typed causal evidence."
            )
            normalized_links.append(legacy)
        normalized["propagation_links"] = normalized_links
        return normalized


class WorkflowInstanceStore(BehaviorModel):
    version: Literal[1, 2] = 2
    workflow_instances: list[WorkflowInstance] = Field(default_factory=list)


class WorkflowFamilyStore(BehaviorModel):
    version: Literal[1, 2] = 2
    workflow_families: list[WorkflowFamily] = Field(default_factory=list)


class StateStore(BehaviorModel):
    version: Literal[1] = 1
    states: list[StateRecord] = Field(default_factory=list)


class TransitionStore(BehaviorModel):
    version: Literal[1] = 1
    transitions: list[TransitionRecord] = Field(default_factory=list)


class BusinessInvariantStore(BehaviorModel):
    version: Literal[1, 2] = 2
    business_invariants: list[BusinessInvariant] = Field(default_factory=list)


class LogicHypothesisStore(BehaviorModel):
    version: Literal[1, 2, 3] = 3
    hypotheses: list[LogicHypothesis] = Field(default_factory=list)
    rejections: list[MutationRejection] = Field(default_factory=list)
    clusters: list[HypothesisCluster] = Field(default_factory=list)
