"""Shared semantic, readiness, and campaign contracts for every hypothesis producer."""

from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from finsec.modeling.semantics import IdentifierSemanticAssessment


class ContractModel(BaseModel):
    """Reject accidental drift in deterministic hypothesis decisions."""

    model_config = ConfigDict(extra="forbid")


class DomainOperation(StrEnum):
    """Canonical business operation resolved independently from route wording."""

    READ = "READ"
    CREATE = "CREATE"
    CREATE_CHILD = "CREATE_CHILD"
    UPDATE = "UPDATE"
    DELETE = "DELETE"
    TRANSITION = "TRANSITION"
    VERIFY_CREDENTIAL = "VERIFY_CREDENTIAL"
    ACTION = "ACTION"
    UNKNOWN = "UNKNOWN"


class VisibilityIntent(StrEnum):
    """Evidence-backed access intent for the protected subject."""

    PUBLIC = "PUBLIC"
    SHARED = "SHARED"
    OWNER_SCOPED = "OWNER_SCOPED"
    ROLE_SCOPED = "ROLE_SCOPED"
    ACTOR_BOUND = "ACTOR_BOUND"
    UNKNOWN = "UNKNOWN"


class BindingType(StrEnum):
    """Security binding that must hold for the protected subject."""

    OWNERSHIP = "OWNERSHIP"
    INITIATING_ACTOR = "INITIATING_ACTOR"
    PRODUCER_CONSUMER = "PRODUCER_CONSUMER"
    SESSION = "SESSION"
    ROLE = "ROLE"
    TENANT_ACCOUNT = "TENANT_ACCOUNT"
    UNKNOWN = "UNKNOWN"


class SemanticConfidence(StrEnum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class DecisionEvidence(ContractModel):
    """Machine-readable, secret-free support or counterevidence for one decision."""

    reference: str
    source: Literal[
        "OBSERVATION",
        "ENDPOINT",
        "INVARIANT",
        "WORKFLOW",
        "TARGET_POLICY",
        "GENERATOR",
        "LEGACY",
    ]
    detail: str


class DomainIntentAssessment(ContractModel):
    """Resolved subject, operation, visibility, and binding with retained ambiguity."""

    subject_resource: str = "Unknown"
    parent_resource: str | None = None
    operation: DomainOperation = DomainOperation.UNKNOWN
    visibility: VisibilityIntent = VisibilityIntent.UNKNOWN
    binding: BindingType = BindingType.UNKNOWN
    positive_evidence: list[DecisionEvidence] = Field(default_factory=list)
    counterevidence: list[DecisionEvidence] = Field(default_factory=list)
    ambiguity: list[str] = Field(default_factory=list)
    confidence: SemanticConfidence = SemanticConfidence.LOW


class ClaimStrengthLevel(StrEnum):
    """Maximum security claim justified by the stated evidence contract."""

    INPUT_ACCEPTED = "1_INPUT_ACCEPTED"
    VALIDATOR_ACCEPTED = "2_VALIDATOR_ACCEPTED"
    IDENTITY_OR_SESSION_ESTABLISHED = "3_IDENTITY_OR_SESSION_ESTABLISHED"
    PROTECTED_RESOURCE_REACHED = "4_PROTECTED_RESOURCE_REACHED"
    BACKEND_EFFECT_CONFIRMED = "5_BACKEND_EFFECT_CONFIRMED"


class ClaimStrengthAssessment(ContractModel):
    """Current and targeted claim levels, without promoting a hypothesis to a finding."""

    current_level: ClaimStrengthLevel = ClaimStrengthLevel.INPUT_ACCEPTED
    target_level: ClaimStrengthLevel = ClaimStrengthLevel.INPUT_ACCEPTED
    evidence: list[DecisionEvidence] = Field(default_factory=list)
    upgrade_requirements: list[str] = Field(default_factory=list)
    explanation: str = "No stronger security effect is established by current evidence."


class BlockerStage(StrEnum):
    """Pipeline boundary responsible for a blocker or mandatory gate."""

    HYPOTHESIS_EVIDENCE = "HYPOTHESIS_EVIDENCE"
    PLAN_CONSTRUCTABILITY = "PLAN_CONSTRUCTABILITY"
    HUMAN_APPROVAL = "HUMAN_APPROVAL"
    EXECUTION_POLICY = "EXECUTION_POLICY"


class CapabilityKind(StrEnum):
    """Capabilities required to turn a security question into a bounded plan."""

    CONCRETE_TEST = "CONCRETE_TEST"
    SEMANTIC_TARGET = "SEMANTIC_TARGET"
    ACTOR = "ACTOR"
    OWNERSHIP = "OWNERSHIP"
    BASELINE = "BASELINE"
    REQUEST_TEMPLATE = "REQUEST_TEMPLATE"
    ORACLE = "ORACLE"
    BUDGET = "BUDGET"
    SEGMENTATION = "SEGMENTATION"
    CLEANUP = "CLEANUP"


class ComparisonBaseline(ContractModel):
    """One canonical actor/object baseline with merged supporting provenance."""

    actor_id: str
    object_reference: str
    parent_reference: str | None = None
    resource_type: str | None = None
    parent_resource_type: str | None = None
    route_family: str | None = None
    collection_route_family: str | None = None
    operation: str | None = None
    baseline_ids: list[str] = Field(default_factory=list)
    endpoint_ids: list[str] = Field(default_factory=list)
    supporting_relationship_ids: list[str] = Field(default_factory=list)
    observation_ids: list[str] = Field(default_factory=list)


class ComparisonCoverage(ContractModel):
    """Hypothesis-specific cross-actor baseline coverage."""

    required_distinct_actors: int = Field(default=0, ge=0)
    observed_distinct_actors: int = Field(default=0, ge=0)
    distinct_controlled_objects: int = Field(default=0, ge=0)
    baseline_actor_ids: list[str] = Field(default_factory=list)
    missing_actor_ids: list[str] = Field(default_factory=list)
    resource_type: str | None = None
    route_families: list[str] = Field(default_factory=list)
    parent_resource_type: str | None = None
    baseline_ids: list[str] = Field(default_factory=list)
    evidence_references: list[str] = Field(default_factory=list)
    baselines: list[ComparisonBaseline] = Field(default_factory=list)


class CapabilityAssessment(ContractModel):
    """One explicit readiness prerequisite and the evidence supporting its result."""

    capability: CapabilityKind
    required: bool = True
    satisfied: bool
    stage: BlockerStage
    summary: str
    evidence: list[DecisionEvidence] = Field(default_factory=list)
    missing: list[str] = Field(default_factory=list)
    next_action: str | None = None


class ReadinessIssue(ContractModel):
    """Categorized blocker or gate with a stable deterministic code."""

    code: str
    stage: BlockerStage
    capability: CapabilityKind | None = None
    summary: str
    evidence: list[DecisionEvidence] = Field(default_factory=list)
    next_action: str | None = None


HypothesisReadinessValue = Literal["RESEARCH_ONLY", "REVIEW_REQUIRED", "TEST_READY"]


class HypothesisReadinessAssessment(ContractModel):
    """Authoritative readiness decision shared by generation and planning."""

    version: Literal[1] = 1
    evaluator: str = "unified-hypothesis-readiness-v1"
    readiness: HypothesisReadinessValue = "REVIEW_REQUIRED"
    actionable_plan: bool = False
    reasons: list[str] = Field(default_factory=list)
    missing_prerequisites: list[str] = Field(default_factory=list)
    blockers: list[ReadinessIssue] = Field(default_factory=list)
    warnings: list[ReadinessIssue] = Field(default_factory=list)
    capabilities: list[CapabilityAssessment] = Field(default_factory=list)
    comparison_coverage: ComparisonCoverage = Field(default_factory=ComparisonCoverage)
    evidence_references: list[str] = Field(default_factory=list)


class MutationTargetAssessment(ContractModel):
    """Exact scalar mutation target and its canonical identifier semantics."""

    parameter: str | None = None
    location: str | None = None
    json_path: str | None = None
    endpoint_ids: list[str] = Field(default_factory=list)
    semantics: IdentifierSemanticAssessment = Field(default_factory=IdentifierSemanticAssessment)
    expected_authorization_relationship: str = "UNKNOWN"


class SemanticRelationship(StrEnum):
    EXACT_DUPLICATE = "EXACT_DUPLICATE"
    OVERLAPPING_TEST_CAMPAIGN = "OVERLAPPING_TEST_CAMPAIGN"
    RELATED_DISTINCT = "RELATED_DISTINCT"
    NONE = "NONE"


class SemanticDescriptor(ContractModel):
    """Canonical cross-generator identity independent from titles, scores, and IDs."""

    target_services: list[str] = Field(default_factory=list)
    route_families: list[str] = Field(default_factory=list)
    methods: list[str] = Field(default_factory=list)
    operation: DomainOperation = DomainOperation.UNKNOWN
    subject_resource: str = "unknown"
    parent_resource: str | None = None
    parent_contexts: list[str] = Field(default_factory=list)
    visibility: VisibilityIntent = VisibilityIntent.UNKNOWN
    binding: BindingType = BindingType.UNKNOWN
    weakness_family: str = "UNKNOWN"
    test_operator: str = "UNKNOWN"
    expected_effect: str = "UNKNOWN"
    oracle_family: str = "UNKNOWN"
    actor_requirements: list[str] = Field(default_factory=list)
    mutation_parameter: str | None = None
    mutation_location: str | None = None
    mutation_json_path: str | None = None
    identifier_semantic_class: str = "OPAQUE_UNKNOWN"
    identifier_resource_role: str = "UNKNOWN"
    ownership_state: str = "UNKNOWN"
    expected_authorization_relationship: str = "UNKNOWN"
    workflow_family: str | None = None
    transition: str | None = None
    exact_key: str
    campaign_key: str


class HypothesisGrouping(ContractModel):
    """Stable exact-cluster and campaign membership for one retained record."""

    campaign_id: str | None = None
    cluster_id: str | None = None
    relationship: SemanticRelationship = SemanticRelationship.NONE
    primary_hypothesis_id: str | None = None
    cluster_member_ids: list[str] = Field(default_factory=list)
    campaign_member_ids: list[str] = Field(default_factory=list)
    member_generators: list[str] = Field(default_factory=list)


class HypothesisPresentation(ContractModel):
    """Queue visibility kept separate from readiness and generator disposition."""

    visible: bool = True
    display_title: str | None = None
    suppression_reason: str | None = None
    next_action: str | None = None
    retention_reasons: list[str] = Field(default_factory=list)
    difference_reasons: list[str] = Field(default_factory=list)
    similar_hypothesis_ids: list[str] = Field(default_factory=list)


class HypothesisCampaign(ContractModel):
    """One deterministic setup-sharing campaign across HYP and BLH generators."""

    id: str
    key: str
    title: str
    relationship: SemanticRelationship
    primary_hypothesis_id: str
    member_ids: list[str] = Field(default_factory=list)
    member_generators: list[str] = Field(default_factory=list)
    cluster_ids: list[str] = Field(default_factory=list)
    target_services: list[str] = Field(default_factory=list)
    authentication_schemes: list[str] = Field(default_factory=list)
    affected_endpoints: list[str] = Field(default_factory=list)
    affected_resources: list[str] = Field(default_factory=list)
    shared_setup: list[str] = Field(default_factory=list)
    distinctions: list[str] = Field(default_factory=list)
    missing_controls: list[str] = Field(default_factory=list)
    next_action: str
