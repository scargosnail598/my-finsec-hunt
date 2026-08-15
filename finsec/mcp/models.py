"""Typed, JSON-serializable response contracts for the FinSec Hunt MCP server."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from finsec.hypotheses.contracts import ComparisonCoverage
from finsec.readiness.domain import ReadinessReport

AuthenticationState = Literal["PRESENT", "ABSENT_CONFIRMED", "UNKNOWN_OR_REDACTED"]
TestedBranch = Literal[
    "CREDENTIAL_PRESENT",
    "ANONYMOUS_OR_CREDENTIAL_ABSENT",
    "AUTHENTICATION_UNKNOWN",
]


class McpModel(BaseModel):
    """Strict base model for public MCP responses."""

    model_config = ConfigDict(extra="forbid")


class AuthenticationMetadata(McpModel):
    """Credential-free authentication metadata with explicit evidence fidelity."""

    state: AuthenticationState
    type: str
    value: Literal["<REDACTED>"] | None = None
    fingerprint: str | None = None
    fidelity: Literal["MECHANISM_ONLY", "EXECUTION_REFERENCE", "NOT_AVAILABLE"]


class AuthenticationStateCounts(McpModel):
    """Counts for the authentication tri-state."""

    present: int = 0
    absent_confirmed: int = 0
    unknown_or_redacted: int = 0


class CredentialFidelity(McpModel):
    """Describe what the MCP layer can and cannot know about credentials."""

    credential_values_retained: Literal[False] = False
    credential_values_exposed: Literal[False] = False
    observation_fidelity: str
    execution_fidelity: str
    fingerprint_scope: str


class WorkspaceCounts(McpModel):
    """Deterministic counts from one configured workspace."""

    observations: int
    endpoints: int
    invariants: int
    active_hypotheses: int
    research_tasks: int
    raw_active_hypotheses: int
    raw_research_tasks: int
    executions: int
    evidence_sets: int
    evidence_records: int


class WorkspaceSummary(McpModel):
    """Safe workspace overview exposed through MCP."""

    target_name: str
    in_scope_hosts: list[str]
    testing_policy: dict[str, bool | int | float]
    restrictions: dict[str, bool]
    researcher_controlled_account_count: int
    counts: WorkspaceCounts
    credential_fidelity: CredentialFidelity
    observation_authentication_states: AuthenticationStateCounts
    interpretation_rules: list[str]
    readiness: ReadinessReport


class WorkspaceSetupResult(McpModel):
    """Safe result for one exact-path, default-deny workspace setup."""

    status: Literal["CREATED"] = "CREATED"
    target_name: str
    slug: str
    in_scope_hosts: list[str]
    account_labels: list[str]
    testing_policy: dict[str, bool | int | float]
    restrictions: dict[str, bool]
    next_step: str


class HarIngestSummary(McpModel):
    """Credential-free result for one passive HAR import."""

    status: Literal["IMPORTED"] = "IMPORTED"
    actor: str
    channel: str
    imported: int
    skipped: int
    relabeled: int
    total_observations: int
    original_retained: Literal[True] = True
    redacted_copy_written: Literal[True] = True
    knowledge_state: Literal["OBSERVED"] = "OBSERVED"


class PassiveWorkflowSummary(McpModel):
    """Counts returned by the deterministic offline analysis workflow."""

    observations: int
    endpoints: int
    suppressed_endpoints: int
    actors: int
    resources: int
    workflows: int
    invariants: int
    active_hypotheses: int
    research_tasks: int
    raw_active_hypotheses: int | None = None
    raw_research_tasks: int | None = None
    hypotheses_generated: bool
    conflicts: list[str]
    interpretation_rules: list[str]


class MutationTargetSummary(McpModel):
    """Exact mutation scalar without concrete request values."""

    parameter: str | None
    location: str | None
    json_path: str | None = None
    endpoint_ids: list[str]
    expected_authorization_relationship: str


class IdentifierSemanticsSummary(McpModel):
    """Sanitized identifier meaning and ownership evidence."""

    semantic_class: str
    resource_role: str
    resource_type: str | None
    parent_resource_type: str | None
    ownership_state: str
    confidence: str
    evidence: list[str]
    counterevidence: list[str]
    sources: list[str]
    explanation: str


class HypothesisExplanation(McpModel):
    """Why a hypothesis is retained, distinct, and ready or blocked."""

    mutation_target: MutationTargetSummary
    identifier_semantics: IdentifierSemanticsSummary
    readiness_reasons: list[str]
    missing_prerequisites: list[str]
    comparison_coverage: ComparisonCoverage
    retention_reasons: list[str]
    difference_reasons: list[str]
    similar_hypothesis_ids: list[str]


class HypothesisSummary(McpModel):
    """Stable backlog item summary."""

    id: str
    kind: str
    title: str
    member_title: str
    campaign_title: str | None = None
    category: str
    priority: str
    score: int
    lifecycle_status: str
    evidence_status: str
    disposition: str
    readiness: str
    protected_subject: str
    operation: str
    visibility: str
    binding: str
    cluster_id: str | None = None
    campaign_id: str | None = None
    relationship: str
    explanation: HypothesisExplanation


class HypothesisList(McpModel):
    """Filtered hypothesis collection with priority semantics."""

    active_only: bool
    include_research_tasks: bool
    priority_interpretation: str
    hypotheses: list[HypothesisSummary]


class ObservationContext(McpModel):
    """Sanitized factual observation context."""

    id: str
    knowledge_status: Literal["OBSERVED"] = "OBSERVED"
    source_type: str
    actor: str
    channel: str
    host: str
    method: str
    path: str
    query_parameter_names: list[str]
    request_fields: list[str]
    response_fields: list[str]
    status_code: int | None
    content_type: str | None
    authentication: AuthenticationMetadata


class EndpointParameterContext(McpModel):
    """Safe endpoint parameter metadata without examples or concrete values."""

    name: str
    location: str
    json_path: str | None = None
    inferred_type: str
    semantic_type: str
    client_controlled: bool
    knowledge_status: str
    evidence: list[str]
    identifier_semantic_class: str
    identifier_resource_role: str
    ownership_state: str
    semantic_confidence: str
    semantic_evidence: list[str]
    semantic_counterevidence: list[str]
    semantic_explanation: str


class ObjectAccessContext(McpModel):
    """Aggregate object-boundary evidence without concrete identifiers."""

    identifier: str
    parameter_location: str | None = None
    parameter_json_path: str | None = None
    source: str
    confidence: str
    owner_field_path: str | None
    scope_parameter: str | None
    distinct_actors: int
    distinct_objects: int
    distinct_owner_values: int
    distinct_scope_values: int
    actor_object_binding_observed: bool
    observations: list[str]


class OwnershipInferenceContext(McpModel):
    """Sanitized reason for applying or rejecting parent-scope ownership inference."""

    parameter: str
    classification: str
    status: str
    controlled_actors: int
    distinct_scope_values: int
    observations: list[str]
    reasons: list[str]


class EndpointContext(McpModel):
    """Sanitized inferred endpoint context."""

    id: str
    knowledge_status: Literal["INFERRED"] = "INFERRED"
    method: str
    path: str
    hosts: list[str]
    channels: list[str]
    classification: str
    resource: str
    action: str
    state_change: bool
    authentication_required: bool
    authentication_type: str
    parameters: list[EndpointParameterContext]
    object_access: list[ObjectAccessContext]
    ownership_inference: list[OwnershipInferenceContext]
    sources: list[str]
    disposition: str


class InvariantContext(McpModel):
    """Expected property linked to its evidence."""

    id: str
    knowledge_status: str
    category: str
    statement: str
    resources: list[str]
    endpoints: list[str]
    evidence: list[str]
    confidence: str
    validation_status: str
    disposition: str


class ExecutionResponseContext(McpModel):
    """Body-free response facts from one bounded execution request."""

    request_id: str
    status_code: int | None
    content_type: str | None
    response_length: int
    json_paths: list[str]
    requested_object_present: bool
    returned_object_present: bool
    requested_returned_match: bool | None
    owner_fingerprint_present: bool
    resource_item_count: int | None
    redirect_observed: bool
    error_class: str | None


class ExecutionSummary(McpModel):
    """Safe execution and comparison history."""

    revision: str
    plan_id: str
    status: str
    outcome: str
    actor_labels: list[str]
    request_count: int
    methods: list[str]
    hosts: list[str]
    paths: list[str]
    mutation_dimensions: list[str]
    authentication: AuthenticationMetadata
    tested_branch: TestedBranch
    authorization_boundary_tested: bool
    baseline: ExecutionResponseContext | None = None
    comparison: ExecutionResponseContext | None = None
    reasons: list[str] = Field(default_factory=list)
    interpretation: list[str] = Field(default_factory=list)


class EvidenceArtifactSummary(McpModel):
    """Artifact index metadata without source names, paths, or content."""

    id: str
    kind: str
    sha256: str
    redaction: str
    description: str | None = None


class AssessmentProgress(McpModel):
    """Evidence checklist completion counts."""

    answered: int
    total: int
    true: int
    false: int
    unknown: int


class ValidationSummary(McpModel):
    """Safe persisted validation result."""

    disposition: str
    summary: str
    missing_requirements: list[str]
    report_ready: bool
    unresolved_check_ids: list[str]


class EvidenceSummary(McpModel):
    """Safe evidence metadata and conclusion state for one hypothesis."""

    hypothesis_id: str
    evidence_exists: bool
    test_id: str | None
    artifact_count: int
    artifacts: list[EvidenceArtifactSummary]
    assessment: AssessmentProgress
    narrative_fields_completed: list[str]
    narrative_fields_missing: list[str]
    validation: ValidationSummary | None = None
    notes: str | None = None


class HypothesisClaims(McpModel):
    """Sanitized hypothesis assertions and evidence gaps."""

    hypothesis: str
    reasoning: str
    preconditions: list[str]
    expected_secure_behavior: str
    possible_vulnerable_behavior: str
    required_state: list[str]
    attacker_capability: list[str]
    mutation_dimensions: list[str]
    eligibility_evidence: list[str]
    missing_evidence: list[str]
    safety_notes: list[str]
    domain_ambiguity: list[str]
    claim_strength_current: str
    claim_strength_target: str
    readiness_blockers: list[str]
    approval_and_execution_gates: list[str]


class HypothesisContext(McpModel):
    """Evidence-linked, sanitized review context for one hypothesis."""

    hypothesis: HypothesisSummary
    claims: HypothesisClaims
    source_ids: dict[str, list[str]]
    potential_impact: dict[str, str]
    endpoints: list[EndpointContext]
    invariants: list[InvariantContext]
    observations: list[ObservationContext]
    executions: list[ExecutionSummary]
    evidence: EvidenceSummary
    scope_constraints: dict[str, object]
    credential_fidelity: CredentialFidelity
    authentication_state_counts: AuthenticationStateCounts
    knowledge_legend: dict[str, str]
    interpretation_rules: list[str]
    untrusted_data_notice: str
