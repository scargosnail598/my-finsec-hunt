"""Serializable contracts for canonical workspace readiness."""

from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class ReadinessModel(BaseModel):
    """Reject accidental drift in public readiness responses."""

    model_config = ConfigDict(extra="forbid")


class PipelineStage(StrEnum):
    """The canonical FinSec Hunt pipeline stages in display order."""

    SETUP = "setup"
    AUTH = "auth"
    INGEST = "ingest"
    CLASSIFY = "classify"
    NORMALIZE = "normalize"
    MODEL = "model"
    INVARIANTS = "invariants"
    HYPOTHESIZE = "hypothesize"
    PLAN = "plan"
    EXECUTE = "execute"
    VALIDATE = "validate"
    REPORT = "report"


class LifecycleStatus(StrEnum):
    """Lifecycle state kept separate from interface capability metadata."""

    NOT_CONFIGURED = "NOT_CONFIGURED"
    BLOCKED = "BLOCKED"
    READY = "READY"
    COMPLETE = "COMPLETE"
    STALE = "STALE"


class BlockerCode(StrEnum):
    """Stable reason codes used by CLI, Web, MCP, and tests."""

    WORKSPACE_NOT_CONFIGURED = "WORKSPACE_NOT_CONFIGURED"
    TARGET_NOT_CONFIGURED = "TARGET_NOT_CONFIGURED"
    NO_OBSERVATIONS = "NO_OBSERVATIONS"
    ARTIFACT_MISSING = "ARTIFACT_MISSING"
    ARTIFACT_MALFORMED = "ARTIFACT_MALFORMED"
    ARTIFACT_SCHEMA_INCOMPATIBLE = "ARTIFACT_SCHEMA_INCOMPATIBLE"
    ARTIFACT_PROVENANCE_MISSING = "ARTIFACT_PROVENANCE_MISSING"
    ARTIFACT_INTEGRITY_FAILURE = "ARTIFACT_INTEGRITY_FAILURE"
    UPSTREAM_DEPENDENCY_CHANGED = "UPSTREAM_DEPENDENCY_CHANGED"
    UPSTREAM_STAGE_BLOCKED = "UPSTREAM_STAGE_BLOCKED"
    NO_ACTOR_CREDENTIAL = "NO_ACTOR_CREDENTIAL"
    CREDENTIAL_EXPIRED = "CREDENTIAL_EXPIRED"
    CREDENTIAL_EXPIRATION_UNKNOWN = "CREDENTIAL_EXPIRATION_UNKNOWN"
    CREDENTIAL_UNUSABLE = "CREDENTIAL_UNUSABLE"
    CREDENTIAL_NOT_ACCEPTED = "CREDENTIAL_NOT_ACCEPTED"
    TARGET_VALIDATION_MISSING = "TARGET_VALIDATION_MISSING"
    ACTOR_IDENTITY_NOT_CONFIRMED = "ACTOR_IDENTITY_NOT_CONFIRMED"
    INSUFFICIENT_CONTROLLED_ACTORS = "INSUFFICIENT_CONTROLLED_ACTORS"
    OWNERSHIP_BASELINES_MISSING = "OWNERSHIP_BASELINES_MISSING"
    OWNERSHIP_BASELINE_STALE = "OWNERSHIP_BASELINE_STALE"
    OWNERSHIP_BASELINE_CONFLICTING = "OWNERSHIP_BASELINE_CONFLICTING"
    NO_ELIGIBLE_HYPOTHESIS = "NO_ELIGIBLE_HYPOTHESIS"
    HYPOTHESIS_REQUIRES_MORE_EVIDENCE = "HYPOTHESIS_REQUIRES_MORE_EVIDENCE"
    PLAN_MISSING = "PLAN_MISSING"
    PLAN_STALE = "PLAN_STALE"
    PLAN_REQUEST_BUDGET_MISMATCH = "PLAN_REQUEST_BUDGET_MISMATCH"
    PLAN_POLICY_BLOCKED = "PLAN_POLICY_BLOCKED"
    HUMAN_APPROVAL_MISSING = "HUMAN_APPROVAL_MISSING"
    APPROVAL_STALE = "APPROVAL_STALE"
    ACTIVE_EXECUTION_DISABLED = "ACTIVE_EXECUTION_DISABLED"
    READ_ONLY_POLICY_CONFLICT = "READ_ONLY_POLICY_CONFLICT"
    DESTINATION_SCOPE_VALIDATION_FAILURE = "DESTINATION_SCOPE_VALIDATION_FAILURE"
    EVIDENCE_MISSING = "EVIDENCE_MISSING"
    BEFORE_AFTER_STATE_EVIDENCE_MISSING = "BEFORE_AFTER_STATE_EVIDENCE_MISSING"
    NO_CONFIRMED_VULNERABILITY = "NO_CONFIRMED_VULNERABILITY"


class BlockerScope(ReadinessModel):
    """Optional scope for one reason without sensitive request data."""

    workspace: str | None = None
    actor_ids: list[str] = Field(default_factory=list)
    hypothesis_id: str | None = None
    plan_id: str | None = None
    evidence_set_id: str | None = None
    artifact: str | None = None


class ReadinessEvidence(ReadinessModel):
    """Small numeric or boolean evidence facts safe for presentation."""

    required: int | None = None
    confirmed: int | None = None
    expected: str | None = None
    actual: str | None = None


class NextAction(ReadinessModel):
    """A concrete remediation step separated from readiness calculation."""

    type: Literal["cli_command", "manual"]
    label: str
    command: str | None = None
    safety: Literal["safe_to_automate", "requires_review", "requires_human_approval"]


class ReadinessBlocker(ReadinessModel):
    """Machine-readable reason with deterministic remediation metadata."""

    code: BlockerCode
    stage: PipelineStage
    severity: Literal["error", "warning"]
    scope: BlockerScope = Field(default_factory=BlockerScope)
    summary: str
    details: str | None = None
    evidence: ReadinessEvidence | None = None
    next_actions: list[NextAction] = Field(default_factory=list)


class ArtifactReadiness(ReadinessModel):
    """Validity and provenance state for one non-secret workspace artifact."""

    name: str
    path: str
    exists: bool
    valid: bool
    stale: bool = False
    schema_version: int | None = None
    provenance: Literal[
        "NOT_APPLICABLE",
        "MISSING",
        "CURRENT",
        "STALE",
        "LEGACY_UNKNOWN",
        "MALFORMED",
    ] = "NOT_APPLICABLE"


class CredentialReadiness(ReadinessModel):
    """Credential metadata without references or values."""

    available: bool
    type: str
    accepted: bool = False
    status: str = "UNKNOWN"
    expiration: Literal["valid", "expiring_soon", "expired", "unknown", "not_applicable"]
    locally_usable: bool


class TargetValidationReadiness(ReadinessModel):
    """Whether a target-side authentication validation was recorded."""

    recorded: bool


class IdentityConfirmationReadiness(ReadinessModel):
    """Whether the validated baseline matched the intended controlled actor."""

    confirmed: bool


class OwnershipReadiness(ReadinessModel):
    """Per-actor baseline presence for the report's focused hypothesis."""

    required_baselines: int = 1
    confirmed_baselines: int = 0
    hypothesis_id: str | None = None
    resource_type: str | None = None


class FocusedComparisonReadiness(ReadinessModel):
    """Hypothesis-level comparison coverage displayed alongside actor baseline presence."""

    hypothesis_id: str
    resource_type: str | None = None
    parent_resource_type: str | None = None
    required_distinct_actors: int = 0
    observed_distinct_actors: int = 0
    distinct_controlled_objects: int = 0
    distinct_parent_references: int = 0
    baseline_actor_ids: list[str] = Field(default_factory=list)
    missing_actor_ids: list[str] = Field(default_factory=list)
    parent_references: list[str] = Field(default_factory=list)
    target_parent_baseline_reference: str | None = None
    comparison_baseline_references: list[str] = Field(default_factory=list)
    evidence_references: list[str] = Field(default_factory=list)
    cross_parent_comparison: bool = False
    explanation: str = "No cross-actor comparison coverage is required."


class ActorCapabilities(ReadinessModel):
    """Actor capabilities derived from separate readiness dimensions."""

    offline_analysis: bool = True
    planning: bool
    authorization_execution: bool


class ActorReadiness(ReadinessModel):
    """Secret-free readiness dimensions for one configured actor."""

    actor_id: str
    credential: CredentialReadiness
    target_validation: TargetValidationReadiness
    identity_confirmation: IdentityConfirmationReadiness
    ownership: OwnershipReadiness
    capabilities: ActorCapabilities


class StageReadiness(ReadinessModel):
    """Canonical readiness result for one pipeline stage."""

    id: PipelineStage
    status: LifecycleStatus
    summary: str
    dependencies: list[PipelineStage] = Field(default_factory=list)
    artifacts: list[ArtifactReadiness] = Field(default_factory=list)
    blockers: list[ReadinessBlocker] = Field(default_factory=list)
    warnings: list[ReadinessBlocker] = Field(default_factory=list)
    available_via: list[Literal["cli", "web", "mcp"]] = Field(default_factory=list)
    web_action_available: bool = False
    result_count: int = 0
    next_actions: list[NextAction] = Field(default_factory=list)


class OverallReadiness(ReadinessModel):
    """Aggregated label that never hides stage-specific reasons."""

    status: LifecycleStatus
    next_stage: PipelineStage | None = None


class ReadinessMetrics(ReadinessModel):
    """Deterministic counts retained for compatibility presentation."""

    observations: int = 0
    endpoints: int = 0
    suppressed_endpoints: int = 0
    graphql_operations: int = 0
    mobile_discoveries: int = 0
    actors: int = 0
    resources: int = 0
    workflows: int = 0
    workflow_instances: int = 0
    workflow_families: int = 0
    inferred_states: int = 0
    observed_transitions: int = 0
    invariants: int = 0
    business_invariants: int = 0
    active_hypotheses: int = 0
    research_tasks: int = 0
    raw_active_hypotheses: int = 0
    raw_research_tasks: int = 0
    logic_hypotheses: int = 0
    logic_research_tasks: int = 0
    plans: int = 0
    current_ready_plans: int = 0
    current_blocked_plans: int = 0
    stale_plans: int = 0
    executions: int = 0
    evidence_sets: int = 0
    validations: int = 0
    reports: int = 0
    hypotheses_not_tested: int = 0
    hypotheses_test_planned: int = 0
    hypotheses_refuted: int = 0
    hypotheses_needs_evidence: int = 0
    hypotheses_confirmed: int = 0


class ReadinessContext(ReadinessModel):
    """Optional capability overrides for a presentation adapter."""

    available_via: dict[PipelineStage, list[Literal["cli", "web", "mcp"]]] = Field(
        default_factory=dict
    )
    web_actions: dict[PipelineStage, bool] = Field(default_factory=dict)


class ReadinessReport(ReadinessModel):
    """Canonical, deterministic, credential-free workspace report."""

    workspace: str
    engine_version: Literal[1] = 1
    overall: OverallReadiness
    stages: list[StageReadiness]
    actors: list[ActorReadiness] = Field(default_factory=list)
    focused_comparison: FocusedComparisonReadiness | None = None
    metrics: ReadinessMetrics = Field(default_factory=ReadinessMetrics)
    next_actions: list[NextAction] = Field(default_factory=list)


PIPELINE_ORDER = tuple(PipelineStage)
