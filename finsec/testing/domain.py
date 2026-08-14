"""Typed safe test-plan and policy-decision models."""

from datetime import datetime
from typing import Literal

from pydantic import Field

from finsec.hypotheses.contracts import (
    HypothesisReadinessAssessment,
    MutationTargetAssessment,
    ReadinessIssue,
)
from finsec.modeling.domain import EditableModel, GenerationMetadata


class RiskClassification(EditableModel):
    """Static safety classification; it never grants execution authority."""

    destructive: bool
    financial: bool
    affects_external_user: bool
    concurrency: bool
    request_budget: int = Field(ge=0, le=10)
    decision: Literal["BLOCKED", "REQUIRES_HUMAN_APPROVAL"]
    reasons: list[str] = Field(default_factory=list)


class PlanAccounts(EditableModel):
    """Researcher-controlled account labels assigned to the experiment."""

    object_owner: str | None = None
    actor: str | None = None


ExecutionPattern = Literal[
    "OBJECT_SUBSTITUTION",
    "AUTHENTICATION_COMPARISON",
    "VERSION_COMPARISON",
    "CHANNEL_COMPARISON",
    "UNSUPPORTED",
]
PlanMutationDimension = Literal["OBJECT", "AUTHENTICATION", "VERSION", "CHANNEL"]


class RuntimeSecretReference(EditableModel):
    """Reference one runtime-only secret without persisting its value."""

    header: str
    source: Literal["actor_store", "environment"] = "environment"
    reference: str | None = None
    variable: str | None = None
    actor: str | None = None


class PlanActorAuthentication(EditableModel):
    """Non-secret binding between a reviewed plan and an actor credential profile."""

    actor: str
    credential_profile_ref: str
    required_status: Literal["READY"] = "READY"
    context_fingerprint: str | None = None


class RequestExpectation(EditableModel):
    """Passive identity evidence required before a bounded comparison proceeds."""

    ownership_source: (
        Literal["RESPONSE_BODY", "PATH_PARENT_SCOPE", "CONTROLLED_LIFECYCLE"] | None
    ) = None
    scope_parameter: str | None = None
    nonempty_json_required: bool = False
    object_path: str | None = None
    object_value: str | None = None
    owner_path: str | None = None
    owner_fingerprint: str | None = None
    baseline_id: str | None = None
    subject_resource_id: str | None = None
    parent_resource_id: str | None = None
    relationship_ids: list[str] = Field(default_factory=list)


class RequestMutation(EditableModel):
    """One explicitly bounded difference from a reviewed baseline request."""

    dimension: PlanMutationDimension
    location: Literal["path", "header", "route", "channel"]
    parameter: str
    from_value: str
    to_value: str | None = None
    source_actor: str | None = None
    target_actor: str | None = None
    source_resource_id: str | None = None
    target_resource_id: str | None = None
    source_parent_resource_id: str | None = None
    target_parent_resource_id: str | None = None
    substitution_scope: (
        Literal[
            "SUBJECT_ONLY",
            "PARENT_ONLY",
            "SUBJECT_AND_PARENT",
            "TENANT",
        ]
        | None
    ) = None


class StructuredRequest(EditableModel):
    """A complete redacted request template generated from passive observations."""

    id: str
    role: Literal["BASELINE", "MUTATED", "COMPARISON"]
    clone_of: str | None = None
    method: Literal["GET", "HEAD"]
    scheme: Literal["http", "https"]
    host: str
    port: int | None = Field(default=None, ge=1, le=65535)
    path: str
    query_parameters: dict[str, list[str]] = Field(default_factory=dict)
    headers: dict[str, str] = Field(default_factory=dict)
    runtime_secrets: list[RuntimeSecretReference] = Field(default_factory=list)
    remove_headers: list[str] = Field(default_factory=list)
    body: None = None
    actor: str
    channel: str = "UNKNOWN"
    mutations: list[RequestMutation] = Field(default_factory=list)
    expected: RequestExpectation = Field(default_factory=RequestExpectation)


class PlanExecutionConfig(EditableModel):
    """Generated bounded-execution policy; unsupported plans remain manual."""

    supported: bool = False
    pattern: ExecutionPattern = "UNSUPPORTED"
    blockers: list[str] = Field(default_factory=list)
    request_budget: int = Field(default=0, ge=0, le=10)
    parallelism: int = Field(default=1, ge=1, le=1)
    mutation_dimensions: list[PlanMutationDimension] = Field(default_factory=list)
    follow_redirects: Literal[False] = False
    tls_verification: Literal[True] = True
    connection_timeout_seconds: float = Field(default=5.0, gt=0, le=30)
    read_timeout_seconds: float = Field(default=10.0, gt=0, le=60)
    maximum_response_bytes: int = Field(default=2 * 1024 * 1024, ge=1024, le=10 * 1024 * 1024)
    stop_conditions: list[str] = Field(default_factory=list)


class PlanApproval(EditableModel):
    """Human approval bound to one exact plan and target-policy snapshot."""

    enabled: Literal[True] = True
    approved_by: str
    approved_at: datetime
    plan_checksum: str
    target_policy_checksum: str
    approval_token_sha256: str | None = None


class TestPlanRecord(EditableModel):
    """A non-executing controlled experiment for one hypothesis."""

    id: str
    key: str
    hypothesis_id: str
    purpose: str
    risk: RiskClassification
    accounts: PlanAccounts
    preconditions: list[str]
    setup: list[str]
    actions: list[str]
    secure_assertions: list[str]
    interesting_behavior: list[str]
    evidence_to_capture: list[str]
    stop_conditions: list[str]
    cleanup: list[str]
    requests: list[StructuredRequest] = Field(default_factory=list)
    authentication: list[PlanActorAuthentication] = Field(default_factory=list)
    execution: PlanExecutionConfig = Field(default_factory=PlanExecutionConfig)
    mutation_target: MutationTargetAssessment = Field(default_factory=MutationTargetAssessment)
    readiness_assessment: HypothesisReadinessAssessment = Field(
        default_factory=HypothesisReadinessAssessment
    )
    planning_blockers: list[ReadinessIssue] = Field(default_factory=list)
    readiness_consistent: bool = True
    readiness_invariant_violation: str | None = None
    human_approval_required: bool = True
    execution_default: Literal["DO_NOT_EXECUTE"] = "DO_NOT_EXECUTE"
    approval_status: Literal["NOT_REQUESTED", "APPROVED", "REJECTED"] = "NOT_REQUESTED"
    approval: PlanApproval | None = None
    status: Literal["BLOCKED", "READY_FOR_REVIEW"]
    notes: str | None = None
    generation: GenerationMetadata | None = None


class TestPlanStore(EditableModel):
    """Versioned collection of safe plans."""

    version: int = 1
    plans: list[TestPlanRecord] = Field(default_factory=list)
