"""Typed execution, comparison, and append-only audit records."""

from datetime import datetime
from typing import Any, Literal

from pydantic import Field

from finsec.modeling.domain import EditableModel

ExecutionStatus = Literal[
    "NOT_EXECUTED",
    "DRY_RUN_COMPLETE",
    "EXECUTION_APPROVED",
    "RUNNING",
    "COMPLETED",
    "INCONCLUSIVE",
    "STOPPED",
    "FAILED",
]
ExecutionOutcome = Literal[
    "CROSS_OBJECT_RESPONSE_OBSERVED",
    "CROSS_SCOPE_RESPONSE_OBSERVED",
    "NO_CROSS_OBJECT_ACCESS",
    "AUTHENTICATION_ENFORCED",
    "ANONYMOUS_RESPONSE_OBSERVED",
    "COMPARISON_OBSERVED",
    "INCONCLUSIVE",
    "BASELINE_FAILED",
    "BASELINE_AUTH_FAILED",
    "BASELINE_AUTHORIZATION_DENIED",
    "BASELINE_MISMATCH",
    "TEST_BLOCKED_BY_AUTH",
    "OUT_OF_SCOPE_REDIRECT",
    "RESPONSE_SIZE_EXCEEDED",
    "STOPPED_BY_POLICY",
    "INTERRUPTED",
    "TRANSPORT_FAILED",
]


class ExecutionResponseSummary(EditableModel):
    """Redacted response facts retained for conservative comparison."""

    request_id: str
    status_code: int | None = None
    content_type: str | None = None
    response_length: int = 0
    json_paths: list[str] = Field(default_factory=list)
    requested_object_id: str | None = None
    returned_object_id: str | None = None
    owner_fingerprint: str | None = None
    resource_item_count: int | None = None
    redirect_location: str | None = None
    error_class: str | None = None
    authentication_signal: str | None = None


class ExecutionComparison(EditableModel):
    """Machine-produced observations that still require skeptical validation."""

    outcome: ExecutionOutcome
    baseline: ExecutionResponseSummary | None = None
    comparison: ExecutionResponseSummary | None = None
    reasons: list[str] = Field(default_factory=list)


class EvidenceHash(EditableModel):
    """Integrity record for one generated redacted artifact."""

    path: str
    sha256: str


class ExecutionAuditRecord(EditableModel):
    """One immutable bounded-execution revision."""

    version: int = 1
    hypothesis_id: str
    plan_id: str
    plan_checksum: str
    target_policy_checksum: str
    started_at: datetime
    completed_at: datetime
    status: ExecutionStatus
    outcome: ExecutionOutcome
    actor_labels: list[str] = Field(default_factory=list)
    request_count: int = Field(default=0, ge=0)
    methods: list[str] = Field(default_factory=list)
    hosts: list[str] = Field(default_factory=list)
    paths: list[str] = Field(default_factory=list)
    mutation_dimensions: list[str] = Field(default_factory=list)
    stop_conditions: list[str] = Field(default_factory=list)
    evidence: list[EvidenceHash] = Field(default_factory=list)
    tool_version: str
    notes: list[str] = Field(default_factory=list)
    authentication_events: list[dict[str, Any]] = Field(default_factory=list)
