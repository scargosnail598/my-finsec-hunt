"""Typed safe test-plan and policy-decision models."""

from typing import Literal

from pydantic import Field

from finsec.modeling.domain import EditableModel, GenerationMetadata


class RiskClassification(EditableModel):
    """Static safety classification; it never grants execution authority."""

    destructive: bool
    financial: bool
    affects_external_user: bool
    concurrency: bool
    request_budget: int = Field(ge=0, le=3)
    decision: Literal["BLOCKED", "REQUIRES_HUMAN_APPROVAL"]
    reasons: list[str] = Field(default_factory=list)


class PlanAccounts(EditableModel):
    """Researcher-controlled account labels assigned to the experiment."""

    object_owner: str | None = None
    actor: str | None = None


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
    human_approval_required: bool = True
    execution_default: Literal["DO_NOT_EXECUTE"] = "DO_NOT_EXECUTE"
    approval_status: Literal["NOT_REQUESTED", "APPROVED", "REJECTED"] = "NOT_REQUESTED"
    status: Literal["BLOCKED", "READY_FOR_REVIEW"]
    notes: str | None = None
    generation: GenerationMetadata | None = None


class TestPlanStore(EditableModel):
    """Versioned collection of safe plans."""

    version: int = 1
    plans: list[TestPlanRecord] = Field(default_factory=list)
