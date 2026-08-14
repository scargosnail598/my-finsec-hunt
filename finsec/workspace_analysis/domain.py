"""Typed contracts for preliminary workspace analysis reports."""

from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from finsec.behavior.domain import (
    BusinessInvariant,
    HypothesisCluster,
    LogicHypothesis,
    MutationRejection,
    PropagationLink,
    StateRecord,
    TransitionRecord,
    WorkflowFamily,
    WorkflowInstance,
)
from finsec.captures.domain import Capture
from finsec.config.models import TargetDocument
from finsec.hypotheses.contracts import HypothesisCampaign
from finsec.hypotheses.domain import HypothesisRecord
from finsec.modeling.domain import ActorRecord, InvariantRecord, ResourceRecord
from finsec.modeling.models import Endpoint, Observation
from finsec.modeling.relationships import ControlledOwnershipStore
from finsec.readiness.domain import ReadinessReport
from finsec.testing.domain import TestPlanRecord
from finsec.validation.domain import ValidationRecord


class WorkspaceAnalysisModel(BaseModel):
    """Reject accidental drift in workspace-report contracts."""

    model_config = ConfigDict(extra="forbid")


class WorkspaceAnalysisMode(StrEnum):
    """Regeneration policy selected for one report run."""

    DEFAULT = "default"
    REPORT_ONLY = "report-only"
    FORCE = "force"


class WorkspaceAnalysisStageStatus(StrEnum):
    """Outcome of one logical safe offline stage."""

    SUCCESS = "SUCCESS"
    WARNING = "WARNING"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"


class WorkspaceAnalysisStage(WorkspaceAnalysisModel):
    """Central registry entry for one actual application-service boundary."""

    stage_id: str
    display_name: str
    conceptual_stages: list[str] = Field(default_factory=list)
    required: bool
    prerequisites: list[str] = Field(default_factory=list)
    inputs: list[str] = Field(default_factory=list)
    outputs: list[str] = Field(default_factory=list)
    safe_offline: Literal[True] = True
    service_name: str
    freshness_condition: str
    failure_allows_continue: bool = True


StageMetric = int | float | str | bool


class WorkspaceAnalysisStageResult(WorkspaceAnalysisModel):
    """Sanitized execution result retained even when a report is partial."""

    stage_id: str
    display_name: str
    status: WorkspaceAnalysisStageStatus
    required: bool
    prerequisites: list[str] = Field(default_factory=list)
    started_at: datetime
    finished_at: datetime
    duration: float = Field(ge=0)
    inputs: list[str] = Field(default_factory=list)
    outputs: list[str] = Field(default_factory=list)
    metrics: dict[str, StageMetric] = Field(default_factory=dict)
    warnings: list[str] = Field(default_factory=list)
    error_summary: str | None = None
    diagnostic_output: str | None = None
    required_data_available: bool = True


class WorkspaceAnalysisMetadata(WorkspaceAnalysisModel):
    """Secret-free report provenance and workspace policy metadata."""

    workspace_name: str
    workspace_path: str
    generated_at: datetime
    timezone: str
    finsec_version: str
    git_commit: str | None = None
    mode: WorkspaceAnalysisMode
    target_hosts: list[str] = Field(default_factory=list)
    environment_type: str
    safety_policy_summary: str
    active_execution_policy: str
    human_approval_policy: str
    configuration_warnings: list[str] = Field(default_factory=list)


class WorkspaceAnalysisMetrics(WorkspaceAnalysisModel):
    """Deterministic counts used by both Markdown and terminal summaries."""

    captures: int = 0
    observations: int = 0
    endpoint_families: int = 0
    suppressed_endpoints: int = 0
    actors: int = 0
    authenticated_actors: int = 0
    ownership_baselines: int = 0
    resources: int = 0
    workflow_instances: int = 0
    workflow_families: int = 0
    active_invariants: int = 0
    visible_hypotheses: int = 0
    active_hypotheses: int = 0
    hyp_hypotheses: int = 0
    blh_hypotheses: int = 0
    research_tasks: int = 0
    suppressed_hypotheses: int = 0
    campaigns: int = 0
    test_ready: int = 0
    review_required: int = 0
    research_only: int = 0
    planned_hypotheses: int = 0
    tested_hypotheses: int = 0
    confirmed_hypotheses: int = 0
    rejected_hypotheses: int = 0


class WorkspaceNextAction(WorkspaceAnalysisModel):
    """One deterministic recommendation that never performs an active operation."""

    action_id: str
    priority: Literal["P1", "P2", "P3"]
    title: str
    why: str
    affected: list[str] = Field(default_factory=list)
    expected_evidence: str
    classification: Literal["PASSIVE", "REVIEW", "ACTIVE_REQUIRES_APPROVAL"]
    prerequisite: str | None = None
    command: str | None = None


class WorkspaceArtifactIndexEntry(WorkspaceAnalysisModel):
    """One report-linked workspace artifact, whether present or optional."""

    label: str
    path: Path
    exists: bool
    required: bool
    description: str


class WorkspaceAnalysisReportModel(WorkspaceAnalysisModel):
    """Complete typed input to the Markdown renderer."""

    metadata: WorkspaceAnalysisMetadata
    include_suppressed: bool = True
    assessment: str
    primary_blocker: str | None = None
    metrics: WorkspaceAnalysisMetrics
    stages: list[WorkspaceAnalysisStageResult]
    target: TargetDocument | None = None
    captures: list[Capture] = Field(default_factory=list)
    observations: list[Observation] = Field(default_factory=list)
    endpoints: list[Endpoint] = Field(default_factory=list)
    actors: list[ActorRecord] = Field(default_factory=list)
    resources: list[ResourceRecord] = Field(default_factory=list)
    ownership: ControlledOwnershipStore = Field(default_factory=ControlledOwnershipStore)
    workflow_instances: list[WorkflowInstance] = Field(default_factory=list)
    workflow_families: list[WorkflowFamily] = Field(default_factory=list)
    states: list[StateRecord] = Field(default_factory=list)
    transitions: list[TransitionRecord] = Field(default_factory=list)
    propagation_links: list[PropagationLink] = Field(default_factory=list)
    invariants: list[InvariantRecord] = Field(default_factory=list)
    business_invariants: list[BusinessInvariant] = Field(default_factory=list)
    hypotheses: list[HypothesisRecord] = Field(default_factory=list)
    campaigns: list[HypothesisCampaign] = Field(default_factory=list)
    logic_hypotheses: list[LogicHypothesis] = Field(default_factory=list)
    logic_clusters: list[HypothesisCluster] = Field(default_factory=list)
    mutation_rejections: list[MutationRejection] = Field(default_factory=list)
    plans: list[TestPlanRecord] = Field(default_factory=list)
    validations: list[ValidationRecord] = Field(default_factory=list)
    readiness: ReadinessReport | None = None
    next_actions: list[WorkspaceNextAction] = Field(default_factory=list)
    artifacts: list[WorkspaceArtifactIndexEntry] = Field(default_factory=list)
    confirmed_report_paths: list[Path] = Field(default_factory=list)
    unavailable_sections: dict[str, str] = Field(default_factory=dict)
    warnings: list[str] = Field(default_factory=list)


class WorkspaceAnalysisRunResult(WorkspaceAnalysisModel):
    """Final command result after an atomic Markdown write."""

    path: Path
    report: WorkspaceAnalysisReportModel
    strict_failure: bool = False
    partial: bool = False
