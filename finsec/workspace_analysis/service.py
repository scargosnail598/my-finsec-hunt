"""Safe typed orchestration for post-ingest workspace analysis reports."""

from __future__ import annotations

import os
import shlex
import subprocess
import tempfile
import traceback
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from time import monotonic
from typing import TypeVar

import yaml
from pydantic import BaseModel, ValidationError

from finsec import __version__
from finsec.behavior.analysis import analyze_business_logic
from finsec.behavior.domain import (
    ActionStore,
    BusinessInvariantStore,
    LogicHypothesisStore,
    PropagationStore,
    ResourceInstanceStore,
    StateStore,
    TransitionStore,
    WorkflowFamilyStore,
    WorkflowInstanceStore,
)
from finsec.captures.domain import Capture
from finsec.captures.service import list_captures
from finsec.config.models import TargetDocument
from finsec.config.workspace import WorkspacePaths
from finsec.errors import FinsecError
from finsec.hypotheses.clustering import presentation_visible
from finsec.hypotheses.domain import HypothesisStore
from finsec.hypotheses.generator import generate_hypotheses
from finsec.hypotheses.population import hypothesis_population
from finsec.modeling.domain import ActorStore, InvariantStore, ResourceStore
from finsec.modeling.generator import generate_model
from finsec.modeling.invariants import generate_invariants
from finsec.modeling.models import EndpointStore, ObservationStore
from finsec.modeling.relationships import ControlledOwnershipStore, load_controlled_ownership
from finsec.normalization.inventory import build_inventory
from finsec.readiness.domain import LifecycleStatus, PipelineStage, ReadinessReport
from finsec.readiness.resolver import resolve_workspace_readiness
from finsec.testing.domain import TestPlanStore
from finsec.utils.yaml_store import load_yaml
from finsec.validation.domain import ValidationStore
from finsec.workspace_analysis.domain import (
    StageMetric,
    WorkspaceAnalysisMetadata,
    WorkspaceAnalysisMetrics,
    WorkspaceAnalysisMode,
    WorkspaceAnalysisReportModel,
    WorkspaceAnalysisRunResult,
    WorkspaceAnalysisStage,
    WorkspaceAnalysisStageResult,
    WorkspaceAnalysisStageStatus,
    WorkspaceArtifactIndexEntry,
    WorkspaceNextAction,
)
from finsec.workspace_analysis.redaction import WorkspaceAnalysisRedactor
from finsec.workspace_analysis.rendering import WorkspaceAnalysisMarkdownRenderer
from finsec.workspace_analysis.stages import WORKSPACE_ANALYSIS_STAGES

MODEL_T = TypeVar("MODEL_T", bound=BaseModel)


@dataclass
class _StagePayload:
    status: WorkspaceAnalysisStageStatus = WorkspaceAnalysisStageStatus.SUCCESS
    metrics: dict[str, StageMetric] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    error_summary: str | None = None
    diagnostic_output: str | None = None
    required_data_available: bool = True


class WorkspaceAnalysisOrchestrator:
    """Run only deterministic offline stages and render one preliminary report."""

    def __init__(
        self,
        workspace: WorkspacePaths,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.workspace = workspace
        self._clock = clock or (lambda: datetime.now(UTC))
        self._redactor = WorkspaceAnalysisRedactor()
        self._stage_results: list[WorkspaceAnalysisStageResult] = []
        self._result_by_id: dict[str, WorkspaceAnalysisStageResult] = {}
        self._target: TargetDocument | None = None
        self._observations: ObservationStore | None = None
        self._readiness: ReadinessReport | None = None
        self._unavailable: dict[str, str] = {}
        self._collection_warnings: list[str] = []
        self._mode = WorkspaceAnalysisMode.DEFAULT

    def run(
        self,
        *,
        output: Path | None = None,
        report_only: bool = False,
        force: bool = False,
        include_suppressed: bool = True,
        include_command_output: bool = False,
        strict: bool = False,
    ) -> WorkspaceAnalysisRunResult:
        """Execute the registered safe stages and atomically write Markdown."""

        if report_only and force:
            raise FinsecError("--report-only and --force are mutually exclusive.")
        self._mode = (
            WorkspaceAnalysisMode.REPORT_ONLY
            if report_only
            else WorkspaceAnalysisMode.FORCE
            if force
            else WorkspaceAnalysisMode.DEFAULT
        )
        self._stage_results = []
        self._result_by_id = {}
        self._unavailable = {}
        self._collection_warnings = []
        self._target = None
        self._observations = None
        self._readiness = None
        destination = self._resolve_output_path(output)

        runners: dict[str, Callable[[], _StagePayload]] = {
            "workspace_validation": self._validate_workspace,
            "configuration_scope": self._load_configuration,
            "capture_observation_validation": self._validate_captures_and_observations,
            "classification_inventory": self._run_inventory,
            "actor_authentication_analysis": self._analyze_actor_authentication,
            "ownership_baseline_analysis": self._analyze_ownership,
            "actor_resource_modeling": self._run_modeling,
            "security_invariant_generation": self._run_invariants,
            "security_hypothesis_generation": self._run_security_hypotheses,
            "behavior_workflow_analysis": self._run_behavior_analysis,
            "domain_intent_readiness_validation": self._validate_intent_and_readiness,
            "clustering_deduplication_campaigns": self._validate_grouping,
            "suppression_research_calibration": self._summarize_suppression,
            "final_workspace_status": self._aggregate_status,
        }
        for stage in WORKSPACE_ANALYSIS_STAGES:
            failed_prerequisites = [
                prerequisite
                for prerequisite in stage.prerequisites
                if self._result_by_id.get(prerequisite) is not None
                and (
                    self._result_by_id[prerequisite].status == WorkspaceAnalysisStageStatus.FAILED
                    or not self._result_by_id[prerequisite].required_data_available
                )
            ]
            if failed_prerequisites:
                result = self._skipped_for_prerequisite(stage, failed_prerequisites)
            else:
                result = self._execute_stage(stage, runners[stage.stage_id])
            self._stage_results.append(result)
            self._result_by_id[result.stage_id] = result

        report = self._collect_report(include_suppressed=include_suppressed)
        renderer = WorkspaceAnalysisMarkdownRenderer(
            report_path=destination,
            include_command_output=include_command_output,
            redactor=self._redactor,
        )
        content = renderer.render(report)
        self._atomic_write(destination, content)

        strict_failure = strict and any(
            result.required
            and (
                result.status == WorkspaceAnalysisStageStatus.FAILED
                or not result.required_data_available
            )
            for result in self._stage_results
        )
        partial = any(
            result.status
            in {
                WorkspaceAnalysisStageStatus.WARNING,
                WorkspaceAnalysisStageStatus.FAILED,
            }
            for result in self._stage_results
        ) or bool(report.unavailable_sections)
        return WorkspaceAnalysisRunResult(
            path=destination,
            report=report,
            strict_failure=strict_failure,
            partial=partial,
        )

    def _execute_stage(
        self,
        stage: WorkspaceAnalysisStage,
        runner: Callable[[], _StagePayload],
    ) -> WorkspaceAnalysisStageResult:
        started_at = self._clock()
        started = monotonic()
        try:
            payload = runner()
        except Exception as error:
            safe_error = self._redactor.text(error)
            payload = _StagePayload(
                status=WorkspaceAnalysisStageStatus.FAILED,
                error_summary=safe_error,
                diagnostic_output=(
                    f"{stage.service_name} failed.\n"
                    f"{self._redactor.diagnostic(traceback.format_exc(limit=8))}"
                ),
                required_data_available=False,
            )
        finished_at = self._clock()
        duration = max(0.0, monotonic() - started)
        outputs = [item for item in stage.outputs if self._artifact_exists(item)]
        return WorkspaceAnalysisStageResult(
            stage_id=stage.stage_id,
            display_name=stage.display_name,
            status=payload.status,
            required=stage.required,
            prerequisites=stage.prerequisites,
            started_at=started_at,
            finished_at=finished_at,
            duration=duration,
            inputs=stage.inputs,
            outputs=outputs,
            metrics=payload.metrics,
            warnings=[self._redactor.text(item) for item in payload.warnings],
            error_summary=(
                self._redactor.text(payload.error_summary) if payload.error_summary else None
            ),
            diagnostic_output=(
                self._redactor.diagnostic(payload.diagnostic_output)
                if payload.diagnostic_output
                else None
            ),
            required_data_available=payload.required_data_available,
        )

    def _skipped_for_prerequisite(
        self,
        stage: WorkspaceAnalysisStage,
        failed_prerequisites: list[str],
    ) -> WorkspaceAnalysisStageResult:
        timestamp = self._clock()
        reason = "Prerequisite failure: " + ", ".join(failed_prerequisites)
        return WorkspaceAnalysisStageResult(
            stage_id=stage.stage_id,
            display_name=stage.display_name,
            status=WorkspaceAnalysisStageStatus.SKIPPED,
            required=stage.required,
            prerequisites=stage.prerequisites,
            started_at=timestamp,
            finished_at=timestamp,
            duration=0.0,
            inputs=stage.inputs,
            outputs=[],
            warnings=[reason],
            error_summary=reason if stage.required else None,
            diagnostic_output=f"{stage.service_name} was not called. {reason}",
            required_data_available=False,
        )

    def _artifact_exists(self, relative: str) -> bool:
        normalized = relative.rstrip("/")
        if normalized == "all current workspace artifacts":
            return False
        return (self.workspace.root / normalized).exists()

    def _validate_workspace(self) -> _StagePayload:
        if not self.workspace.root.is_dir():
            raise FinsecError(f"Workspace directory does not exist: {self.workspace.root}")
        if not self.workspace.target.is_file():
            raise FinsecError(f"Workspace target configuration is missing: {self.workspace.target}")
        return _StagePayload(
            metrics={
                "workspace_files": sum(
                    1 for item in self.workspace.root.rglob("*") if item.is_file()
                )
            },
            diagnostic_output=f"Validated workspace root {self.workspace.root}",
        )

    def _environment_type(self, target: TargetDocument) -> tuple[str, list[str]]:
        warnings: list[str] = []
        if target.testing.production:
            if target.testing.synthetic or target.testing.local_lab:
                warnings.append(
                    "Production and non-production environment flags are enabled together."
                )
            return "production", warnings
        if target.testing.synthetic:
            return "synthetic", warnings
        if target.testing.local_lab:
            return "local lab", warnings
        warnings.append("No environment-type flag is enabled in target.yaml.")
        return "unspecified", warnings

    def _load_configuration(self) -> _StagePayload:
        try:
            self._target = TargetDocument.model_validate(load_yaml(self.workspace.target))
        except (OSError, TypeError, ValueError, ValidationError, yaml.YAMLError) as error:
            raise FinsecError(f"Cannot load target configuration: {error}") from error
        warnings: list[str] = []
        if not self._target.scope.hosts:
            warnings.append("No authorized target hosts are configured.")
        _, environment_warnings = self._environment_type(self._target)
        warnings.extend(environment_warnings)
        return _StagePayload(
            status=(
                WorkspaceAnalysisStageStatus.WARNING
                if warnings
                else WorkspaceAnalysisStageStatus.SUCCESS
            ),
            metrics={
                "scope_hosts": len(self._target.scope.hosts),
                "configured_accounts": len(self._target.accounts),
            },
            warnings=warnings,
            diagnostic_output="Loaded target configuration and offline safety policy.",
        )

    def _validate_captures_and_observations(self) -> _StagePayload:
        try:
            self._observations = ObservationStore.model_validate(
                load_yaml(self.workspace.observations)
            )
        except (OSError, TypeError, ValueError, ValidationError, yaml.YAMLError) as error:
            raise FinsecError(f"Cannot load observation store: {error}") from error
        captures = list_captures(self.workspace)
        if not self._observations.observations:
            return _StagePayload(
                status=WorkspaceAnalysisStageStatus.FAILED,
                metrics={"captures": len(captures), "observations": 0},
                error_summary="No ingested observations are available for offline analysis.",
                warnings=["The report will describe the empty workspace and required ingest step."],
                diagnostic_output=(
                    "ObservationStore validated with zero observations; ingest was not run."
                ),
                required_data_available=False,
            )
        warnings = [warning for capture in captures for warning in capture.warnings]
        return _StagePayload(
            status=(
                WorkspaceAnalysisStageStatus.WARNING
                if warnings
                else WorkspaceAnalysisStageStatus.SUCCESS
            ),
            metrics={
                "captures": len(captures),
                "observations": len(self._observations.observations),
            },
            warnings=warnings,
            diagnostic_output="Validated capture metadata and redacted factual observations.",
        )

    def _current_readiness(self, *, refresh: bool = False) -> ReadinessReport:
        if self._readiness is None or refresh:
            self._readiness = resolve_workspace_readiness(self.workspace)
        return self._readiness

    def _pipeline_status(self, stage: PipelineStage) -> LifecycleStatus:
        readiness = self._current_readiness(refresh=True)
        return next(item.status for item in readiness.stages if item.id == stage)

    def _report_only_payload(
        self,
        *,
        current: bool,
        metrics: dict[str, StageMetric],
        unavailable_message: str,
        freshness_unknown: bool = False,
        required: bool = False,
    ) -> _StagePayload:
        if current and not freshness_unknown:
            return _StagePayload(
                status=WorkspaceAnalysisStageStatus.SKIPPED,
                metrics=metrics,
                warnings=[
                    "Report-only mode used the current derived artifact without regeneration."
                ],
                diagnostic_output=(
                    "Derived service was not called because --report-only was selected."
                ),
            )
        warning = (
            "Report-only mode cannot establish behavior-artifact freshness; existing artifacts "
            "were read without regeneration."
            if current and freshness_unknown
            else unavailable_message
        )
        return _StagePayload(
            status=(
                WorkspaceAnalysisStageStatus.WARNING
                if current
                else WorkspaceAnalysisStageStatus.FAILED
                if required
                else WorkspaceAnalysisStageStatus.WARNING
            ),
            metrics=metrics,
            warnings=[warning],
            error_summary=None if current else warning,
            diagnostic_output="Derived service was not called because --report-only was selected.",
            required_data_available=current,
        )

    def _run_inventory(self) -> _StagePayload:
        existing = self._safe_load_now(
            self.workspace.endpoints,
            EndpointStore,
            EndpointStore,
        )
        current = all(
            self._pipeline_status(stage) == LifecycleStatus.COMPLETE
            for stage in (PipelineStage.CLASSIFY, PipelineStage.NORMALIZE)
        )
        metrics: dict[str, StageMetric] = {"endpoints": len(existing.endpoints)}
        if self._mode == WorkspaceAnalysisMode.REPORT_ONLY:
            return self._report_only_payload(
                current=current,
                metrics=metrics,
                unavailable_message=(
                    "Endpoint inventory is missing or stale and regeneration is disabled."
                ),
                required=True,
            )
        if self._mode != WorkspaceAnalysisMode.FORCE and current:
            return _StagePayload(
                status=WorkspaceAnalysisStageStatus.SKIPPED,
                metrics=metrics,
                warnings=[
                    "Current endpoint inventory was reused according to provenance metadata."
                ],
                diagnostic_output=(
                    "build_inventory was not called because inventory provenance is current."
                ),
            )
        result = build_inventory(self.workspace)
        self._readiness = None
        endpoints = self._safe_load_now(self.workspace.endpoints, EndpointStore, EndpointStore)
        return _StagePayload(
            metrics={
                "observations": result.observations,
                "endpoints": result.endpoints,
                "suppressed_endpoints": sum(
                    item.disposition != "ACTIVE" for item in endpoints.endpoints
                ),
            },
            diagnostic_output="Called build_inventory directly; no CLI output was parsed.",
        )

    def _analyze_actor_authentication(self) -> _StagePayload:
        readiness = self._current_readiness(refresh=True)
        auth = next(item for item in readiness.stages if item.id == PipelineStage.AUTH)
        warnings = sorted({item.summary for item in [*auth.blockers, *auth.warnings]})
        return _StagePayload(
            status=(
                WorkspaceAnalysisStageStatus.WARNING
                if warnings
                else WorkspaceAnalysisStageStatus.SUCCESS
            ),
            metrics={
                "actors": len(readiness.actors),
                "credentials_available": sum(
                    item.credential.available for item in readiness.actors
                ),
                "identities_confirmed": sum(
                    item.identity_confirmation.confirmed for item in readiness.actors
                ),
            },
            warnings=warnings,
            diagnostic_output=(
                "Resolved actor readiness without reading credential values or contacting a target."
            ),
        )

    def _analyze_ownership(self) -> _StagePayload:
        store = load_controlled_ownership(self.workspace)
        warnings = list(store.identity_assumptions)
        if not store.controlled_baselines:
            warnings.append("No controlled actor-object-owner baseline is currently available.")
        return _StagePayload(
            status=(
                WorkspaceAnalysisStageStatus.WARNING
                if warnings and not store.controlled_baselines
                else WorkspaceAnalysisStageStatus.SUCCESS
            ),
            metrics={
                "resource_identities": len(store.resources),
                "relationships": len(store.relationships),
                "controlled_baselines": len(store.controlled_baselines),
            },
            warnings=warnings,
            diagnostic_output="Validated the secret-free controlled ownership store.",
        )

    def _run_modeling(self) -> _StagePayload:
        actors = self._safe_load_now(self.workspace.actors, ActorStore, ActorStore)
        resources = self._safe_load_now(self.workspace.resources, ResourceStore, ResourceStore)
        current = self._pipeline_status(PipelineStage.MODEL) == LifecycleStatus.COMPLETE
        metrics: dict[str, StageMetric] = {
            "actors": len(actors.actors),
            "resources": len(resources.resources),
        }
        if self._mode == WorkspaceAnalysisMode.REPORT_ONLY:
            return self._report_only_payload(
                current=current,
                metrics=metrics,
                unavailable_message=(
                    "Actor/resource model is missing or stale and regeneration is disabled."
                ),
                required=True,
            )
        if self._mode != WorkspaceAnalysisMode.FORCE and current:
            return _StagePayload(
                status=WorkspaceAnalysisStageStatus.SKIPPED,
                metrics=metrics,
                warnings=[
                    "Current actor/resource model was reused according to provenance metadata."
                ],
                diagnostic_output=(
                    "generate_model was not called because model provenance is current."
                ),
            )
        result = generate_model(self.workspace)
        self._readiness = None
        return _StagePayload(
            metrics={
                "actors": result.actors,
                "resources": result.resources,
                "workflow_maps": result.workflows,
            },
            warnings=list(result.conflicts),
            status=(
                WorkspaceAnalysisStageStatus.WARNING
                if result.conflicts
                else WorkspaceAnalysisStageStatus.SUCCESS
            ),
            diagnostic_output=(
                "Called generate_model directly; researcher-edited records were preserved."
            ),
        )

    def _run_invariants(self) -> _StagePayload:
        resources = self._safe_load_now(self.workspace.resources, ResourceStore, ResourceStore)
        existing = self._safe_load_now(self.workspace.invariants, InvariantStore, InvariantStore)
        if not resources.resources:
            return _StagePayload(
                status=WorkspaceAnalysisStageStatus.SKIPPED,
                metrics={"invariants": len(existing.invariants)},
                warnings=[
                    "No resources are modeled; security invariant generation is not applicable."
                ],
                diagnostic_output=(
                    "generate_invariants was not called because the resource model is empty."
                ),
            )
        current = self._pipeline_status(PipelineStage.INVARIANTS) == LifecycleStatus.COMPLETE
        if self._mode == WorkspaceAnalysisMode.REPORT_ONLY:
            return self._report_only_payload(
                current=current,
                metrics={"invariants": len(existing.invariants)},
                unavailable_message=(
                    "Security invariants are missing or stale and regeneration is disabled."
                ),
            )
        if self._mode != WorkspaceAnalysisMode.FORCE and current:
            return _StagePayload(
                status=WorkspaceAnalysisStageStatus.SKIPPED,
                metrics={"invariants": len(existing.invariants)},
                warnings=[
                    "Current security invariants were reused according to provenance metadata."
                ],
                diagnostic_output=(
                    "generate_invariants was not called because provenance is current."
                ),
            )
        result = generate_invariants(self.workspace)
        self._readiness = None
        return _StagePayload(
            status=(
                WorkspaceAnalysisStageStatus.WARNING
                if result.conflicts
                else WorkspaceAnalysisStageStatus.SUCCESS
            ),
            metrics={"invariants": result.invariants},
            warnings=list(result.conflicts),
            diagnostic_output="Called generate_invariants directly; no evidence was confirmed.",
        )

    def _run_security_hypotheses(self) -> _StagePayload:
        invariants = self._safe_load_now(self.workspace.invariants, InvariantStore, InvariantStore)
        existing = self._safe_load_now(self.workspace.hypotheses, HypothesisStore, HypothesisStore)
        active_invariants = sum(item.disposition == "ACTIVE" for item in invariants.invariants)
        if active_invariants == 0:
            return _StagePayload(
                status=WorkspaceAnalysisStageStatus.SKIPPED,
                metrics={"hypothesis_records": len(existing.hypotheses)},
                warnings=[
                    "No active security invariants exist; endpoint hypothesis generation was "
                    "skipped."
                ],
                diagnostic_output=(
                    "generate_hypotheses was not called because no active invariants exist."
                ),
            )
        current = self._pipeline_status(PipelineStage.HYPOTHESIZE) == LifecycleStatus.COMPLETE
        if self._mode == WorkspaceAnalysisMode.REPORT_ONLY:
            return self._report_only_payload(
                current=current,
                metrics={"hypothesis_records": len(existing.hypotheses)},
                unavailable_message=(
                    "Hypothesis backlog is missing or stale and regeneration is disabled."
                ),
            )
        if self._mode != WorkspaceAnalysisMode.FORCE and current:
            return _StagePayload(
                status=WorkspaceAnalysisStageStatus.SKIPPED,
                metrics={"hypothesis_records": len(existing.hypotheses)},
                warnings=[
                    "Current endpoint hypotheses were reused according to provenance metadata."
                ],
                diagnostic_output=(
                    "generate_hypotheses was not called because provenance is current."
                ),
            )
        result = generate_hypotheses(self.workspace)
        self._readiness = None
        return _StagePayload(
            status=(
                WorkspaceAnalysisStageStatus.WARNING
                if result.conflicts
                else WorkspaceAnalysisStageStatus.SUCCESS
            ),
            metrics={"hypothesis_records": result.hypotheses},
            warnings=list(result.conflicts),
            diagnostic_output=(
                "Called generate_hypotheses directly; lifecycle status and notes were preserved."
            ),
        )

    def _run_behavior_analysis(self) -> _StagePayload:
        paths = (
            self.workspace.workflow_instances,
            self.workspace.workflow_families,
            self.workspace.business_invariants,
            self.workspace.business_logic_hypotheses,
        )
        current = all(path.is_file() for path in paths)
        metrics: dict[str, StageMetric] = {
            "workflow_instances": self._safe_list_count(
                self.workspace.workflow_instances, "workflow_instances"
            ),
            "workflow_families": self._safe_list_count(
                self.workspace.workflow_families, "workflow_families"
            ),
        }
        if self._mode == WorkspaceAnalysisMode.REPORT_ONLY:
            return self._report_only_payload(
                current=current,
                metrics=metrics,
                unavailable_message=(
                    "Behavior/workflow artifacts are missing and regeneration is disabled."
                ),
                freshness_unknown=True,
            )
        result = analyze_business_logic(self.workspace)
        self._readiness = None
        return _StagePayload(
            status=(
                WorkspaceAnalysisStageStatus.WARNING
                if result.conflicts
                else WorkspaceAnalysisStageStatus.SUCCESS
            ),
            metrics={
                "business_invariants": result.business_invariants,
                "logic_hypotheses": result.hypotheses,
                "logic_research_tasks": result.research_tasks,
                "logic_clusters": result.clusters,
                "suppressed_candidates": result.suppressed_candidates,
            },
            warnings=list(result.conflicts),
            diagnostic_output=(
                "Called analyze_business_logic directly. It rebuilt deterministic behavior, "
                "workflow, BLH, clustering, and shared backlog artifacts without target requests."
            ),
        )

    def _validate_intent_and_readiness(self) -> _StagePayload:
        store = self._safe_load_now(self.workspace.hypotheses, HypothesisStore, HypothesisStore)
        invalid = [
            item.id
            for item in store.hypotheses
            if item.readiness_assessment.evaluator != "unified-hypothesis-readiness-v1"
        ]
        if invalid:
            return _StagePayload(
                status=WorkspaceAnalysisStageStatus.WARNING,
                metrics={"records": len(store.hypotheses), "invalid_readiness": len(invalid)},
                warnings=["Records without canonical readiness: " + ", ".join(sorted(invalid))],
                diagnostic_output=(
                    "Validated persisted domain-intent and unified-readiness contracts."
                ),
                required_data_available=False,
            )
        return _StagePayload(
            metrics={
                "records": len(store.hypotheses),
                "test_ready": sum(item.readiness == "TEST_READY" for item in store.hypotheses),
                "review_required": sum(
                    item.readiness == "REVIEW_REQUIRED" for item in store.hypotheses
                ),
                "research_only": sum(
                    item.readiness == "RESEARCH_ONLY" for item in store.hypotheses
                ),
            },
            diagnostic_output=(
                "Validated persisted domain-intent and unified-readiness contracts."
            ),
        )

    def _validate_grouping(self) -> _StagePayload:
        store = self._safe_load_now(self.workspace.hypotheses, HypothesisStore, HypothesisStore)
        grouped = sum(item.grouping.cluster_id is not None for item in store.hypotheses)
        warnings: list[str] = []
        if store.hypotheses and grouped != len(store.hypotheses):
            warnings.append("One or more records lack a shared semantic cluster assignment.")
        return _StagePayload(
            status=(
                WorkspaceAnalysisStageStatus.WARNING
                if warnings
                else WorkspaceAnalysisStageStatus.SUCCESS
            ),
            metrics={
                "records": len(store.hypotheses),
                "clustered_records": grouped,
                "campaigns": len(store.campaigns),
                "exact_duplicates": sum(
                    item.grouping.relationship == "EXACT_DUPLICATE" for item in store.hypotheses
                ),
            },
            warnings=warnings,
            diagnostic_output="Validated shared cross-generator grouping and campaign records.",
        )

    def _summarize_suppression(self) -> _StagePayload:
        endpoints = self._safe_load_now(self.workspace.endpoints, EndpointStore, EndpointStore)
        hypotheses = self._safe_load_now(
            self.workspace.hypotheses, HypothesisStore, HypothesisStore
        )
        population = hypothesis_population(hypotheses.hypotheses)
        suppressed = sum(not presentation_visible(item) for item in hypotheses.hypotheses)
        return _StagePayload(
            metrics={
                "suppressed_endpoints": sum(
                    item.disposition != "ACTIVE" for item in endpoints.endpoints
                ),
                "suppressed_hypotheses": suppressed,
                "visible_active_hypotheses": len(population.visible_active_hypotheses),
                "visible_research_tasks": len(population.visible_research_tasks),
            },
            diagnostic_output="Summarized persisted suppression and population decisions.",
        )

    def _aggregate_status(self) -> _StagePayload:
        readiness = self._current_readiness(refresh=True)
        warnings = sorted(
            {
                item.summary
                for stage in readiness.stages
                for item in [*stage.blockers, *stage.warnings]
                if stage.id
                in {
                    PipelineStage.SETUP,
                    PipelineStage.INGEST,
                    PipelineStage.CLASSIFY,
                    PipelineStage.NORMALIZE,
                    PipelineStage.MODEL,
                    PipelineStage.INVARIANTS,
                    PipelineStage.HYPOTHESIZE,
                }
            }
        )
        return _StagePayload(
            status=(
                WorkspaceAnalysisStageStatus.WARNING
                if warnings
                else WorkspaceAnalysisStageStatus.SUCCESS
            ),
            metrics={
                "overall_status": readiness.overall.status.value,
                "active_hypotheses": readiness.metrics.active_hypotheses,
                "research_tasks": readiness.metrics.research_tasks,
            },
            warnings=warnings,
            diagnostic_output=(
                "Computed canonical readiness read-only; planning, approval, execution, "
                "validation, and confirmed reporting services were not called."
            ),
        )

    def _safe_load_now(
        self,
        path: Path,
        model: type[MODEL_T],
        default_factory: Callable[[], MODEL_T],
    ) -> MODEL_T:
        if not path.is_file():
            return default_factory()
        try:
            return model.model_validate(load_yaml(path))
        except (OSError, TypeError, ValueError, ValidationError, yaml.YAMLError):
            return default_factory()

    def _safe_list_count(self, path: Path, key: str) -> int:
        if not path.is_file():
            return 0
        try:
            document = load_yaml(path)
        except (OSError, TypeError, ValueError, yaml.YAMLError):
            return 0
        values = document.get(key) if isinstance(document, dict) else None
        return len(values) if isinstance(values, list) else 0

    def _collect_store(
        self,
        path: Path,
        model: type[MODEL_T],
        default_factory: Callable[[], MODEL_T],
        section: str,
        *,
        mark_missing_unavailable: bool = True,
    ) -> MODEL_T:
        if not path.is_file():
            if mark_missing_unavailable:
                message = f"Artifact is unavailable: {path.relative_to(self.workspace.root)}"
                self._unavailable.setdefault(section, message)
            return default_factory()
        try:
            return model.model_validate(load_yaml(path))
        except Exception as error:
            safe_error = self._redactor.text(error)
            message = f"Unavailable because {path.name} is malformed: {safe_error}"
            self._unavailable[section] = message
            self._collection_warnings.append(message)
            return default_factory()

    def _collect_report(self, *, include_suppressed: bool) -> WorkspaceAnalysisReportModel:
        target: TargetDocument | None = None
        try:
            target = TargetDocument.model_validate(load_yaml(self.workspace.target))
        except (OSError, TypeError, ValueError, ValidationError, yaml.YAMLError) as error:
            message = (
                "Unavailable because target configuration failed validation: "
                f"{self._redactor.text(error)}"
            )
            self._unavailable["metadata"] = message
            self._collection_warnings.append(message)

        observations = self._collect_store(
            self.workspace.observations,
            ObservationStore,
            ObservationStore,
            "capture and observation quality",
        )
        endpoints = self._collect_store(
            self.workspace.endpoints,
            EndpointStore,
            EndpointStore,
            "endpoint and resource inventory",
        )
        actors = self._collect_store(
            self.workspace.actors,
            ActorStore,
            ActorStore,
            "actors, authentication, identity, and ownership",
        )
        resources = self._collect_store(
            self.workspace.resources,
            ResourceStore,
            ResourceStore,
            "endpoint and resource inventory",
        )
        invariants = self._collect_store(
            self.workspace.invariants,
            InvariantStore,
            InvariantStore,
            "invariant summary",
        )
        hypotheses = self._collect_store(
            self.workspace.hypotheses,
            HypothesisStore,
            HypothesisStore,
            "hypothesis summary",
        )
        plans = self._collect_store(
            self.workspace.test_plans,
            TestPlanStore,
            TestPlanStore,
            "readiness and execution-policy assessment",
            mark_missing_unavailable=False,
        )
        validations = self._collect_store(
            self.workspace.validations,
            ValidationStore,
            ValidationStore,
            "detailed active hypotheses",
        )
        workflow_instances = self._collect_store(
            self.workspace.workflow_instances,
            WorkflowInstanceStore,
            WorkflowInstanceStore,
            "workflow and behavior analysis",
        )
        workflow_families = self._collect_store(
            self.workspace.workflow_families,
            WorkflowFamilyStore,
            WorkflowFamilyStore,
            "workflow and behavior analysis",
        )
        states = self._collect_store(
            self.workspace.behavior_states,
            StateStore,
            StateStore,
            "workflow and behavior analysis",
        )
        transitions = self._collect_store(
            self.workspace.behavior_transitions,
            TransitionStore,
            TransitionStore,
            "workflow and behavior analysis",
        )
        propagation = self._collect_store(
            self.workspace.propagation_links,
            PropagationStore,
            PropagationStore,
            "workflow and behavior analysis",
        )
        business_invariants = self._collect_store(
            self.workspace.business_invariants,
            BusinessInvariantStore,
            BusinessInvariantStore,
            "invariant summary",
        )
        logic = self._collect_store(
            self.workspace.business_logic_hypotheses,
            LogicHypothesisStore,
            LogicHypothesisStore,
            "business-logic hypotheses",
        )
        actions = self._collect_store(
            self.workspace.behavior_actions,
            ActionStore,
            ActionStore,
            "workflow and behavior analysis",
        )
        resource_instances = self._collect_store(
            self.workspace.behavior_resources,
            ResourceInstanceStore,
            ResourceInstanceStore,
            "workflow and behavior analysis",
        )
        try:
            captures: list[Capture] = list_captures(self.workspace)
        except Exception as error:
            captures = []
            message = (
                "Unavailable because capture metadata failed validation: "
                f"{self._redactor.text(error)}"
            )
            self._unavailable["capture and observation quality"] = message
            self._collection_warnings.append(message)
        try:
            ownership = load_controlled_ownership(self.workspace)
        except Exception as error:
            ownership = ControlledOwnershipStore()
            message = f"Unavailable because ownership analysis failed: {self._redactor.text(error)}"
            self._unavailable["actors, authentication, identity, and ownership"] = message
            self._collection_warnings.append(message)
        try:
            readiness = self._current_readiness(refresh=True)
        except Exception as error:
            readiness = None
            message = (
                "Unavailable because final readiness aggregation failed: "
                f"{self._redactor.text(error)}"
            )
            self._unavailable["readiness and execution-policy assessment"] = message
            self._collection_warnings.append(message)

        generated_at = self._clock()
        metadata = self._metadata(target, generated_at)
        metrics = self._metrics(
            target=target,
            captures=captures,
            observations=observations,
            endpoints=endpoints,
            actors=actors,
            resources=resources,
            ownership=ownership,
            workflow_instances=workflow_instances,
            workflow_families=workflow_families,
            invariants=invariants,
            business_invariants=business_invariants,
            hypotheses=hypotheses,
        )
        assessment, primary_blocker = self._assessment(metrics, readiness)
        next_actions = self._next_actions(
            captures=captures,
            endpoints=endpoints,
            hypotheses=hypotheses,
            readiness=readiness,
        )
        confirmed_reports = (
            sorted(self.workspace.reports.glob("HYP-*-report-v*.md"))
            if self.workspace.reports.is_dir()
            else []
        )
        artifacts = self._artifact_index()
        # Load these stores to validate their schemas even though their detail is reached through
        # workflow records; counts remain available in stage diagnostics.
        _ = actions, resource_instances
        return WorkspaceAnalysisReportModel(
            metadata=metadata,
            include_suppressed=include_suppressed,
            assessment=assessment,
            primary_blocker=primary_blocker,
            metrics=metrics,
            stages=list(self._stage_results),
            target=target,
            captures=sorted(captures, key=lambda item: item.capture_id),
            observations=sorted(observations.observations, key=lambda item: item.id),
            endpoints=sorted(
                endpoints.endpoints,
                key=lambda item: (
                    (item.hosts[0] if item.hosts else ""),
                    item.path,
                    item.method,
                    item.id,
                ),
            ),
            actors=sorted(actors.actors, key=lambda item: item.id),
            resources=sorted(resources.resources, key=lambda item: item.id),
            ownership=ownership,
            workflow_instances=sorted(
                workflow_instances.workflow_instances, key=lambda item: item.id
            ),
            workflow_families=sorted(
                workflow_families.workflow_families,
                key=lambda item: (item.structural_signature, item.id),
            ),
            states=sorted(states.states, key=lambda item: item.id),
            transitions=sorted(transitions.transitions, key=lambda item: item.id),
            propagation_links=sorted(propagation.propagation_links, key=lambda item: item.id),
            invariants=sorted(invariants.invariants, key=lambda item: (item.category, item.id)),
            business_invariants=sorted(
                business_invariants.business_invariants,
                key=lambda item: (item.invariant_type, item.id),
            ),
            hypotheses=sorted(
                hypotheses.hypotheses,
                key=lambda item: (
                    {"P1": 0, "P2": 1, "P3": 2}[item.priority],
                    -item.scores.total,
                    item.id,
                ),
            ),
            campaigns=sorted(hypotheses.campaigns, key=lambda item: item.id),
            logic_hypotheses=sorted(logic.hypotheses, key=lambda item: item.id),
            logic_clusters=sorted(logic.clusters, key=lambda item: item.id),
            mutation_rejections=sorted(logic.rejections, key=lambda item: item.id),
            plans=sorted(plans.plans, key=lambda item: (item.hypothesis_id, item.id)),
            validations=sorted(
                validations.validations, key=lambda item: (item.hypothesis_id, item.id)
            ),
            readiness=readiness,
            next_actions=next_actions,
            artifacts=artifacts,
            confirmed_report_paths=confirmed_reports,
            unavailable_sections=dict(sorted(self._unavailable.items())),
            warnings=sorted(set(self._collection_warnings)),
        )

    def _metadata(
        self, target: TargetDocument | None, generated_at: datetime
    ) -> WorkspaceAnalysisMetadata:
        warnings: list[str] = []
        if target is None:
            workspace_name = self.workspace.root.name
            hosts: list[str] = []
            environment = "unspecified"
            active = "Unknown because target.yaml is unavailable."
            approval = "Unknown because target.yaml is unavailable."
            safety = "Offline report generation only; no active service was called."
        else:
            workspace_name = target.target.name
            hosts = sorted(target.scope.hosts)
            environment, environment_warnings = self._environment_type(target)
            warnings.extend(environment_warnings)
            if not hosts:
                warnings.append("No authorized target hosts are configured.")
            active = (
                "Active execution is enabled by target policy, but still requires a current plan "
                "and all independent safety gates."
                if target.testing.active_execution_enabled
                else "Active execution is disabled by target policy."
            )
            approval = (
                "Explicit human approval is required for active execution."
                if target.testing.human_approval_required
                else (
                    "Target policy does not require approval, but command-specific safety gates "
                    "remain."
                )
            )
            safety = (
                f"read_only_only={str(target.testing.read_only_only).lower()}, "
                f"destructive_testing={str(target.testing.destructive_testing).lower()}, "
                f"maximum_requests_per_plan={target.testing.maximum_requests_per_plan}. "
                "This report command runs deterministic offline analysis only."
            )
        return WorkspaceAnalysisMetadata(
            workspace_name=workspace_name,
            workspace_path=str(self.workspace.root),
            generated_at=generated_at,
            timezone=generated_at.tzname() or "UTC",
            finsec_version=__version__,
            git_commit=self._git_commit(),
            mode=self._mode,
            target_hosts=hosts,
            environment_type=environment,
            safety_policy_summary=safety,
            active_execution_policy=active,
            human_approval_policy=approval,
            configuration_warnings=warnings,
        )

    def _metrics(
        self,
        *,
        target: TargetDocument | None,
        captures: list[Capture],
        observations: ObservationStore,
        endpoints: EndpointStore,
        actors: ActorStore,
        resources: ResourceStore,
        ownership: ControlledOwnershipStore,
        workflow_instances: WorkflowInstanceStore,
        workflow_families: WorkflowFamilyStore,
        invariants: InvariantStore,
        business_invariants: BusinessInvariantStore,
        hypotheses: HypothesisStore,
    ) -> WorkspaceAnalysisMetrics:
        visible = [item for item in hypotheses.hypotheses if presentation_visible(item)]
        visible_security = [item for item in visible if item.kind == "SECURITY_HYPOTHESIS"]
        actor_ids = {item.name for item in actors.actors}
        actor_ids.update(item.actor for item in observations.observations)
        if target is not None:
            actor_ids.update(item.id for item in target.accounts)
        authenticated_actor_ids = {
            item.actor
            for item in observations.observations
            if item.authentication.present and item.actor not in {"UNKNOWN", "ANONYMOUS"}
        }
        if target is not None:
            authenticated_actor_ids.update(
                item.id
                for item in target.accounts
                if item.authenticated and (item.actor_type or "authenticated_user") != "anonymous"
            )
        suppressed = [item for item in hypotheses.hypotheses if not presentation_visible(item)]
        return WorkspaceAnalysisMetrics(
            captures=len(captures),
            observations=len(observations.observations),
            endpoint_families=len(endpoints.endpoints),
            suppressed_endpoints=sum(item.disposition != "ACTIVE" for item in endpoints.endpoints),
            actors=len(actor_ids),
            authenticated_actors=len(authenticated_actor_ids),
            ownership_baselines=len(ownership.controlled_baselines),
            resources=sum(item.disposition == "ACTIVE" for item in resources.resources),
            workflow_instances=len(workflow_instances.workflow_instances),
            workflow_families=len(workflow_families.workflow_families),
            active_invariants=(
                sum(item.disposition == "ACTIVE" for item in invariants.invariants)
                + len(business_invariants.business_invariants)
            ),
            visible_hypotheses=len(visible_security),
            active_hypotheses=sum(item.disposition == "ACTIVE" for item in visible_security),
            hyp_hypotheses=sum(item.id.startswith("HYP-") for item in visible_security),
            blh_hypotheses=sum(item.id.startswith("BLH-") for item in visible_security),
            research_tasks=sum(item.kind == "RESEARCH_TASK" for item in visible),
            suppressed_hypotheses=len(suppressed),
            campaigns=len(hypotheses.campaigns),
            test_ready=sum(item.readiness == "TEST_READY" for item in visible),
            review_required=sum(item.readiness == "REVIEW_REQUIRED" for item in visible),
            research_only=sum(item.readiness == "RESEARCH_ONLY" for item in visible),
            planned_hypotheses=sum(item.status == "TEST_PLANNED" for item in visible_security),
            tested_hypotheses=sum(
                item.status in {"REFUTED", "NEEDS_EVIDENCE", "CONFIRMED"}
                for item in visible_security
            ),
            confirmed_hypotheses=sum(item.status == "CONFIRMED" for item in visible_security),
            rejected_hypotheses=sum(item.status == "REFUTED" for item in visible_security),
        )

    def _assessment(
        self,
        metrics: WorkspaceAnalysisMetrics,
        readiness: ReadinessReport | None,
    ) -> tuple[str, str | None]:
        required_failure = next(
            (
                result
                for result in self._stage_results
                if result.required and result.status == WorkspaceAnalysisStageStatus.FAILED
            ),
            None,
        )
        if required_failure is not None:
            required_blocker = required_failure.error_summary or required_failure.display_name
            return (
                "A partial offline workspace report was generated, but one or more required "
                "analysis stages failed. Unavailable sections and stage diagnostics remain "
                "visible.",
                required_blocker,
            )
        if metrics.observations == 0:
            return (
                "The workspace is configured, but offline analysis cannot begin until reviewed "
                "captures are ingested as redacted factual observations.",
                "No ingested observations are available.",
            )
        readiness_blocker = self._primary_readiness_blocker(readiness)
        if (
            metrics.test_ready
            and readiness is not None
            and readiness.overall.status != LifecycleStatus.COMPLETE
        ):
            return (
                "The offline analysis pipeline produced TEST_READY candidate hypotheses, while "
                "execution permission remains a separate state governed by actor, ownership, "
                "plan, approval, and environment-policy gates.",
                readiness_blocker,
            )
        if metrics.active_hypotheses == 0 and metrics.research_tasks:
            return (
                "Offline analysis completed with research tasks but no visible active security "
                "hypothesis. Additional passive evidence is required before bounded test "
                "planning.",
                readiness_blocker,
            )
        if readiness_blocker is not None:
            return (
                "The offline analysis pipeline completed or produced a usable partial result, "
                "but downstream investigation remains blocked by the highest-priority readiness "
                "fact.",
                readiness_blocker,
            )
        return (
            "The deterministic offline analysis pipeline completed successfully. Candidate "
            "hypotheses remain preliminary and require separate planning, approval, execution, "
            "evidence, and validation decisions.",
            None,
        )

    def _primary_readiness_blocker(self, readiness: ReadinessReport | None) -> str | None:
        if readiness is None:
            return None
        rank = {
            "NO_OBSERVATIONS": 0,
            "ARTIFACT_MISSING": 1,
            "ARTIFACT_MALFORMED": 1,
            "UPSTREAM_DEPENDENCY_CHANGED": 2,
            "NO_ACTOR_CREDENTIAL": 3,
            "CREDENTIAL_EXPIRED": 3,
            "ACTOR_IDENTITY_NOT_CONFIRMED": 4,
            "OWNERSHIP_BASELINES_MISSING": 5,
            "INSUFFICIENT_CONTROLLED_ACTORS": 5,
            "HYPOTHESIS_REQUIRES_MORE_EVIDENCE": 6,
            "ACTIVE_EXECUTION_DISABLED": 7,
            "HUMAN_APPROVAL_MISSING": 8,
        }
        blockers = [item for stage in readiness.stages for item in stage.blockers]
        if not blockers:
            return None
        selected = sorted(
            blockers,
            key=lambda item: (rank.get(item.code.value, 50), item.stage.value, item.code.value),
        )[0]
        return selected.summary

    def _next_actions(
        self,
        *,
        captures: list[Capture],
        endpoints: EndpointStore,
        hypotheses: HypothesisStore,
        readiness: ReadinessReport | None,
    ) -> list[WorkspaceNextAction]:
        workspace_arg = shlex.quote(str(self.workspace.root))
        candidates: list[tuple[int, str, str, list[str], str, str, str | None, str | None]] = []
        if not self._observations or not self._observations.observations:
            candidates.append(
                (
                    0,
                    "Ingest reviewed captures",
                    "Offline analysis requires redacted factual observations.",
                    [self.workspace.root.name],
                    "Redacted observations with explicit actor and capture intent metadata.",
                    "PASSIVE",
                    None,
                    f"hunt ingest-wizard -w {workspace_arg}",
                )
            )
        for capture in captures:
            labels = {item.value for item in capture.quality.labels}
            if labels.intersection({"BROAD", "MIXED", "MULTI_INTENT", "LOW_SIGNAL"}):
                candidates.append(
                    (
                        1,
                        "Capture a focused single-intent workflow",
                        "Broad or mixed captures reduce workflow-boundary confidence.",
                        [capture.capture_id, capture.actor_id],
                        "One normal-behavior journey with a single declared purpose.",
                        "PASSIVE",
                        "Use a researcher-controlled actor and reviewed capture source.",
                        f"hunt ingest-wizard -w {workspace_arg}",
                    )
                )
        if readiness is not None:
            for actor in readiness.actors:
                if not actor.identity_confirmation.confirmed:
                    candidates.append(
                        (
                            0,
                            "Confirm actor identity",
                            "Authentication evidence does not by itself confirm the intended actor "
                            "identity.",
                            [actor.actor_id],
                            "A target-validated identity baseline for the controlled actor.",
                            "REVIEW",
                            "Fresh reviewed authentication metadata may be required.",
                            None,
                        )
                    )
                if not actor.ownership.confirmed_baselines:
                    candidates.append(
                        (
                            0,
                            "Create controlled actor-object-owner baselines",
                            "Authorization comparisons require object ownership evidence separate "
                            "from authentication.",
                            [actor.actor_id, actor.ownership.hypothesis_id or "workspace"],
                            "A successful normal-behavior actor/object operation with owner or "
                            "boundary evidence.",
                            "PASSIVE",
                            "Confirm actor identity before relying on the baseline.",
                            f"hunt ingest-wizard -w {workspace_arg}",
                        )
                    )
            for action in readiness.next_actions:
                classification = (
                    "ACTIVE_REQUIRES_APPROVAL"
                    if action.safety == "requires_human_approval"
                    else "REVIEW"
                    if action.safety == "requires_review"
                    else "PASSIVE"
                )
                priority = 0 if "ingest" in (action.command or "") else 2
                candidates.append(
                    (
                        priority,
                        action.label,
                        "The canonical readiness engine selected this dependency-aware "
                        "remediation.",
                        [readiness.workspace],
                        "The evidence or artifact named by the readiness blocker.",
                        classification,
                        None,
                        action.command,
                    )
                )
        ambiguous = sorted(
            {
                f"{endpoint.id}:{parameter.name}"
                for endpoint in endpoints.endpoints
                for parameter in endpoint.parameters
                if parameter.identifier_semantics.semantic_class.value == "OPAQUE_UNKNOWN"
                and parameter.client_controlled
            }
        )
        if ambiguous:
            candidates.append(
                (
                    1,
                    "Resolve ambiguous identifiers",
                    "Unknown identifier semantics prevent safe ownership and deduplication "
                    "decisions.",
                    ambiguous[:10],
                    "Reviewed resource role and ownership evidence for each identifier.",
                    "REVIEW",
                    None,
                    None,
                )
            )
        visible = [item for item in hypotheses.hypotheses if presentation_visible(item)]
        for item in visible:
            if item.kind == "SECURITY_HYPOTHESIS" and item.readiness == "TEST_READY":
                candidates.append(
                    (
                        2,
                        f"Review TEST_READY hypothesis {item.id}",
                        "Technical readiness is established, but planning and execution permission "
                        "remain separate.",
                        [item.id],
                        "Human review of the mutation target, oracle, request budget, and safety "
                        "classification.",
                        "REVIEW",
                        "Do not plan until the candidate and current ownership evidence are "
                        "reviewed.",
                        f"hunt show {shlex.quote(item.id)} -w {workspace_arg}",
                    )
                )
            if item.kind == "RESEARCH_TASK":
                candidates.append(
                    (
                        1,
                        f"Collect passive evidence for {item.id}",
                        item.missing_evidence[0] if item.missing_evidence else item.reasoning,
                        [item.id, *item.invariant[:1]],
                        item.evidence_to_collect[0]
                        if item.evidence_to_collect
                        else "Reviewed passive evidence.",
                        "PASSIVE",
                        item.preconditions[0] if item.preconditions else None,
                        f"hunt hypotheses --research-tasks -w {workspace_arg}",
                    )
                )
        if hypotheses.campaigns:
            campaign = hypotheses.campaigns[0]
            candidates.append(
                (
                    2,
                    f"Review campaign {campaign.id}",
                    "Campaign members share setup but retain distinct mutation and oracle "
                    "semantics.",
                    [campaign.id, *campaign.member_ids],
                    "A manual decision that each member remains correctly grouped or distinct.",
                    "REVIEW",
                    None,
                    f"hunt hypotheses --campaigns -w {workspace_arg}",
                )
            )
        deduplicated: dict[
            tuple[str, str, tuple[str, ...]],
            tuple[int, str, str, list[str], str, str, str | None, str | None],
        ] = {}
        for candidate in candidates:
            key = (candidate[1], candidate[7] or "", tuple(candidate[3]))
            deduplicated.setdefault(key, candidate)
        ordered = sorted(deduplicated.values(), key=lambda item: (item[0], item[1], item[3]))[:30]
        priorities = {0: "P1", 1: "P2", 2: "P3"}
        return [
            WorkspaceNextAction(
                action_id=f"ACT-{index:03d}",
                priority=priorities.get(item[0], "P3"),  # type: ignore[arg-type]
                title=item[1],
                why=item[2],
                affected=item[3],
                expected_evidence=item[4],
                classification=item[5],  # type: ignore[arg-type]
                prerequisite=item[6],
                command=item[7],
            )
            for index, item in enumerate(ordered, 1)
        ]

    def _artifact_index(self) -> list[WorkspaceArtifactIndexEntry]:
        entries = [
            (
                "Captures",
                self.workspace.captures,
                False,
                "Capture provenance and quality metadata.",
            ),
            ("Observations", self.workspace.observations, True, "Redacted factual observations."),
            ("Endpoints", self.workspace.endpoints, True, "Classified endpoint families."),
            ("Resources", self.workspace.resources, False, "Evidence-linked resource model."),
            ("Actors", self.workspace.actors, False, "Secret-free actor model."),
            (
                "Ownership baselines",
                self.workspace.controlled_ownership,
                False,
                "Controlled actor/object/owner boundary evidence.",
            ),
            (
                "Workflow instances",
                self.workspace.workflow_instances,
                False,
                "Reconstructed workflows.",
            ),
            (
                "Workflow families",
                self.workspace.workflow_families,
                False,
                "Canonical workflow families.",
            ),
            ("Invariants", self.workspace.invariants, False, "Endpoint security invariants."),
            (
                "Business invariants",
                self.workspace.business_invariants,
                False,
                "Workflow-level business invariants.",
            ),
            ("Hypothesis backlog", self.workspace.hypotheses, False, "Unified HYP/BLH backlog."),
            (
                "Business-logic hypotheses",
                self.workspace.business_logic_hypotheses,
                False,
                "Raw BLH, rejection, and precision-cluster store.",
            ),
            (
                "Research tasks",
                self.workspace.hypotheses,
                False,
                "Research tasks in the unified backlog.",
            ),
            ("Campaigns", self.workspace.hypotheses, False, "Campaigns in the unified backlog."),
            ("Plans", self.workspace.test_plans, False, "Non-executing test plans."),
            ("Evidence", self.workspace.root / "evidence", False, "Existing evidence packages."),
            (
                "Execution results",
                self.workspace.root / "tests" / "executions",
                False,
                "Immutable execution audit records, when any exist.",
            ),
            (
                "Confirmed reports",
                self.workspace.reports,
                False,
                "Existing confirmed-evidence reports.",
            ),
        ]
        return [
            WorkspaceArtifactIndexEntry(
                label=label,
                path=path,
                exists=path.exists(),
                required=required,
                description=description,
            )
            for label, path, required, description in entries
        ]

    def _resolve_output_path(self, output: Path | None) -> Path:
        workspace_namespace = (self.workspace.reports / "workspace").resolve()
        if output is None:
            timestamp = self._clock().astimezone(UTC).strftime("%Y%m%dT%H%M%SZ")
            return workspace_namespace / f"workspace-analysis-{timestamp}.md"
        destination = output.expanduser().resolve()
        if destination.suffix.lower() != ".md":
            raise FinsecError("Workspace analysis report output must use a .md filename.")
        reports_root = self.workspace.reports.resolve()
        try:
            relative = destination.relative_to(reports_root)
        except ValueError:
            return destination
        if not relative.parts or relative.parts[0] != "workspace":
            raise FinsecError(
                "Workspace analysis reports must not use the confirmed-report namespace; "
                f"write under {workspace_namespace} or outside {reports_root}."
            )
        return destination

    def _atomic_write(self, destination: Path, content: str) -> None:
        destination.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{destination.name}.tmp-",
            dir=destination.parent,
            text=True,
        )
        temporary = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, destination)
        except Exception:
            temporary.unlink(missing_ok=True)
            raise

    def _git_commit(self) -> str | None:
        try:
            result = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=Path(__file__).resolve().parents[2],
                capture_output=True,
                text=True,
                check=False,
            )
        except OSError:
            return None
        if result.returncode != 0:
            return None
        value = result.stdout.strip()
        return value if value else None
