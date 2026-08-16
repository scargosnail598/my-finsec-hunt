"""Markdown rendering for preliminary whole-workspace analysis."""

from __future__ import annotations

import os
from collections import Counter, defaultdict
from collections.abc import Iterable
from pathlib import Path

from finsec.behavior.domain import RelationshipType
from finsec.hypotheses.clustering import presentation_title, presentation_visible
from finsec.modeling.models import Observation
from finsec.readiness.domain import PipelineStage
from finsec.workspace_analysis.domain import WorkspaceAnalysisReportModel
from finsec.workspace_analysis.redaction import WorkspaceAnalysisRedactor


class WorkspaceAnalysisMarkdownRenderer:
    """Render a complete deterministic report without invoking active services."""

    def __init__(
        self,
        *,
        report_path: Path,
        include_command_output: bool,
        redactor: WorkspaceAnalysisRedactor | None = None,
    ) -> None:
        self.report_path = report_path
        self.include_command_output = include_command_output
        self.redactor = redactor or WorkspaceAnalysisRedactor()

    def render(self, report: WorkspaceAnalysisReportModel) -> str:
        """Return redacted Markdown with deterministic section ordering."""

        lines: list[str] = [
            "# FinSec Hunt Workspace Analysis Report",
            "",
            "> **Preliminary analysis - not a confirmed vulnerability report.**",
            ">",
            "> This is a preliminary workspace analysis report generated from currently "
            "available captures and derived artifacts.",
            ">",
            "> Hypotheses and research tasks in this document are candidate investigation "
            "leads and are not confirmed vulnerabilities.",
            ">",
            "> Execution readiness, approval permission, and confirmed evidence are separate "
            "states.",
            "",
        ]
        self._metadata(lines, report)
        self._executive_summary(lines, report)
        self._pipeline_summary(lines, report)
        self._capture_quality(lines, report)
        self._actors(lines, report)
        self._endpoints(lines, report)
        self._workflows(lines, report)
        self._invariants(lines, report)
        self._hypothesis_summary(lines, report)
        self._detailed_hypotheses(lines, report)
        self._business_logic(lines, report)
        self._research_tasks(lines, report)
        self._campaigns(lines, report)
        self._suppressed(lines, report)
        self._readiness(lines, report)
        self._next_actions(lines, report)
        self._artifact_index(lines, report)
        if self.include_command_output:
            self._diagnostics(lines, report)
        lines.extend(
            [
                "## Safety Boundary",
                "",
                "This command performed deterministic offline analysis and report generation only. "
                "It did not plan, approve, execute, replay target requests, promote evidence, "
                "confirm a vulnerability, or change a hypothesis lifecycle status.",
                "",
            ]
        )
        content = "\n".join(lines).rstrip() + "\n"
        return self.redactor.text(content)

    def _metadata(self, lines: list[str], report: WorkspaceAnalysisReportModel) -> None:
        metadata = report.metadata
        lines.extend(
            [
                "## Report Metadata",
                "",
                "| Field | Value |",
                "| --- | --- |",
                self._row("Workspace name", metadata.workspace_name),
                self._row("Workspace path", self._code(metadata.workspace_path)),
                self._row("Generated at", metadata.generated_at.isoformat()),
                self._row("Timezone", metadata.timezone),
                self._row("FinSec Hunt version", metadata.finsec_version),
                self._row("Repository Git commit", metadata.git_commit or "Unavailable"),
                self._row("Report mode", metadata.mode.value),
                self._row("Target hosts and scope", self._join(metadata.target_hosts)),
                self._row("Environment type", metadata.environment_type),
                self._row("Safety policy", metadata.safety_policy_summary),
                self._row("Active execution policy", metadata.active_execution_policy),
                self._row("Human approval policy", metadata.human_approval_policy),
                "",
            ]
        )
        warnings = [*metadata.configuration_warnings, *report.warnings]
        lines.extend(["### Configuration Warnings", ""])
        self._bullets(lines, warnings, empty="No workspace configuration warnings were detected.")
        lines.append("")

    def _executive_summary(self, lines: list[str], report: WorkspaceAnalysisReportModel) -> None:
        metrics = report.metrics
        values = [
            ("Captures", metrics.captures),
            ("Observations", metrics.observations),
            ("Endpoint families", metrics.endpoint_families),
            ("Suppressed endpoints", metrics.suppressed_endpoints),
            ("Actors", metrics.actors),
            ("Authenticated actors", metrics.authenticated_actors),
            ("Ownership baselines", metrics.ownership_baselines),
            ("Resources", metrics.resources),
            ("Workflow instances", metrics.workflow_instances),
            ("Workflow families", metrics.workflow_families),
            ("Active invariants", metrics.active_invariants),
            ("Visible hypotheses", metrics.visible_hypotheses),
            ("Active hypotheses", metrics.active_hypotheses),
            ("HYP hypotheses", metrics.hyp_hypotheses),
            ("BLH hypotheses", metrics.blh_hypotheses),
            ("Research tasks", metrics.research_tasks),
            ("Suppressed hypotheses", metrics.suppressed_hypotheses),
            ("Campaigns", metrics.campaigns),
            ("TEST_READY", metrics.test_ready),
            ("REVIEW_REQUIRED", metrics.review_required),
            ("RESEARCH_ONLY", metrics.research_only),
            ("Planned hypotheses", metrics.planned_hypotheses),
            ("Tested hypotheses", metrics.tested_hypotheses),
            ("Confirmed hypotheses", metrics.confirmed_hypotheses),
            ("Rejected hypotheses", metrics.rejected_hypotheses),
        ]
        lines.extend(["## Executive Summary", "", report.assessment, ""])
        if report.primary_blocker:
            lines.extend(
                [
                    f"**Primary blocker:** {self.redactor.text(report.primary_blocker)}",
                    "",
                ]
            )
        lines.extend(["| Metric | Count |", "| --- | ---: |"])
        lines.extend(self._row(label, count) for label, count in values)
        lines.append("")

    def _pipeline_summary(self, lines: list[str], report: WorkspaceAnalysisReportModel) -> None:
        lines.extend(
            [
                "## Pipeline Execution Summary",
                "",
                "| Stage | Status | Required | Duration | Inputs | Outputs | Warning/Error |",
                "| --- | --- | ---: | ---: | --- | --- | --- |",
            ]
        )
        for stage in report.stages:
            issue = stage.error_summary or "; ".join(stage.warnings) or "None"
            lines.append(
                self._row(
                    stage.display_name,
                    stage.status.value,
                    "yes" if stage.required else "no",
                    f"{stage.duration:.3f}s",
                    self._join(stage.inputs),
                    self._join(stage.outputs),
                    issue,
                )
            )
        lines.extend(
            [
                "",
                "Stages marked `SKIPPED` were either already current, not applicable, disabled "
                "by `--report-only`, or blocked by an explicitly reported prerequisite failure.",
                "",
            ]
        )

    def _capture_quality(self, lines: list[str], report: WorkspaceAnalysisReportModel) -> None:
        lines.extend(["## Capture and Observation Quality", ""])
        if self._unavailable(lines, report, "capture and observation quality"):
            return
        observations_by_capture: dict[str, list[Observation]] = defaultdict(list)
        for observation in report.observations:
            if observation.capture_id is not None:
                observations_by_capture[observation.capture_id].append(observation)
        lines.extend(
            [
                "| Capture ID | Actor | Type | Purpose | Channel | Requests | Observations | "
                "Sessions | Auth material detected | Quality | Broad/multi-intent | "
                "Duplicate/noise indicators | Missing metadata / warnings |",
                "| --- | --- | --- | --- | --- | ---: | ---: | ---: | --- | --- | "
                "--- | --- | --- |",
            ]
        )
        for capture in report.captures:
            selected = observations_by_capture.get(capture.capture_id, [])
            channels = sorted({item.channel for item in selected})
            sessions = {item.session_identity for item in selected if item.session_identity}
            auth = any(item.authentication.present for item in selected)
            quality = [item.value for item in capture.quality.labels]
            broad = sorted(set(quality).intersection({"BROAD", "MIXED", "MULTI_INTENT"}))
            noise = (
                f"noise={capture.counts.noise}; protocol={capture.counts.protocol_support}; "
                f"repeated={capture.analysis_metrics.repeated_passive_observations_saturated}"
            )
            missing: list[str] = list(capture.warnings)
            if capture.actor_id in {"UNKNOWN", "ANONYMOUS"}:
                missing.append("controlled actor metadata unavailable")
            if capture.capture_mode.value == "UNKNOWN":
                missing.append("capture mode unknown")
            if capture.intent.action == "UNKNOWN":
                missing.append("capture purpose unknown")
            purpose = (
                f"{capture.intent.action} {capture.intent.resource_type} ({capture.intent.label})"
            )
            lines.append(
                self._row(
                    capture.capture_id,
                    capture.actor_id,
                    capture.source.type.value,
                    purpose,
                    self._join(channels),
                    capture.counts.observations,
                    len(selected),
                    len(sessions),
                    "yes" if auth else "no",
                    self._join(quality),
                    self._join(broad),
                    noise,
                    self._join(missing),
                )
            )
        if not report.captures:
            lines.append(
                self._row(
                    "None",
                    "-",
                    "-",
                    "-",
                    "-",
                    0,
                    0,
                    0,
                    "no",
                    "-",
                    "-",
                    "-",
                    "No capture metadata is available.",
                )
            )
        hosts = sorted({item.host for item in report.observations})
        methods = sorted({item.method for item in report.observations})
        authenticated = sum(item.authentication.present for item in report.observations)
        unauthenticated = len(report.observations) - authenticated
        state_changing = sum(
            item.method not in {"GET", "HEAD", "OPTIONS"} for item in report.observations
        )
        repeated = len(report.observations) - len(
            {(item.actor, item.method, item.host, item.path) for item in report.observations}
        )
        lines.extend(
            [
                "",
                "### Coverage Summary",
                "",
                f"- Hosts covered: {self._join(hosts)}",
                f"- HTTP methods covered: {self._join(methods)}",
                "- Authenticated / unauthenticated observations: "
                f"{authenticated} / {unauthenticated}",
                f"- State-changing observations: {state_changing}",
                f"- Repeated route/actor observations: {repeated}",
                "- Raw credentials, cookies, tokens, request bodies, and response bodies are not "
                "included.",
                "",
            ]
        )
        low_coverage = [
            item
            for item in report.captures
            if item.counts.primary == 0 or item.intent.action == "UNKNOWN"
        ]
        if low_coverage:
            lines.append(
                "Coverage warning: focused intent coverage is insufficient for "
                + self._join(item.capture_id for item in low_coverage)
                + "."
            )
            lines.append("")

    def _actors(self, lines: list[str], report: WorkspaceAnalysisReportModel) -> None:
        lines.extend(["## Actors, Authentication, Identity, and Ownership", ""])
        if self._unavailable(lines, report, "actors, authentication, identity, and ownership"):
            return
        target_accounts = (
            {item.id: item for item in report.target.accounts} if report.target else {}
        )
        model_actors = {item.name: item for item in report.actors}
        readiness_actors = (
            {item.actor_id: item for item in report.readiness.actors} if report.readiness else {}
        )
        observations_by_actor = defaultdict(list)
        for observation in report.observations:
            observations_by_actor[observation.actor].append(observation)
        baselines_by_actor = defaultdict(list)
        for baseline in report.ownership.controlled_baselines:
            baselines_by_actor[baseline.actor_id].append(baseline)
        actor_ids = sorted(
            set(target_accounts)
            | set(model_actors)
            | set(readiness_actors)
            | set(observations_by_actor)
            | set(baselines_by_actor)
        )
        lines.extend(
            [
                "| Actor ID | Label | Authentication mechanism | Credential state | Credential "
                "accepted | Scope validated | Credential source capture | Identity confirmed | "
                "Session coverage | Owned object types | Ownership baselines | Controlled "
                "baseline status | Planning readiness | Execution readiness | Blockers |",
                "| --- | --- | --- | --- | --- | --- | --- | --- | ---: | --- | ---: | --- | "
                "--- | --- | --- |",
            ]
        )
        for actor_id in actor_ids:
            account = target_accounts.get(actor_id)
            actor = model_actors.get(actor_id)
            readiness = readiness_actors.get(actor_id)
            auth = account.authentication if account is not None else None
            mechanisms: list[str] = []
            if auth is not None:
                mechanisms.append(f"configured={auth.auth_type}")
            if actor is not None and actor.authentication_types:
                mechanisms.append(f"observed={self._join(actor.authentication_types)}")
            mechanism = "; ".join(mechanisms) or "none observed"
            credential = (
                readiness.credential.status if readiness else (auth.status if auth else "UNKNOWN")
            )
            source = auth.source.file_reference if auth is not None else None
            sessions = {
                item.session_identity
                for item in observations_by_actor.get(actor_id, [])
                if item.session_identity
            }
            baselines = baselines_by_actor.get(actor_id, [])
            owned_types = sorted({item.subject_resource_type for item in baselines})
            blockers: list[str] = []
            if readiness is not None:
                if not readiness.credential.accepted:
                    blockers.append("credential not accepted")
                if not readiness.target_validation.recorded:
                    blockers.append("scope not validated")
                if not readiness.identity_confirmation.confirmed:
                    blockers.append("identity not confirmed")
                if readiness.ownership.confirmed_baselines == 0:
                    blockers.append("ownership baseline missing")
                if readiness.credential.status not in {"READY", "NOT_REQUIRED"}:
                    blockers.append(f"credential {readiness.credential.status}")
            lines.append(
                self._row(
                    actor_id,
                    actor.name if actor else (account.id if account else actor_id),
                    mechanism,
                    credential,
                    "yes" if readiness and readiness.credential.accepted else "no",
                    "yes" if readiness and readiness.target_validation.recorded else "no",
                    source or "not recorded",
                    "yes" if readiness and readiness.identity_confirmation.confirmed else "no",
                    len(sessions),
                    self._join(owned_types),
                    len(baselines),
                    "available" if baselines else "missing",
                    "ready" if readiness and readiness.capabilities.planning else "blocked",
                    (
                        "ready"
                        if readiness and readiness.capabilities.authorization_execution
                        else "blocked"
                    ),
                    self._join(blockers),
                )
            )
        if not actor_ids:
            lines.append(
                self._row(
                    "None",
                    "-",
                    "-",
                    "no",
                    "no",
                    "-",
                    "-",
                    "no",
                    0,
                    "-",
                    0,
                    "missing",
                    "blocked",
                    "blocked",
                    "No actors are configured.",
                )
            )
        lines.extend(
            [
                "",
                "Authentication evidence, identity confirmation, object ownership evidence, "
                "hypothesis readiness, and execution-policy permission are independent facts. "
                "Authentication never substitutes for ownership, and two actors using the same "
                "route do not automatically constitute two controlled ownership baselines.",
                "",
            ]
        )

    def _endpoints(self, lines: list[str], report: WorkspaceAnalysisReportModel) -> None:
        lines.extend(["## Endpoint and Resource Inventory", ""])
        if self._unavailable(lines, report, "endpoint and resource inventory"):
            return
        lines.extend(
            [
                "| Host/service | Method | Route family | Authentication | Security relevance | "
                "Behavior | Resource | Identifier semantics | Suppression |",
                "| --- | --- | --- | --- | ---: | --- | --- | --- | --- |",
            ]
        )
        semantic_counts: Counter[str] = Counter()
        for endpoint in report.endpoints:
            identifiers: list[str] = []
            for parameter in endpoint.parameters:
                semantics = parameter.identifier_semantics
                if parameter.client_controlled:
                    semantic_counts[semantics.semantic_class.value] += 1
                identifiers.append(
                    f"{parameter.name}@{parameter.location}: {semantics.semantic_class.value}/"
                    f"{semantics.resource_role.value}/{semantics.ownership_state.value}"
                )
            behavior = "state-changing" if endpoint.state_change else "read-only/observational"
            lines.append(
                self._row(
                    self._join(endpoint.hosts),
                    endpoint.method,
                    endpoint.path,
                    (
                        f"required={str(endpoint.authentication.required).lower()}, "
                        f"type={endpoint.authentication.observed_type}"
                    ),
                    endpoint.security_relevance,
                    behavior,
                    endpoint.resource.type,
                    self._join(identifiers),
                    endpoint.disposition,
                )
            )
        if not report.endpoints:
            lines.append(
                self._row(
                    "None",
                    "-",
                    "-",
                    "-",
                    0,
                    "-",
                    "-",
                    "-",
                    "No endpoint artifact records are available.",
                )
            )
        lines.extend(["", "### Identifier Semantics", ""])
        labels = [
            "OWNED_OBJECT",
            "OBJECT_IDENTIFIER",
            "REGION",
            "SHARED_SCOPE",
            "TENANT_CONTAINER",
            "PARENT_CONTAINER",
            "COLLECTION",
            "ACTOR_IDENTIFIER",
            "OPAQUE_UNKNOWN",
            "NON_SECURITY_RELEVANT",
        ]
        lines.extend(["| Semantic type | Count |", "| --- | ---: |"])
        lines.extend(self._row(label, semantic_counts[label]) for label in labels)
        lines.extend(
            [
                "",
                "Shared regions, availability zones, product codes, collection labels, and other "
                "infrastructure values are not treated as owned objects without explicit evidence.",
                "",
                "### Resources",
                "",
                "| Resource ID | Type | Identifiers | Owner state | Operations | States | "
                "Disposition |",
                "| --- | --- | --- | --- | ---: | --- | --- |",
            ]
        )
        for resource in report.resources:
            lines.append(
                self._row(
                    resource.id,
                    resource.name,
                    self._join(resource.identifiers),
                    f"{resource.owner.value or 'unknown'} ({resource.owner.knowledge_status})",
                    len(resource.operations),
                    self._join(resource.states),
                    resource.disposition,
                )
            )
        if not report.resources:
            lines.append(
                self._row(
                    "None", "-", "-", "unknown", 0, "-", "No resource model records are available."
                )
            )
        lines.append("")

    def _workflows(self, lines: list[str], report: WorkspaceAnalysisReportModel) -> None:
        lines.extend(["## Workflow and Behavior Analysis", ""])
        if self._unavailable(lines, report, "workflow and behavior analysis"):
            return
        hard = [
            item
            for item in report.propagation_links
            if item.relationship_type == RelationshipType.CAUSAL_HARD
        ]
        soft = [
            item
            for item in report.propagation_links
            if item.relationship_type == RelationshipType.CONTEXT_SOFT
        ]
        lines.extend(
            [
                f"Hard causal links: **{len(hard)}**; soft contextual links: **{len(soft)}**; "
                "other typed relationships: "
                f"**{len(report.propagation_links) - len(hard) - len(soft)}**.",
                "",
                "Hard causal evidence requires typed producer/consumer support. Capture order, "
                "actor match, session match, and scalar equality are supporting context only; "
                "coincidental scalar similarity is never presented as causation.",
                "",
                "### Workflow Instances",
                "",
                "| Workflow | Family | Actors | Captures | Ordered steps | Resources | Outcome | "
                "Reconstruction confidence | Boundary warnings |",
                "| --- | --- | --- | --- | --- | --- | --- | --- | --- |",
            ]
        )
        for workflow in report.workflow_instances:
            steps = [
                f"{step.position}. {step.action_name} ({step.method} {step.route})"
                for step in sorted(workflow.steps, key=lambda item: item.position)
            ]
            lines.append(
                self._row(
                    workflow.id,
                    workflow.family_id,
                    self._join(workflow.actors),
                    self._join(workflow.captures),
                    self._join(steps),
                    self._join(workflow.resource_types),
                    workflow.terminal_outcome or "unknown",
                    workflow.segmentation_confidence.value,
                    self._join(workflow.ambiguities),
                )
            )
        if not report.workflow_instances:
            lines.append(
                self._row(
                    "None",
                    "-",
                    "-",
                    "-",
                    "-",
                    "-",
                    "-",
                    "-",
                    "No workflow instances are available.",
                )
            )
        lines.extend(["", "### Workflow Families", ""])
        for family in report.workflow_families:
            lines.extend(
                [
                    f"#### {self._heading(family.id)} - {self._heading(family.name)}",
                    "",
                    f"- Actors: {self._join(family.actors)}",
                    f"- Workflow instances: {self._join(family.workflow_instance_ids)}",
                    f"- Ordered common path: {self._join(family.common_path)}",
                    f"- Optional steps: {self._join(family.optional_steps)}",
                    f"- Resources: {self._join(family.resource_types)}",
                    f"- State transitions: {self._join(family.transition_frequencies)}",
                    f"- Reconstruction confidence: {family.inference_confidence.value}",
                    f"- Confidence explanation: {self._join(family.confidence_explanation)}",
                    f"- Boundary warnings/research clues: {self._join(family.research_clues)}",
                    "",
                    "| Prerequisite | Dependent step | Support | Causal basis | Counterexamples | "
                    "Confidence |",
                    "| --- | --- | ---: | --- | --- | --- |",
                ]
            )
            for prerequisite in family.causal_prerequisites:
                lines.append(
                    self._row(
                        prerequisite.prerequisite_action,
                        prerequisite.dependent_action,
                        f"{prerequisite.support_count}/{prerequisite.comparable_instances} "
                        f"({prerequisite.support_ratio:.2f})",
                        self._join(item.value for item in prerequisite.causal_bases),
                        self._join(prerequisite.counterexamples),
                        prerequisite.confidence.value,
                    )
                )
            if not family.causal_prerequisites:
                lines.append(
                    self._row(
                        "None established", "-", 0, "-", "-", family.inference_confidence.value
                    )
                )
            lines.append("")
        if not report.workflow_families:
            lines.extend(["No workflow families are available.", ""])
        suspicious = sorted(
            {
                *(
                    warning
                    for workflow in report.workflow_instances
                    for warning in workflow.ambiguities
                ),
                *(
                    item.evidence_reason
                    for item in report.propagation_links
                    if item.relationship_type != RelationshipType.CAUSAL_HARD
                    and (
                        item.source_actor != item.destination_actor
                        or item.source_capture != item.destination_capture
                        or item.source_session != item.destination_session
                    )
                ),
            }
        )
        lines.extend(["### Suspicious Merge and Boundary Review", ""])
        self._bullets(
            lines,
            suspicious,
            empty=(
                "No explicit cross-actor, cross-session, cross-capture, or segmentation warning "
                "is recorded."
            ),
        )
        lines.append("")

    def _invariants(self, lines: list[str], report: WorkspaceAnalysisReportModel) -> None:
        lines.extend(["## Invariant Summary", ""])
        if self._unavailable(lines, report, "invariant summary"):
            return
        related: dict[str, list[str]] = defaultdict(list)
        for hypothesis in report.hypotheses:
            for invariant_id in hypothesis.invariant:
                related[invariant_id].append(hypothesis.id)
        counts: Counter[str] = Counter(item.category for item in report.invariants)
        counts.update(item.invariant_type for item in report.business_invariants)
        lines.extend(["| Category | Total |", "| --- | ---: |"])
        for category, count in sorted(counts.items()):
            lines.append(self._row(category, count))
        if not counts:
            lines.append(self._row("None", 0))
        lines.extend(
            [
                "",
                "### Endpoint Security Invariants",
                "",
                "| ID | Title/statement | Category | Subject/resource | Workflow/endpoints | "
                "Supporting observations | Confidence | Evidence type | Counterevidence | "
                "Related hypotheses | Status |",
                "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
            ]
        )
        for security_invariant in report.invariants:
            lines.append(
                self._row(
                    security_invariant.id,
                    security_invariant.statement,
                    security_invariant.category,
                    self._join(security_invariant.resources),
                    self._join(security_invariant.endpoints),
                    self._join(security_invariant.evidence),
                    security_invariant.confidence,
                    security_invariant.knowledge_status,
                    "None recorded",
                    self._join(related.get(security_invariant.id, [])),
                    f"{security_invariant.disposition}/{security_invariant.validation_status}",
                )
            )
        if not report.invariants:
            lines.append(
                self._row(
                    "None",
                    "No endpoint invariants are available.",
                    "-",
                    "-",
                    "-",
                    "-",
                    "-",
                    "-",
                    "-",
                    "-",
                    "-",
                )
            )
        lines.extend(["", "### Business Invariants", ""])
        lines.extend(
            [
                "| ID | Statement | Category | Resource | Workflow | Support | Confidence | "
                "Causal evidence | Counterevidence | Related hypotheses | Status |",
                "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
            ]
        )
        for business_invariant in report.business_invariants:
            lines.append(
                self._row(
                    business_invariant.id,
                    business_invariant.statement,
                    business_invariant.invariant_type,
                    self._join(business_invariant.resource_types),
                    business_invariant.workflow_family_id,
                    self._join(business_invariant.supporting_observations),
                    business_invariant.confidence.value,
                    self._join(business_invariant.causal_evidence),
                    self._join(
                        [
                            *business_invariant.counterexamples,
                            *business_invariant.contradicting_observations,
                        ]
                    ),
                    self._join(related.get(business_invariant.id, [])),
                    business_invariant.epistemic_status.value,
                )
            )
        if not report.business_invariants:
            lines.append(
                self._row(
                    "None",
                    "No business invariants are available.",
                    "-",
                    "-",
                    "-",
                    "-",
                    "-",
                    "-",
                    "-",
                    "-",
                    "-",
                )
            )
        lines.append("")

    def _hypothesis_summary(self, lines: list[str], report: WorkspaceAnalysisReportModel) -> None:
        lines.extend(["## Hypothesis Summary", ""])
        if self._unavailable(lines, report, "hypothesis summary"):
            return
        records = [item for item in report.hypotheses if presentation_visible(item)]
        groupings: list[tuple[str, Counter[str]]] = [
            ("Readiness", Counter[str](item.readiness for item in records)),
            ("Priority", Counter[str](item.priority for item in records)),
            ("Lifecycle status", Counter[str](item.status for item in records)),
            (
                "Generator",
                Counter[str](
                    item.generation.generator
                    if item.generation is not None
                    else "business-logic-analysis"
                    if item.id.startswith("BLH-")
                    else "legacy/researcher"
                    for item in records
                ),
            ),
            (
                "Resource/domain subject",
                Counter[str](item.domain_intent.subject_resource for item in records),
            ),
            (
                "Action/operation",
                Counter[str](item.domain_intent.operation.value for item in records),
            ),
            (
                "Service",
                Counter[str](
                    service
                    for item in records
                    if item.semantic_descriptor is not None
                    for service in item.semantic_descriptor.target_services
                ),
            ),
            (
                "Campaign",
                Counter[str](item.grouping.campaign_id or "unassigned" for item in records),
            ),
            (
                "Suppression state",
                Counter[str](item.disposition for item in report.hypotheses),
            ),
        ]
        for title, values in groupings:
            lines.extend([f"### {title}", "", "| Value | Count |", "| --- | ---: |"])
            for value, count in sorted(values.items(), key=lambda item: (-item[1], str(item[0]))):
                lines.append(self._row(value, count))
            if not values:
                lines.append(self._row("None", 0))
            lines.append("")
        lines.extend(
            [
                "Unified readiness shown here is serialized by the existing canonical readiness "
                "engine; this renderer does not recalculate it.",
                "",
            ]
        )

    def _detailed_hypotheses(self, lines: list[str], report: WorkspaceAnalysisReportModel) -> None:
        lines.extend(["## Detailed Active Hypotheses", ""])
        if self._unavailable(lines, report, "detailed active hypotheses"):
            return
        endpoints = {item.id: item for item in report.endpoints}
        plans = {item.hypothesis_id: item for item in report.plans}
        validations = {item.hypothesis_id: item for item in report.validations}
        active = [
            item
            for item in report.hypotheses
            if item.kind == "SECURITY_HYPOTHESIS" and presentation_visible(item)
        ]
        for item in active:
            selected_endpoints = [
                endpoints[identifier]
                for identifier in item.source.endpoints
                if identifier in endpoints
            ]
            hosts = sorted({host for endpoint in selected_endpoints for host in endpoint.hosts})
            methods = sorted({endpoint.method for endpoint in selected_endpoints})
            routes = sorted({endpoint.path for endpoint in selected_endpoints})
            plan = plans.get(item.id)
            validation = validations.get(item.id)
            target = item.mutation_target
            semantics = target.semantics
            assessment = item.readiness_assessment
            coverage = assessment.comparison_coverage
            constructability = assessment.constructability
            ownership_capabilities = [
                capability
                for capability in assessment.capabilities
                if capability.capability.value in {"OWNERSHIP", "BASELINE"}
                and capability.required
            ]
            ownership_satisfied = bool(ownership_capabilities) and all(
                capability.satisfied for capability in ownership_capabilities
            )
            related = sorted(
                set(item.grouping.campaign_member_ids or item.grouping.cluster_member_ids)
                - {item.id}
            )
            ownership_evidence = [
                *semantics.evidence,
                *coverage.evidence_references,
                *coverage.baseline_ids,
            ]
            comparison_contexts = [
                (
                    f"{baseline.canonical_reference}: actor={baseline.actor_id}; "
                    f"object={baseline.object_reference}; "
                    f"parent={baseline.parent_reference or 'None'}; "
                    f"liveness={baseline.liveness.value}; "
                    f"target-parent={'yes' if baseline.matches_target_parent else 'no'}; "
                    "provenance="
                    + self._join(
                        sorted(
                            {
                                *baseline.baseline_ids,
                                *baseline.endpoint_ids,
                                *baseline.supporting_relationship_ids,
                                *baseline.observation_ids,
                                *baseline.liveness_evidence_references,
                            }
                        )
                    )
                )
                for baseline in coverage.baselines
            ]
            supporting = [
                *item.eligibility_evidence,
                *(evidence.detail for evidence in item.domain_intent.positive_evidence),
                *item.source.observations,
                *item.invariant,
            ]
            negative = [
                *semantics.counterevidence,
                *(evidence.detail for evidence in item.domain_intent.counterevidence),
                *item.domain_intent.ambiguity,
            ]
            blockers = [
                f"{blocker.stage.value}/{blocker.code}: {blocker.summary}"
                for blocker in assessment.blockers
            ]
            next_action = (
                item.presentation.next_action
                or constructability.next_action
                or next(
                    (
                        blocker.next_action
                        for blocker in assessment.blockers
                        if blocker.next_action is not None
                    ),
                    None,
                )
                or (
                    f"Review {item.id} before creating a plan."
                    if item.readiness == "TEST_READY"
                    else "Collect the missing evidence listed below."
                )
            )
            lines.extend(
                [
                    f"### {self._heading(item.id)} - {self._heading(presentation_title(item))}",
                    "",
                    "| Field | Value |",
                    "| --- | --- |",
                    self._row(
                        "Generator",
                        item.generation.generator
                        if item.generation
                        else (
                            "business-logic-analysis"
                            if item.id.startswith("BLH-")
                            else "legacy/researcher"
                        ),
                    ),
                    self._row("Priority / score", f"{item.priority} / {item.scores.total}"),
                    self._row("Lifecycle status", item.status),
                    self._row("Unified readiness", item.readiness),
                    self._row(
                        "Ownership evidence satisfied",
                        "yes" if ownership_satisfied else "no",
                    ),
                    self._row(
                        "Cross-parent comparison satisfied",
                        "yes" if coverage.cross_parent_comparison else "no",
                    ),
                    self._row(
                        "Automated execution support",
                        "satisfied" if constructability.supported else "unsatisfied",
                    ),
                    self._row("Execution mode", constructability.execution_mode.value),
                    self._row(
                        "Constructability blocker codes",
                        self._join([blocker.code for blocker in constructability.blockers]),
                    ),
                    self._row(
                        "Execution liveness",
                        self._join(
                            [
                                f"{baseline.canonical_reference}={baseline.liveness.value}"
                                for baseline in constructability.baselines
                            ]
                        ),
                    ),
                    self._row(
                        "Identity confirmation",
                        "required="
                        f"{'yes' if constructability.identity_confirmation_required else 'no'}; "
                        "confirmed="
                        f"{'yes' if constructability.identity_confirmed else 'no'}",
                    ),
                    self._row(
                        "Target host/service",
                        self._join(
                            hosts
                            or (
                                item.semantic_descriptor.target_services
                                if item.semantic_descriptor
                                else []
                            )
                        ),
                    ),
                    self._row("HTTP method", self._join(methods)),
                    self._row("Route template", self._join(routes)),
                    self._row("Domain subject", item.domain_intent.subject_resource),
                    self._row("Action/operation", item.domain_intent.operation.value),
                    self._row("Tested/mutated identifier", target.parameter or "None"),
                    self._row("Identifier location", target.location or target.json_path or "None"),
                    self._row(
                        "Identifier semantic type",
                        f"{semantics.semantic_class.value}/{semantics.resource_role.value}",
                    ),
                    self._row("Actor binding", item.domain_intent.binding.value),
                    self._row("Object binding", target.expected_authorization_relationship),
                    self._row(
                        "Comparison coverage",
                        f"{coverage.observed_distinct_actors}/"
                        f"{coverage.required_distinct_actors} actors; "
                        f"{coverage.distinct_controlled_objects} objects; "
                        f"{coverage.distinct_parent_references} parent contexts",
                    ),
                    self._row(
                        "Baseline actors",
                        self._join(coverage.baseline_actor_ids),
                    ),
                    self._row(
                        "Opaque parent references",
                        self._join(coverage.parent_references),
                    ),
                    self._row(
                        "Target-parent baseline",
                        coverage.target_parent_baseline_reference or "None",
                    ),
                    self._row(
                        "Controlled comparison baselines",
                        self._join(coverage.comparison_baseline_references),
                    ),
                    self._row("Ownership state", semantics.ownership_state.value),
                    self._row("Campaign", item.grouping.campaign_id or "None"),
                    self._row("Related hypotheses", self._join(related)),
                    self._row("Suppression relationship", item.grouping.relationship.value),
                    self._row(
                        "Existing plan",
                        f"{plan.id} ({plan.status}, approval={plan.approval_status})"
                        if plan
                        else "None",
                    ),
                    self._row("Evidence status", item.evidence_status),
                    self._row(
                        "Test-result status", validation.disposition if validation else item.status
                    ),
                    self._row("Recommended next action", next_action),
                    "",
                    "**Hypothesis.** " + self.redactor.text(item.hypothesis),
                    "",
                    "**Reasoning.** " + self.redactor.text(item.reasoning),
                    "",
                    "**Cross-actor comparison interpretation.** "
                    + self.redactor.text(coverage.explanation),
                    "",
                    "**Controlled comparison contexts**",
                    "",
                ]
            )
            self._bullets(
                lines,
                comparison_contexts,
                empty="No canonical comparison context is recorded.",
            )
            lines.extend(
                [
                    "",
                    "**Eligibility evidence**",
                    "",
                ]
            )
            self._bullets(lines, supporting, empty="None recorded.")
            lines.extend(["", "**Ownership evidence**", ""])
            self._bullets(
                lines, ownership_evidence, empty="No controlled ownership evidence is recorded."
            )
            lines.extend(["", "**Negative evidence and counterexamples**", ""])
            self._bullets(
                lines, negative, empty="No negative evidence or counterexample is recorded."
            )
            lines.extend(["", "**Required prerequisites**", ""])
            self._bullets(
                lines, [*item.preconditions, *item.required_state], empty="None recorded."
            )
            lines.extend(["", "**Missing evidence**", ""])
            self._bullets(
                lines,
                [*item.missing_evidence, *assessment.missing_prerequisites],
                empty="None recorded.",
            )
            lines.extend(["", "**Readiness blockers**", ""])
            self._bullets(lines, blockers, empty="No unified-readiness blocker is recorded.")
            artifact_paths = [
                self._artifact_link("Hypothesis backlog", report, "Hypothesis backlog"),
                *([self._artifact_link("Plans", report, "Plans")] if plan is not None else []),
            ]
            lines.extend(["", "**Relevant artifact paths**", ""])
            self._bullets(lines, artifact_paths, empty="None available.", raw=True)
            lines.append("")
        if not active:
            lines.extend(["No visible active security hypotheses are available.", ""])

    def _business_logic(self, lines: list[str], report: WorkspaceAnalysisReportModel) -> None:
        lines.extend(["## Business-Logic Hypotheses", ""])
        if self._unavailable(lines, report, "business-logic hypotheses"):
            return
        canonical_by_id = {item.id: item for item in report.hypotheses}
        for logic_hypothesis in report.logic_hypotheses:
            canonical = canonical_by_id.get(logic_hypothesis.id)
            lines.extend(
                [
                    f"### {self._heading(logic_hypothesis.id)} - "
                    f"{self._heading(logic_hypothesis.title)}",
                    "",
                    "| Field | Value |",
                    "| --- | --- |",
                    self._row(
                        "Priority / score",
                        (
                            f"{canonical.priority} / {canonical.scores.total}"
                            if canonical is not None
                            else "Unavailable"
                        ),
                    ),
                    self._row("Workflow family", logic_hypothesis.workflow_family_id),
                    self._row("Category", logic_hypothesis.family),
                    self._row("Affected action", logic_hypothesis.affected_action),
                    self._row(
                        "Affected transition",
                        logic_hypothesis.affected_transition_id or "None",
                    ),
                    self._row(
                        "Expected invariant",
                        f"{logic_hypothesis.invariant_id}: {logic_hypothesis.invariant_statement}",
                    ),
                    self._row("Candidate violation", logic_hypothesis.mutated_behavior),
                    self._row("Canonical behavior", logic_hypothesis.canonical_behavior),
                    self._row(
                        "Supporting behavior evidence",
                        self._join(logic_hypothesis.supporting_evidence),
                    ),
                    self._row(
                        "Missing behavioral evidence",
                        self._join(
                            [
                                *logic_hypothesis.readiness_blockers,
                                *logic_hypothesis.uncertainty,
                            ]
                        ),
                    ),
                    self._row(
                        "Counterexamples",
                        self._join(logic_hypothesis.contradicting_evidence),
                    ),
                    self._row("Readiness", logic_hypothesis.readiness.value),
                    self._row(
                        "Constructability blockers",
                        (
                            self._join(
                                [
                                    blocker.code
                                    for blocker in canonical.readiness_assessment.constructability.blockers
                                ]
                            )
                            if canonical is not None
                            else "Unavailable"
                        ),
                    ),
                    self._row(
                        "Research requirements",
                        self._join(logic_hypothesis.suggested_validation_strategy),
                    ),
                    self._row(
                        "Safety classification",
                        logic_hypothesis.safety_classification.value,
                    ),
                    self._row("Epistemic status", logic_hypothesis.epistemic_status.value),
                    "",
                ]
            )
        if not report.logic_hypotheses:
            lines.extend(["No BLH records are available.", ""])
        lines.extend(["### Rejected Business-Logic Mutations", ""])
        lines.extend(
            ["| ID | Workflow | Category | Action | Reason |", "| --- | --- | --- | --- | --- |"]
        )
        for rejection in report.mutation_rejections:
            lines.append(
                self._row(
                    rejection.id,
                    rejection.workflow_family_id,
                    rejection.mutation_family,
                    rejection.affected_action,
                    self._join(rejection.reasons),
                )
            )
        if not report.mutation_rejections:
            lines.append(
                self._row("None", "-", "-", "-", "No rejected mutation records are available.")
            )
        lines.extend(
            [
                "",
                "HYP and BLH records are combined only through shared semantic descriptors; "
                "title similarity alone is not a merge criterion.",
                "",
            ]
        )

    def _research_tasks(self, lines: list[str], report: WorkspaceAnalysisReportModel) -> None:
        lines.extend(["## Research Tasks", ""])
        tasks = [
            item
            for item in report.hypotheses
            if item.kind == "RESEARCH_TASK" and presentation_visible(item)
        ]
        lines.extend(
            [
                "| Task ID | Title | Priority | Related hypothesis/campaign | Related invariant | "
                "Related workflow | Research-only reason | Missing evidence | Expected evidence | "
                "Passive capture recommendation | Promotion criteria | Blocking dependency |",
                "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
            ]
        )
        for item in tasks:
            reason = next(iter(item.readiness_assessment.reasons), item.reasoning)
            promotion = (
                item.readiness_assessment.blockers[0].next_action
                if item.readiness_assessment.blockers
                and item.readiness_assessment.blockers[0].next_action
                else "Satisfy unified readiness prerequisites and regenerate the backlog."
            )
            lines.append(
                self._row(
                    item.id,
                    presentation_title(item),
                    item.priority,
                    item.grouping.primary_hypothesis_id or item.grouping.campaign_id or "None",
                    self._join(item.invariant),
                    item.component if item.category == "business_logic" else "None",
                    reason,
                    self._join(item.missing_evidence),
                    self._join(item.evidence_to_collect),
                    "Collect focused normal-behavior traffic; do not execute a hypothesis.",
                    promotion,
                    self._join(item.readiness_assessment.missing_prerequisites),
                )
            )
        if not tasks:
            lines.append(
                self._row(
                    "None",
                    "No active research tasks are available.",
                    "-",
                    "-",
                    "-",
                    "-",
                    "-",
                    "-",
                    "-",
                    "-",
                    "-",
                    "-",
                )
            )
        lines.extend(
            [
                "",
                "Passive observation work is distinct from active testing. Any action requiring "
                "execution remains separately gated by a plan, human approval, environment policy, "
                "and current evidence.",
                "",
            ]
        )

    def _campaigns(self, lines: list[str], report: WorkspaceAnalysisReportModel) -> None:
        lines.extend(["## Campaigns, Clustering, and Deduplication", ""])
        for campaign in report.campaigns:
            suppressed = [
                item.id
                for item in report.hypotheses
                if item.id in campaign.member_ids and not presentation_visible(item)
            ]
            lines.extend(
                [
                    f"### {self._heading(campaign.id)} - {self._heading(campaign.title)}",
                    "",
                    "| Field | Value |",
                    "| --- | --- |",
                    self._row("Relationship type", campaign.relationship.value),
                    self._row("Primary hypothesis", campaign.primary_hypothesis_id),
                    self._row("Members", self._join(campaign.member_ids)),
                    self._row("Services", self._join(campaign.target_services)),
                    self._row("Resources", self._join(campaign.affected_resources)),
                    self._row("Cluster basis", self._join(campaign.cluster_ids)),
                    self._row("Semantic comparison", self._join(campaign.distinctions)),
                    self._row("Suppression winner", campaign.primary_hypothesis_id),
                    self._row("Suppressed members", self._join(suppressed)),
                    self._row("Manual-review warnings", self._join(campaign.missing_controls)),
                    self._row("Next action", campaign.next_action),
                    "",
                ]
            )
        if not report.campaigns:
            lines.extend(["No cross-generator campaigns are available.", ""])
        lines.extend(
            [
                "Exact duplicates, overlapping test campaigns, variants, and related-but-distinct "
                "records remain separate relationship types. UUID object identifiers are not "
                "suppressed against shared region-like values, and distinct domain subjects or "
                "owned identifiers are not collapsed from route or title similarity alone.",
                "",
                "### Business-Logic Precision Clusters",
                "",
                "| Cluster | Representative | Members | Promotion | Readiness | Evidence "
                "strength | "
                "Independent support | Suppression reason |",
                "| --- | --- | --- | --- | --- | --- | ---: | --- |",
            ]
        )
        for cluster in report.logic_clusters:
            lines.append(
                self._row(
                    cluster.id,
                    cluster.representative_hypothesis_id,
                    self._join(cluster.member_hypothesis_ids),
                    cluster.promotion.value,
                    cluster.readiness.value,
                    cluster.evidence_strength.value,
                    cluster.independent_support_count,
                    self._join(cluster.suppression_reasons),
                )
            )
        if not report.logic_clusters:
            lines.append(
                self._row(
                    "None", "-", "-", "-", "-", "-", 0, "No logic precision clusters are available."
                )
            )
        lines.append("")

    def _suppressed(self, lines: list[str], report: WorkspaceAnalysisReportModel) -> None:
        lines.extend(["## Suppressed Items Appendix", ""])
        if not report.include_suppressed:
            lines.extend(
                [
                    "Suppressed records were excluded by `--no-include-suppressed`. Summary counts "
                    "still reflect the complete persisted workspace.",
                    "",
                ]
            )
            return
        suppressed = [item for item in report.hypotheses if not presentation_visible(item)]
        lines.extend(
            [
                "### Suppressed Hypotheses",
                "",
                "| ID | Title | Generator | Readiness | Canonical item | Suppression reason | "
                "Campaign | Semantic relationship | Affected identifier | Manual review |",
                "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
            ]
        )
        for item in suppressed:
            generator = (
                item.generation.generator
                if item.generation
                else (
                    "business-logic-analysis" if item.id.startswith("BLH-") else "legacy/researcher"
                )
            )
            lines.append(
                self._row(
                    item.id,
                    presentation_title(item),
                    generator,
                    item.readiness,
                    item.grouping.primary_hypothesis_id or "None",
                    item.presentation.suppression_reason or item.disposition,
                    item.grouping.campaign_id or "None",
                    item.grouping.relationship.value,
                    item.mutation_target.parameter or "None",
                    "yes"
                    if item.presentation.difference_reasons
                    else "review if semantics changed",
                )
            )
        if not suppressed:
            lines.append(
                self._row(
                    "None", "No hypotheses are suppressed.", "-", "-", "-", "-", "-", "-", "-", "-"
                )
            )
        lines.extend(
            [
                "",
                "### Suppressed Endpoints",
                "",
                "| Host | Method | Route | Suppression reason | Canonical endpoint | Security "
                "relevance |",
                "| --- | --- | --- | --- | --- | ---: |",
            ]
        )
        suppressed_endpoints = [item for item in report.endpoints if item.disposition != "ACTIVE"]
        for endpoint in suppressed_endpoints:
            lines.append(
                self._row(
                    self._join(endpoint.hosts),
                    endpoint.method,
                    endpoint.path,
                    endpoint.disposition,
                    endpoint.id,
                    endpoint.security_relevance,
                )
            )
        if not suppressed_endpoints:
            lines.append(self._row("None", "-", "-", "No endpoints are suppressed.", "-", 0))
        lines.append("")

    def _readiness(self, lines: list[str], report: WorkspaceAnalysisReportModel) -> None:
        lines.extend(["## Readiness and Execution-Policy Assessment", ""])
        if self._unavailable(lines, report, "readiness and execution-policy assessment"):
            return
        readiness = report.readiness
        if readiness is None:
            lines.extend(["Canonical readiness is unavailable.", ""])
            return
        lines.extend(
            [
                "### Actor Authentication Readiness",
                "",
                "| Actor | Credential | Accepted | Expiration | Locally usable |",
                "| --- | --- | --- | --- | --- |",
            ]
        )
        for actor in readiness.actors:
            lines.append(
                self._row(
                    actor.actor_id,
                    actor.credential.status,
                    "yes" if actor.credential.accepted else "no",
                    actor.credential.expiration,
                    "yes" if actor.credential.locally_usable else "no",
                )
            )
        if not readiness.actors:
            lines.append(self._row("None", "UNKNOWN", "no", "unknown", "no"))
        lines.extend(
            [
                "",
                "### Identity Confirmation",
                "",
                "| Actor | Scope validation recorded | Identity confirmed |",
                "| --- | --- | --- |",
            ]
        )
        for actor in readiness.actors:
            lines.append(
                self._row(
                    actor.actor_id,
                    "yes" if actor.target_validation.recorded else "no",
                    "yes" if actor.identity_confirmation.confirmed else "no",
                )
            )
        if not readiness.actors:
            lines.append(self._row("None", "no", "no"))
        lines.extend(
            [
                "",
                "### Ownership Baseline Readiness",
                "",
                "| Actor | Hypothesis | Resource | Required | Confirmed |",
                "| --- | --- | --- | ---: | ---: |",
            ]
        )
        for actor in readiness.actors:
            lines.append(
                self._row(
                    actor.actor_id,
                    actor.ownership.hypothesis_id or "workspace",
                    actor.ownership.resource_type or "focused baseline",
                    actor.ownership.required_baselines,
                    actor.ownership.confirmed_baselines,
                )
            )
        if not readiness.actors:
            lines.append(self._row("None", "-", "-", 0, 0))
        visible = [item for item in report.hypotheses if presentation_visible(item)]
        lines.extend(
            [
                "",
                "### Hypothesis Test Readiness",
                "",
                "| Hypothesis | Readiness | Actionable plan | Evidence blockers |",
                "| --- | --- | --- | --- |",
            ]
        )
        for item in visible:
            lines.append(
                self._row(
                    item.id,
                    item.readiness,
                    "yes" if item.readiness_assessment.actionable_plan else "no",
                    self._join(blocker.summary for blocker in item.readiness_assessment.blockers),
                )
            )
        if not visible:
            lines.append(self._row("None", "RESEARCH_ONLY", "no", "No visible records."))
        plan_stage = next(item for item in readiness.stages if item.id == PipelineStage.PLAN)
        execute_stage = next(item for item in readiness.stages if item.id == PipelineStage.EXECUTE)
        lines.extend(
            [
                "",
                "### Plan Constructability",
                "",
                "| Stage status | Current plans | Blockers |",
                "| --- | ---: | --- |",
                self._row(
                    plan_stage.status.value,
                    plan_stage.result_count,
                    self._join(item.summary for item in plan_stage.blockers),
                ),
                "",
                "### Human Approval",
                "",
                "| Policy requires approval | Approved plans | Permission meaning |",
                "| --- | ---: | --- |",
                self._row(
                    "yes"
                    if report.target and report.target.testing.human_approval_required
                    else "no/unknown",
                    sum(item.approval_status == "APPROVED" for item in report.plans),
                    "Approval is checksum-bound and does not confirm a vulnerability.",
                ),
                "",
                "### Environment Policy",
                "",
                "| Environment | Read-only only | Destructive testing | Request budget |",
                "| --- | --- | --- | ---: |",
                self._row(
                    report.metadata.environment_type,
                    str(report.target.testing.read_only_only).lower()
                    if report.target
                    else "unknown",
                    str(report.target.testing.destructive_testing).lower()
                    if report.target
                    else "unknown",
                    report.target.testing.maximum_requests_per_plan if report.target else 0,
                ),
                "",
                "### Active Execution Permission",
                "",
                "| Policy enabled | Canonical execute stage | Current audits | Blockers |",
                "| --- | --- | ---: | --- |",
                self._row(
                    "yes"
                    if report.target and report.target.testing.active_execution_enabled
                    else "no",
                    execute_stage.status.value,
                    execute_stage.result_count,
                    self._join(item.summary for item in execute_stage.blockers),
                ),
                "",
                "A hypothesis may be `TEST_READY` while execution is blocked. A plan may also be "
                "constructable while actor identity, ownership evidence, human approval, or "
                "environment policy remains incomplete.",
                "",
            ]
        )

    def _next_actions(self, lines: list[str], report: WorkspaceAnalysisReportModel) -> None:
        lines.extend(
            [
                "## Prioritized Next Actions",
                "",
                "| Action | Priority | Why | Affected | Expected evidence | Classification | "
                "Prerequisite | Recommended command |",
                "| --- | --- | --- | --- | --- | --- | --- | --- |",
            ]
        )
        for action in report.next_actions:
            lines.append(
                self._row(
                    f"{action.action_id}: {action.title}",
                    action.priority,
                    action.why,
                    self._join(action.affected),
                    action.expected_evidence,
                    action.classification,
                    action.prerequisite or "None",
                    self._code(action.command) if action.command else "Manual review",
                )
            )
        if not report.next_actions:
            lines.append(
                self._row(
                    "None",
                    "-",
                    "No deterministic remediation is currently required.",
                    "-",
                    "-",
                    "REVIEW",
                    "-",
                    "-",
                )
            )
        lines.extend(
            [
                "",
                "Commands are recommendations only. This report never automatically plans, "
                "approves, or executes a hypothesis.",
                "",
            ]
        )

    def _artifact_index(self, lines: list[str], report: WorkspaceAnalysisReportModel) -> None:
        lines.extend(
            [
                "## Artifact Index",
                "",
                "| Artifact | Path | Present | Required | Description |",
                "| --- | --- | --- | --- | --- |",
            ]
        )
        for artifact in report.artifacts:
            path = (
                self._link(artifact.label, artifact.path)
                if artifact.exists
                else self._code(str(artifact.path))
            )
            lines.append(
                self._row(
                    artifact.label,
                    path,
                    "yes" if artifact.exists else "no",
                    "yes" if artifact.required else "no",
                    artifact.description,
                    raw_columns={1},
                )
            )
        lines.extend(["", "### Existing Confirmed-Evidence Reports", ""])
        self._bullets(
            lines,
            [self._link(path.name, path) for path in report.confirmed_report_paths],
            empty="No confirmed-evidence report files exist.",
            raw=True,
        )
        lines.extend(
            [
                "",
                "Workspace analysis reports use the separate `reports/workspace/` namespace. "
                "They are not inputs to, or replacements for, confirmed-evidence reports.",
                "",
            ]
        )

    def _diagnostics(self, lines: list[str], report: WorkspaceAnalysisReportModel) -> None:
        lines.extend(["## Diagnostic Appendix", ""])
        for stage in report.stages:
            lines.extend(
                [
                    "<details>",
                    f"<summary>{self.redactor.text(stage.stage_id)} - "
                    f"{stage.status.value}</summary>",
                    "",
                    f"- Logical service: {self.redactor.text(stage.display_name)}",
                    f"- Exit status: {stage.status.value}",
                    f"- Duration: {stage.duration:.3f}s",
                    f"- Warnings: {self._join(stage.warnings)}",
                    "",
                    "```text",
                    self.redactor.diagnostic(
                        stage.diagnostic_output or stage.error_summary or "No diagnostic output."
                    ),
                    "```",
                    "",
                    "</details>",
                    "",
                ]
            )

    def _unavailable(
        self,
        lines: list[str],
        report: WorkspaceAnalysisReportModel,
        section: str,
    ) -> bool:
        message = report.unavailable_sections.get(section)
        if message is None:
            return False
        lines.extend([f"> **Unavailable:** {self.redactor.text(message)}", ""])
        return True

    def _artifact_link(
        self, label: str, report: WorkspaceAnalysisReportModel, artifact_label: str
    ) -> str:
        artifact = next((item for item in report.artifacts if item.label == artifact_label), None)
        if artifact is None or not artifact.exists:
            return f"{label}: unavailable"
        return f"{label}: {self._link(artifact.label, artifact.path)}"

    def _link(self, label: str, path: Path) -> str:
        relative = Path(os.path.relpath(path, self.report_path.parent)).as_posix()
        return f"[{self.redactor.text(label)}](<{self.redactor.text(relative)}>)"

    def _row(self, *values: object, raw_columns: set[int] | None = None) -> str:
        raw = raw_columns or set()
        rendered = [
            str(value) if index in raw else self.redactor.table(value)
            for index, value in enumerate(values)
        ]
        return "| " + " | ".join(rendered) + " |"

    def _join(
        self,
        values: Iterable[object] | dict[object, object] | str | None,
    ) -> str:
        if isinstance(values, dict):
            items = [
                f"{key}={value}"
                for key, value in sorted(values.items(), key=lambda item: str(item[0]))
            ]
        elif isinstance(values, str):
            items = [values] if values else []
        elif values is None:
            items = []
        else:
            items = [str(item) for item in values]
        return ", ".join(self.redactor.text(item) for item in items if str(item)) or "None"

    def _bullets(
        self,
        lines: list[str],
        values: Iterable[object],
        *,
        empty: str,
        raw: bool = False,
    ) -> None:
        items = list(values)
        if not items:
            lines.append(empty)
            return
        for item in items:
            lines.append(f"- {item if raw else self.redactor.text(item)}")

    def _code(self, value: object | None) -> str:
        text = self.redactor.text(value).replace("`", "\\`")
        return f"`{text}`"

    def _heading(self, value: object) -> str:
        return self.redactor.text(value).replace("#", r"\#").replace("\n", " ")
