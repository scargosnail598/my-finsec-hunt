"""Regression, orchestration, safety, and rendering tests for workspace reports."""

from __future__ import annotations

import http.client
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

import finsec.workspace_analysis.service as workspace_service
from finsec.cli import app
from finsec.config.workspace import WorkspacePaths, create_workspace
from finsec.errors import FinsecError
from finsec.evidence.manager import ensure_evidence
from finsec.hypotheses.contracts import (
    HypothesisCampaign,
    HypothesisGrouping,
    HypothesisPresentation,
    SemanticRelationship,
)
from finsec.hypotheses.domain import HypothesisRecord, HypothesisStore
from finsec.hypotheses.generator import generate_hypotheses
from finsec.reporting.generator import generate_report
from finsec.utils.yaml_store import load_yaml, write_yaml
from finsec.workspace_analysis import WorkspaceAnalysisOrchestrator
from finsec.workspace_analysis.domain import (
    WorkspaceAnalysisStageStatus,
)
from finsec.workspace_analysis.stages import WORKSPACE_ANALYSIS_STAGES

runner = CliRunner()
FIXED_TIME = datetime(2026, 8, 14, 14, 0, tzinfo=UTC)


def _fixed_clock() -> datetime:
    return FIXED_TIME


def _output(workspace: WorkspacePaths, name: str = "analysis.md") -> Path:
    return workspace.root / "reports" / "workspace" / name


def _report_only(workspace: WorkspacePaths, name: str = "analysis.md") -> Path:
    result = WorkspaceAnalysisOrchestrator(workspace, clock=_fixed_clock).run(
        output=_output(workspace, name),
        report_only=True,
    )
    return result.path


def _generate_store(workspace: WorkspacePaths) -> HypothesisStore:
    generate_hypotheses(workspace)
    return HypothesisStore.model_validate(load_yaml(workspace.hypotheses))


def _write_records(
    workspace: WorkspacePaths,
    records: list[HypothesisRecord],
    campaigns: list[HypothesisCampaign] | None = None,
) -> None:
    write_yaml(
        workspace.hypotheses,
        HypothesisStore(hypotheses=records, campaigns=campaigns or []).model_dump(
            mode="json", exclude_none=True
        ),
    )


def test_existing_report_still_requires_hypothesis_id() -> None:
    result = runner.invoke(app, ["report"])

    assert result.exit_code == 2
    assert "Missing argument 'hypothesis_id'" in result.output


def test_existing_report_help_remains_compatible() -> None:
    result = runner.invoke(app, ["report", "--help"], terminal_width=160)

    assert result.exit_code == 0
    assert "Generate a versioned report only from currently confirmed evidence." in result.output
    assert "hypothesis_id" in result.output
    assert "required" in result.output


def test_existing_report_confirmed_evidence_gate_is_unchanged(
    phase4_workspace: WorkspacePaths,
) -> None:
    ensure_evidence(phase4_workspace, "HYP-002")
    result = runner.invoke(
        app,
        ["report", "HYP-002", "--workspace", str(phase4_workspace.root)],
    )

    assert result.exit_code == 1
    assert "CONFIRMED" in result.output
    assert not (phase4_workspace.reports / "HYP-002-report-v1.md").exists()


def test_existing_report_output_contract_is_unchanged(
    complete_phase4_workspace: WorkspacePaths,
) -> None:
    result = generate_report(complete_phase4_workspace, "HYP-002")

    assert result.path == complete_phase4_workspace.reports / "HYP-002-report-v1.md"
    assert result.path.parent == complete_phase4_workspace.reports
    assert "reports/workspace" not in result.path.as_posix()


def test_workspace_report_registered_under_workspace_group() -> None:
    result = runner.invoke(app, ["workspace", "--help"], terminal_width=160)

    assert result.exit_code == 0
    assert "report" in result.output
    assert "preliminary" in result.output


def test_workspace_report_help() -> None:
    result = runner.invoke(app, ["workspace", "report", "--help"], terminal_width=200)

    assert result.exit_code == 0
    for option in (
        "--workspace",
        "--output",
        "--report-only",
        "--force",
        "--include-suppressed",
        "--strict",
    ):
        assert option in result.output

    for option in ("--no-include-suppressed", "--include-command-output"):
        option_result = runner.invoke(app, ["workspace", "report", option, "--help"])
        assert option_result.exit_code == 0


def test_workspace_report_does_not_require_hypothesis_id(tmp_path: Path) -> None:
    workspace = create_workspace("empty", tmp_path / "workspaces")
    result = runner.invoke(
        app,
        [
            "workspace",
            "report",
            "-w",
            str(workspace.root),
            "-o",
            str(_output(workspace)),
        ],
    )

    assert result.exit_code == 0
    assert _output(workspace).is_file()
    assert "hypothesis_id" not in result.output


def test_workspace_report_default_mode(phase3_workspace: WorkspacePaths) -> None:
    destination = _output(phase3_workspace, "default.md")
    result = runner.invoke(
        app,
        ["workspace", "report", "-w", str(phase3_workspace.root), "-o", str(destination)],
    )

    assert result.exit_code == 0, result.output
    assert destination.is_file()
    content = destination.read_text(encoding="utf-8")
    assert "# FinSec Hunt Workspace Analysis Report" in content
    assert "## Detailed Active Hypotheses" in content
    assert "## Research Tasks" in content
    assert "## Safety Boundary" in content
    assert "not confirmed vulnerabilities" in content


def test_workspace_report_exposes_canonical_comparison_coverage(
    phase4_workspace: WorkspacePaths,
) -> None:
    content = _report_only(phase4_workspace, "comparison-coverage.md").read_text(encoding="utf-8")
    store = HypothesisStore.model_validate(load_yaml(phase4_workspace.hypotheses))
    focused = next(
        item
        for item in store.hypotheses
        if item.readiness_assessment.comparison_coverage.required_distinct_actors > 0
    )
    coverage = focused.readiness_assessment.comparison_coverage

    assert (
        f"{coverage.observed_distinct_actors}/{coverage.required_distinct_actors} actors; "
        f"{coverage.distinct_controlled_objects} objects; "
        f"{coverage.distinct_parent_references} parent contexts"
    ) in content
    assert "Target-parent baseline" in content
    assert "Controlled comparison baselines" in content
    assert "Cross-actor comparison interpretation" in content
    assert coverage.explanation in content


def test_workspace_report_report_only_mode(phase3_workspace: WorkspacePaths) -> None:
    derived = [
        phase3_workspace.endpoints,
        phase3_workspace.actors,
        phase3_workspace.resources,
        phase3_workspace.invariants,
        phase3_workspace.hypotheses,
        phase3_workspace.workflow_instances,
    ]
    before = {
        path: (path.read_bytes(), path.stat().st_mtime_ns) for path in derived if path.is_file()
    }

    result = WorkspaceAnalysisOrchestrator(phase3_workspace, clock=_fixed_clock).run(
        output=_output(phase3_workspace, "report-only.md"),
        report_only=True,
    )

    assert result.path.is_file()
    after = {path: (path.read_bytes(), path.stat().st_mtime_ns) for path in before}
    assert after == before
    behavior = next(
        item for item in result.report.stages if item.stage_id == "behavior_workflow_analysis"
    )
    assert behavior.status in {
        WorkspaceAnalysisStageStatus.WARNING,
        WorkspaceAnalysisStageStatus.SKIPPED,
    }


def test_workspace_report_force_mode(
    phase3_workspace: WorkspacePaths,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []

    def wrap(name: str, function: Any) -> Any:
        def inner(*args: Any, **kwargs: Any) -> Any:
            calls.append(name)
            return function(*args, **kwargs)

        return inner

    for name in (
        "build_inventory",
        "generate_model",
        "generate_invariants",
        "generate_hypotheses",
        "analyze_business_logic",
    ):
        monkeypatch.setattr(
            workspace_service,
            name,
            wrap(name, getattr(workspace_service, name)),
        )

    result = WorkspaceAnalysisOrchestrator(phase3_workspace, clock=_fixed_clock).run(
        output=_output(phase3_workspace, "force.md"),
        force=True,
    )

    assert result.path.is_file()
    assert calls == [
        "build_inventory",
        "generate_model",
        "generate_invariants",
        "generate_hypotheses",
        "analyze_business_logic",
    ]


def test_workspace_report_strict_mode(tmp_path: Path) -> None:
    workspace = create_workspace("strict-empty", tmp_path / "workspaces")
    destination = _output(workspace, "strict.md")
    result = runner.invoke(
        app,
        [
            "workspace",
            "report",
            "-w",
            str(workspace.root),
            "-o",
            str(destination),
            "--strict",
        ],
    )

    assert result.exit_code == 1
    assert destination.is_file()
    assert "Partial workspace analysis report generated" in result.output


def test_workspace_report_stage_dependency_order() -> None:
    identifiers = [item.stage_id for item in WORKSPACE_ANALYSIS_STAGES]

    assert identifiers.index("classification_inventory") < identifiers.index(
        "actor_resource_modeling"
    )
    assert identifiers.index("actor_resource_modeling") < identifiers.index(
        "security_invariant_generation"
    )
    assert identifiers.index("security_invariant_generation") < identifiers.index(
        "security_hypothesis_generation"
    )
    assert identifiers.index("security_hypothesis_generation") < identifiers.index(
        "behavior_workflow_analysis"
    )
    assert identifiers[-1] == "final_workspace_status"
    assert all(item.safe_offline for item in WORKSPACE_ANALYSIS_STAGES)


def test_workspace_report_prerequisite_skip(tmp_path: Path) -> None:
    workspace = create_workspace("skip-empty", tmp_path / "workspaces")
    result = WorkspaceAnalysisOrchestrator(workspace, clock=_fixed_clock).run(
        output=_output(workspace),
    )
    stages = {item.stage_id: item for item in result.report.stages}

    assert stages["capture_observation_validation"].status == WorkspaceAnalysisStageStatus.FAILED
    assert stages["classification_inventory"].status == WorkspaceAnalysisStageStatus.SKIPPED
    assert stages["actor_resource_modeling"].status == WorkspaceAnalysisStageStatus.SKIPPED
    assert "Prerequisite failure" in stages["actor_resource_modeling"].warnings[0]


def test_workspace_report_partial_failure_still_writes_report(
    phase3_workspace: WorkspacePaths,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_model(_workspace: WorkspacePaths) -> Any:
        raise RuntimeError("synthetic model failure")

    monkeypatch.setattr(workspace_service, "generate_model", fail_model)
    result = WorkspaceAnalysisOrchestrator(phase3_workspace, clock=_fixed_clock).run(
        output=_output(phase3_workspace, "partial.md"),
        force=True,
    )

    assert result.path.is_file()
    assert result.partial is True
    content = result.path.read_text(encoding="utf-8")
    assert "synthetic model failure" in content
    assert "behavior_workflow_analysis" not in content or "SKIPPED" in content


def test_workspace_report_missing_workspace(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        ["workspace", "report", "-w", str(tmp_path / "missing")],
    )

    assert result.exit_code == 1
    assert "Not a FinSec Hunt workspace" in result.output


def test_workspace_report_empty_workspace(tmp_path: Path) -> None:
    workspace = create_workspace("empty-report", tmp_path / "workspaces")
    path = _report_only(workspace)
    content = path.read_text(encoding="utf-8")

    assert "No ingested observations are available" in content
    assert "## Artifact Index" in content


def test_workspace_report_no_hypotheses(phase3_workspace: WorkspacePaths) -> None:
    _write_records(phase3_workspace, [])
    content = _report_only(phase3_workspace).read_text(encoding="utf-8")

    assert "No visible active security hypotheses are available." in content
    assert "No active research tasks are available." in content


def test_workspace_report_research_tasks_only(phase3_workspace: WorkspacePaths) -> None:
    store = _generate_store(phase3_workspace)
    record = store.hypotheses[0]
    task = record.model_copy(
        update={
            "id": "HYP-RESEARCH-ONLY",
            "key": "research-only",
            "kind": "RESEARCH_TASK",
            "readiness": "RESEARCH_ONLY",
            "readiness_assessment": record.readiness_assessment.model_copy(
                update={"readiness": "RESEARCH_ONLY", "actionable_plan": False}
            ),
        }
    )
    _write_records(phase3_workspace, [task])
    content = _report_only(phase3_workspace).read_text(encoding="utf-8")

    assert "HYP-RESEARCH-ONLY" in content
    assert "No visible active security hypotheses are available." in content


def test_workspace_report_mixed_hyp_and_blh(phase3_workspace: WorkspacePaths) -> None:
    store = _generate_store(phase3_workspace)
    hyp = store.hypotheses[0].model_copy(update={"id": "HYP-MIXED", "key": "mixed-hyp"})
    blh = store.hypotheses[0].model_copy(
        update={
            "id": "BLH-MIXED",
            "key": "mixed-blh",
            "category": "business_logic",
            "component": "WF-MIXED",
            "logic_details": {"family": "REPLAY"},
        }
    )
    _write_records(phase3_workspace, [blh, hyp])
    content = _report_only(phase3_workspace).read_text(encoding="utf-8")

    assert "HYP-MIXED" in content
    assert "BLH-MIXED" in content
    assert content.index("HYP-MIXED") < content.index("BLH-MIXED") or "P" in content


def test_workspace_report_campaigns(phase3_workspace: WorkspacePaths) -> None:
    store = _generate_store(phase3_workspace)
    first = store.hypotheses[0].model_copy(update={"id": "HYP-CAMP-A", "key": "camp-a"})
    second = store.hypotheses[0].model_copy(update={"id": "HYP-CAMP-B", "key": "camp-b"})
    member_ids = [first.id, second.id]
    grouping = HypothesisGrouping(
        campaign_id="HCMP-TEST",
        cluster_id="HXC-TEST",
        relationship=SemanticRelationship.OVERLAPPING_TEST_CAMPAIGN,
        primary_hypothesis_id=first.id,
        cluster_member_ids=[first.id],
        campaign_member_ids=member_ids,
    )
    first = first.model_copy(update={"grouping": grouping})
    second = second.model_copy(
        update={"grouping": grouping.model_copy(update={"cluster_id": "HXC-TEST-B"})}
    )
    campaign = HypothesisCampaign(
        id="HCMP-TEST",
        key="campaign-test",
        title="Synthetic campaign",
        relationship=SemanticRelationship.OVERLAPPING_TEST_CAMPAIGN,
        primary_hypothesis_id=first.id,
        member_ids=member_ids,
        cluster_ids=["HXC-TEST", "HXC-TEST-B"],
        target_services=["api.example.test:root"],
        affected_endpoints=first.source.endpoints,
        affected_resources=[first.domain_intent.subject_resource],
        distinctions=["Distinct identifiers are retained."],
        next_action="Review each mutation separately.",
    )
    _write_records(phase3_workspace, [first, second], [campaign])
    content = _report_only(phase3_workspace).read_text(encoding="utf-8")

    assert "HCMP-TEST" in content
    assert "Distinct identifiers are retained." in content


def test_workspace_report_suppressed_items(phase3_workspace: WorkspacePaths) -> None:
    store = _generate_store(phase3_workspace)
    record = store.hypotheses[0]
    suppressed = record.model_copy(
        update={
            "id": "HYP-SUPPRESSED",
            "key": "suppressed",
            "disposition": "SUPPRESSED_DUPLICATE",
            "presentation": HypothesisPresentation(
                visible=False,
                suppression_reason="Exact semantic duplicate of HYP-CANONICAL.",
            ),
            "grouping": record.grouping.model_copy(
                update={"primary_hypothesis_id": "HYP-CANONICAL"}
            ),
        }
    )
    _write_records(phase3_workspace, [suppressed])
    path = _report_only(phase3_workspace)
    content = path.read_text(encoding="utf-8")

    assert "HYP-SUPPRESSED" in content
    assert "Exact semantic duplicate" in content
    excluded = WorkspaceAnalysisOrchestrator(phase3_workspace, clock=_fixed_clock).run(
        output=_output(phase3_workspace, "without-suppressed.md"),
        report_only=True,
        include_suppressed=False,
    )
    assert "Suppressed records were excluded" in excluded.path.read_text(encoding="utf-8")


def test_workspace_report_readiness_distribution(phase3_workspace: WorkspacePaths) -> None:
    store = _generate_store(phase3_workspace)
    base = store.hypotheses[0]
    records: list[HypothesisRecord] = []
    for index, readiness in enumerate(
        ["TEST_READY", "REVIEW_REQUIRED", "RESEARCH_ONLY"],
        start=1,
    ):
        records.append(
            base.model_copy(
                update={
                    "id": f"HYP-RDY-{index}",
                    "key": f"ready-{index}",
                    "kind": "RESEARCH_TASK"
                    if readiness == "RESEARCH_ONLY"
                    else "SECURITY_HYPOTHESIS",
                    "disposition": "NEEDS_RESEARCH" if readiness == "RESEARCH_ONLY" else "ACTIVE",
                    "presentation": HypothesisPresentation(visible=True),
                    "readiness": readiness,
                    "readiness_assessment": base.readiness_assessment.model_copy(
                        update={
                            "readiness": readiness,
                            "actionable_plan": readiness == "TEST_READY",
                        }
                    ),
                }
            )
        )
    _write_records(phase3_workspace, records)
    result = WorkspaceAnalysisOrchestrator(phase3_workspace, clock=_fixed_clock).run(
        output=_output(phase3_workspace), report_only=True
    )

    assert result.report.metrics.test_ready == 1
    assert result.report.metrics.review_required == 1
    assert result.report.metrics.research_only == 1


def test_workspace_report_authentication_not_ownership(phase3_workspace: WorkspacePaths) -> None:
    result = WorkspaceAnalysisOrchestrator(phase3_workspace, clock=_fixed_clock).run(
        output=_output(phase3_workspace),
        report_only=True,
    )
    content = result.path.read_text(encoding="utf-8")

    assert result.report.metrics.actors == 2
    assert "| ACT-001 |" not in content
    assert "observed=" in content
    assert "Authentication never substitutes for ownership" in content
    assert "ownership baseline missing" in content or "No controlled actor-object-owner" in content


def test_workspace_report_shared_identifier_not_owned_object(
    phase3_workspace: WorkspacePaths,
) -> None:
    content = _report_only(phase3_workspace).read_text(encoding="utf-8")

    assert "Shared regions, availability zones, product codes" in content
    assert "not treated as owned objects without explicit evidence" in content


def test_workspace_report_uuid_not_deduplicated_with_region(
    phase3_workspace: WorkspacePaths,
) -> None:
    content = _report_only(phase3_workspace).read_text(encoding="utf-8")

    assert "UUID object identifiers are not suppressed against shared region-like values" in content


def test_workspace_report_deterministic_order(phase3_workspace: WorkspacePaths) -> None:
    store = _generate_store(phase3_workspace)
    first = store.hypotheses[0].model_copy(update={"id": "HYP-Z", "key": "z"})
    second = store.hypotheses[0].model_copy(update={"id": "HYP-A", "key": "a"})
    _write_records(phase3_workspace, [first, second])
    content = _report_only(phase3_workspace).read_text(encoding="utf-8")
    detail = content.split("## Detailed Active Hypotheses", maxsplit=1)[1]

    assert detail.index("HYP-A") < detail.index("HYP-Z")


def test_workspace_report_markdown_escaping(phase3_workspace: WorkspacePaths) -> None:
    target = load_yaml(phase3_workspace.target)
    target["target"]["name"] = "demo | injected"
    write_yaml(phase3_workspace.target, target)
    content = _report_only(phase3_workspace).read_text(encoding="utf-8")

    assert "demo \\| injected" in content


def test_workspace_report_relative_artifact_links(phase3_workspace: WorkspacePaths) -> None:
    content = _report_only(phase3_workspace).read_text(encoding="utf-8")

    assert "](<../../hypotheses/backlog.yaml>)" in content
    assert "](<../../api/endpoints.yaml>)" in content


def test_workspace_report_atomic_write(
    phase3_workspace: WorkspacePaths,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = _output(phase3_workspace, "atomic.md")
    replacements: list[tuple[Path, Path]] = []
    original_replace = os.replace

    def record_replace(source: str | Path, target: str | Path) -> None:
        replacements.append((Path(source), Path(target)))
        original_replace(source, target)

    monkeypatch.setattr(workspace_service.os, "replace", record_replace)
    WorkspaceAnalysisOrchestrator(phase3_workspace, clock=_fixed_clock).run(
        output=destination,
        report_only=True,
    )

    assert replacements[-1][1] == destination
    assert replacements[-1][0].name.startswith(f".{destination.name}.tmp-")
    assert not replacements[-1][0].exists()


def test_workspace_report_paths_with_spaces(tmp_path: Path) -> None:
    workspace = create_workspace("space-demo", tmp_path / "workspace root with spaces")
    destination = workspace.root / "reports" / "workspace" / "initial analysis.md"
    result = WorkspaceAnalysisOrchestrator(workspace, clock=_fixed_clock).run(
        output=destination,
        report_only=True,
    )

    assert result.path == destination
    assert result.path.is_file()


def test_workspace_report_synthetic_environment_metadata(
    phase3_workspace: WorkspacePaths,
) -> None:
    target = load_yaml(phase3_workspace.target)
    target["testing"].update({"production": False, "synthetic": True, "local_lab": True})
    write_yaml(phase3_workspace.target, target)
    result = WorkspaceAnalysisOrchestrator(phase3_workspace, clock=_fixed_clock).run(
        output=_output(phase3_workspace, "synthetic.md"),
        report_only=True,
    )

    assert result.report.metadata.environment_type == "synthetic"
    assert not any(
        "environment flags" in warning for warning in result.report.metadata.configuration_warnings
    )


def test_workspace_report_secret_redaction(
    phase3_workspace: WorkspacePaths,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secrets = [
        "SYNTHETIC_BEARER_SECRET",
        "SYNTHETIC_PASSWORD_SECRET",
        "SYNTHETIC_API_KEY_SECRET",
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature",
    ]

    def fail_model(_workspace: WorkspacePaths) -> Any:
        raise FinsecError(
            "Authorization: Bearer SYNTHETIC_BEARER_SECRET "
            "password=SYNTHETIC_PASSWORD_SECRET api_key=SYNTHETIC_API_KEY_SECRET "
            "jwt=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature"
        )

    monkeypatch.setattr(workspace_service, "generate_model", fail_model)
    result = WorkspaceAnalysisOrchestrator(phase3_workspace, clock=_fixed_clock).run(
        output=_output(phase3_workspace, "redacted.md"),
        force=True,
        include_command_output=True,
    )
    content = result.path.read_text(encoding="utf-8")

    assert "[REDACTED]" in content
    assert all(secret not in content for secret in secrets)


def test_workspace_report_snapshot_structure(phase3_workspace: WorkspacePaths) -> None:
    content = _report_only(phase3_workspace).read_text(encoding="utf-8")
    headings = [
        "## Report Metadata",
        "## Executive Summary",
        "## Pipeline Execution Summary",
        "## Capture and Observation Quality",
        "## Actors, Authentication, Identity, and Ownership",
        "## Endpoint and Resource Inventory",
        "## Workflow and Behavior Analysis",
        "## Invariant Summary",
        "## Hypothesis Summary",
        "## Detailed Active Hypotheses",
        "## Business-Logic Hypotheses",
        "## Research Tasks",
        "## Campaigns, Clustering, and Deduplication",
        "## Suppressed Items Appendix",
        "## Readiness and Execution-Policy Assessment",
        "## Prioritized Next Actions",
        "## Artifact Index",
    ]

    positions = [content.index(heading) for heading in headings]
    assert positions == sorted(positions)


def test_workspace_report_malformed_yaml_still_writes_report(
    phase3_workspace: WorkspacePaths,
) -> None:
    phase3_workspace.observations.write_text("observations: [", encoding="utf-8")
    result = WorkspaceAnalysisOrchestrator(phase3_workspace, clock=_fixed_clock).run(
        output=_output(phase3_workspace, "malformed.md"),
        report_only=True,
    )

    assert result.path.is_file()
    assert "Unavailable because" in result.path.read_text(encoding="utf-8")


def test_workspace_report_malformed_optional_yaml_still_writes_report(
    phase3_workspace: WorkspacePaths,
) -> None:
    phase3_workspace.controlled_ownership.write_text("version: [", encoding="utf-8")
    result = WorkspaceAnalysisOrchestrator(phase3_workspace, clock=_fixed_clock).run(
        output=_output(phase3_workspace, "malformed-ownership.md"),
        report_only=True,
    )

    assert result.path.is_file()
    content = result.path.read_text(encoding="utf-8")
    assert "Unavailable because ownership analysis failed" in content


def test_workspace_report_missing_git_metadata_is_nonfatal(
    phase3_workspace: WorkspacePaths,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def missing_git(*_args: object, **_kwargs: object) -> Any:
        raise FileNotFoundError("git is unavailable")

    monkeypatch.setattr(workspace_service.subprocess, "run", missing_git)
    result = WorkspaceAnalysisOrchestrator(phase3_workspace, clock=_fixed_clock).run(
        output=_output(phase3_workspace, "no-git.md"),
        report_only=True,
    )

    assert result.path.is_file()
    assert "Repository Git commit | Unavailable" in result.path.read_text(encoding="utf-8")


def test_workspace_report_does_not_call_confirmed_report_generator(
    phase3_workspace: WorkspacePaths,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("finsec.reporting.generator.generate_report", pytest.fail)
    _report_only(phase3_workspace, "no-confirmed-report.md")


def test_workspace_report_does_not_plan(
    phase3_workspace: WorkspacePaths,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("finsec.testing.planner.generate_plan", pytest.fail)
    _report_only(phase3_workspace, "no-plan.md")


def test_workspace_report_does_not_approve(
    phase3_workspace: WorkspacePaths,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("finsec.execution.policy.approve_plan", pytest.fail)
    _report_only(phase3_workspace, "no-approve.md")


def test_workspace_report_does_not_execute(
    phase3_workspace: WorkspacePaths,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("finsec.execution.runner.execute_prepared", pytest.fail)
    _report_only(phase3_workspace, "no-execute.md")


def test_workspace_report_makes_no_network_requests(
    phase3_workspace: WorkspacePaths,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_request(*_args: object, **_kwargs: object) -> None:
        pytest.fail("network request attempted")

    monkeypatch.setattr(http.client.HTTPConnection, "request", fail_request)
    _report_only(phase3_workspace, "no-network.md")


def test_workspace_report_does_not_change_hypothesis_status(
    phase3_workspace: WorkspacePaths,
) -> None:
    store = _generate_store(phase3_workspace)
    document = store.model_dump(mode="json", exclude_none=True)
    document["hypotheses"][0]["status"] = "NEEDS_EVIDENCE"
    write_yaml(phase3_workspace.hypotheses, document)
    before = {
        item["id"]: item["status"] for item in load_yaml(phase3_workspace.hypotheses)["hypotheses"]
    }

    WorkspaceAnalysisOrchestrator(phase3_workspace, clock=_fixed_clock).run(
        output=_output(phase3_workspace, "status.md"),
        force=True,
    )
    after = {
        item["id"]: item["status"]
        for item in load_yaml(phase3_workspace.hypotheses)["hypotheses"]
        if item["id"] in before
    }

    assert after == before


def test_workspace_report_does_not_create_confirmation_evidence(
    phase3_workspace: WorkspacePaths,
) -> None:
    evidence_root = phase3_workspace.root / "evidence"
    before = sorted(path.relative_to(evidence_root) for path in evidence_root.rglob("*"))

    WorkspaceAnalysisOrchestrator(phase3_workspace, clock=_fixed_clock).run(
        output=_output(phase3_workspace, "no-evidence.md"),
        force=True,
    )
    after = sorted(path.relative_to(evidence_root) for path in evidence_root.rglob("*"))

    assert after == before
