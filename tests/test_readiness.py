"""Canonical readiness, blocker, provenance, and adapter regressions."""

from __future__ import annotations

import copy
import hashlib
import json
from collections import Counter
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

import finsec.hypotheses.generator as hypothesis_generator_module
import finsec.readiness.resolver as resolver_module
import finsec.testing.planner as planner_module
from finsec.auth.service import missing_authentication
from finsec.auth.store import SecretStore
from finsec.cli import app
from finsec.config.models import (
    ActorAuthenticationConfig,
    AuthenticationComponentConfig,
    AuthenticationExpirationConfig,
    AuthenticationIdentityConfig,
    AuthenticationSourceConfig,
    TargetDocument,
)
from finsec.config.workspace import WorkspacePaths, create_workspace
from finsec.hypotheses.domain import HypothesisStore
from finsec.hypotheses.generator import generate_hypotheses
from finsec.ingest.har import ingest_har
from finsec.mcp.service import FinsecMcpService
from finsec.modeling.domain import ResourceStore
from finsec.modeling.generator import generate_model
from finsec.modeling.invariants import generate_invariants
from finsec.modeling.models import EndpointStore, ObservationStore
from finsec.readiness.domain import BlockerCode, LifecycleStatus, PipelineStage
from finsec.readiness.resolver import resolve_workspace_readiness
from finsec.reporting.generator import generate_report
from finsec.testing.domain import TestPlanRecord as PlanRecord
from finsec.testing.domain import TestPlanStore as PlanStore
from finsec.testing.planner import (
    generate_plan,
    inspect_plan_alignment,
    inspect_plan_alignment_from_inputs,
)
from finsec.utils.yaml_store import load_yaml, write_yaml
from finsec.web.service import load_snapshot, workspace_overview
from finsec.workflow import run_offline_workflow

RUNNER = CliRunner()


def _stage(report: Any, stage_id: PipelineStage) -> Any:
    return next(item for item in report.stages if item.id == stage_id)


def _configured_workspace(tmp_path: Path, *, accounts: int = 2) -> WorkspacePaths:
    workspace = create_workspace("readiness", tmp_path / "workspaces")
    target = load_yaml(workspace.target)
    target["scope"]["hosts"] = ["api.example.test"]
    target["accounts"] = [
        {
            "id": f"ACCOUNT_{chr(65 + index)}",
            "ownership": "researcher",
            "actor_type": "authenticated_user",
            "authentication": missing_authentication().model_dump(mode="json", exclude_none=True),
        }
        for index in range(accounts)
    ]
    write_yaml(workspace.target, target)
    return workspace


def _offline_workspace(
    tmp_path: Path,
    sample_har: tuple[Path, dict[str, Any]],
) -> WorkspacePaths:
    workspace = _configured_workspace(tmp_path)
    ingest_har(sample_har[0], workspace, actor="ACCOUNT_A", channel="WEB")
    run_offline_workflow(workspace)
    return workspace


def _install_credential(
    workspace: WorkspacePaths,
    *,
    baseline_confirmed: bool,
    expires_at: datetime | None = None,
) -> None:
    target = TargetDocument.model_validate(load_yaml(workspace.target))
    account = target.accounts[0]
    account.authentication = ActorAuthenticationConfig(
        auth_type="bearer",
        profile_ref="actor-account-a-default",
        components=[
            AuthenticationComponentConfig(
                name="Authorization",
                credential_ref="actor-auth-account-a-token",
                purpose="access",
            )
        ],
        source=AuthenticationSourceConfig(type="manual"),
        expiration=AuthenticationExpirationConfig(
            detectable=expires_at is not None,
            expires_at=expires_at,
            source="unknown",
        ),
        identity=AuthenticationIdentityConfig(
            confirmed=baseline_confirmed,
            confirmation_reference=(
                "identity-assertion:readiness-synthetic" if baseline_confirmed else None
            ),
            last_assertion_status="CONFIRMED" if baseline_confirmed else "NOT_CONFIGURED",
        ),
        status="READY",
        target_hosts=target.scope.hosts,
        credential_accepted=True,
        credential_accepted_at=datetime.now(UTC),
        scope_validated=True,
        scope_validated_at=datetime.now(UTC),
    )
    write_yaml(workspace.target, target.model_dump(mode="json", exclude_none=True))
    SecretStore(workspace).put(
        "actor-auth-account-a-token",
        account.id,
        "access",
        "READINESS_SECRET_CANARY",
    )


def test_empty_and_partial_workspaces_use_all_lifecycle_states(
    tmp_path: Path,
    sample_har: tuple[Path, dict[str, Any]],
) -> None:
    absent = resolve_workspace_readiness(WorkspacePaths(tmp_path / "absent"))
    assert _stage(absent, PipelineStage.SETUP).status == LifecycleStatus.NOT_CONFIGURED

    workspace = _configured_workspace(tmp_path)
    empty = resolve_workspace_readiness(workspace)
    assert _stage(empty, PipelineStage.INGEST).status == LifecycleStatus.READY
    assert _stage(empty, PipelineStage.CLASSIFY).status == LifecycleStatus.BLOCKED

    ingest_har(sample_har[0], workspace, actor="ACCOUNT_A", channel="WEB")
    partial = resolve_workspace_readiness(workspace)
    assert _stage(partial, PipelineStage.INGEST).status == LifecycleStatus.COMPLETE
    assert _stage(partial, PipelineStage.CLASSIFY).status == LifecycleStatus.READY

    run_offline_workflow(workspace)
    complete = resolve_workspace_readiness(workspace)
    assert _stage(complete, PipelineStage.CLASSIFY).status == LifecycleStatus.COMPLETE
    assert _stage(complete, PipelineStage.MODEL).status == LifecycleStatus.COMPLETE
    assert _stage(complete, PipelineStage.HYPOTHESIZE).status == LifecycleStatus.COMPLETE
    assert _stage(complete, PipelineStage.PLAN).status == LifecycleStatus.BLOCKED


def test_new_observation_stales_only_observation_derived_artifacts(
    tmp_path: Path,
    sample_har: tuple[Path, dict[str, Any]],
) -> None:
    workspace = _offline_workspace(tmp_path, sample_har)
    observations = load_yaml(workspace.observations)
    added = copy.deepcopy(observations["observations"][0])
    added["id"] = "OBS-999999"
    added["source_fingerprint"] = "readiness-new-observation"
    observations["observations"].append(added)
    write_yaml(workspace.observations, observations)

    report = resolve_workspace_readiness(workspace)

    assert _stage(report, PipelineStage.INGEST).status == LifecycleStatus.COMPLETE
    assert _stage(report, PipelineStage.CLASSIFY).status == LifecycleStatus.STALE
    assert _stage(report, PipelineStage.NORMALIZE).status == LifecycleStatus.STALE
    assert _stage(report, PipelineStage.MODEL).status == LifecycleStatus.STALE
    codes = {item.code for item in _stage(report, PipelineStage.CLASSIFY).blockers}
    assert BlockerCode.UPSTREAM_DEPENDENCY_CHANGED in codes


def test_authentication_changes_do_not_stale_offline_analysis(
    tmp_path: Path,
    sample_har: tuple[Path, dict[str, Any]],
) -> None:
    workspace = _offline_workspace(tmp_path, sample_har)
    before = resolve_workspace_readiness(workspace)
    assert _stage(before, PipelineStage.HYPOTHESIZE).status == LifecycleStatus.COMPLETE

    target = load_yaml(workspace.target)
    target["accounts"][0]["authentication"]["status"] = "AVAILABLE_NOT_VALIDATED"
    target["accounts"][0]["authentication"]["credential_accepted_at"] = (
        datetime.now(UTC).isoformat()
    )
    write_yaml(workspace.target, target)

    after = resolve_workspace_readiness(workspace)
    assert _stage(after, PipelineStage.CLASSIFY).status == LifecycleStatus.COMPLETE
    assert _stage(after, PipelineStage.MODEL).status == LifecycleStatus.COMPLETE
    assert _stage(after, PipelineStage.HYPOTHESIZE).status == LifecycleStatus.COMPLETE


def test_relevant_analysis_configuration_change_stales_inventory(
    tmp_path: Path,
    sample_har: tuple[Path, dict[str, Any]],
) -> None:
    workspace = _offline_workspace(tmp_path, sample_har)
    target = load_yaml(workspace.target)
    target["analysis"]["excluded_path_patterns"].append("/readiness-change/")
    write_yaml(workspace.target, target)

    report = resolve_workspace_readiness(workspace)

    assert _stage(report, PipelineStage.CLASSIFY).status == LifecycleStatus.STALE
    assert _stage(report, PipelineStage.AUTH).status == LifecycleStatus.BLOCKED


def test_credential_identity_and_ownership_are_separate_and_redacted(tmp_path: Path) -> None:
    workspace = _configured_workspace(tmp_path, accounts=1)
    _install_credential(workspace, baseline_confirmed=False)

    report = resolve_workspace_readiness(workspace)
    actor = report.actors[0]
    serialized = json.dumps(report.model_dump(mode="json"), sort_keys=True)

    assert actor.credential.available is True
    assert actor.credential.expiration == "unknown"
    assert actor.target_validation.recorded is True
    assert actor.identity_confirmation.confirmed is False
    assert actor.ownership.confirmed_baselines == 0
    assert actor.capabilities.authorization_execution is False
    assert BlockerCode.ACTOR_IDENTITY_NOT_CONFIRMED in {
        item.code for item in _stage(report, PipelineStage.AUTH).blockers
    }
    assert BlockerCode.CREDENTIAL_EXPIRATION_UNKNOWN in {
        item.code for item in _stage(report, PipelineStage.AUTH).warnings
    }
    assert any(
        action.command is not None and "actor auth check ACCOUNT_A --network" in action.command
        for action in _stage(report, PipelineStage.AUTH).next_actions
    )
    assert "READINESS_SECRET_CANARY" not in serialized
    assert "actor-auth-account-a-token" not in serialized


def test_auth_context_changed_is_explicit_in_status(tmp_path: Path) -> None:
    workspace = _configured_workspace(tmp_path, accounts=1)
    _install_credential(workspace, baseline_confirmed=False)
    target = load_yaml(workspace.target)
    target["accounts"][0]["authentication"]["status"] = "AUTH_CONTEXT_CHANGED"
    write_yaml(workspace.target, target)

    report = resolve_workspace_readiness(workspace)
    status = RUNNER.invoke(app, ["status", "--workspace", str(workspace.root)])

    assert report.actors[0].credential.status == "AUTH_CONTEXT_CHANGED"
    assert report.actors[0].identity_confirmation.confirmed is False
    assert status.exit_code == 0, status.output
    assert "AUTH_CONTEXT_CHANGED" in status.output
    assert "unconfirmed" in status.output


def test_anonymous_actor_is_not_authorization_execution_ready(tmp_path: Path) -> None:
    workspace = _configured_workspace(tmp_path)
    target = load_yaml(workspace.target)
    target["accounts"] = [
        {
            "id": "ANONYMOUS",
            "ownership": "researcher",
            "authenticated": False,
            "actor_type": "anonymous",
        }
    ]
    write_yaml(workspace.target, target)

    actor = resolve_workspace_readiness(workspace).actors[0]

    assert actor.credential.type == "none"
    assert actor.capabilities.planning is True
    assert actor.capabilities.authorization_execution is False


def test_known_expiry_is_not_confused_with_unknown_expiry(tmp_path: Path) -> None:
    workspace = _configured_workspace(tmp_path, accounts=1)
    _install_credential(
        workspace,
        baseline_confirmed=True,
        expires_at=datetime.now(UTC) - timedelta(minutes=1),
    )

    report = resolve_workspace_readiness(workspace)
    actor = report.actors[0]

    assert actor.credential.expiration == "expired"
    assert BlockerCode.CREDENTIAL_EXPIRED in {
        item.code for item in _stage(report, PipelineStage.AUTH).blockers
    }
    assert BlockerCode.CREDENTIAL_EXPIRATION_UNKNOWN not in {
        item.code for item in _stage(report, PipelineStage.AUTH).warnings
    }


def test_observed_accounts_do_not_manufacture_ownership(
    tmp_path: Path,
    sample_har: tuple[Path, dict[str, Any]],
) -> None:
    workspace = _offline_workspace(tmp_path, sample_har)
    report = resolve_workspace_readiness(workspace)

    assert all(item.ownership.confirmed_baselines == 0 for item in report.actors)
    endpoints = load_yaml(workspace.endpoints)
    assert not any(
        binding["actor_object_binding_observed"]
        for endpoint in endpoints["endpoints"]
        for binding in endpoint.get("object_access", [])
    )


def test_controlled_ownership_baselines_are_reported_for_applicable_actors(
    phase4_workspace: WorkspacePaths,
) -> None:
    report = resolve_workspace_readiness(phase4_workspace)
    by_actor = {item.actor_id: item for item in report.actors}

    assert by_actor["ACCOUNT_A"].ownership.confirmed_baselines >= 1
    assert by_actor["ACCOUNT_B"].ownership.confirmed_baselines >= 1
    assert all(item.ownership.required_baselines == 1 for item in by_actor.values())
    assert report.focused_comparison is not None
    assert report.focused_comparison.observed_distinct_actors == 2
    hypotheses = HypothesisStore.model_validate(load_yaml(phase4_workspace.hypotheses))
    focused = next(
        item for item in hypotheses.hypotheses if item.id == report.focused_comparison.hypothesis_id
    )
    coverage = focused.readiness_assessment.comparison_coverage
    assert report.focused_comparison.required_distinct_actors == coverage.required_distinct_actors
    assert report.focused_comparison.distinct_controlled_objects == (
        coverage.distinct_controlled_objects
    )
    assert report.focused_comparison.distinct_parent_references == (
        coverage.distinct_parent_references
    )
    assert report.focused_comparison.parent_references == coverage.parent_references
    assert report.focused_comparison.target_parent_baseline_reference == (
        coverage.target_parent_baseline_reference
    )
    assert report.focused_comparison.comparison_baseline_references == (
        coverage.comparison_baseline_references
    )
    assert report.focused_comparison.evidence_references == coverage.evidence_references
    assert report.focused_comparison.explanation == coverage.explanation
    assert all(
        item.ownership.hypothesis_id == report.focused_comparison.hypothesis_id
        for item in by_actor.values()
    )
    assert all(
        item.ownership.resource_type == report.focused_comparison.resource_type
        for item in by_actor.values()
    )
    cli_normal = RUNNER.invoke(
        app,
        ["status", "--workspace", str(phase4_workspace.root)],
    )
    cli_json = RUNNER.invoke(
        app,
        ["status", "--workspace", str(phase4_workspace.root), "--json"],
    )
    assert cli_normal.exit_code == 0, cli_normal.output
    assert cli_json.exit_code == 0, cli_json.output
    focused_json = json.loads(cli_json.output)["focused_comparison"]
    assert focused_json["distinct_parent_references"] == coverage.distinct_parent_references
    assert focused_json["target_parent_baseline_reference"] == (
        coverage.target_parent_baseline_reference
    )
    assert focused_json["comparison_baseline_references"] == (
        coverage.comparison_baseline_references
    )


def test_unapproved_plan_and_disabled_execution_have_distinct_blockers(
    phase4_workspace: WorkspacePaths,
) -> None:
    report = resolve_workspace_readiness(phase4_workspace)
    codes = {item.code for item in _stage(report, PipelineStage.EXECUTE).blockers}

    assert BlockerCode.HUMAN_APPROVAL_MISSING in codes
    assert BlockerCode.ACTIVE_EXECUTION_DISABLED in codes
    assert _stage(report, PipelineStage.PLAN).status == LifecycleStatus.COMPLETE


def test_blocked_canonical_plan_never_makes_status_plan_ready(
    phase4_workspace: WorkspacePaths,
) -> None:
    target = load_yaml(phase4_workspace.target)
    target["testing"]["maximum_requests_per_plan"] = 1
    write_yaml(phase4_workspace.target, target)
    generate_hypotheses(phase4_workspace)
    plan = generate_plan(phase4_workspace, "HYP-002").plan

    alignment = inspect_plan_alignment(phase4_workspace, "HYP-002")
    report = resolve_workspace_readiness(phase4_workspace)

    assert plan.status == "BLOCKED"
    assert alignment.plan_status == "BLOCKED"
    assert alignment.agrees is True
    assert _stage(report, PipelineStage.PLAN).status == LifecycleStatus.BLOCKED
    assert _stage(report, PipelineStage.PLAN).status != LifecycleStatus.READY


def _workspace_hashes(workspace: WorkspacePaths) -> dict[str, str]:
    return {
        str(path.relative_to(workspace.root)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(workspace.root.rglob("*"))
        if path.is_file()
    }


def test_status_loads_planner_artifacts_once_independent_of_active_hypothesis_count(
    phase4_workspace: WorkspacePaths,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tracked = {
        phase4_workspace.target,
        phase4_workspace.observations,
        phase4_workspace.endpoints,
        phase4_workspace.resources,
        phase4_workspace.hypotheses,
    }
    calls: Counter[Path] = Counter()
    original_load_yaml = resolver_module.load_yaml

    def counted_load(path: Path) -> Any:
        resolved = Path(path)
        if resolved in tracked:
            calls[resolved] += 1
        return original_load_yaml(path)

    monkeypatch.setattr(resolver_module, "load_yaml", counted_load)
    monkeypatch.setattr(planner_module, "load_yaml", counted_load)
    monkeypatch.setattr(hypothesis_generator_module, "load_yaml", counted_load)

    first_before = _workspace_hashes(phase4_workspace)
    first = resolve_workspace_readiness(phase4_workspace)
    first_counts = {path: calls[path] for path in tracked}
    assert first.metrics.active_hypotheses >= 1
    assert set(first_counts.values()) == {1}
    assert _workspace_hashes(phase4_workspace) == first_before

    store = HypothesisStore.model_validate(original_load_yaml(phase4_workspace.hypotheses))
    source = next(item for item in store.hypotheses if item.disposition == "ACTIVE")
    duplicates = [
        source.model_copy(
            deep=True,
            update={
                "id": f"HYP-LOAD-{index:03d}",
                "key": f"load-regression:{index:03d}",
                "generation": None,
            },
        )
        for index in range(8)
    ]
    write_yaml(
        phase4_workspace.hypotheses,
        HypothesisStore(hypotheses=[*store.hypotheses, *duplicates]).model_dump(
            mode="json", exclude_none=True
        ),
    )
    monkeypatch.setattr(resolver_module, "_generated_store_integrity", lambda *_: True)
    calls.clear()
    second_before = _workspace_hashes(phase4_workspace)

    second = resolve_workspace_readiness(phase4_workspace)
    second_counts = {path: calls[path] for path in tracked}

    assert second.metrics.active_hypotheses > first.metrics.active_hypotheses
    assert second_counts == first_counts
    assert _workspace_hashes(phase4_workspace) == second_before


def test_public_and_in_memory_alignment_are_identical_order_independent_and_read_only(
    phase4_workspace: WorkspacePaths,
) -> None:
    target = TargetDocument.model_validate(load_yaml(phase4_workspace.target))
    observations = ObservationStore.model_validate(load_yaml(phase4_workspace.observations))
    endpoints = EndpointStore.model_validate(load_yaml(phase4_workspace.endpoints))
    resources = ResourceStore.model_validate(load_yaml(phase4_workspace.resources))
    hypotheses = HypothesisStore.model_validate(load_yaml(phase4_workspace.hypotheses))
    hypothesis = next(item for item in hypotheses.hypotheses if item.id == "HYP-002")
    before = _workspace_hashes(phase4_workspace)

    public = inspect_plan_alignment(phase4_workspace, hypothesis.id)
    in_memory = inspect_plan_alignment_from_inputs(
        target,
        observations,
        endpoints,
        resources,
        hypothesis,
    )
    reversed_inputs = inspect_plan_alignment_from_inputs(
        target,
        observations.model_copy(update={"observations": list(reversed(observations.observations))}),
        endpoints.model_copy(update={"endpoints": list(reversed(endpoints.endpoints))}),
        resources.model_copy(update={"resources": list(reversed(resources.resources))}),
        hypothesis,
    )

    assert public == in_memory == reversed_inputs
    assert public.plan_status == "READY_FOR_REVIEW"
    blocked_target = target.model_copy(
        update={"testing": target.testing.model_copy(update={"maximum_requests_per_plan": 1})}
    )
    blocked = inspect_plan_alignment_from_inputs(
        blocked_target,
        observations,
        endpoints,
        resources,
        hypothesis,
    )
    assert blocked.plan_status == "BLOCKED"
    assert blocked.readiness.actionable_plan is False
    assert _workspace_hashes(phase4_workspace) == before


def _install_plan_matrix(
    workspace: WorkspacePaths,
    source_hypotheses: HypothesisStore,
    source_plan: PlanRecord,
    *,
    current_statuses: tuple[str, ...] = (),
    stale_statuses: tuple[str, ...] = (),
    suppressed_stale: bool = False,
) -> set[str]:
    base = next(item for item in source_hypotheses.hypotheses if item.id == "HYP-002")
    hypotheses = list(source_hypotheses.hypotheses)
    plans: list[PlanRecord] = []
    current_ids: set[str] = set()
    for index, status in enumerate(current_statuses, start=1):
        hypothesis_id = f"HYP-MATRIX-{index:03d}"
        hypotheses.append(
            base.model_copy(
                deep=True,
                update={
                    "id": hypothesis_id,
                    "key": f"matrix-current:{index:03d}",
                    "generation": None,
                },
            )
        )
        plan_id = f"PLAN-MATRIX-{index:03d}"
        blocked = status == "BLOCKED"
        plans.append(
            source_plan.model_copy(
                deep=True,
                update={
                    "id": plan_id,
                    "key": f"plan:{hypothesis_id}",
                    "hypothesis_id": hypothesis_id,
                    "status": status,
                    "risk": source_plan.risk.model_copy(
                        update={
                            "decision": "BLOCKED" if blocked else "REQUIRES_HUMAN_APPROVAL",
                            "reasons": (
                                ["Synthetic current plan is blocked by canonical policy."]
                                if blocked
                                else [
                                    "Static policy checks pass; explicit human approval is "
                                    "still mandatory."
                                ]
                            ),
                        }
                    ),
                    "generation": None,
                },
            )
        )
        current_ids.add(plan_id)
    for index, status in enumerate(stale_statuses, start=1):
        hypothesis_id = f"HYP-STALE-{index:03d}"
        if suppressed_stale:
            hypotheses.append(
                base.model_copy(
                    deep=True,
                    update={
                        "id": hypothesis_id,
                        "key": f"matrix-suppressed:{index:03d}",
                        "disposition": "SUPPRESSED_INSUFFICIENT_EVIDENCE",
                        "generation": None,
                    },
                )
            )
        plans.append(
            source_plan.model_copy(
                deep=True,
                update={
                    "id": f"PLAN-STALE-{index:03d}",
                    "key": f"plan:{hypothesis_id}",
                    "hypothesis_id": hypothesis_id,
                    "status": status,
                    "generation": None,
                },
            )
        )
    write_yaml(
        workspace.hypotheses,
        HypothesisStore(hypotheses=hypotheses).model_dump(mode="json", exclude_none=True),
    )
    write_yaml(
        workspace.test_plans,
        PlanStore(plans=plans).model_dump(mode="json", exclude_none=True),
    )
    return current_ids


def test_conservative_mixed_plan_aggregation_matrix_and_surface_consistency(
    phase4_workspace: WorkspacePaths,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_hypotheses = HypothesisStore.model_validate(load_yaml(phase4_workspace.hypotheses))
    source_plans = PlanStore.model_validate(load_yaml(phase4_workspace.test_plans))
    source_plan = next(item for item in source_plans.plans if item.hypothesis_id == "HYP-002")
    current_ids: set[str] = set()
    monkeypatch.setattr(resolver_module, "_generated_store_integrity", lambda *_: True)
    monkeypatch.setattr(
        resolver_module,
        "_plan_current",
        lambda plan, *_: plan.id in current_ids,
    )
    monkeypatch.setattr(
        resolver_module,
        "inspect_plan_alignment_from_inputs",
        lambda _target, _observations, _endpoints, _resources, hypothesis: (
            planner_module.PlanAlignment(
                readiness=hypothesis.readiness_assessment.model_copy(
                    update={"readiness": "TEST_READY", "actionable_plan": True, "blockers": []}
                ),
                plan_status="READY_FOR_REVIEW",
                agrees=True,
                violation=None,
            )
        ),
    )
    matrix = [
        ((), (), False, LifecycleStatus.READY, (0, 0, 0)),
        (("READY_FOR_REVIEW",), (), False, LifecycleStatus.COMPLETE, (1, 0, 0)),
        (("BLOCKED",), (), False, LifecycleStatus.BLOCKED, (0, 1, 0)),
        (
            ("READY_FOR_REVIEW", "BLOCKED"),
            (),
            False,
            LifecycleStatus.BLOCKED,
            (1, 1, 0),
        ),
        (
            ("READY_FOR_REVIEW",),
            ("READY_FOR_REVIEW",),
            False,
            LifecycleStatus.COMPLETE,
            (1, 0, 1),
        ),
        (
            ("BLOCKED",),
            ("READY_FOR_REVIEW",),
            False,
            LifecycleStatus.BLOCKED,
            (0, 1, 1),
        ),
        (
            ("READY_FOR_REVIEW", "READY_FOR_REVIEW"),
            (),
            False,
            LifecycleStatus.COMPLETE,
            (2, 0, 0),
        ),
        (
            (),
            ("READY_FOR_REVIEW",),
            True,
            LifecycleStatus.STALE,
            (0, 0, 1),
        ),
    ]
    for ready_or_blocked, stale, suppressed, expected_status, expected_counts in matrix:
        current_ids.clear()
        current_ids.update(
            _install_plan_matrix(
                phase4_workspace,
                source_hypotheses,
                source_plan,
                current_statuses=ready_or_blocked,
                stale_statuses=stale,
                suppressed_stale=suppressed,
            )
        )
        before = phase4_workspace.test_plans.read_bytes()

        report = resolve_workspace_readiness(phase4_workspace)
        plan_stage = _stage(report, PipelineStage.PLAN)

        assert plan_stage.status == expected_status
        assert (
            report.metrics.current_ready_plans,
            report.metrics.current_blocked_plans,
            report.metrics.stale_plans,
        ) == expected_counts
        assert phase4_workspace.test_plans.read_bytes() == before
        if expected_counts[1]:
            assert plan_stage.blockers
            assert all(item.stage == PipelineStage.PLAN for item in plan_stage.blockers)

    current_ids.clear()
    current_ids.update(
        _install_plan_matrix(
            phase4_workspace,
            source_hypotheses,
            source_plan,
            current_statuses=("READY_FOR_REVIEW", "BLOCKED"),
        )
    )
    domain = resolve_workspace_readiness(phase4_workspace).model_dump(mode="json")
    cli_json = RUNNER.invoke(
        app,
        ["status", "--workspace", str(phase4_workspace.root), "--json"],
    )
    cli_normal = RUNNER.invoke(
        app,
        ["status", "--workspace", str(phase4_workspace.root)],
    )
    web = workspace_overview(load_snapshot(phase4_workspace))["readiness"]
    mcp = (
        FinsecMcpService.from_workspace_path(phase4_workspace.root)
        .workspace_summary()
        .readiness.model_dump(mode="json")
    )

    assert cli_json.exit_code == 0, cli_json.output
    assert cli_normal.exit_code == 0, cli_normal.output
    assert json.loads(cli_json.output) == domain == web == mcp
    assert "plan" in cli_normal.output
    assert "BLOCKED" in cli_normal.output
    assert "Current Ready Plans" in cli_normal.output
    assert "Current Blocked Plans" in cli_normal.output
    stored = PlanStore.model_validate(load_yaml(phase4_workspace.test_plans))
    assert sorted(item.status for item in stored.plans) == ["BLOCKED", "READY_FOR_REVIEW"]


def test_state_changing_validation_requires_before_and_after_evidence(
    complete_phase4_workspace: WorkspacePaths,
) -> None:
    endpoints = load_yaml(complete_phase4_workspace.endpoints)
    payment = next(item for item in endpoints["endpoints"] if item["id"] == "EP-001")
    payment["state_change"] = True
    payment["state_change_reasons"] = ["synthetic readiness regression"]
    write_yaml(complete_phase4_workspace.endpoints, endpoints)
    generate_model(complete_phase4_workspace)
    generate_invariants(complete_phase4_workspace)
    generate_hypotheses(complete_phase4_workspace)
    generate_plan(complete_phase4_workspace, "HYP-002")
    plans = load_yaml(complete_phase4_workspace.test_plans)
    plan = next(item for item in plans["plans"] if item["hypothesis_id"] == "HYP-002")
    plan["approval_status"] = "APPROVED"
    write_yaml(complete_phase4_workspace.test_plans, plans)
    write_yaml(complete_phase4_workspace.validations, {"version": 1, "validations": []})

    report = resolve_workspace_readiness(complete_phase4_workspace)
    codes = {item.code for item in _stage(report, PipelineStage.VALIDATE).blockers}

    assert BlockerCode.BEFORE_AFTER_STATE_EVIDENCE_MISSING in codes


def test_http_execution_is_never_treated_as_a_confirmed_report(tmp_path: Path) -> None:
    workspace = _configured_workspace(tmp_path)
    report = resolve_workspace_readiness(workspace)

    assert _stage(report, PipelineStage.REPORT).status == LifecycleStatus.BLOCKED
    assert BlockerCode.NO_CONFIRMED_VULNERABILITY in {
        item.code for item in _stage(report, PipelineStage.REPORT).blockers
    }


def test_unbound_legacy_report_is_stale_not_complete(tmp_path: Path) -> None:
    workspace = _configured_workspace(tmp_path)
    workspace.reports.mkdir(parents=True, exist_ok=True)
    (workspace.reports / "HYP-001-report-v1.md").write_text(
        "# Legacy report\n",
        encoding="utf-8",
    )

    report = resolve_workspace_readiness(workspace)
    report_stage = _stage(report, PipelineStage.REPORT)

    assert report_stage.status == LifecycleStatus.STALE
    assert BlockerCode.ARTIFACT_PROVENANCE_MISSING in {item.code for item in report_stage.blockers}


def test_confirmed_report_is_current_and_readiness_is_non_destructive(
    complete_phase4_workspace: WorkspacePaths,
) -> None:
    result = generate_report(complete_phase4_workspace, "HYP-002")
    metadata = complete_phase4_workspace.evidence_for("HYP-002") / "metadata.yaml"
    before = metadata.read_bytes()
    provenance_before = complete_phase4_workspace.readiness_provenance.read_bytes()

    report = resolve_workspace_readiness(complete_phase4_workspace)

    assert result.path.is_file()
    assert _stage(report, PipelineStage.REPORT).status == LifecycleStatus.COMPLETE
    assert metadata.read_bytes() == before
    assert complete_phase4_workspace.readiness_provenance.read_bytes() == provenance_before


def test_legacy_provenance_is_conservatively_stale(
    tmp_path: Path,
    sample_har: tuple[Path, dict[str, Any]],
) -> None:
    workspace = _offline_workspace(tmp_path, sample_har)
    workspace.readiness_provenance.unlink()

    report = resolve_workspace_readiness(workspace)

    assert _stage(report, PipelineStage.CLASSIFY).status == LifecycleStatus.STALE
    assert BlockerCode.ARTIFACT_PROVENANCE_MISSING in {
        item.code for item in _stage(report, PipelineStage.CLASSIFY).blockers
    }


def test_malformed_artifact_fails_closed_without_crashing(
    tmp_path: Path,
    sample_har: tuple[Path, dict[str, Any]],
) -> None:
    workspace = _offline_workspace(tmp_path, sample_har)
    workspace.endpoints.write_text("endpoints: not-a-list\n", encoding="utf-8")

    report = resolve_workspace_readiness(workspace)
    cli = RUNNER.invoke(
        app,
        ["status", "--workspace", str(workspace.root), "--json"],
    )

    assert cli.exit_code == 0, cli.output
    assert _stage(report, PipelineStage.CLASSIFY).status == LifecycleStatus.BLOCKED
    assert BlockerCode.ARTIFACT_SCHEMA_INCOMPATIBLE in {
        item.code for item in _stage(report, PipelineStage.CLASSIFY).blockers
    }
    assert workspace.endpoints.read_text(encoding="utf-8") == "endpoints: not-a-list\n"


def test_blockers_are_deterministic_ordered_and_deduplicated(
    phase4_workspace: WorkspacePaths,
) -> None:
    first = resolve_workspace_readiness(phase4_workspace)
    second = resolve_workspace_readiness(phase4_workspace)

    assert first.model_dump(mode="json") == second.model_dump(mode="json")
    for stage in first.stages:
        keys = [
            (
                item.code.value,
                json.dumps(item.scope.model_dump(mode="json"), sort_keys=True),
            )
            for item in stage.blockers
        ]
        assert keys == sorted(keys)
        assert len(keys) == len(set(keys))


def test_cli_web_and_mcp_adapters_share_the_domain_result(
    tmp_path: Path,
    sample_har: tuple[Path, dict[str, Any]],
) -> None:
    workspace = _offline_workspace(tmp_path, sample_har)
    domain = resolve_workspace_readiness(workspace).model_dump(mode="json")
    cli = RUNNER.invoke(
        app,
        ["status", "--workspace", str(workspace.root), "--json"],
    )
    web = workspace_overview(load_snapshot(workspace))["readiness"]
    mcp = (
        FinsecMcpService.from_workspace_path(workspace.root)
        .workspace_summary()
        .readiness.model_dump(mode="json")
    )

    assert cli.exit_code == 0, cli.output
    assert json.loads(cli.output) == domain
    assert web == domain
    assert mcp == domain
