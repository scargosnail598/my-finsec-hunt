"""Canonical readiness, blocker, provenance, and adapter regressions."""

from __future__ import annotations

import copy
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from typer.testing import CliRunner

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
from finsec.hypotheses.generator import generate_hypotheses
from finsec.ingest.har import ingest_har
from finsec.mcp.service import FinsecMcpService
from finsec.modeling.generator import generate_model
from finsec.modeling.invariants import generate_invariants
from finsec.readiness.domain import BlockerCode, LifecycleStatus, PipelineStage
from finsec.readiness.resolver import resolve_workspace_readiness
from finsec.reporting.generator import generate_report
from finsec.testing.planner import generate_plan
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
        identity=AuthenticationIdentityConfig(baseline_confirmed=baseline_confirmed),
        status="READY",
        target_hosts=target.scope.hosts,
        last_validated_at=datetime.now(UTC),
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
    assert _stage(complete, PipelineStage.PLAN).status == LifecycleStatus.READY


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
    target["accounts"][0]["authentication"]["last_validated_at"] = datetime.now(UTC).isoformat()
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

    assert by_actor["ACCOUNT_A"].ownership.confirmed_baselines >= 2
    assert by_actor["ACCOUNT_B"].ownership.confirmed_baselines >= 2


def test_unapproved_plan_and_disabled_execution_have_distinct_blockers(
    phase4_workspace: WorkspacePaths,
) -> None:
    report = resolve_workspace_readiness(phase4_workspace)
    codes = {item.code for item in _stage(report, PipelineStage.EXECUTE).blockers}

    assert BlockerCode.HUMAN_APPROVAL_MISSING in codes
    assert BlockerCode.ACTIVE_EXECUTION_DISABLED in codes
    assert _stage(report, PipelineStage.PLAN).status == LifecycleStatus.COMPLETE


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
