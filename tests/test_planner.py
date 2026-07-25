"""Phase 3 safety-gated test-plan tests."""

import copy
from pathlib import Path
from typing import Any

from finsec.config.workspace import WorkspacePaths, create_workspace
from finsec.hypotheses.domain import HypothesisStore
from finsec.hypotheses.generator import generate_hypotheses
from finsec.ingest.har import ingest_har
from finsec.modeling.generator import generate_model
from finsec.modeling.invariants import generate_invariants
from finsec.modeling.models import EndpointStore
from finsec.normalization.inventory import build_inventory
from finsec.testing.domain import TestPlanStore as PlanStore
from finsec.testing.planner import generate_plan
from finsec.utils.yaml_store import load_yaml, write_yaml


def test_plan_is_review_only_and_uses_researcher_controlled_accounts(
    phase3_workspace: WorkspacePaths,
) -> None:
    generate_hypotheses(phase3_workspace)
    result = generate_plan(phase3_workspace, "HYP-002")
    plan = result.plan

    assert result.conflict is False
    assert plan.status == "READY_FOR_REVIEW"
    assert plan.execution_default == "DO_NOT_EXECUTE"
    assert plan.human_approval_required is True
    assert plan.approval_status == "NOT_REQUESTED"
    assert plan.risk.decision == "REQUIRES_HUMAN_APPROVAL"
    assert plan.risk.request_budget == 2
    assert plan.risk.affects_external_user is False
    assert plan.accounts.object_owner == "ACCOUNT_A"
    assert plan.accounts.actor == "ACCOUNT_B"
    assert any("exactly one modified request" in item.lower() for item in plan.actions)

    hypotheses = HypothesisStore.model_validate(load_yaml(phase3_workspace.hypotheses))
    payment = next(item for item in hypotheses.hypotheses if item.id == "HYP-002")
    assert payment.status == "TEST_PLANNED"

    regeneration = generate_hypotheses(phase3_workspace)
    hypotheses = HypothesisStore.model_validate(load_yaml(phase3_workspace.hypotheses))
    payment = next(item for item in hypotheses.hypotheses if item.id == "HYP-002")
    assert regeneration.conflicts == ()
    assert payment.status == "TEST_PLANNED"


def test_plan_blocks_incomplete_scope_and_uncontrolled_accounts(
    tmp_path: Path, sample_har: tuple[Path, dict[str, Any]]
) -> None:
    har_path, _ = sample_har
    workspace = create_workspace("blocked", tmp_path / "workspaces")
    ingest_har(har_path, workspace, actor="ACCOUNT_A")
    build_inventory(workspace)
    generate_model(workspace)
    generate_invariants(workspace)
    generate_hypotheses(workspace)

    result = generate_plan(workspace, "HYP-002")
    assert result.plan.status == "BLOCKED"
    assert result.plan.execution_default == "DO_NOT_EXECUTE"
    assert result.plan.risk.affects_external_user is True
    assert "No in-scope hosts" in " ".join(result.plan.risk.reasons)
    assert "Two researcher-controlled accounts" in " ".join(result.plan.risk.reasons)


def test_plan_approval_and_notes_survive_regeneration(
    phase3_workspace: WorkspacePaths,
) -> None:
    generate_hypotheses(phase3_workspace)
    generate_plan(phase3_workspace, "HYP-002")
    document = load_yaml(phase3_workspace.test_plans)
    document["plans"][0]["approval_status"] = "APPROVED"
    document["plans"][0]["notes"] = "Approved for a staging account only."
    write_yaml(phase3_workspace.test_plans, document)

    result = generate_plan(phase3_workspace, "HYP-002")
    store = PlanStore.model_validate(load_yaml(phase3_workspace.test_plans))
    plan = next(item for item in store.plans if item.hypothesis_id == "HYP-002")
    assert result.conflict is False
    assert plan.approval_status == "APPROVED"
    assert plan.notes == "Approved for a staging account only."
    assert plan.execution_default == "DO_NOT_EXECUTE"


def test_differential_plans_check_every_endpoint_and_use_channel_language(
    phase3_workspace: WorkspacePaths,
) -> None:
    document = load_yaml(phase3_workspace.endpoints)
    payment = document["endpoints"][0]
    payment["path"] = "/api/v1/payments/{paymentId}"
    payment["channels"] = ["WEB", "MOBILE"]
    legacy = copy.deepcopy(payment)
    legacy["id"] = "EP-099"
    legacy["path"] = "/api/v2/payments/{paymentId}"
    legacy["hosts"] = ["legacy.example.test"]
    legacy["channels"] = ["WEB"]
    document["endpoints"].append(legacy)
    EndpointStore.model_validate(document)
    write_yaml(phase3_workspace.endpoints, document)

    generate_hypotheses(phase3_workspace)
    hypotheses = HypothesisStore.model_validate(load_yaml(phase3_workspace.hypotheses))
    version = next(item for item in hypotheses.hypotheses if item.category == "version_parity")
    channel = next(item for item in hypotheses.hypotheses if item.category == "channel_parity")

    version_plan = generate_plan(phase3_workspace, version.id).plan
    assert version_plan.status == "BLOCKED"
    assert "not fully covered" in " ".join(version_plan.risk.reasons)

    channel_plan = generate_plan(phase3_workspace, channel.id).plan
    assert any("observed channel" in item for item in channel_plan.actions)
    assert all("observed version" not in item for item in channel_plan.actions)
