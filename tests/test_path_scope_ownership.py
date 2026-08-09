"""Regressions for fail-closed parent-scope ownership inference and approval UX."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from finsec.cli import app
from finsec.config.workspace import WorkspacePaths, create_workspace
from finsec.hypotheses.domain import HypothesisRecord, HypothesisStore
from finsec.hypotheses.generator import generate_hypotheses
from finsec.ingest.har import ingest_har
from finsec.mcp.service import FinsecMcpService
from finsec.modeling.generator import generate_model
from finsec.modeling.invariants import generate_invariants
from finsec.modeling.models import Endpoint, EndpointStore
from finsec.normalization.inventory import build_inventory
from finsec.testing.planner import generate_plan
from finsec.utils.yaml_store import load_yaml, write_yaml

RUNNER = CliRunner()


def _entry(
    index: int,
    method: str,
    path: str,
    response: Any,
    *,
    authenticated: bool = True,
    status: int = 200,
) -> dict[str, Any]:
    headers = (
        [{"name": "Authorization", "value": "Bearer SYNTHETIC_TOKEN"}] if authenticated else []
    )
    return {
        "startedDateTime": f"2026-07-29T10:{index:02d}:00Z",
        "request": {
            "method": method,
            "url": f"https://api.example.test{path}",
            "headers": headers,
        },
        "response": {
            "status": status,
            "headers": [{"name": "Content-Type", "value": "application/json"}],
            "content": {"mimeType": "application/json", "text": json.dumps(response)},
        },
    }


def _workspace(
    tmp_path: Path,
    actor_entries: list[tuple[str, dict[str, Any]]],
    *,
    active_execution: bool = False,
) -> WorkspacePaths:
    workspace = create_workspace("path-scope", tmp_path / "workspaces")
    target = load_yaml(workspace.target)
    target["scope"]["hosts"] = ["api.example.test"]
    target["accounts"] = [
        {"id": actor, "ownership": "researcher"}
        for actor in sorted({actor for actor, _ in actor_entries})
    ]
    target["testing"].update(
        {
            "production": False,
            "active_execution_enabled": active_execution,
        }
    )
    write_yaml(workspace.target, target)

    for index, (actor, entry) in enumerate(actor_entries, start=1):
        capture = tmp_path / f"scope-{index}.har"
        capture.write_text(
            json.dumps(
                {
                    "log": {
                        "version": "1.2",
                        "creator": {"name": "path-scope-tests", "version": "1"},
                        "entries": [entry],
                    }
                }
            ),
            encoding="utf-8",
        )
        ingest_har(capture, workspace, actor=actor, channel="WEB")

    build_inventory(workspace)
    generate_model(workspace)
    generate_invariants(workspace)
    generate_hypotheses(workspace)
    return workspace


def _endpoint(workspace: WorkspacePaths, path: str, method: str = "GET") -> Endpoint:
    store = EndpointStore.model_validate(load_yaml(workspace.endpoints))
    return next(item for item in store.endpoints if item.method == method and item.path == path)


def _hypothesis(workspace: WorkspacePaths, endpoint: Endpoint) -> HypothesisRecord:
    store = HypothesisStore.model_validate(load_yaml(workspace.hypotheses))
    return next(
        item
        for item in store.hypotheses
        if item.kind == "SECURITY_HYPOTHESIS"
        and item.disposition == "ACTIVE"
        and endpoint.id in item.source.endpoints
        and item.category == "authorization"
    )


def _account_entries() -> list[tuple[str, dict[str, Any]]]:
    return [
        (
            "ACCOUNT_A",
            _entry(
                1,
                "GET",
                "/v1/accounts/acct-a-1001/iam/resources",
                {"resources": [{"kind": "role", "name": "synthetic-a"}]},
            ),
        ),
        (
            "ACCOUNT_B",
            _entry(
                2,
                "GET",
                "/v1/accounts/acct-b-2002/iam/resources",
                {"resources": [{"kind": "role", "name": "synthetic-b"}]},
            ),
        ),
    ]


def test_account_parent_scope_builds_supported_object_substitution(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path, _account_entries())
    for command in ("inventory", "model", "invariants", "hypotheses"):
        result = RUNNER.invoke(app, [command, "--workspace", str(workspace.root)])
        assert result.exit_code == 0, result.output
    endpoint = _endpoint(workspace, "/v1/accounts/{accountId}/iam/resources")
    binding = next(item for item in endpoint.object_access if item.identifier == "accountId")

    assert binding.source == "PATH_PARENT_SCOPE"
    assert binding.confidence == "medium"
    assert binding.owner_field_path is None
    assert binding.scope_parameter == "accountId"
    assert binding.distinct_actors == 2
    assert binding.distinct_scope_values == 2
    assert all(item.owner_value_fingerprint is None for item in binding.baselines)
    assert all(item.scope_value_fingerprint is not None for item in binding.baselines)

    hypothesis = _hypothesis(workspace, endpoint)
    plan = generate_plan(workspace, hypothesis.id).plan

    assert plan.status == "READY_FOR_REVIEW"
    assert plan.execution.supported is True
    assert plan.execution.pattern == "OBJECT_SUBSTITUTION"
    assert plan.execution.request_budget == 2
    assert plan.requests[0].actor == "ACCOUNT_A"
    assert plan.requests[1].actor == "ACCOUNT_A"
    assert plan.requests[0].path.endswith("/acct-a-1001/iam/resources")
    assert plan.requests[1].path.endswith("/acct-b-2002/iam/resources")
    assert plan.requests[1].mutations[0].source_actor == "ACCOUNT_A"
    assert plan.requests[1].mutations[0].target_actor == "ACCOUNT_B"

    planned = RUNNER.invoke(app, ["plan", hypothesis.id, "--workspace", str(workspace.root)])
    assert planned.exit_code == 0, planned.output
    assert "Bounded execution template: OBJECT_SUBSTITUTION (2 requests)" in planned.output

    explained = RUNNER.invoke(app, ["explain", endpoint.id, "--workspace", str(workspace.root)])
    assert explained.exit_code == 0, explained.output
    assert "controlled parent-scope baseline" in explained.output
    assert "Parameter: accountId" in explained.output
    assert "OBJECT_SUBSTITUTION" in explained.output
    assert "acct-a-1001" not in explained.output
    assert "acct-b-2002" not in explained.output

    context = FinsecMcpService.from_workspace_path(workspace.root).hypothesis_context(hypothesis.id)
    mcp_endpoint = next(item for item in context.endpoints if item.id == endpoint.id)
    assert mcp_endpoint.object_access[0].source == "PATH_PARENT_SCOPE"
    assert mcp_endpoint.object_access[0].owner_field_path is None
    assert mcp_endpoint.ownership_inference[0].status == "APPLIED"


def test_tenant_parent_scope_uses_the_same_generic_inference(tmp_path: Path) -> None:
    workspace = _workspace(
        tmp_path,
        [
            (
                "ACCOUNT_A",
                _entry(1, "GET", "/v2/tenants/tenant-a-1001/audit", {"events": [1]}),
            ),
            (
                "ACCOUNT_B",
                _entry(2, "GET", "/v2/tenants/tenant-b-2002/audit", {"events": [2]}),
            ),
        ],
    )
    endpoint = _endpoint(workspace, "/v2/tenants/{tenantId}/audit")
    binding = next(item for item in endpoint.object_access if item.identifier == "tenantId")

    assert binding.source == "PATH_PARENT_SCOPE"
    assert generate_plan(workspace, _hypothesis(workspace, endpoint).id).plan.execution.supported


def test_public_region_scope_never_becomes_path_ownership(tmp_path: Path) -> None:
    workspace = _workspace(
        tmp_path,
        [
            (
                "ACCOUNT_A",
                _entry(1, "GET", "/ecc/v1/regions/region-a-1001/servers", {"data": [1]}),
            ),
            (
                "ACCOUNT_B",
                _entry(2, "GET", "/ecc/v1/regions/region-b-2002/servers", {"data": [2]}),
            ),
        ],
        active_execution=True,
    )
    endpoint = _endpoint(workspace, "/ecc/v1/regions/{regionId}/servers")

    assert endpoint.object_access == []
    decision = next(item for item in endpoint.ownership_inference if item.parameter == "regionId")
    assert decision.status == "REJECTED"
    assert decision.classification == "PUBLIC_SHARED_SCOPE"
    assert "public/shared" in " ".join(decision.reasons)

    store = HypothesisStore.model_validate(load_yaml(workspace.hypotheses))
    hypothesis = next(
        item
        for item in store.hypotheses
        if endpoint.id in item.source.endpoints and item.category == "authorization"
    )
    assert hypothesis.kind == "RESEARCH_TASK"
    assert hypothesis.disposition == "NEEDS_RESEARCH"
    assert hypothesis.priority == "P3"
    assert hypothesis.readiness == "RESEARCH_ONLY"
    assert hypothesis.domain_intent.visibility == "SHARED"
    assert hypothesis.title.startswith("Validate shared Region access semantics")

    planned = RUNNER.invoke(app, ["plan", hypothesis.id, "--workspace", str(workspace.root)])
    assert planned.exit_code == 1
    assert "research or suppressed candidate" in planned.output


@pytest.mark.parametrize(
    "actor_entries, expected_reason",
    [
        (
            [
                (
                    "ACCOUNT_A",
                    _entry(1, "GET", "/v1/accounts/shared-1001/iam/resources", {"data": [1]}),
                ),
                (
                    "ACCOUNT_B",
                    _entry(2, "GET", "/v1/accounts/shared-1001/iam/resources", {"data": [2]}),
                ),
            ],
            "shared by multiple controlled actors",
        ),
        (
            [
                (
                    "ACCOUNT_A",
                    _entry(1, "GET", "/v1/accounts/acct-a-1001/iam/resources", {"data": [1]}),
                )
            ],
            "Only one controlled actor baseline",
        ),
        (
            [
                (
                    "ACCOUNT_A",
                    _entry(
                        1,
                        "GET",
                        "/v1/accounts/acct-a-1001/iam/resources",
                        {"data": [1]},
                        authenticated=False,
                    ),
                ),
                (
                    "ACCOUNT_B",
                    _entry(
                        2,
                        "GET",
                        "/v1/accounts/acct-b-2002/iam/resources",
                        {"data": [2]},
                        authenticated=False,
                    ),
                ),
            ],
            "Authenticated controlled baselines are missing",
        ),
        (
            [
                (
                    "ACCOUNT_A",
                    _entry(1, "GET", "/v1/accounts/acct-a-1001/iam/resources", {"data": [1]}),
                ),
                (
                    "ACCOUNT_A",
                    _entry(2, "GET", "/v1/accounts/acct-c-3003/iam/resources", {"data": [3]}),
                ),
                (
                    "ACCOUNT_B",
                    _entry(3, "GET", "/v1/accounts/acct-b-2002/iam/resources", {"data": [2]}),
                ),
            ],
            "associated with multiple parent-scope values",
        ),
    ],
)
def test_ambiguous_parent_scope_relationships_fail_closed(
    tmp_path: Path,
    actor_entries: list[tuple[str, dict[str, Any]]],
    expected_reason: str,
) -> None:
    workspace = _workspace(tmp_path, actor_entries)
    endpoint = _endpoint(workspace, "/v1/accounts/{accountId}/iam/resources")
    decision = next(item for item in endpoint.ownership_inference if item.parameter == "accountId")

    assert endpoint.object_access == []
    assert decision.status == "REJECTED"
    assert expected_reason in " ".join(decision.reasons)


@pytest.mark.parametrize(
    "second_status, second_response",
    [(403, {"error": "denied"}), (200, {"data": []})],
)
def test_unsuccessful_or_empty_baseline_is_not_executable(
    tmp_path: Path, second_status: int, second_response: dict[str, Any]
) -> None:
    workspace = _workspace(
        tmp_path,
        [
            (
                "ACCOUNT_A",
                _entry(1, "GET", "/v1/accounts/acct-a-1001/iam/resources", {"data": [1]}),
            ),
            (
                "ACCOUNT_B",
                _entry(
                    2,
                    "GET",
                    "/v1/accounts/acct-b-2002/iam/resources",
                    second_response,
                    status=second_status,
                ),
            ),
        ],
    )
    endpoint = _endpoint(workspace, "/v1/accounts/{accountId}/iam/resources")

    assert endpoint.object_access == []
    assert next(item for item in endpoint.ownership_inference).status == "REJECTED"


def test_options_requests_do_not_contribute_to_parent_scope_binding(tmp_path: Path) -> None:
    entries = [
        (
            "ACCOUNT_A",
            _entry(
                1,
                "OPTIONS",
                "/v1/accounts/acct-a-1001/iam/resources",
                {},
                authenticated=False,
            ),
        ),
        *_account_entries(),
    ]
    workspace = _workspace(tmp_path, entries)
    get_endpoint = _endpoint(workspace, "/v1/accounts/{accountId}/iam/resources")
    options_endpoint = _endpoint(
        workspace, "/v1/accounts/{accountId}/iam/resources", method="OPTIONS"
    )

    assert any(item.source == "PATH_PARENT_SCOPE" for item in get_endpoint.object_access)
    assert options_endpoint.object_access == []


def test_conflicting_response_scope_metadata_disables_fallback(tmp_path: Path) -> None:
    workspace = _workspace(
        tmp_path,
        [
            (
                "ACCOUNT_A",
                _entry(
                    1,
                    "GET",
                    "/v1/accounts/acct-a-1001/iam/resources",
                    {"accountId": "other-a-9001", "resources": [1]},
                ),
            ),
            (
                "ACCOUNT_B",
                _entry(
                    2,
                    "GET",
                    "/v1/accounts/acct-b-2002/iam/resources",
                    {"accountId": "other-b-9002", "resources": [2]},
                ),
            ),
        ],
    )
    endpoint = _endpoint(workspace, "/v1/accounts/{accountId}/iam/resources")
    decision = next(item for item in endpoint.ownership_inference if item.parameter == "accountId")

    assert endpoint.object_access == []
    assert decision.status == "REJECTED"
    assert "conflicts with the request parent scope" in " ".join(decision.reasons)


def test_supported_approval_still_prompts_and_records_checksum_binding(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path, _account_entries(), active_execution=True)
    endpoint = _endpoint(workspace, "/v1/accounts/{accountId}/iam/resources")
    hypothesis = _hypothesis(workspace, endpoint)
    generate_plan(workspace, hypothesis.id)

    result = RUNNER.invoke(
        app,
        ["approve", hypothesis.id, "--workspace", str(workspace.root)],
        input=f"APPROVE {hypothesis.id}\n",
    )

    assert result.exit_code == 0, result.output
    assert "Type APPROVE" in result.output
    assert "approved for bounded execution" in result.output
    plan = next(
        item
        for item in load_yaml(workspace.test_plans)["plans"]
        if item["hypothesis_id"] == hypothesis.id
    )
    assert plan["approval_status"] == "APPROVED"
    assert plan["approval"]["plan_checksum"]
    assert plan["approval"]["target_policy_checksum"]


def test_disabled_active_execution_is_rejected_before_approval_prompt(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path, _account_entries())
    endpoint = _endpoint(workspace, "/v1/accounts/{accountId}/iam/resources")
    hypothesis = _hypothesis(workspace, endpoint)
    generate_plan(workspace, hypothesis.id)

    result = RUNNER.invoke(
        app,
        ["approve", hypothesis.id, "--workspace", str(workspace.root)],
        input=f"APPROVE {hypothesis.id}\n",
    )

    assert result.exit_code == 1
    assert "active_execution_enabled is false" in result.output
    assert "Type APPROVE" not in result.output


def test_edited_plan_is_rejected_before_approval_prompt(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path, _account_entries(), active_execution=True)
    endpoint = _endpoint(workspace, "/v1/accounts/{accountId}/iam/resources")
    hypothesis = _hypothesis(workspace, endpoint)
    generate_plan(workspace, hypothesis.id)
    plans = load_yaml(workspace.test_plans)
    plan = next(item for item in plans["plans"] if item["hypothesis_id"] == hypothesis.id)
    plan["actions"].append("Externally edited synthetic action.")
    write_yaml(workspace.test_plans, plans)

    result = RUNNER.invoke(
        app,
        ["approve", hypothesis.id, "--workspace", str(workspace.root)],
        input=f"APPROVE {hypothesis.id}\n",
    )

    assert result.exit_code == 1
    assert "generated plan content was edited" in result.output
    assert "Type APPROVE" not in result.output


def test_stale_plan_is_rejected_before_approval_prompt(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path, _account_entries(), active_execution=True)
    endpoint = _endpoint(workspace, "/v1/accounts/{accountId}/iam/resources")
    hypothesis = _hypothesis(workspace, endpoint)
    generate_plan(workspace, hypothesis.id)
    observations = load_yaml(workspace.observations)
    observations["observations"][0]["notes"] = "Synthetic input changed after planning."
    write_yaml(workspace.observations, observations)

    result = RUNNER.invoke(
        app,
        ["approve", hypothesis.id, "--workspace", str(workspace.root)],
        input=f"APPROVE {hypothesis.id}\n",
    )

    assert result.exit_code == 1
    assert "plan inputs changed after generation" in result.output
    assert "Type APPROVE" not in result.output


def test_path_scope_pipeline_regeneration_is_idempotent(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path, _account_entries())
    first_endpoints = load_yaml(workspace.endpoints)
    first_hypotheses = load_yaml(workspace.hypotheses)

    build_inventory(workspace)
    generate_model(workspace)
    generate_invariants(workspace)
    generate_hypotheses(workspace)

    assert load_yaml(workspace.endpoints) == first_endpoints
    assert load_yaml(workspace.hypotheses) == first_hypotheses
