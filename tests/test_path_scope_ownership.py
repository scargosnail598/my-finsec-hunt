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
from finsec.modeling.semantics import IdentifierSemanticClass, OwnershipState
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
    invariants = load_yaml(workspace.invariants)
    if invariants.get("invariants"):
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


def test_account_parent_scope_remains_tenant_container_research_only(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path, _account_entries())
    for command in ("inventory", "model", "invariants", "hypotheses"):
        result = RUNNER.invoke(app, [command, "--workspace", str(workspace.root)])
        assert result.exit_code == 0, result.output
    endpoint = _endpoint(workspace, "/v1/accounts/{accountId}/iam/resources")
    parameter = next(item for item in endpoint.parameters if item.name == "accountId")
    decision = next(item for item in endpoint.ownership_inference if item.parameter == "accountId")
    store = HypothesisStore.model_validate(load_yaml(workspace.hypotheses))

    assert endpoint.object_access == []
    assert parameter.identifier_semantics.semantic_class == IdentifierSemanticClass.TENANT_CONTAINER
    assert parameter.identifier_semantics.ownership_state == OwnershipState.WEAK_INFERRED
    assert decision.status == "REJECTED"
    assert "structural scope observations only" in " ".join(decision.reasons)
    assert not any(
        item.category == "authorization" and endpoint.id in item.source.endpoints
        for item in store.hypotheses
    )

    mcp = FinsecMcpService.from_workspace_path(workspace.root)
    summary = mcp.list_hypotheses(active_only=False, include_research_tasks=True)
    assert summary.hypotheses


def test_tenant_parent_scope_uses_the_same_container_semantics(tmp_path: Path) -> None:
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
    parameter = next(item for item in endpoint.parameters if item.name == "tenantId")

    assert endpoint.object_access == []
    assert parameter.identifier_semantics.semantic_class == IdentifierSemanticClass.TENANT_CONTAINER
    assert parameter.identifier_semantics.ownership_state == OwnershipState.WEAK_INFERRED


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
    assert not any(
        item.category == "authorization" and endpoint.id in item.source.endpoints
        for item in store.hypotheses
    )


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

    assert get_endpoint.object_access == []
    assert (
        next(
            item for item in get_endpoint.parameters if item.name == "accountId"
        ).identifier_semantics.semantic_class
        == IdentifierSemanticClass.TENANT_CONTAINER
    )
    assert options_endpoint.object_access == []


def _owned_object_entries() -> list[tuple[str, dict[str, Any]]]:
    object_a = "11111111-1111-4111-8111-111111111111"
    object_b = "22222222-2222-4222-8222-222222222222"
    return [
        ("ACCOUNT_A", _entry(1, "POST", "/v1/firewalls", {"id": object_a})),
        ("ACCOUNT_A", _entry(2, "GET", f"/v1/firewalls/{object_a}", {"id": object_a})),
        ("ACCOUNT_B", _entry(3, "POST", "/v1/firewalls", {"id": object_b})),
        ("ACCOUNT_B", _entry(4, "GET", f"/v1/firewalls/{object_b}", {"id": object_b})),
    ]


def _owned_object_workspace(tmp_path: Path, *, active_execution: bool) -> WorkspacePaths:
    workspace = create_workspace("path-scope", tmp_path / "workspaces")
    target = load_yaml(workspace.target)
    target["scope"]["hosts"] = ["api.example.test"]
    target["accounts"] = [
        {"id": actor, "ownership": "researcher"}
        for actor in sorted({actor for actor, _ in _owned_object_entries()})
    ]
    target["testing"].update(
        {
            "production": False,
            "synthetic": True,
            "local_lab": True,
            "active_execution_enabled": active_execution,
            "maximum_requests_per_plan": 6,
        }
    )
    write_yaml(workspace.target, target)

    entries = _owned_object_entries()
    for index, actor in enumerate(sorted({actor for actor, _ in entries}), start=1):
        capture = tmp_path / f"owned-{index}.har"
        capture.write_text(
            json.dumps(
                {
                    "log": {
                        "version": "1.2",
                        "creator": {"name": "path-scope-tests", "version": "1"},
                        "entries": [
                            entry for entry_actor, entry in entries if entry_actor == actor
                        ],
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


def _owned_object_context(
    tmp_path: Path, *, active_execution: bool
) -> tuple[WorkspacePaths, Endpoint, HypothesisRecord]:
    workspace = _owned_object_workspace(tmp_path, active_execution=active_execution)
    endpoint = _endpoint(workspace, "/v1/firewalls/{firewallId}")
    return workspace, endpoint, _hypothesis(workspace, endpoint)


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
    workspace, _endpoint_record, hypothesis = _owned_object_context(tmp_path, active_execution=True)
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
    workspace, _endpoint_record, hypothesis = _owned_object_context(
        tmp_path, active_execution=False
    )
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
    workspace, _endpoint_record, hypothesis = _owned_object_context(tmp_path, active_execution=True)
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
    workspace, _endpoint_record, hypothesis = _owned_object_context(tmp_path, active_execution=True)
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
