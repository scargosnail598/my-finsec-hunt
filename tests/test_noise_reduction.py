"""Regression coverage for endpoint noise reduction and evidence gates."""

from pathlib import Path

from typer.testing import CliRunner

from finsec.cli import app
from finsec.config.workspace import WorkspacePaths, create_workspace
from finsec.hypotheses.domain import HypothesisStore
from finsec.hypotheses.generator import generate_hypotheses
from finsec.ingest.har import ingest_har
from finsec.modeling.generator import generate_model
from finsec.modeling.invariants import generate_invariants
from finsec.modeling.models import EndpointPrimaryClassification, EndpointStore
from finsec.normalization.inventory import build_inventory
from finsec.utils.yaml_store import load_yaml, write_yaml

FIXTURES = Path(__file__).parent / "fixtures/noise"
RUNNER = CliRunner()


def _workspace(tmp_path: Path, fixture: str, accounts: int = 0) -> WorkspacePaths:
    workspace = create_workspace(fixture.removesuffix(".har"), tmp_path / "workspaces")
    target = load_yaml(workspace.target)
    target["scope"]["hosts"] = ["api.example.test"]
    target["accounts"] = [
        {"id": f"ACCOUNT_{index}", "ownership": "researcher"} for index in range(1, accounts + 1)
    ]
    write_yaml(workspace.target, target)
    ingest_har(FIXTURES / fixture, workspace, actor="ACCOUNT_1" if accounts else "UNKNOWN")
    build_inventory(workspace)
    return workspace


def _endpoints(workspace: WorkspacePaths) -> EndpointStore:
    return EndpointStore.model_validate(load_yaml(workspace.endpoints))


def test_static_assets_are_grouped_and_suppressed(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path, "static-images.har", accounts=2)
    endpoints = _endpoints(workspace).endpoints

    assert len(endpoints) == 2
    assert all(
        item.classification.primary == EndpointPrimaryClassification.STATIC_ASSET
        for item in endpoints
    )
    assert all(item.disposition == "SUPPRESSED_STATIC_ASSET" for item in endpoints)
    assert all(item.state_change is False for item in endpoints)


def test_version_segments_remain_literal(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path, "versioned-assets.har")
    paths = {item.path for item in _endpoints(workspace).endpoints}

    assert "/web/v3/loader_v3.12.3.js" in paths
    assert "/api/v8/profile" in paths
    assert all("{v3Id}" not in path and "{v8Id}" not in path for path in paths)


def test_telemetry_is_suppressed_without_business_state(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path, "telemetry.har")
    endpoints = _endpoints(workspace).endpoints

    assert len(endpoints) == 4
    assert all(
        item.classification.primary == EndpointPrimaryClassification.TELEMETRY for item in endpoints
    )
    assert all(item.disposition == "SUPPRESSED_TELEMETRY" for item in endpoints)
    assert all(item.state_change is False for item in endpoints)


def test_post_read_actions_do_not_become_state_changes(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path, "post-read-endpoints.har")
    endpoints = _endpoints(workspace).endpoints

    assert {item.action.name for item in endpoints} == {"search", "menu", "list", "viewport"}
    assert all(item.action.type == "read" for item in endpoints)
    assert all(item.state_change is False for item in endpoints)


def test_body_identifiers_are_structured_and_bola_is_gated(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path, "authenticated-wallet.har", accounts=2)
    endpoint = _endpoints(workspace).endpoints[0]
    wallet_id = next(item for item in endpoint.parameters if item.name == "walletId")

    assert endpoint.resource.type == "Wallet"
    assert EndpointPrimaryClassification.FINANCIAL in endpoint.classification.tags
    assert wallet_id.location == "body"
    assert wallet_id.json_path == "$.walletId"
    assert wallet_id.semantic_type == "object_identifier"
    assert wallet_id.client_controlled is True

    generate_model(workspace)
    generate_invariants(workspace)
    generate_hypotheses(workspace)
    store = HypothesisStore.model_validate(load_yaml(workspace.hypotheses))
    active = [item for item in store.hypotheses if item.disposition == "ACTIVE"]
    assert any(item.generation_rule.get("id") == "AUTH_OBJECT_ACCESS" for item in active)


def test_nested_body_fields_preserve_json_paths_and_semantics(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path, "body-identifiers.har", accounts=2)
    endpoint = _endpoints(workspace).endpoints[0]
    parameters = {(item.json_path, item.semantic_type) for item in endpoint.parameters}

    assert ("$.payment.accountId", "object_identifier") in parameters
    assert ("$.destination.id", "object_identifier") in parameters
    assert ("$.sender.id", "object_identifier") in parameters
    assert ("$.recipient.id", "object_identifier") in parameters
    assert ("$.billing.account.id", "object_identifier") in parameters
    assert ("$.shipping.account.id", "object_identifier") in parameters
    assert ("$.items[*].paymentId", "object_identifier") in parameters
    assert ("$.amount", "monetary_value") in parameters


def test_authentication_code_creates_research_task_not_generic_state_hypothesis(
    tmp_path: Path,
) -> None:
    workspace = _workspace(tmp_path, "authentication-code.har", accounts=1)
    generate_model(workspace)
    generate_invariants(workspace)
    generate_hypotheses(workspace)
    store = HypothesisStore.model_validate(load_yaml(workspace.hypotheses))

    assert not any(item.category == "state_integrity" for item in store.hypotheses)
    tasks = [item for item in store.hypotheses if item.kind == "RESEARCH_TASK"]
    assert len(tasks) == 1
    assert "replay and binding" in tasks[0].title.lower()


def test_duplicate_route_instances_create_one_semantic_hypothesis(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path, "duplicate-route-instances.har", accounts=2)
    generate_model(workspace)
    generate_invariants(workspace)
    generate_hypotheses(workspace)
    store = HypothesisStore.model_validate(load_yaml(workspace.hypotheses))

    authorization = [
        item
        for item in store.hypotheses
        if item.category == "authorization" and item.disposition == "ACTIVE"
    ]
    assert len(_endpoints(workspace).endpoints) == 1
    assert len(authorization) == 1
    assert len(authorization[0].observations) == 3


def test_classification_noise_and_explain_cli(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path, "telemetry.har")

    classified = RUNNER.invoke(app, ["classify", "--workspace", str(workspace.root)])
    noise = RUNNER.invoke(app, ["noise", "--workspace", str(workspace.root)])
    explained = RUNNER.invoke(app, ["explain", "EP-001", "--workspace", str(workspace.root)])

    assert classified.exit_code == 0
    assert "TELEMETRY" in classified.output
    assert noise.exit_code == 0
    assert "SUPPRESSED_TELEMETRY: 4" in noise.output
    assert explained.exit_code == 0
    assert "Security relevance" in explained.output


def test_wildcard_scope_and_configured_path_exclusions_are_enforced(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path, "post-read-endpoints.har", accounts=1)
    target = load_yaml(workspace.target)
    target["scope"]["hosts"] = ["*.example.test"]
    target["analysis"]["include_hosts"] = ["*.example.test"]
    target["analysis"]["excluded_path_patterns"].append("/search")
    write_yaml(workspace.target, target)

    build_inventory(workspace)
    endpoints = _endpoints(workspace).endpoints
    search = next(item for item in endpoints if item.path.endswith("/search"))
    remaining = [item for item in endpoints if item is not search]

    assert search.disposition == "SUPPRESSED_INSUFFICIENT_EVIDENCE"
    assert "configured exclusion pattern /search" in " ".join(search.classification.reasons)
    assert all(
        item.classification.primary == EndpointPrimaryClassification.FIRST_PARTY_API
        for item in remaining
    )
