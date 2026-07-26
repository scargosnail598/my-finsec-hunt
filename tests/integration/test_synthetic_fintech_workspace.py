"""End-to-end regression coverage for the offline SyntheticPay workspace."""

from __future__ import annotations

import json
import runpy
from pathlib import Path

import pytest
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
from finsec.testing.planner import generate_plan
from finsec.utils.yaml_store import load_yaml

REPO_ROOT = Path(__file__).parents[2]
GENERATOR = runpy.run_path(str(REPO_ROOT / "scripts/generate_synthetic_fintech_hars.py"))
VALIDATOR = runpy.run_path(str(REPO_ROOT / "scripts/validate_synthetic_workspace.py"))
fixtures = GENERATOR["fixtures"]
OVERRIDE_PATH = VALIDATOR["OVERRIDE_PATH"]
PRESERVATION_NOTE = VALIDATOR["PRESERVATION_NOTE"]
SECRETS = VALIDATOR["SECRETS"]
annotate_lifecycle = VALIDATOR["annotate_lifecycle"]
configure = VALIDATOR["configure"]
prepare_preservation = VALIDATOR["prepare_preservation"]
snapshot = VALIDATOR["snapshot"]

RUNNER = CliRunner()
ACTORS = {
    "01-account-a-private-resources.har": "ACCOUNT_A",
    "02-account-b-private-resources.har": "ACCOUNT_B",
    "03-body-identifier-wallet.har": "ACCOUNT_A",
    "04-state-transitions.har": "ACCOUNT_A",
    "05-auth-code-replay.har": "ANONYMOUS",
    "06-static-and-versioned-assets.har": "ANONYMOUS",
    "07-telemetry-and-third-party.har": "ANONYMOUS",
    "08-post-read-endpoints.har": "ACCOUNT_A",
    "09-duplicate-route-instances.har": "ACCOUNT_A",
    "10-incomplete-evidence.har": "ACCOUNT_A",
}


def _build_workspace(root: Path, name: str = "syntheticpay") -> WorkspacePaths:
    har_root = root / "synthetic-hars"
    har_root.mkdir(parents=True)
    for filename, document in fixtures().items():
        (har_root / filename).write_text(
            json.dumps(document, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    workspace = create_workspace(name, root / "workspaces")
    configure(workspace)
    for filename, actor in ACTORS.items():
        ingest_har(har_root / filename, workspace, actor=actor, channel="WEB")
    build_inventory(workspace)
    generate_model(workspace)
    annotate_lifecycle(workspace)
    generate_invariants(workspace)
    generate_hypotheses(workspace)
    return workspace


@pytest.fixture(scope="module")
def synthetic_workspace(tmp_path_factory: pytest.TempPathFactory) -> WorkspacePaths:
    return _build_workspace(tmp_path_factory.mktemp("syntheticpay"))


def _endpoints(workspace: WorkspacePaths) -> EndpointStore:
    return EndpointStore.model_validate(load_yaml(workspace.endpoints))


def _hypotheses(workspace: WorkspacePaths) -> HypothesisStore:
    return HypothesisStore.model_validate(load_yaml(workspace.hypotheses))


def test_static_telemetry_versions_and_post_reads(
    synthetic_workspace: WorkspacePaths,
) -> None:
    endpoints = _endpoints(synthetic_workspace).endpoints
    static = [
        item
        for item in endpoints
        if item.classification.primary == EndpointPrimaryClassification.STATIC_ASSET
    ]
    telemetry = [
        item
        for item in endpoints
        if item.classification.primary == EndpointPrimaryClassification.TELEMETRY
    ]

    assert static and all(item.disposition == "SUPPRESSED_STATIC_ASSET" for item in static)
    assert telemetry and all(item.disposition == "SUPPRESSED_TELEMETRY" for item in telemetry)
    assert any(
        item.classification.primary == EndpointPrimaryClassification.THIRD_PARTY
        and "thirdparty.invalid" in item.hosts
        for item in endpoints
    )
    assert any(item.path == "/web/v3/loader_v3.12.3.js" for item in endpoints)
    assert not any("{v3Id}" in item.path for item in endpoints)
    read_posts = [
        item for item in endpoints if item.method == "POST" and item.action.type == "read"
    ]
    assert len(read_posts) >= 6
    assert all(not item.state_change for item in read_posts)


def test_path_and_body_bola_are_semantic_and_deduplicated(
    synthetic_workspace: WorkspacePaths,
) -> None:
    endpoints = _endpoints(synthetic_workspace).endpoints
    payment = next(
        item
        for item in endpoints
        if item.method == "GET" and item.path == "/api/v2/payments/{paymentId}"
    )
    wallet = next(item for item in endpoints if item.path == "/api/v2/wallet/payment-history")
    wallet_id = next(item for item in wallet.parameters if item.name == "walletId")
    active = [
        item for item in _hypotheses(synthetic_workspace).hypotheses if item.disposition == "ACTIVE"
    ]

    assert len(payment.sources) == 8
    assert wallet_id.location == "body"
    assert wallet_id.json_path == "$.walletId"
    assert wallet_id.semantic_type == "object_identifier"
    assert wallet_id.client_controlled
    assert any("paymentId" in item.hypothesis for item in active)
    assert sum("walletId" in item.hypothesis for item in active) == 1
    assert len({item.key for item in active}) == len(active)


def test_auth_lifecycle_and_incomplete_evidence_use_specific_candidates(
    synthetic_workspace: WorkspacePaths,
) -> None:
    records = _hypotheses(synthetic_workspace).hypotheses
    active = [item for item in records if item.disposition == "ACTIVE"]
    tasks = [item for item in records if item.kind == "RESEARCH_TASK"]
    task_text = " ".join(
        value for item in tasks for value in [item.title, item.reasoning, *item.evidence_to_collect]
    ).lower()

    assert all(
        word in task_text for word in ("replay", "challenge", "session", "account", "purpose")
    )
    assert "change-wallet persists server-side state" in task_text
    assert "lifecycle and security impact of user verification" in task_text
    assert not any(item.category == "state_integrity" for item in active)
    assert "confirm operation rejects cancelled payment" in task_text
    assert "cancel operation rejects confirmed payment" in task_text
    assert not any(
        item.category == "state_integrity"
        and any(word in item.hypothesis.lower() for word in ("search", "menu", "list", "viewport"))
        for item in active
    )


def test_pipeline_is_deterministic(tmp_path: Path) -> None:
    first = _build_workspace(tmp_path / "first")
    second = _build_workspace(tmp_path / "second")

    assert snapshot(first) == snapshot(second)


def test_researcher_state_and_redaction_survive_regeneration(tmp_path: Path) -> None:
    workspace = _build_workspace(tmp_path / "preservation")
    hypothesis_id = prepare_preservation(workspace)
    generate_plan(workspace, hypothesis_id)
    build_inventory(workspace)
    generate_model(workspace)
    generate_invariants(workspace)
    generate_hypotheses(workspace)

    records = _hypotheses(workspace).hypotheses
    preserved = next(item for item in records if item.notes == PRESERVATION_NOTE)
    override = next(item for item in _endpoints(workspace).endpoints if item.path == OVERRIDE_PATH)
    stored_text = "\n".join(
        path.read_text(encoding="utf-8") for path in workspace.root.rglob("*") if path.is_file()
    )

    assert preserved.status == "TEST_PLANNED"
    assert "researcher classification override" in override.classification.reasons
    assert all(secret not in stored_text for secret in SECRETS)


def test_synthetic_workspace_is_inspectable_through_cli(
    synthetic_workspace: WorkspacePaths,
) -> None:
    result = RUNNER.invoke(app, ["status", "--workspace", str(synthetic_workspace.root)])

    assert result.exit_code == 0
    assert "Observations" in result.output
    assert "Research Tasks" in result.output
