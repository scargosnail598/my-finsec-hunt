"""Endpoint normalization and evidence-linking tests."""

from pathlib import Path
from typing import Any

from finsec.config.workspace import create_workspace
from finsec.ingest.har import ingest_har
from finsec.modeling.models import Confidence, EndpointStore, KnowledgeStatus
from finsec.normalization.inventory import build_inventory
from finsec.utils.yaml_store import load_yaml


def test_inventory_groups_dynamic_paths_conservatively(
    tmp_path: Path, sample_har: tuple[Path, dict[str, Any]]
) -> None:
    har_path, _ = sample_har
    workspace = create_workspace("demo", tmp_path / "workspaces")
    ingest_har(har_path, workspace, actor="ACCOUNT_A")

    result = build_inventory(workspace)
    store = EndpointStore.model_validate(load_yaml(workspace.endpoints))
    by_path = {(item.method, item.path): item for item in store.endpoints}

    assert result.observations == 5
    assert result.endpoints == 4

    payments = by_path[("GET", "/api/payments/{paymentId}")]
    assert payments.sources == ["OBS-000001", "OBS-000002"]
    assert payments.normalization.observed_paths == [
        "/api/payments/12345",
        "/api/payments/67890",
    ]
    assert payments.normalization.rules == ["repeated_numeric"]
    assert payments.confidence == Confidence.MEDIUM
    assert payments.knowledge_status == KnowledgeStatus.INFERRED
    assert payments.observed_by == ["ACCOUNT_A"]

    assert ("GET", "/api/reports/2024") in by_path
    assert ("GET", "/api/reports/{reportId}") not in by_path

    transaction = by_path[("GET", "/api/transactions/{transactionId}")]
    assert transaction.normalization.rules == ["uuid"]
    assert transaction.sources == ["OBS-000004"]

    login = by_path[("POST", "/api/login")]
    assert login.state_change is True
    assert login.financial_impact == "unknown"


def test_inventory_rebuild_preserves_endpoint_ids(
    tmp_path: Path, sample_har: tuple[Path, dict[str, Any]]
) -> None:
    har_path, _ = sample_har
    workspace = create_workspace("demo", tmp_path / "workspaces")
    ingest_har(har_path, workspace)

    build_inventory(workspace)
    first = EndpointStore.model_validate(load_yaml(workspace.endpoints))
    build_inventory(workspace)
    second = EndpointStore.model_validate(load_yaml(workspace.endpoints))

    assert {(item.method, item.path): item.id for item in first.endpoints} == {
        (item.method, item.path): item.id for item in second.endpoints
    }
