"""Endpoint normalization and evidence-linking tests."""

import json
from pathlib import Path
from typing import Any

from finsec.config.workspace import create_workspace
from finsec.ingest.har import ingest_har
from finsec.modeling.models import Confidence, EndpointStore, KnowledgeStatus
from finsec.normalization.inventory import build_inventory
from finsec.utils.yaml_store import load_yaml, write_yaml


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
    assert login.state_change is False
    assert login.action.type == "unknown"
    assert "POST without a business action" in login.action.reasons[0]
    assert login.financial_impact == "none"


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


def test_inventory_recognizes_crapi_style_identifiers_and_local_lab_mutations(
    tmp_path: Path,
) -> None:
    workspace = create_workspace("crapi-shapes", tmp_path / "workspaces")
    target = load_yaml(workspace.target)
    target["scope"]["hosts"] = ["api.example.test"]
    target["testing"]["local_lab"] = True
    write_yaml(workspace.target, target)

    def entry(
        index: int,
        method: str,
        path: str,
        response: dict[str, Any],
        request: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        request_document: dict[str, Any] = {
            "method": method,
            "url": f"https://api.example.test{path}",
            "headers": [{"name": "Authorization", "value": "Bearer SYNTHETIC_TOKEN"}],
        }
        if request is not None:
            request_document["postData"] = {
                "mimeType": "application/json",
                "text": json.dumps(request),
            }
        return {
            "startedDateTime": f"2026-02-01T10:{index:02d}:00Z",
            "request": request_document,
            "response": {
                "status": 200,
                "headers": [{"name": "Content-Type", "value": "application/json"}],
                "content": {"mimeType": "application/json", "text": json.dumps(response)},
            },
        }

    capture = tmp_path / "crapi-shapes.har"
    capture.write_text(
        json.dumps(
            {
                "log": {
                    "version": "1.2",
                    "creator": {"name": "inventory-tests", "version": "1"},
                    "entries": [
                        entry(
                            1,
                            "GET",
                            "/api/service_requests/0P96308CFVJ2B8J9G",
                            {"id": "0P96308CFVJ2B8J9G"},
                        ),
                        entry(2, "GET", "/api/users/videos/0", {"id": 0}),
                        entry(
                            3,
                            "GET",
                            "/api/mechanic_report?report_id=12",
                            {"id": 12},
                        ),
                        entry(
                            4,
                            "POST",
                            "/api/orders",
                            {"id": 5, "status": "created"},
                            {"quantity": 1},
                        ),
                    ],
                }
            }
        ),
        encoding="utf-8",
    )
    ingest_har(capture, workspace, actor="ACCOUNT_A")

    build_inventory(workspace)
    by_path = {
        item.path: item
        for item in EndpointStore.model_validate(load_yaml(workspace.endpoints)).endpoints
    }

    service_request = by_path["/api/service_requests/{serviceRequestId}"]
    assert service_request.resource.type == "ServiceRequest"
    assert service_request.normalization.rules == ["long_opaque"]

    video = by_path["/api/users/videos/{videoId}"]
    assert video.normalization.rules == ["terminal_resource_numeric"]
    assert next(item for item in video.parameters if item.name == "videoId").semantic_type == (
        "object_identifier"
    )

    report = by_path["/api/mechanic_report"]
    report_id = next(item for item in report.parameters if item.name == "report_id")
    assert report_id.semantic_type == "object_identifier"
    assert report_id.confidence == Confidence.HIGH

    order = by_path["/api/orders"]
    assert order.resource.type == "Order"
    assert order.action.name == "create"
    assert order.action.type == "mutation"
    assert order.state_change is True
