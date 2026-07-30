"""Phase 5 passive traffic and API documentation ingestion tests."""

import base64
import json
from pathlib import Path
from typing import Any

import pytest

from finsec.config.workspace import create_workspace
from finsec.errors import FinsecError
from finsec.hypotheses.domain import HypothesisStore
from finsec.hypotheses.generator import generate_hypotheses
from finsec.ingest.openapi import ingest_openapi
from finsec.ingest.traffic import ingest_burp_xml, ingest_caido_json
from finsec.modeling.generator import generate_model
from finsec.modeling.invariants import generate_invariants
from finsec.modeling.models import EndpointStore, ObservationStore
from finsec.normalization.inventory import build_inventory
from finsec.utils.redaction import REDACTED
from finsec.utils.yaml_store import load_yaml, write_yaml


def _burp_export(path: Path) -> None:
    request = (
        "POST /api/v1/payments/abc?access_token=QUERY_SECRET HTTP/1.1\r\n"
        "Host: api.example.test\r\n"
        "Authorization: Bearer BURP_SECRET\r\n"
        "Cookie: session=COOKIE_SECRET\r\n"
        "Content-Type: application/json\r\n\r\n"
        '{"amount":1,"otp":"123456"}'
    )
    response = (
        "HTTP/1.1 201 Created\r\n"
        "Content-Type: application/json\r\n"
        "Set-Cookie: session=RESPONSE_SECRET\r\n\r\n"
        '{"id":"abc","access_token":"BODY_SECRET"}'
    )
    request_encoded = base64.b64encode(request.encode()).decode()
    response_encoded = base64.b64encode(response.encode()).decode()
    path.write_text(
        '<?xml version="1.0"?>\n'
        "<!DOCTYPE items [\n"
        "<!ELEMENT items (item*)>\n"
        "<!ELEMENT item ANY>\n"
        "]>\n"
        "<items><item>"
        "<url>https://api.example.test/api/v1/payments/abc?access_token=QUERY_SECRET</url>"
        "<host>api.example.test</host><port>443</port><protocol>https</protocol>"
        "<method>POST</method><status>201</status><mimetype>application/json</mimetype>"
        f'<request base64="true">{request_encoded}</request>'
        f'<response base64="true">{response_encoded}</response>'
        "</item></items>",
        encoding="utf-8",
    )


def test_burp_xml_import_is_redacted_evidence_linked_and_idempotent(tmp_path: Path) -> None:
    workspace = create_workspace("demo", tmp_path / "workspaces")
    source = tmp_path / "burp.xml"
    _burp_export(source)

    first = ingest_burp_xml(source, workspace, actor="ACCOUNT_A", channel="WEB")
    second = ingest_burp_xml(source, workspace, actor="ACCOUNT_A", channel="WEB")

    assert (first.imported, first.skipped, first.total) == (1, 0, 1)
    assert (second.imported, second.skipped, second.total) == (0, 1, 1)
    stored = first.redacted_capture.read_text(encoding="utf-8")
    for secret in (
        "QUERY_SECRET",
        "BURP_SECRET",
        "COOKIE_SECRET",
        "RESPONSE_SECRET",
        "BODY_SECRET",
        "123456",
    ):
        assert secret not in stored
    assert REDACTED in stored

    observations = ObservationStore.model_validate(load_yaml(workspace.observations))
    observation = observations.observations[0]
    assert observation.source == "BURP_XML"
    assert observation.source_reference.endswith("#item-0")
    assert observation.authentication.observed_type == "mixed"
    assert observation.query_parameters["access_token"] == [REDACTED]
    assert observation.request_fields == ["amount", "otp"]
    assert observation.response_fields == ["access_token", "id"]


def test_burp_xml_rejects_entity_declarations(tmp_path: Path) -> None:
    workspace = create_workspace("demo", tmp_path / "workspaces")
    source = tmp_path / "unsafe.xml"
    source.write_text(
        "<?xml version='1.0'?><!   DOCTYPE items [<!ENTITY x 'value'>]><items />",
        encoding="utf-8",
    )

    with pytest.raises(FinsecError, match="entity declarations"):
        ingest_burp_xml(source, workspace)


def test_burp_xml_rejects_external_dtd(tmp_path: Path) -> None:
    workspace = create_workspace("demo", tmp_path / "workspaces")
    source = tmp_path / "unsafe-external.xml"
    source.write_text(
        "<?xml version='1.0'?><!DOCTYPE items SYSTEM 'https://example.test/burp.dtd'>"
        "<items><item /></items>",
        encoding="utf-8",
    )

    with pytest.raises(FinsecError, match="external DTD"):
        ingest_burp_xml(source, workspace)


def test_caido_json_import_redacts_nested_data_and_preserves_fields(tmp_path: Path) -> None:
    workspace = create_workspace("demo", tmp_path / "workspaces")
    source = tmp_path / "caido.json"
    document = {
        "entries": [
            {
                "request": {
                    "method": "PATCH",
                    "url": "https://api.example.test/api/v2/wallets/w-1?api_key=CAIDO_QUERY",
                    "headers": [
                        {"name": "Authorization", "value": "Bearer CAIDO_SECRET"},
                        {"name": "Content-Type", "value": "application/json"},
                    ],
                    "body": {"nickname": "research", "password": "PASSWORD_SECRET"},
                },
                "response": {
                    "statusCode": 200,
                    "headers": {"Content-Type": "application/json"},
                    "body": {"id": "w-1", "refresh_token": "REFRESH_SECRET"},
                },
            }
        ]
    }
    source.write_text(json.dumps(document), encoding="utf-8")

    first = ingest_caido_json(source, workspace, actor="ACCOUNT_B", channel="MOBILE")
    second = ingest_caido_json(source, workspace, actor="ACCOUNT_B", channel="MOBILE")

    assert first.imported == 1
    assert second.skipped == 1
    stored = first.redacted_capture.read_text(encoding="utf-8")
    for secret in ("CAIDO_QUERY", "CAIDO_SECRET", "PASSWORD_SECRET", "REFRESH_SECRET"):
        assert secret not in stored
    observations = ObservationStore.model_validate(load_yaml(workspace.observations))
    observation = observations.observations[0]
    assert observation.source == "CAIDO_JSON"
    assert observation.actor == "ACCOUNT_B"
    assert observation.request_fields == ["nickname", "password"]
    assert observation.response_fields == ["id", "refresh_token"]


def _openapi_document() -> dict[str, Any]:
    return {
        "openapi": "3.1.0",
        "servers": [{"url": "https://api.example.test/api/v2"}],
        "security": [{"bearerAuth": []}],
        "components": {
            "securitySchemes": {
                "bearerAuth": {"type": "http", "scheme": "bearer"},
            }
        },
        "paths": {
            "/payments/{paymentId}": {
                "get": {
                    "parameters": [
                        {"name": "paymentId", "in": "path", "required": True},
                        {"name": "expand", "in": "query"},
                    ],
                    "responses": {
                        "200": {
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "id": {"type": "string"},
                                            "status": {"type": "string"},
                                        },
                                    },
                                    "example": {"access_token": "OPENAPI_EXAMPLE_SECRET"},
                                }
                            }
                        }
                    },
                },
                "post": {
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "amount": {"type": "number"},
                                        "destination": {
                                            "type": "object",
                                            "properties": {"id": {"type": "string"}},
                                        },
                                    },
                                }
                            }
                        }
                    },
                    "responses": {"204": {"description": "updated"}},
                },
            }
        },
    }


def test_openapi_import_creates_documented_observations_and_inventory(tmp_path: Path) -> None:
    workspace = create_workspace("demo", tmp_path / "workspaces")
    source = tmp_path / "openapi.json"
    source.write_text(json.dumps(_openapi_document()), encoding="utf-8")

    first = ingest_openapi(source, workspace)
    second = ingest_openapi(source, workspace)
    inventory = build_inventory(workspace)

    assert first.imported == 2
    assert second.skipped == 2
    assert inventory.endpoints == 2
    assert "OPENAPI_EXAMPLE_SECRET" not in first.redacted_capture.read_text(encoding="utf-8")
    observations = ObservationStore.model_validate(load_yaml(workspace.observations))
    assert {item.source for item in observations.observations} == {"OPENAPI"}
    assert all(
        "runtime behavior is not observed" in (item.notes or "")
        for item in observations.observations
    )

    endpoints = EndpointStore.model_validate(load_yaml(workspace.endpoints))
    by_method = {item.method: item for item in endpoints.endpoints}
    endpoint = by_method["GET"]
    assert endpoint.path == "/api/v2/payments/{paymentId}"
    assert endpoint.authentication.required is True
    assert endpoint.authentication.observed_type == "bearer"
    assert endpoint.normalization.rules == ["documented_template"]
    assert {(item.name, item.location) for item in endpoint.parameters} == {
        ("paymentId", "path"),
        ("expand", "query"),
        ("id", "response_body"),
        ("status", "response_body"),
    }
    assert all(
        item.source == "response" and not item.client_controlled
        for item in endpoint.parameters
        if item.location == "response_body"
    )
    assert by_method["POST"].sources == ["OBS-000002"]


def test_openapi_without_server_requires_explicit_base_url(tmp_path: Path) -> None:
    workspace = create_workspace("demo", tmp_path / "workspaces")
    source = tmp_path / "openapi.yaml"
    source.write_text(
        "openapi: 3.1.0\npaths:\n  /health:\n    get:\n      responses: {}\n", encoding="utf-8"
    )

    with pytest.raises(FinsecError, match="pass --base-url"):
        ingest_openapi(source, workspace)

    result = ingest_openapi(source, workspace, base_url="https://api.example.test")
    assert result.imported == 1


def test_openapi_only_evidence_does_not_create_active_security_hypotheses(
    tmp_path: Path,
) -> None:
    workspace = create_workspace("documented-only", tmp_path / "workspaces")
    target = load_yaml(workspace.target)
    target["scope"]["hosts"] = ["api.example.test"]
    target["accounts"] = [
        {"id": "ACCOUNT_A", "ownership": "researcher"},
        {"id": "ACCOUNT_B", "ownership": "researcher"},
    ]
    write_yaml(workspace.target, target)
    source = tmp_path / "openapi.json"
    source.write_text(json.dumps(_openapi_document()), encoding="utf-8")

    ingest_openapi(source, workspace)
    build_inventory(workspace)
    generate_model(workspace)
    generate_invariants(workspace)
    generate_hypotheses(workspace)

    hypotheses = HypothesisStore.model_validate(load_yaml(workspace.hypotheses)).hypotheses
    assert not any(
        item.kind == "SECURITY_HYPOTHESIS" and item.disposition == "ACTIVE" for item in hypotheses
    )
    assert any(item.kind == "RESEARCH_TASK" for item in hypotheses)
