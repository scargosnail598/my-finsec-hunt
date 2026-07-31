"""Burp Repeater export tests for approved structured plans."""

import json
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from finsec.cli import app
from finsec.config.workspace import WorkspacePaths, create_workspace
from finsec.errors import FinsecError
from finsec.execution.policy import approve_plan
from finsec.hypotheses.domain import HypothesisStore
from finsec.hypotheses.generator import generate_hypotheses
from finsec.ingest.har import ingest_har
from finsec.modeling.generator import generate_model
from finsec.modeling.invariants import generate_invariants
from finsec.normalization.inventory import build_inventory
from finsec.testing.burp import export_burp_requests, render_burp_request
from finsec.testing.domain import RuntimeSecretReference, StructuredRequest
from finsec.testing.planner import generate_plan
from finsec.utils.yaml_store import load_yaml, write_yaml

runner = CliRunner()


def _entry(object_id: int, owner_id: int, secret: str) -> dict[str, Any]:
    return {
        "startedDateTime": "2026-07-30T10:00:00Z",
        "request": {
            "method": "GET",
            "url": f"https://api.example.test/rest/basket/{object_id}",
            "headers": [
                {"name": "Accept", "value": "application/json"},
                {"name": "Authorization", "value": f"Bearer {secret}"},
            ],
        },
        "response": {
            "status": 200,
            "headers": [{"name": "Content-Type", "value": "application/json"}],
            "content": {
                "mimeType": "application/json",
                "text": json.dumps({"data": {"id": object_id, "UserId": owner_id}}),
            },
        },
    }


def _workspace(tmp_path: Path) -> tuple[WorkspacePaths, str, str]:
    workspace = create_workspace("burp-export", tmp_path / "workspaces")
    target = load_yaml(workspace.target)
    target["scope"]["hosts"] = ["api.example.test"]
    target["accounts"] = [
        {"id": "ACCOUNT_A", "ownership": "researcher"},
        {"id": "ACCOUNT_B", "ownership": "researcher"},
    ]
    target["testing"]["active_execution_enabled"] = True
    write_yaml(workspace.target, target)
    secret = "SYNTHETIC_BURP_EXPORT_SECRET"
    for index, (actor, object_id, owner_id) in enumerate(
        [("ACCOUNT_A", 6, 10), ("ACCOUNT_B", 7, 11)], start=1
    ):
        capture = tmp_path / f"actor-{index}.har"
        capture.write_text(
            json.dumps(
                {
                    "log": {
                        "version": "1.2",
                        "creator": {"name": "burp-export-tests", "version": "1"},
                        "entries": [_entry(object_id, owner_id, secret)],
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
    hypotheses = HypothesisStore.model_validate(load_yaml(workspace.hypotheses))
    hypothesis = next(
        item
        for item in hypotheses.hypotheses
        if item.category == "authorization" and item.disposition == "ACTIVE"
    )
    plan = generate_plan(workspace, hypothesis.id).plan
    assert plan.status == "READY_FOR_REVIEW"
    assert plan.execution.supported is True
    return workspace, hypothesis.id, secret


def test_burp_export_requires_checksum_bound_approval(tmp_path: Path) -> None:
    workspace, hypothesis_id, _ = _workspace(tmp_path)

    with pytest.raises(FinsecError, match="Burp export refused.*checksum-bound approval"):
        export_burp_requests(workspace, hypothesis_id)

    assert not workspace.burp_exports_for(hypothesis_id).exists()


def test_burp_export_writes_secret_free_repeater_requests_and_manifest(tmp_path: Path) -> None:
    workspace, hypothesis_id, secret = _workspace(tmp_path)
    plan = approve_plan(workspace, hypothesis_id, approved_by="pytest")

    result = export_burp_requests(workspace, hypothesis_id)

    assert result.created is True
    assert result.root.name == "export-v1"
    assert [path.name for path in result.requests] == [
        "01-baseline.http",
        "02-object-substitution.http",
    ]
    baseline = result.requests[0].read_bytes()
    mutation = result.requests[1].read_bytes()
    assert baseline.startswith(b"GET /rest/basket/7 HTTP/1.1\r\n")
    assert mutation.startswith(b"GET /rest/basket/6 HTTP/1.1\r\n")
    assert b"Host: api.example.test\r\n" in baseline
    assert b"Authorization: <FINSEC_RUNTIME_SECRET:ACCOUNT_B:AUTHORIZATION>\r\n" in baseline
    assert b"Connection: close\r\n\r\n" in baseline
    assert secret.encode() not in baseline + mutation

    manifest = load_yaml(result.manifest)
    assert manifest["format"] == "burp_repeater_raw_http"
    assert manifest["hypothesis_id"] == hypothesis_id
    assert manifest["plan_checksum"] == plan.approval.plan_checksum
    assert manifest["runtime_credentials"] == "PLACEHOLDERS_ONLY"
    assert manifest["mutation_dimensions"] == ["OBJECT"]
    assert manifest["requests"][1]["mutations"][0]["to_value"] == "6"


def test_burp_export_is_idempotent_and_preserves_edited_revision(tmp_path: Path) -> None:
    workspace, hypothesis_id, _ = _workspace(tmp_path)
    approve_plan(workspace, hypothesis_id, approved_by="pytest")
    first = export_burp_requests(workspace, hypothesis_id)

    reused = export_burp_requests(workspace, hypothesis_id)
    assert reused.created is False
    assert reused.root == first.root

    first.requests[0].write_bytes(b"\xffresearcher-edited request\n")
    second = export_burp_requests(workspace, hypothesis_id)
    assert second.created is True
    assert second.root.name == "export-v2"
    assert first.requests[0].read_bytes() == b"\xffresearcher-edited request\n"


def test_render_burp_request_encodes_query_and_removes_credentials() -> None:
    request = StructuredRequest(
        id="query-control",
        role="MUTATED",
        method="GET",
        scheme="https",
        host="api.example.test",
        path="/search",
        query_parameters={"q": ["a b", "two"], "path": ["/"]},
        headers={"Accept": "application/json"},
        runtime_secrets=[
            RuntimeSecretReference(
                header="Authorization",
                source="environment",
                variable="FINSEC_ACCOUNT_A_AUTH",
                actor="ACCOUNT_A",
            )
        ],
        remove_headers=["authorization"],
        actor="ACCOUNT_A",
    )

    rendered = render_burp_request(request)

    assert rendered.startswith("GET /search?q=a+b&q=two&path=%2F HTTP/1.1\r\n")
    assert "Authorization:" not in rendered


def test_cli_export_burp_reports_files_and_sends_no_request(tmp_path: Path) -> None:
    workspace, hypothesis_id, _ = _workspace(tmp_path)
    approve_plan(workspace, hypothesis_id, approved_by="pytest")

    result = runner.invoke(
        app,
        ["export-burp", hypothesis_id, "--workspace", str(workspace.root)],
    )

    assert result.exit_code == 0, result.output
    assert "Created 2 Burp Repeater request files" in result.output
    assert "Runtime credentials remain actor-specific placeholders" in result.output
    assert "No request was sent" in result.output
