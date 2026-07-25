"""End-to-end CLI tests for the deterministic Phase 1 through 5 workflow."""

import base64
import json
from pathlib import Path
from typing import Any

from typer.testing import CliRunner

from finsec.cli import app
from finsec.utils.yaml_store import load_yaml, write_yaml

runner = CliRunner()


def test_full_cli_flow(tmp_path: Path, sample_har: tuple[Path, dict[str, Any]]) -> None:
    har_path, _ = sample_har
    workspace_root = tmp_path / "workspaces"
    workspace = workspace_root / "demo"

    initialized = runner.invoke(
        app,
        ["init", "demo", "--workspace-root", str(workspace_root)],
    )
    assert initialized.exit_code == 0, initialized.output
    assert "Created workspace" in initialized.output

    target = load_yaml(workspace / "target.yaml")
    target["scope"]["hosts"] = ["api.example.test"]
    target["accounts"] = [
        {"id": "ACCOUNT_A", "ownership": "researcher"},
        {"id": "ACCOUNT_B", "ownership": "researcher"},
    ]
    write_yaml(workspace / "target.yaml", target)

    ingested = runner.invoke(
        app,
        [
            "ingest",
            str(har_path),
            "--workspace",
            str(workspace),
            "--actor",
            "ACCOUNT_A",
            "--channel",
            "WEB",
        ],
    )
    assert ingested.exit_code == 0, ingested.output
    assert "Imported 5" in ingested.output

    inventoried = runner.invoke(app, ["inventory", "--workspace", str(workspace)])
    assert inventoried.exit_code == 0, inventoried.output
    assert "4 endpoints" in inventoried.output

    modeled = runner.invoke(app, ["model", "--workspace", str(workspace)])
    assert modeled.exit_code == 0, modeled.output
    assert "2 actors, 3 resources, and 3 workflows" in modeled.output

    invariants = runner.invoke(app, ["invariants", "--workspace", str(workspace)])
    assert invariants.exit_code == 0, invariants.output
    assert "Generated 3 invariants" in invariants.output

    hypotheses = runner.invoke(
        app, ["hypotheses", "--workspace", str(workspace), "--priority", "P1"]
    )
    assert hypotheses.exit_code == 0, hypotheses.output
    assert "HYP-002" in hypotheses.output
    assert "Cross-account Payment" in hypotheses.output

    shown = runner.invoke(app, ["show", "HYP-002", "--workspace", str(workspace)])
    assert shown.exit_code == 0, shown.output
    assert "Mutations: ACTOR, OBJECT" in shown.output

    planned = runner.invoke(app, ["plan", "HYP-002", "--workspace", str(workspace)])
    assert planned.exit_code == 0, planned.output
    assert "READY_FOR_REVIEW" in planned.output
    assert "DO_NOT_EXECUTE" in planned.output

    request = tmp_path / "request.txt"
    request.write_text(
        "GET /api/payments/12345\nAuthorization: Bearer CLI_SECRET\n",
        encoding="utf-8",
    )
    response = tmp_path / "response.json"
    response.write_text('{"id":12345,"owner":"ACCOUNT_A"}', encoding="utf-8")
    request_added = runner.invoke(
        app,
        [
            "evidence",
            "HYP-002",
            "--workspace",
            str(workspace),
            "--add",
            str(request),
            "--kind",
            "request",
        ],
    )
    assert request_added.exit_code == 0, request_added.output
    assert "EVD-001" in request_added.output
    response_added = runner.invoke(
        app,
        [
            "evidence",
            "HYP-002",
            "--workspace",
            str(workspace),
            "--add",
            str(response),
            "--kind",
            "response",
        ],
    )
    assert response_added.exit_code == 0, response_added.output
    assert "EVD-002" in response_added.output

    plans = load_yaml(workspace / "tests/plans/plans.yaml")
    plans["plans"][0]["approval_status"] = "APPROVED"
    write_yaml(workspace / "tests/plans/plans.yaml", plans)
    metadata_path = workspace / "evidence/HYP-002/metadata.yaml"
    metadata = load_yaml(metadata_path)
    metadata["assessment"] = {
        "scope_compliant": True,
        "rules_compliant": True,
        "researcher_controlled_accounts": True,
        "ownership_or_boundary_verified": True,
        "expected_secure_behavior_observed": False,
        "unauthorized_capability_demonstrated": True,
        "actual_behavior_verified": True,
        "authoritative_result_verified": True,
        "negative_control_performed": True,
        "reproduced_clean_session": True,
        "alternative_explanations_ruled_out": True,
        "meaningful_impact_demonstrated": True,
        "realistic_prerequisites": True,
        "documented_or_intended_behavior": False,
        "client_side_only": False,
        "known_duplicate": False,
        "redaction_reviewed": True,
    }
    metadata["narrative"] = {
        "report_title": "Missing Ownership Check Allows Cross-Account Payment Disclosure",
        "summary": "Account B can retrieve Account A's payment using Account A's paymentId.",
        "root_cause": "The endpoint does not enforce payment ownership.",
        "affected_boundary": "Payment ownership between Account A and Account B.",
        "actual_behavior": "The server returns Account A's payment to Account B.",
        "reproduction_steps": [
            "Create separate researcher-owned payment objects.",
            "Authenticate as Account B and substitute Account A's paymentId.",
            "Send one request and verify the returned owner.",
        ],
        "technical_impact": "Cross-account payment data disclosure.",
        "business_impact": "Payment metadata crosses account boundaries.",
        "realistic_attack_scenario": "An authenticated user obtains another payment identifier.",
        "severity_rationale": "Authentication and a payment identifier are required.",
        "remediation": "Enforce server-side payment ownership checks.",
    }
    write_yaml(metadata_path, metadata)

    validated = runner.invoke(app, ["validate", "HYP-002", "--workspace", str(workspace)])
    assert validated.exit_code == 0, validated.output
    assert "CONFIRMED" in validated.output
    assert "Report ready: yes" in validated.output

    reported = runner.invoke(app, ["report", "HYP-002", "--workspace", str(workspace)])
    assert reported.exit_code == 0, reported.output
    assert (workspace / "reports/HYP-002-report-v1.md").is_file()

    status = runner.invoke(app, ["status", "--workspace", str(workspace)])
    assert status.exit_code == 0, status.output
    assert "Target: demo" in status.output
    assert "Observations" in status.output
    assert "Endpoints" in status.output
    assert "Resources" in status.output
    assert "Actors" in status.output
    assert "Workflows" in status.output
    assert "Invariants" in status.output
    assert "Evidence Sets" in status.output
    assert "Validations" in status.output
    assert "Reports" in status.output
    assert "TEST_PLANNED" in status.output
    assert "5" in status.output
    assert "4" in status.output


def test_phase_five_cli_passive_integrations(tmp_path: Path) -> None:
    workspace_root = tmp_path / "workspaces"
    workspace = workspace_root / "passive"
    initialized = runner.invoke(
        app,
        ["init", "passive", "--workspace-root", str(workspace_root)],
    )
    assert initialized.exit_code == 0, initialized.output

    burp_request = base64.b64encode(
        b"GET /api/v1/payments/1 HTTP/1.1\r\nHost: api.example.test\r\n\r\n"
    ).decode()
    burp = tmp_path / "burp.xml"
    burp.write_text(
        "<items><item><url>https://api.example.test/api/v1/payments/1</url>"
        "<method>GET</method>"
        f'<request base64="true">{burp_request}</request>'
        "<response>HTTP/1.1 200 OK</response></item></items>",
        encoding="utf-8",
    )
    caido = tmp_path / "caido.json"
    caido.write_text(
        json.dumps(
            [
                {
                    "request": {
                        "method": "GET",
                        "url": "https://api.example.test/api/v1/payments/2",
                    },
                    "response": {"status": 200},
                }
            ]
        ),
        encoding="utf-8",
    )
    openapi = tmp_path / "openapi.json"
    openapi.write_text(
        json.dumps(
            {
                "openapi": "3.1.0",
                "servers": [{"url": "https://api.example.test"}],
                "paths": {"/api/v1/refunds/{refundId}": {"get": {"responses": {}}}},
            }
        ),
        encoding="utf-8",
    )
    graphql = tmp_path / "schema.graphql"
    graphql.write_text("type Query { wallet(id: ID!): Wallet }", encoding="utf-8")
    mobile = tmp_path / "mobile.txt"
    mobile.write_text("https://api.example.test/graphql\nX-Client-Version", encoding="utf-8")

    commands = [
        ["ingest-burp", str(burp), "--channel", "WEB"],
        ["ingest-caido", str(caido), "--channel", "MOBILE"],
        ["ingest-openapi", str(openapi)],
        ["ingest-graphql", str(graphql), "--endpoint", "https://api.example.test/graphql"],
        ["scan-mobile", str(mobile)],
    ]
    for command in commands:
        result = runner.invoke(app, [*command, "--workspace", str(workspace)])
        assert result.exit_code == 0, result.output

    inventoried = runner.invoke(app, ["inventory", "--workspace", str(workspace)])
    assert inventoried.exit_code == 0, inventoried.output
    status = runner.invoke(app, ["status", "--workspace", str(workspace)])
    assert status.exit_code == 0, status.output
    assert "GraphQL Operations" in status.output
    assert "Mobile Discoveries" in status.output
    assert "3" in status.output
