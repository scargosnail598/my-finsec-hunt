"""Shared synthetic HAR fixtures containing no real target data."""

import json
from pathlib import Path
from typing import Any

import pytest

from finsec.config.workspace import WorkspacePaths, create_workspace
from finsec.evidence.manager import add_evidence, ensure_evidence
from finsec.hypotheses.generator import generate_hypotheses
from finsec.ingest.har import ingest_har
from finsec.modeling.generator import generate_model
from finsec.modeling.invariants import generate_invariants
from finsec.normalization.inventory import build_inventory
from finsec.testing.planner import generate_plan
from finsec.utils.yaml_store import load_yaml, write_yaml


@pytest.fixture
def sample_har(tmp_path: Path) -> tuple[Path, dict[str, Any]]:
    """Create traffic covering redaction and conservative normalization."""

    document: dict[str, Any] = {
        "log": {
            "version": "1.2",
            "creator": {"name": "pytest", "version": "1"},
            "entries": [
                {
                    "startedDateTime": "2026-01-02T10:00:00Z",
                    "request": {
                        "method": "GET",
                        "url": (
                            "https://api.example.test/api/payments/12345"
                            "?include=receipt&access_token=QUERY_SECRET"
                        ),
                        "headers": [
                            {"name": "Authorization", "value": "Bearer BEARER_SECRET"},
                            {"name": "Cookie", "value": "session=COOKIE_SECRET"},
                        ],
                        "queryString": [
                            {"name": "include", "value": "receipt"},
                            {"name": "access_token", "value": "QUERY_SECRET"},
                        ],
                    },
                    "response": {
                        "status": 200,
                        "headers": [
                            {"name": "Content-Type", "value": "application/json"},
                            {"name": "Set-Cookie", "value": "session=RESPONSE_COOKIE_SECRET"},
                        ],
                        "content": {
                            "mimeType": "application/json",
                            "text": '{"id":12345,"status":"paid","token":"BODY_SECRET"}',
                        },
                    },
                },
                {
                    "startedDateTime": "2026-01-02T10:01:00Z",
                    "request": {
                        "method": "GET",
                        "url": "https://api.example.test/api/payments/67890?include=receipt",
                        "headers": [{"name": "Authorization", "value": "Bearer SECOND_SECRET"}],
                        "queryString": [{"name": "include", "value": "receipt"}],
                    },
                    "response": {
                        "status": 200,
                        "headers": [{"name": "Content-Type", "value": "application/json"}],
                        "content": {
                            "mimeType": "application/json",
                            "text": '{"id":67890,"status":"pending"}',
                        },
                    },
                },
                {
                    "startedDateTime": "2026-01-02T10:02:00Z",
                    "request": {
                        "method": "GET",
                        "url": "https://api.example.test/api/reports/2024",
                        "headers": [],
                    },
                    "response": {
                        "status": 200,
                        "headers": [{"name": "Content-Type", "value": "application/json"}],
                        "content": {"mimeType": "application/json", "text": '{"year":2024}'},
                    },
                },
                {
                    "startedDateTime": "2026-01-02T10:03:00Z",
                    "request": {
                        "method": "GET",
                        "url": (
                            "https://api.example.test/api/transactions/"
                            "550e8400-e29b-41d4-a716-446655440000"
                        ),
                        "headers": [],
                    },
                    "response": {
                        "status": 404,
                        "headers": [{"name": "Content-Type", "value": "application/json"}],
                        "content": {"mimeType": "application/json", "text": '{"error":"missing"}'},
                    },
                },
                {
                    "startedDateTime": "2026-01-02T10:04:00Z",
                    "request": {
                        "method": "POST",
                        "url": "https://api.example.test/api/login",
                        "headers": [{"name": "Content-Type", "value": "application/json"}],
                        "postData": {
                            "mimeType": "application/json",
                            "text": (
                                '{"email":"researcher@example.test",'
                                '"password":"PASSWORD_SECRET","otp":"123456"}'
                            ),
                        },
                    },
                    "response": {
                        "status": 200,
                        "headers": [{"name": "Content-Type", "value": "application/json"}],
                        "content": {
                            "mimeType": "application/json",
                            "text": '{"access_token":"LOGIN_TOKEN_SECRET","user":{"id":1}}',
                        },
                    },
                },
            ],
        }
    }
    path = tmp_path / "traffic.har"
    path.write_text(json.dumps(document), encoding="utf-8")
    return path, document


@pytest.fixture
def phase3_workspace(tmp_path: Path, sample_har: tuple[Path, dict[str, Any]]) -> WorkspacePaths:
    """Build a scoped two-account workspace through Phase 2."""

    har_path, _ = sample_har
    workspace = create_workspace("demo", tmp_path / "workspaces")
    target = load_yaml(workspace.target)
    target["scope"]["hosts"] = ["api.example.test"]
    target["accounts"] = [
        {"id": "ACCOUNT_A", "ownership": "researcher"},
        {"id": "ACCOUNT_B", "ownership": "researcher"},
    ]
    write_yaml(workspace.target, target)
    ingest_har(har_path, workspace, actor="ACCOUNT_A", channel="WEB")
    build_inventory(workspace)
    generate_model(workspace)
    generate_invariants(workspace)
    return workspace


@pytest.fixture
def phase4_workspace(phase3_workspace: WorkspacePaths, tmp_path: Path) -> WorkspacePaths:
    """Build a Phase 3 hypothesis with an explicitly approved review-only plan."""

    generate_hypotheses(phase3_workspace)
    for index, (actor, payment_id, owner_id) in enumerate(
        [
            ("ACCOUNT_A", "PAY-A-1001", "OWNER-A-1001"),
            ("ACCOUNT_B", "PAY-B-2002", "OWNER-B-2002"),
        ],
        start=1,
    ):
        capture = tmp_path / f"controlled-payment-{index}.har"
        capture.write_text(
            json.dumps(
                {
                    "log": {
                        "version": "1.2",
                        "creator": {"name": "phase4-tests", "version": "1"},
                        "entries": [
                            {
                                "startedDateTime": f"2026-01-02T11:0{index}:00Z",
                                "request": {
                                    "method": "GET",
                                    "url": (f"https://api.example.test/api/payments/{payment_id}"),
                                    "headers": [
                                        {
                                            "name": "Authorization",
                                            "value": "Bearer SYNTHETIC_PHASE4_TOKEN",
                                        }
                                    ],
                                },
                                "response": {
                                    "status": 200,
                                    "headers": [
                                        {
                                            "name": "Content-Type",
                                            "value": "application/json",
                                        }
                                    ],
                                    "content": {
                                        "mimeType": "application/json",
                                        "text": json.dumps({"id": payment_id, "ownerId": owner_id}),
                                    },
                                },
                            }
                        ],
                    }
                }
            ),
            encoding="utf-8",
        )
        ingest_har(capture, phase3_workspace, actor=actor, channel="WEB")
    build_inventory(phase3_workspace)
    generate_model(phase3_workspace)
    generate_invariants(phase3_workspace)
    generate_hypotheses(phase3_workspace)
    generate_plan(phase3_workspace, "HYP-002")
    plans = load_yaml(phase3_workspace.test_plans)
    plans["plans"][0]["approval_status"] = "APPROVED"
    write_yaml(phase3_workspace.test_plans, plans)
    return phase3_workspace


@pytest.fixture
def complete_phase4_workspace(phase4_workspace: WorkspacePaths, tmp_path: Path) -> WorkspacePaths:
    """Add minimum redacted evidence plus a complete skeptical assessment."""

    request = tmp_path / "request.txt"
    request.write_text(
        "GET /api/payments/12345\nAuthorization: Bearer REQUEST_SECRET\n",
        encoding="utf-8",
    )
    response = tmp_path / "response.json"
    response.write_text(
        '{"id":12345,"owner":"ACCOUNT_A","token":"RESPONSE_SECRET"}',
        encoding="utf-8",
    )
    add_evidence(phase4_workspace, "HYP-002", request, "request")
    add_evidence(phase4_workspace, "HYP-002", response, "response")
    result = ensure_evidence(phase4_workspace, "HYP-002")
    metadata = load_yaml(result.root / "metadata.yaml")
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
        "report_title": ("Missing Ownership Validation Allows Cross-Account Payment Disclosure"),
        "summary": (
            "The payment lookup endpoint accepts another researcher-controlled account's "
            "payment identifier and returns the object to an authenticated non-owner."
        ),
        "root_cause": (
            "The endpoint authenticates the caller but does not verify payment ownership."
        ),
        "affected_boundary": "Payment ownership between Researcher Account A and Account B.",
        "actual_behavior": (
            "Account B received Account A's payment object. Authorization: Bearer REPORT_SECRET"
        ),
        "reproduction_steps": [
            "Create separate payment objects with Researcher Account A and Account B.",
            "Authenticate as Account B and replace only paymentId with Account A's identifier.",
            "Send one request and verify the returned object belongs to Account A.",
        ],
        "technical_impact": "Unauthorized cross-account payment data disclosure.",
        "business_impact": "Payment metadata can cross an account ownership boundary.",
        "realistic_attack_scenario": (
            "An authenticated user who learns a payment identifier can retrieve another user's "
            "payment metadata."
        ),
        "severity_rationale": (
            "Exploitation requires authentication and a payment identifier; no victim "
            "interaction is required."
        ),
        "remediation": (
            "Enforce server-side payment ownership or explicit delegation on every lookup."
        ),
    }
    write_yaml(result.root / "metadata.yaml", metadata)
    return phase4_workspace
