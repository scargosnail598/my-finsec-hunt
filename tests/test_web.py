"""Read-only Web UI integration and sanitization tests."""

import asyncio
from pathlib import Path
from typing import Any

import httpx
import pytest
from starlette.applications import Starlette

from finsec.config.workspace import create_workspace
from finsec.errors import FinsecError, WorkspaceError
from finsec.utils.yaml_store import load_yaml, write_yaml
from finsec.web.app import create_app
from finsec.web.server import run_server
from finsec.web.service import WorkspaceCatalog


def _get(app: Starlette, path: str) -> httpx.Response:
    async def request() -> httpx.Response:
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            return await client.get(path)

    return asyncio.run(request())


def _configured_workspace(tmp_path: Path) -> Path:
    paths = create_workspace("web-demo", tmp_path / "workspaces")
    target = load_yaml(paths.target)
    target["scope"]["hosts"] = ["api.example.test"]
    target["accounts"] = [
        {
            "id": "ACCOUNT_A",
            "ownership": "researcher",
            "role": "customer",
            "authentication": {
                "auth_type": "bearer",
                "profile_ref": "private/profile/account-a",
                "components": [
                    {
                        "name": "Authorization",
                        "credential_ref": "private/credential/account-a",
                        "purpose": "access",
                    }
                ],
                "source": {"type": "manual"},
                "status": "READY",
                "legacy_environment": {"Authorization": "ACCOUNT_A_TOKEN"},
            },
        }
    ]
    write_yaml(paths.target, target)
    return paths.root


def _add_hypothesis_and_plan(workspace: Path) -> None:
    hypothesis: dict[str, Any] = {
        "id": "HYP-001",
        "key": "test:web-hypothesis",
        "title": "Check the controlled account boundary",
        "kind": "SECURITY_HYPOTHESIS",
        "disposition": "ACTIVE",
        "category": "authorization",
        "component": "Account / EP-001",
        "source": {"endpoints": [], "invariants": [], "observations": []},
        "invariant": [],
        "observations": [],
        "mutation_dimensions": ["OBJECT"],
        "required_state": [],
        "attacker_capability": [],
        "evidence_status": "INFERRED",
        "hypothesis": "A controlled actor may cross an account ownership boundary.",
        "reasoning": "A concrete object identifier is client controlled.",
        "preconditions": ["Both accounts belong to the researcher."],
        "expected_secure_behavior": "The boundary is enforced.",
        "possible_vulnerable_behavior": "The other controlled account object is returned.",
        "potential_impact": {},
        "evidence_to_collect": ["Owner and negative-control responses."],
        "scores": {
            "impact": 3,
            "likelihood": 3,
            "confidence": 3,
            "testability": 3,
            "total": 12,
        },
        "priority": "P2",
    }
    write_yaml(workspace / "hypotheses/backlog.yaml", {"version": 1, "hypotheses": [hypothesis]})
    plan: dict[str, Any] = {
        "id": "TEST-001",
        "key": "plan:HYP-001",
        "hypothesis_id": "HYP-001",
        "purpose": "Review one bounded controlled-account comparison.",
        "risk": {
            "destructive": False,
            "financial": False,
            "affects_external_user": False,
            "concurrency": False,
            "request_budget": 1,
            "decision": "REQUIRES_HUMAN_APPROVAL",
        },
        "accounts": {"object_owner": "ACCOUNT_A", "actor": "ACCOUNT_B"},
        "preconditions": [],
        "setup": [],
        "actions": [],
        "secure_assertions": [],
        "interesting_behavior": [],
        "evidence_to_capture": [],
        "stop_conditions": [],
        "cleanup": [],
        "requests": [
            {
                "id": "REQ-001",
                "role": "BASELINE",
                "method": "GET",
                "scheme": "https",
                "host": "api.example.test",
                "path": "/api/accounts/PRIVATE_PATH_VALUE",
                "query_parameters": {"account": ["PRIVATE_QUERY_VALUE"]},
                "headers": {"X-Research-Value": "PRIVATE_HEADER_VALUE"},
                "runtime_secrets": [
                    {
                        "header": "Authorization",
                        "source": "environment",
                        "variable": "PRIVATE_ACCOUNT_A_TOKEN",
                        "actor": "ACCOUNT_A",
                    }
                ],
                "mutations": [
                    {
                        "dimension": "OBJECT",
                        "location": "path",
                        "parameter": "accountId",
                        "from_value": "PRIVATE_SOURCE_VALUE",
                        "to_value": "PRIVATE_TARGET_VALUE",
                    }
                ],
                "actor": "ACCOUNT_A",
            }
        ],
        "authentication": [
            {
                "actor": "ACCOUNT_A",
                "credential_profile_ref": "private/profile/account-a",
            }
        ],
        "status": "READY_FOR_REVIEW",
    }
    write_yaml(workspace / "tests/plans/plans.yaml", {"version": 1, "plans": [plan]})


def test_web_ui_serves_bundled_assets_and_overview(tmp_path: Path) -> None:
    workspace = _configured_workspace(tmp_path)
    app = create_app(workspace_root=workspace.parent)

    index = _get(app, "/")
    assert index.status_code == 200
    assert "Research Cockpit" in index.text
    assert "READ-ONLY UI" in index.text
    assert index.headers["cache-control"] == "no-store"
    assert "default-src 'self'" in index.headers["content-security-policy"]

    stylesheet = _get(app, "/assets/app.css")
    assert stylesheet.status_code == 200
    assert "--signal: #e85d2a" in stylesheet.text

    listed = _get(app, "/api/workspaces")
    assert listed.status_code == 200
    assert listed.json()["workspaces"][0]["key"] == "web-demo"

    overview = _get(app, "/api/workspaces/web-demo/overview")
    assert overview.status_code == 200
    payload = overview.json()
    assert payload["workspace"]["name"] == "web-demo"
    assert payload["scope"]["hosts"] == ["api.example.test"]
    assert payload["accounts"][0]["authentication"]["status"] == "READY"
    assert "profile_ref" not in payload["accounts"][0]["authentication"]
    assert "private/profile/account-a" not in overview.text
    assert "private/credential/account-a" not in overview.text
    assert "ACCOUNT_A_TOKEN" not in overview.text


def test_hypothesis_detail_replaces_runtime_secret_references(tmp_path: Path) -> None:
    workspace = _configured_workspace(tmp_path)
    _add_hypothesis_and_plan(workspace)
    app = create_app(selected_workspace=workspace)

    response = _get(app, "/api/workspaces/web-demo/hypotheses/HYP-001")
    assert response.status_code == 200
    payload = response.json()
    assert payload["hypothesis"]["id"] == "HYP-001"
    assert payload["plan"]["authentication"] == [
        {"actor": "ACCOUNT_A", "required_status": "READY", "configured": True}
    ]
    runtime_secret = payload["plan"]["requests"][0]["runtime_secrets"][0]
    assert runtime_secret == {
        "header": "Authorization",
        "actor": "ACCOUNT_A",
        "configured": True,
    }
    assert "PRIVATE_ACCOUNT_A_TOKEN" not in response.text
    assert "private/profile/account-a" not in response.text
    assert "PRIVATE_PATH_VALUE" not in response.text
    assert "PRIVATE_QUERY_VALUE" not in response.text
    assert "PRIVATE_HEADER_VALUE" not in response.text
    assert "PRIVATE_SOURCE_VALUE" not in response.text
    assert "PRIVATE_TARGET_VALUE" not in response.text


def test_workspace_catalog_and_server_reject_unsafe_paths_and_binds(tmp_path: Path) -> None:
    workspace = _configured_workspace(tmp_path)
    catalog = WorkspaceCatalog(workspace.parent)

    with pytest.raises(WorkspaceError, match="Invalid workspace key"):
        catalog.resolve("../web-demo")

    with pytest.raises(FinsecError, match="loopback"):
        run_server(
            workspace_root=workspace.parent,
            workspace=workspace,
            host="0.0.0.0",
            port=8765,
        )
