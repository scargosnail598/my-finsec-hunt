"""Local Web UI integration, write-boundary, and sanitization tests."""

import asyncio
from pathlib import Path
from typing import Any

import httpx
import pytest
from starlette.applications import Starlette

from finsec.auth.store import SecretStore
from finsec.config.workspace import WorkspacePaths, create_workspace
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


def _post_json(
    app: Starlette,
    path: str,
    document: dict[str, Any],
    *,
    local_write: bool = True,
    destructive: bool = False,
) -> httpx.Response:
    async def request() -> httpx.Response:
        transport = httpx.ASGITransport(app=app)
        headers = {"X-Finsec-UI": "1"} if local_write else {}
        if destructive:
            headers["X-Finsec-Destructive"] = "workspace-delete"
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            return await client.post(path, json=document, headers=headers)

    return asyncio.run(request())


def _post_bytes(
    app: Starlette,
    path: str,
    content: bytes,
    *,
    reviewed: bool = True,
) -> httpx.Response:
    async def request() -> httpx.Response:
        transport = httpx.ASGITransport(app=app)
        headers = {
            "Content-Type": "application/octet-stream",
            "X-Finsec-UI": "1",
            "X-Finsec-Reviewed": "true" if reviewed else "false",
        }
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            return await client.post(path, content=content, headers=headers)

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
    assert "LOCAL SAFE MODE" in index.text
    assert "Ingest HARs" in index.text
    assert 'data-view="authentication"' in index.text
    app_script = _get(app, "/assets/app.js")
    assert "data-rerun-workflow" in app_script.text
    assert "data-review-deletion" in app_script.text
    assert 'data-theme-choice="dark"' in index.text
    assert '<script src="/assets/theme.js"></script>' in index.text
    assert index.headers["cache-control"] == "no-store"
    assert "default-src 'self'" in index.headers["content-security-policy"]

    stylesheet = _get(app, "/assets/app.css")
    assert stylesheet.status_code == 200
    assert "--signal: #e85d2a" in stylesheet.text
    assert ':root[data-theme="dark"]' in stylesheet.text

    theme_script = _get(app, "/assets/theme.js")
    assert theme_script.status_code == 200
    assert "window.localStorage.getItem(storageKey)" in theme_script.text

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


def test_web_authentication_preflight_is_redacted_and_local(tmp_path: Path) -> None:
    workspace = _configured_workspace(tmp_path)
    target = load_yaml(workspace / "target.yaml")
    authentication = target["accounts"][0]["authentication"]
    authentication["profile_ref"] = "account-a-profile"
    authentication["components"][0]["credential_ref"] = "account-a-authorization"
    write_yaml(workspace / "target.yaml", target)
    SecretStore(WorkspacePaths(workspace)).put(
        "account-a-authorization",
        "ACCOUNT_A",
        "header",
        "DO_NOT_RETURN_THIS_SECRET",
    )
    app = create_app(selected_workspace=workspace)

    response = _get(app, "/api/workspaces/web-demo/authentication")
    assert response.status_code == 200
    payload = response.json()
    assert payload["network_requests_sent"] == 0
    assert payload["browser_collects_credentials"] is False
    assert payload["storage"] == {
        "backend": "permission_restricted_file",
        "permissions": "0600",
    }
    actor = payload["actors"][0]
    assert actor["id"] == "ACCOUNT_A"
    assert actor["auth_type"] == "bearer"
    assert actor["preflight"]["status"] == "READY"
    assert actor["preflight"]["credential_available"] is True
    assert actor["preflight"]["result"] == "READY_FOR_EXECUTION"
    assert "DO_NOT_RETURN_THIS_SECRET" not in response.text
    assert "account-a-authorization" not in response.text
    assert "account-a-profile" not in response.text


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
            capture_root=None,
            host="0.0.0.0",
            port=8765,
        )


def test_web_setup_creates_default_deny_workspace_and_capture_layout(tmp_path: Path) -> None:
    workspace_root = tmp_path / "workspaces"
    capture_root = tmp_path / "captures"
    app = create_app(workspace_root=workspace_root, capture_root=capture_root)
    request = {
        "project_name": "Web Setup Demo",
        "slug": "web-setup-demo",
        "hosts": ["example.test", "api.example.test"],
        "accounts": [
            {
                "label": "ACCOUNT_A",
                "role": "customer",
                "authenticated": True,
                "verification_level": "unknown",
                "channel": "web",
            },
            {
                "label": "ACCOUNT_B",
                "role": "customer",
                "authenticated": True,
                "verification_level": "unknown",
                "channel": "mobile",
            },
        ],
        "production": True,
        "base_url": "https://api.example.test",
    }

    missing_guard = _post_json(app, "/api/setup", request, local_write=False)
    assert missing_guard.status_code == 400
    assert not (workspace_root / "web-setup-demo").exists()

    response = _post_json(app, "/api/setup", request)
    assert response.status_code == 201, response.text
    workspace = workspace_root / "web-setup-demo"
    target = load_yaml(workspace / "target.yaml")
    assert target["scope"]["hosts"] == ["example.test", "api.example.test"]
    assert target["testing"]["active_execution_enabled"] is False
    assert target["testing"]["human_approval_required"] is True
    assert target["testing"]["destructive_testing"] is False
    assert target["restrictions"]["real_user_testing"] is False
    assert (capture_root / "web-setup-demo/incoming").is_dir()
    assert load_yaml(capture_root / "web-setup-demo/workflow.yaml") == {
        "version": 1,
        "captures": [],
    }

    listed = _get(app, "/api/workspaces")
    assert [item["key"] for item in listed.json()["workspaces"]] == ["web-setup-demo"]


def test_web_workspace_delete_preserves_external_project_data(tmp_path: Path) -> None:
    workspace_root = tmp_path / "workspaces"
    capture_root = tmp_path / "captures"
    app = create_app(workspace_root=workspace_root, capture_root=capture_root)
    setup = _post_json(
        app,
        "/api/setup",
        {
            "project_name": "Delete Demo",
            "slug": "delete-demo",
            "hosts": ["api.example.test"],
            "accounts": [
                {
                    "label": "ACCOUNT_A",
                    "role": "customer",
                    "authenticated": True,
                    "verification_level": "unknown",
                    "channel": "web",
                }
            ],
            "production": True,
            "base_url": "https://api.example.test",
        },
    )
    assert setup.status_code == 201, setup.text
    workspace = workspace_root / "delete-demo"
    secret_store = SecretStore(WorkspacePaths(workspace))
    secret_store.put("delete-demo-secret", "ACCOUNT_A", "header", "PRESERVE_ME")

    preview = _get(app, "/api/workspaces/delete-demo/deletion-preview?mode=delete")
    assert preview.status_code == 200
    assert preview.json()["expected_confirmation"] == "delete-demo"
    assert preview.json()["preserves_related_data"] is True
    assert preview.json()["targets"]["credential_store"] is None
    assert preview.json()["targets"]["capture_directory"] is None

    missing_guard = _post_json(
        app,
        "/api/workspaces/delete-demo/delete",
        {"mode": "delete", "confirmation": "delete-demo", "acknowledged": True},
    )
    assert missing_guard.status_code == 400
    assert workspace.is_dir()

    missing_acknowledgement = _post_json(
        app,
        "/api/workspaces/delete-demo/delete",
        {"mode": "delete", "confirmation": "delete-demo"},
        destructive=True,
    )
    assert missing_acknowledgement.status_code == 422
    assert workspace.is_dir()

    wrong_confirmation = _post_json(
        app,
        "/api/workspaces/delete-demo/delete",
        {"mode": "delete", "confirmation": "wrong", "acknowledged": True},
        destructive=True,
    )
    assert wrong_confirmation.status_code == 400
    assert workspace.is_dir()

    deleted = _post_json(
        app,
        "/api/workspaces/delete-demo/delete",
        {"mode": "delete", "confirmation": "delete-demo", "acknowledged": True},
        destructive=True,
    )
    assert deleted.status_code == 200, deleted.text
    assert deleted.json()["mode"] == "delete"
    assert not workspace.exists()
    assert (capture_root / "delete-demo").is_dir()
    assert secret_store.path.is_file()
    assert _get(app, "/api/workspaces").json()["workspaces"] == []


def test_web_workspace_purge_removes_validated_related_project_data(tmp_path: Path) -> None:
    workspace_root = tmp_path / "workspaces"
    capture_root = tmp_path / "custom-captures"
    app = create_app(workspace_root=workspace_root, capture_root=capture_root)
    setup = _post_json(
        app,
        "/api/setup",
        {
            "project_name": "Purge Demo",
            "slug": "purge-demo",
            "hosts": ["api.example.test"],
            "accounts": [
                {
                    "label": "ACCOUNT_A",
                    "role": "customer",
                    "authenticated": True,
                    "verification_level": "unknown",
                    "channel": "web",
                }
            ],
            "production": True,
            "base_url": "https://api.example.test",
        },
    )
    assert setup.status_code == 201, setup.text
    workspace = workspace_root / "purge-demo"
    secret_store = SecretStore(WorkspacePaths(workspace))
    secret_store.put("purge-demo-secret", "ACCOUNT_A", "header", "REMOVE_ME")

    preview = _get(app, "/api/workspaces/purge-demo/deletion-preview?mode=purge")
    assert preview.status_code == 200
    payload = preview.json()
    assert payload["expected_confirmation"] == "PURGE purge-demo"
    assert payload["targets"]["credential_store"]["present"] is True
    assert payload["targets"]["capture_directory"] == {
        "path": str((capture_root / "purge-demo").resolve()),
        "present": True,
    }

    purged = _post_json(
        app,
        "/api/workspaces/purge-demo/delete",
        {
            "mode": "purge",
            "confirmation": "PURGE purge-demo",
            "acknowledged": True,
        },
        destructive=True,
    )
    assert purged.status_code == 200, purged.text
    assert purged.json()["credential_files_removed"] == 1
    assert purged.json()["capture_removed"] is True
    assert not workspace.exists()
    assert not (capture_root / "purge-demo").exists()
    assert not secret_store.path.exists()


def test_web_ingest_uploads_assigns_and_runs_passive_pipeline(
    tmp_path: Path,
    sample_har: tuple[Path, dict[str, Any]],
) -> None:
    workspace_root = tmp_path / "workspaces"
    capture_root = tmp_path / "captures"
    app = create_app(workspace_root=workspace_root, capture_root=capture_root)
    setup = _post_json(
        app,
        "/api/setup",
        {
            "project_name": "Web Ingest Demo",
            "slug": "web-ingest-demo",
            "hosts": ["api.example.test"],
            "accounts": [
                {
                    "label": "ACCOUNT_A",
                    "role": "customer",
                    "authenticated": True,
                    "verification_level": "unknown",
                    "channel": "web",
                },
                {
                    "label": "ACCOUNT_B",
                    "role": "customer",
                    "authenticated": True,
                    "verification_level": "unknown",
                    "channel": "mobile",
                },
            ],
            "production": True,
            "base_url": "https://api.example.test",
        },
    )
    assert setup.status_code == 201, setup.text
    source, _ = sample_har
    raw_har = source.read_bytes()

    unreviewed = _post_bytes(
        app,
        "/api/workspaces/web-ingest-demo/ingest/upload?filename=account-a.har",
        raw_har,
        reviewed=False,
    )
    assert unreviewed.status_code == 400
    assert not (capture_root / "web-ingest-demo/incoming/account-a.har").exists()

    uploaded = _post_bytes(
        app,
        "/api/workspaces/web-ingest-demo/ingest/upload?filename=account-a.har",
        raw_har,
    )
    assert uploaded.status_code == 201, uploaded.text
    assert uploaded.json()["size"] == len(raw_har)
    assert raw_har.decode() not in uploaded.text

    ingest_state = _get(app, "/api/workspaces/web-ingest-demo/ingest")
    assert ingest_state.status_code == 200
    assert ingest_state.json()["files"] == [
        {
            "file": "account-a.har",
            "size": len(raw_har),
            "updated_at": ingest_state.json()["files"][0]["updated_at"],
            "actor": None,
            "channel": None,
            "enabled": True,
            "assigned": False,
        }
    ]

    run = _post_json(
        app,
        "/api/workspaces/web-ingest-demo/ingest/run",
        {
            "assignments": [
                {
                    "file": "account-a.har",
                    "actor": "ACCOUNT_A",
                    "channel": "WEB",
                    "enabled": True,
                }
            ],
            "run_analysis": True,
            "reviewed": True,
        },
    )
    assert run.status_code == 200, run.text
    result = run.json()
    assert result["network_requests_sent"] == 0
    assert result["ingested"][0]["imported"] == 5
    assert result["analysis"]["observations"] == 5
    assert result["analysis"]["endpoints"] == 4
    assert result["analysis"]["active_hypotheses"] >= 1
    assert result["analysis"]["raw_active_hypotheses"] >= result["analysis"]["active_hypotheses"]
    assert result["analysis"]["raw_research_tasks"] >= result["analysis"]["research_tasks"]
    assert load_yaml(capture_root / "web-ingest-demo/workflow.yaml")["captures"] == [
        {"file": "account-a.har", "actor": "ACCOUNT_A", "channel": "WEB", "enabled": True}
    ]

    rerun = _post_json(
        app,
        "/api/workspaces/web-ingest-demo/ingest/run",
        {
            "assignments": [
                {
                    "file": "account-a.har",
                    "actor": "ACCOUNT_A",
                    "channel": "WEB",
                    "enabled": True,
                }
            ],
            "run_analysis": True,
            "reviewed": True,
        },
    )
    assert rerun.status_code == 200, rerun.text
    assert rerun.json()["network_requests_sent"] == 0
    assert rerun.json()["ingested"][0]["imported"] == 0
    assert rerun.json()["ingested"][0]["skipped"] == 5
    assert rerun.json()["analysis"]["endpoints"] == 4

    target = load_yaml(workspace_root / "web-ingest-demo/target.yaml")
    assert target["accounts"][0]["authentication"]["status"] == "MISSING"
    overview = _get(app, "/api/workspaces/web-ingest-demo/overview")
    assert overview.json()["counts"]["observations"] == 5
    assert overview.json()["counts"]["endpoints"] == 4
