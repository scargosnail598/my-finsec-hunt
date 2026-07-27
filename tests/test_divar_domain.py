"""Integration test suite for Divar domain setup, ingestion, and validation."""

import json
from pathlib import Path

from typer.testing import CliRunner

from finsec.config.models import TargetDocument
from finsec.config.scope import host_is_covered, hosts_are_covered
from finsec.ingest.har import ingest_har
from finsec.modeling.generator import generate_model
from finsec.normalization.inventory import build_inventory
from finsec.setup import AccountInput, build_setup_config, create_setup_workspace
from finsec.utils.yaml_store import load_yaml

RUNNER = CliRunner()


def _create_sample_divar_har(path: Path) -> Path:
    har_content = {
        "log": {
            "version": "1.2",
            "creator": {"name": "TestHar", "version": "1.0"},
            "entries": [
                {
                    "startedDateTime": "2026-07-27T10:00:00Z",
                    "request": {
                        "method": "GET",
                        "url": "https://api.divar.ir/v8/posts/gZ123456",
                        "headers": [
                            {"name": "Host", "value": "api.divar.ir"},
                            {"name": "Authorization", "value": "Bearer SECRET_JWT_TOKEN_HERE"},
                        ],
                    },
                    "response": {
                        "status": 200,
                        "statusText": "OK",
                        "headers": [{"name": "Content-Type", "value": "application/json"}],
                        "content": {
                            "mimeType": "application/json",
                            "text": json.dumps({"title": "Sample Post", "price": 1000000}),
                        },
                    },
                },
                {
                    "startedDateTime": "2026-07-27T10:05:00Z",
                    "request": {
                        "method": "POST",
                        "url": "https://api.divar.ir/v1/chat/conversation",
                        "headers": [
                            {"name": "Host", "value": "api.divar.ir"},
                            {"name": "Cookie", "value": "session=SENSITIVE_COOKIE_VALUE"},
                        ],
                        "postData": {
                            "mimeType": "application/json",
                            "text": json.dumps(
                                {"post_token": "gZ123456", "message": "Is this available?"}
                            ),
                        },
                    },
                    "response": {
                        "status": 201,
                        "statusText": "Created",
                        "headers": [{"name": "Content-Type", "value": "application/json"}],
                        "content": {
                            "mimeType": "application/json",
                            "text": json.dumps({"status": "sent", "conversation_id": "c-999"}),
                        },
                    },
                },
            ],
        }
    }
    path.write_text(json.dumps(har_content), encoding="utf-8")
    return path


def test_divar_scope_matching() -> None:
    scope_patterns = ["divar.ir", "api.divar.ir", "*.services.divar.ir"]

    assert host_is_covered("divar.ir", scope_patterns)
    assert host_is_covered("api.divar.ir", scope_patterns)
    assert host_is_covered("chat.services.divar.ir", scope_patterns)
    assert host_is_covered("pay.services.divar.ir", scope_patterns)

    assert not host_is_covered("services.divar.ir", scope_patterns)  # Wildcard requires subdomain
    assert not host_is_covered("divar.ir.attacker.com", scope_patterns)
    assert not host_is_covered("example.com", scope_patterns)

    assert hosts_are_covered({"divar.ir", "api.divar.ir", "auth.services.divar.ir"}, scope_patterns)
    assert not hosts_are_covered({"divar.ir", "untrusted.external.com"}, scope_patterns)


def test_divar_workspace_setup_and_target_yaml(tmp_path: Path) -> None:
    workspace_root = tmp_path / "workspaces"
    capture_root = tmp_path / "captures"

    config = build_setup_config(
        project_name="Divar Target",
        slug="divar",
        hosts=["divar.ir", "api.divar.ir", "*.services.divar.ir"],
        accounts=[AccountInput("ACCOUNT_A"), AccountInput("ACCOUNT_B")],
        production=True,
    )

    created = create_setup_workspace(config, workspace_root, capture_root)
    assert created.workspace.root.is_dir()
    assert created.workspace.target.is_file()

    target_doc = TargetDocument.model_validate(load_yaml(created.workspace.target))
    assert target_doc.target.slug == "divar"
    assert target_doc.scope.hosts == ["divar.ir", "api.divar.ir", "*.services.divar.ir"]
    assert len(target_doc.accounts) == 2
    assert target_doc.testing.human_approval_required is True


def test_divar_har_ingestion_and_redaction(tmp_path: Path) -> None:
    workspace_root = tmp_path / "workspaces"
    capture_root = tmp_path / "captures"

    config = build_setup_config(
        project_name="Divar Target",
        slug="divar",
        hosts=["divar.ir", "api.divar.ir"],
        accounts=[AccountInput("ACCOUNT_A"), AccountInput("ACCOUNT_B")],
        production=True,
    )
    created = create_setup_workspace(config, workspace_root, capture_root)

    har_path = _create_sample_divar_har(tmp_path / "sample_divar.har")

    result = ingest_har(
        har_path=har_path,
        workspace=created.workspace,
        actor="ACCOUNT_A",
        channel="MOBILE",
    )

    assert result.imported == 2
    assert created.workspace.observations.is_file()

    obs_content = created.workspace.observations.read_text(encoding="utf-8")
    assert "SECRET_JWT_TOKEN_HERE" not in obs_content
    assert "SENSITIVE_COOKIE_VALUE" not in obs_content
    assert "ACCOUNT_A" in obs_content


def test_divar_pipeline_end_to_end(tmp_path: Path) -> None:
    workspace_root = tmp_path / "workspaces"
    capture_root = tmp_path / "captures"

    config = build_setup_config(
        project_name="Divar Target",
        slug="divar",
        hosts=["divar.ir", "api.divar.ir"],
        accounts=[AccountInput("ACCOUNT_A"), AccountInput("ACCOUNT_B")],
        production=True,
    )
    created = create_setup_workspace(config, workspace_root, capture_root)
    har_path = _create_sample_divar_har(tmp_path / "sample_divar.har")

    ingest_har(
        har_path=har_path,
        workspace=created.workspace,
        actor="ACCOUNT_A",
        channel="WEB",
    )

    build_inventory(created.workspace)
    generate_model(created.workspace)

    assert created.workspace.endpoints.is_file()

    endpoints_data = load_yaml(created.workspace.endpoints)
    assert "endpoints" in endpoints_data
    assert len(endpoints_data["endpoints"]) > 0
