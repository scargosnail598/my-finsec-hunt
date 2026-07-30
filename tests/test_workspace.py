"""Workspace initialization tests."""

from pathlib import Path

import pytest

from finsec.config.models import TargetDocument
from finsec.config.workspace import create_workspace
from finsec.errors import WorkspaceError
from finsec.utils.yaml_store import load_yaml


def test_create_workspace_builds_phase_one_contract(tmp_path: Path) -> None:
    workspace = create_workspace("demo-fintech", tmp_path / "workspaces")

    required = [
        workspace.target,
        workspace.observations,
        workspace.endpoints,
        workspace.graphql,
        workspace.mobile_discoveries,
        workspace.root / "scope/program.md",
        workspace.root / "observations/raw",
        workspace.root / "observations/mobile",
        workspace.root / "model/actors.yaml",
        workspace.root / "tests/plans",
        workspace.root / "evidence",
        workspace.root / "findings",
        workspace.root / "reports",
    ]
    assert all(path.exists() for path in required)
    assert not (workspace.root / "api/parameters.yaml").exists()
    assert not (workspace.root / "api/versions.md").exists()
    assert not (workspace.root / "model/assets.yaml").exists()
    assert not (workspace.root / "observations/screenshots").exists()
    assert not (workspace.root / "tests/manual").exists()
    assert not (workspace.root / "tests/automated").exists()

    target = TargetDocument.model_validate(load_yaml(workspace.target))
    assert target.target.name == "demo-fintech"
    assert target.testing.human_approval_required is True
    assert target.testing.destructive_testing is False
    assert "password" not in workspace.target.read_text(encoding="utf-8").lower()


def test_create_workspace_never_overwrites_existing_target(tmp_path: Path) -> None:
    root = tmp_path / "workspaces"
    create_workspace("demo", root)
    with pytest.raises(WorkspaceError, match="already exists"):
        create_workspace("demo", root)


@pytest.mark.parametrize("name", ["../escape", "UPPER", "has spaces", "a" * 65])
def test_target_name_rejects_non_portable_paths(tmp_path: Path, name: str) -> None:
    with pytest.raises(WorkspaceError):
        create_workspace(name, tmp_path)
