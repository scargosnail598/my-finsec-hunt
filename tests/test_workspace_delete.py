"""Guardrails for explicit workspace deletion."""

from pathlib import Path

import pytest
from typer.testing import CliRunner

from finsec.cli import app
from finsec.config.workspace import create_workspace, resolve_workspace_deletion_target
from finsec.errors import WorkspaceError

RUNNER = CliRunner()


def test_workspace_delete_requires_exact_interactive_slug_and_preserves_captures(
    tmp_path: Path,
) -> None:
    workspace = create_workspace("demo", tmp_path / "workspaces").root
    capture = tmp_path / "captures" / "demo"
    capture.mkdir(parents=True)
    (capture / "workflow.yaml").write_text("version: 1\ncaptures: []\n", encoding="utf-8")

    result = RUNNER.invoke(
        app,
        ["workspace", "delete", "--workspace", str(workspace)],
        input="demo\n",
    )

    assert result.exit_code == 0, result.output
    assert not workspace.exists()
    assert (capture / "workflow.yaml").is_file()
    assert "Deletion is permanent" in result.output
    assert "capture directories were left untouched" in result.output


def test_workspace_delete_rejects_wrong_confirmation(tmp_path: Path) -> None:
    workspace = create_workspace("demo", tmp_path / "workspaces").root

    result = RUNNER.invoke(
        app,
        ["workspace", "delete", "--workspace", str(workspace)],
        input="wrong-workspace\n",
    )

    assert result.exit_code == 1
    assert workspace.is_dir()
    assert "nothing was deleted" in result.output


def test_workspace_delete_supports_exact_noninteractive_confirmation(tmp_path: Path) -> None:
    workspace = create_workspace("demo", tmp_path / "workspaces").root
    sibling = create_workspace("keep-me", tmp_path / "workspaces").root

    result = RUNNER.invoke(
        app,
        [
            "workspace",
            "delete",
            "--workspace",
            str(workspace),
            "--confirm",
            "demo",
        ],
    )

    assert result.exit_code == 0, result.output
    assert not workspace.exists()
    assert sibling.is_dir()


def test_workspace_delete_rejects_non_workspace_and_symbolic_link(tmp_path: Path) -> None:
    plain_directory = tmp_path / "plain"
    plain_directory.mkdir()
    workspace = create_workspace("demo", tmp_path / "workspaces").root
    link = tmp_path / "workspace-link"
    link.symlink_to(workspace, target_is_directory=True)
    parent_link = tmp_path / "workspaces-link"
    parent_link.symlink_to(tmp_path / "workspaces", target_is_directory=True)

    plain_result = RUNNER.invoke(
        app,
        ["workspace", "delete", "--workspace", str(plain_directory), "--confirm", "plain"],
    )
    link_result = RUNNER.invoke(
        app,
        ["workspace", "delete", "--workspace", str(link), "--confirm", "demo"],
    )
    parent_link_result = RUNNER.invoke(
        app,
        [
            "workspace",
            "delete",
            "--workspace",
            str(parent_link / "demo"),
            "--confirm",
            "demo",
        ],
    )

    assert plain_result.exit_code == 1
    assert "Not a FinSec Hunt workspace" in plain_result.output
    assert link_result.exit_code == 1
    assert "symbolic link" in link_result.output
    assert parent_link_result.exit_code == 1
    assert "symbolic link" in parent_link_result.output
    assert workspace.is_dir()


def test_workspace_delete_rejects_repository_and_current_directory_boundaries(
    tmp_path: Path,
) -> None:
    workspace = create_workspace("demo", tmp_path / "workspaces").root
    (workspace / ".git").mkdir()

    repository_result = RUNNER.invoke(
        app,
        ["workspace", "delete", "--workspace", str(workspace), "--confirm", "demo"],
    )

    assert repository_result.exit_code == 1
    assert ".git repository" in repository_result.output
    (workspace / ".git").rmdir()
    with pytest.raises(WorkspaceError, match="current directory"):
        resolve_workspace_deletion_target(
            workspace,
            current_directory=workspace / "scope",
        )
