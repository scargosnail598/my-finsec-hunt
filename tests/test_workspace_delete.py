"""Guardrails for explicit workspace deletion."""

from pathlib import Path

import pytest
from typer.testing import CliRunner

from finsec.auth.store import SecretStore
from finsec.cli import app
from finsec.config.workspace import (
    WorkspacePaths,
    create_workspace,
    resolve_workspace_deletion_target,
)
from finsec.errors import WorkspaceError

RUNNER = CliRunner()


def _capture_directory(root: Path, slug: str) -> Path:
    capture = root / "captures" / slug
    (capture / "incoming").mkdir(parents=True)
    (capture / "workflow.yaml").write_text("version: 1\ncaptures: []\n", encoding="utf-8")
    return capture


def test_workspace_delete_requires_exact_interactive_slug_and_preserves_captures(
    tmp_path: Path,
) -> None:
    workspace = create_workspace("demo", tmp_path / "workspaces").root
    capture = _capture_directory(tmp_path, "demo")
    secret_store = SecretStore(WorkspacePaths(workspace))
    secret_store.put("actor-demo-default", "ACCOUNT_A", "access", "synthetic-secret")

    result = RUNNER.invoke(
        app,
        ["workspace", "delete", "--workspace", str(workspace)],
        input="demo\n",
    )

    assert result.exit_code == 0, result.output
    assert not workspace.exists()
    assert (capture / "workflow.yaml").is_file()
    assert secret_store.path.is_file()
    assert "Deletion is permanent" in result.output
    assert "credential and capture data were left untouched" in result.output


def test_workspace_purge_removes_workspace_capture_and_only_its_secret_files(
    tmp_path: Path,
) -> None:
    workspace = create_workspace("demo", tmp_path / "workspaces").root
    sibling = create_workspace("keep-me", tmp_path / "workspaces").root
    capture = _capture_directory(tmp_path, "demo")
    sibling_capture = _capture_directory(tmp_path, "keep-me")
    store = SecretStore(WorkspacePaths(workspace))
    sibling_store = SecretStore(WorkspacePaths(sibling))
    store.put("actor-demo-default", "ACCOUNT_A", "access", "demo-secret")
    sibling_store.put("actor-keep-default", "ACCOUNT_B", "access", "sibling-secret")
    abandoned = store.root / f".{store.path.name}.tmp-99999"
    abandoned.write_text("temporary", encoding="utf-8")

    result = RUNNER.invoke(
        app,
        [
            "workspace",
            "delete",
            "--workspace",
            str(workspace),
            "--purge",
            "--confirm",
            "PURGE demo",
        ],
    )

    assert result.exit_code == 0, result.output
    assert not workspace.exists()
    assert not capture.exists()
    assert not store.path.exists()
    assert not abandoned.exists()
    assert sibling.is_dir()
    assert sibling_capture.is_dir()
    assert sibling_store.path.is_file()
    assert "Complete project purge finished" in result.output


def test_workspace_purge_requires_stronger_confirmation(tmp_path: Path) -> None:
    workspace = create_workspace("demo", tmp_path / "workspaces").root
    capture = _capture_directory(tmp_path, "demo")
    store = SecretStore(WorkspacePaths(workspace))
    store.put("actor-demo-default", "ACCOUNT_A", "access", "demo-secret")

    result = RUNNER.invoke(
        app,
        ["workspace", "delete", "--workspace", str(workspace), "--purge"],
        input="demo\n",
    )

    assert result.exit_code == 1
    assert workspace.is_dir()
    assert capture.is_dir()
    assert store.path.is_file()
    assert "PURGE demo" in result.output


def test_workspace_purge_succeeds_when_default_capture_is_absent(tmp_path: Path) -> None:
    workspace = create_workspace("demo", tmp_path / "workspaces").root
    store = SecretStore(WorkspacePaths(workspace))
    store.put("actor-demo-default", "ACCOUNT_A", "access", "demo-secret")

    result = RUNNER.invoke(
        app,
        [
            "workspace",
            "delete",
            "--workspace",
            str(workspace),
            "--purge",
            "--confirm",
            "PURGE demo",
        ],
    )

    assert result.exit_code == 0, result.output
    assert not workspace.exists()
    assert not store.root.exists()
    assert "Capture directory: not present" in result.output


def test_workspace_purge_rejects_unrecognized_capture_before_deleting_secrets(
    tmp_path: Path,
) -> None:
    workspace = create_workspace("demo", tmp_path / "workspaces").root
    capture = tmp_path / "captures" / "demo"
    (capture / "incoming").mkdir(parents=True)
    store = SecretStore(WorkspacePaths(workspace))
    store.put("actor-demo-default", "ACCOUNT_A", "access", "demo-secret")

    result = RUNNER.invoke(
        app,
        [
            "workspace",
            "delete",
            "--workspace",
            str(workspace),
            "--purge",
            "--confirm",
            "PURGE demo",
        ],
    )

    assert result.exit_code == 1
    assert "unrecognized capture directory" in result.output
    assert workspace.is_dir()
    assert capture.is_dir()
    assert store.path.is_file()


def test_workspace_purge_rejects_symlinked_capture_directory(tmp_path: Path) -> None:
    workspace = create_workspace("demo", tmp_path / "workspaces").root
    actual_capture = tmp_path / "external" / "demo"
    (actual_capture / "incoming").mkdir(parents=True)
    (actual_capture / "workflow.yaml").write_text("version: 1\ncaptures: []\n", encoding="utf-8")
    capture_link = tmp_path / "captures" / "demo"
    capture_link.parent.mkdir()
    capture_link.symlink_to(actual_capture, target_is_directory=True)

    result = RUNNER.invoke(
        app,
        [
            "workspace",
            "delete",
            "--workspace",
            str(workspace),
            "--purge",
            "--confirm",
            "PURGE demo",
        ],
    )

    assert result.exit_code == 1
    assert "symbolic link" in result.output
    assert workspace.is_dir()
    assert actual_capture.is_dir()


def test_workspace_purge_supports_explicit_custom_capture_directory(tmp_path: Path) -> None:
    workspace = create_workspace("demo", tmp_path / "targets").root
    capture = tmp_path / "authorized-captures" / "demo"
    (capture / "incoming").mkdir(parents=True)
    (capture / "workflow.yaml").write_text("version: 1\ncaptures: []\n", encoding="utf-8")
    store = SecretStore(WorkspacePaths(workspace))
    store.put("actor-demo-default", "ACCOUNT_A", "access", "demo-secret")

    missing_capture = RUNNER.invoke(
        app,
        [
            "workspace",
            "delete",
            "--workspace",
            str(workspace),
            "--purge",
            "--confirm",
            "PURGE demo",
        ],
    )

    assert missing_capture.exit_code == 1
    assert "Cannot infer the capture directory" in missing_capture.output
    assert workspace.is_dir()

    purged = RUNNER.invoke(
        app,
        [
            "workspace",
            "delete",
            "--workspace",
            str(workspace),
            "--purge",
            "--capture-directory",
            str(capture),
            "--confirm",
            "PURGE demo",
        ],
    )

    assert purged.exit_code == 0, purged.output
    assert not workspace.exists()
    assert not capture.exists()
    assert not store.root.exists()


def test_capture_directory_option_requires_purge(tmp_path: Path) -> None:
    workspace = create_workspace("demo", tmp_path / "workspaces").root
    capture = _capture_directory(tmp_path, "demo")

    result = RUNNER.invoke(
        app,
        [
            "workspace",
            "delete",
            "--workspace",
            str(workspace),
            "--capture-directory",
            str(capture),
            "--confirm",
            "demo",
        ],
    )

    assert result.exit_code == 1
    assert "--capture-directory requires --purge" in result.output
    assert workspace.is_dir()
    assert capture.is_dir()


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
