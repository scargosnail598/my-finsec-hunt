"""Persistent default-workspace selection tests."""

import os
from pathlib import Path

import pytest
from typer.testing import CliRunner

from finsec.cli import app
from finsec.config.workspace import (
    clear_default_workspace,
    create_workspace,
    default_workspace_config_path,
    load_default_workspace,
    resolve_workspace,
    set_default_workspace,
)
from finsec.errors import WorkspaceError

RUNNER = CliRunner()


@pytest.fixture
def config_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    config_directory = tmp_path / "config"
    monkeypatch.setenv("FINSEC_HUNT_CONFIG_DIR", str(config_directory))
    return config_directory / "default-workspace"


def test_workspace_use_persists_absolute_selection_and_status_uses_it(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    config_path: Path,
) -> None:
    selected = create_workspace("selected", tmp_path / "workspaces").root
    create_workspace("other", tmp_path / "workspaces")
    monkeypatch.chdir(tmp_path)

    result = RUNNER.invoke(app, ["workspace", "use", str(selected)])

    assert result.exit_code == 0, result.output
    assert str(selected) in "".join(result.output.splitlines())
    assert config_path.read_text(encoding="utf-8") == f"{selected}\n"
    assert Path(config_path.read_text(encoding="utf-8").strip()).is_absolute()

    status = RUNNER.invoke(app, ["status"])
    assert status.exit_code == 0, status.output
    assert "Target: selected" in status.output


def test_explicit_workspace_overrides_configured_default(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    config_path: Path,
) -> None:
    configured = create_workspace("configured", tmp_path / "workspaces").root
    explicit = create_workspace("explicit", tmp_path / "workspaces").root
    set_default_workspace(configured, config_path)
    monkeypatch.chdir(tmp_path)

    result = RUNNER.invoke(app, ["status", "--workspace", str(explicit)])

    assert result.exit_code == 0, result.output
    assert "Target: explicit" in result.output


def test_ancestor_workspace_overrides_configured_default(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    config_path: Path,
) -> None:
    configured = create_workspace("configured", tmp_path / "workspaces").root
    ancestor = create_workspace("ancestor", tmp_path / "workspaces").root
    set_default_workspace(configured, config_path)
    monkeypatch.chdir(ancestor / "scope")

    result = RUNNER.invoke(app, ["status"])

    assert result.exit_code == 0, result.output
    assert "Target: ancestor" in result.output


def test_workspace_current_and_clear_report_selection(
    tmp_path: Path,
    config_path: Path,
) -> None:
    workspace = create_workspace("demo", tmp_path / "workspaces").root
    set_default_workspace(workspace, config_path)

    current = RUNNER.invoke(app, ["workspace", "current"])
    cleared = RUNNER.invoke(app, ["workspace", "clear"])
    after_clear = RUNNER.invoke(app, ["workspace", "current"])

    assert current.exit_code == 0, current.output
    assert str(workspace) in "".join(current.output.splitlines())
    assert cleared.exit_code == 0, cleared.output
    assert "Cleared the default workspace" in cleared.output
    assert not config_path.exists()
    assert after_clear.exit_code == 0, after_clear.output
    assert "No default workspace is configured" in after_clear.output


def test_invalid_workspace_use_does_not_replace_existing_selection(
    tmp_path: Path,
    config_path: Path,
) -> None:
    workspace = create_workspace("demo", tmp_path / "workspaces").root
    set_default_workspace(workspace, config_path)
    previous = config_path.read_text(encoding="utf-8")

    result = RUNNER.invoke(app, ["workspace", "use", str(tmp_path / "missing")])

    assert result.exit_code == 1
    assert "Not a FinSec Hunt workspace" in result.output
    assert config_path.read_text(encoding="utf-8") == previous


def test_stale_default_fails_with_recovery_commands(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    config_path: Path,
) -> None:
    config_path.parent.mkdir(parents=True)
    config_path.write_text(f"{tmp_path / 'missing-workspace'}\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    result = RUNNER.invoke(app, ["status"])

    assert result.exit_code == 1
    assert "Configured default workspace is unavailable" in result.output
    assert "hunt workspace use PATH" in result.output
    assert "hunt workspace clear" in result.output


def test_no_default_preserves_single_local_workspace_discovery(
    tmp_path: Path,
    config_path: Path,
) -> None:
    workspace = create_workspace("only", tmp_path / "workspaces").root

    resolved = resolve_workspace(start=tmp_path, default_config=config_path)

    assert resolved.root == workspace


def test_multiple_local_workspaces_suggest_selecting_a_default(
    tmp_path: Path,
    config_path: Path,
) -> None:
    create_workspace("one", tmp_path / "workspaces")
    create_workspace("two", tmp_path / "workspaces")

    with pytest.raises(WorkspaceError, match="hunt workspace use PATH"):
        resolve_workspace(start=tmp_path, default_config=config_path)


@pytest.mark.skipif(os.name == "nt", reason="Symlink creation may require elevated privileges")
def test_default_workspace_config_rejects_symlinks(
    tmp_path: Path,
    config_path: Path,
) -> None:
    workspace = create_workspace("demo", tmp_path / "workspaces").root
    redirected = tmp_path / "redirected-default"
    redirected.write_text(f"{workspace}\n", encoding="utf-8")
    config_path.parent.mkdir(parents=True)
    config_path.symlink_to(redirected)

    with pytest.raises(WorkspaceError, match="not a safe regular file"):
        load_default_workspace(config_path)
    with pytest.raises(WorkspaceError, match="not a safe regular file"):
        set_default_workspace(workspace, config_path)


@pytest.mark.skipif(os.name != "posix", reason="POSIX permission bits are not portable")
def test_default_workspace_config_uses_private_permissions(
    tmp_path: Path,
    config_path: Path,
) -> None:
    workspace = create_workspace("demo", tmp_path / "workspaces").root

    set_default_workspace(workspace, config_path)

    assert config_path.parent.stat().st_mode & 0o777 == 0o700
    assert config_path.stat().st_mode & 0o777 == 0o600


def test_workspace_delete_still_requires_explicit_workspace(
    tmp_path: Path,
    config_path: Path,
) -> None:
    workspace = create_workspace("demo", tmp_path / "workspaces").root
    set_default_workspace(workspace, config_path)

    result = RUNNER.invoke(app, ["workspace", "delete"])

    assert result.exit_code == 2
    assert "Missing option" in result.output
    assert workspace.is_dir()


def test_default_workspace_helpers_load_and_clear_selection(
    tmp_path: Path,
    config_path: Path,
) -> None:
    workspace = create_workspace("demo", tmp_path / "workspaces").root

    assert default_workspace_config_path() == config_path
    assert load_default_workspace(config_path) is None
    selected = set_default_workspace(workspace, config_path)
    loaded = load_default_workspace(config_path)

    assert selected.root == workspace
    assert loaded is not None
    assert loaded.root == workspace
    assert clear_default_workspace(config_path) is True
    assert clear_default_workspace(config_path) is False
