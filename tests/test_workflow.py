"""Automated passive-ingestion and offline workflow tests."""

import shutil
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError
from typer.testing import CliRunner

from finsec.cli import app
from finsec.errors import FinsecError
from finsec.modeling.models import ObservationStore
from finsec.setup import AccountInput, build_setup_config, create_setup_workspace
from finsec.utils.yaml_store import load_yaml, write_yaml
from finsec.workflow import (
    WorkflowCapture,
    WorkflowManifest,
    load_workflow_manifest,
    merge_workflow_assignments,
    run_offline_workflow,
)

RUNNER = CliRunner()


def _workspace(tmp_path: Path) -> tuple[Any, Path]:
    config = build_setup_config(
        project_name="Workflow Demo",
        slug="workflow-demo",
        hosts=["api.example.test"],
        accounts=[AccountInput("ACCOUNT_A"), AccountInput("ACCOUNT_B")],
        production=False,
    )
    created = create_setup_workspace(config, tmp_path / "workspaces", tmp_path / "captures")
    return created, created.capture_root / "workflow.yaml"


def _assign_sample_har(
    tmp_path: Path, sample_har: tuple[Path, dict[str, Any]]
) -> tuple[Any, Path, Path]:
    created, manifest = _workspace(tmp_path)
    source, _ = sample_har
    incoming = created.capture_root / "incoming" / "account-a.har"
    shutil.copy2(source, incoming)
    merge_workflow_assignments(
        manifest,
        [WorkflowCapture(file=incoming.name, actor="ACCOUNT_A", channel="WEB")],
    )
    return created, manifest, incoming


def test_setup_creates_empty_workflow_manifest(tmp_path: Path) -> None:
    _, manifest = _workspace(tmp_path)
    document = load_workflow_manifest(manifest)
    assert document == WorkflowManifest()


def test_workflow_manifest_drives_complete_offline_pipeline(
    tmp_path: Path, sample_har: tuple[Path, dict[str, Any]]
) -> None:
    created, manifest, incoming = _assign_sample_har(tmp_path, sample_har)
    progress: list[str] = []

    result = run_offline_workflow(
        created.workspace,
        manifest_path=manifest,
        progress=progress.append,
    )

    assert result.observations == 5
    assert result.endpoints == 4
    assert result.actors == 2
    assert result.resources == 3
    assert result.invariants == 3
    assert result.active_hypotheses >= 1
    assert result.ingested[0].imported == 5
    assert incoming.is_file()
    assert any("endpoint inventory" in message for message in progress)
    assert any("hypotheses" in message for message in progress)


def test_workflow_rerun_is_idempotent(
    tmp_path: Path, sample_har: tuple[Path, dict[str, Any]]
) -> None:
    created, manifest, _ = _assign_sample_har(tmp_path, sample_har)
    first = run_offline_workflow(created.workspace, manifest_path=manifest)
    second = run_offline_workflow(created.workspace, manifest_path=manifest)

    assert first.observations == second.observations == 5
    assert second.ingested[0].imported == 0
    assert second.ingested[0].skipped == 5
    assert second.ingested[0].relabeled == 0


def test_workflow_manifest_correction_refreshes_labels(
    tmp_path: Path, sample_har: tuple[Path, dict[str, Any]]
) -> None:
    created, manifest, _ = _assign_sample_har(tmp_path, sample_har)
    run_offline_workflow(created.workspace, manifest_path=manifest)
    merge_workflow_assignments(
        manifest,
        [WorkflowCapture(file="account-a.har", actor="ACCOUNT_B", channel="MOBILE")],
    )

    corrected = run_offline_workflow(created.workspace, manifest_path=manifest)

    assert corrected.ingested[0].relabeled == 5
    observations = ObservationStore.model_validate(load_yaml(created.workspace.observations))
    assert {item.actor for item in observations.observations} == {"ACCOUNT_B"}
    assert {item.channel for item in observations.observations} == {"MOBILE"}


def test_workflow_rejects_unconfigured_actor_before_ingestion(
    tmp_path: Path, sample_har: tuple[Path, dict[str, Any]]
) -> None:
    created, manifest = _workspace(tmp_path)
    source, _ = sample_har
    shutil.copy2(source, created.capture_root / "incoming/unmapped.har")
    write_yaml(
        manifest,
        {
            "version": 1,
            "captures": [{"file": "unmapped.har", "actor": "NOT_CONFIGURED", "channel": "WEB"}],
        },
    )

    with pytest.raises(FinsecError, match="unconfigured actors"):
        run_offline_workflow(created.workspace, manifest_path=manifest)

    observations = load_yaml(created.workspace.observations)
    assert observations["observations"] == []


def test_workflow_requires_observations(tmp_path: Path) -> None:
    created, manifest = _workspace(tmp_path)
    with pytest.raises(FinsecError, match="No observations"):
        run_offline_workflow(created.workspace, manifest_path=manifest)


@pytest.mark.parametrize("filename", ["../capture.har", "/tmp/capture.har", "capture.json"])
def test_workflow_manifest_rejects_unsafe_filenames(filename: str) -> None:
    with pytest.raises(ValidationError):
        WorkflowCapture(file=filename, actor="ACCOUNT_A", channel="WEB")


def test_workflow_cli_runs_to_human_review_boundary(
    tmp_path: Path, sample_har: tuple[Path, dict[str, Any]]
) -> None:
    created, manifest, _ = _assign_sample_har(tmp_path, sample_har)

    result = RUNNER.invoke(
        app,
        [
            "workflow",
            "--workspace",
            str(created.workspace.root),
            "--manifest",
            str(manifest),
        ],
    )

    assert result.exit_code == 0, result.output
    assert "Automated offline workflow completed" in result.output
    assert "Active hypotheses" in result.output
    assert "stops here" in result.output
    assert "human review" in result.output


def test_workflow_cli_requires_explicit_ingestion_choice(
    tmp_path: Path, sample_har: tuple[Path, dict[str, Any]]
) -> None:
    created, manifest, _ = _assign_sample_har(tmp_path, sample_har)
    run_offline_workflow(created.workspace, manifest_path=manifest)

    missing_manifest = RUNNER.invoke(
        app,
        [
            "workflow",
            "--workspace",
            str(created.workspace.root),
            "--capture-root",
            str(tmp_path / "no-captures-here"),
        ],
    )
    existing_only = RUNNER.invoke(
        app,
        ["workflow", "--workspace", str(created.workspace.root), "--no-ingest"],
    )

    assert missing_manifest.exit_code == 1
    assert "No workflow manifest was found" in missing_manifest.output
    assert existing_only.exit_code == 0, existing_only.output
    assert "explicitly skipped" in existing_only.output
