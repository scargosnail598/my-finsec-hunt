"""Phase 2 deterministic modeling and preservation tests."""

from pathlib import Path
from typing import Any

from finsec.config.workspace import create_workspace
from finsec.ingest.har import ingest_har
from finsec.modeling.domain import ActorStore, ResourceStore
from finsec.modeling.generator import generate_model
from finsec.modeling.models import KnowledgeStatus
from finsec.normalization.inventory import build_inventory
from finsec.utils.yaml_store import load_yaml, write_yaml


def _modeled_workspace(tmp_path: Path, sample_har: tuple[Path, dict[str, Any]]) -> tuple[Path, Any]:
    har_path, _ = sample_har
    workspace = create_workspace("demo", tmp_path / "workspaces")
    ingest_har(har_path, workspace, actor="ACCOUNT_A")
    build_inventory(workspace)
    return har_path, workspace


def test_model_builds_evidence_backed_actors_resources_and_workflows(
    tmp_path: Path, sample_har: tuple[Path, dict[str, Any]]
) -> None:
    _, workspace = _modeled_workspace(tmp_path, sample_har)

    result = generate_model(workspace)
    actors = ActorStore.model_validate(load_yaml(workspace.actors))
    resources = ResourceStore.model_validate(load_yaml(workspace.resources))
    by_name = {item.name: item for item in resources.resources}

    assert result.actors == 1
    assert result.resources == 3
    assert result.workflows == 3
    assert result.conflicts == ()

    actor = actors.actors[0]
    assert actor.name == "ACCOUNT_A"
    assert actor.knowledge_status == KnowledgeStatus.OBSERVED
    assert actor.role.knowledge_status == KnowledgeStatus.ASSUMED
    assert actor.evidence == [
        "OBS-000001",
        "OBS-000002",
        "OBS-000003",
        "OBS-000004",
        "OBS-000005",
    ]

    assert set(by_name) == {"Payment", "Report", "Transaction"}
    payment = by_name["Payment"]
    assert payment.identifiers == ["paymentId"]
    assert payment.owner.knowledge_status == KnowledgeStatus.ASSUMED
    assert payment.states == []
    assert "status" in payment.sensitive_fields
    assert payment.operations[0].endpoint == "EP-001"

    workflows = (workspace.root / "model/workflows.md").read_text(encoding="utf-8")
    state_machines = (workspace.root / "model/state-machines.md").read_text(encoding="utf-8")
    assert workflows.count("## Workflow:") == 3
    assert "Transition order: `NOT CONFIRMED`" in workflows
    assert "Observed states: None" in state_machines
    assert "FINSEC-GENERATED:workflows:START" in workflows


def test_model_preserves_researcher_yaml_and_markdown_edits(
    tmp_path: Path, sample_har: tuple[Path, dict[str, Any]]
) -> None:
    _, workspace = _modeled_workspace(tmp_path, sample_har)
    first = generate_model(workspace)
    first_actors = ActorStore.model_validate(load_yaml(workspace.actors))
    first_ids = {item.key: item.id for item in first_actors.actors}

    actor_document = load_yaml(workspace.actors)
    actor_document["actors"][0]["notes"] = "Researcher-confirmed account label."
    write_yaml(workspace.actors, actor_document)

    workflows_path = workspace.root / "model/workflows.md"
    workflows_path.write_text(
        workflows_path.read_text(encoding="utf-8") + "\nManual workflow note.\n",
        encoding="utf-8",
    )

    second = generate_model(workspace)
    second_actors = ActorStore.model_validate(load_yaml(workspace.actors))
    second_ids = {item.key: item.id for item in second_actors.actors}

    assert first.conflicts == ()
    assert second.conflicts == ("actors:actor:ACCOUNT_A",)
    assert second_actors.actors[0].notes == "Researcher-confirmed account label."
    assert first_ids == second_ids
    assert "Manual workflow note." in workflows_path.read_text(encoding="utf-8")
    assert workflows_path.read_text(encoding="utf-8").count("FINSEC-GENERATED:workflows:START") == 1
