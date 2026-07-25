"""Phase 2 invariant extraction tests."""

from pathlib import Path
from typing import Any

import pytest

from finsec.config.workspace import create_workspace
from finsec.errors import FinsecError
from finsec.ingest.har import ingest_har
from finsec.modeling.domain import InvariantStore
from finsec.modeling.generator import generate_model
from finsec.modeling.invariants import generate_invariants
from finsec.modeling.models import KnowledgeStatus
from finsec.normalization.inventory import build_inventory
from finsec.utils.yaml_store import load_yaml, write_yaml


def _workspace_with_inventory(tmp_path: Path, sample_har: tuple[Path, dict[str, Any]]) -> Any:
    har_path, _ = sample_har
    workspace = create_workspace("demo", tmp_path / "workspaces")
    ingest_har(har_path, workspace, actor="ACCOUNT_A")
    build_inventory(workspace)
    return workspace


def test_invariants_are_specific_traceable_and_never_confirmed(
    tmp_path: Path, sample_har: tuple[Path, dict[str, Any]]
) -> None:
    workspace = _workspace_with_inventory(tmp_path, sample_har)
    generate_model(workspace)

    result = generate_invariants(workspace)
    store = InvariantStore.model_validate(load_yaml(workspace.invariants))
    by_key = {item.key: item for item in store.invariants}

    assert result.invariants == 3
    assert result.conflicts == ()
    assert "authentication:EP-001" in by_key
    assert "object-authorization:EP-001:paymentId" in by_key
    assert "object-authorization:EP-003:transactionId" in by_key
    assert all(item.validation_status == "NOT_CONFIRMED" for item in store.invariants)
    assert all(item.knowledge_status != KnowledgeStatus.CONFIRMED for item in store.invariants)
    assert by_key["authentication:EP-001"].knowledge_status == KnowledgeStatus.INFERRED
    assert (
        by_key["object-authorization:EP-001:paymentId"].knowledge_status == KnowledgeStatus.ASSUMED
    )
    assert by_key["authentication:EP-001"].evidence == [
        "EP-001",
        "OBS-000001",
        "OBS-000002",
    ]


def test_invariant_generation_requires_model_and_preserves_edits(
    tmp_path: Path, sample_har: tuple[Path, dict[str, Any]]
) -> None:
    workspace = _workspace_with_inventory(tmp_path, sample_har)
    with pytest.raises(FinsecError, match="hunt model"):
        generate_invariants(workspace)

    generate_model(workspace)
    first = generate_invariants(workspace)
    document = load_yaml(workspace.invariants)
    document["invariants"][0]["notes"] = "Researcher review pending."
    write_yaml(workspace.invariants, document)

    second = generate_invariants(workspace)
    store = InvariantStore.model_validate(load_yaml(workspace.invariants))

    assert first.conflicts == ()
    assert second.conflicts == ("authentication:EP-001",)
    assert store.invariants[0].notes == "Researcher review pending."
