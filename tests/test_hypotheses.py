"""Phase 3 hypothesis specificity, scoring, and mutation tests."""

import copy
import json
from pathlib import Path
from typing import Any

from finsec.config.workspace import WorkspacePaths, create_workspace
from finsec.hypotheses.domain import HypothesisStore
from finsec.hypotheses.generator import generate_hypotheses
from finsec.ingest.har import ingest_har
from finsec.modeling.generator import generate_model
from finsec.modeling.invariants import generate_invariants
from finsec.modeling.models import EndpointStore
from finsec.normalization.inventory import build_inventory
from finsec.utils.yaml_store import load_yaml, write_yaml


def test_hypotheses_are_specific_traceable_and_transparently_prioritized(
    phase3_workspace: WorkspacePaths,
) -> None:
    result = generate_hypotheses(phase3_workspace)
    store = HypothesisStore.model_validate(load_yaml(phase3_workspace.hypotheses))
    by_id = {item.id: item for item in store.hypotheses}

    assert result.hypotheses == 3
    assert result.conflicts == ()
    assert set(by_id) == {"HYP-001", "HYP-002", "HYP-003"}

    payment = by_id["HYP-002"]
    assert payment.priority == "P1"
    assert payment.scores.total == 14
    assert payment.scores.total == (
        payment.scores.impact
        + payment.scores.likelihood
        + payment.scores.confidence
        + payment.scores.testability
    )
    assert payment.mutation_dimensions == ["ACTOR", "OBJECT"]
    assert payment.source.endpoints == ["EP-001"]
    assert payment.invariant == ["INV-002"]
    assert payment.observations == ["OBS-000001", "OBS-000002"]
    assert "paymentId" in payment.hypothesis
    assert "Account A" in payment.hypothesis
    assert "Account B" in payment.hypothesis
    assert "test for idor" not in payment.hypothesis.lower()
    assert all(item.status == "NOT_TESTED" for item in store.hypotheses)


def test_hypothesis_lifecycle_fields_survive_regeneration(
    phase3_workspace: WorkspacePaths,
) -> None:
    generate_hypotheses(phase3_workspace)
    document = load_yaml(phase3_workspace.hypotheses)
    payment = next(item for item in document["hypotheses"] if item["id"] == "HYP-002")
    payment["status"] = "NEEDS_EVIDENCE"
    payment["notes"] = "Confirm that both accounts have identical KYC tier."
    write_yaml(phase3_workspace.hypotheses, document)

    preserved = generate_hypotheses(phase3_workspace)
    store = HypothesisStore.model_validate(load_yaml(phase3_workspace.hypotheses))
    payment_record = next(item for item in store.hypotheses if item.id == "HYP-002")
    assert preserved.conflicts == ()
    assert payment_record.status == "NEEDS_EVIDENCE"
    assert payment_record.notes == "Confirm that both accounts have identical KYC tier."

    document = load_yaml(phase3_workspace.hypotheses)
    payment = next(item for item in document["hypotheses"] if item["id"] == "HYP-002")
    payment["reasoning"] = "Researcher-edited reasoning."
    write_yaml(phase3_workspace.hypotheses, document)

    conflict = generate_hypotheses(phase3_workspace)
    assert conflict.conflicts == ("cross-account:EP-001:paymentId",)
    store = HypothesisStore.model_validate(load_yaml(phase3_workspace.hypotheses))
    payment_record = next(item for item in store.hypotheses if item.id == "HYP-002")
    assert payment_record.reasoning == "Researcher-edited reasoning."


def test_version_and_channel_hypotheses_require_observed_differentials(
    phase3_workspace: WorkspacePaths,
) -> None:
    endpoint_document = load_yaml(phase3_workspace.endpoints)
    payment = endpoint_document["endpoints"][0]
    payment["path"] = "/api/v1/payments/{paymentId}"
    payment["channels"] = ["WEB", "MOBILE"]
    alternate = copy.deepcopy(payment)
    alternate["id"] = "EP-099"
    alternate["path"] = "/api/v2/payments/{paymentId}"
    alternate["channels"] = ["WEB"]
    endpoint_document["endpoints"].append(alternate)
    unrelated = copy.deepcopy(payment)
    unrelated["id"] = "EP-100"
    unrelated["path"] = "/api/v3/payments/search"
    unrelated["channels"] = ["WEB"]
    endpoint_document["endpoints"].append(unrelated)
    EndpointStore.model_validate(endpoint_document)
    write_yaml(phase3_workspace.endpoints, endpoint_document)

    generate_hypotheses(phase3_workspace)
    store = HypothesisStore.model_validate(load_yaml(phase3_workspace.hypotheses))
    version = next(item for item in store.hypotheses if item.category == "version_parity")
    channel = next(item for item in store.hypotheses if item.category == "channel_parity")

    assert version.mutation_dimensions == ["VERSION"]
    assert set(version.source.endpoints) == {"EP-001", "EP-099"}
    assert "EP-100" not in version.source.endpoints
    assert channel.mutation_dimensions == ["CHANNEL"]
    assert channel.source.endpoints == ["EP-001"]


def test_state_time_and_value_mutations_require_matching_evidence(
    tmp_path: Path, sample_har: tuple[Path, dict[str, Any]]
) -> None:
    _, original = sample_har
    document = copy.deepcopy(original)
    entry = document["log"]["entries"][4]
    entry["request"]["url"] = "https://api.example.test/api/payments"
    entry["request"]["headers"].append({"name": "Authorization", "value": "Bearer PAYMENT_SECRET"})
    entry["request"]["postData"]["text"] = (
        '{"amount":"1.00","currency":"USD","destinationId":"TEST"}'
    )
    entry["response"]["content"]["text"] = '{"id":"PAY-1","status":"pending"}'
    document["log"]["entries"] = [entry]
    har_path = tmp_path / "payment.har"
    har_path.write_text(json.dumps(document), encoding="utf-8")

    workspace = create_workspace("payment-demo", tmp_path / "workspaces")
    target = load_yaml(workspace.target)
    target["scope"]["hosts"] = ["api.example.test"]
    target["accounts"] = [{"id": "ACCOUNT_A", "ownership": "researcher"}]
    write_yaml(workspace.target, target)
    ingest_har(har_path, workspace, actor="ACCOUNT_A", channel="WEB")
    build_inventory(workspace)
    generate_model(workspace)
    generate_invariants(workspace)
    generate_hypotheses(workspace)

    store = HypothesisStore.model_validate(load_yaml(workspace.hypotheses))
    categories = {item.category: item for item in store.hypotheses}
    assert categories["state_integrity"].mutation_dimensions == ["STATE", "TIME"]
    assert categories["replay"].mutation_dimensions == ["TIME"]
    assert categories["value_validation"].mutation_dimensions == ["VALUE"]
