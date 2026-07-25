"""Phase 4 skeptical validation tests."""

from finsec.config.workspace import WorkspacePaths
from finsec.evidence.manager import ensure_evidence
from finsec.hypotheses.domain import HypothesisStore
from finsec.utils.yaml_store import load_yaml, write_yaml
from finsec.validation.validator import validate_hypothesis


def test_incomplete_evidence_never_becomes_confirmed(
    phase4_workspace: WorkspacePaths,
) -> None:
    ensure_evidence(phase4_workspace, "HYP-002")

    result = validate_hypothesis(phase4_workspace, "HYP-002")

    assert result.validation.disposition == "NEEDS_MORE_EVIDENCE"
    assert result.validation.report_ready is False
    assert result.validation.missing_requirements


def test_complete_controlled_evidence_is_confirmed_and_updates_hypothesis(
    complete_phase4_workspace: WorkspacePaths,
) -> None:
    result = validate_hypothesis(complete_phase4_workspace, "HYP-002")

    assert result.conflict is False
    assert result.validation.disposition == "CONFIRMED"
    assert result.validation.report_ready is True
    assert all(item.result == "PASS" for item in result.validation.checks)
    hypotheses = HypothesisStore.model_validate(load_yaml(complete_phase4_workspace.hypotheses))
    payment = next(item for item in hypotheses.hypotheses if item.id == "HYP-002")
    assert payment.status == "CONFIRMED"


def test_secure_control_refutes_hypothesis(
    complete_phase4_workspace: WorkspacePaths,
) -> None:
    path = complete_phase4_workspace.evidence_for("HYP-002") / "metadata.yaml"
    metadata = load_yaml(path)
    metadata["assessment"]["expected_secure_behavior_observed"] = True
    metadata["assessment"]["unauthorized_capability_demonstrated"] = False
    write_yaml(path, metadata)

    result = validate_hypothesis(complete_phase4_workspace, "HYP-002")

    assert result.validation.disposition == "REFUTED"
    assert result.validation.report_ready is False


def test_scope_failure_is_out_of_scope(
    complete_phase4_workspace: WorkspacePaths,
) -> None:
    path = complete_phase4_workspace.evidence_for("HYP-002") / "metadata.yaml"
    metadata = load_yaml(path)
    metadata["assessment"]["scope_compliant"] = False
    write_yaml(path, metadata)

    result = validate_hypothesis(complete_phase4_workspace, "HYP-002")

    assert result.validation.disposition == "OUT_OF_SCOPE"


def test_tampered_artifact_checksum_prevents_confirmation(
    complete_phase4_workspace: WorkspacePaths,
) -> None:
    metadata = load_yaml(complete_phase4_workspace.evidence_for("HYP-002") / "metadata.yaml")
    artifact_path = (
        complete_phase4_workspace.evidence_for("HYP-002") / metadata["artifacts"][0]["path"]
    )
    artifact_path.write_text("tampered", encoding="utf-8")

    result = validate_hypothesis(complete_phase4_workspace, "HYP-002")

    assert result.validation.disposition == "NEEDS_MORE_EVIDENCE"
    integrity = next(item for item in result.validation.checks if item.id == "EVIDENCE-INTEGRITY")
    assert integrity.result == "FAIL"
