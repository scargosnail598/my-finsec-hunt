"""Phase 4 validated, versioned report-generation tests."""

from importlib.resources import files
from pathlib import Path

import pytest

from finsec.config.workspace import WorkspacePaths
from finsec.errors import FinsecError
from finsec.evidence.manager import ensure_evidence
from finsec.reporting.generator import generate_report
from finsec.utils.yaml_store import load_yaml, write_yaml


def test_report_template_is_packaged_and_matches_repository_source() -> None:
    packaged = (
        files("finsec.reporting.templates").joinpath("report.md.j2").read_text(encoding="utf-8")
    )
    repository = Path(__file__).parents[1] / "templates" / "report.md.j2"
    assert packaged == repository.read_text(encoding="utf-8")


def test_report_requires_confirmed_evidence(phase4_workspace: WorkspacePaths) -> None:
    ensure_evidence(phase4_workspace, "HYP-002")

    with pytest.raises(FinsecError, match="requires CONFIRMED evidence"):
        generate_report(phase4_workspace, "HYP-002")


def test_confirmed_report_is_redacted_and_versioned(
    complete_phase4_workspace: WorkspacePaths,
) -> None:
    first = generate_report(complete_phase4_workspace, "HYP-002")
    repeated = generate_report(complete_phase4_workspace, "HYP-002")

    assert first.created is True
    assert first.path.name == "HYP-002-report-v1.md"
    assert repeated.created is False
    assert repeated.path == first.path
    content = first.path.read_text(encoding="utf-8")
    assert "# Missing Ownership Validation" in content
    assert "## Technical Impact" in content
    assert "## Business Impact" in content
    assert "REPORT_SECRET" not in content
    assert "[REDACTED]" in content

    metadata_path = complete_phase4_workspace.evidence_for("HYP-002") / "metadata.yaml"
    metadata = load_yaml(metadata_path)
    metadata["narrative"]["business_impact"] = (
        "Payment and settlement metadata can cross the account boundary."
    )
    write_yaml(metadata_path, metadata)
    second = generate_report(complete_phase4_workspace, "HYP-002")
    assert second.created is True
    assert second.path.name == "HYP-002-report-v2.md"
