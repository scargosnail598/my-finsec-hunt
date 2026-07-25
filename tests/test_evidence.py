"""Phase 4 evidence indexing and redaction tests."""

from pathlib import Path

import pytest

from finsec.config.workspace import WorkspacePaths
from finsec.errors import FinsecError
from finsec.evidence.manager import add_evidence, ensure_evidence


def test_evidence_scaffold_and_text_import_redact_without_modifying_source(
    phase4_workspace: WorkspacePaths, tmp_path: Path
) -> None:
    source = tmp_path / "request.http"
    original = (
        "GET /api/payments/12345 HTTP/1.1\n"
        "Authorization: Bearer TOP_SECRET\n"
        "Cookie: session=COOKIE_SECRET\n"
    )
    source.write_text(original, encoding="utf-8")

    result = add_evidence(
        phase4_workspace,
        "HYP-002",
        source,
        "request",
        description="Account B cross-account control request.",
    )

    assert result.added_artifact == "EVD-001"
    assert result.metadata.test_id == "TEST-001"
    assert source.read_text(encoding="utf-8") == original
    artifact = result.metadata.artifacts[0]
    stored = (result.root / artifact.path).read_text(encoding="utf-8")
    assert "TOP_SECRET" not in stored
    assert "COOKIE_SECRET" not in stored
    assert "[REDACTED]" in stored
    assert "Authorization: [REDACTED]\n" in stored
    assert "Cookie: [REDACTED]\n" in stored
    assert artifact.redaction == "AUTOMATIC"
    assert (result.root / "metadata.yaml").is_file()
    assert (result.root / "conclusion.md").is_file()


def test_binary_and_screenshot_evidence_require_explicit_redaction_confirmation(
    phase4_workspace: WorkspacePaths, tmp_path: Path
) -> None:
    screenshot = tmp_path / "proof.png"
    screenshot.write_bytes(b"synthetic-redacted-image")

    with pytest.raises(FinsecError, match="already-redacted"):
        add_evidence(phase4_workspace, "HYP-002", screenshot, "screenshot")

    result = add_evidence(
        phase4_workspace,
        "HYP-002",
        screenshot,
        "screenshot",
        already_redacted=True,
    )
    assert result.metadata.artifacts[0].redaction == "RESEARCHER_CONFIRMED"


def test_before_and_after_evidence_require_valid_json(
    phase4_workspace: WorkspacePaths, tmp_path: Path
) -> None:
    invalid = tmp_path / "before.txt"
    invalid.write_text("not-json", encoding="utf-8")
    ensure_evidence(phase4_workspace, "HYP-002")

    with pytest.raises(FinsecError, match="valid JSON"):
        add_evidence(phase4_workspace, "HYP-002", invalid, "before")
