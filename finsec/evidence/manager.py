"""Create evidence workspaces and import redacted researcher artifacts."""

import hashlib
import json
import re
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from pydantic import ValidationError

from finsec.config.workspace import WorkspacePaths
from finsec.errors import FinsecError
from finsec.evidence.domain import (
    EvidenceArtifact,
    EvidenceKind,
    EvidenceMetadata,
    RedactionMethod,
)
from finsec.hypotheses.generator import find_hypothesis
from finsec.testing.domain import TestPlanStore
from finsec.utils.redaction import redact_data, redact_text
from finsec.utils.yaml_store import load_yaml, write_yaml

EVIDENCE_KINDS = {
    "request",
    "response",
    "before",
    "after",
    "screenshot",
    "ownership",
    "other",
}
BINARY_SUFFIXES = {".gif", ".jpeg", ".jpg", ".pdf", ".png", ".webp", ".zip"}


@dataclass(frozen=True)
class EvidenceResult:
    """Evidence state returned to the CLI."""

    metadata: EvidenceMetadata
    root: Path
    added_artifact: str | None = None


def _test_id(workspace: WorkspacePaths, hypothesis_id: str) -> str | None:
    if not workspace.test_plans.is_file():
        return None
    try:
        store = TestPlanStore.model_validate(load_yaml(workspace.test_plans))
    except (OSError, ValidationError) as error:
        raise FinsecError(f"Cannot load test plans: {error}") from error
    plan = next((item for item in store.plans if item.hypothesis_id == hypothesis_id), None)
    return plan.id if plan is not None else None


def _metadata_path(root: Path) -> Path:
    return root / "metadata.yaml"


def _write_conclusion(path: Path, hypothesis_id: str) -> None:
    if path.is_file():
        return
    path.write_text(
        (
            f"# Evidence Conclusion - {hypothesis_id}\n\n"
            "## Observed Result\n\n"
            "## Negative Controls\n\n"
            "## Alternative Explanations\n\n"
            "## Remaining Uncertainty\n"
        ),
        encoding="utf-8",
        newline="\n",
    )


def ensure_evidence(workspace: WorkspacePaths, hypothesis_id: str) -> EvidenceResult:
    """Create a non-overwriting evidence scaffold and return its metadata."""

    hypothesis = find_hypothesis(workspace, hypothesis_id)
    root = workspace.evidence_for(hypothesis.id)
    for relative in ("requests", "responses", "screenshots", "attachments"):
        (root / relative).mkdir(parents=True, exist_ok=True)
    path = _metadata_path(root)
    if not path.is_file():
        metadata = EvidenceMetadata(
            hypothesis_id=hypothesis.id,
            test_id=_test_id(workspace, hypothesis.id),
        )
        write_yaml(path, metadata.model_dump(mode="json"))
    else:
        metadata = load_evidence(workspace, hypothesis.id)
        current_test_id = _test_id(workspace, hypothesis.id)
        if metadata.test_id is None and current_test_id is not None:
            metadata.test_id = current_test_id
            write_yaml(path, metadata.model_dump(mode="json"))
    _write_conclusion(root / "conclusion.md", hypothesis.id)
    return EvidenceResult(load_evidence(workspace, hypothesis.id), root)


def load_evidence(workspace: WorkspacePaths, hypothesis_id: str) -> EvidenceMetadata:
    """Load and validate an existing evidence index."""

    path = _metadata_path(workspace.evidence_for(hypothesis_id))
    if not path.is_file():
        raise FinsecError(f"Evidence metadata does not exist for {hypothesis_id}.")
    try:
        metadata = EvidenceMetadata.model_validate(load_yaml(path))
    except (OSError, ValidationError) as error:
        raise FinsecError(f"Cannot load evidence metadata: {error}") from error
    if metadata.hypothesis_id.upper() != hypothesis_id.upper():
        raise FinsecError("Evidence metadata hypothesis_id does not match its directory.")
    return metadata


def _next_artifact_id(metadata: EvidenceMetadata) -> str:
    numbers = [
        int(match.group(1))
        for artifact in metadata.artifacts
        if (match := re.fullmatch(r"EVD-(\d+)", artifact.id)) is not None
    ]
    return f"EVD-{max(numbers, default=0) + 1:03d}"


def _safe_name(name: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "-", Path(name).name).strip(".-")
    return cleaned or "artifact.txt"


def _destination(root: Path, kind: EvidenceKind, artifact_id: str, source: Path) -> Path:
    if kind == "before":
        return root / "before.json"
    if kind == "after":
        return root / "after.json"
    directory = {
        "request": "requests",
        "response": "responses",
        "screenshot": "screenshots",
        "ownership": "attachments",
        "other": "attachments",
    }[kind]
    return root / directory / f"{artifact_id}-{_safe_name(source.name)}"


def _write_redacted_text(source: Path, destination: Path, require_json: bool) -> None:
    try:
        content = source.read_text(encoding="utf-8")
    except UnicodeDecodeError as error:
        raise FinsecError(
            "Binary evidence requires --already-redacted and explicit researcher review."
        ) from error
    if require_json or source.suffix.lower() in {".har", ".json"}:
        try:
            parsed = json.loads(content)
        except json.JSONDecodeError as error:
            if require_json:
                raise FinsecError(f"{source.name} must contain valid JSON.") from error
        else:
            destination.write_text(
                f"{json.dumps(redact_data(parsed), indent=2, sort_keys=True)}\n",
                encoding="utf-8",
                newline="\n",
            )
            return
    destination.write_text(redact_text(content), encoding="utf-8", newline="\n")


def add_evidence(
    workspace: WorkspacePaths,
    hypothesis_id: str,
    source: Path,
    kind: str,
    description: str | None = None,
    already_redacted: bool = False,
) -> EvidenceResult:
    """Import one artifact, redacting text and never modifying the source."""

    normalized_kind = kind.lower()
    if normalized_kind not in EVIDENCE_KINDS:
        raise FinsecError(
            "Evidence kind must be request, response, before, after, screenshot, ownership, "
            "or other."
        )
    evidence_kind = cast(EvidenceKind, normalized_kind)
    source = source.expanduser().resolve()
    if not source.is_file():
        raise FinsecError(f"Evidence source is not a file: {source}")
    result = ensure_evidence(workspace, hypothesis_id)
    try:
        source.relative_to(result.root.resolve())
    except ValueError:
        pass
    else:
        raise FinsecError("The source file is already inside this hypothesis evidence directory.")
    metadata = result.metadata
    artifact_id = _next_artifact_id(metadata)
    destination = _destination(result.root, evidence_kind, artifact_id, source)
    if destination.exists():
        raise FinsecError(f"Evidence artifact already exists: {destination}")
    if evidence_kind == "screenshot" and not already_redacted:
        raise FinsecError("Screenshots require --already-redacted after manual privacy review.")
    if source.suffix.lower() in BINARY_SUFFIXES and not already_redacted:
        raise FinsecError(
            "Binary evidence requires --already-redacted after manual privacy review."
        )
    destination.parent.mkdir(parents=True, exist_ok=True)
    if already_redacted:
        shutil.copyfile(source, destination)
        redaction: RedactionMethod = "RESEARCHER_CONFIRMED"
    else:
        _write_redacted_text(
            source,
            destination,
            require_json=evidence_kind in {"before", "after"},
        )
        redaction = "AUTOMATIC"
    relative = destination.relative_to(result.root).as_posix()
    digest = hashlib.sha256(destination.read_bytes()).hexdigest()
    metadata.artifacts.append(
        EvidenceArtifact(
            id=artifact_id,
            kind=evidence_kind,
            path=relative,
            source_name=_safe_name(source.name),
            sha256=digest,
            redaction=redaction,
            description=description,
        )
    )
    validated = EvidenceMetadata.model_validate(metadata.model_dump(mode="json"))
    write_yaml(_metadata_path(result.root), validated.model_dump(mode="json"))
    return EvidenceResult(validated, result.root, artifact_id)


def add_generated_evidence(
    workspace: WorkspacePaths,
    hypothesis_id: str,
    files: list[tuple[str, EvidenceKind, str, str]],
) -> EvidenceResult:
    """Register already-structured runner output after applying text redaction again."""

    result = ensure_evidence(workspace, hypothesis_id)
    metadata = result.metadata
    root = result.root.resolve()
    prepared: list[tuple[Path, EvidenceKind, str, str]] = []
    seen: set[Path] = set()
    for relative, kind, content, description in files:
        destination = (root / relative).resolve()
        try:
            destination.relative_to(root)
        except ValueError as error:
            raise FinsecError(
                "Generated evidence path escapes the hypothesis directory."
            ) from error
        if destination in seen:
            raise FinsecError(f"Duplicate generated evidence path: {destination}")
        if destination.exists():
            raise FinsecError(f"Generated evidence artifact already exists: {destination}")
        seen.add(destination)
        prepared.append((destination, kind, content, description))

    last_id: str | None = None
    for destination, kind, content, description in prepared:
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(redact_text(content), encoding="utf-8", newline="\n")
        artifact_id = _next_artifact_id(metadata)
        digest = hashlib.sha256(destination.read_bytes()).hexdigest()
        metadata.artifacts.append(
            EvidenceArtifact(
                id=artifact_id,
                kind=kind,
                path=destination.relative_to(root).as_posix(),
                source_name=_safe_name(destination.name),
                sha256=digest,
                redaction="AUTOMATIC",
                description=description,
            )
        )
        last_id = artifact_id
    validated = EvidenceMetadata.model_validate(metadata.model_dump(mode="json"))
    write_yaml(_metadata_path(root), validated.model_dump(mode="json"))
    return EvidenceResult(validated, root, last_id)
