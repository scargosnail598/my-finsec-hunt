"""Typed skeptical-validation results for Phase 4."""

from typing import Literal

from pydantic import Field

from finsec.modeling.domain import EditableModel, GenerationMetadata

ValidationDisposition = Literal[
    "CONFIRMED",
    "REFUTED",
    "NEEDS_MORE_EVIDENCE",
    "OUT_OF_SCOPE",
    "EXPECTED_BEHAVIOR",
]
CheckResult = Literal["PASS", "FAIL", "MISSING", "NOT_APPLICABLE"]


class ValidationCheck(EditableModel):
    """One explicit question asked while attempting to disprove a finding."""

    id: str
    question: str
    result: CheckResult
    detail: str


class ValidationRecord(EditableModel):
    """Persisted disposition for one hypothesis and evidence set."""

    id: str
    key: str
    hypothesis_id: str
    title: str
    disposition: ValidationDisposition
    summary: str
    checks: list[ValidationCheck]
    evidence_artifacts: list[str] = Field(default_factory=list)
    missing_requirements: list[str] = Field(default_factory=list)
    report_ready: bool = False
    notes: str | None = None
    generation: GenerationMetadata | None = None


class ValidationStore(EditableModel):
    """Versioned collection of skeptical validation outcomes."""

    version: int = 1
    validations: list[ValidationRecord] = Field(default_factory=list)
