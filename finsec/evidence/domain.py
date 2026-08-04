"""Typed researcher-supplied evidence and validation-input contracts."""

from typing import Literal

from pydantic import Field

from finsec.modeling.domain import EditableModel

EvidenceKind = Literal[
    "request",
    "response",
    "before",
    "after",
    "delayed_after",
    "related_state",
    "ledger_state",
    "entitlement_state",
    "inventory_state",
    "workflow_state",
    "screenshot",
    "ownership",
    "other",
]
RedactionMethod = Literal["AUTOMATIC", "RESEARCHER_CONFIRMED"]


class EvidenceArtifact(EditableModel):
    """One redacted artifact stored inside the hypothesis evidence directory."""

    id: str
    kind: EvidenceKind
    path: str
    source_name: str
    sha256: str
    redaction: RedactionMethod
    description: str | None = None


class EvidenceAssessment(EditableModel):
    """Researcher answers consumed by the skeptical deterministic validator."""

    scope_compliant: bool | None = None
    rules_compliant: bool | None = None
    researcher_controlled_accounts: bool | None = None
    ownership_or_boundary_verified: bool | None = None
    expected_secure_behavior_observed: bool | None = None
    unauthorized_capability_demonstrated: bool | None = None
    actual_behavior_verified: bool | None = None
    authoritative_result_verified: bool | None = None
    negative_control_performed: bool | None = None
    reproduced_clean_session: bool | None = None
    alternative_explanations_ruled_out: bool | None = None
    meaningful_impact_demonstrated: bool | None = None
    realistic_prerequisites: bool | None = None
    documented_or_intended_behavior: bool | None = None
    client_side_only: bool | None = None
    known_duplicate: bool | None = None
    redaction_reviewed: bool | None = None


class FindingNarrative(EditableModel):
    """Researcher-authored facts required for a non-fabricated report."""

    report_title: str | None = None
    summary: str | None = None
    root_cause: str | None = None
    affected_boundary: str | None = None
    actual_behavior: str | None = None
    reproduction_steps: list[str] = Field(default_factory=list)
    technical_impact: str | None = None
    business_impact: str | None = None
    realistic_attack_scenario: str | None = None
    severity_rationale: str | None = None
    remediation: str | None = None


class EvidenceMetadata(EditableModel):
    """Researcher-editable evidence index for one hypothesis."""

    version: int = 1
    hypothesis_id: str
    test_id: str | None = None
    artifacts: list[EvidenceArtifact] = Field(default_factory=list)
    assessment: EvidenceAssessment = Field(default_factory=EvidenceAssessment)
    narrative: FindingNarrative = Field(default_factory=FindingNarrative)
    notes: str | None = None
