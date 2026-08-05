"""Typed hypothesis, scoring, and mutation models."""

from typing import Literal, Self

from pydantic import Field, model_validator

from finsec.modeling.domain import EditableModel, GenerationMetadata
from finsec.modeling.models import KnowledgeStatus

MutationDimension = Literal[
    "ACTOR",
    "OBJECT",
    "STATE",
    "TIME",
    "VALUE",
    "CHANNEL",
    "VERSION",
    "WORKFLOW",
    "CONCURRENCY",
]
HypothesisPriority = Literal["P1", "P2", "P3"]
HypothesisStatus = Literal[
    "NOT_TESTED",
    "TEST_PLANNED",
    "REFUTED",
    "NEEDS_EVIDENCE",
    "CONFIRMED",
]
ImpactLevel = Literal["none", "low", "medium", "high", "unknown"]
BusinessEpistemicStatus = Literal[
    "OBSERVED_FACT",
    "INFERRED_PATTERN",
    "RESEARCH_TASK",
    "TEST_CANDIDATE",
    "TEST_PLANNED",
    "NEEDS_EVIDENCE",
    "REJECTED_BY_BACKEND",
    "CONFIRMED",
]
HypothesisReadiness = Literal["RESEARCH_ONLY", "REVIEW_REQUIRED", "TEST_READY"]


class HypothesisSource(EditableModel):
    """Traceability from a hypothesis back to model artifacts."""

    endpoints: list[str] = Field(default_factory=list)
    invariants: list[str] = Field(default_factory=list)
    observations: list[str] = Field(default_factory=list)


class HypothesisScores(EditableModel):
    """Transparent 1-5 scoring with a validated additive total."""

    impact: int = Field(ge=1, le=5)
    likelihood: int = Field(ge=1, le=5)
    confidence: int = Field(ge=1, le=5)
    testability: int = Field(ge=1, le=5)
    total: int = Field(ge=4, le=20)

    @model_validator(mode="after")
    def total_matches_components(self) -> Self:
        expected = self.impact + self.likelihood + self.confidence + self.testability
        if self.total != expected:
            raise ValueError(f"score total must equal {expected}")
        return self


class PotentialImpact(EditableModel):
    """Impact dimensions kept separate to avoid severity inflation."""

    confidentiality: ImpactLevel = "none"
    integrity: ImpactLevel = "none"
    availability: ImpactLevel = "none"
    financial: ImpactLevel = "unknown"


class HypothesisRecord(EditableModel):
    """A specific, testable, evidence-backed research hypothesis."""

    id: str
    key: str
    title: str
    kind: Literal["SECURITY_HYPOTHESIS", "RESEARCH_TASK"] = "SECURITY_HYPOTHESIS"
    disposition: Literal[
        "ACTIVE",
        "SUPPRESSED_STATIC_ASSET",
        "SUPPRESSED_TELEMETRY",
        "SUPPRESSED_THIRD_PARTY",
        "SUPPRESSED_PUBLIC_RESOURCE",
        "SUPPRESSED_INSUFFICIENT_EVIDENCE",
        "SUPPRESSED_DUPLICATE",
        "NEEDS_RESEARCH",
    ] = "ACTIVE"
    category: Literal[
        "authentication",
        "authorization",
        "state_integrity",
        "replay",
        "value_validation",
        "version_parity",
        "channel_parity",
        "research",
        "business_logic",
    ]
    component: str
    source: HypothesisSource
    invariant: list[str] = Field(default_factory=list)
    observations: list[str] = Field(default_factory=list)
    mutation_dimensions: list[MutationDimension]
    required_state: list[str] = Field(default_factory=list)
    attacker_capability: list[str] = Field(default_factory=list)
    evidence_status: KnowledgeStatus
    hypothesis: str
    reasoning: str
    preconditions: list[str]
    expected_secure_behavior: str
    possible_vulnerable_behavior: str
    potential_impact: PotentialImpact
    evidence_to_collect: list[str]
    eligibility_evidence: list[str] = Field(default_factory=list)
    missing_evidence: list[str] = Field(default_factory=list)
    generation_rule: dict[str, str] = Field(default_factory=dict)
    priority_rationale: list[str] = Field(default_factory=list)
    scores: HypothesisScores
    priority: HypothesisPriority
    status: HypothesisStatus = "NOT_TESTED"
    safety_notes: list[str] = Field(default_factory=list)
    readiness: HypothesisReadiness = "TEST_READY"
    epistemic_status: BusinessEpistemicStatus | None = None
    logic_details: dict[str, object] | None = None
    notes: str | None = None
    generation: GenerationMetadata | None = None


class HypothesisStore(EditableModel):
    """Versioned hypothesis backlog."""

    version: int = 2
    hypotheses: list[HypothesisRecord] = Field(default_factory=list)
