"""Canonical identifier and ownership semantics shared across the pipeline."""

from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class SemanticModel(BaseModel):
    """Reject accidental drift in persisted semantic assessments."""

    model_config = ConfigDict(extra="forbid")


class IdentifierSemanticClass(StrEnum):
    """Security meaning of one scalar identifier, independent from its shape."""

    OWNED_OBJECT = "OWNED_OBJECT"
    OBJECT_IDENTIFIER = "OBJECT_IDENTIFIER"
    SHARED_SCOPE = "SHARED_SCOPE"
    TENANT_CONTAINER = "TENANT_CONTAINER"
    PARENT_CONTAINER = "PARENT_CONTAINER"
    COLLECTION = "COLLECTION"
    ACTOR_IDENTIFIER = "ACTOR_IDENTIFIER"
    AUTH_IDENTIFIER = "AUTH_IDENTIFIER"
    REGION = "REGION"
    OPAQUE_UNKNOWN = "OPAQUE_UNKNOWN"
    NON_SECURITY_RELEVANT = "NON_SECURITY_RELEVANT"


class IdentifierResourceRole(StrEnum):
    """Structural role played by an identifier on one request surface."""

    SUBJECT = "SUBJECT"
    CHILD_OBJECT = "CHILD_OBJECT"
    PARENT = "PARENT"
    TENANT = "TENANT"
    COLLECTION = "COLLECTION"
    ACTOR = "ACTOR"
    AUTH = "AUTH"
    SHARED_SCOPE = "SHARED_SCOPE"
    UNKNOWN = "UNKNOWN"


class OwnershipState(StrEnum):
    """Evidence strength for exclusive actor control of an identifier."""

    CONFIRMED = "CONFIRMED"
    STRONG_INFERRED = "STRONG_INFERRED"
    WEAK_INFERRED = "WEAK_INFERRED"
    SHARED = "SHARED"
    UNKNOWN = "UNKNOWN"
    CONTRADICTED = "CONTRADICTED"


class IdentifierSemanticAssessment(SemanticModel):
    """Deterministic, explainable meaning assigned to one endpoint parameter."""

    semantic_class: IdentifierSemanticClass = IdentifierSemanticClass.OPAQUE_UNKNOWN
    resource_role: IdentifierResourceRole = IdentifierResourceRole.UNKNOWN
    resource_type: str | None = None
    parent_resource_type: str | None = None
    ownership_state: OwnershipState = OwnershipState.UNKNOWN
    confidence: Literal["low", "medium", "high"] = "low"
    evidence: list[str] = Field(default_factory=list)
    counterevidence: list[str] = Field(default_factory=list)
    sources: list[str] = Field(default_factory=list)
    explanation: str = "Identifier semantics are not established by current evidence."


OWNERSHIP_RELEVANT_CLASSES = frozenset({IdentifierSemanticClass.OWNED_OBJECT})
OBJECT_CANDIDATE_CLASSES = frozenset(
    {IdentifierSemanticClass.OWNED_OBJECT, IdentifierSemanticClass.OBJECT_IDENTIFIER}
)
EXECUTION_OWNERSHIP_STATES = frozenset({OwnershipState.CONFIRMED, OwnershipState.STRONG_INFERRED})


def ownership_relevant(assessment: IdentifierSemanticAssessment) -> bool:
    """Return whether this semantic target can represent an object boundary."""

    return assessment.semantic_class in OWNERSHIP_RELEVANT_CLASSES


def object_candidate(assessment: IdentifierSemanticAssessment) -> bool:
    """Return whether a scalar can identify an object without asserting ownership."""

    return assessment.semantic_class in OBJECT_CANDIDATE_CLASSES


def execution_ownership_supported(assessment: IdentifierSemanticAssessment) -> bool:
    """Return whether ownership evidence is strong enough for readiness evaluation."""

    return ownership_relevant(assessment) and assessment.ownership_state in (
        EXECUTION_OWNERSHIP_STATES
    )
