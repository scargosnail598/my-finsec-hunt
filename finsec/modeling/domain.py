"""Researcher-editable Phase 2 domain and invariant models."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from finsec.modeling.models import AuthenticationType, Confidence, KnowledgeStatus


class EditableModel(BaseModel):
    """Allow researcher annotations while validating generated core fields."""

    model_config = ConfigDict(extra="allow")


class GenerationMetadata(EditableModel):
    """Checksum metadata used to avoid overwriting researcher changes."""

    managed: bool = True
    generator: str
    generated_checksum: str
    source_fingerprint: str


class KnowledgeClaim(EditableModel):
    """A value whose evidence status is explicit."""

    value: str | None = None
    knowledge_status: KnowledgeStatus
    confidence: Confidence
    evidence: list[str] = Field(default_factory=list)


class ActorRecord(EditableModel):
    """An observed account label without an invented business role."""

    id: str
    key: str
    name: str
    category: Literal["account_label"] = "account_label"
    ownership: KnowledgeClaim
    role: KnowledgeClaim
    authentication_types: list[AuthenticationType] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)
    confidence: Confidence
    knowledge_status: KnowledgeStatus
    notes: str | None = None
    generation: GenerationMetadata | None = None


class ResourceOperation(EditableModel):
    """An endpoint-derived operation available for a resource."""

    endpoint: str
    action: str
    method: str
    path: str
    state_change: bool
    authentication_required: bool
    evidence: list[str] = Field(default_factory=list)
    knowledge_status: KnowledgeStatus = KnowledgeStatus.INFERRED


class ResourceRecord(EditableModel):
    """A backend business object inferred conservatively from endpoints."""

    id: str
    key: str
    name: str
    identifiers: list[str] = Field(default_factory=list)
    owner: KnowledgeClaim
    operations: list[ResourceOperation] = Field(default_factory=list)
    states: list[str] = Field(default_factory=list)
    sensitive_fields: list[str] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)
    confidence: Confidence
    knowledge_status: KnowledgeStatus = KnowledgeStatus.INFERRED
    notes: str | None = None
    generation: GenerationMetadata | None = None


InvariantCategory = Literal[
    "authentication",
    "authorization",
    "state_integrity",
    "single_execution",
]


class InvariantRecord(EditableModel):
    """An evidence-linked security property that is not yet a finding."""

    id: str
    key: str
    category: InvariantCategory
    statement: str
    resources: list[str] = Field(default_factory=list)
    endpoints: list[str] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)
    confidence: Confidence
    knowledge_status: KnowledgeStatus
    validation_status: Literal["NOT_CONFIRMED"] = "NOT_CONFIRMED"
    rationale: str
    notes: str | None = None
    generation: GenerationMetadata | None = None


class ActorStore(EditableModel):
    """Versioned actor model file."""

    version: int = 1
    actors: list[ActorRecord] = Field(default_factory=list)


class ResourceStore(EditableModel):
    """Versioned resource model file."""

    version: int = 1
    resources: list[ResourceRecord] = Field(default_factory=list)


class InvariantStore(EditableModel):
    """Versioned invariant model file."""

    version: int = 1
    invariants: list[InvariantRecord] = Field(default_factory=list)
