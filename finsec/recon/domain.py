"""Typed passive discovery inventories for GraphQL and mobile artifacts."""

from typing import Literal

from pydantic import Field

from finsec.modeling.domain import EditableModel, GenerationMetadata
from finsec.modeling.models import Confidence, KnowledgeStatus


class GraphQLArgument(EditableModel):
    """One documented GraphQL field argument."""

    name: str
    type: str


class GraphQLOperation(EditableModel):
    """A GraphQL root field observed in supplied schema evidence."""

    id: str
    key: str
    operation_type: Literal["query", "mutation", "subscription"]
    field: str
    arguments: list[GraphQLArgument] = Field(default_factory=list)
    return_type: str
    endpoint: str | None = None
    sources: list[str] = Field(default_factory=list)
    confidence: Confidence = Confidence.HIGH
    knowledge_status: KnowledgeStatus = KnowledgeStatus.OBSERVED
    notes: str | None = None
    generation: GenerationMetadata | None = None


class GraphQLStore(EditableModel):
    """Versioned GraphQL operation inventory."""

    version: int = 1
    operations: list[GraphQLOperation] = Field(default_factory=list)


MobileDiscoveryKind = Literal[
    "BASE_URL",
    "API_PATH",
    "GRAPHQL_ENDPOINT",
    "WEBSOCKET",
    "DEEP_LINK",
    "CUSTOM_HEADER",
]


class MobileDiscovery(EditableModel):
    """One string-level architecture lead from an authorized mobile artifact."""

    id: str
    key: str
    kind: MobileDiscoveryKind
    value: str
    sources: list[str] = Field(default_factory=list)
    channel: Literal["MOBILE"] = "MOBILE"
    confidence: Confidence
    knowledge_status: KnowledgeStatus = KnowledgeStatus.OBSERVED
    notes: str
    generation: GenerationMetadata | None = None


class MobileDiscoveryStore(EditableModel):
    """Versioned static mobile discovery inventory."""

    version: int = 1
    discoveries: list[MobileDiscovery] = Field(default_factory=list)
