"""Pydantic models for Phase 1 facts and normalized endpoint knowledge."""

from datetime import datetime
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

AuthenticationType = Literal["none", "bearer", "basic", "cookie", "api_key", "mixed"]
ParameterType = Literal["string", "integer", "uuid"]
ChannelType = Literal["WEB", "MOBILE", "PARTNER_API", "PUBLIC_API", "UNKNOWN"]
ObservationSource = Literal["HAR", "BURP_XML", "CAIDO_JSON", "OPENAPI"]


class StrictModel(BaseModel):
    """Base model that rejects accidental schema drift."""

    model_config = ConfigDict(extra="forbid")


class KnowledgeStatus(StrEnum):
    """Required separation between facts and derived knowledge."""

    OBSERVED = "OBSERVED"
    INFERRED = "INFERRED"
    ASSUMED = "ASSUMED"
    CONFIRMED = "CONFIRMED"
    REFUTED = "REFUTED"


class Confidence(StrEnum):
    """Human-readable confidence for derived knowledge."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class AuthenticationObservation(StrictModel):
    """Authentication mechanism observed without retaining credentials."""

    present: bool
    observed_type: AuthenticationType
    knowledge_status: KnowledgeStatus = KnowledgeStatus.OBSERVED


class Observation(StrictModel):
    """A factual record derived from one supplied passive source entry."""

    id: str
    timestamp: datetime | None = None
    source: ObservationSource = "HAR"
    source_reference: str
    source_fingerprint: str
    actor: str = "UNKNOWN"
    channel: ChannelType = "UNKNOWN"
    host: str
    scheme: str | None = None
    method: str
    path: str
    query_parameters: dict[str, list[str]] = Field(default_factory=dict)
    request_fields: list[str] = Field(default_factory=list)
    response_fields: list[str] = Field(default_factory=list)
    status_code: int | None = None
    content_type: str | None = None
    authentication: AuthenticationObservation
    notes: str | None = None
    knowledge_status: KnowledgeStatus = KnowledgeStatus.OBSERVED


class EndpointAuthentication(StrictModel):
    """Authentication summary aggregated from source observations."""

    required: bool
    observed_type: AuthenticationType
    knowledge_status: KnowledgeStatus = KnowledgeStatus.INFERRED


class EndpointResource(StrictModel):
    """Conservative resource name inferred from the normalized path."""

    type: str
    confidence: Confidence
    knowledge_status: KnowledgeStatus = KnowledgeStatus.INFERRED


class EndpointParameter(StrictModel):
    """Observed or inferred endpoint input parameter."""

    name: str
    location: Literal["path", "query"]
    inferred_type: ParameterType
    confidence: Confidence
    evidence: list[str] = Field(default_factory=list)
    knowledge_status: KnowledgeStatus


class NormalizationEvidence(StrictModel):
    """Why concrete paths were grouped into a normalized endpoint."""

    observed_paths: list[str]
    rules: list[str] = Field(default_factory=list)


class Endpoint(StrictModel):
    """A deterministic aggregation of one or more observations."""

    id: str
    method: str
    path: str
    hosts: list[str]
    channels: list[ChannelType] = Field(default_factory=list)
    authentication: EndpointAuthentication
    resource: EndpointResource
    parameters: list[EndpointParameter] = Field(default_factory=list)
    state_change: bool
    state_change_confidence: KnowledgeStatus = KnowledgeStatus.INFERRED
    financial_impact: Literal["none", "unknown"] = "unknown"
    observed_by: list[str] = Field(default_factory=list)
    sources: list[str]
    confidence: Confidence
    knowledge_status: KnowledgeStatus = KnowledgeStatus.INFERRED
    normalization: NormalizationEvidence


class ObservationStore(StrictModel):
    """Versioned observation file persisted in a target workspace."""

    version: int = 1
    observations: list[Observation] = Field(default_factory=list)


class EndpointStore(StrictModel):
    """Versioned endpoint inventory persisted in a target workspace."""

    version: int = 1
    endpoints: list[Endpoint] = Field(default_factory=list)
