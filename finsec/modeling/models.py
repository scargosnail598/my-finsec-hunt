"""Pydantic models for factual observations and normalized endpoint knowledge."""

from datetime import datetime
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from finsec.captures.domain import CaptureMode, CaptureRelevance

AuthenticationType = Literal["none", "bearer", "basic", "cookie", "api_key", "mixed"]
ParameterType = Literal["string", "integer", "uuid", "ulid", "hash", "date", "version"]
ParameterSemanticType = Literal[
    "object_identifier",
    "monetary_value",
    "state",
    "authentication",
    "pagination",
    "unknown",
]
ParameterSource = Literal[
    "request",
    "response",
    "derived_resource_schema",
    "related_endpoint_schema",
]
OwnershipEvidenceSource = Literal[
    "RESPONSE_BODY",
    "PATH_PARENT_SCOPE",
    "CONTROLLED_LIFECYCLE",
]
OwnershipInferenceStatus = Literal["APPLIED", "REJECTED", "NOT_NEEDED"]
EndpointActionType = Literal["read", "mutation", "financial_mutation", "authentication", "unknown"]
SideEffectEvidenceKind = Literal[
    "CORRELATED_STATE_DELTA",
    "TRUSTED_CONTRACT_ANNOTATION",
    "HIGH_CONFIDENCE_SIGNAL",
]
EndpointDisposition = Literal[
    "ACTIVE",
    "SUPPRESSED_STATIC_ASSET",
    "SUPPRESSED_TELEMETRY",
    "SUPPRESSED_ANALYTICS",
    "SUPPRESSED_THIRD_PARTY",
    "SUPPRESSED_PUBLIC_RESOURCE",
    "SUPPRESSED_INSUFFICIENT_EVIDENCE",
]
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


class EndpointPrimaryClassification(StrEnum):
    """Primary traffic role used to gate downstream security analysis."""

    FIRST_PARTY_API = "FIRST_PARTY_API"
    STATIC_ASSET = "STATIC_ASSET"
    TELEMETRY = "TELEMETRY"
    ANALYTICS = "ANALYTICS"
    THIRD_PARTY = "THIRD_PARTY"
    PAGE_NAVIGATION = "PAGE_NAVIGATION"
    FILE_DOWNLOAD = "FILE_DOWNLOAD"
    AUTHENTICATION = "AUTHENTICATION"
    FINANCIAL = "FINANCIAL"
    UNKNOWN = "UNKNOWN"


class EndpointClassification(StrictModel):
    """Explainable deterministic endpoint classification."""

    primary: EndpointPrimaryClassification = EndpointPrimaryClassification.UNKNOWN
    tags: list[EndpointPrimaryClassification] = Field(default_factory=list)
    confidence: Confidence = Confidence.LOW
    reasons: list[str] = Field(default_factory=list)


class EndpointAction(StrictModel):
    """Business action separated from the inferred resource."""

    name: str = "unknown"
    type: EndpointActionType = "unknown"
    confidence: Confidence = Confidence.LOW
    reasons: list[str] = Field(default_factory=list)


class SideEffectEvidence(StrictModel):
    """Explicit evidence allowed to override the safe-method read-only default."""

    kind: SideEffectEvidenceKind
    action: str
    references: list[str] = Field(default_factory=list)
    reason: str
    confidence: Confidence = Confidence.HIGH


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
    capture_id: str | None = None
    capture_identity: str | None = None
    capture_mode: CaptureMode = CaptureMode.UNKNOWN
    capture_relevance: CaptureRelevance = CaptureRelevance.UNKNOWN
    session_identity: str | None = None
    sequence_position: int | None = Field(default=None, ge=0)
    actor: str = "UNKNOWN"
    channel: ChannelType = "UNKNOWN"
    host: str
    scheme: str | None = None
    method: str
    path: str
    concrete_url: str | None = None
    query_parameters: dict[str, list[str]] = Field(default_factory=dict)
    request_fields: list[str] = Field(default_factory=list)
    response_fields: list[str] = Field(default_factory=list)
    relevant_header_names: list[str] = Field(default_factory=list)
    redirect_target: str | None = None
    redaction_metadata: list[str] = Field(default_factory=list)
    status_code: int | None = None
    content_type: str | None = None
    authentication: AuthenticationObservation
    notes: str | None = None
    knowledge_status: KnowledgeStatus = KnowledgeStatus.OBSERVED


class EndpointAuthentication(StrictModel):
    """Authentication summary aggregated from source observations."""

    required: bool
    observed_type: AuthenticationType
    anonymous_success_observed: bool = False
    knowledge_status: KnowledgeStatus = KnowledgeStatus.INFERRED


class EndpointResource(StrictModel):
    """Conservative resource name inferred from the normalized path."""

    type: str
    confidence: Confidence
    knowledge_status: KnowledgeStatus = KnowledgeStatus.INFERRED


class EndpointParameter(StrictModel):
    """Observed or inferred endpoint input parameter."""

    name: str
    location: Literal[
        "path",
        "query",
        "body",
        "header",
        "cookie",
        "graphql_variable",
        "response_body",
    ]
    source: ParameterSource = "request"
    inferred_type: ParameterType
    confidence: Confidence
    evidence: list[str] = Field(default_factory=list)
    knowledge_status: KnowledgeStatus
    json_path: str | None = None
    semantic_type: ParameterSemanticType = "unknown"
    client_controlled: bool = True
    original_examples: list[str] = Field(default_factory=list)
    normalization_reasons: list[str] = Field(default_factory=list)


class NormalizationEvidence(StrictModel):
    """Why concrete paths were grouped into a normalized endpoint."""

    observed_paths: list[str]
    rules: list[str] = Field(default_factory=list)


class ActorObjectBaseline(StrictModel):
    """Redacted passive evidence associating one controlled actor with one object."""

    actor: str
    requested_value: str
    response_object_path: str | None = None
    owner_value_fingerprint: str | None = None
    scope_value_fingerprint: str | None = None
    subject_resource_id: str | None = None
    parent_resource_id: str | None = None
    parent_resource_type: str | None = None
    parent_value: str | None = None
    endpoint_id: str | None = None
    baseline_id: str | None = None
    relationship_ids: list[str] = Field(default_factory=list)
    capture_ids: list[str] = Field(default_factory=list)
    session_ids: list[str] = Field(default_factory=list)
    operation: Literal["READ", "CREATE", "UPDATE", "DELETE", "ACTION"] | None = None
    authentication_type: str | None = None
    observations: list[str] = Field(default_factory=list)


class ObjectAccessEvidence(StrictModel):
    """Cross-actor object and owner signals for one client-controlled identifier."""

    identifier: str
    source: OwnershipEvidenceSource = "RESPONSE_BODY"
    confidence: Confidence = Confidence.HIGH
    owner_field_path: str | None = None
    scope_parameter: str | None = None
    baselines: list[ActorObjectBaseline] = Field(default_factory=list)
    distinct_actors: int = Field(default=0, ge=0)
    distinct_objects: int = Field(default=0, ge=0)
    distinct_owner_values: int = Field(default=0, ge=0)
    distinct_scope_values: int = Field(default=0, ge=0)
    distinct_parent_values: int = Field(default=0, ge=0)
    actor_object_binding_observed: bool = False
    relationship_ids: list[str] = Field(default_factory=list)
    baseline_ids: list[str] = Field(default_factory=list)
    counterevidence: list[str] = Field(default_factory=list)
    ambiguity: list[str] = Field(default_factory=list)


class OwnershipInference(StrictModel):
    """Explain one path-scope fallback decision without retaining concrete identifiers."""

    parameter: str
    classification: Literal[
        "TRUSTED_PARENT_SCOPE",
        "PUBLIC_SHARED_SCOPE",
        "UNCLASSIFIED",
    ]
    status: OwnershipInferenceStatus
    controlled_actors: int = Field(default=0, ge=0)
    distinct_scope_values: int = Field(default=0, ge=0)
    observations: list[str] = Field(default_factory=list)
    reasons: list[str] = Field(default_factory=list)


class Endpoint(StrictModel):
    """A deterministic aggregation of one or more observations."""

    id: str
    method: str
    path: str
    hosts: list[str]
    channels: list[ChannelType] = Field(default_factory=list)
    authentication: EndpointAuthentication
    classification: EndpointClassification = Field(default_factory=EndpointClassification)
    resource: EndpointResource
    action: EndpointAction = Field(default_factory=EndpointAction)
    parameters: list[EndpointParameter] = Field(default_factory=list)
    object_access: list[ObjectAccessEvidence] = Field(default_factory=list)
    ownership_inference: list[OwnershipInference] = Field(default_factory=list)
    state_change: bool
    state_change_confidence: KnowledgeStatus = KnowledgeStatus.INFERRED
    state_change_reasons: list[str] = Field(default_factory=list)
    side_effect_evidence: list[SideEffectEvidence] = Field(default_factory=list)
    financial_impact: Literal["none", "unknown"] = "unknown"
    security_relevance: int = Field(default=0, ge=0, le=10)
    relevance_reasons: list[str] = Field(default_factory=list)
    disposition: EndpointDisposition = "ACTIVE"
    observed_by: list[str] = Field(default_factory=list)
    baseline_observed_by: list[str] = Field(default_factory=list)
    capture_modes: list[CaptureMode] = Field(default_factory=list)
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

    version: int = 2
    endpoints: list[Endpoint] = Field(default_factory=list)
