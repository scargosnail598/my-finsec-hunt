"""Canonical session-capture contracts and downstream evidence semantics."""

import re
from datetime import datetime
from enum import StrEnum
from typing import Protocol

from pydantic import BaseModel, ConfigDict, Field, field_validator


class CaptureModel(BaseModel):
    """Reject accidental capture-schema drift."""

    model_config = ConfigDict(extra="forbid")


class CaptureSourceType(StrEnum):
    """Passive source adapters supported by the capture context layer."""

    HAR = "HAR"
    BURP_XML = "BURP_XML"
    CAIDO_JSON = "CAIDO_JSON"
    LEGACY = "LEGACY"


class CaptureMode(StrEnum):
    """Researcher intent governing how downstream engines interpret evidence."""

    NORMAL_BEHAVIOR = "NORMAL_BEHAVIOR"
    RESEARCHER_PROBE = "RESEARCHER_PROBE"
    AUTHENTICATION = "AUTHENTICATION"
    MIXED = "MIXED"
    UNKNOWN = "UNKNOWN"


class MetadataSource(StrEnum):
    """Provenance for actor, mode, and intent metadata."""

    ENGINE_INFERRED = "ENGINE_INFERRED"
    ENGINE_INFERRED_RAW = "ENGINE_INFERRED_RAW"
    ENGINE_REFINED = "ENGINE_REFINED"
    USER_CONFIRMED = "USER_CONFIRMED"
    USER_SUPPLIED = "USER_SUPPLIED"
    UNKNOWN = "UNKNOWN"


class CaptureConfidence(StrEnum):
    """Human-readable confidence for capture-level analysis."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class CaptureRelevance(StrEnum):
    """Soft relevance of an observation to the reported capture intent."""

    PRIMARY = "PRIMARY"
    SUPPORTING = "SUPPORTING"
    CONTEXT = "CONTEXT"
    NOISE = "NOISE"
    PROTOCOL_SUPPORT = "PROTOCOL_SUPPORT"
    UNKNOWN = "UNKNOWN"


class CaptureQualityLabel(StrEnum):
    """Non-blocking capture-corpus diagnostics."""

    FOCUSED = "FOCUSED"
    BROAD = "BROAD"
    MIXED = "MIXED"
    LOW_SIGNAL = "LOW_SIGNAL"
    AUTH_HEAVY = "AUTH_HEAVY"
    MULTI_INTENT = "MULTI_INTENT"


class IntentAnalysisStage(StrEnum):
    """Evidence stage used to derive the observed capture intent."""

    PROVISIONAL = "PROVISIONAL"
    REFINED = "REFINED"


class IntentAlignment(StrEnum):
    """Relationship between explicit researcher context and observed semantics."""

    CONSISTENT = "CONSISTENT"
    PARTIAL = "PARTIAL"
    CONFLICTING = "CONFLICTING"
    UNKNOWN = "UNKNOWN"


class CaptureSource(CaptureModel):
    """Traceable source metadata without copying raw source contents."""

    type: CaptureSourceType
    file: str
    fingerprint: str
    redacted_reference: str | None = None


class CaptureIntent(CaptureModel):
    """Minimal high-level human or engine context for one journey."""

    label: str = "unknown"
    action: str = "UNKNOWN"
    resource_type: str = "unknown"
    confidence: CaptureConfidence = CaptureConfidence.LOW
    source: MetadataSource = MetadataSource.UNKNOWN

    @field_validator("action")
    @classmethod
    def normalize_action(cls, value: str) -> str:
        normalized = re.sub(r"[^A-Za-z0-9]+", "_", value.strip()).strip("_").upper()
        return normalized or "UNKNOWN"

    @field_validator("resource_type")
    @classmethod
    def normalize_resource(cls, value: str) -> str:
        normalized = re.sub(r"[^a-z0-9]+", "_", value.strip().lower()).strip("_")
        return normalized or "unknown"

    @field_validator("label")
    @classmethod
    def normalize_label(cls, value: str) -> str:
        normalized = re.sub(r"[^a-z0-9]+", "_", value.strip().lower()).strip("_")
        return normalized or "unknown"


class IntentInference(CaptureModel):
    """Explainable deterministic intent proposal retained independently of confirmation."""

    proposed_action: str = "UNKNOWN"
    proposed_resource: str = "unknown"
    confidence: CaptureConfidence = CaptureConfidence.LOW
    evidence: list[str] = Field(default_factory=list)

    @field_validator("proposed_action")
    @classmethod
    def normalize_action(cls, value: str) -> str:
        return CaptureIntent(action=value).action

    @field_validator("proposed_resource")
    @classmethod
    def normalize_resource(cls, value: str) -> str:
        return CaptureIntent(resource_type=value).resource_type


class JourneyAnchor(CaptureModel):
    """One explainable operation candidate for the center of a capture journey."""

    anchor_id: str
    observation_ids: list[str] = Field(default_factory=list)
    endpoint_ids: list[str] = Field(default_factory=list)
    action: str = "UNKNOWN"
    resource_type: str = "unknown"
    parent_resource_type: str | None = None
    subject_selector: str | None = None
    method: str
    path: str
    status_code: int | None = None
    score: int = Field(default=0, ge=0)
    confidence: CaptureConfidence = CaptureConfidence.LOW
    state_changing: bool = False
    evidence: list[str] = Field(default_factory=list)

    @field_validator("action")
    @classmethod
    def normalize_action(cls, value: str) -> str:
        return CaptureIntent(action=value).action

    @field_validator("resource_type", "parent_resource_type")
    @classmethod
    def normalize_resource(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return CaptureIntent(resource_type=value).resource_type


class CaptureAnalysisMetrics(CaptureModel):
    """Deterministic diagnostics for anchor precision and excluded traffic."""

    protocol_requests_excluded: int = Field(default=0, ge=0)
    background_requests_excluded: int = Field(default=0, ge=0)
    passive_observations: int = Field(default=0, ge=0)
    passive_operation_groups: int = Field(default=0, ge=0)
    repeated_passive_observations_saturated: int = Field(default=0, ge=0)
    anchor_candidates: int = Field(default=0, ge=0)


class CaptureQuality(CaptureModel):
    """Advisory quality assessment that never blocks ingestion."""

    labels: list[CaptureQualityLabel] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)
    recommendation: str | None = None


class CaptureCounts(CaptureModel):
    """Researcher-facing capture composition counts."""

    observations: int = Field(default=0, ge=0)
    first_party: int = Field(default=0, ge=0)
    state_changing: int = Field(default=0, ge=0)
    primary: int = Field(default=0, ge=0)
    supporting: int = Field(default=0, ge=0)
    context: int = Field(default=0, ge=0)
    noise: int = Field(default=0, ge=0)
    protocol_support: int = Field(default=0, ge=0)
    unknown: int = Field(default=0, ge=0)


class Capture(CaptureModel):
    """One logical researcher-observed application journey."""

    capture_id: str
    source: CaptureSource
    actor_id: str = "UNKNOWN"
    actor_source: MetadataSource = MetadataSource.UNKNOWN
    actor_confidence: CaptureConfidence = CaptureConfidence.LOW
    actor_evidence: list[str] = Field(default_factory=list)
    capture_mode: CaptureMode = CaptureMode.UNKNOWN
    capture_mode_source: MetadataSource = MetadataSource.UNKNOWN
    intent: CaptureIntent = Field(default_factory=CaptureIntent)
    declared_intent: CaptureIntent | None = None
    provisional_intent: CaptureIntent = Field(default_factory=CaptureIntent)
    observed_intent: CaptureIntent = Field(default_factory=CaptureIntent)
    intent_alignment: IntentAlignment = IntentAlignment.UNKNOWN
    intent_analysis_stage: IntentAnalysisStage = IntentAnalysisStage.PROVISIONAL
    intent_inference: IntentInference = Field(default_factory=IntentInference)
    journey_anchors: list[JourneyAnchor] = Field(default_factory=list)
    primary_anchor_id: str | None = None
    analysis_metrics: CaptureAnalysisMetrics = Field(default_factory=CaptureAnalysisMetrics)
    started_at: datetime | None = None
    ended_at: datetime | None = None
    notes: list[str] = Field(default_factory=list)
    observation_ids: list[str] = Field(default_factory=list)
    observation_relevance: dict[str, CaptureRelevance] = Field(default_factory=dict)
    counts: CaptureCounts = Field(default_factory=CaptureCounts)
    quality: CaptureQuality = Field(default_factory=CaptureQuality)
    warnings: list[str] = Field(default_factory=list)
    legacy: bool = False

    @field_validator("capture_id")
    @classmethod
    def capture_id_is_stable_and_readable(cls, value: str) -> str:
        normalized = value.strip().upper()
        if re.fullmatch(r"CAP-[A-Z0-9-]{8,32}", normalized) is None:
            raise ValueError(
                "capture_id must use CAP- followed by 8-32 letters, digits, or hyphens"
            )
        return normalized


class CaptureStore(CaptureModel):
    """Versioned, human-readable workspace capture registry."""

    version: int = 1
    captures: list[Capture] = Field(default_factory=list)


class CaptureAssignment(CaptureModel):
    """Capture context supplied by a CLI, manifest, MCP, or future source adapter."""

    actor_source: MetadataSource = MetadataSource.UNKNOWN
    actor_confidence: CaptureConfidence = CaptureConfidence.LOW
    actor_evidence: list[str] = Field(default_factory=list)
    capture_mode: CaptureMode = CaptureMode.UNKNOWN
    capture_mode_source: MetadataSource = MetadataSource.UNKNOWN
    intent: CaptureIntent | None = None
    notes: list[str] = Field(default_factory=list)


class CaptureAwareObservation(Protocol):
    """Structural subset used to avoid coupling evidence policy to observation storage."""

    capture_id: str | None
    capture_mode: CaptureMode
    capture_relevance: CaptureRelevance
    method: str


def observation_is_probe_evidence(observation: CaptureAwareObservation) -> bool:
    """Return whether an observation represents manipulated or inseparable testing traffic."""

    return observation.capture_mode in {CaptureMode.RESEARCHER_PROBE, CaptureMode.MIXED}


def observation_supports_passive_baseline(observation: CaptureAwareObservation) -> bool:
    """Return whether traffic may support endpoint hypotheses and passive baselines."""

    if observation_is_probe_evidence(observation):
        return False
    if observation.method in {"HEAD", "OPTIONS"}:
        return False
    if observation.capture_mode == CaptureMode.UNKNOWN:
        return observation.capture_id is None
    return observation.capture_relevance not in {
        CaptureRelevance.CONTEXT,
        CaptureRelevance.NOISE,
        CaptureRelevance.PROTOCOL_SUPPORT,
    }


def observation_supports_normal_behavior(observation: CaptureAwareObservation) -> bool:
    """Return whether traffic may contribute to ordinary workflows and ownership inference."""

    if observation.method in {"HEAD", "OPTIONS"}:
        return False
    if observation.capture_mode == CaptureMode.UNKNOWN:
        return observation.capture_id is None
    return observation.capture_mode == CaptureMode.NORMAL_BEHAVIOR and (
        observation.capture_relevance
        not in {
            CaptureRelevance.CONTEXT,
            CaptureRelevance.NOISE,
            CaptureRelevance.PROTOCOL_SUPPORT,
        }
    )


def observation_supports_ownership_baseline(observation: CaptureAwareObservation) -> bool:
    """Require explicit normal behavior for new ownership claims while preserving legacy facts."""

    if observation.method in {"HEAD", "OPTIONS"}:
        return False
    if observation.capture_id is None and observation.capture_mode == CaptureMode.UNKNOWN:
        return True
    return (
        observation.capture_mode == CaptureMode.NORMAL_BEHAVIOR
        and observation.capture_relevance
        not in {
            CaptureRelevance.CONTEXT,
            CaptureRelevance.NOISE,
            CaptureRelevance.PROTOCOL_SUPPORT,
        }
    )
