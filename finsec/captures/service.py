"""Workspace persistence and observation association for session captures."""

from __future__ import annotations

import hashlib
from collections import Counter, defaultdict
from pathlib import Path

from pydantic import ValidationError

from finsec.captures.analysis import (
    CaptureSignal,
    IntentAnalysis,
    align_intents,
    assess_quality,
    classify_relevance,
    infer_intent,
    inferred_intent,
)
from finsec.captures.domain import (
    Capture,
    CaptureAssignment,
    CaptureConfidence,
    CaptureCounts,
    CaptureIntent,
    CaptureMode,
    CaptureQualityLabel,
    CaptureRelevance,
    CaptureSource,
    CaptureSourceType,
    CaptureStore,
    IntentAlignment,
    MetadataSource,
)
from finsec.config.models import DomainIntentRule, TargetDocument
from finsec.config.scope import host_is_covered
from finsec.config.workspace import WorkspacePaths
from finsec.errors import FinsecError
from finsec.modeling.models import Endpoint, EndpointStore, Observation, ObservationStore
from finsec.utils.yaml_store import load_yaml, write_yaml


def capture_id_for(source_type: CaptureSourceType, fingerprint: str) -> str:
    """Return a stable source-content identity independent of observation numbering."""

    digest = hashlib.sha256(f"{source_type.value}\0{fingerprint}".encode()).hexdigest()
    return f"CAP-{digest[:12].upper()}"


def load_capture_store(workspace: WorkspacePaths) -> CaptureStore:
    """Load the capture registry, treating its absence as a legacy empty store."""

    if not workspace.captures.is_file():
        return CaptureStore()
    try:
        return CaptureStore.model_validate(load_yaml(workspace.captures))
    except (OSError, ValidationError) as error:
        raise FinsecError(f"Cannot read capture store {workspace.captures}: {error}") from error


def _load_observations(workspace: WorkspacePaths) -> ObservationStore:
    try:
        return ObservationStore.model_validate(load_yaml(workspace.observations))
    except (OSError, ValidationError) as error:
        raise FinsecError(
            f"Cannot read observation store {workspace.observations}: {error}"
        ) from error


def _load_target(workspace: WorkspacePaths) -> TargetDocument:
    try:
        return TargetDocument.model_validate(load_yaml(workspace.target))
    except (OSError, ValidationError) as error:
        raise FinsecError(
            f"Cannot read target configuration {workspace.target}: {error}"
        ) from error


USER_INTENT_SOURCES = {MetadataSource.USER_CONFIRMED, MetadataSource.USER_SUPPLIED}


def _endpoints_by_observation(workspace: WorkspacePaths) -> dict[str, Endpoint]:
    if not workspace.endpoints.is_file():
        return {}
    try:
        endpoints = EndpointStore.model_validate(load_yaml(workspace.endpoints))
    except (OSError, ValidationError):
        return {}
    return {
        observation_id: endpoint
        for endpoint in endpoints.endpoints
        for observation_id in endpoint.sources
    }


def _relative_capture_reference(workspace: WorkspacePaths, path: Path) -> str:
    try:
        return path.resolve().relative_to(workspace.root.resolve()).as_posix()
    except ValueError as error:
        raise FinsecError(
            "Redacted capture must be stored inside the selected workspace."
        ) from error


def _first_party_patterns(target: TargetDocument) -> list[str]:
    return target.analysis.include_hosts or target.scope.hosts


def _signals(
    observations: list[Observation],
    target: TargetDocument,
    endpoints_by_observation: dict[str, Endpoint],
) -> list[CaptureSignal]:
    patterns = _first_party_patterns(target)
    ordered = sorted(
        observations,
        key=lambda item: (
            item.sequence_position if item.sequence_position is not None else 10**9,
            item.timestamp.isoformat() if item.timestamp is not None else "",
            item.id,
        ),
    )
    domain_rules: dict[tuple[str, str], DomainIntentRule] = {
        (item.method, item.path): item for item in target.analysis.domain_intent_rules
    }
    signals: list[CaptureSignal] = []
    for index, item in enumerate(ordered):
        endpoint = endpoints_by_observation.get(item.id)
        domain_rule = (
            domain_rules.get((endpoint.method, endpoint.path)) if endpoint is not None else None
        )
        signals.append(
            CaptureSignal(
                observation_id=item.id,
                position=index,
                host=item.host,
                method=item.method,
                path=item.path,
                status_code=item.status_code,
                first_party=host_is_covered(item.host, patterns) if patterns else True,
                endpoint_id=endpoint.id if endpoint is not None else None,
                endpoint_disposition=endpoint.disposition if endpoint is not None else None,
                endpoint_classification=(
                    endpoint.classification.primary.value if endpoint is not None else None
                ),
                endpoint_action=endpoint.action.name if endpoint is not None else None,
                endpoint_action_type=endpoint.action.type if endpoint is not None else None,
                endpoint_resource=endpoint.resource.type if endpoint is not None else None,
                endpoint_state_change=endpoint.state_change if endpoint is not None else False,
                endpoint_reasons=(
                    tuple([*endpoint.action.reasons, *endpoint.state_change_reasons])
                    if endpoint is not None
                    else ()
                ),
                domain_operation=domain_rule.operation if domain_rule is not None else None,
                domain_subject_resource=(
                    domain_rule.subject_resource if domain_rule is not None else None
                ),
                domain_parent_resource=(
                    domain_rule.parent_resource if domain_rule is not None else None
                ),
                domain_evidence=(
                    (f"Reviewed domain-intent rule: {domain_rule.rationale}",)
                    if domain_rule is not None
                    else ()
                ),
            )
        )
    return signals


def _selected_context(
    existing: Capture | None,
    actor_id: str,
    assignment: CaptureAssignment,
) -> tuple[
    MetadataSource,
    CaptureConfidence,
    CaptureMode,
    MetadataSource,
    CaptureIntent | None,
]:
    actor_source = assignment.actor_source
    actor_confidence = assignment.actor_confidence
    if actor_id != "UNKNOWN" and actor_source == MetadataSource.UNKNOWN:
        actor_source = MetadataSource.USER_SUPPLIED
        actor_confidence = CaptureConfidence.HIGH
    elif actor_id != "UNKNOWN" and actor_source in {
        MetadataSource.USER_CONFIRMED,
        MetadataSource.USER_SUPPLIED,
    }:
        actor_confidence = CaptureConfidence.HIGH
    if existing is not None and assignment.actor_source == MetadataSource.UNKNOWN:
        actor_source = existing.actor_source
        actor_confidence = existing.actor_confidence

    capture_mode = assignment.capture_mode
    capture_mode_source = assignment.capture_mode_source
    if existing is not None and capture_mode_source == MetadataSource.UNKNOWN:
        capture_mode = existing.capture_mode
        capture_mode_source = existing.capture_mode_source

    declared_intent = assignment.intent
    if declared_intent is None and existing is not None:
        if existing.declared_intent is not None:
            declared_intent = existing.declared_intent
        elif existing.intent.source in USER_INTENT_SOURCES:
            declared_intent = existing.intent
    return (
        actor_source,
        actor_confidence,
        capture_mode,
        capture_mode_source,
        declared_intent,
    )


def _actor_evidence(
    existing: Capture | None,
    assignment: CaptureAssignment,
    actor_id: str,
    actor_source: MetadataSource,
) -> list[str]:
    evidence = (
        list(existing.actor_evidence)
        if existing is not None and existing.actor_id == actor_id
        else []
    )
    evidence.extend(assignment.actor_evidence)
    if not evidence and actor_id != "UNKNOWN":
        evidence.append(f"Actor label was assigned with {actor_source.value} provenance.")
    return list(dict.fromkeys(evidence))


def _counts(signals: list[CaptureSignal], relevance: dict[str, CaptureRelevance]) -> CaptureCounts:
    distribution = Counter(relevance.values())
    return CaptureCounts(
        observations=len(signals),
        first_party=sum(item.first_party for item in signals),
        state_changing=sum(item.method in {"POST", "PUT", "PATCH", "DELETE"} for item in signals),
        primary=distribution[CaptureRelevance.PRIMARY],
        supporting=distribution[CaptureRelevance.SUPPORTING],
        context=distribution[CaptureRelevance.CONTEXT],
        noise=distribution[CaptureRelevance.NOISE],
        protocol_support=distribution[CaptureRelevance.PROTOCOL_SUPPORT],
        unknown=distribution[CaptureRelevance.UNKNOWN],
    )


def _contextual_relevance(
    signals: list[CaptureSignal],
    observed_intent: CaptureIntent,
    declared_intent: CaptureIntent | None,
    analysis: IntentAnalysis,
    mode_source: MetadataSource,
    infer_intent_enabled: bool,
) -> dict[str, CaptureRelevance]:
    declared_source = (
        declared_intent.source if declared_intent is not None else MetadataSource.UNKNOWN
    )
    if mode_source not in USER_INTENT_SOURCES and declared_source not in USER_INTENT_SOURCES:
        return classify_relevance(signals, CaptureIntent(), analysis)
    if not infer_intent_enabled and declared_intent is None:
        return classify_relevance(signals, CaptureIntent(), analysis)
    return classify_relevance(signals, observed_intent, analysis)


def _warnings(
    actor_id: str,
    mode: CaptureMode,
    quality_labels: list[CaptureQualityLabel],
    alignment: IntentAlignment = IntentAlignment.UNKNOWN,
    observed_confidence: CaptureConfidence = CaptureConfidence.LOW,
) -> list[str]:
    warnings: list[str] = []
    if actor_id == "UNKNOWN":
        warnings.append("Actor identity is unresolved; actor-specific comparisons remain weak.")
    if mode == CaptureMode.RESEARCHER_PROBE:
        warnings.append(
            "Researcher-probe traffic is retained as test evidence and excluded from normal "
            "workflow and ownership baselines."
        )
    elif mode == CaptureMode.MIXED:
        warnings.append(
            "Mixed normal/probe traffic is excluded from normal workflow and ownership baselines."
        )
    elif mode == CaptureMode.UNKNOWN:
        warnings.append(
            "Capture mode is unknown; this new capture is not used as a normal-behavior baseline."
        )
    if CaptureQualityLabel.BROAD in quality_labels:
        warnings.append("Broad capture content may reduce workflow precision.")
    if CaptureQualityLabel.MULTI_INTENT in quality_labels:
        warnings.append("Multiple state-changing intent groups were detected.")
    if alignment == IntentAlignment.CONFLICTING and observed_confidence != CaptureConfidence.LOW:
        warnings.append(
            "Declared intent conflicts with the observed journey anchor; both are preserved for "
            "researcher review."
        )
    return warnings


def associate_capture(
    workspace: WorkspacePaths,
    *,
    source_type: CaptureSourceType,
    source_file: Path,
    source_fingerprint: str,
    redacted_capture: Path,
    actor_id: str,
    assignment: CaptureAssignment | None = None,
) -> Capture:
    """Create or refresh one capture after generic source ingestion has completed."""

    selected_assignment = assignment or CaptureAssignment()
    observation_store = _load_observations(workspace)
    redacted_reference = _relative_capture_reference(workspace, redacted_capture)
    capture_id = capture_id_for(source_type, source_fingerprint)
    associated = [
        item
        for item in observation_store.observations
        if item.capture_id == capture_id
        or item.capture_identity == redacted_reference
        or item.source_reference.startswith(f"{redacted_reference}#")
    ]
    if not associated:
        raise FinsecError("No observations were associated with the redacted capture.")

    target = _load_target(workspace)
    signals = _signals(associated, target, {})
    analysis = infer_intent(signals)
    provisional_intent = inferred_intent(analysis)
    store = load_capture_store(workspace)
    existing = next((item for item in store.captures if item.capture_id == capture_id), None)
    if existing is None and selected_assignment.capture_mode_source == MetadataSource.UNKNOWN:
        selected_assignment = selected_assignment.model_copy(
            update={
                "capture_mode": CaptureMode(target.capture_policy.default_mode),
                "capture_mode_source": MetadataSource.ENGINE_INFERRED,
            }
        )
    actor_source, actor_confidence, mode, mode_source, declared_intent = _selected_context(
        existing,
        actor_id,
        selected_assignment,
    )
    observed_intent = provisional_intent
    effective_intent = declared_intent or (
        observed_intent if target.capture_policy.infer_intent else CaptureIntent()
    )
    alignment = align_intents(declared_intent, observed_intent)
    relevance = _contextual_relevance(
        signals,
        observed_intent,
        declared_intent,
        analysis,
        mode_source,
        target.capture_policy.infer_intent,
    )
    quality = assess_quality(signals, analysis, relevance)
    if mode == CaptureMode.MIXED and CaptureQualityLabel.MIXED not in quality.labels:
        quality = quality.model_copy(
            update={"labels": [CaptureQualityLabel.MIXED, *quality.labels]}
        )
    timestamps = sorted(item.timestamp for item in associated if item.timestamp is not None)
    capture = Capture(
        capture_id=capture_id,
        source=CaptureSource(
            type=source_type,
            file=source_file.name,
            fingerprint=source_fingerprint,
            redacted_reference=redacted_reference,
        ),
        actor_id=actor_id,
        actor_source=actor_source,
        actor_confidence=actor_confidence,
        actor_evidence=_actor_evidence(existing, selected_assignment, actor_id, actor_source),
        capture_mode=mode,
        capture_mode_source=mode_source,
        intent=effective_intent,
        declared_intent=declared_intent,
        provisional_intent=provisional_intent,
        observed_intent=observed_intent,
        intent_alignment=alignment,
        intent_analysis_stage=analysis.stage,
        intent_inference=analysis.inference,
        journey_anchors=list(analysis.anchors),
        primary_anchor_id=analysis.primary_anchor_id,
        analysis_metrics=analysis.metrics,
        started_at=timestamps[0] if timestamps else None,
        ended_at=timestamps[-1] if timestamps else None,
        notes=list(
            dict.fromkeys([*(existing.notes if existing else []), *selected_assignment.notes])
        ),
        observation_ids=sorted(item.id for item in associated),
        observation_relevance={key: relevance[key] for key in sorted(relevance)},
        counts=_counts(signals, relevance),
        quality=quality,
        warnings=_warnings(
            actor_id,
            mode,
            quality.labels,
            alignment,
            observed_intent.confidence,
        ),
    )

    for observation in associated:
        observation.capture_id = capture_id
        observation.capture_mode = mode
        observation.capture_relevance = relevance.get(observation.id, CaptureRelevance.UNKNOWN)
        observation.session_identity = f"{actor_id}:{capture_id}"
    write_yaml(
        workspace.observations,
        observation_store.model_dump(mode="json", exclude_none=True),
    )
    by_id = {item.capture_id: item for item in store.captures}
    by_id[capture_id] = capture
    write_yaml(
        workspace.captures,
        CaptureStore(captures=[by_id[key] for key in sorted(by_id)]).model_dump(
            mode="json", exclude_none=True
        ),
    )
    return capture


def refresh_capture_analysis(workspace: WorkspacePaths) -> CaptureStore:
    """Refresh relevance and quality after endpoint classification changes."""

    store = load_capture_store(workspace)
    if not store.captures:
        return store
    observation_store = _load_observations(workspace)
    target = _load_target(workspace)
    endpoints_by_observation = _endpoints_by_observation(workspace)
    by_capture: dict[str, list[Observation]] = defaultdict(list)
    for observation in observation_store.observations:
        if observation.capture_id is not None:
            by_capture[observation.capture_id].append(observation)

    refreshed: list[Capture] = []
    for capture in store.captures:
        associated = by_capture.get(capture.capture_id, [])
        if not associated:
            refreshed.append(capture)
            continue
        raw_signals = _signals(associated, target, {})
        raw_analysis = infer_intent(raw_signals)
        provisional_intent = inferred_intent(raw_analysis)
        signals = _signals(associated, target, endpoints_by_observation)
        analysis = infer_intent(signals)
        observed_intent = inferred_intent(analysis)
        declared_intent = capture.declared_intent
        if declared_intent is None and capture.intent.source in USER_INTENT_SOURCES:
            declared_intent = capture.intent
        effective_intent = declared_intent or (
            observed_intent if target.capture_policy.infer_intent else CaptureIntent()
        )
        alignment = align_intents(declared_intent, observed_intent)
        relevance = _contextual_relevance(
            signals,
            observed_intent,
            declared_intent,
            analysis,
            capture.capture_mode_source,
            target.capture_policy.infer_intent,
        )
        quality = assess_quality(signals, analysis, relevance)
        if (
            capture.capture_mode == CaptureMode.MIXED
            and CaptureQualityLabel.MIXED not in quality.labels
        ):
            quality = quality.model_copy(
                update={"labels": [CaptureQualityLabel.MIXED, *quality.labels]}
            )
        updated = capture.model_copy(
            update={
                "intent": effective_intent,
                "declared_intent": declared_intent,
                "provisional_intent": provisional_intent,
                "observed_intent": observed_intent,
                "intent_alignment": alignment,
                "intent_analysis_stage": analysis.stage,
                "intent_inference": analysis.inference,
                "journey_anchors": list(analysis.anchors),
                "primary_anchor_id": analysis.primary_anchor_id,
                "analysis_metrics": analysis.metrics,
                "observation_ids": sorted(item.id for item in associated),
                "observation_relevance": {key: relevance[key] for key in sorted(relevance)},
                "counts": _counts(signals, relevance),
                "quality": quality,
                "warnings": _warnings(
                    capture.actor_id,
                    capture.capture_mode,
                    quality.labels,
                    alignment,
                    observed_intent.confidence,
                ),
            }
        )
        refreshed.append(updated)
        for observation in associated:
            observation.capture_mode = capture.capture_mode
            observation.capture_relevance = relevance.get(observation.id, CaptureRelevance.UNKNOWN)
    result = CaptureStore(captures=sorted(refreshed, key=lambda item: item.capture_id))
    write_yaml(workspace.captures, result.model_dump(mode="json", exclude_none=True))
    write_yaml(
        workspace.observations,
        observation_store.model_dump(mode="json", exclude_none=True),
    )
    return result


def _legacy_source_type(observation: Observation) -> CaptureSourceType:
    try:
        return CaptureSourceType(observation.source)
    except ValueError:
        return CaptureSourceType.LEGACY


def synthesize_legacy_captures(workspace: WorkspacePaths) -> list[Capture]:
    """Represent pre-feature observations conservatively without rewriting source artifacts."""

    observation_store = _load_observations(workspace)
    groups: dict[str, list[Observation]] = defaultdict(list)
    for observation in observation_store.observations:
        if observation.capture_id is not None or observation.source == "OPENAPI":
            continue
        identity = observation.capture_identity or observation.source_reference.split("#", 1)[0]
        groups[identity].append(observation)
    captures: list[Capture] = []
    for identity, observations in sorted(groups.items()):
        digest = hashlib.sha256(identity.encode()).hexdigest()
        relevance = {item.id: CaptureRelevance.UNKNOWN for item in observations}
        capture_id = f"CAP-LEGACY-{digest[:8].upper()}"
        captures.append(
            Capture(
                capture_id=capture_id,
                source=CaptureSource(
                    type=_legacy_source_type(observations[0]),
                    file=Path(identity).name,
                    fingerprint=digest,
                    redacted_reference=identity,
                ),
                actor_id=(
                    next(iter({item.actor for item in observations}))
                    if len({item.actor for item in observations}) == 1
                    else "UNKNOWN"
                ),
                actor_evidence=["Actor label was synthesized from legacy observation metadata."],
                capture_mode=CaptureMode.UNKNOWN,
                intent=CaptureIntent(),
                observation_ids=sorted(item.id for item in observations),
                observation_relevance=relevance,
                counts=CaptureCounts(
                    observations=len(observations),
                    first_party=len(observations),
                    state_changing=sum(
                        item.method in {"POST", "PUT", "PATCH", "DELETE"} for item in observations
                    ),
                    unknown=len(observations),
                ),
                warnings=[
                    "Legacy capture metadata is synthesized as UNKNOWN; existing analysis "
                    "semantics are preserved until the researcher supplies context."
                ],
                legacy=True,
            )
        )
    return captures


def list_captures(workspace: WorkspacePaths, *, include_legacy: bool = True) -> list[Capture]:
    """Return persisted captures plus conservative in-memory legacy representations."""

    persisted = load_capture_store(workspace).captures
    legacy = synthesize_legacy_captures(workspace) if include_legacy else []
    return sorted([*persisted, *legacy], key=lambda item: item.capture_id)


def find_capture(workspace: WorkspacePaths, capture_id: str) -> Capture | None:
    """Find one persisted or synthesized capture by stable identifier."""

    normalized = capture_id.strip().upper()
    return next((item for item in list_captures(workspace) if item.capture_id == normalized), None)
