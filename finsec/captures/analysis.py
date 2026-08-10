"""Explainable, deterministic capture intent, relevance, and quality inference."""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass

from finsec.captures.domain import (
    CaptureConfidence,
    CaptureIntent,
    CaptureQuality,
    CaptureQualityLabel,
    CaptureRelevance,
    IntentInference,
    MetadataSource,
)

STATE_CHANGING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
AUTH_TOKENS = {
    "auth",
    "authenticate",
    "callback",
    "login",
    "logout",
    "mfa",
    "oauth",
    "otp",
    "refresh",
    "session",
    "signin",
    "signup",
    "token",
    "verify",
}
ACTION_SEGMENTS = {
    "accept",
    "activate",
    "approve",
    "cancel",
    "claim",
    "close",
    "confirm",
    "consume",
    "create",
    "delete",
    "disable",
    "enable",
    "login",
    "logout",
    "pay",
    "refund",
    "reject",
    "return",
    "revoke",
    "settle",
    "signin",
    "signup",
    "suspend",
    "transfer",
    "update",
    "verify",
    "withdraw",
}
GENERIC_SEGMENTS = {
    "api",
    "app",
    "data",
    "graphql",
    "internal",
    "public",
    "rest",
    "service",
}


@dataclass(frozen=True)
class CaptureSignal:
    """Credential-free HTTP shape used by capture-level deterministic analysis."""

    observation_id: str
    position: int
    host: str
    method: str
    path: str
    status_code: int | None = None
    first_party: bool = True
    endpoint_disposition: str | None = None


@dataclass(frozen=True)
class IntentAnalysis:
    """Intent proposal plus the state-changing groups used for quality diagnostics."""

    inference: IntentInference
    candidate_groups: tuple[tuple[str, str], ...]
    primary_positions: tuple[int, ...]


def _snake(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", value.lower()).strip("_")


def _singular(value: str) -> str:
    if value.endswith("ies") and len(value) > 3:
        return f"{value[:-3]}y"
    if value.endswith("sses"):
        return value[:-2]
    if value.endswith("s") and not value.endswith(("ss", "us")):
        return value[:-1]
    return value


def _segments(path: str) -> list[str]:
    result: list[str] = []
    for raw in path.split("/"):
        raw = raw.strip()
        if (
            not raw
            or (raw.startswith("{") and raw.endswith("}"))
            or raw.isdigit()
            or re.fullmatch(r"[A-Fa-f0-9-]{8,}", raw)
        ):
            continue
        segment = _snake(raw)
        if not segment or segment in GENERIC_SEGMENTS or re.fullmatch(r"v\d+", segment):
            continue
        if segment.startswith("{") or re.fullmatch(r"[a-f0-9-]{8,}", segment):
            continue
        if any(character.isdigit() for character in segment) and len(segment) >= 4:
            continue
        result.append(segment)
    return result


def resource_family(path: str) -> str:
    """Infer a conservative resource family from an HTTP path."""

    segments = _segments(path)
    if not segments:
        return "unknown"
    candidate = segments[-1]
    if candidate in ACTION_SEGMENTS and len(segments) >= 2:
        candidate = segments[-2]
    return _singular(candidate)


def _action(signal: CaptureSignal) -> str:
    tokens = set(_segments(signal.path))
    if tokens & AUTH_TOKENS:
        return "AUTHENTICATE"
    if signal.method == "DELETE":
        return "DELETE"
    if signal.method in {"PATCH", "PUT"}:
        return "UPDATE"
    if signal.method == "POST":
        path_action = next(
            (item.upper() for item in reversed(_segments(signal.path)) if item in ACTION_SEGMENTS),
            None,
        )
        return path_action or "CREATE"
    return "READ"


def infer_intent(signals: Iterable[CaptureSignal]) -> IntentAnalysis:
    """Propose one explainable intent using only ordered HTTP structure."""

    ordered = sorted(signals, key=lambda item: (item.position, item.observation_id))
    scores: Counter[tuple[str, str]] = Counter()
    evidence: dict[tuple[str, str], list[str]] = {}
    positions: dict[tuple[str, str], list[int]] = {}
    state_groups: set[tuple[str, str]] = set()
    for signal in ordered:
        if not signal.first_party or (signal.endpoint_disposition or "").startswith("SUPPRESSED_"):
            continue
        action = _action(signal)
        resource = resource_family(signal.path)
        candidate = (action, resource)
        weight = 1
        if signal.method in STATE_CHANGING_METHODS:
            weight = 6
            state_groups.add(candidate)
        if signal.status_code == 201:
            weight += 2
        if action == "AUTHENTICATE":
            weight += 3
        scores[candidate] += weight
        positions.setdefault(candidate, []).append(signal.position)
        evidence.setdefault(candidate, []).append(
            f"{signal.method} {signal.path} supports {action} {resource}."
        )
    if not scores:
        return IntentAnalysis(IntentInference(), (), ())

    ranked = scores.most_common()
    (action, resource), top_score = ranked[0]
    runner_up = ranked[1][1] if len(ranked) > 1 else 0
    matching = [
        item
        for item in ordered
        if item.first_party
        and not (item.endpoint_disposition or "").startswith("SUPPRESSED_")
        and resource_family(item.path) == resource
    ]
    if any(
        item.method == "GET" and item.position > min(positions[(action, resource)])
        for item in matching
    ):
        evidence[(action, resource)].append(
            f"A later GET revisited the {resource} resource family after the main operation."
        )
        top_score += 1
    confidence = (
        CaptureConfidence.HIGH
        if top_score >= 8 and top_score >= runner_up + 4
        else CaptureConfidence.MEDIUM
        if top_score >= 5 and top_score > runner_up
        else CaptureConfidence.LOW
    )
    return IntentAnalysis(
        inference=IntentInference(
            proposed_action=action,
            proposed_resource=resource,
            confidence=confidence,
            evidence=list(dict.fromkeys(evidence[(action, resource)])),
        ),
        candidate_groups=tuple(sorted(state_groups)),
        primary_positions=tuple(sorted(positions[(action, resource)])),
    )


def inferred_intent(analysis: IntentAnalysis) -> CaptureIntent:
    """Convert an intent proposal into engine-inferred capture metadata."""

    inference = analysis.inference
    label = (
        f"{inference.proposed_action.lower()}_{inference.proposed_resource}"
        if inference.proposed_action != "UNKNOWN" and inference.proposed_resource != "unknown"
        else "unknown"
    )
    return CaptureIntent(
        label=label,
        action=inference.proposed_action,
        resource_type=inference.proposed_resource,
        confidence=inference.confidence,
        source=MetadataSource.ENGINE_INFERRED,
    )


def classify_relevance(
    signals: Iterable[CaptureSignal], intent: CaptureIntent, analysis: IntentAnalysis
) -> dict[str, CaptureRelevance]:
    """Use intent as a soft prior without manufacturing causal relationships."""

    ordered = sorted(signals, key=lambda item: (item.position, item.observation_id))
    if intent.action == "UNKNOWN" or intent.resource_type == "unknown":
        return {
            item.observation_id: (
                CaptureRelevance.NOISE
                if not item.first_party
                or (item.endpoint_disposition or "").startswith("SUPPRESSED_")
                else CaptureRelevance.UNKNOWN
            )
            for item in ordered
        }

    primary = [
        item
        for item in ordered
        if resource_family(item.path) == intent.resource_type
        and (_action(item) == intent.action or item.method == "GET")
    ]
    primary_paths = [item.path.rstrip("/") for item in primary]
    relevance: dict[str, CaptureRelevance] = {}
    for item in ordered:
        if not item.first_party or (item.endpoint_disposition or "").startswith("SUPPRESSED_"):
            relevance[item.observation_id] = CaptureRelevance.NOISE
            continue
        family = resource_family(item.path)
        action = _action(item)
        if family == intent.resource_type and (action == intent.action or item.method == "GET"):
            relevance[item.observation_id] = CaptureRelevance.PRIMARY
            continue
        normalized = item.path.rstrip("/")
        path_related = any(
            candidate.startswith(f"{normalized}/") or normalized.startswith(f"{candidate}/")
            for candidate in primary_paths
            if normalized and candidate
        )
        if family == intent.resource_type or path_related:
            relevance[item.observation_id] = CaptureRelevance.SUPPORTING
        else:
            relevance[item.observation_id] = CaptureRelevance.CONTEXT
    return relevance


def assess_quality(
    signals: Iterable[CaptureSignal],
    analysis: IntentAnalysis,
    relevance: dict[str, CaptureRelevance],
) -> CaptureQuality:
    """Return non-blocking quality labels with concrete evidence."""

    ordered = list(signals)
    first_party = [item for item in ordered if item.first_party]
    resource_families = {resource_family(item.path) for item in first_party} - {"unknown"}
    mutation_groups = set(analysis.candidate_groups)
    auth_count = sum(_action(item) == "AUTHENTICATE" for item in first_party)
    primary_count = sum(value == CaptureRelevance.PRIMARY for value in relevance.values())
    labels: list[CaptureQualityLabel] = []
    evidence: list[str] = []

    if len(mutation_groups) > 1:
        labels.append(CaptureQualityLabel.MULTI_INTENT)
        evidence.append(
            f"{len(mutation_groups)} distinct state-changing intent groups were observed."
        )
    if len(resource_families) >= 5 or len(mutation_groups) >= 3:
        labels.append(CaptureQualityLabel.BROAD)
        evidence.append(f"{len(resource_families)} resource families appear in one capture.")
    if auth_count and auth_count * 2 >= max(len(first_party), 1):
        labels.append(CaptureQualityLabel.AUTH_HEAVY)
        evidence.append(
            f"{auth_count} of {len(first_party)} first-party requests are authentication-related."
        )
    if not mutation_groups and primary_count <= 1:
        labels.append(CaptureQualityLabel.LOW_SIGNAL)
        evidence.append("No clear state-changing journey was observed.")
    if not labels and len(resource_families) <= 3 and len(mutation_groups) <= 1:
        labels.append(CaptureQualityLabel.FOCUSED)
        evidence.append("One dominant journey is supported by a small set of resource families.")
    recommendation = None
    broad_labels = {CaptureQualityLabel.BROAD, CaptureQualityLabel.MULTI_INTENT}
    if any(label in labels for label in broad_labels):
        recommendation = "Record separate focused captures for each primary business journey."
    return CaptureQuality(
        labels=list(dict.fromkeys(labels)),
        evidence=list(dict.fromkeys(evidence)),
        recommendation=recommendation,
    )
