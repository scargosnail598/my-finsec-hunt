"""Explainable, deterministic capture intent, relevance, and quality inference."""

from __future__ import annotations

import hashlib
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field

from finsec.captures.domain import (
    CaptureAnalysisMetrics,
    CaptureConfidence,
    CaptureIntent,
    CaptureQuality,
    CaptureQualityLabel,
    CaptureRelevance,
    IntentAlignment,
    IntentAnalysisStage,
    IntentInference,
    JourneyAnchor,
    MetadataSource,
)
from finsec.normalization.path_semantics import (
    ACTION_SEGMENTS,
    IDENTITY_SELECTORS,
    PathResourceSemantics,
    is_background_path,
    path_resource_semantics,
    snake_case,
)

STATE_CHANGING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
PROTOCOL_METHODS = {"HEAD", "OPTIONS"}
BACKGROUND_CLASSIFICATIONS = {"ANALYTICS", "STATIC_ASSET", "TELEMETRY", "THIRD_PARTY"}
AUTH_TOKENS = {
    "auth",
    "authenticate",
    "callback",
    "challenge",
    "login",
    "logout",
    "mfa",
    "oauth",
    "otp",
    "session",
    "signin",
    "signup",
    "token",
    "verify",
}
UPDATE_ACTIONS = {"change", "edit", "replace", "reset", "rotate", "update"}
CREATE_ACTIONS = {"add", "create", "invite", "signup"}
DELETE_ACTIONS = {"delete", "remove", "revoke"}
ACTION_EQUIVALENCE = (
    {"CHANGE", "EDIT", "REPLACE", "RESET", "ROTATE", "UPDATE"},
    {"ADD", "CREATE", "CREATE_CHILD", "INVITE"},
    {"AUTHENTICATE", "LOGIN", "SIGNIN", "VERIFY_CREDENTIAL"},
    {"DELETE", "REMOVE", "REVOKE"},
)


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
    endpoint_id: str | None = None
    endpoint_disposition: str | None = None
    endpoint_classification: str | None = None
    endpoint_action: str | None = None
    endpoint_action_type: str | None = None
    endpoint_resource: str | None = None
    endpoint_state_change: bool = False
    endpoint_reasons: tuple[str, ...] = ()
    domain_operation: str | None = None
    domain_subject_resource: str | None = None
    domain_parent_resource: str | None = None
    domain_evidence: tuple[str, ...] = ()


@dataclass(frozen=True)
class IntentAnalysis:
    """Observed intent plus ranked journey-anchor and exclusion diagnostics."""

    inference: IntentInference
    candidate_groups: tuple[tuple[str, str], ...]
    primary_positions: tuple[int, ...]
    anchors: tuple[JourneyAnchor, ...] = ()
    primary_anchor_id: str | None = None
    stage: IntentAnalysisStage = IntentAnalysisStage.PROVISIONAL
    metrics: CaptureAnalysisMetrics = field(default_factory=CaptureAnalysisMetrics)

    @property
    def primary_anchor(self) -> JourneyAnchor | None:
        """Return the selected anchor without relying on list position."""

        return next(
            (item for item in self.anchors if item.anchor_id == self.primary_anchor_id),
            None,
        )


@dataclass(frozen=True)
class _Operation:
    signal: CaptureSignal
    action: str
    resource: str
    parent_resource: str | None
    subject_selector: str | None
    semantic_component: str | None
    normalized_path: str
    state_changing: bool
    refined: bool
    evidence: tuple[str, ...]


def _path_tokens(path: str) -> list[str]:
    return [snake_case(item) for item in path.split("/") if snake_case(item)]


def resource_family(path: str) -> str:
    """Infer a selector-aware resource family from an HTTP path."""

    return path_resource_semantics(path).resource


def _canonical_action(value: str) -> str:
    normalized = snake_case(value).upper()
    if normalized in {"GET", "LIST", "READ", "SEARCH"}:
        return "READ"
    if normalized in {item.upper() for item in UPDATE_ACTIONS}:
        return "UPDATE"
    if normalized in {item.upper() for item in CREATE_ACTIONS}:
        return "CREATE"
    if normalized in {item.upper() for item in DELETE_ACTIONS}:
        return "DELETE"
    if normalized == "CREATE_CHILD":
        return "CREATE"
    if normalized == "VERIFY_CREDENTIAL":
        return "AUTHENTICATE"
    return normalized or "UNKNOWN"


def _raw_action(
    signal: CaptureSignal, semantics: PathResourceSemantics
) -> tuple[str, bool, list[str]]:
    method = signal.method.upper()
    tokens = _path_tokens(signal.path)
    token_set = set(tokens)
    if method == "DELETE":
        return "DELETE", True, ["DELETE provides a strong mutation signal."]
    if method in {"PATCH", "PUT"}:
        return "UPDATE", True, [f"{method} provides a strong update signal."]
    if method == "POST":
        if semantics.semantic_component == "credential":
            return (
                "UPDATE",
                True,
                [
                    "POST targets an actor-scoped credential component, which is modeled as an "
                    "update rather than creation."
                ],
            )
        path_action = next(
            (item for item in reversed(tokens) if item in ACTION_SEGMENTS),
            None,
        )
        if path_action in UPDATE_ACTIONS:
            return "UPDATE", True, [f"Path action {path_action} is update-like."]
        if path_action in CREATE_ACTIONS:
            return "CREATE", True, [f"Path action {path_action} is create-like."]
        if path_action in DELETE_ACTIONS:
            return "DELETE", True, [f"Path action {path_action} is delete-like."]
        if token_set & AUTH_TOKENS:
            return (
                "AUTHENTICATE",
                False,
                ["Authentication vocabulary identifies a session or identity operation."],
            )
        if semantics.terminal_is_collection:
            return (
                "CREATE",
                True,
                [
                    "POST to a plural collection is retained only as a low-confidence create "
                    "fallback until endpoint semantics are available."
                ],
            )
        return (
            "EXECUTE",
            False,
            ["POST alone is insufficient to prove CREATE or a backend state transition."],
        )
    return "READ", False, [f"{method} is treated as passive application access."]


def _operation(signal: CaptureSignal) -> _Operation:
    semantics = path_resource_semantics(signal.path)
    resource = semantics.resource
    parent = semantics.parent_resource
    action, state_changing, evidence = _raw_action(signal, semantics)
    refined = False

    endpoint_resource = snake_case(signal.endpoint_resource or "")
    if endpoint_resource not in {"", "unknown", *IDENTITY_SELECTORS}:
        if semantics.semantic_component is None:
            resource = endpoint_resource
        refined = True
        evidence.append(f"Endpoint inventory resolves the resource as {resource}.")
    if signal.domain_subject_resource:
        resource = snake_case(signal.domain_subject_resource)
        parent = snake_case(signal.domain_parent_resource or "") or parent
        refined = True
        evidence.extend(signal.domain_evidence)
    if signal.domain_operation and signal.domain_operation != "UNKNOWN":
        action = _canonical_action(signal.domain_operation)
        state_changing = signal.domain_operation not in {"READ", "VERIFY_CREDENTIAL"}
        refined = True
        evidence.append(f"Reviewed domain intent resolves the operation as {action}.")
    elif signal.endpoint_action and signal.endpoint_action.lower() != "unknown":
        action = _canonical_action(signal.endpoint_action)
        state_changing = signal.endpoint_state_change or signal.endpoint_action_type in {
            "financial_mutation",
            "mutation",
        }
        refined = True
        evidence.append(f"Endpoint inventory resolves the action as {action}.")
    elif signal.endpoint_state_change:
        state_changing = True
        refined = True
        evidence.append("Endpoint state-change evidence marks this operation as mutating.")
    evidence.extend(signal.endpoint_reasons)
    return _Operation(
        signal=signal,
        action=action,
        resource=resource,
        parent_resource=parent,
        subject_selector=semantics.subject_selector,
        semantic_component=semantics.semantic_component,
        normalized_path=semantics.normalized_operation_path,
        state_changing=state_changing,
        refined=refined,
        evidence=tuple(dict.fromkeys(evidence)),
    )


def _background_reason(signal: CaptureSignal) -> str | None:
    disposition = signal.endpoint_disposition or ""
    if not signal.first_party:
        return "host is outside the first-party analysis scope"
    if disposition.startswith("SUPPRESSED_"):
        return f"endpoint disposition is {disposition}"
    if (signal.endpoint_classification or "") in BACKGROUND_CLASSIFICATIONS:
        return f"endpoint classification is {signal.endpoint_classification}"
    if is_background_path(signal.path):
        return "path has an explicit telemetry or heartbeat marker"
    tokens = set(_path_tokens(signal.path))
    if signal.method == "POST" and "refresh" in tokens and tokens & {"session", "token"}:
        return "request performs session credential maintenance"
    return None


def _successful(status_code: int | None) -> bool:
    return status_code is not None and 200 <= status_code < 300


def _score(operation: _Operation) -> tuple[int, list[str]]:
    signal = operation.signal
    method = signal.method.upper()
    score = 1
    reasons = ["+1 first-party active application operation."]
    if method == "GET":
        score += 2
        reasons.append("+2 passive read evidence.")
        if _successful(signal.status_code):
            score += 1
            reasons.append("+1 successful passive response.")
        if operation.refined and operation.action == "READ":
            score += 1
            reasons.append("+1 endpoint semantics confirm a read operation.")
        return score, reasons

    if method in STATE_CHANGING_METHODS:
        score += 4
        reasons.append(f"+4 {method} is a state-changing HTTP-method signal.")
    if operation.state_changing:
        score += 6
        reasons.append("+6 semantic evidence identifies a state transition.")
    if _successful(signal.status_code):
        success_weight = 3 if operation.state_changing else 1
        score += success_weight
        reasons.append(f"+{success_weight} successful application response.")
    if signal.status_code in {201, 202}:
        score += 1
        reasons.append(f"+1 response status {signal.status_code} supports lifecycle handling.")
    if operation.refined and (
        signal.domain_operation not in {None, "UNKNOWN"}
        or signal.endpoint_action_type in {"financial_mutation", "mutation"}
    ):
        score += 3
        reasons.append("+3 refined endpoint/domain mutation semantics.")
    if operation.semantic_component == "credential":
        score += 3
        reasons.append("+3 actor-scoped credential component semantics.")
    if operation.action == "CREATE" and not operation.refined:
        score += 1
        reasons.append("+1 low-confidence plural-collection create fallback.")
    if operation.action == "AUTHENTICATE":
        score += 2
        reasons.append("+2 explicit authentication operation semantics.")
    if operation.resource != "unknown":
        score += 1
        reasons.append("+1 resolved business resource.")
    return score, reasons


def _anchor_id(action: str, resource: str, normalized_path: str, observation_ids: list[str]) -> str:
    payload = "\0".join([action, resource, normalized_path, *observation_ids])
    return f"ANCH-{hashlib.sha256(payload.encode()).hexdigest()[:12].upper()}"


def _anchor_confidence(score: int) -> CaptureConfidence:
    if score >= 16:
        return CaptureConfidence.HIGH
    if score >= 9:
        return CaptureConfidence.MEDIUM
    return CaptureConfidence.LOW


def _related_resources(left: JourneyAnchor, right: JourneyAnchor) -> bool:
    left_resources = {left.resource_type, left.parent_resource_type} - {None, "unknown"}
    right_resources = {right.resource_type, right.parent_resource_type} - {None, "unknown"}
    return bool(left_resources & right_resources)


def _build_anchors(operations: list[_Operation]) -> list[JourneyAnchor]:
    grouped: dict[tuple[str, str, str, str], list[_Operation]] = defaultdict(list)
    for operation in operations:
        key = (
            operation.signal.method.upper(),
            operation.normalized_path,
            operation.action,
            operation.resource,
        )
        grouped[key].append(operation)

    anchors: list[JourneyAnchor] = []
    positions: dict[str, tuple[int, ...]] = {}
    for (_method, normalized_path, action, resource), items in sorted(grouped.items()):
        ordered = sorted(items, key=lambda item: (item.signal.position, item.signal.observation_id))
        scored = [(_score(item), item) for item in ordered]
        (base_score, score_reasons), representative = max(
            scored,
            key=lambda item: (
                item[0][0],
                item[1].state_changing,
                -item[1].signal.position,
            ),
        )
        repeat_bonus = 0
        repeat_evidence: list[str] = []
        if representative.signal.method == "GET" and len(ordered) > 1:
            repeat_bonus = 1 if len(ordered) < 4 else 2
            repeat_evidence.append(
                f"+{repeat_bonus} saturated repeat bonus for {len(ordered)} passive observations; "
                "duplicates never contribute more than +2."
            )
        observation_ids = [item.signal.observation_id for item in ordered]
        endpoint_ids = sorted(
            {item.signal.endpoint_id for item in ordered if item.signal.endpoint_id is not None}
        )
        anchor_id = _anchor_id(action, resource, normalized_path, observation_ids)
        anchor = JourneyAnchor(
            anchor_id=anchor_id,
            observation_ids=observation_ids,
            endpoint_ids=endpoint_ids,
            action=action,
            resource_type=resource,
            parent_resource_type=representative.parent_resource,
            subject_selector=representative.subject_selector,
            method=representative.signal.method,
            path=representative.signal.path,
            status_code=representative.signal.status_code,
            score=base_score + repeat_bonus,
            confidence=_anchor_confidence(base_score + repeat_bonus),
            state_changing=representative.state_changing,
            evidence=list(
                dict.fromkeys([*score_reasons, *representative.evidence, *repeat_evidence])
            ),
        )
        anchors.append(anchor)
        positions[anchor_id] = tuple(item.signal.position for item in ordered)

    mutation_anchors = [
        item for item in anchors if item.method in STATE_CHANGING_METHODS and item.state_changing
    ]
    passive_anchors = [item for item in anchors if item.method == "GET"]
    for mutation in mutation_anchors:
        mutation_positions = positions[mutation.anchor_id]
        nearby = [
            item
            for item in passive_anchors
            if _related_resources(mutation, item)
            and min(
                abs(left - right)
                for left in mutation_positions
                for right in positions[item.anchor_id]
            )
            <= 3
        ]
        if nearby:
            bonus = min(2, len(nearby))
            index = anchors.index(mutation)
            anchors[index] = mutation.model_copy(
                update={
                    "score": mutation.score + bonus,
                    "confidence": _anchor_confidence(mutation.score + bonus),
                    "evidence": [
                        *mutation.evidence,
                        f"+{bonus} TEMPORAL_SUPPORT from {len(nearby)} nearby related read "
                        "operation(s); adjacency is not treated as hard causality.",
                    ],
                }
            )
    return sorted(
        anchors,
        key=lambda item: (
            -item.score,
            -int(item.state_changing),
            min(positions[item.anchor_id]),
            item.anchor_id,
        ),
    )


def infer_intent(signals: Iterable[CaptureSignal]) -> IntentAnalysis:
    """Rank saturated operation groups and select an explainable journey anchor."""

    ordered = sorted(signals, key=lambda item: (item.position, item.observation_id))
    eligible: list[_Operation] = []
    protocol_count = 0
    background_count = 0
    for signal in ordered:
        if signal.method.upper() in PROTOCOL_METHODS:
            protocol_count += 1
            continue
        if _background_reason(signal) is not None:
            background_count += 1
            continue
        eligible.append(_operation(signal))

    anchors = _build_anchors(eligible)
    primary = anchors[0] if anchors else None
    passive_groups = {
        (item.normalized_path, item.action, item.resource)
        for item in eligible
        if item.signal.method.upper() == "GET"
    }
    passive_count = sum(item.signal.method.upper() == "GET" for item in eligible)
    repeated_saturated = max(0, passive_count - len(passive_groups))
    metrics = CaptureAnalysisMetrics(
        protocol_requests_excluded=protocol_count,
        background_requests_excluded=background_count,
        passive_observations=passive_count,
        passive_operation_groups=len(passive_groups),
        repeated_passive_observations_saturated=repeated_saturated,
        anchor_candidates=len(anchors),
    )
    if primary is None:
        return IntentAnalysis(IntentInference(), (), (), metrics=metrics)

    runner_up = anchors[1].score if len(anchors) > 1 else 0
    confidence = (
        CaptureConfidence.HIGH
        if primary.score >= 16 and primary.score >= runner_up + 4
        else CaptureConfidence.MEDIUM
        if primary.score >= 9 and primary.score > runner_up
        else CaptureConfidence.LOW
    )
    stage = (
        IntentAnalysisStage.REFINED
        if any(item.refined for item in eligible)
        else IntentAnalysisStage.PROVISIONAL
    )
    significant = [
        item
        for item in anchors
        if item.method in STATE_CHANGING_METHODS or item.score >= primary.score - 3
    ]
    candidate_groups = {
        (item.action, item.resource)
        for item in eligible
        if item.signal.method.upper() in STATE_CHANGING_METHODS
    }
    positions_by_id = {item.signal.observation_id: item.signal.position for item in eligible}
    primary_positions = tuple(
        sorted(
            positions_by_id[observation_id]
            for observation_id in primary.observation_ids
            if observation_id in positions_by_id
        )
    )
    evidence = [
        f"Selected {primary.method} {primary.path} as the primary journey anchor at score "
        f"{primary.score}.",
        *primary.evidence,
    ]
    return IntentAnalysis(
        inference=IntentInference(
            proposed_action=primary.action,
            proposed_resource=primary.resource_type,
            confidence=confidence,
            evidence=list(dict.fromkeys(evidence)),
        ),
        candidate_groups=tuple(sorted(candidate_groups)),
        primary_positions=primary_positions,
        anchors=tuple(significant),
        primary_anchor_id=primary.anchor_id,
        stage=stage,
        metrics=metrics,
    )


def inferred_intent(analysis: IntentAnalysis) -> CaptureIntent:
    """Convert an intent proposal into stage-specific engine metadata."""

    inference = analysis.inference
    label = (
        f"{inference.proposed_action.lower()}_{inference.proposed_resource}"
        if inference.proposed_action != "UNKNOWN" and inference.proposed_resource != "unknown"
        else "unknown"
    )
    source = (
        MetadataSource.ENGINE_REFINED
        if analysis.stage == IntentAnalysisStage.REFINED
        else MetadataSource.ENGINE_INFERRED_RAW
    )
    return CaptureIntent(
        label=label,
        action=inference.proposed_action,
        resource_type=inference.proposed_resource,
        confidence=inference.confidence,
        source=source,
    )


def _actions_align(left: str, right: str) -> bool:
    if left == right:
        return True
    return any(left in group and right in group for group in ACTION_EQUIVALENCE)


def _resources_align(left: str, right: str) -> bool:
    if left == right:
        return True
    if left in IDENTITY_SELECTORS or right in IDENTITY_SELECTORS:
        return False
    left_tokens = set(left.split("_"))
    right_tokens = set(right.split("_"))
    return bool(left_tokens & right_tokens) and (
        left.endswith(right) or right.endswith(left) or "credential" in left_tokens & right_tokens
    )


def align_intents(declared: CaptureIntent | None, observed: CaptureIntent) -> IntentAlignment:
    """Compare human context and engine evidence without allowing either to overwrite the other."""

    if (
        declared is None
        or declared.action == "UNKNOWN"
        or declared.resource_type == "unknown"
        or observed.action == "UNKNOWN"
        or observed.resource_type == "unknown"
    ):
        return IntentAlignment.UNKNOWN
    action_match = _actions_align(declared.action, observed.action)
    resource_match = _resources_align(declared.resource_type, observed.resource_type)
    if action_match and resource_match:
        return IntentAlignment.CONSISTENT
    if action_match or resource_match:
        return IntentAlignment.PARTIAL
    return IntentAlignment.CONFLICTING


def _anchors_by_observation(analysis: IntentAnalysis) -> dict[str, JourneyAnchor]:
    return {
        observation_id: anchor
        for anchor in analysis.anchors
        for observation_id in anchor.observation_ids
    }


def _resource_related_to_anchor(
    semantics: PathResourceSemantics, anchor: JourneyAnchor
) -> tuple[bool, bool]:
    if semantics.resource == anchor.resource_type:
        return True, True
    resources = {semantics.resource, semantics.parent_resource} - {None, "unknown"}
    anchor_resources = {anchor.resource_type, anchor.parent_resource_type} - {None, "unknown"}
    return bool(resources & anchor_resources), False


def classify_relevance(
    signals: Iterable[CaptureSignal], intent: CaptureIntent, analysis: IntentAnalysis
) -> dict[str, CaptureRelevance]:
    """Classify evidence relative to the selected anchor without creating causal claims."""

    ordered = sorted(signals, key=lambda item: (item.position, item.observation_id))
    primary = analysis.primary_anchor
    if intent.action == "UNKNOWN" or intent.resource_type == "unknown" or primary is None:
        return {
            item.observation_id: (
                CaptureRelevance.PROTOCOL_SUPPORT
                if item.method.upper() in PROTOCOL_METHODS
                else CaptureRelevance.NOISE
                if _background_reason(item) is not None
                else CaptureRelevance.UNKNOWN
            )
            for item in ordered
        }

    primary_ids = set(primary.observation_ids)
    anchor_by_observation = _anchors_by_observation(analysis)
    primary_positions = [item.position for item in ordered if item.observation_id in primary_ids]
    relevance: dict[str, CaptureRelevance] = {}
    for item in ordered:
        if item.method.upper() in PROTOCOL_METHODS:
            relevance[item.observation_id] = CaptureRelevance.PROTOCOL_SUPPORT
            continue
        if _background_reason(item) is not None:
            relevance[item.observation_id] = CaptureRelevance.NOISE
            continue
        if item.observation_id in primary_ids:
            relevance[item.observation_id] = CaptureRelevance.PRIMARY
            continue

        semantics = path_resource_semantics(item.path)
        related, exact_resource = _resource_related_to_anchor(semantics, primary)
        near = (
            bool(primary_positions)
            and min(abs(item.position - position) for position in primary_positions) <= 3
        )
        competing = anchor_by_observation.get(item.observation_id)
        competing_related = competing is not None and _related_resources(primary, competing)
        if exact_resource or competing_related or (related and near):
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
    auth_count = sum(
        _operation(item).action == "AUTHENTICATE"
        for item in first_party
        if item.method.upper() not in PROTOCOL_METHODS
    )
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
