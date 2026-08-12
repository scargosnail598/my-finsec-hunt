"""Deterministic domain-intent and claim-strength assessment."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence

from finsec.config.models import TargetDocument
from finsec.hypotheses.contracts import (
    BindingType,
    ClaimStrengthAssessment,
    ClaimStrengthLevel,
    DecisionEvidence,
    DomainIntentAssessment,
    DomainOperation,
    MutationTargetAssessment,
    SemanticConfidence,
    VisibilityIntent,
)
from finsec.modeling.models import Endpoint
from finsec.modeling.relationships import structural_parent_resource
from finsec.modeling.semantics import IdentifierSemanticClass, OwnershipState
from finsec.normalization.path_semantics import path_resource_semantics

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
VERIFY_ACTIONS = {"check", "inspect", "validate", "verification", "verify"}
UPDATE_ACTIONS = {"change", "edit", "replace", "reset", "rotate", "update"}
TRANSITION_ACTIONS = {
    "accept",
    "activate",
    "approve",
    "cancel",
    "claim",
    "close",
    "complete",
    "confirm",
    "consume",
    "deactivate",
    "disable",
    "enable",
    "expire",
    "pay",
    "publish",
    "redeem",
    "refund",
    "reject",
    "return",
    "settle",
    "ship",
    "submit",
    "suspend",
    "transfer",
    "withdraw",
}
EXCLUSIVE_OWNER_FIELDS = {"accountid", "customerid", "ownerid", "userid"}


def _normalized(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", value.lower())


def _singular(value: str) -> str:
    lowered = value.lower().replace("-", "_")
    if lowered.endswith("ies"):
        return f"{lowered[:-3]}y"
    if lowered.endswith("s") and not lowered.endswith("ss"):
        return lowered[:-1]
    return lowered


def _display_resource(value: str) -> str:
    tokens = [item for item in re.split(r"[^A-Za-z0-9]+", value) if item]
    return "".join(item[:1].upper() + item[1:] for item in tokens) or "Unknown"


def _evidence(reference: str, source: str, detail: str) -> DecisionEvidence:
    return DecisionEvidence(reference=reference, source=source, detail=detail)  # type: ignore[arg-type]


def _response_paths(endpoint: Endpoint) -> list[str]:
    return sorted(
        parameter.json_path or parameter.name
        for parameter in endpoint.parameters
        if parameter.source == "response"
    )


def _child_subject(endpoint: Endpoint) -> tuple[str, DecisionEvidence] | None:
    if endpoint.method != "POST":
        return None
    segments = [item for item in endpoint.path.strip("/").split("/") if item]
    if len(segments) < 2 or not any(item.startswith("{") for item in segments[:-1]):
        return None
    tail = segments[-1]
    if tail.startswith("{") or "_" in tail or "-" in tail:
        return None
    child = _singular(tail)
    if not child or child in TRANSITION_ACTIONS or child in VERIFY_ACTIONS:
        return None
    paths = [_normalized(item) for item in _response_paths(endpoint)]
    plural = _normalized(f"{child}s")
    if not any(plural in path or _normalized(child) in path for path in paths):
        return None
    return (
        _display_resource(child),
        _evidence(
            endpoint.id,
            "ENDPOINT",
            "POST targets a child-shaped route beneath a parent identifier and the response "
            "contains the corresponding child collection or fields.",
        ),
    )


def _operation(
    endpoints: Sequence[Endpoint], rule_id: str
) -> tuple[DomainOperation, list[DecisionEvidence]]:
    evidence: list[DecisionEvidence] = []
    if rule_id.startswith("JWT_ALGORITHM_VALIDATION"):
        return (
            DomainOperation.VERIFY_CREDENTIAL,
            [
                _evidence(
                    rule_id,
                    "GENERATOR",
                    "The configured test concerns credential verification, not an established "
                    "authenticated backend effect.",
                )
            ],
        )
    children = [item for endpoint in endpoints if (item := _child_subject(endpoint)) is not None]
    if children:
        return DomainOperation.CREATE_CHILD, [item[1] for item in children]
    if endpoints and all(
        endpoint.method in SAFE_METHODS and not endpoint.state_change for endpoint in endpoints
    ):
        return (
            DomainOperation.READ,
            [
                _evidence(
                    endpoint.id,
                    "ENDPOINT",
                    f"{endpoint.method} resolves to read-only semantics without explicit "
                    "side-effect evidence.",
                )
                for endpoint in endpoints
            ],
        )
    actions = {endpoint.action.name.lower() for endpoint in endpoints}
    methods = {endpoint.method for endpoint in endpoints}
    if actions.intersection(VERIFY_ACTIONS):
        return DomainOperation.VERIFY_CREDENTIAL, [
            _evidence(
                endpoint.id,
                "ENDPOINT",
                "Verification vocabulary is treated as credential validation unless a backend "
                "state effect is explicitly evidenced.",
            )
            for endpoint in endpoints
            if endpoint.action.name.lower() in VERIFY_ACTIONS
        ]
    if "DELETE" in methods:
        return DomainOperation.DELETE, evidence
    if methods.intersection({"PUT", "PATCH"}):
        return DomainOperation.UPDATE, evidence
    if actions.intersection(UPDATE_ACTIONS):
        return DomainOperation.UPDATE, evidence
    if actions.intersection(TRANSITION_ACTIONS):
        return DomainOperation.TRANSITION, evidence
    collection_posts = [
        item
        for item in endpoints
        if item.method == "POST" and path_resource_semantics(item.path).terminal_is_collection
    ]
    if "create" in actions or (collection_posts and len(collection_posts) == len(endpoints)):
        return DomainOperation.CREATE, evidence
    if any(endpoint.state_change for endpoint in endpoints):
        return DomainOperation.ACTION, evidence
    return DomainOperation.UNKNOWN, evidence


def _logic_evidence(logic_details: Mapping[str, object] | None) -> Mapping[str, object]:
    if logic_details is None:
        return {}
    qualification = logic_details.get("qualification")
    if not isinstance(qualification, Mapping):
        return {}
    evidence = qualification.get("evidence")
    return evidence if isinstance(evidence, Mapping) else {}


def assess_domain_intent(
    target: TargetDocument,
    endpoints: Sequence[Endpoint],
    *,
    category: str,
    generation_rule_id: str,
    logic_details: Mapping[str, object] | None = None,
    mutation_target: MutationTargetAssessment | None = None,
) -> DomainIntentAssessment:
    """Resolve the protected subject and boundary without treating names as policy proof."""

    ordered = sorted(endpoints, key=lambda item: item.id)
    operation, operation_evidence = _operation(ordered, generation_rule_id)
    positive = list(operation_evidence)
    counter: list[DecisionEvidence] = []
    ambiguity: list[str] = []
    endpoint_resources = [endpoint.resource.type for endpoint in ordered]
    subject = endpoint_resources[0] if endpoint_resources else "Unknown"
    if mutation_target is not None and mutation_target.semantics.resource_type is not None:
        subject = mutation_target.semantics.resource_type
    parent: str | None = None
    structural_parents = {
        value for endpoint in ordered if (value := structural_parent_resource(endpoint)) is not None
    }
    if len(structural_parents) == 1:
        parent = next(iter(structural_parents))
        positive.extend(
            _evidence(
                endpoint.id,
                "ENDPOINT",
                f"Nested route structure places {endpoint.resource.type} beneath {parent}; "
                "this is structural scope evidence, not ownership proof.",
            )
            for endpoint in ordered
            if structural_parent_resource(endpoint) == parent
        )
    elif len(structural_parents) > 1:
        ambiguity.append("Source endpoints imply conflicting structural parent resource types.")
    if operation == DomainOperation.CREATE_CHILD and ordered:
        child = _child_subject(ordered[0])
        if child is not None:
            subject = child[0]
            parent = ordered[0].resource.type

    endpoint_keys = {(endpoint.method, endpoint.path) for endpoint in ordered}
    intent_rules = sorted(
        (
            rule
            for rule in target.analysis.domain_intent_rules
            if (rule.method, rule.path) in endpoint_keys
        ),
        key=lambda item: (item.method, item.path),
    )
    annotated_intents: list[tuple[VisibilityIntent, BindingType, DecisionEvidence]] = []
    for intent_rule in intent_rules:
        reference = f"{intent_rule.method} {intent_rule.path}"
        evidence = _evidence(
            reference,
            "TARGET_POLICY",
            f"Reviewed domain-intent policy: {intent_rule.rationale}",
        )
        annotated_intents.append(
            (
                VisibilityIntent(intent_rule.visibility),
                BindingType(intent_rule.binding),
                evidence,
            )
        )
        positive.extend(
            _evidence(
                evidence_ref,
                "TARGET_POLICY",
                f"Evidence reference supporting reviewed domain intent for {reference}.",
            )
            for evidence_ref in intent_rule.evidence_refs
        )
        if intent_rule.subject_resource is not None:
            subject = intent_rule.subject_resource
        if intent_rule.parent_resource is not None:
            parent = intent_rule.parent_resource
        if intent_rule.operation is not None:
            operation = DomainOperation(intent_rule.operation)
            positive.append(
                _evidence(
                    reference,
                    "TARGET_POLICY",
                    f"Reviewed policy resolves the business operation as {operation.value}.",
                )
            )

    visibility = VisibilityIntent.UNKNOWN
    binding = BindingType.UNKNOWN
    public_signals: list[DecisionEvidence] = []
    owner_signals: list[DecisionEvidence] = []
    role_signals: list[DecisionEvidence] = []
    anonymous_read_observed = False
    if mutation_target is not None and mutation_target.parameter is not None:
        target_reference = mutation_target.parameter
        target_semantics = mutation_target.semantics
        positive.extend(
            _evidence(target_reference, "ENDPOINT", item) for item in target_semantics.evidence
        )
        counter.extend(
            _evidence(target_reference, "ENDPOINT", item)
            for item in target_semantics.counterevidence
        )
        if target_semantics.semantic_class in {
            IdentifierSemanticClass.REGION,
            IdentifierSemanticClass.SHARED_SCOPE,
            IdentifierSemanticClass.COLLECTION,
            IdentifierSemanticClass.NON_SECURITY_RELEVANT,
        }:
            public_signals.append(
                _evidence(
                    target_reference,
                    "ENDPOINT",
                    f"Mutation target is classified as "
                    f"{target_semantics.semantic_class.value}, not an owned object.",
                )
            )
        elif (
            target_semantics.semantic_class == IdentifierSemanticClass.OWNED_OBJECT
            and target_semantics.ownership_state
            in {OwnershipState.CONFIRMED, OwnershipState.STRONG_INFERRED}
        ):
            owner_signals.append(
                _evidence(
                    target_reference,
                    "ENDPOINT",
                    f"Mutation target has {target_semantics.ownership_state.value} "
                    "actor/object control evidence.",
                )
            )
            binding = (
                BindingType.PRODUCER_CONSUMER
                if "CONTROLLED_LIFECYCLE" in target_semantics.sources
                else BindingType.OWNERSHIP
            )
        elif target_semantics.ownership_state == OwnershipState.CONTRADICTED:
            ambiguity.append(
                "Owned-object and shared/public evidence conflict for the mutation target."
            )
        elif target_semantics.semantic_class in {
            IdentifierSemanticClass.OWNED_OBJECT,
            IdentifierSemanticClass.OBJECT_IDENTIFIER,
        }:
            ambiguity.append(
                "The mutation target is object-like, but ownership evidence remains weak or "
                "unknown."
            )
    for endpoint in ordered:
        if operation == DomainOperation.READ and endpoint.authentication.anonymous_success_observed:
            anonymous_read_observed = True
            public_signals.append(
                _evidence(
                    endpoint.id,
                    "ENDPOINT",
                    "A structured successful read was observed without request credentials.",
                )
            )
            ambiguity.append(
                "Observed anonymous reachability does not by itself establish the intended "
                "visibility policy."
            )
        for decision in endpoint.ownership_inference:
            if (
                mutation_target is not None
                and mutation_target.parameter is not None
                and _normalized(decision.parameter) != _normalized(mutation_target.parameter)
            ):
                continue
            if decision.classification == "PUBLIC_SHARED_SCOPE":
                public_signals.append(
                    _evidence(
                        endpoint.id,
                        "ENDPOINT",
                        f"{decision.parameter} is explicitly classified as public/shared scope.",
                    )
                )
        for access in endpoint.object_access:
            if (
                mutation_target is not None
                and mutation_target.parameter is not None
                and _normalized(access.identifier) != _normalized(mutation_target.parameter)
            ):
                continue
            if not access.actor_object_binding_observed:
                continue
            if access.source == "PATH_PARENT_SCOPE":
                counter.append(
                    _evidence(
                        endpoint.id,
                        "ENDPOINT",
                        "Authenticated path access is retained as structural scope evidence and "
                        "does not establish actor ownership or control.",
                    )
                )
                ambiguity.extend(access.ambiguity)
                continue
            if access.source == "CONTROLLED_LIFECYCLE":
                owner_signals.append(
                    _evidence(
                        endpoint.id,
                        "ENDPOINT",
                        f"{access.distinct_actors} controlled actor(s) have "
                        "CREATE-produced, subsequently consumed resource baseline(s) for "
                        f"{access.identifier}.",
                    )
                )
                positive.extend(
                    _evidence(
                        relationship_id,
                        "WORKFLOW",
                        "Canonical controlled-lifecycle relationship supports this actor/resource "
                        "binding.",
                    )
                    for relationship_id in access.relationship_ids
                )
                counter.extend(
                    _evidence(endpoint.id, "ENDPOINT", item) for item in access.counterevidence
                )
                ambiguity.extend(access.ambiguity)
                if binding == BindingType.UNKNOWN:
                    binding = BindingType.PRODUCER_CONSUMER
                continue
            owner_field = _normalized((access.owner_field_path or "").rsplit(".", 1)[-1])
            if access.source == "RESPONSE_BODY" and owner_field not in EXCLUSIVE_OWNER_FIELDS:
                counter.append(
                    _evidence(
                        endpoint.id,
                        "ENDPOINT",
                        f"The response association field {access.owner_field_path or 'unknown'} "
                        "does not establish exclusive owner or actor visibility.",
                    )
                )
                ambiguity.append(
                    "A producer, member, profile, or other response association is not an "
                    "owner-only access policy."
                )
                continue
            source = BindingType.OWNERSHIP
            owner_signals.append(
                _evidence(
                    endpoint.id,
                    "ENDPOINT",
                    f"{access.distinct_actors} controlled actors have distinct "
                    f"{access.source.lower()} baselines for {access.identifier}.",
                )
            )
            if binding == BindingType.UNKNOWN:
                binding = source
        if endpoint.authentication.required:
            counter.append(
                _evidence(
                    endpoint.id,
                    "ENDPOINT",
                    "Authentication identifies a request actor but does not prove ownership, "
                    "exclusive visibility, or initiating-actor binding.",
                )
            )

    for authorization_rule in target.analysis.function_authorization_rules:
        if (authorization_rule.method, authorization_rule.path) in endpoint_keys:
            role_signals.append(
                _evidence(
                    f"{authorization_rule.method} {authorization_rule.path}",
                    "TARGET_POLICY",
                    f"Researcher policy restricts the operation to roles: "
                    f"{', '.join(authorization_rule.allowed_roles)}.",
                )
            )

    logic = _logic_evidence(logic_details)
    ownership_known = logic.get("ownership_known") is True
    causal_binding = logic.get("causal_prerequisites_proven") is True
    details = logic_details or {}
    family = str(details.get("family", ""))
    if family == "ACTOR_SWITCH" and ownership_known:
        owner_signals.append(
            _evidence(
                str(details.get("invariant_id", "logic")),
                "INVARIANT",
                "The workflow candidate has evidence-backed ownership or actor-object binding.",
            )
        )
        binding = BindingType.INITIATING_ACTOR
    elif family in {"RESOURCE_SWITCH", "CROSS_WORKFLOW_TOKEN_REUSE"} and causal_binding:
        owner_signals.append(
            _evidence(
                str(details.get("invariant_id", "logic")),
                "INVARIANT",
                "Typed producer-consumer evidence binds the resource to one workflow context.",
            )
        )
        binding = BindingType.PRODUCER_CONSUMER

    if operation == DomainOperation.CREATE_CHILD and owner_signals:
        counter.extend(owner_signals)
        owner_signals = []
        binding = BindingType.UNKNOWN
        ambiguity.append(
            "A parent identifier or parent ownership signal does not establish owner-only or "
            "actor-exclusive policy for the created child resource."
        )

    annotated_values = {(item[0], item[1]) for item in annotated_intents}
    if len(annotated_values) > 1:
        counter.extend(item[2] for item in annotated_intents)
        ambiguity.append("Reviewed domain-intent annotations conflict across source endpoints.")
    elif annotated_intents:
        visibility, binding, annotated_evidence = annotated_intents[0]
        positive.append(annotated_evidence)
        if visibility in {VisibilityIntent.PUBLIC, VisibilityIntent.SHARED}:
            counter.extend(owner_signals)
            if owner_signals:
                ambiguity.append(
                    "Observed actor/object association conflicts with reviewed public/shared "
                    "intent and must be retained for review."
                )
        elif visibility in {
            VisibilityIntent.OWNER_SCOPED,
            VisibilityIntent.ROLE_SCOPED,
            VisibilityIntent.ACTOR_BOUND,
        }:
            counter.extend(public_signals)
            if public_signals:
                ambiguity.append(
                    "Public/shared scope evidence conflicts with reviewed scoped intent."
                )
    elif public_signals and owner_signals:
        positive.extend(owner_signals)
        counter.extend(public_signals)
        visibility = (
            VisibilityIntent.ACTOR_BOUND
            if binding
            in {
                BindingType.INITIATING_ACTOR,
                BindingType.PRODUCER_CONSUMER,
                BindingType.SESSION,
            }
            else VisibilityIntent.OWNER_SCOPED
        )
        ambiguity.append("Public/shared and owner-scoped signals conflict and require review.")
    elif public_signals:
        positive.extend(public_signals)
        visibility = VisibilityIntent.PUBLIC if anonymous_read_observed else VisibilityIntent.SHARED
        binding = BindingType.UNKNOWN
    elif role_signals:
        positive.extend(role_signals)
        visibility = VisibilityIntent.ROLE_SCOPED
        binding = BindingType.ROLE
    elif owner_signals:
        positive.extend(owner_signals)
        visibility = (
            VisibilityIntent.ACTOR_BOUND
            if binding
            in {
                BindingType.INITIATING_ACTOR,
                BindingType.PRODUCER_CONSUMER,
                BindingType.SESSION,
            }
            else VisibilityIntent.OWNER_SCOPED
        )
    else:
        ambiguity.append(
            "No ownership, tenant, role, session, producer-consumer, or explicit visibility "
            "policy is established for the protected subject."
        )

    if category == "authorization" and visibility == VisibilityIntent.UNKNOWN:
        ambiguity.append(
            "A controllable identifier proves substitution capability, not an authorization "
            "boundary."
        )
    confidence = (
        SemanticConfidence.HIGH
        if visibility != VisibilityIntent.UNKNOWN and positive
        else SemanticConfidence.MEDIUM
        if operation not in {DomainOperation.UNKNOWN, DomainOperation.ACTION}
        else SemanticConfidence.LOW
    )
    return DomainIntentAssessment(
        subject_resource=subject,
        parent_resource=parent,
        operation=operation,
        visibility=visibility,
        binding=binding,
        positive_evidence=sorted(positive, key=lambda item: (item.reference, item.detail)),
        counterevidence=sorted(counter, key=lambda item: (item.reference, item.detail)),
        ambiguity=sorted(set(ambiguity)),
        confidence=confidence,
    )


_CLAIM_RANK = {
    ClaimStrengthLevel.INPUT_ACCEPTED: 1,
    ClaimStrengthLevel.VALIDATOR_ACCEPTED: 2,
    ClaimStrengthLevel.IDENTITY_OR_SESSION_ESTABLISHED: 3,
    ClaimStrengthLevel.PROTECTED_RESOURCE_REACHED: 4,
    ClaimStrengthLevel.BACKEND_EFFECT_CONFIRMED: 5,
}


def claim_strength_rank(level: ClaimStrengthLevel) -> int:
    return _CLAIM_RANK[level]


def assess_claim_strength(
    *,
    generation_rule_id: str,
    category: str,
    intent: DomainIntentAssessment,
    eligibility_evidence: Sequence[str],
) -> ClaimStrengthAssessment:
    """Calibrate the strongest claim without converting a hypothesis into a finding."""

    text = " ".join(eligibility_evidence).lower()
    evidence: list[DecisionEvidence] = []
    current = ClaimStrengthLevel.INPUT_ACCEPTED
    if any(marker in text for marker in ("validator accepted", "verification accepted")):
        current = ClaimStrengthLevel.VALIDATOR_ACCEPTED
    if any(
        marker in text
        for marker in (
            "accepted identity",
            "authenticated identity",
            "session established",
            "subject established",
        )
    ):
        current = ClaimStrengthLevel.IDENTITY_OR_SESSION_ESTABLISHED
    if any(marker in text for marker in ("protected endpoint", "protected resource reached")):
        current = ClaimStrengthLevel.PROTECTED_RESOURCE_REACHED
    if any(marker in text for marker in ("backend effect confirmed", "authoritative state delta")):
        current = ClaimStrengthLevel.BACKEND_EFFECT_CONFIRMED

    if generation_rule_id.startswith("JWT_ALGORITHM_VALIDATION"):
        target = max(
            current,
            ClaimStrengthLevel.VALIDATOR_ACCEPTED,
            key=claim_strength_rank,
        )
        evidence.append(
            _evidence(
                generation_rule_id,
                "GENERATOR",
                "The bounded claim is verifier acceptance of altered credential material.",
            )
        )
        return ClaimStrengthAssessment(
            current_level=current,
            target_level=target,
            evidence=evidence,
            upgrade_requirements=[
                "Show that the altered token establishes an authenticated identity, role, or "
                "session.",
                "Reach one protected endpoint or action using that established context.",
                "Confirm any claimed backend effect with authoritative state evidence.",
            ],
            explanation=(
                "Verifier acceptance is distinct from authentication bypass until downstream "
                "identity, session, role, or protected-resource evidence exists."
            ),
        )

    if intent.operation in {DomainOperation.READ, DomainOperation.VERIFY_CREDENTIAL}:
        target = (
            ClaimStrengthLevel.PROTECTED_RESOURCE_REACHED
            if category in {"authentication", "authorization"}
            else ClaimStrengthLevel.VALIDATOR_ACCEPTED
        )
    elif intent.operation in {
        DomainOperation.CREATE,
        DomainOperation.CREATE_CHILD,
        DomainOperation.UPDATE,
        DomainOperation.DELETE,
        DomainOperation.TRANSITION,
        DomainOperation.ACTION,
    }:
        target = ClaimStrengthLevel.BACKEND_EFFECT_CONFIRMED
    else:
        target = ClaimStrengthLevel.INPUT_ACCEPTED
    return ClaimStrengthAssessment(
        current_level=current,
        target_level=target,
        evidence=evidence,
        upgrade_requirements=(
            ["Confirm the claimed security-relevant backend effect with an authoritative oracle."]
            if target == ClaimStrengthLevel.BACKEND_EFFECT_CONFIRMED
            else []
        ),
        explanation=(
            "The hypothesis target is bounded by the operation and oracle family; current "
            "passive evidence does not itself confirm the security claim."
        ),
    )
