"""Cross-generator semantic clustering and deterministic queue presentation."""

from __future__ import annotations

from collections import defaultdict

from finsec.config.models import TargetDocument
from finsec.hypotheses.contracts import (
    CapabilityKind,
    ClaimStrengthLevel,
    DomainOperation,
    HypothesisCampaign,
    HypothesisGrouping,
    HypothesisPresentation,
    SemanticDescriptor,
    SemanticRelationship,
    VisibilityIntent,
)
from finsec.hypotheses.domain import HypothesisRecord, HypothesisScores, HypothesisStore
from finsec.hypotheses.readiness import assess_record_readiness
from finsec.hypotheses.scoring import canonical_scoring, canonicalize_scores
from finsec.hypotheses.semantics import (
    assess_claim_strength,
    assess_domain_intent,
    claim_strength_rank,
)
from finsec.hypotheses.targets import resolve_mutation_target
from finsec.modeling.domain import ResourceStore
from finsec.modeling.merge import stable_fingerprint
from finsec.modeling.models import Endpoint, EndpointStore, ObservationStore
from finsec.modeling.semantics import IdentifierSemanticClass, OwnershipState
from finsec.normalization.path_semantics import path_hierarchy

_SOURCE_SUPPRESSIONS = {
    "SUPPRESSED_STATIC_ASSET",
    "SUPPRESSED_TELEMETRY",
    "SUPPRESSED_THIRD_PARTY",
    "SUPPRESSED_PUBLIC_RESOURCE",
    "SUPPRESSED_INSUFFICIENT_EVIDENCE",
}
_AUTH_COVERAGE_CONTROLS = [
    "anonymous credential removal",
    "malformed credential",
    "expired credential",
    "revoked credential",
    "wrong audience",
    "wrong role",
]
_DESCRIPTOR_DIFFERENCE_FIELDS = (
    ("mutation target", "mutation_parameter"),
    ("mutation location", "mutation_location"),
    ("mutation JSON path", "mutation_json_path"),
    ("identifier class", "identifier_semantic_class"),
    ("resource role", "identifier_resource_role"),
    ("ownership state", "ownership_state"),
    ("authorization relationship", "expected_authorization_relationship"),
    ("HTTP method", "methods"),
    ("route family", "route_families"),
    ("operation", "operation"),
    ("subject resource", "subject_resource"),
    ("parent resource", "parent_resource"),
    ("parent context", "parent_contexts"),
    ("test operator", "test_operator"),
)


def _generator(record: HypothesisRecord) -> str:
    if record.generation is not None:
        return record.generation.generator
    return "business-logic-analysis" if record.id.startswith("BLH-") else "legacy-or-researcher"


def _base_visible(record: HypothesisRecord) -> bool:
    if record.disposition in _SOURCE_SUPPRESSIONS or record.disposition == "SUPPRESSED_DUPLICATE":
        return False
    if record.kind == "SECURITY_HYPOTHESIS":
        return record.disposition == "ACTIVE"
    return record.disposition in {"ACTIVE", "NEEDS_RESEARCH"}


def _campaign_eligible(record: HypothesisRecord) -> bool:
    return record.disposition not in {
        "SUPPRESSED_STATIC_ASSET",
        "SUPPRESSED_TELEMETRY",
        "SUPPRESSED_THIRD_PARTY",
        "SUPPRESSED_PUBLIC_RESOURCE",
    }


def _canonical_route(endpoint: Endpoint) -> str:
    return path_hierarchy(
        endpoint.path,
        endpoint.path,
        endpoint.resource.type,
    ).route_family


def _services(endpoint: Endpoint) -> list[str]:
    segments = [item for item in endpoint.path.strip("/").split("/") if item]
    segment = segments[0].lower() if len(segments) > 1 and segments[1].lower() == "api" else "root"
    hosts = endpoint.hosts or ["unknown-host"]
    return [f"{host.lower()}:{segment}" for host in sorted(hosts)]


def _logic_family(record: HypothesisRecord) -> str:
    if record.logic_details is not None:
        value = record.logic_details.get("family")
        if isinstance(value, str):
            return value
    rule = record.generation_rule.get("id", "")
    return rule.removeprefix("BUSINESS_LOGIC_") if rule.startswith("BUSINESS_LOGIC_") else ""


def _weakness_family(record: HypothesisRecord) -> str:
    rule = record.generation_rule.get("id", "")
    family = _logic_family(record)
    if rule == "AUTH_ENFORCEMENT_RESEARCH":
        return "AUTHENTICATION_COVERAGE"
    if rule.startswith("JWT_ALGORITHM_VALIDATION"):
        return "JWT_VALIDATION"
    if record.category == "authorization" or family in {"ACTOR_SWITCH", "RESOURCE_SWITCH"}:
        return "AUTHORIZATION_BOUNDARY"
    if record.category == "value_validation" or family == "QUANTITY_VALUE_INVARIANT":
        return "VALUE_VALIDATION"
    if family in {"REPLAY", "DUPLICATE_ACTION", "CONCURRENT_EXECUTION"}:
        return "SINGLE_EXECUTION"
    if family:
        return family
    return record.category.upper()


def _test_operator(record: HypothesisRecord) -> str:
    family = _logic_family(record)
    if family:
        return family
    rule = record.generation_rule.get("id", "")
    return {
        "AUTH_OBJECT_ACCESS": "ACTOR_OBJECT_SUBSTITUTION",
        "VALUE_VALIDATION": "VALUE_BOUNDARY_MUTATION",
        "JWT_ALGORITHM_VALIDATION": "UNSIGNED_TOKEN_MUTATION",
        "AUTH_ENFORCEMENT": "AUTHENTICATION_REMOVAL",
        "AUTH_ENFORCEMENT_RESEARCH": "AUTHENTICATION_CONTROL_COLLECTION",
    }.get(rule, rule or record.category.upper())


def _oracle_family(record: HypothesisRecord) -> str:
    target = record.claim_strength.target_level
    if target == ClaimStrengthLevel.VALIDATOR_ACCEPTED:
        return "VERIFIER_DECISION"
    if target == ClaimStrengthLevel.IDENTITY_OR_SESSION_ESTABLISHED:
        return "IDENTITY_OR_SESSION"
    if target == ClaimStrengthLevel.PROTECTED_RESOURCE_REACHED:
        return "PROTECTED_RESPONSE_OR_ACTION"
    if target == ClaimStrengthLevel.BACKEND_EFFECT_CONFIRMED:
        return "AUTHORITATIVE_STATE_DELTA"
    return "INPUT_ACCEPTANCE"


def _actor_requirements(record: HypothesisRecord) -> list[str]:
    actor = next(
        (
            item
            for item in record.readiness_assessment.capabilities
            if item.capability == CapabilityKind.ACTOR
        ),
        None,
    )
    ownership = next(
        (
            item
            for item in record.readiness_assessment.capabilities
            if item.capability == CapabilityKind.OWNERSHIP and item.required
        ),
        None,
    )
    values = [actor.summary] if actor is not None else []
    if ownership is not None:
        values.append(f"binding:{record.domain_intent.binding.value}")
    return sorted(values)


def _descriptor(record: HypothesisRecord, endpoints: list[Endpoint]) -> SemanticDescriptor:
    services = sorted({service for item in endpoints for service in _services(item)})
    routes = sorted({_canonical_route(item) for item in endpoints})
    parent_contexts = sorted(
        {
            hierarchy.parent.value
            for endpoint in endpoints
            for hierarchy in [path_hierarchy(endpoint.path, endpoint.path, endpoint.resource.type)]
            if hierarchy.parent is not None and hierarchy.parent.value is not None
        }
    )
    methods = sorted({item.method for item in endpoints})
    weakness = _weakness_family(record)
    operator = _test_operator(record)
    effect = record.claim_strength.target_level.value
    oracle = _oracle_family(record)
    workflow = record.component if record.category == "business_logic" else None
    transition = None
    if record.logic_details is not None:
        value = record.logic_details.get("affected_transition_id")
        transition = value if isinstance(value, str) else None
    workflow_identity = (
        workflow
        if weakness
        not in {
            "AUTHENTICATION_COVERAGE",
            "AUTHORIZATION_BOUNDARY",
            "JWT_VALIDATION",
            "VALUE_VALIDATION",
        }
        else None
    )
    transition_identity = transition if workflow_identity is not None else None
    exact_payload = {
        "services": services,
        "routes": routes,
        "methods": methods,
        "operation": record.domain_intent.operation,
        "subject": record.domain_intent.subject_resource.lower(),
        "parent": (
            record.domain_intent.parent_resource.lower()
            if record.domain_intent.parent_resource is not None
            else None
        ),
        "parent_contexts": parent_contexts,
        "visibility": record.domain_intent.visibility,
        "binding": record.domain_intent.binding,
        "weakness": weakness,
        "operator": operator,
        "effect": effect,
        "oracle": oracle,
        "actors": _actor_requirements(record),
        "mutation_parameter": record.mutation_target.parameter,
        "mutation_location": record.mutation_target.location,
        "mutation_json_path": record.mutation_target.json_path,
        "identifier_semantic_class": record.mutation_target.semantics.semantic_class,
        "identifier_resource_role": record.mutation_target.semantics.resource_role,
        "ownership_state": record.mutation_target.semantics.ownership_state,
        "expected_authorization_relationship": (
            record.mutation_target.expected_authorization_relationship
        ),
        "workflow": workflow_identity,
        "transition": transition_identity,
    }
    if weakness == "AUTHENTICATION_COVERAGE":
        campaign_payload = {
            "services": services,
            "scheme": sorted({item.authentication.observed_type for item in endpoints}),
            "weakness": weakness,
        }
    else:
        campaign_payload = {
            "services": services,
            "routes": routes,
            "operation": record.domain_intent.operation,
            "subject": record.domain_intent.subject_resource.lower(),
            "parent": (
                record.domain_intent.parent_resource.lower()
                if record.domain_intent.parent_resource is not None
                else None
            ),
            "weakness": weakness,
        }
    return SemanticDescriptor(
        target_services=services,
        route_families=routes,
        methods=methods,
        operation=record.domain_intent.operation,
        subject_resource=record.domain_intent.subject_resource.lower(),
        parent_resource=(
            record.domain_intent.parent_resource.lower()
            if record.domain_intent.parent_resource is not None
            else None
        ),
        parent_contexts=parent_contexts,
        visibility=record.domain_intent.visibility,
        binding=record.domain_intent.binding,
        weakness_family=weakness,
        test_operator=operator,
        expected_effect=effect,
        oracle_family=oracle,
        actor_requirements=_actor_requirements(record),
        mutation_parameter=record.mutation_target.parameter,
        mutation_location=record.mutation_target.location,
        mutation_json_path=record.mutation_target.json_path,
        identifier_semantic_class=record.mutation_target.semantics.semantic_class.value,
        identifier_resource_role=record.mutation_target.semantics.resource_role.value,
        ownership_state=record.mutation_target.semantics.ownership_state.value,
        expected_authorization_relationship=(
            record.mutation_target.expected_authorization_relationship
        ),
        workflow_family=workflow,
        transition=transition,
        exact_key=stable_fingerprint(exact_payload),
        campaign_key=stable_fingerprint(campaign_payload),
    )


def _title(record: HypothesisRecord, endpoints: list[Endpoint]) -> str:
    endpoint = endpoints[0] if endpoints else None
    operation = record.domain_intent.operation
    subject = record.domain_intent.subject_resource
    route = f"{endpoint.method} {endpoint.path}" if endpoint is not None else record.component
    rule = record.generation_rule.get("id", "")
    if rule == "JWT_ALGORITHM_VALIDATION":
        if claim_strength_rank(record.claim_strength.current_level) >= 3:
            return f"Unsigned JWT acceptance may bypass authentication on {route}"
        return f"Unsigned JWT may be accepted by the verifier on {route}"
    if record.category == "authorization" and rule.startswith("AUTH_OBJECT_ACCESS"):
        parameter = record.mutation_target.parameter or "identifier"
        if operation == DomainOperation.READ:
            action = "access"
        elif operation == DomainOperation.CREATE_CHILD:
            parent = record.domain_intent.parent_resource or "parent resource"
            return (
                f"Potential cross-account {subject} creation under {parent} through {parameter} "
                f"on {route}"
            )
        else:
            action = "modification" if operation != DomainOperation.VERIFY_CREDENTIAL else "action"
        if record.domain_intent.visibility in {
            VisibilityIntent.PUBLIC,
            VisibilityIntent.SHARED,
        }:
            visibility = record.domain_intent.visibility.value.lower().replace("_", " ")
            return (
                f"Validate {visibility} {subject} access semantics through {parameter} on {route}"
            )
        actor_scope = (
            "unauthenticated cross-account"
            if endpoint is not None and not endpoint.authentication.required
            else "cross-account"
        )
        return f"Potential {actor_scope} {subject} {action} through {parameter} on {route}"
    return record.title


def _calibrated_scores(record: HypothesisRecord) -> tuple[HypothesisScores, str]:
    values = record.scores.model_dump()
    semantics = record.mutation_target.semantics
    if record.category == "authorization" and record.domain_intent.visibility in {
        VisibilityIntent.PUBLIC,
        VisibilityIntent.SHARED,
        VisibilityIntent.UNKNOWN,
    }:
        values["confidence"] = min(values["confidence"], 2)
        values["testability"] = min(values["testability"], 2)
        values["likelihood"] = min(values["likelihood"], 2)
    if semantics.semantic_class in {
        IdentifierSemanticClass.REGION,
        IdentifierSemanticClass.SHARED_SCOPE,
        IdentifierSemanticClass.COLLECTION,
        IdentifierSemanticClass.NON_SECURITY_RELEVANT,
    }:
        values["confidence"] = min(values["confidence"], 1)
        values["testability"] = min(values["testability"], 1)
        values["likelihood"] = min(values["likelihood"], 1)
    elif semantics.semantic_class == IdentifierSemanticClass.OBJECT_IDENTIFIER:
        values["confidence"] = min(values["confidence"], 2)
        values["testability"] = min(values["testability"], 2)
        values["likelihood"] = min(values["likelihood"], 2)
    elif (
        semantics.semantic_class == IdentifierSemanticClass.OWNED_OBJECT
        and semantics.ownership_state in {OwnershipState.CONFIRMED, OwnershipState.STRONG_INFERRED}
    ):
        values["confidence"] = min(5, values["confidence"] + 1)
        coverage = record.readiness_assessment.comparison_coverage
        if coverage.observed_distinct_actors >= coverage.required_distinct_actors:
            values["testability"] = min(5, values["testability"] + 1)
        else:
            values["testability"] = min(values["testability"], 3)
    if any(
        item.capability in {CapabilityKind.BASELINE, CapabilityKind.BUDGET, CapabilityKind.CLEANUP}
        and item.required
        and not item.satisfied
        for item in record.readiness_assessment.capabilities
    ):
        values["testability"] = min(values["testability"], 3)
    if semantics.counterevidence:
        values["likelihood"] = max(1, values["likelihood"] - 1)
    if record.generation_rule.get("id", "").startswith("JWT_ALGORITHM_VALIDATION") and (
        claim_strength_rank(record.claim_strength.target_level) <= 2
    ):
        values["impact"] = min(values["impact"], 3)
        values["confidence"] = min(values["confidence"], 3)
    if record.kind == "RESEARCH_TASK" or record.disposition != "ACTIVE":
        values["likelihood"] = 1
        values["confidence"] = 1
        values["testability"] = 1
    canonical = canonical_scoring(
        values["impact"],
        values["likelihood"],
        values["confidence"],
        values["testability"],
    )
    return canonical.scores, canonical.priority


def _primary(records: list[HypothesisRecord]) -> HypothesisRecord:
    readiness_rank = {"TEST_READY": 0, "REVIEW_REQUIRED": 1, "RESEARCH_ONLY": 2}
    generator_rank = {"phase3-hypothesis-generator": 0, "business-logic-analysis": 1}
    return sorted(
        records,
        key=lambda item: (
            0 if _base_visible(item) else 1,
            0 if item.kind == "SECURITY_HYPOTHESIS" else 1,
            readiness_rank[item.readiness],
            canonicalize_scores(item.scores).ranking_key,
            generator_rank.get(_generator(item), 2),
            item.id,
        ),
    )[0]


def _campaign_title(primary: HypothesisRecord, members: list[HypothesisRecord]) -> str:
    descriptor = primary.semantic_descriptor
    assert descriptor is not None
    if descriptor.weakness_family == "AUTHENTICATION_COVERAGE":
        services = ", ".join(descriptor.target_services) or "target service"
        return f"Authentication coverage gaps for {services} across {len(members)} records"
    if descriptor.weakness_family == "SINGLE_EXECUTION":
        return (
            "Single-execution and idempotency campaign for "
            f"{primary.domain_intent.subject_resource}"
        )
    if descriptor.weakness_family == "VALUE_VALIDATION":
        return f"Value-validation campaign for {primary.domain_intent.subject_resource} creation"
    family = descriptor.weakness_family.replace("_", " ").title()
    return f"{family} campaign for {primary.domain_intent.subject_resource}"


def _campaign_relationship(records: list[HypothesisRecord]) -> SemanticRelationship:
    routes = {
        tuple(record.semantic_descriptor.route_families)
        for record in records
        if record.semantic_descriptor is not None
    }
    return (
        SemanticRelationship.OVERLAPPING_TEST_CAMPAIGN
        if len(routes) == 1
        else SemanticRelationship.RELATED_DISTINCT
    )


def _campaign_shared_setup(primary: HypothesisRecord) -> list[str]:
    descriptor = primary.semantic_descriptor
    assert descriptor is not None
    services = ", ".join(descriptor.target_services) or "the reviewed target service"
    routes = ", ".join(descriptor.route_families) or "the reviewed route family"
    return [
        f"Reuse the same reviewed target scope and authentication context for {services}.",
        (
            f"Reuse controlled {primary.domain_intent.subject_resource} lifecycle baselines only "
            f"when they match {routes}; preserve each member's concrete parent context."
        ),
    ]


def _campaign_distinctions(members: list[HypothesisRecord]) -> list[str]:
    return sorted(
        {
            reason
            for index, member in enumerate(members)
            for peer in members[index + 1 :]
            for reason in _difference_reasons(member, [peer])
        }
    )


def _refresh_checksum(record: HypothesisRecord) -> HypothesisRecord:
    if record.generation is None:
        return record
    payload = record.model_dump(mode="json", exclude_none=True)
    generation = payload.pop("generation")
    for field in ("status", "epistemic_status", "notes"):
        payload.pop(field, None)
    generation["generated_checksum"] = stable_fingerprint(payload)
    return record.model_copy(update={"generation": record.generation.model_copy(update=generation)})


def _display_descriptor_value(value: object) -> str:
    if value is None:
        return "none"
    if isinstance(value, list):
        return ", ".join(str(item) for item in value) or "none"
    return str(value)


def _difference_reasons(
    record: HypothesisRecord,
    peers: list[HypothesisRecord],
) -> list[str]:
    descriptor = record.semantic_descriptor
    if descriptor is None:
        return []
    reasons: list[str] = []
    for peer in sorted(peers, key=lambda item: item.id):
        peer_descriptor = peer.semantic_descriptor
        if peer_descriptor is None:
            continue
        differences = [
            (
                f"{label} is {_display_descriptor_value(getattr(descriptor, field))} "
                f"instead of {_display_descriptor_value(getattr(peer_descriptor, field))}"
            )
            for label, field in _DESCRIPTOR_DIFFERENCE_FIELDS
            if getattr(descriptor, field) != getattr(peer_descriptor, field)
        ]
        if differences:
            reasons.append(f"Differs from {peer.id}: " + "; ".join(differences) + ".")
    return reasons


def _presentation_explanation(
    record: HypothesisRecord,
    records_by_id: dict[str, HypothesisRecord],
) -> HypothesisPresentation:
    grouping = record.grouping
    descriptor = record.semantic_descriptor
    related_ids = {
        peer.id
        for peer in records_by_id.values()
        if peer.id != record.id
        and descriptor is not None
        and peer.semantic_descriptor is not None
        and peer.semantic_descriptor.weakness_family == descriptor.weakness_family
        and set(peer.semantic_descriptor.target_services).intersection(descriptor.target_services)
        and set(peer.semantic_descriptor.route_families).intersection(descriptor.route_families)
    }
    similar_ids = sorted(
        (set(grouping.campaign_member_ids or grouping.cluster_member_ids) | related_ids)
        - {record.id}
    )
    peers = [records_by_id[item] for item in similar_ids if item in records_by_id]
    differences = _difference_reasons(record, peers)
    retention: list[str] = []
    if record.presentation.visible:
        if len(grouping.cluster_member_ids) > 1 and grouping.primary_hypothesis_id == record.id:
            retention.append(
                "Retained as the canonical representative of an exact semantic cluster; "
                "duplicate provenance remains linked."
            )
        else:
            retention.append(
                "Retained because no other record has the same exact semantic fingerprint."
            )
        target = record.mutation_target
        if target.parameter is not None:
            retention.append(
                f"Mutation target {target.parameter} at {target.location or 'unknown'} remains "
                f"distinct as {target.semantics.semantic_class.value}/"
                f"{target.semantics.resource_role.value} with ownership "
                f"{target.semantics.ownership_state.value}."
            )
        if differences:
            retention.append(
                "Related campaign records remain separate because their semantic descriptors "
                "differ."
            )
        if record.presentation.suppression_reason is None:
            retention.append("No source, evidence, or semantic suppression rule applies.")
    return record.presentation.model_copy(
        update={
            "retention_reasons": retention,
            "difference_reasons": differences,
            "similar_hypothesis_ids": similar_ids,
        }
    )


def finalize_hypothesis_store(
    target: TargetDocument,
    observations: ObservationStore,
    endpoints: EndpointStore,
    resources: ResourceStore,
    store: HypothesisStore,
) -> HypothesisStore:
    """Apply shared semantics, readiness, clustering, and presentation to HYP and BLH."""

    endpoint_by_id = {item.id: item for item in endpoints.endpoints}
    prepared: list[HypothesisRecord] = []
    for record in sorted(store.hypotheses, key=lambda item: item.id):
        selected = [
            endpoint_by_id[item] for item in record.source.endpoints if item in endpoint_by_id
        ]
        mutation_target = resolve_mutation_target(record, selected)
        semantic_record = record.model_copy(update={"mutation_target": mutation_target})
        intent = assess_domain_intent(
            target,
            selected,
            category=semantic_record.category,
            generation_rule_id=semantic_record.generation_rule.get("id", ""),
            logic_details=semantic_record.logic_details,
            mutation_target=mutation_target,
        )
        claim = assess_claim_strength(
            generation_rule_id=semantic_record.generation_rule.get("id", ""),
            category=semantic_record.category,
            intent=intent,
            eligibility_evidence=semantic_record.eligibility_evidence,
        )
        target_class = mutation_target.semantics.semantic_class
        if semantic_record.category == "authorization" and (
            intent.visibility in {VisibilityIntent.PUBLIC, VisibilityIntent.SHARED}
            or target_class
            in {
                IdentifierSemanticClass.REGION,
                IdentifierSemanticClass.SHARED_SCOPE,
                IdentifierSemanticClass.COLLECTION,
                IdentifierSemanticClass.NON_SECURITY_RELEVANT,
            }
        ):
            semantic_record = semantic_record.model_copy(
                update={
                    "kind": "RESEARCH_TASK",
                    "disposition": (
                        "NEEDS_RESEARCH"
                        if semantic_record.disposition == "ACTIVE"
                        else semantic_record.disposition
                    ),
                    "priority": "P3",
                    "priority_rationale": [
                        *semantic_record.priority_rationale,
                        (
                            f"Mutation target {mutation_target.parameter or 'unknown'} is "
                            f"classified as {target_class.value}, not an owned-object boundary."
                        ),
                    ],
                }
            )
        assessment = assess_record_readiness(
            target,
            observations,
            endpoints.endpoints,
            resources,
            semantic_record,
            intent,
            claim,
        )
        updated = semantic_record.model_copy(
            deep=True,
            update={
                "readiness": assessment.readiness,
                "readiness_assessment": assessment,
                "domain_intent": intent,
                "claim_strength": claim,
                "grouping": HypothesisGrouping(),
                "presentation": HypothesisPresentation(
                    visible=_base_visible(record),
                    display_title=None,
                ),
            },
        )
        selected = [
            endpoint_by_id[item] for item in updated.source.endpoints if item in endpoint_by_id
        ]
        title = _title(updated, selected)
        scores, priority = _calibrated_scores(updated)
        updated = updated.model_copy(
            update={"title": title, "scores": scores, "priority": priority}
        )
        updated = updated.model_copy(update={"semantic_descriptor": _descriptor(updated, selected)})
        prepared.append(updated)

    exact_groups: dict[str, list[HypothesisRecord]] = defaultdict(list)
    for record in prepared:
        if record.semantic_descriptor is not None:
            exact_groups[record.semantic_descriptor.exact_key].append(record)
    updates: dict[str, HypothesisRecord] = {item.id: item for item in prepared}
    cluster_primary_ids: list[str] = []
    for exact_key, members in sorted(exact_groups.items()):
        ordered = sorted(members, key=lambda item: item.id)
        primary = _primary(ordered)
        cluster_id = f"HXC-{exact_key[:16].upper()}"
        cluster_primary_ids.append(primary.id)
        generators = sorted({_generator(item) for item in ordered})
        for member in ordered:
            relationship = (
                SemanticRelationship.EXACT_DUPLICATE
                if len(ordered) > 1
                else SemanticRelationship.NONE
            )
            presentation = member.presentation.model_copy(
                update={
                    "visible": member.presentation.visible and member.id == primary.id,
                    "suppression_reason": (
                        f"Exact semantic duplicate of {primary.id}; provenance is retained."
                        if member.id != primary.id
                        else member.presentation.suppression_reason
                    ),
                }
            )
            updates[member.id] = member.model_copy(
                update={
                    "grouping": HypothesisGrouping(
                        cluster_id=cluster_id,
                        relationship=relationship,
                        primary_hypothesis_id=primary.id,
                        cluster_member_ids=[item.id for item in ordered],
                        member_generators=generators,
                    ),
                    "presentation": presentation,
                }
            )

    campaign_groups: dict[str, list[HypothesisRecord]] = defaultdict(list)
    for primary_id in sorted(set(cluster_primary_ids)):
        record = updates[primary_id]
        if record.semantic_descriptor is not None and _campaign_eligible(record):
            campaign_groups[record.semantic_descriptor.campaign_key].append(record)
    campaigns: list[HypothesisCampaign] = []
    for campaign_key, primaries in sorted(campaign_groups.items()):
        if len(primaries) < 2:
            continue
        ordered_primaries = sorted(primaries, key=lambda item: item.id)
        primary = _primary(ordered_primaries)
        relationship = _campaign_relationship(ordered_primaries)
        campaign_id = f"HCMP-{campaign_key[:16].upper()}"
        campaign_member_ids = sorted(
            {
                member_id
                for item in ordered_primaries
                for member_id in updates[item.id].grouping.cluster_member_ids
            }
        )
        all_members = [updates[item] for item in campaign_member_ids]
        generators = sorted({_generator(item) for item in all_members})
        auth_campaign = (
            primary.semantic_descriptor is not None
            and primary.semantic_descriptor.weakness_family == "AUTHENTICATION_COVERAGE"
        )
        title = _campaign_title(primary, all_members)
        campaign_cluster_ids: set[str] = set()
        for member_id in campaign_member_ids:
            member_cluster_id = updates[member_id].grouping.cluster_id
            if member_cluster_id is not None:
                campaign_cluster_ids.add(member_cluster_id)
        for item in all_members:
            existing = updates[item.id]
            item_relationship = existing.grouping.relationship
            if item_relationship != SemanticRelationship.EXACT_DUPLICATE:
                item_relationship = relationship
            visible = existing.presentation.visible
            suppression = existing.presentation.suppression_reason
            if auth_campaign and existing.id != primary.id and visible:
                visible = False
                suppression = (
                    f"Represented by authentication-coverage campaign {campaign_id}; "
                    "member evidence is retained."
                )
            updates[item.id] = existing.model_copy(
                update={
                    "grouping": existing.grouping.model_copy(
                        update={
                            "campaign_id": campaign_id,
                            "relationship": item_relationship,
                            "campaign_member_ids": campaign_member_ids,
                            "member_generators": generators,
                        }
                    ),
                    "presentation": existing.presentation.model_copy(
                        update={
                            "visible": visible,
                            "display_title": (
                                title if auth_campaign and existing.id == primary.id else None
                            ),
                            "suppression_reason": suppression,
                            "next_action": (
                                "Collect one bounded authentication-control matrix for the "
                                "campaign."
                                if auth_campaign
                                else existing.presentation.next_action
                            ),
                        }
                    ),
                }
            )
        campaigns.append(
            HypothesisCampaign(
                id=campaign_id,
                key=campaign_key,
                title=title,
                relationship=relationship,
                primary_hypothesis_id=primary.id,
                member_ids=campaign_member_ids,
                member_generators=generators,
                cluster_ids=sorted(campaign_cluster_ids),
                target_services=sorted(
                    {
                        service
                        for item in all_members
                        if item.semantic_descriptor is not None
                        for service in item.semantic_descriptor.target_services
                    }
                ),
                authentication_schemes=sorted(
                    {
                        endpoint_by_id[endpoint_id].authentication.observed_type
                        for item in all_members
                        for endpoint_id in item.source.endpoints
                        if endpoint_id in endpoint_by_id
                    }
                ),
                affected_endpoints=sorted(
                    {endpoint for item in all_members for endpoint in item.source.endpoints}
                ),
                affected_resources=sorted(
                    {item.domain_intent.subject_resource for item in all_members}
                ),
                shared_setup=_campaign_shared_setup(primary),
                distinctions=_campaign_distinctions(all_members),
                missing_controls=_AUTH_COVERAGE_CONTROLS if auth_campaign else [],
                next_action=(
                    "Collect one authorized bounded control matrix across the affected endpoints."
                    if auth_campaign
                    else (
                        "Reuse the controlled setup and execute each distinct mutation/oracle "
                        "separately."
                    )
                ),
            )
        )

    explained = {
        identifier: record.model_copy(
            update={"presentation": _presentation_explanation(record, updates)}
        )
        for identifier, record in sorted(updates.items())
    }
    finalized = [_refresh_checksum(explained[item]) for item in sorted(explained)]
    return HypothesisStore(
        version=3, hypotheses=finalized, campaigns=sorted(campaigns, key=lambda item: item.id)
    )


def presentation_title(record: HypothesisRecord) -> str:
    """Return the queue title without mutating the retained generated title."""

    return record.presentation.display_title or record.title


def presentation_visible(record: HypothesisRecord) -> bool:
    """Return common queue visibility with a safe legacy fallback."""

    return record.presentation.visible and _base_visible(record)
