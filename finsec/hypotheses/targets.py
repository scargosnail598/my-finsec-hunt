"""Resolve one canonical mutation target for hypothesis semantics and planning."""

from __future__ import annotations

import re

from finsec.hypotheses.contracts import MutationTargetAssessment
from finsec.hypotheses.domain import HypothesisRecord
from finsec.modeling.models import Endpoint, EndpointParameter
from finsec.modeling.semantics import IdentifierSemanticClass


def _normalized(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", value.lower())


def _key_parameter(record: HypothesisRecord) -> str | None:
    if record.generation_rule.get("id", "").startswith("AUTH_OBJECT_ACCESS"):
        value = record.key.rsplit(":", 1)[-1]
        return value or None
    details = record.logic_details or {}
    for key in ("mutation_parameter", "candidate_field", "mutated_field"):
        detail_value = details.get(key)
        if isinstance(detail_value, str) and detail_value.strip():
            return detail_value.rsplit(".", 1)[-1]
    return None


def _candidate_parameters(
    record: HypothesisRecord,
    endpoints: list[Endpoint],
) -> list[tuple[Endpoint, EndpointParameter]]:
    requested = _key_parameter(record)
    if requested is None and not {"OBJECT", "VALUE"}.intersection(record.mutation_dimensions):
        return []
    requested_key = _normalized(requested) if requested is not None else None
    candidates = [
        (endpoint, parameter)
        for endpoint in endpoints
        for parameter in endpoint.parameters
        if parameter.source == "request" and parameter.client_controlled
    ]
    if requested_key is not None:
        exact = [item for item in candidates if _normalized(item[1].name) == requested_key]
        if exact:
            return exact
    ownership_targets = [
        item
        for item in candidates
        if item[1].identifier_semantics.semantic_class == IdentifierSemanticClass.OWNED_OBJECT
    ]
    return ownership_targets or candidates


def _authorization_relationship(semantic_class: IdentifierSemanticClass) -> str:
    return {
        IdentifierSemanticClass.OWNED_OBJECT: "ACTOR_TO_OWNED_OBJECT",
        IdentifierSemanticClass.OBJECT_IDENTIFIER: "POTENTIAL_OBJECT_BOUNDARY",
        IdentifierSemanticClass.TENANT_CONTAINER: "ACTOR_TO_TENANT_CONTAINER",
        IdentifierSemanticClass.PARENT_CONTAINER: "PARENT_SCOPES_CHILD",
        IdentifierSemanticClass.SHARED_SCOPE: "SHARED_SCOPE",
        IdentifierSemanticClass.REGION: "SHARED_INFRASTRUCTURE_SCOPE",
        IdentifierSemanticClass.ACTOR_IDENTIFIER: "ACTOR_IDENTITY",
        IdentifierSemanticClass.AUTH_IDENTIFIER: "AUTHENTICATION_BINDING",
        IdentifierSemanticClass.COLLECTION: "COLLECTION_TRAVERSAL",
        IdentifierSemanticClass.NON_SECURITY_RELEVANT: "NONE",
        IdentifierSemanticClass.OPAQUE_UNKNOWN: "UNKNOWN",
    }[semantic_class]


def resolve_mutation_target(
    record: HypothesisRecord,
    endpoints: list[Endpoint],
) -> MutationTargetAssessment:
    """Resolve the exact parameter used by generation, deduplication, and planning."""

    candidates = _candidate_parameters(record, endpoints)
    if not candidates:
        return MutationTargetAssessment(endpoint_ids=sorted(item.id for item in endpoints))
    ordered = sorted(
        candidates,
        key=lambda item: (
            0 if item[0].id in record.source.endpoints else 1,
            item[0].id,
            item[1].location,
            item[1].name,
        ),
    )
    endpoint, parameter = ordered[0]
    matching_endpoint_ids = sorted(
        {
            item.id
            for item, candidate in ordered
            if _normalized(candidate.name) == _normalized(parameter.name)
        }
    )
    semantics = parameter.identifier_semantics
    return MutationTargetAssessment(
        parameter=parameter.name,
        location=parameter.location,
        endpoint_ids=matching_endpoint_ids or [endpoint.id],
        semantics=semantics,
        expected_authorization_relationship=_authorization_relationship(semantics.semantic_class),
    )
