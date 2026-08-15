"""Resolve one canonical mutation target for hypothesis semantics and planning."""

from __future__ import annotations

from finsec.hypotheses.contracts import MutationTargetAssessment
from finsec.hypotheses.domain import HypothesisRecord
from finsec.modeling.models import Endpoint, EndpointParameter
from finsec.modeling.parameter_identity import (
    normalize_json_path,
    normalize_parameter_name,
    parameter_identities_match,
)
from finsec.modeling.semantics import IdentifierSemanticClass


def _key_target(record: HypothesisRecord) -> tuple[str | None, str | None, bool]:
    if record.generation_rule.get("id", "").startswith("AUTH_OBJECT_ACCESS"):
        parts = record.key.rsplit(":", 2)
        value = parts[-1]
        location = (
            parts[-2]
            if len(parts) == 3
            and parts[-2]
            in {
                "path",
                "query",
                "body",
                "header",
                "cookie",
                "graphql_variable",
            }
            else None
        )
        return value or None, location, location is None
    details = record.logic_details or {}
    for key in ("mutation_parameter", "candidate_field", "mutated_field"):
        detail_value = details.get(key)
        if isinstance(detail_value, str) and detail_value.strip():
            raw_location = details.get("mutation_location")
            location = raw_location if isinstance(raw_location, str) else None
            return (
                detail_value.strip(),
                location,
                False,
            )
    return None, None, False


def _candidate_parameters(
    record: HypothesisRecord,
    endpoints: list[Endpoint],
) -> list[tuple[Endpoint, EndpointParameter]]:
    requested, requested_location, legacy = _key_target(record)
    if requested is None and not {"OBJECT", "VALUE"}.intersection(record.mutation_dimensions):
        return []
    if requested is None:
        return []
    requested_key = normalize_parameter_name(requested.rsplit(".", 1)[-1])
    candidates = [
        (endpoint, parameter)
        for endpoint in endpoints
        for parameter in endpoint.parameters
        if parameter.source == "request" and parameter.client_controlled
    ]
    if requested_location is None:
        candidates = [item for item in candidates if item[1].location == "path"]
    else:
        exact_identity = [
            item
            for item in candidates
            if parameter_identities_match(
                evidence_location=item[1].location,
                evidence_json_path=item[1].json_path,
                evidence_name=item[1].name,
                target_location=requested_location,
                target_json_path=requested if requested_location == "body" else None,
                target_name=requested.rsplit(".", 1)[-1],
            )
        ]
        if exact_identity:
            return exact_identity
        return []
    exact = [item for item in candidates if normalize_parameter_name(item[1].name) == requested_key]
    if len(exact) == 1 and (legacy or "." not in requested):
        return exact
    return []


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
            normalize_json_path(item[1].json_path) or "",
            item[1].name,
        ),
    )
    endpoint, parameter = ordered[0]
    matching_endpoint_ids = sorted(
        {
            item.id
            for item, candidate in ordered
            if parameter_identities_match(
                evidence_location=candidate.location,
                evidence_json_path=candidate.json_path,
                evidence_name=candidate.name,
                target_location=parameter.location,
                target_json_path=parameter.json_path,
                target_name=parameter.name,
            )
        }
    )
    semantics = parameter.identifier_semantics
    return MutationTargetAssessment(
        parameter=parameter.name,
        location=parameter.location,
        json_path=normalize_json_path(parameter.json_path),
        endpoint_ids=matching_endpoint_ids or [endpoint.id],
        semantics=semantics,
        expected_authorization_relationship=_authorization_relationship(semantics.semantic_class),
    )
