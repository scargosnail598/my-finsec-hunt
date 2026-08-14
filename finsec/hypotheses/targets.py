"""Resolve one canonical mutation target for hypothesis semantics and planning."""

from __future__ import annotations

import re

from finsec.hypotheses.contracts import MutationTargetAssessment
from finsec.hypotheses.domain import HypothesisRecord
from finsec.modeling.models import Endpoint, EndpointParameter
from finsec.modeling.semantics import IdentifierSemanticClass


def _normalized(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", value.lower())


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
    requested_key = _normalized(requested.rsplit(".", 1)[-1])
    candidates = [
        (endpoint, parameter)
        for endpoint in endpoints
        for parameter in endpoint.parameters
        if parameter.source == "request" and parameter.client_controlled
    ]
    if requested_location is not None:
        candidates = [item for item in candidates if item[1].location == requested_location]
    exact_path = [
        item
        for item in candidates
        if item[1].json_path is not None
        and item[1].json_path.removeprefix("$.").replace("[*]", "[]").casefold()
        == requested.casefold()
    ]
    if exact_path:
        return exact_path
    exact = [item for item in candidates if _normalized(item[1].name) == requested_key]
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
            item[1].name,
        ),
    )
    endpoint, parameter = ordered[0]
    matching_endpoint_ids = sorted(
        {
            item.id
            for item, candidate in ordered
            if candidate.location == parameter.location
            and candidate.json_path == parameter.json_path
            and _normalized(candidate.name) == _normalized(parameter.name)
        }
    )
    semantics = parameter.identifier_semantics
    return MutationTargetAssessment(
        parameter=parameter.name,
        location=parameter.location,
        json_path=parameter.json_path,
        endpoint_ids=matching_endpoint_ids or [endpoint.id],
        semantics=semantics,
        expected_authorization_relationship=_authorization_relationship(semantics.semantic_class),
    )
