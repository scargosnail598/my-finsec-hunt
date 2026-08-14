"""Deterministic identifier classification without assuming ownership from shape."""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass
from typing import Literal

from finsec.captures.domain import observation_supports_normal_behavior
from finsec.config.models import TargetDocument
from finsec.modeling.models import EndpointParameter, Observation
from finsec.modeling.semantics import (
    IdentifierResourceRole,
    IdentifierSemanticAssessment,
    IdentifierSemanticClass,
    OwnershipState,
)
from finsec.normalization.ownership import normalized_parameter_name
from finsec.normalization.path_semantics import path_hierarchy
from finsec.normalization.path_semantics import (
    structural_parent_resource as canonical_structural_parent_resource,
)

TENANT_NAMES = {
    "account",
    "accountid",
    "customer",
    "customerid",
    "organization",
    "organizationid",
    "org",
    "orgid",
    "tenant",
    "tenantid",
    "workspace",
    "workspaceid",
}
ACTOR_NAMES = {
    "actor",
    "actorid",
    "member",
    "memberid",
    "owner",
    "ownerid",
    "user",
    "userid",
}
AUTH_NAMES = {
    "apikey",
    "authorization",
    "challenge",
    "challengeid",
    "nonce",
    "session",
    "sessionid",
    "token",
}
REGION_NAMES = {"az", "availabilityzone", "availabilityzoneid", "region", "regionid"}
COLLECTION_NAMES = {"cursor", "limit", "offset", "page"}
SHARED_NAMES = {
    "category",
    "categoryid",
    "country",
    "countryid",
    "language",
    "languageid",
    "plan",
    "planid",
}


def _region_semantics(path: str, normalized: str, resource_type: str | None) -> bool:
    if normalized in REGION_NAMES:
        return True
    if normalized not in {"zone", "zoneid"}:
        return False
    route = _snake(path)
    resource = _snake(resource_type or "")
    return "availability_zone" in route or resource in {"availability_zone", "region"}


def _snake(value: str) -> str:
    split = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", value)
    return re.sub(r"[^a-z0-9]+", "_", split.lower()).strip("_")


def _singular(value: str) -> str:
    if value.endswith("ies") and len(value) > 3:
        return f"{value[:-3]}y"
    if value.endswith("sses"):
        return value[:-2]
    if value.endswith("s") and not value.endswith(("ss", "us")):
        return value[:-1]
    return value


def _display_resource(value: str) -> str:
    return "".join(item[:1].upper() + item[1:] for item in _snake(value).split("_"))


def _named_resource(parameter: str, fallback: str) -> str:
    stem = re.sub(r"(?:_?id|_?identifier|_?reference)$", "", parameter, flags=re.I)
    return _display_resource(stem) if stem else fallback


def _parameter_value(template: str, concrete: str, parameter: str) -> str | None:
    expected = [item for item in template.split("/") if item]
    actual = [item for item in concrete.split("/") if item]
    if len(expected) != len(actual):
        return None
    marker = f"{{{parameter}}}"
    matches = [value for item, value in zip(expected, actual, strict=True) if item == marker]
    return matches[0] if len(matches) == 1 else None


@dataclass(frozen=True)
class StructuralParameterRole:
    role: IdentifierResourceRole
    resource_type: str | None
    parent_resource_type: str | None


def structural_parameter_role(
    path: str,
    parameter: str,
    endpoint_resource: str,
) -> StructuralParameterRole:
    """Resolve parent/child position without treating path nesting as ownership."""

    hierarchy = path_hierarchy(path, path, endpoint_resource)
    node = next((item for item in hierarchy.nodes if item.parameter == parameter), None)
    if node is None:
        return StructuralParameterRole(IdentifierResourceRole.UNKNOWN, None, None)
    if hierarchy.subject is not None and node.collection_index < hierarchy.subject.collection_index:
        role = IdentifierResourceRole.PARENT
    elif normalized_parameter_name(node.resource_type) == normalized_parameter_name(
        endpoint_resource
    ):
        role = IdentifierResourceRole.CHILD_OBJECT
    else:
        role = IdentifierResourceRole.SUBJECT
    parent = next(
        (
            item
            for item in reversed(hierarchy.nodes)
            if item.collection_index < node.collection_index and item.value_index is not None
        ),
        None,
    )
    return StructuralParameterRole(
        role,
        node.resource_type,
        parent.resource_type if parent is not None else None,
    )


def structural_parent_resource(path: str, endpoint_resource: str) -> str | None:
    """Return the immediate nested parent resource type for an endpoint route."""

    return canonical_structural_parent_resource(path, endpoint_resource)


def _actor_value_evidence(
    path: str,
    parameter: str,
    observations: list[Observation],
    controlled_actors: set[str],
) -> tuple[dict[str, set[str]], dict[str, set[str]], list[str]]:
    actor_values: dict[str, set[str]] = defaultdict(set)
    value_actors: dict[str, set[str]] = defaultdict(set)
    evidence: list[str] = []
    for observation in observations:
        if (
            observation.actor not in controlled_actors
            or not observation.authentication.present
            or observation.status_code is None
            or not 200 <= observation.status_code < 300
            or not observation_supports_normal_behavior(observation)
        ):
            continue
        value = _parameter_value(path, observation.path, parameter)
        if value is None:
            continue
        actor_values[observation.actor].add(value)
        value_actors[value].add(observation.actor)
        evidence.append(observation.id)
    return actor_values, value_actors, sorted(set(evidence))


def _cross_actor_rejections(
    path: str,
    parameter: str,
    observations: list[Observation],
    controlled_actors: set[str],
    value_actors: dict[str, set[str]],
) -> list[str]:
    rejected: list[str] = []
    for observation in observations:
        if (
            observation.actor not in controlled_actors
            or not observation.authentication.present
            or observation.status_code not in {403, 404}
        ):
            continue
        value = _parameter_value(path, observation.path, parameter)
        owners = value_actors.get(value or "", set())
        if owners and observation.actor not in owners:
            rejected.append(observation.id)
    return sorted(set(rejected))


def classify_identifier_semantics(
    *,
    path: str,
    endpoint_resource: str,
    parameter: EndpointParameter,
    observations: list[Observation],
    target: TargetDocument,
) -> IdentifierSemanticAssessment:
    """Classify one parameter from policy, structure, and conservative actor variance."""

    normalized = normalized_parameter_name(parameter.name)
    evidence: list[str] = []
    counterevidence: list[str] = []
    sources: list[str] = []
    structural = structural_parameter_role(path, parameter.name, endpoint_resource)
    resource_type = structural.resource_type or _named_resource(parameter.name, endpoint_resource)
    semantic_class = IdentifierSemanticClass.OPAQUE_UNKNOWN
    resource_role = structural.role
    ownership_state = OwnershipState.UNKNOWN
    confidence: Literal["low", "medium", "high"] = "low"

    if parameter.semantic_type == "pagination" or normalized in COLLECTION_NAMES:
        semantic_class = IdentifierSemanticClass.COLLECTION
        resource_role = IdentifierResourceRole.COLLECTION
        confidence = "high"
        evidence.append("Parameter represents collection traversal rather than an object identity.")
        sources.append("PARAMETER_NAME")
    elif parameter.semantic_type == "authentication" or normalized in AUTH_NAMES:
        semantic_class = IdentifierSemanticClass.AUTH_IDENTIFIER
        resource_role = IdentifierResourceRole.AUTH
        confidence = "high"
        evidence.append("Parameter name has authentication or session semantics.")
        sources.append("PARAMETER_NAME")
    elif normalized in ACTOR_NAMES:
        semantic_class = IdentifierSemanticClass.ACTOR_IDENTIFIER
        resource_role = IdentifierResourceRole.ACTOR
        confidence = "high"
        evidence.append("Parameter identifies an actor or user, not an actor-owned object.")
        sources.append("PARAMETER_NAME")
    elif _region_semantics(path, normalized, structural.resource_type):
        semantic_class = IdentifierSemanticClass.REGION
        resource_role = IdentifierResourceRole.SHARED_SCOPE
        ownership_state = OwnershipState.SHARED
        confidence = "high"
        evidence.append("Parameter name denotes a region or availability-zone scope.")
        sources.append("PARAMETER_NAME")
    elif normalized in TENANT_NAMES:
        semantic_class = IdentifierSemanticClass.TENANT_CONTAINER
        resource_role = IdentifierResourceRole.TENANT
        ownership_state = OwnershipState.WEAK_INFERRED
        confidence = "high"
        evidence.append("Parameter denotes a tenant/account container boundary.")
        sources.append("PARAMETER_NAME")
    else:
        configured_shared = {
            normalized_parameter_name(item)
            for item in target.analysis.ownership_inference.public_shared_parameters
        }
        configured_parents = {
            normalized_parameter_name(item)
            for item in target.analysis.ownership_inference.trusted_parent_parameters
        }
        if normalized in configured_shared:
            semantic_class = IdentifierSemanticClass.SHARED_SCOPE
            resource_role = IdentifierResourceRole.SHARED_SCOPE
            ownership_state = OwnershipState.SHARED
            confidence = "high"
            evidence.append("Target policy or parameter semantics classify this as shared scope.")
            sources.append("TARGET_POLICY")
        elif normalized in configured_parents or structural.role == IdentifierResourceRole.PARENT:
            semantic_class = IdentifierSemanticClass.PARENT_CONTAINER
            resource_role = IdentifierResourceRole.PARENT
            ownership_state = OwnershipState.WEAK_INFERRED
            confidence = "medium"
            evidence.append("Nested route structure identifies this as a parent/container.")
            sources.append("PATH_STRUCTURE")
        elif parameter.semantic_type == "object_identifier" and structural.role in {
            IdentifierResourceRole.SUBJECT,
            IdentifierResourceRole.CHILD_OBJECT,
            IdentifierResourceRole.UNKNOWN,
        }:
            semantic_class = IdentifierSemanticClass.OBJECT_IDENTIFIER
            if resource_role == IdentifierResourceRole.UNKNOWN:
                resource_role = IdentifierResourceRole.SUBJECT
            ownership_state = OwnershipState.UNKNOWN
            confidence = "medium"
            evidence.append(
                "Parameter selects the endpoint subject or nested child object, so it is an "
                "object-identifier candidate; ownership requires independent evidence."
            )
            sources.append("PATH_STRUCTURE")
        elif normalized in SHARED_NAMES:
            semantic_class = IdentifierSemanticClass.OPAQUE_UNKNOWN
            confidence = "low"
            evidence.append(
                "Parameter name suggests shared scope, but name-only evidence is insufficient."
            )
            sources.append("PARAMETER_NAME")
        elif parameter.location == "path" and normalized == "filename":
            semantic_class = IdentifierSemanticClass.NON_SECURITY_RELEVANT
            confidence = "high"
            evidence.append("The normalized path parameter represents a filename, not an object.")
            sources.append("PATH_STRUCTURE")

    controlled = {item.id for item in target.accounts if item.ownership == "researcher"}
    actor_values, value_actors, observation_ids = _actor_value_evidence(
        path, parameter.name, observations, controlled
    )
    if observation_ids:
        sources.append("NORMAL_BEHAVIOR")
    shared_values = sorted(value for value, actors in value_actors.items() if len(actors) >= 2)
    stable_actor_values = bool(actor_values) and all(
        len(values) == 1 for values in actor_values.values()
    )
    distinct_actor_values = (
        {next(iter(values)) for values in actor_values.values()} if stable_actor_values else set()
    )
    if shared_values:
        counterevidence.append(
            "The same successful normal-behavior value is used by multiple controlled actors."
        )
        ownership_state = OwnershipState.SHARED
        confidence = "high"
        if semantic_class in {
            IdentifierSemanticClass.REGION,
            IdentifierSemanticClass.SHARED_SCOPE,
        }:
            resource_role = IdentifierResourceRole.SHARED_SCOPE
        elif semantic_class == IdentifierSemanticClass.OWNED_OBJECT:
            semantic_class = IdentifierSemanticClass.OBJECT_IDENTIFIER
    elif len(actor_values) >= 2 and len(distinct_actor_values) >= 2:
        evidence.append(
            "Equivalent successful actor baselines use distinct identifier values; this supports "
            "actor scoping but does not alone prove ownership."
        )
        counterevidence.append(
            "No successful identifier value is reused across controlled actor baselines; the "
            "observed differentiation is consistent with secure account scoping."
        )
        if semantic_class == IdentifierSemanticClass.OBJECT_IDENTIFIER:
            semantic_class = IdentifierSemanticClass.OWNED_OBJECT
            ownership_state = OwnershipState.WEAK_INFERRED
            confidence = "medium"

    rejected_cross_actor = _cross_actor_rejections(
        path, parameter.name, observations, controlled, value_actors
    )
    if rejected_cross_actor:
        counterevidence.append(
            "Observed cross-actor requests for another controlled actor's identifier were "
            "consistently rejected with 403/404."
        )
        sources.append("SECURE_CONTROL_OBSERVATION")
        evidence.extend(rejected_cross_actor)

    explanation = {
        IdentifierSemanticClass.OWNED_OBJECT: (
            "The identifier selects a subject/child object, but exclusive actor control is only "
            "as strong as the retained ownership evidence."
        ),
        IdentifierSemanticClass.OBJECT_IDENTIFIER: (
            "The identifier selects a subject/child object, but current evidence does not "
            "establish which actor owns or controls it."
        ),
        IdentifierSemanticClass.REGION: (
            "The identifier is infrastructure scope and is not an actor-owned object."
        ),
        IdentifierSemanticClass.SHARED_SCOPE: (
            "The identifier is shared/global scope and is not suitable for object substitution."
        ),
        IdentifierSemanticClass.TENANT_CONTAINER: (
            "The identifier denotes a tenant/account container, not a child owned object."
        ),
        IdentifierSemanticClass.PARENT_CONTAINER: (
            "The identifier structurally scopes a nested resource; path nesting alone is not "
            "ownership evidence."
        ),
        IdentifierSemanticClass.COLLECTION: (
            "The identifier controls collection traversal rather than an authorization object."
        ),
        IdentifierSemanticClass.ACTOR_IDENTIFIER: (
            "The identifier names the acting principal rather than a separate owned object."
        ),
        IdentifierSemanticClass.AUTH_IDENTIFIER: (
            "The identifier belongs to authentication/session semantics."
        ),
        IdentifierSemanticClass.NON_SECURITY_RELEVANT: (
            "The identifier has no current security-boundary relevance."
        ),
        IdentifierSemanticClass.OPAQUE_UNKNOWN: (
            "Current evidence does not establish object, scope, parent, actor, or auth semantics."
        ),
    }[semantic_class]
    return IdentifierSemanticAssessment(
        semantic_class=semantic_class,
        resource_role=resource_role,
        resource_type=resource_type,
        parent_resource_type=structural.parent_resource_type,
        ownership_state=ownership_state,
        confidence=confidence,
        evidence=sorted(set(evidence)),
        counterevidence=sorted(set(counterevidence)),
        sources=sorted(set(sources)),
        explanation=explanation,
    )


def classify_endpoint_parameters(
    *,
    path: str,
    endpoint_resource: str,
    parameters: list[EndpointParameter],
    observations: list[Observation],
    target: TargetDocument,
) -> list[EndpointParameter]:
    """Attach canonical semantics to every endpoint parameter deterministically."""

    return [
        parameter.model_copy(
            update={
                "identifier_semantics": classify_identifier_semantics(
                    path=path,
                    endpoint_resource=endpoint_resource,
                    parameter=parameter,
                    observations=observations,
                    target=target,
                )
            }
        )
        for parameter in parameters
    ]
