"""Build an evidence-linked endpoint inventory from factual observations."""

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

from pydantic import ValidationError

from finsec.config.models import TargetDocument
from finsec.config.workspace import WorkspacePaths
from finsec.errors import FinsecError
from finsec.modeling.models import (
    ActorObjectBaseline,
    AuthenticationType,
    Confidence,
    Endpoint,
    EndpointAction,
    EndpointActionType,
    EndpointAuthentication,
    EndpointClassification,
    EndpointParameter,
    EndpointPrimaryClassification,
    EndpointResource,
    EndpointStore,
    KnowledgeStatus,
    NormalizationEvidence,
    ObjectAccessEvidence,
    Observation,
    ObservationStore,
    ParameterSemanticType,
    ParameterType,
)
from finsec.normalization.classification import (
    ClassificationContext,
    classify_observation,
    endpoint_disposition,
)
from finsec.normalization.paths import NormalizedPath, normalize_paths
from finsec.utils.redaction import REDACTED
from finsec.utils.yaml_store import load_yaml, write_yaml

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
READ_ACTIONS = {
    "get",
    "list",
    "search",
    "filter",
    "filters",
    "menu",
    "page",
    "viewport",
    "preview",
    "lookup",
    "status",
    "history",
    "details",
    "config",
    "places",
    "suggestions",
}
MUTATION_ACTIONS = {
    "create",
    "update",
    "edit",
    "delete",
    "remove",
    "cancel",
    "confirm",
    "approve",
    "reject",
    "consume",
    "activate",
    "deactivate",
    "submit",
    "publish",
    "refund",
    "withdraw",
    "transfer",
    "settle",
    "verify",
    "bind",
    "unbind",
    "change",
}
OBJECT_IDENTIFIER_FIELDS = {
    "id",
    "userid",
    "accountid",
    "walletid",
    "paymentid",
    "transactionid",
    "withdrawalid",
    "destinationid",
    "beneficiaryid",
    "merchantid",
    "postid",
    "invoiceid",
    "orderid",
    "resourceid",
    "ownerid",
}
MONETARY_FIELDS = {
    "amount",
    "price",
    "fee",
    "balance",
    "credit",
    "debit",
    "currency",
    "quantity",
    "refundamount",
}
STATE_FIELDS = {"status", "state", "action", "operation", "type", "mode", "step", "stage"}
AUTH_FIELDS = {"code", "otp", "challengeid", "sessionid", "verificationid", "nonce", "token"}
OWNER_ASSOCIATION_FIELDS = {
    "userid",
    "ownerid",
    "accountid",
    "customerid",
    "memberid",
    "profileid",
    "merchantid",
}


@dataclass(frozen=True)
class InventoryResult:
    """Summary returned after rebuilding endpoint inventory."""

    endpoints: int
    observations: int


def _load_observations(path: Path) -> ObservationStore:
    try:
        return ObservationStore.model_validate(load_yaml(path))
    except (OSError, ValidationError) as error:
        raise FinsecError(f"Cannot read observations from {path}: {error}") from error


def _load_endpoints(path: Path) -> EndpointStore:
    try:
        return EndpointStore.model_validate(load_yaml(path))
    except (OSError, ValidationError) as error:
        raise FinsecError(f"Cannot read endpoint inventory {path}: {error}") from error


def _load_target(path: Path) -> TargetDocument:
    try:
        return TargetDocument.model_validate(load_yaml(path))
    except (OSError, ValidationError) as error:
        raise FinsecError(f"Cannot read target configuration {path}: {error}") from error


def _number_from_id(value: str, prefix: str) -> int | None:
    match = re.fullmatch(rf"{re.escape(prefix)}-(\d+)", value)
    return int(match.group(1)) if match else None


def _resource_name(
    path: str, classification: EndpointClassification, action_name: str
) -> tuple[str, Confidence]:
    if classification.primary == EndpointPrimaryClassification.STATIC_ASSET:
        return ("StaticAsset", Confidence.HIGH)
    if classification.primary in {
        EndpointPrimaryClassification.TELEMETRY,
        EndpointPrimaryClassification.ANALYTICS,
    }:
        return ("Telemetry", Confidence.HIGH)

    lowered_path = path.lower()
    if "wallet" in lowered_path:
        return ("Wallet", Confidence.HIGH)
    if "payment" in lowered_path:
        return ("Payment", Confidence.HIGH)
    if "authenticate" in lowered_path and "/code/" in lowered_path:
        return ("AuthenticationCode", Confidence.HIGH)
    if "user_verification" in lowered_path or "user-verification" in lowered_path:
        return ("UserVerification", Confidence.HIGH)
    if "my-posts" in lowered_path and action_name == "list":
        return ("PostCollection", Confidence.HIGH)

    placeholders = re.findall(r"\{([A-Za-z][A-Za-z0-9]*)Id\}", path)
    if placeholders:
        return (placeholders[-1][0].upper() + placeholders[-1][1:], Confidence.MEDIUM)

    segments = [segment for segment in path.split("/") if segment and not segment.startswith("{")]
    ignored = {"api", "w", action_name, *READ_ACTIONS, *MUTATION_ACTIONS}
    candidates = [
        segment
        for segment in segments
        if segment.lower() not in ignored
        and not re.fullmatch(r"v\d+(?:\.\d+){0,2}", segment.lower())
    ]
    if not candidates:
        return ("Unknown", Confidence.LOW)
    value = candidates[-1].replace("-", "_")
    if value.isdigit() and len(candidates) > 1:
        value = candidates[-2].replace("-", "_")
    if value.endswith("ies"):
        value = f"{value[:-3]}y"
    elif value.endswith("s") and not value.endswith("ss"):
        value = value[:-1]
    return ("".join(part.title() for part in value.split("_")), Confidence.LOW)


def _authentication(observations: list[Observation]) -> EndpointAuthentication:
    present_types = {
        item.authentication.observed_type
        for item in observations
        if item.authentication.observed_type != "none"
    }
    anonymous_success_observed = any(
        not item.authentication.present
        and item.status_code is not None
        and 200 <= item.status_code < 300
        and bool(item.response_fields)
        for item in observations
    )
    required = bool(present_types)
    if not present_types:
        observed_type: AuthenticationType = "none"
    elif len(present_types) == 1:
        observed_type = next(iter(present_types))
    else:
        observed_type = "mixed"
    return EndpointAuthentication(
        required=required,
        observed_type=observed_type,
        anonymous_success_observed=anonymous_success_observed,
    )


def _query_parameters(observations: list[Observation]) -> list[EndpointParameter]:
    evidence: dict[str, set[str]] = {}
    values: dict[str, list[str]] = {}
    for observation in observations:
        for name, items in observation.query_parameters.items():
            evidence.setdefault(name, set()).add(observation.id)
            values.setdefault(name, []).extend(item for item in items if item != REDACTED)

    result: list[EndpointParameter] = []
    for name in sorted(evidence):
        items = values.get(name, [])
        inferred_type: ParameterType = (
            "integer" if items and all(item.isdigit() for item in items) else "string"
        )
        result.append(
            EndpointParameter(
                name=name,
                location="query",
                inferred_type=inferred_type,
                confidence=Confidence.MEDIUM,
                evidence=sorted(evidence[name]),
                knowledge_status=KnowledgeStatus.INFERRED,
            )
        )
    return result


def _path_parameters(
    normalized: NormalizedPath, observations: list[Observation]
) -> list[EndpointParameter]:
    sources = sorted(item.id for item in observations)
    return [
        EndpointParameter(
            name=item.name,
            location="path",
            inferred_type=item.inferred_type,
            confidence=item.confidence,
            evidence=sources,
            knowledge_status=KnowledgeStatus.INFERRED,
            semantic_type=("unknown" if item.name == "filename" else "object_identifier"),
            original_examples=list(item.original_examples),
            normalization_reasons=list(item.normalization_reason),
        )
        for item in normalized.parameters
    ]


def _documented_path_parameters(
    path: str, observations: list[Observation]
) -> list[EndpointParameter]:
    """Preserve explicit path-template parameters from API documentation."""

    sources = sorted(item.id for item in observations)
    return [
        EndpointParameter(
            name=name,
            location="path",
            inferred_type="string",
            confidence=Confidence.HIGH,
            evidence=sources,
            knowledge_status=KnowledgeStatus.INFERRED,
            semantic_type=("object_identifier" if name.lower().endswith("id") else "unknown"),
            normalization_reasons=["parameter name is declared by API documentation"],
        )
        for name in sorted(set(re.findall(r"\{([A-Za-z][A-Za-z0-9_]*)\}", path)))
    ]


def _field_semantic_type(name: str) -> ParameterSemanticType:
    compact = re.sub(r"[^a-z0-9]", "", name.lower())
    if compact in OBJECT_IDENTIFIER_FIELDS:
        return "object_identifier"
    if compact in MONETARY_FIELDS:
        return "monetary_value"
    if compact in STATE_FIELDS:
        return "state"
    if compact in AUTH_FIELDS:
        return "authentication"
    if compact in {"cursor", "offset", "limit", "page", "pagesize"}:
        return "pagination"
    return "unknown"


def _body_parameters(observations: list[Observation]) -> list[EndpointParameter]:
    evidence: dict[str, set[str]] = {}
    for observation in observations:
        for field in observation.request_fields:
            evidence.setdefault(field, set()).add(observation.id)

    result: list[EndpointParameter] = []
    for field in sorted(evidence):
        name = re.split(r"\.|\[\]", field)[-1]
        if not name:
            continue
        json_path = "$." + field.replace("[]", "[*]")
        semantic_type = _field_semantic_type(name)
        result.append(
            EndpointParameter(
                name=name,
                location="body",
                json_path=json_path,
                inferred_type="string",
                confidence=Confidence.HIGH if semantic_type != "unknown" else Confidence.MEDIUM,
                evidence=sorted(evidence[field]),
                knowledge_status=KnowledgeStatus.OBSERVED,
                semantic_type=semantic_type,
                client_controlled=True,
                normalization_reasons=[f"request JSON contains field {json_path}"],
            )
        )
    return result


def _response_parameters(observations: list[Observation]) -> list[EndpointParameter]:
    evidence: dict[str, set[str]] = {}
    for observation in observations:
        for field in observation.response_fields:
            evidence.setdefault(field, set()).add(observation.id)

    result: list[EndpointParameter] = []
    for field in sorted(evidence):
        name = re.split(r"\.|\[\]", field)[-1]
        if not name:
            continue
        json_path = "$." + field.replace("[]", "[*]")
        semantic_type = _field_semantic_type(name)
        result.append(
            EndpointParameter(
                name=name,
                location="response_body",
                source="response",
                json_path=json_path,
                inferred_type="string",
                confidence=Confidence.HIGH,
                evidence=sorted(evidence[field]),
                knowledge_status=KnowledgeStatus.OBSERVED,
                semantic_type=semantic_type,
                client_controlled=False,
                normalization_reasons=[f"response JSON contains field {json_path}"],
            )
        )
    return result


def _path_parameter_value(template: str, observed: str, identifier: str) -> str | None:
    template_segments = [segment for segment in template.split("/") if segment]
    observed_segments = [segment for segment in observed.split("/") if segment]
    if len(template_segments) != len(observed_segments):
        return None
    placeholder = f"{{{identifier}}}"
    result: str | None = None
    for expected, actual in zip(template_segments, observed_segments, strict=True):
        if expected == placeholder:
            result = actual
        elif expected.startswith("{") and expected.endswith("}"):
            continue
        elif expected != actual:
            return None
    return result


def _har_entry(
    workspace: WorkspacePaths,
    observation: Observation,
    cache: dict[Path, list[Any] | None],
) -> dict[str, Any] | None:
    if observation.source != "HAR":
        return None
    reference, marker, index_text = observation.source_reference.partition("#entry-")
    if not marker or not index_text.isdigit():
        return None
    source = (workspace.root / reference).resolve()
    if not source.is_relative_to(workspace.root.resolve()) or not source.is_file():
        return None
    if source not in cache:
        try:
            document = json.loads(source.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            cache[source] = None
        else:
            log = document.get("log") if isinstance(document, dict) else None
            entries = log.get("entries") if isinstance(log, dict) else None
            cache[source] = entries if isinstance(entries, list) else None
    entries = cache[source]
    index = int(index_text)
    if entries is None or index >= len(entries) or not isinstance(entries[index], dict):
        return None
    return cast(dict[str, Any], entries[index])


def _response_json(
    workspace: WorkspacePaths,
    observation: Observation,
    cache: dict[Path, list[Any] | None],
) -> Any | None:
    if (
        observation.status_code is None
        or not 200 <= observation.status_code < 300
        or "json" not in (observation.content_type or "").lower()
    ):
        return None
    entry = _har_entry(workspace, observation, cache)
    response = entry.get("response") if isinstance(entry, dict) else None
    content = response.get("content") if isinstance(response, dict) else None
    if not isinstance(content, dict) or content.get("encoding") == "base64":
        return None
    text = content.get("text")
    if not isinstance(text, str):
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None


def _scalar_paths(value: Any, prefix: str = "$") -> list[tuple[str, str]]:
    result: list[tuple[str, str]] = []
    if isinstance(value, dict):
        for key, item in value.items():
            result.extend(_scalar_paths(item, f"{prefix}.{key}"))
    elif isinstance(value, list):
        for item in value:
            result.extend(_scalar_paths(item, f"{prefix}[*]"))
    elif isinstance(value, str | int | float) and not isinstance(value, bool):
        text = str(value)
        if text and text != REDACTED:
            result.append((prefix, text))
    return result


def _terminal_name(path: str) -> str:
    return re.sub(r"[^a-z0-9]", "", path.rsplit(".", 1)[-1].lower())


def _owner_fingerprint(path: str, value: str) -> str:
    return hashlib.sha256(f"{path}\0{value}".encode()).hexdigest()


def _object_access_evidence(
    workspace: WorkspacePaths,
    path: str,
    observations: list[Observation],
    path_parameters: list[EndpointParameter],
    target: TargetDocument,
    cache: dict[Path, list[Any] | None],
) -> list[ObjectAccessEvidence]:
    controlled_actors = {
        account.id for account in target.accounts if account.ownership == "researcher"
    }
    identifiers = [
        parameter.name
        for parameter in path_parameters
        if parameter.location == "path" and parameter.semantic_type == "object_identifier"
    ]
    grouped: dict[
        tuple[str, str],
        dict[tuple[str, str, str, str], set[str]],
    ] = {}
    for observation in observations:
        if observation.actor not in controlled_actors:
            continue
        response = _response_json(workspace, observation, cache)
        if response is None:
            continue
        scalars = _scalar_paths(response)
        for identifier in identifiers:
            requested = _path_parameter_value(path, observation.path, identifier)
            if requested is None:
                continue
            identifier_name = re.sub(r"[^a-z0-9]", "", identifier.lower())
            object_matches = [
                (field_path, value)
                for field_path, value in scalars
                if value == requested and _terminal_name(field_path) in {identifier_name, "id"}
            ]
            if not object_matches:
                continue
            object_path, _ = min(
                object_matches,
                key=lambda item: (item[0].count(".") + item[0].count("[*]"), item[0]),
            )
            object_parent = object_path.rsplit(".", 1)[0]
            owner_matches = [
                (field_path, value)
                for field_path, value in scalars
                if field_path.rsplit(".", 1)[0] == object_parent
                and _terminal_name(field_path) in OWNER_ASSOCIATION_FIELDS
            ]
            for owner_path, owner_value in owner_matches:
                fingerprint = _owner_fingerprint(owner_path, owner_value)
                key = (observation.actor, requested, object_path, fingerprint)
                grouped.setdefault((identifier, owner_path), {}).setdefault(key, set()).add(
                    observation.id
                )

    evidence: list[ObjectAccessEvidence] = []
    for (identifier, owner_path), records in sorted(grouped.items()):
        baselines = [
            ActorObjectBaseline(
                actor=actor,
                requested_value=requested,
                response_object_path=object_path,
                owner_value_fingerprint=fingerprint,
                observations=sorted(observation_ids),
            )
            for (actor, requested, object_path, fingerprint), observation_ids in sorted(
                records.items()
            )
        ]
        actors = {item.actor for item in baselines}
        objects = {item.requested_value for item in baselines}
        owners = {item.owner_value_fingerprint for item in baselines}
        actor_owners = {
            actor: {item.owner_value_fingerprint for item in baselines if item.actor == actor}
            for actor in actors
        }
        object_owners = {
            object_id: {
                item.owner_value_fingerprint
                for item in baselines
                if item.requested_value == object_id
            }
            for object_id in objects
        }
        binding_observed = (
            len(actors) >= 2
            and len(objects) >= 2
            and len(owners) >= 2
            and all(len(values) == 1 for values in actor_owners.values())
            and all(len(values) == 1 for values in object_owners.values())
            and len({next(iter(values)) for values in actor_owners.values()}) == len(actors)
        )
        evidence.append(
            ObjectAccessEvidence(
                identifier=identifier,
                owner_field_path=owner_path,
                baselines=baselines,
                distinct_actors=len(actors),
                distinct_objects=len(objects),
                distinct_owner_values=len(owners),
                actor_object_binding_observed=binding_observed,
            )
        )
    return evidence


def _action(path: str, method: str) -> tuple[EndpointAction, bool, list[str]]:
    segments = [segment.lower().replace("-", "_") for segment in path.split("/") if segment]
    tokens = [token for segment in segments for token in segment.split("_")]
    read = next((token for token in reversed(tokens) if token in READ_ACTIONS), None)
    mutation = next(
        (
            token if token in MUTATION_ACTIONS else token[:-1]
            for token in reversed(tokens)
            if token in MUTATION_ACTIONS or (token.endswith("s") and token[:-1] in MUTATION_ACTIONS)
        ),
        None,
    )
    if read and (not mutation or tokens.index(read) > tokens.index(mutation)):
        return (
            EndpointAction(
                name=read,
                type="read",
                confidence=Confidence.HIGH,
                reasons=[f"path contains strong read-like action {read}"],
            ),
            False,
            [f"action verb {read} is read-like"],
        )
    if mutation:
        action_type: EndpointActionType = (
            "financial_mutation"
            if mutation in {"refund", "withdraw", "transfer", "settle"}
            else "mutation"
        )
        return (
            EndpointAction(
                name=mutation,
                type=action_type,
                confidence=Confidence.MEDIUM,
                reasons=[f"path contains mutation-like action {mutation}"],
            ),
            True,
            [f"action verb {mutation} is mutation-like"],
        )
    if method in SAFE_METHODS:
        return (
            EndpointAction(
                name="read",
                type="read",
                confidence=Confidence.HIGH,
                reasons=[f"{method} is a safe HTTP method"],
            ),
            False,
            [f"{method} is a safe HTTP method"],
        )
    if method in {"PUT", "PATCH", "DELETE"}:
        return (
            EndpointAction(
                name={"PUT": "replace", "PATCH": "update", "DELETE": "delete"}[method],
                type="mutation",
                confidence=Confidence.MEDIUM,
                reasons=[f"{method} commonly represents mutation but no state delta is observed"],
            ),
            True,
            [f"{method} commonly represents mutation"],
        )
    return (
        EndpointAction(
            name="unknown",
            type="unknown",
            confidence=Confidence.LOW,
            reasons=["POST without a business action is not sufficient evidence of mutation"],
        ),
        False,
        ["no mutating action or observed state delta"],
    )


def _aggregate_classification(
    observations: list[Observation], classifications: dict[str, EndpointClassification]
) -> EndpointClassification:
    items = [classifications[item.id] for item in observations]
    counts = {
        value: sum(item.primary == value for item in items)
        for value in EndpointPrimaryClassification
    }
    conservative_order = {
        EndpointPrimaryClassification.THIRD_PARTY: 10,
        EndpointPrimaryClassification.STATIC_ASSET: 9,
        EndpointPrimaryClassification.TELEMETRY: 8,
        EndpointPrimaryClassification.ANALYTICS: 7,
        EndpointPrimaryClassification.UNKNOWN: 6,
        EndpointPrimaryClassification.PAGE_NAVIGATION: 5,
        EndpointPrimaryClassification.FILE_DOWNLOAD: 4,
        EndpointPrimaryClassification.AUTHENTICATION: 3,
        EndpointPrimaryClassification.FINANCIAL: 2,
        EndpointPrimaryClassification.FIRST_PARTY_API: 1,
    }
    primary = max(counts, key=lambda value: (counts[value], conservative_order[value]))
    return EndpointClassification(
        primary=primary,
        tags=sorted({tag for item in items for tag in item.tags}, key=lambda item: item.value),
        confidence=max(
            (item.confidence for item in items),
            key=lambda value: {Confidence.LOW: 0, Confidence.MEDIUM: 1, Confidence.HIGH: 2}[value],
        ),
        reasons=sorted({reason for item in items for reason in item.reasons}),
    )


def _security_relevance(
    classification: EndpointClassification,
    authentication: EndpointAuthentication,
    parameters: list[EndpointParameter],
    action: EndpointAction,
    object_access: list[ObjectAccessEvidence],
) -> tuple[int, list[str]]:
    score = 2 if classification.primary == EndpointPrimaryClassification.FIRST_PARTY_API else 0
    reasons: list[str] = []
    if score:
        reasons.append("first-party API endpoint")
    if EndpointPrimaryClassification.AUTHENTICATION in classification.tags:
        score += 3
        reasons.append("authentication-sensitive path")
    if EndpointPrimaryClassification.FINANCIAL in classification.tags:
        score += 3
        reasons.append("financial or wallet-related path")
    if authentication.required:
        score += 2
        reasons.append("authenticated endpoint observed")
    request_parameters = [
        item for item in parameters if item.source == "request" and item.client_controlled
    ]
    if any(item.semantic_type == "object_identifier" for item in request_parameters):
        score += 2
        reasons.append("client-controlled object identifier observed")
    binding = next(
        (item for item in object_access if item.actor_object_binding_observed),
        None,
    )
    if binding is not None:
        score += 1
        reasons.append("two controlled actors have distinct object baselines")
        score += 1
        reasons.append("successful JSON response object IDs match requested IDs")
        score += 1
        reasons.append(f"distinct owner/account values observed at {binding.owner_field_path}")
    if any(
        item.semantic_type in {"monetary_value", "authentication"} for item in request_parameters
    ):
        score += 2
        reasons.append("security-sensitive request field observed")
    if action.type in {"mutation", "financial_mutation"}:
        score += 2
        reasons.append("mutation-like business action observed")
    penalties = {
        EndpointPrimaryClassification.STATIC_ASSET: (-10, "static asset"),
        EndpointPrimaryClassification.TELEMETRY: (-8, "telemetry endpoint"),
        EndpointPrimaryClassification.ANALYTICS: (-8, "analytics endpoint"),
        EndpointPrimaryClassification.THIRD_PARTY: (-6, "third-party host"),
    }
    if classification.primary in penalties:
        penalty, reason = penalties[classification.primary]
        score += penalty
        reasons.append(reason)
    if not authentication.required and binding is not None:
        score += 1
        reasons.append("account-scoped object responses observed without request authentication")
    elif not authentication.required:
        score -= 2
        reasons.append("no authentication requirement observed")
    if not request_parameters:
        score -= 2
        reasons.append("no client-controlled input structure observed")
    if action.type == "unknown":
        score -= 3
        reasons.append("generic POST with no state evidence")
    return max(0, min(10, score)), reasons


def build_inventory(workspace: WorkspacePaths) -> InventoryResult:
    """Rebuild endpoint inventory while preserving stable endpoint IDs."""

    target = _load_target(workspace.target)
    observation_store = _load_observations(workspace.observations)
    existing_store = _load_endpoints(workspace.endpoints)
    context = ClassificationContext(target)
    classifications = {
        item.id: classify_observation(item, context) for item in observation_store.observations
    }
    normalized_by_observation = normalize_paths(
        observation_store.observations,
        {item: classification.primary for item, classification in classifications.items()},
    )

    groups: dict[tuple[str, str], list[Observation]] = {}
    for observation in observation_store.observations:
        normalized = normalized_by_observation[observation.id]
        groups.setdefault((observation.method, normalized.path), []).append(observation)

    existing_ids = {(item.method, item.path): item.id for item in existing_store.endpoints}
    existing_numbers = [
        number
        for item in existing_store.endpoints
        if (number := _number_from_id(item.id, "EP")) is not None
    ]
    next_number = max(existing_numbers, default=0) + 1
    endpoints: list[Endpoint] = []
    har_cache: dict[Path, list[Any] | None] = {}

    for method, path in sorted(groups):
        observations = groups[(method, path)]
        representative = normalized_by_observation[observations[0].id]
        endpoint_id = existing_ids.get((method, path))
        if endpoint_id is None:
            endpoint_id = f"EP-{next_number:03d}"
            next_number += 1

        classification = _aggregate_classification(observations, classifications)
        action, state_change, state_change_reasons = _action(path, method)
        resource_name, resource_confidence = _resource_name(path, classification, action.name)
        rules = sorted(
            {
                rule
                for observation in observations
                for rule in normalized_by_observation[observation.id].rules
            }
        )
        confidence = Confidence.MEDIUM if "repeated_numeric" in rules else Confidence.HIGH
        path_parameters = _path_parameters(representative, observations)
        documented_observations = [item for item in observations if item.source == "OPENAPI"]
        documented_parameters = (
            _documented_path_parameters(path, documented_observations)
            if documented_observations
            else []
        )
        existing_path_names = {item.name for item in path_parameters}
        path_parameters.extend(
            item for item in documented_parameters if item.name not in existing_path_names
        )
        query_parameters = _query_parameters(observations)
        body_parameters = _body_parameters(observations)
        response_parameters = _response_parameters(observations)
        parameters = path_parameters + query_parameters + body_parameters + response_parameters
        authentication = _authentication(observations)
        object_access = _object_access_evidence(
            workspace,
            path,
            observations,
            path_parameters,
            target,
            har_cache,
        )
        relevance, relevance_reasons = _security_relevance(
            classification, authentication, parameters, action, object_access
        )
        if documented_parameters:
            rules = sorted({*rules, "documented_template"})
        endpoints.append(
            Endpoint(
                id=endpoint_id,
                method=method,
                path=path,
                hosts=sorted({item.host for item in observations}),
                channels=sorted({item.channel for item in observations}),
                authentication=authentication,
                classification=classification,
                resource=EndpointResource(
                    type=resource_name,
                    confidence=resource_confidence,
                ),
                action=action,
                parameters=parameters,
                object_access=object_access,
                state_change=state_change,
                state_change_reasons=state_change_reasons,
                financial_impact=(
                    "unknown"
                    if EndpointPrimaryClassification.FINANCIAL in classification.tags
                    else "none"
                ),
                security_relevance=relevance,
                relevance_reasons=relevance_reasons,
                disposition=endpoint_disposition(classification, target),
                observed_by=sorted({item.actor for item in observations}),
                sources=sorted(item.id for item in observations),
                confidence=confidence,
                normalization=NormalizationEvidence(
                    observed_paths=sorted({item.path for item in observations}),
                    rules=rules,
                ),
            )
        )

    store = EndpointStore(endpoints=endpoints)
    write_yaml(workspace.endpoints, store.model_dump(mode="json", exclude_none=True))
    return InventoryResult(len(endpoints), len(observation_store.observations))
