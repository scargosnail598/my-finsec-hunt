"""Build an evidence-linked endpoint inventory from factual observations."""

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

from pydantic import ValidationError

from finsec.captures.domain import (
    observation_supports_ownership_baseline,
    observation_supports_passive_baseline,
)
from finsec.captures.service import refresh_capture_analysis
from finsec.config.models import EndpointSideEffectRule, TargetDocument
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
    OwnershipInference,
    OwnershipInferenceStatus,
    ParameterSemanticType,
    ParameterType,
    SideEffectEvidence,
)
from finsec.modeling.relationships import reconstruct_controlled_ownership
from finsec.normalization.classification import (
    ClassificationContext,
    classify_observation,
    endpoint_disposition,
)
from finsec.normalization.ownership import (
    classify_ownership_scope_parameter,
    normalized_parameter_name,
)
from finsec.normalization.path_semantics import path_resource_semantics
from finsec.normalization.paths import NormalizedPath, normalize_paths
from finsec.readiness.provenance import (
    inventory_source_fingerprint,
    output_fingerprint,
    record_stage_provenance,
)
from finsec.utils.redaction import REDACTED
from finsec.utils.yaml_store import load_yaml, write_yaml

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
READ_ACTIONS = {
    "all",
    "get",
    "list",
    "recent",
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
    "validate",
}
MUTATION_ACTIONS = {
    "add",
    "accept",
    "apply",
    "capture",
    "claim",
    "close",
    "complete",
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
    "disable",
    "enable",
    "expire",
    "initiate",
    "invite",
    "pay",
    "redeem",
    "request",
    "ship",
    "suspend",
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
    "comment",
    "contact",
    "resend",
    "return",
}
NON_MUTATING_ACTIONS = {"check", "inspect", "validate", "verification", "verify"}
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
    "reportid",
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
AUTH_FIELDS = {
    "apikey",
    "challengeid",
    "code",
    "credential",
    "currentpassword",
    "newpassword",
    "nonce",
    "otp",
    "passcode",
    "password",
    "pin",
    "secret",
    "sessionid",
    "token",
    "verificationid",
}
OWNER_ASSOCIATION_FIELDS = {
    "userid",
    "ownerid",
    "accountid",
    "customerid",
    "memberid",
    "profileid",
    "merchantid",
}
OWNERSHIP_APPLICATION_CLASSIFICATIONS = {
    EndpointPrimaryClassification.FIRST_PARTY_API,
    EndpointPrimaryClassification.AUTHENTICATION,
    EndpointPrimaryClassification.FINANCIAL,
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

    semantics = path_resource_semantics(path)
    if semantics.resource != "unknown" and (
        semantics.subject_selector is not None or semantics.semantic_component is not None
    ):
        return (
            "".join(part.title() for part in semantics.resource.split("_")),
            Confidence.MEDIUM,
        )

    placeholders = re.findall(r"\{([A-Za-z][A-Za-z0-9]*)Id\}", path)
    if placeholders:
        return (placeholders[-1][0].upper() + placeholders[-1][1:], Confidence.MEDIUM)

    segments = [segment for segment in path.split("/") if segment and not segment.startswith("{")]
    ignored = {"api", "w", action_name, *READ_ACTIONS, *MUTATION_ACTIONS}
    candidates: list[str] = []
    for segment in segments:
        lowered = segment.lower().replace("-", "_")
        parts = lowered.split("_")
        if len(parts) > 1 and parts[0] in ignored:
            lowered = "_".join(parts[1:])
        if lowered in ignored or re.fullmatch(r"v\d+(?:\.\d+){0,2}", lowered):
            continue
        candidates.append(lowered)
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
        semantic_type = _field_semantic_type(name)
        result.append(
            EndpointParameter(
                name=name,
                location="query",
                inferred_type=inferred_type,
                confidence=Confidence.HIGH if semantic_type != "unknown" else Confidence.MEDIUM,
                evidence=sorted(evidence[name]),
                knowledge_status=KnowledgeStatus.INFERRED,
                semantic_type=semantic_type,
                normalization_reasons=(
                    [f"query parameter name {name} has recognized security semantics"]
                    if semantic_type != "unknown"
                    else []
                ),
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


def _scope_fingerprint(parameter: str, value: str) -> str:
    return hashlib.sha256(f"{normalized_parameter_name(parameter)}\0{value}".encode()).hexdigest()


def _has_meaningful_json(value: Any) -> bool:
    if isinstance(value, dict):
        return any(_has_meaningful_json(item) for item in value.values())
    if isinstance(value, list):
        return any(_has_meaningful_json(item) for item in value)
    if value is None or value == REDACTED:
        return False
    return not isinstance(value, str) or bool(value.strip())


def _response_scope_conflict(response: Any, identifier: str, requested: str) -> bool:
    expected = normalized_parameter_name(identifier)
    return any(
        normalized_parameter_name(_terminal_name(field_path)) == expected and value != requested
        for field_path, value in _scalar_paths(response)
    )


def _response_object_access_evidence(
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
        if (
            observation.actor not in controlled_actors
            or not observation_supports_ownership_baseline(observation)
        ):
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
                source="RESPONSE_BODY",
                confidence=Confidence.HIGH,
                owner_field_path=owner_path,
                baselines=baselines,
                distinct_actors=len(actors),
                distinct_objects=len(objects),
                distinct_owner_values=len(owners),
                actor_object_binding_observed=binding_observed,
            )
        )
    return evidence


def _path_scope_evidence(
    workspace: WorkspacePaths,
    path: str,
    observations: list[Observation],
    path_parameters: list[EndpointParameter],
    target: TargetDocument,
    classification: EndpointClassification,
    response_evidence: list[ObjectAccessEvidence],
    cache: dict[Path, list[Any] | None],
) -> tuple[list[ObjectAccessEvidence], list[OwnershipInference]]:
    controlled_accounts = {
        account.id: account for account in target.accounts if account.ownership == "researcher"
    }
    bindings: list[ObjectAccessEvidence] = []
    decisions: list[OwnershipInference] = []
    identifiers = [
        parameter.name
        for parameter in path_parameters
        if parameter.location == "path" and parameter.semantic_type == "object_identifier"
    ]
    response_by_identifier: dict[str, list[ObjectAccessEvidence]] = {}
    for item in response_evidence:
        response_by_identifier.setdefault(item.identifier, []).append(item)

    for identifier in sorted(set(identifiers)):
        scope_classification = classify_ownership_scope_parameter(
            identifier, target.analysis.ownership_inference
        )
        if scope_classification == "PUBLIC_SHARED_SCOPE":
            decisions.append(
                OwnershipInference(
                    parameter=identifier,
                    classification=scope_classification,
                    status="REJECTED",
                    reasons=[f"{identifier} is classified as a public/shared scope parameter."],
                )
            )
            continue
        if scope_classification == "UNCLASSIFIED":
            decisions.append(
                OwnershipInference(
                    parameter=identifier,
                    classification=scope_classification,
                    status="REJECTED",
                    reasons=[
                        f"{identifier} is not allowlisted as a trusted ownership scope parameter."
                    ],
                )
            )
            continue
        if classification.primary not in OWNERSHIP_APPLICATION_CLASSIFICATIONS:
            decisions.append(
                OwnershipInference(
                    parameter=identifier,
                    classification=scope_classification,
                    status="REJECTED",
                    reasons=["The endpoint is not classified as an application API request."],
                )
            )
            continue

        response_items = response_by_identifier.get(identifier, [])
        if response_items:
            status: OwnershipInferenceStatus = (
                "NOT_NEEDED"
                if any(item.actor_object_binding_observed for item in response_items)
                else "REJECTED"
            )
            reason = (
                "Response-derived ownership evidence takes precedence over the path fallback."
                if status == "NOT_NEEDED"
                else (
                    "Response-derived ownership evidence is incomplete or ambiguous; "
                    "the path fallback is disabled."
                )
            )
            decisions.append(
                OwnershipInference(
                    parameter=identifier,
                    classification=scope_classification,
                    status=status,
                    controlled_actors=max(item.distinct_actors for item in response_items),
                    distinct_scope_values=max(item.distinct_objects for item in response_items),
                    observations=sorted(
                        {
                            observation_id
                            for item in response_items
                            for baseline in item.baselines
                            for observation_id in baseline.observations
                        }
                    ),
                    reasons=[reason],
                )
            )
            continue

        candidates: dict[tuple[str, str], set[str]] = {}
        conflicting_observations: set[str] = set()
        known_actor_observations = 0
        authenticated_observations = 0
        successful_json_observations = 0
        for observation in observations:
            if not observation_supports_ownership_baseline(observation):
                continue
            account = controlled_accounts.get(observation.actor)
            if (
                account is None
                or account.actor_type == "anonymous"
                or not account.authenticated
                or observation.actor.upper() in {"UNKNOWN", "ANONYMOUS"}
            ):
                continue
            known_actor_observations += 1
            if (
                observation.method == "OPTIONS"
                or not observation.authentication.present
                or observation.authentication.observed_type == "none"
            ):
                continue
            authenticated_observations += 1
            response = _response_json(workspace, observation, cache)
            if response is None:
                continue
            requested = _path_parameter_value(path, observation.path, identifier)
            if requested is None:
                continue
            if not _has_meaningful_json(response):
                continue
            successful_json_observations += 1
            if _response_scope_conflict(response, identifier, requested):
                conflicting_observations.add(observation.id)
                continue
            candidates.setdefault((observation.actor, requested), set()).add(observation.id)

        actor_values: dict[str, set[str]] = {}
        value_actors: dict[str, set[str]] = {}
        for actor, value in candidates:
            actor_values.setdefault(actor, set()).add(value)
            value_actors.setdefault(value, set()).add(actor)
        distinct_values = set(value_actors)
        rejection_reasons: list[str] = []
        if conflicting_observations:
            rejection_reasons.append(
                "Response-derived ownership metadata conflicts with the request parent scope."
            )
        if known_actor_observations == 0:
            rejection_reasons.append("No known researcher-controlled actor baseline is available.")
        elif authenticated_observations == 0:
            rejection_reasons.append("Authenticated controlled baselines are missing.")
        elif successful_json_observations == 0:
            rejection_reasons.append(
                "No successful non-empty JSON application baseline is available."
            )
        if len(actor_values) < 2:
            rejection_reasons.append("Only one controlled actor baseline is available.")
        if any(len(values) != 1 for values in actor_values.values()):
            rejection_reasons.append(
                "A controlled actor is associated with multiple parent-scope values."
            )
        if any(len(actors) != 1 for actors in value_actors.values()):
            rejection_reasons.append(
                "A parent-scope value is shared by multiple controlled actors."
            )
        if len(distinct_values) < 2:
            rejection_reasons.append("Distinct controlled parent-scope values are required.")

        observation_ids = sorted(
            {observation_id for item in candidates.values() for observation_id in item}
            | conflicting_observations
        )
        if rejection_reasons:
            decisions.append(
                OwnershipInference(
                    parameter=identifier,
                    classification=scope_classification,
                    status="REJECTED",
                    controlled_actors=len(actor_values),
                    distinct_scope_values=len(distinct_values),
                    observations=observation_ids,
                    reasons=list(dict.fromkeys(rejection_reasons)),
                )
            )
            continue

        decisions.append(
            OwnershipInference(
                parameter=identifier,
                classification=scope_classification,
                status="REJECTED",
                controlled_actors=len(actor_values),
                distinct_scope_values=len(distinct_values),
                observations=observation_ids,
                reasons=[
                    "Distinct authenticated path values are structural scope observations only; "
                    "successful GET access does not establish actor ownership or control."
                ],
            )
        )
    return bindings, decisions


def _object_access_evidence(
    workspace: WorkspacePaths,
    path: str,
    observations: list[Observation],
    path_parameters: list[EndpointParameter],
    target: TargetDocument,
    classification: EndpointClassification,
    cache: dict[Path, list[Any] | None],
) -> tuple[list[ObjectAccessEvidence], list[OwnershipInference]]:
    response_evidence = _response_object_access_evidence(
        workspace, path, observations, path_parameters, target, cache
    )
    path_evidence, decisions = _path_scope_evidence(
        workspace,
        path,
        observations,
        path_parameters,
        target,
        classification,
        response_evidence,
        cache,
    )
    return [*response_evidence, *path_evidence], decisions


def _action(
    path: str,
    method: str,
    *,
    allow_rest_collection_mutation: bool = False,
    side_effect_evidence: list[SideEffectEvidence] | None = None,
    request_fields: list[str] | None = None,
) -> tuple[EndpointAction, bool, list[str]]:
    segments = [segment.lower().replace("-", "_") for segment in path.split("/") if segment]
    tokens = [token for segment in segments for token in segment.split("_")]
    explicit_side_effects = sorted(
        side_effect_evidence or [], key=lambda item: (item.kind, item.action, item.reason)
    )
    if method in SAFE_METHODS:
        if explicit_side_effects:
            action = explicit_side_effects[0].action.lower().replace("-", "_")
            reasons = [
                f"{item.kind.lower().replace('_', ' ')}: {item.reason}"
                for item in explicit_side_effects
            ]
            return (
                EndpointAction(
                    name=action,
                    type="mutation",
                    confidence=Confidence.HIGH,
                    reasons=reasons,
                ),
                True,
                reasons,
            )
        read = next((token for token in reversed(tokens) if token in READ_ACTIONS), None)
        action = read or "read"
        reason = f"{method} is a safe HTTP method and no explicit side-effect evidence exists"
        return (
            EndpointAction(
                name=action,
                type="read",
                confidence=Confidence.HIGH,
                reasons=[reason],
            ),
            False,
            [reason],
        )
    semantics = path_resource_semantics(path)
    credential_fields = sorted(
        {
            field
            for field in request_fields or []
            if _field_semantic_type(re.split(r"\.|\[\]", field)[-1]) == "authentication"
        }
    )
    if method == "POST" and semantics.semantic_component == "credential" and credential_fields:
        reason = (
            "POST targets a credential component and the request contains credential-shaped "
            "fields; this is an update, not resource creation"
        )
        return (
            EndpointAction(
                name="update",
                type="mutation",
                confidence=Confidence.HIGH,
                reasons=[reason],
            ),
            True,
            [reason],
        )
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
    non_mutating = next(
        (token for token in reversed(tokens) if token in NON_MUTATING_ACTIONS), None
    )
    if non_mutating:
        return (
            EndpointAction(
                name=non_mutating,
                type="authentication" if non_mutating in {"verification", "verify"} else "read",
                confidence=Confidence.MEDIUM,
                reasons=[
                    f"action verb {non_mutating} is validation-like and no explicit state "
                    "delta is observed"
                ],
            ),
            False,
            [f"action verb {non_mutating} is validation-like without state-delta evidence"],
        )
    if mutation:
        action_type: EndpointActionType = (
            "financial_mutation"
            if mutation in {"capture", "pay", "refund", "return", "settle", "transfer", "withdraw"}
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
    terminal = segments[-1] if segments else ""
    if (
        method == "POST"
        and allow_rest_collection_mutation
        and terminal.endswith("s")
        and terminal not in {"status", "search"}
    ):
        return (
            EndpointAction(
                name="create",
                type="mutation",
                confidence=Confidence.MEDIUM,
                reasons=["local-lab POST targets a plural REST collection"],
            ),
            True,
            ["local-lab POST to a plural REST collection is mutation-like"],
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
        if binding.source == "PATH_PARENT_SCOPE":
            reasons.append("two controlled actors have distinct trusted parent-scope baselines")
            score += 1
            reasons.append("authenticated successful non-empty JSON baselines were observed")
            score += 1
            reasons.append(
                f"ownership scope is inferred from allowlisted path parameter {binding.identifier}"
            )
        else:
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
    side_effect_rules: dict[tuple[str, str], EndpointSideEffectRule] = {
        (item.method, item.path): item for item in target.analysis.endpoint_side_effect_rules
    }

    for method, path in sorted(groups):
        observations = groups[(method, path)]
        representative = normalized_by_observation[observations[0].id]
        endpoint_id = existing_ids.get((method, path))
        if endpoint_id is None:
            endpoint_id = f"EP-{next_number:03d}"
            next_number += 1

        classification = _aggregate_classification(observations, classifications)
        side_effect_rule = side_effect_rules.get((method, path))
        explicit_side_effects = (
            [
                SideEffectEvidence(
                    kind="TRUSTED_CONTRACT_ANNOTATION",
                    action=side_effect_rule.action,
                    references=side_effect_rule.evidence_refs,
                    reason=side_effect_rule.rationale,
                )
            ]
            if side_effect_rule is not None
            else []
        )
        action, state_change, state_change_reasons = _action(
            path,
            method,
            allow_rest_collection_mutation=(
                (target.testing.local_lab or target.testing.synthetic)
                and "business_logic" in target.focus
            ),
            side_effect_evidence=explicit_side_effects,
            request_fields=[field for item in observations for field in item.request_fields],
        )
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
        object_access, ownership_inference = _object_access_evidence(
            workspace,
            path,
            observations,
            path_parameters,
            target,
            classification,
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
                ownership_inference=ownership_inference,
                state_change=state_change,
                state_change_reasons=state_change_reasons,
                side_effect_evidence=explicit_side_effects,
                financial_impact=(
                    "unknown"
                    if EndpointPrimaryClassification.FINANCIAL in classification.tags
                    or action.type == "financial_mutation"
                    else "none"
                ),
                security_relevance=relevance,
                relevance_reasons=relevance_reasons,
                disposition=endpoint_disposition(classification, target),
                observed_by=sorted({item.actor for item in observations}),
                baseline_observed_by=sorted(
                    {
                        item.actor
                        for item in observations
                        if observation_supports_passive_baseline(item)
                    }
                ),
                capture_modes=sorted({item.capture_mode for item in observations}),
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
    refresh_capture_analysis(workspace)
    refreshed_observations = ObservationStore.model_validate(load_yaml(workspace.observations))
    _relationships, store, _relationship_result = reconstruct_controlled_ownership(
        workspace,
        target=target,
        observations=refreshed_observations,
        endpoints=store,
    )
    document = store.model_dump(mode="json", exclude_none=True)
    write_yaml(workspace.endpoints, document)
    fingerprint = inventory_source_fingerprint(target, refreshed_observations)
    for stage in ("classify", "normalize"):
        record_stage_provenance(
            workspace,
            key=stage,
            stage=stage,
            producer="endpoint-inventory",
            input_fingerprint=fingerprint,
            output_fingerprint_value=output_fingerprint(document),
        )
    return InventoryResult(len(endpoints), len(observation_store.observations))
