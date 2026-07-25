"""Build an evidence-linked endpoint inventory from factual observations."""

import re
from dataclasses import dataclass
from pathlib import Path

from pydantic import ValidationError

from finsec.config.workspace import WorkspacePaths
from finsec.errors import FinsecError
from finsec.modeling.models import (
    AuthenticationType,
    Confidence,
    Endpoint,
    EndpointAuthentication,
    EndpointParameter,
    EndpointResource,
    EndpointStore,
    KnowledgeStatus,
    NormalizationEvidence,
    Observation,
    ObservationStore,
    ParameterType,
)
from finsec.normalization.paths import NormalizedPath, normalize_paths
from finsec.utils.redaction import REDACTED
from finsec.utils.yaml_store import load_yaml, write_yaml

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


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


def _number_from_id(value: str, prefix: str) -> int | None:
    match = re.fullmatch(rf"{re.escape(prefix)}-(\d+)", value)
    return int(match.group(1)) if match else None


def _resource_name(path: str) -> tuple[str, Confidence]:
    placeholders = re.findall(r"\{([A-Za-z][A-Za-z0-9]*)Id\}", path)
    if placeholders:
        return (placeholders[-1][0].upper() + placeholders[-1][1:], Confidence.MEDIUM)

    segments = [segment for segment in path.split("/") if segment and not segment.startswith("{")]
    ignored = {"api", "v1", "v2", "v3"}
    candidates = [segment for segment in segments if segment.lower() not in ignored]
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
    successful_without_auth = any(
        not item.authentication.present and item.status_code is not None and item.status_code < 400
        for item in observations
    )
    required = bool(present_types) and not successful_without_auth
    if not present_types:
        observed_type: AuthenticationType = "none"
    elif len(present_types) == 1:
        observed_type = next(iter(present_types))
    else:
        observed_type = "mixed"
    return EndpointAuthentication(required=required, observed_type=observed_type)


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
        )
        for name in sorted(set(re.findall(r"\{([A-Za-z][A-Za-z0-9_]*)\}", path)))
    ]


def build_inventory(workspace: WorkspacePaths) -> InventoryResult:
    """Rebuild endpoint inventory while preserving stable endpoint IDs."""

    observation_store = _load_observations(workspace.observations)
    existing_store = _load_endpoints(workspace.endpoints)
    normalized_by_observation = normalize_paths(observation_store.observations)

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

    for method, path in sorted(groups):
        observations = groups[(method, path)]
        representative = normalized_by_observation[observations[0].id]
        endpoint_id = existing_ids.get((method, path))
        if endpoint_id is None:
            endpoint_id = f"EP-{next_number:03d}"
            next_number += 1

        resource_name, resource_confidence = _resource_name(path)
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
        if documented_parameters:
            rules = sorted({*rules, "documented_template"})
        endpoints.append(
            Endpoint(
                id=endpoint_id,
                method=method,
                path=path,
                hosts=sorted({item.host for item in observations}),
                channels=sorted({item.channel for item in observations}),
                authentication=_authentication(observations),
                resource=EndpointResource(
                    type=resource_name,
                    confidence=resource_confidence,
                ),
                parameters=path_parameters + query_parameters,
                state_change=method not in SAFE_METHODS,
                financial_impact="none" if method in SAFE_METHODS else "unknown",
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
