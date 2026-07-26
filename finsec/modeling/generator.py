"""Deterministic Phase 2 actor, resource, authorization, and workflow modeling."""

from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from finsec.config.models import TargetDocument
from finsec.config.workspace import WorkspacePaths
from finsec.errors import FinsecError
from finsec.modeling.domain import (
    ActorStore,
    KnowledgeClaim,
    ResourceOperation,
    ResourceRecord,
    ResourceStore,
)
from finsec.modeling.merge import (
    MergeResult,
    merge_generated_records,
    stable_fingerprint,
    write_managed_markdown,
)
from finsec.modeling.models import (
    Confidence,
    Endpoint,
    EndpointStore,
    KnowledgeStatus,
    Observation,
    ObservationStore,
)
from finsec.utils.yaml_store import load_yaml, write_yaml

NON_RESOURCE_COMPONENTS = {"Authenticate", "Health", "Login", "Logout", "Status"}
ACTION_SEGMENTS = {
    "approve",
    "cancel",
    "confirm",
    "download",
    "duplicate",
    "export",
    "refund",
    "resend",
    "retry",
    "reverse",
    "share",
    "verify",
}
SENSITIVE_FIELD_HINTS = {
    "account",
    "amount",
    "balance",
    "bank",
    "beneficiary",
    "card",
    "currency",
    "destination",
    "fee",
    "kyc",
    "otp",
    "rate",
    "status",
}


@dataclass(frozen=True)
class ModelResult:
    """Summary returned after deterministic modeling."""

    actors: int
    resources: int
    workflows: int
    conflicts: tuple[str, ...]


def _load_inputs(
    workspace: WorkspacePaths,
) -> tuple[TargetDocument, ObservationStore, EndpointStore]:
    try:
        target = TargetDocument.model_validate(load_yaml(workspace.target))
        observations = ObservationStore.model_validate(load_yaml(workspace.observations))
        endpoints = EndpointStore.model_validate(load_yaml(workspace.endpoints))
    except (OSError, ValidationError) as error:
        raise FinsecError(f"Cannot load Phase 2 inputs: {error}") from error
    if not endpoints.endpoints:
        raise FinsecError("Endpoint inventory is empty; run 'hunt inventory' first.")
    return target, observations, endpoints


def _claim(
    value: str | None,
    status: KnowledgeStatus,
    confidence: Confidence,
    evidence: list[str],
) -> dict[str, Any]:
    return KnowledgeClaim(
        value=value,
        knowledge_status=status,
        confidence=confidence,
        evidence=evidence,
    ).model_dump(mode="json", exclude_none=True)


def _actor_drafts(target: TargetDocument, observations: list[Observation]) -> list[dict[str, Any]]:
    configured = {account.id: account for account in target.accounts}
    observed: dict[str, list[Observation]] = defaultdict(list)
    for observation in observations:
        if observation.actor != "UNKNOWN":
            observed[observation.actor].append(observation)

    drafts: list[dict[str, Any]] = []
    for name in sorted(set(configured) | set(observed)):
        account = configured.get(name)
        items = observed.get(name, [])
        evidence = sorted(item.id for item in items)
        if account is not None:
            ownership = _claim(
                account.ownership,
                KnowledgeStatus.OBSERVED,
                Confidence.HIGH,
                [f"target.yaml#accounts:{name}"],
            )
            evidence.append(f"target.yaml#accounts:{name}")
            confidence = Confidence.HIGH
        else:
            ownership = _claim(
                "unknown",
                KnowledgeStatus.ASSUMED,
                Confidence.LOW,
                [],
            )
            confidence = Confidence.MEDIUM

        authentication_types = sorted(
            {
                item.authentication.observed_type
                for item in items
                if item.authentication.observed_type != "none"
            }
        )
        drafts.append(
            {
                "key": f"actor:{name}",
                "name": name,
                "category": "account_label",
                "ownership": ownership,
                "role": _claim(None, KnowledgeStatus.ASSUMED, Confidence.LOW, []),
                "authentication_types": authentication_types,
                "evidence": sorted(evidence),
                "confidence": confidence,
                "knowledge_status": KnowledgeStatus.OBSERVED,
            }
        )
    return drafts


def _operation_action(endpoint: Endpoint) -> str:
    if endpoint.action.name != "unknown":
        return endpoint.action.name
    segments = [segment for segment in endpoint.path.rstrip("/").split("/") if segment]
    last = segments[-1].lower() if segments else ""
    if not last.startswith("{") and last in ACTION_SEGMENTS:
        return last
    return {
        "DELETE": "delete",
        "GET": "read",
        "HEAD": "read_metadata",
        "OPTIONS": "inspect_options",
        "PATCH": "update",
        "POST": "create_or_execute",
        "PUT": "replace",
    }.get(endpoint.method, endpoint.method.lower())


def _sensitive_fields(endpoint: Endpoint, observations: dict[str, Observation]) -> set[str]:
    fields: set[str] = set()
    for source in endpoint.sources:
        observation = observations.get(source)
        if observation is None:
            continue
        for field in observation.request_fields + observation.response_fields:
            lowered = field.lower()
            if any(hint in lowered for hint in SENSITIVE_FIELD_HINTS):
                fields.add(field)
    return fields


def _resource_drafts(
    endpoints: list[Endpoint], observations: list[Observation]
) -> list[dict[str, Any]]:
    grouped: dict[str, list[Endpoint]] = defaultdict(list)
    for endpoint in endpoints:
        is_resource = (
            endpoint.disposition == "ACTIVE"
            and endpoint.classification.primary.value
            not in {"STATIC_ASSET", "TELEMETRY", "ANALYTICS", "THIRD_PARTY"}
            and endpoint.resource.type not in NON_RESOURCE_COMPONENTS
            and endpoint.resource.type != "Unknown"
        )
        if is_resource:
            grouped[endpoint.resource.type].append(endpoint)
    observation_by_id = {item.id: item for item in observations}
    rank = {Confidence.LOW: 0, Confidence.MEDIUM: 1, Confidence.HIGH: 2}

    drafts: list[dict[str, Any]] = []
    for name, items in sorted(grouped.items()):
        identifiers = sorted(
            {
                parameter.name
                for endpoint in items
                for parameter in endpoint.parameters
                if parameter.semantic_type == "object_identifier"
                and parameter.source == "request"
                and parameter.client_controlled
            }
        )
        operations = [
            ResourceOperation(
                endpoint=endpoint.id,
                action=_operation_action(endpoint),
                method=endpoint.method,
                path=endpoint.path,
                state_change=endpoint.state_change,
                authentication_required=endpoint.authentication.required,
                evidence=endpoint.sources,
            ).model_dump(mode="json")
            for endpoint in sorted(items, key=lambda item: (item.path, item.method))
        ]
        confidence = max(
            (endpoint.resource.confidence for endpoint in items),
            key=lambda value: rank[value],
        )
        evidence = sorted(
            {source for endpoint in items for source in [endpoint.id, *endpoint.sources]}
        )
        fields = sorted(
            {
                field
                for endpoint in items
                for field in _sensitive_fields(endpoint, observation_by_id)
            }
        )
        drafts.append(
            {
                "key": f"resource:{name.lower()}",
                "name": name,
                "identifiers": identifiers,
                "owner": _claim("unknown", KnowledgeStatus.ASSUMED, Confidence.LOW, []),
                "operations": operations,
                "states": [],
                "sensitive_fields": fields,
                "evidence": evidence,
                "confidence": confidence,
                "knowledge_status": KnowledgeStatus.INFERRED,
                "disposition": "ACTIVE",
            }
        )
    return drafts


def _escape(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ")


def _render_architecture(
    target: TargetDocument,
    observations: ObservationStore,
    endpoints: EndpointStore,
    resources: ResourceStore,
) -> str:
    observed_hosts = sorted({item.host for item in observations.observations})
    scoped_hosts = sorted(target.scope.hosts)
    hosts = sorted(set(observed_hosts) | set(scoped_hosts))
    lines = [
        "## Evidence Basis",
        "",
        "- HAR-derived hosts and account labels are `OBSERVED`.",
        "- Endpoint aggregation and resource names are `INFERRED`.",
        "- Backend services, ownership, roles, and financial flows remain `NOT CONFIRMED`.",
        "",
        "## Hosts",
        "",
        "| Host | Evidence status |",
        "|---|---|",
    ]
    for host in hosts:
        basis: list[str] = []
        if host in observed_hosts:
            basis.append("OBSERVED in HAR")
        if host in scoped_hosts:
            basis.append("OBSERVED in target configuration")
        lines.append(f"| `{_escape(host)}` | {', '.join(basis)} |")
    if not hosts:
        lines.append("| Not recorded | ASSUMED / incomplete scope |")

    lines.extend(
        [
            "",
            "## Components",
            "",
            "| Resource | Endpoints | Identifiers | Status |",
            "|---|---:|---|---|",
        ]
    )
    for resource in resources.resources:
        if resource.disposition != "ACTIVE":
            continue
        lines.append(
            f"| {_escape(resource.name)} | {len(resource.operations)} | "
            f"{', '.join(resource.identifiers) or 'None observed'} | {resource.knowledge_status} |"
        )
    if not any(item.disposition == "ACTIVE" for item in resources.resources):
        lines.append("| No resource objects inferred | 0 | - | NOT CONFIRMED |")

    authenticated = sum(1 for item in endpoints.endpoints if item.authentication.required)
    lines.extend(
        [
            "",
            "## Trust Boundaries",
            "",
            f"- Client to API host: {len(observed_hosts)} host(s) directly observed.",
            "- Authentication context to endpoint: "
            f"{authenticated} endpoint(s) inferred to require it.",
            "- Actor-to-object ownership and tenant boundaries: `NOT CONFIRMED`.",
            "- Backend-to-bank, payment, KYC, queue, webhook, or settlement boundaries: "
            "`NOT CONFIRMED`.",
        ]
    )
    return "\n".join(lines)


def _render_authorization(endpoints: EndpointStore) -> str:
    lines = [
        "## Endpoint Authorization View",
        "",
        "Authentication presence does not prove object or function authorization.",
        "",
        "| Endpoint | Operation | Resource | Authentication | Observed actors | "
        "Ownership/role condition |",
        "|---|---|---|---|---|---|",
    ]
    for endpoint in endpoints.endpoints:
        if endpoint.disposition != "ACTIVE":
            continue
        auth = (
            f"Required (`{endpoint.authentication.observed_type}`, INFERRED)"
            if endpoint.authentication.required
            else "Not established (INFERRED)"
        )
        actors = ", ".join(endpoint.observed_by) or "UNKNOWN"
        lines.append(
            f"| {endpoint.id} | `{endpoint.method} {_escape(endpoint.path)}` | "
            f"{_escape(endpoint.resource.type)} | {auth} | {_escape(actors)} | NOT CONFIRMED |"
        )
    return "\n".join(lines)


def _render_workflows(resources: ResourceStore) -> str:
    lines = [
        "Operation maps are endpoint-derived. Lifecycle states and transition ordering are "
        "not inferred without direct evidence.",
    ]
    for resource in resources.resources:
        if resource.disposition != "ACTIVE":
            continue
        lines.extend(
            [
                "",
                f"## Workflow: {resource.name}",
                "",
                f"- Evidence status: `{resource.knowledge_status}`",
                f"- Identifiers: {', '.join(resource.identifiers) or 'None observed'}",
                f"- Owner / tenant: {resource.owner.value or 'unknown'} "
                f"(`{resource.owner.knowledge_status}`)",
                "- Operations:",
            ]
        )
        for operation in resource.operations:
            lines.append(
                f"  - `{operation.action}` via `{operation.method} {operation.path}` "
                f"({operation.endpoint}, {operation.knowledge_status})"
            )
        lines.extend(
            [
                f"- Observed states: {', '.join(resource.states) or 'None'}",
                "- Transition order: `NOT CONFIRMED`",
            ]
        )
    if not any(item.disposition == "ACTIVE" for item in resources.resources):
        lines.extend(["", "No workflows can be derived from the current inventory."])
    return "\n".join(lines)


def _render_state_machines(resources: ResourceStore) -> str:
    lines = [
        "Concrete states require observed values or researcher input; field names alone are "
        "insufficient.",
    ]
    for resource in resources.resources:
        if resource.disposition != "ACTIVE":
            continue
        lines.extend(
            [
                "",
                f"## Resource: {resource.name}",
                "",
                f"- Observed states: {', '.join(resource.states) or 'None'}",
                "- Allowed transitions: `NOT CONFIRMED`",
                "- Forbidden transitions: generated only as `ASSUMED` hypotheses; "
                "test plans remain blocked until lifecycle states are confirmed",
            ]
        )
    return "\n".join(lines)


def _write_model_markdown(
    workspace: WorkspacePaths,
    target: TargetDocument,
    observations: ObservationStore,
    endpoints: EndpointStore,
    resources: ResourceStore,
) -> None:
    files: list[tuple[Path, str, str, str]] = [
        (
            workspace.root / "model/architecture.md",
            "Architecture",
            "architecture",
            _render_architecture(target, observations, endpoints, resources),
        ),
        (
            workspace.root / "model/authorization.md",
            "Authorization Model",
            "authorization",
            _render_authorization(endpoints),
        ),
        (
            workspace.root / "model/workflows.md",
            "Workflows",
            "workflows",
            _render_workflows(resources),
        ),
        (
            workspace.root / "model/state-machines.md",
            "State Machines",
            "state-machines",
            _render_state_machines(resources),
        ),
    ]
    for path, title, section, content in files:
        write_managed_markdown(path, title, section, content)


def _validate_and_write_actor_store(path: Path, merge: MergeResult) -> ActorStore:
    try:
        store = ActorStore.model_validate(merge.document)
    except ValidationError as error:
        raise FinsecError(f"Cannot validate actor model {path}: {error}") from error
    write_yaml(path, store.model_dump(mode="json", exclude_none=True))
    return store


def _validate_and_write_resource_store(path: Path, merge: MergeResult) -> ResourceStore:
    try:
        store = ResourceStore.model_validate(merge.document)
    except ValidationError as error:
        raise FinsecError(f"Cannot validate resource model {path}: {error}") from error
    write_yaml(path, store.model_dump(mode="json", exclude_none=True))
    return store


def generate_model(workspace: WorkspacePaths) -> ModelResult:
    """Generate Phase 2 models without overwriting researcher-edited YAML records."""

    target, observations, endpoints = _load_inputs(workspace)
    fingerprint = stable_fingerprint(
        {
            "target": target.model_dump(mode="json"),
            "observations": observations.model_dump(mode="json", exclude_none=True),
            "endpoints": endpoints.model_dump(mode="json", exclude_none=True),
        }
    )
    actor_merge = merge_generated_records(
        workspace.actors,
        "actors",
        "ACT",
        "phase2-modeler",
        fingerprint,
        _actor_drafts(target, observations.observations),
    )
    resource_drafts = _resource_drafts(endpoints.endpoints, observations.observations)
    resource_merge = merge_generated_records(
        workspace.resources,
        "resources",
        "RES",
        "phase2-modeler",
        fingerprint,
        resource_drafts,
    )
    resource_keys = {str(item["key"]) for item in resource_drafts}
    resource_records = resource_merge.document.get("resources", [])
    if isinstance(resource_records, list):
        for record in resource_records:
            if not isinstance(record, dict) or record.get("key") in resource_keys:
                continue
            generation = record.get("generation")
            if not isinstance(generation, dict):
                continue
            if generation.get("generator") != "phase2-modeler":
                continue
            payload = {key: value for key, value in record.items() if key != "generation"}
            if generation.get("generated_checksum") != stable_fingerprint(payload):
                continue
            record["disposition"] = "SUPPRESSED_INSUFFICIENT_EVIDENCE"
            normalized = ResourceRecord.model_validate(record).model_dump(
                mode="json", exclude_none=True
            )
            normalized_generation = normalized["generation"]
            normalized_payload = {
                key: value for key, value in normalized.items() if key != "generation"
            }
            normalized_generation["generated_checksum"] = stable_fingerprint(normalized_payload)
            record.clear()
            record.update(normalized)
    actors = _validate_and_write_actor_store(workspace.actors, actor_merge)
    resources = _validate_and_write_resource_store(workspace.resources, resource_merge)
    _write_model_markdown(workspace, target, observations, endpoints, resources)
    conflicts = tuple(
        sorted(
            [f"actors:{key}" for key in actor_merge.conflicts]
            + [f"resources:{key}" for key in resource_merge.conflicts]
        )
    )
    return ModelResult(
        actors=len(actors.actors),
        resources=sum(item.disposition == "ACTIVE" for item in resources.resources),
        workflows=sum(item.disposition == "ACTIVE" for item in resources.resources),
        conflicts=conflicts,
    )
