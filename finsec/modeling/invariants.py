"""Deterministic extraction of traceable, not-yet-confirmed invariants."""

from dataclasses import dataclass
from typing import Any

from pydantic import ValidationError

from finsec.config.workspace import WorkspacePaths
from finsec.errors import FinsecError
from finsec.modeling.domain import InvariantRecord, InvariantStore, ResourceStore
from finsec.modeling.merge import merge_generated_records, stable_fingerprint
from finsec.modeling.models import Confidence, Endpoint, EndpointStore, KnowledgeStatus
from finsec.modeling.semantics import object_candidate
from finsec.readiness.provenance import invariant_source_fingerprint, record_stage_provenance
from finsec.utils.yaml_store import load_yaml, write_yaml

FINANCIAL_RESOURCES = {
    "balance",
    "invoice",
    "payment",
    "refund",
    "settlement",
    "transaction",
    "transfer",
    "wallet",
    "withdrawal",
}


@dataclass(frozen=True)
class InvariantResult:
    """Summary returned after invariant extraction."""

    invariants: int
    conflicts: tuple[str, ...]


def _load_inputs(workspace: WorkspacePaths) -> tuple[EndpointStore, ResourceStore]:
    try:
        endpoints = EndpointStore.model_validate(load_yaml(workspace.endpoints))
        resources = ResourceStore.model_validate(load_yaml(workspace.resources))
    except (OSError, ValidationError) as error:
        raise FinsecError(f"Cannot load invariant inputs: {error}") from error
    if not resources.resources:
        raise FinsecError("Resource model is empty; run 'hunt model' first.")
    return endpoints, resources


def _base(
    key: str,
    category: str,
    statement: str,
    endpoint: Endpoint,
    resource: str,
    status: KnowledgeStatus,
    confidence: Confidence,
    rationale: str,
) -> dict[str, Any]:
    return {
        "key": key,
        "category": category,
        "statement": statement,
        "resources": [resource],
        "endpoints": [endpoint.id],
        "evidence": [endpoint.id, *endpoint.sources],
        "confidence": confidence,
        "knowledge_status": status,
        "validation_status": "NOT_CONFIRMED",
        "rationale": rationale,
        "disposition": "ACTIVE",
    }


def _drafts(endpoints: EndpointStore, resources: ResourceStore) -> list[dict[str, Any]]:
    known_resources = {item.name for item in resources.resources if item.disposition == "ACTIVE"}
    drafts: list[dict[str, Any]] = []
    for endpoint in endpoints.endpoints:
        if endpoint.disposition != "ACTIVE":
            continue
        resource = endpoint.resource.type
        if resource not in known_resources:
            continue

        if endpoint.authentication.required:
            drafts.append(
                _base(
                    f"authentication:{endpoint.id}",
                    "authentication",
                    f"Access to {endpoint.method} {endpoint.path} should require an authenticated "
                    "context equivalent to the context observed in source traffic.",
                    endpoint,
                    resource,
                    KnowledgeStatus.INFERRED,
                    Confidence.MEDIUM,
                    "The endpoint inventory inferred an authentication requirement from observed "
                    "requests; server policy is not yet confirmed.",
                )
            )

        object_parameters = [
            parameter
            for parameter in endpoint.parameters
            if parameter.client_controlled and object_candidate(parameter.identifier_semantics)
        ]
        seen_targets: set[tuple[str, str, str | None]] = set()
        for parameter_record in object_parameters:
            target = (
                parameter_record.name,
                parameter_record.location,
                parameter_record.json_path,
            )
            if target in seen_targets:
                continue
            seen_targets.add(target)
            parameter = (
                parameter_record.json_path.removeprefix("$.").replace("[*]", "[]")
                if parameter_record.json_path
                else parameter_record.name
            )
            drafts.append(
                _base(
                    (f"object-authorization:{endpoint.id}:{parameter_record.location}:{parameter}"),
                    "authorization",
                    f"Operations on {resource} selected by {parameter} must authorize the calling "
                    "actor for that specific object.",
                    endpoint,
                    resource,
                    KnowledgeStatus.ASSUMED,
                    Confidence.LOW,
                    "The endpoint exposes a caller-controlled object identifier, but ownership, "
                    "delegation, tenant, and role rules are not yet observed.",
                )
            )

        resource_record = next(item for item in resources.resources if item.name == resource)
        if endpoint.state_change and resource_record.states:
            drafts.append(
                _base(
                    f"state-integrity:{endpoint.id}",
                    "state_integrity",
                    f"{endpoint.method} {endpoint.path} must execute only when the current "
                    f"{resource} state permits the requested transition.",
                    endpoint,
                    resource,
                    KnowledgeStatus.ASSUMED,
                    Confidence.LOW,
                    "A mutation-like action and researcher-recorded lifecycle states exist; "
                    "the exact transition guard is not yet confirmed.",
                )
            )

        if (
            endpoint.state_change
            and endpoint.action.type == "financial_mutation"
            and resource.lower() in FINANCIAL_RESOURCES
        ):
            drafts.append(
                _base(
                    f"single-execution:{endpoint.id}",
                    "single_execution",
                    f"One logical invocation of {endpoint.method} {endpoint.path} must produce at "
                    "most one successful financial effect.",
                    endpoint,
                    resource,
                    KnowledgeStatus.ASSUMED,
                    Confidence.LOW,
                    "The operation targets a financial resource, but idempotency and accounting "
                    "effects have not yet been observed.",
                )
            )
    return drafts


def generate_invariants(workspace: WorkspacePaths) -> InvariantResult:
    """Generate only evidence-linked invariants and mark unsupported policy assumptions."""

    endpoints, resources = _load_inputs(workspace)
    fingerprint = invariant_source_fingerprint(endpoints, resources)
    drafts = _drafts(endpoints, resources)
    merge = merge_generated_records(
        workspace.invariants,
        "invariants",
        "INV",
        "phase2-invariant-extractor",
        fingerprint,
        drafts,
    )
    draft_keys = {str(item["key"]) for item in drafts}
    records = merge.document.get("invariants", [])
    if isinstance(records, list):
        for record in records:
            if not isinstance(record, dict) or record.get("key") in draft_keys:
                continue
            generation = record.get("generation")
            if not isinstance(generation, dict):
                continue
            if generation.get("generator") != "phase2-invariant-extractor":
                continue
            payload = {key: value for key, value in record.items() if key != "generation"}
            if generation.get("generated_checksum") != stable_fingerprint(payload):
                continue
            record["disposition"] = "SUPPRESSED_INSUFFICIENT_EVIDENCE"
            normalized = InvariantRecord.model_validate(record).model_dump(
                mode="json", exclude_none=True
            )
            normalized_generation = normalized["generation"]
            normalized_payload = {
                key: value for key, value in normalized.items() if key != "generation"
            }
            normalized_generation["generated_checksum"] = stable_fingerprint(normalized_payload)
            record.clear()
            record.update(normalized)
    try:
        store = InvariantStore.model_validate(merge.document)
    except ValidationError as error:
        raise FinsecError(
            f"Cannot validate invariant model {workspace.invariants}: {error}"
        ) from error
    write_yaml(workspace.invariants, store.model_dump(mode="json", exclude_none=True))
    record_stage_provenance(
        workspace,
        key="invariants",
        stage="invariants",
        producer="phase2-invariant-extractor",
        input_fingerprint=fingerprint,
    )
    return InvariantResult(
        sum(item.disposition == "ACTIVE" for item in store.invariants), merge.conflicts
    )
