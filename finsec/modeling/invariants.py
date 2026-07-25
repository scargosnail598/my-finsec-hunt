"""Deterministic extraction of traceable, not-yet-confirmed invariants."""

from dataclasses import dataclass
from typing import Any

from pydantic import ValidationError

from finsec.config.workspace import WorkspacePaths
from finsec.errors import FinsecError
from finsec.modeling.domain import InvariantStore, ResourceStore
from finsec.modeling.merge import merge_generated_records, stable_fingerprint
from finsec.modeling.models import Confidence, Endpoint, EndpointStore, KnowledgeStatus
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
    }


def _drafts(endpoints: EndpointStore, resources: ResourceStore) -> list[dict[str, Any]]:
    known_resources = {item.name for item in resources.resources}
    drafts: list[dict[str, Any]] = []
    for endpoint in endpoints.endpoints:
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

        path_parameters = [
            parameter.name for parameter in endpoint.parameters if parameter.location == "path"
        ]
        for parameter in path_parameters:
            drafts.append(
                _base(
                    f"object-authorization:{endpoint.id}:{parameter}",
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

        if endpoint.state_change:
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
                    "The HTTP method implies a possible state change, but lifecycle states "
                    "and guards are not confirmed from Phase 1 evidence.",
                )
            )

        if endpoint.state_change and resource.lower() in FINANCIAL_RESOURCES:
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
    fingerprint = stable_fingerprint(
        {
            "endpoints": endpoints.model_dump(mode="json", exclude_none=True),
            "resources": resources.model_dump(mode="json", exclude_none=True),
        }
    )
    merge = merge_generated_records(
        workspace.invariants,
        "invariants",
        "INV",
        "phase2-invariant-extractor",
        fingerprint,
        _drafts(endpoints, resources),
    )
    try:
        store = InvariantStore.model_validate(merge.document)
    except ValidationError as error:
        raise FinsecError(
            f"Cannot validate invariant model {workspace.invariants}: {error}"
        ) from error
    write_yaml(workspace.invariants, store.model_dump(mode="json", exclude_none=True))
    return InvariantResult(len(store.invariants), merge.conflicts)
