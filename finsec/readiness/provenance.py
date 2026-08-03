"""Semantic fingerprints and non-secret stage provenance persistence."""

from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from finsec.config.models import TargetDocument
from finsec.config.workspace import WorkspacePaths
from finsec.evidence.domain import EvidenceMetadata
from finsec.hypotheses.domain import HypothesisRecord
from finsec.modeling.domain import InvariantStore, ResourceStore
from finsec.modeling.merge import stable_fingerprint
from finsec.modeling.models import EndpointStore, ObservationStore
from finsec.testing.domain import TestPlanRecord
from finsec.utils.yaml_store import load_yaml, write_yaml
from finsec.validation.domain import ValidationRecord


class ProvenanceModel(BaseModel):
    """Strict internal provenance model."""

    model_config = ConfigDict(extra="forbid")


class StageProvenance(ProvenanceModel):
    """One producer result bound to semantic inputs."""

    key: str
    stage: str
    producer: str
    input_fingerprint: str
    output_fingerprint: str | None = None


class ProvenanceStore(ProvenanceModel):
    """Backward-compatible sidecar for stage-level provenance."""

    version: int = 1
    entries: list[StageProvenance] = Field(default_factory=list)


def inventory_source_fingerprint(target: TargetDocument, observations: ObservationStore) -> str:
    """Fingerprint only configuration that affects inventory derivation."""

    accounts = [
        {
            "id": item.id,
            "ownership": item.ownership,
            "authenticated": item.authenticated,
            "actor_type": item.actor_type,
        }
        for item in target.accounts
    ]
    return stable_fingerprint(
        {
            "scope": target.scope.model_dump(mode="json"),
            "accounts": accounts,
            "analysis": target.analysis.model_dump(mode="json"),
            "focus": target.focus,
            "local_lab": target.testing.local_lab,
            "synthetic": target.testing.synthetic,
            "observations": observations.model_dump(mode="json", exclude_none=True),
        }
    )


def model_source_fingerprint(
    target: TargetDocument,
    observations: ObservationStore,
    endpoints: EndpointStore,
) -> str:
    """Fingerprint offline model inputs without credential lifecycle metadata."""

    accounts = [
        {
            "id": item.id,
            "ownership": item.ownership,
            "role": item.role,
            "authenticated": item.authenticated,
            "actor_type": item.actor_type,
            "attributes": item.attributes.model_dump(mode="json"),
        }
        for item in target.accounts
    ]
    return stable_fingerprint(
        {
            "scope": target.scope.model_dump(mode="json"),
            "accounts": accounts,
            "observations": observations.model_dump(mode="json", exclude_none=True),
            "endpoints": endpoints.model_dump(mode="json", exclude_none=True),
        }
    )


def invariant_source_fingerprint(endpoints: EndpointStore, resources: ResourceStore) -> str:
    """Fingerprint invariant inputs."""

    return stable_fingerprint(
        {
            "endpoints": endpoints.model_dump(mode="json", exclude_none=True),
            "resources": resources.model_dump(mode="json", exclude_none=True),
        }
    )


def hypothesis_source_fingerprint(
    target: TargetDocument,
    observations: ObservationStore,
    endpoints: EndpointStore,
    resources: ResourceStore,
    invariants: InvariantStore,
) -> str:
    """Fingerprint inputs used by deterministic hypothesis generation."""

    accounts = [
        {"id": item.id, "ownership": item.ownership, "role": item.role} for item in target.accounts
    ]
    target_payload = {
        "focus": target.focus,
        "accounts": accounts,
        "hypothesis_gates": target.analysis.hypothesis_gates.model_dump(mode="json"),
        "function_authorization_rules": [
            item.model_dump(mode="json") for item in target.analysis.function_authorization_rules
        ],
        "jwt_algorithm_rules": [
            item.model_dump(mode="json") for item in target.analysis.jwt_algorithm_rules
        ],
        "production": target.testing.production,
    }
    return stable_fingerprint(
        {
            "target": target_payload,
            "observations": observations.model_dump(mode="json", exclude_none=True),
            "endpoints": endpoints.model_dump(mode="json", exclude_none=True),
            "resources": resources.model_dump(mode="json", exclude_none=True),
            "invariants": invariants.model_dump(mode="json", exclude_none=True),
        }
    )


def validation_source_fingerprint(
    target: TargetDocument,
    endpoints: EndpointStore,
    hypothesis: HypothesisRecord,
    plan: TestPlanRecord | None,
    evidence: EvidenceMetadata,
) -> str:
    """Fingerprint validation facts while excluding hypothesis lifecycle annotations."""

    hypothesis_payload = hypothesis.model_dump(mode="json", exclude_none=True)
    for field in ("status", "notes", "generation"):
        hypothesis_payload.pop(field, None)
    return stable_fingerprint(
        {
            "scope": target.scope.model_dump(mode="json"),
            "endpoints": endpoints.model_dump(mode="json", exclude_none=True),
            "hypothesis": hypothesis_payload,
            "plan": plan.model_dump(mode="json", exclude_none=True) if plan else None,
            "evidence": evidence.model_dump(mode="json", exclude_none=True),
        }
    )


def report_source_fingerprint(
    hypothesis: HypothesisRecord,
    evidence: EvidenceMetadata,
    invariants: InvariantStore,
    validation: ValidationRecord,
) -> str:
    """Fingerprint the complete, current report input contract."""

    hypothesis_payload = hypothesis.model_dump(mode="json", exclude_none=True)
    for field in ("status", "notes", "generation"):
        hypothesis_payload.pop(field, None)
    validation_payload = validation.model_dump(mode="json", exclude_none=True)
    validation_payload.pop("generation", None)
    return stable_fingerprint(
        {
            "hypothesis": hypothesis_payload,
            "evidence": evidence.model_dump(mode="json", exclude_none=True),
            "invariants": invariants.model_dump(mode="json", exclude_none=True),
            "validation": validation_payload,
        }
    )


def output_fingerprint(value: Any) -> str:
    """Fingerprint a serialized derived artifact."""

    return stable_fingerprint(value)


def load_provenance(workspace: WorkspacePaths) -> ProvenanceStore | None:
    """Load provenance without treating legacy absence as an error."""

    if not workspace.readiness_provenance.is_file():
        return None
    return ProvenanceStore.model_validate(load_yaml(workspace.readiness_provenance))


def record_stage_provenance(
    workspace: WorkspacePaths,
    *,
    key: str,
    stage: str,
    producer: str,
    input_fingerprint: str,
    output_fingerprint_value: str | None = None,
) -> None:
    """Atomically update one stage result after its producer succeeds."""

    try:
        store = load_provenance(workspace) or ProvenanceStore()
    except (OSError, TypeError, ValueError, ValidationError):
        store = ProvenanceStore()
    entry = StageProvenance(
        key=key,
        stage=stage,
        producer=producer,
        input_fingerprint=input_fingerprint,
        output_fingerprint=output_fingerprint_value,
    )
    entries = {item.key: item for item in store.entries}
    entries[key] = entry
    store.entries = [entries[item] for item in sorted(entries)]
    write_yaml(workspace.readiness_provenance, store.model_dump(mode="json", exclude_none=True))
