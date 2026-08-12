"""Sanitized read models for the local FinSec Hunt web interface."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from finsec.auth.service import AuthenticationPreflight, actor_preflight
from finsec.auth.store import SecretStore
from finsec.config.models import TargetDocument
from finsec.config.workspace import WorkspacePaths
from finsec.errors import FinsecError, WorkspaceError
from finsec.evidence.domain import EvidenceMetadata
from finsec.hypotheses.clustering import presentation_title, presentation_visible
from finsec.hypotheses.domain import HypothesisRecord, HypothesisStore
from finsec.modeling.domain import ActorStore, InvariantStore, ResourceStore
from finsec.modeling.models import Endpoint, EndpointStore, ObservationStore
from finsec.readiness.domain import LifecycleStatus, ReadinessReport
from finsec.readiness.resolver import resolve_workspace_readiness
from finsec.testing.domain import TestPlanRecord, TestPlanStore
from finsec.utils.yaml_store import load_yaml
from finsec.validation.domain import ValidationRecord, ValidationStore

DOCUMENTS = {
    "program": ("Program rules", Path("scope/program.md")),
    "scope": ("Authorized scope", Path("scope/scope.md")),
    "restrictions": ("Testing restrictions", Path("scope/restrictions.md")),
    "architecture": ("Architecture", Path("model/architecture.md")),
    "authorization": ("Authorization model", Path("model/authorization.md")),
    "workflows": ("Workflows", Path("model/workflows.md")),
    "state-machines": ("State machines", Path("model/state-machines.md")),
}


@dataclass(frozen=True)
class WorkspaceSnapshot:
    """Validated workspace stores used to build consistent API responses."""

    paths: WorkspacePaths
    target: TargetDocument
    observations: ObservationStore
    endpoints: EndpointStore
    actors: ActorStore
    resources: ResourceStore
    invariants: InvariantStore
    hypotheses: HypothesisStore
    plans: TestPlanStore
    validations: ValidationStore


class SnapshotCache:
    """Reuse validated stores until one of the source files changes."""

    def __init__(self) -> None:
        self._entries: dict[Path, tuple[tuple[tuple[str, int, int], ...], WorkspaceSnapshot]] = {}

    def get(self, paths: WorkspacePaths) -> WorkspaceSnapshot:
        """Return a current snapshot without reparsing large observation stores per route."""

        signature = _snapshot_signature(paths)
        cached = self._entries.get(paths.root)
        if cached is not None and cached[0] == signature:
            return cached[1]
        snapshot = load_snapshot(paths)
        self._entries[paths.root] = (signature, snapshot)
        return snapshot

    def invalidate(self, paths: WorkspacePaths) -> None:
        """Discard one removed or externally changed workspace snapshot."""

        self._entries.pop(paths.root, None)


class WorkspaceCatalog:
    """Resolve only direct, validated workspaces selected for the local server."""

    def __init__(self, workspace_root: Path, selected_workspace: Path | None = None) -> None:
        self.workspace_root = workspace_root.expanduser().resolve()
        self.selected_workspace = (
            selected_workspace.expanduser().resolve() if selected_workspace is not None else None
        )
        self._registered: dict[str, Path] = {}

    def register(self, root: Path) -> None:
        """Add a workspace created during this server session to the exact catalog."""

        resolved = root.expanduser().resolve()
        if not (resolved / "target.yaml").is_file():
            raise WorkspaceError(f"Not a FinSec Hunt workspace: {resolved}")
        self._registered[resolved.name] = resolved

    def unregister(self, key: str) -> None:
        """Remove a deleted workspace from this server session's catalog."""

        if self.selected_workspace is not None and self.selected_workspace.name == key:
            self.selected_workspace = None
        self._registered.pop(key, None)

    def list_workspaces(self) -> list[dict[str, Any]]:
        """Return target identities without exposing credential configuration."""

        workspaces: list[dict[str, Any]] = []
        for key, root in self._workspace_roots().items():
            try:
                target = TargetDocument.model_validate(load_yaml(root / "target.yaml"))
            except (OSError, ValidationError, TypeError) as error:
                workspaces.append(
                    {
                        "key": key,
                        "name": key,
                        "valid": False,
                        "error": str(error),
                    }
                )
                continue
            workspaces.append(
                {
                    "key": key,
                    "name": target.target.name,
                    "target_slug": target.target.slug,
                    "target_type": target.target.type,
                    "hosts": len(target.scope.hosts),
                    "accounts": len(target.accounts),
                    "valid": True,
                    "updated_at": _timestamp(root / "target.yaml"),
                }
            )
        return workspaces

    def resolve(self, key: str) -> WorkspacePaths:
        """Resolve an exact catalog key and reject URL-based path traversal."""

        if not key or key in {".", ".."} or "/" in key or "\\" in key:
            raise WorkspaceError("Invalid workspace key.")
        root = self._workspace_roots().get(key)
        if root is None:
            raise WorkspaceError(f"Workspace not found: {key}")
        return WorkspacePaths(root)

    def _workspace_roots(self) -> dict[str, Path]:
        if self.selected_workspace is not None:
            root = self.selected_workspace
            if not (root / "target.yaml").is_file():
                raise WorkspaceError(f"Not a FinSec Hunt workspace: {root}")
            return {root.name: root, **self._registered}

        if not self.workspace_root.is_dir():
            return {}
        roots: dict[str, Path] = {}
        for target_path in sorted(self.workspace_root.glob("*/target.yaml")):
            candidate = target_path.parent.resolve()
            if candidate.parent != self.workspace_root:
                continue
            roots[candidate.name] = candidate
        roots.update(self._registered)
        return roots


def load_snapshot(paths: WorkspacePaths) -> WorkspaceSnapshot:
    """Load typed workspace records, using empty stores for optional later stages."""

    try:
        return WorkspaceSnapshot(
            paths=paths,
            target=TargetDocument.model_validate(load_yaml(paths.target)),
            observations=ObservationStore.model_validate(load_yaml(paths.observations)),
            endpoints=EndpointStore.model_validate(load_yaml(paths.endpoints)),
            actors=_optional_store(paths.actors, ActorStore()),
            resources=_optional_store(paths.resources, ResourceStore()),
            invariants=_optional_store(paths.invariants, InvariantStore()),
            hypotheses=_optional_store(paths.hypotheses, HypothesisStore()),
            plans=_optional_store(paths.test_plans, TestPlanStore()),
            validations=_optional_store(paths.validations, ValidationStore()),
        )
    except (OSError, ValidationError, TypeError) as error:
        raise WorkspaceError(f"Cannot load workspace {paths.root}: {error}") from error


def workspace_overview(snapshot: WorkspaceSnapshot) -> dict[str, Any]:
    """Build the dashboard payload while preserving research knowledge states."""

    readiness = resolve_workspace_readiness(snapshot.paths)
    active_endpoints = [
        item for item in snapshot.endpoints.endpoints if item.disposition == "ACTIVE"
    ]
    active_resources = [
        item for item in snapshot.resources.resources if item.disposition == "ACTIVE"
    ]
    active_invariants = [
        item for item in snapshot.invariants.invariants if item.disposition == "ACTIVE"
    ]
    active_hypotheses = _active_hypotheses(snapshot.hypotheses.hypotheses)
    research_tasks = [
        item
        for item in snapshot.hypotheses.hypotheses
        if item.kind == "RESEARCH_TASK" and presentation_visible(item)
    ]
    evidence_sets = _evidence_metadata(snapshot.paths)
    reports = _report_files(snapshot.paths)
    counts = {
        "observations": len(snapshot.observations.observations),
        "endpoints": len(snapshot.endpoints.endpoints),
        "active_endpoints": len(active_endpoints),
        "suppressed_endpoints": len(snapshot.endpoints.endpoints) - len(active_endpoints),
        "graphql_operations": _yaml_list_count(snapshot.paths.graphql, "operations"),
        "mobile_discoveries": _yaml_list_count(snapshot.paths.mobile_discoveries, "discoveries"),
        "actors": len(snapshot.actors.actors),
        "active_resources": len(active_resources),
        "active_invariants": len(active_invariants),
        "active_hypotheses": len(active_hypotheses),
        "research_tasks": len(research_tasks),
        "plans": len(snapshot.plans.plans),
        "evidence_sets": len(evidence_sets),
        "validations": len(snapshot.validations.validations),
        "reports": len(reports),
    }
    highest = sorted(active_hypotheses, key=_hypothesis_sort_key)[:6]
    return {
        "workspace": {
            "key": snapshot.paths.root.name,
            "path": str(snapshot.paths.root),
            "name": snapshot.target.target.name,
            "slug": snapshot.target.target.slug or snapshot.paths.root.name,
            "type": snapshot.target.target.type,
            "base_url": snapshot.target.target.base_url,
            "updated_at": _workspace_updated_at(snapshot.paths),
        },
        "scope": {
            "hosts": snapshot.target.scope.hosts,
            "focus": snapshot.target.focus,
            "restrictions": snapshot.target.restrictions.model_dump(mode="json"),
        },
        "testing": snapshot.target.testing.model_dump(mode="json"),
        "accounts": [_sanitized_account(item) for item in snapshot.target.accounts],
        "counts": counts,
        "readiness": readiness.model_dump(mode="json"),
        "stages": _stage_summaries(readiness),
        "hypothesis_statuses": _counter_payload(item.status for item in active_hypotheses),
        "plan_statuses": _counter_payload(item.status for item in snapshot.plans.plans),
        "validation_statuses": _counter_payload(
            item.disposition for item in snapshot.validations.validations
        ),
        "coverage": {
            "actors": _counter_payload(item.actor for item in snapshot.observations.observations),
            "channels": _counter_payload(
                item.channel for item in snapshot.observations.observations
            ),
            "sources": _counter_payload(item.source for item in snapshot.observations.observations),
            "classifications": _counter_payload(
                item.classification.primary for item in active_endpoints
            ),
        },
        "highest_priority": [_hypothesis_summary(item) for item in highest],
        "next_action": _next_action(readiness),
        "knowledge_legend": [
            {"state": "Observed", "description": "Recorded from supplied runtime material."},
            {"state": "Inferred", "description": "A conservative model derived from evidence."},
            {"state": "Expected", "description": "A security property that should hold."},
            {"state": "Hypothesis", "description": "A prioritized research question."},
            {"state": "Finding", "description": "Only a confirmed, report-ready validation."},
        ],
    }


def authentication_payload(snapshot: WorkspaceSnapshot) -> dict[str, Any]:
    """Return redacted actor-authentication preflights without network traffic."""

    store = SecretStore(snapshot.paths)
    permissions = store.permissions()
    actors: list[dict[str, Any]] = []
    for account in snapshot.target.accounts:
        authentication = account.authentication
        try:
            preflight = actor_preflight(snapshot.paths, account.id, for_execution=True)
            preflight_payload = _authentication_preflight_payload(preflight)
        except FinsecError as error:
            preflight_payload = {
                "status": "INVALID",
                "credential_available": False,
                "expires_at": (
                    authentication.expiration.expires_at.isoformat()
                    if authentication is not None
                    and authentication.expiration.expires_at is not None
                    else None
                ),
                "remaining_seconds": None,
                "refresh_available": (
                    authentication.refresh.configured if authentication is not None else False
                ),
                "target_validated": False,
                "baseline_identity_confirmed": False,
                "result": "BLOCKED_BY_AUTH",
                "reasons": [str(error)],
            }
        actors.append(
            {
                "id": account.id,
                "role": account.role,
                "actor_type": account.actor_type
                or ("authenticated_user" if account.authenticated else "anonymous"),
                "authenticated": account.authenticated,
                "auth_type": authentication.auth_type if authentication is not None else None,
                "source": authentication.source.type if authentication is not None else None,
                "last_validated_at": (
                    authentication.last_validated_at.isoformat()
                    if authentication is not None and authentication.last_validated_at is not None
                    else None
                ),
                "preflight": preflight_payload,
            }
        )
    return {
        "workspace": {
            "key": snapshot.paths.root.name,
            "name": snapshot.target.target.name,
            "path": str(snapshot.paths.root),
        },
        "storage": {
            "backend": store.backend_name,
            "permissions": f"{permissions:04o}" if permissions is not None else None,
        },
        "checked_at": datetime.now(UTC).isoformat(),
        "network_requests_sent": 0,
        "browser_collects_credentials": False,
        "actors": actors,
    }


def hypotheses_payload(snapshot: WorkspaceSnapshot) -> dict[str, Any]:
    """Return hypothesis summaries and lifecycle links for the backlog view."""

    plans = {item.hypothesis_id: item for item in snapshot.plans.plans}
    validations = {item.hypothesis_id: item for item in snapshot.validations.validations}
    evidence = {item.hypothesis_id: item for item in _evidence_metadata(snapshot.paths)}
    hypotheses = sorted(
        (item for item in snapshot.hypotheses.hypotheses if presentation_visible(item)),
        key=_hypothesis_sort_key,
    )
    rows: list[dict[str, Any]] = []
    for item in hypotheses:
        row = _hypothesis_summary(item)
        plan = plans.get(item.id)
        validation = validations.get(item.id)
        metadata = evidence.get(item.id)
        row.update(
            {
                "plan_status": plan.status if plan is not None else None,
                "approval_status": plan.approval_status if plan is not None else None,
                "validation_disposition": (
                    validation.disposition if validation is not None else None
                ),
                "evidence_artifacts": len(metadata.artifacts) if metadata is not None else 0,
            }
        )
        rows.append(row)
    return {"hypotheses": rows}


def hypothesis_detail(snapshot: WorkspaceSnapshot, hypothesis_id: str) -> dict[str, Any]:
    """Return one hypothesis with its sanitized evidence chain and current lifecycle records."""

    normalized = hypothesis_id.upper()
    hypothesis = next(
        (item for item in snapshot.hypotheses.hypotheses if item.id == normalized), None
    )
    if hypothesis is None:
        raise WorkspaceError(f"Hypothesis not found: {normalized}")
    plan = next((item for item in snapshot.plans.plans if item.hypothesis_id == normalized), None)
    validation = next(
        (item for item in snapshot.validations.validations if item.hypothesis_id == normalized),
        None,
    )
    evidence = next(
        (item for item in _evidence_metadata(snapshot.paths) if item.hypothesis_id == normalized),
        None,
    )
    endpoint_ids = set(hypothesis.source.endpoints)
    invariant_ids = set(hypothesis.source.invariants)
    return {
        "hypothesis": hypothesis.model_dump(mode="json"),
        "explanation": _hypothesis_explanation(hypothesis),
        "plan": _plan_payload(plan),
        "validation": _validation_payload(validation),
        "evidence": evidence.model_dump(mode="json") if evidence is not None else None,
        "source_endpoints": [
            _endpoint_summary(item)
            for item in snapshot.endpoints.endpoints
            if item.id in endpoint_ids
        ],
        "source_invariants": [
            item.model_dump(mode="json")
            for item in snapshot.invariants.invariants
            if item.id in invariant_ids
        ],
        "reports": [
            item.name for item in _report_files(snapshot.paths) if item.name.startswith(normalized)
        ],
    }


def endpoints_payload(snapshot: WorkspaceSnapshot) -> dict[str, Any]:
    """Return normalized endpoint summaries without raw request values."""

    endpoints = sorted(snapshot.endpoints.endpoints, key=lambda item: item.id)
    return {
        "endpoints": [_endpoint_summary(item) for item in endpoints],
        "classifications": _counter_payload(item.classification.primary for item in endpoints),
        "dispositions": _counter_payload(item.disposition for item in endpoints),
    }


def model_payload(snapshot: WorkspaceSnapshot) -> dict[str, Any]:
    """Return inferred actors/resources and expected invariants for review."""

    return {
        "actors": [item.model_dump(mode="json") for item in snapshot.actors.actors],
        "resources": [item.model_dump(mode="json") for item in snapshot.resources.resources],
        "invariants": [item.model_dump(mode="json") for item in snapshot.invariants.invariants],
    }


def evidence_payload(snapshot: WorkspaceSnapshot) -> dict[str, Any]:
    """Return evidence indexes and validation outcomes, never evidence file contents."""

    validations = {item.hypothesis_id: item for item in snapshot.validations.validations}
    reports = _report_files(snapshot.paths)
    sets: list[dict[str, Any]] = []
    for metadata in _evidence_metadata(snapshot.paths):
        validation = validations.get(metadata.hypothesis_id)
        sets.append(
            {
                "metadata": metadata.model_dump(mode="json"),
                "validation": _validation_payload(validation),
                "reports": [
                    item.name
                    for item in reports
                    if item.name.startswith(f"{metadata.hypothesis_id}-report-")
                ],
            }
        )
    return {
        "evidence_sets": sets,
        "validations_without_evidence": [
            _validation_payload(item)
            for item in snapshot.validations.validations
            if not any(
                metadata.hypothesis_id == item.hypothesis_id
                for metadata in _evidence_metadata(snapshot.paths)
            )
        ],
        "reports": [item.name for item in reports],
    }


def documents_payload(snapshot: WorkspaceSnapshot) -> dict[str, Any]:
    """List allowlisted researcher documents available in the workspace."""

    documents: list[dict[str, Any]] = []
    for document_id, (title, relative) in DOCUMENTS.items():
        path = snapshot.paths.root / relative
        documents.append(
            {
                "id": document_id,
                "title": title,
                "exists": path.is_file(),
                "updated_at": _timestamp(path) if path.is_file() else None,
            }
        )
    return {"documents": documents}


def document_payload(snapshot: WorkspaceSnapshot, document_id: str) -> dict[str, Any]:
    """Read one allowlisted Markdown document from the selected workspace."""

    document = DOCUMENTS.get(document_id)
    if document is None:
        raise WorkspaceError(f"Document not found: {document_id}")
    title, relative = document
    path = snapshot.paths.root / relative
    if not path.is_file():
        return {"id": document_id, "title": title, "content": "", "exists": False}
    return {
        "id": document_id,
        "title": title,
        "content": path.read_text(encoding="utf-8"),
        "exists": True,
        "updated_at": _timestamp(path),
    }


def report_payload(snapshot: WorkspaceSnapshot, filename: str) -> dict[str, Any]:
    """Read one exact immutable report revision from the selected workspace."""

    if not filename.startswith("HYP-") or not filename.endswith(".md") or "/" in filename:
        raise WorkspaceError("Invalid report filename.")
    path = snapshot.paths.reports / filename
    if path not in _report_files(snapshot.paths):
        raise WorkspaceError(f"Report not found: {filename}")
    return {
        "filename": filename,
        "content": path.read_text(encoding="utf-8"),
        "updated_at": _timestamp(path),
    }


def _optional_store(path: Path, default: Any) -> Any:
    if not path.is_file():
        return default
    return type(default).model_validate(load_yaml(path))


def _sanitized_account(account: Any) -> dict[str, Any]:
    authentication = account.authentication
    return {
        "id": account.id,
        "ownership": account.ownership,
        "role": account.role,
        "actor_type": account.actor_type,
        "authenticated": account.authenticated,
        "attributes": account.attributes.model_dump(mode="json"),
        "authentication": (
            {
                "status": authentication.status,
                "auth_type": authentication.auth_type,
                "source": authentication.source.type,
                "expires_at": (
                    authentication.expiration.expires_at.isoformat()
                    if authentication.expiration.expires_at is not None
                    else None
                ),
                "refresh_configured": authentication.refresh.configured,
                "last_validated_at": (
                    authentication.last_validated_at.isoformat()
                    if authentication.last_validated_at is not None
                    else None
                ),
            }
            if authentication is not None
            else None
        ),
    }


def _authentication_preflight_payload(preflight: AuthenticationPreflight) -> dict[str, Any]:
    return {
        "status": preflight.status,
        "credential_available": preflight.credential_available,
        "expires_at": preflight.expires_at.isoformat()
        if preflight.expires_at is not None
        else None,
        "remaining_seconds": preflight.remaining_seconds,
        "refresh_available": preflight.refresh_available,
        "target_validated": preflight.target_validated,
        "baseline_identity_confirmed": preflight.baseline_identity_confirmed,
        "result": preflight.result,
        "reasons": list(preflight.reasons),
    }


def _hypothesis_summary(item: HypothesisRecord) -> dict[str, Any]:
    return {
        "id": item.id,
        "title": presentation_title(item),
        "kind": item.kind,
        "disposition": item.disposition,
        "category": item.category,
        "component": item.component,
        "priority": item.priority,
        "score": item.scores.total,
        "scores": item.scores.model_dump(mode="json"),
        "status": item.status,
        "evidence_status": item.evidence_status,
        "readiness": item.readiness,
        "protected_subject": item.domain_intent.subject_resource,
        "operation": item.domain_intent.operation,
        "visibility": item.domain_intent.visibility,
        "binding": item.domain_intent.binding,
        "cluster_id": item.grouping.cluster_id,
        "campaign_id": item.grouping.campaign_id,
        "relationship": item.grouping.relationship,
        "explanation": _hypothesis_explanation(item),
        "presentation_visible": presentation_visible(item),
        "suppression_reason": item.presentation.suppression_reason,
        "mutation_dimensions": item.mutation_dimensions,
        "missing_evidence_count": len(item.missing_evidence),
        "source_counts": {
            "endpoints": len(item.source.endpoints),
            "invariants": len(item.source.invariants),
            "observations": len(item.source.observations),
        },
    }


def _hypothesis_explanation(item: HypothesisRecord) -> dict[str, Any]:
    target = item.mutation_target
    semantics = target.semantics
    return {
        "mutation_target": {
            "parameter": target.parameter,
            "location": target.location,
            "endpoint_ids": list(target.endpoint_ids),
            "expected_authorization_relationship": target.expected_authorization_relationship,
        },
        "identifier_semantics": {
            "semantic_class": semantics.semantic_class,
            "resource_role": semantics.resource_role,
            "resource_type": semantics.resource_type,
            "parent_resource_type": semantics.parent_resource_type,
            "ownership_state": semantics.ownership_state,
            "confidence": semantics.confidence,
            "evidence": list(semantics.evidence),
            "counterevidence": list(semantics.counterevidence),
            "sources": list(semantics.sources),
            "explanation": semantics.explanation,
        },
        "readiness": {
            "decision": item.readiness_assessment.readiness,
            "reasons": list(item.readiness_assessment.reasons),
            "missing_prerequisites": list(item.readiness_assessment.missing_prerequisites),
        },
        "presentation": {
            "visible": item.presentation.visible,
            "suppression_reason": item.presentation.suppression_reason,
            "retention_reasons": list(item.presentation.retention_reasons),
            "difference_reasons": list(item.presentation.difference_reasons),
            "similar_hypothesis_ids": list(item.presentation.similar_hypothesis_ids),
            "cluster_id": item.grouping.cluster_id,
            "campaign_id": item.grouping.campaign_id,
        },
    }


def _endpoint_summary(item: Endpoint) -> dict[str, Any]:
    return {
        "id": item.id,
        "method": item.method,
        "path": item.path,
        "hosts": item.hosts,
        "channels": item.channels,
        "classification": item.classification.model_dump(mode="json"),
        "resource": item.resource.model_dump(mode="json"),
        "action": item.action.model_dump(mode="json"),
        "authentication": item.authentication.model_dump(mode="json"),
        "state_change": item.state_change,
        "state_change_reasons": item.state_change_reasons,
        "financial_impact": item.financial_impact,
        "security_relevance": item.security_relevance,
        "relevance_reasons": item.relevance_reasons,
        "disposition": item.disposition,
        "confidence": item.confidence,
        "knowledge_status": item.knowledge_status,
        "observations": len(item.sources),
        "parameters": [
            {
                "name": parameter.name,
                "location": parameter.location,
                "inferred_type": parameter.inferred_type,
                "semantic_type": parameter.semantic_type,
                "client_controlled": parameter.client_controlled,
                "knowledge_status": parameter.knowledge_status,
                "evidence_count": len(parameter.evidence),
            }
            for parameter in item.parameters
        ],
        "ownership_signals": [
            {
                "identifier": signal.identifier,
                "source": signal.source,
                "distinct_actors": signal.distinct_actors,
                "distinct_objects": signal.distinct_objects,
                "binding_observed": signal.actor_object_binding_observed,
            }
            for signal in item.object_access
        ],
        "normalization": {
            "observed_paths": len(item.normalization.observed_paths),
            "rules": item.normalization.rules,
        },
    }


def _plan_payload(plan: TestPlanRecord | None) -> dict[str, Any] | None:
    if plan is None:
        return None
    payload = plan.model_dump(mode="json")
    # The plan contains secret references only, but the browser does not need their names.
    payload["authentication"] = [
        {
            "actor": item.actor,
            "required_status": item.required_status,
            "configured": bool(item.credential_profile_ref),
        }
        for item in plan.authentication
    ]
    payload["requests"] = [
        {
            "id": request.id,
            "role": request.role,
            "method": request.method,
            "host": request.host,
            "actor": request.actor,
            "channel": request.channel,
            "mutation_dimensions": [item.dimension for item in request.mutations],
            "runtime_secrets": [
                {
                    "header": secret.header,
                    "actor": secret.actor,
                    "configured": True,
                }
                for secret in request.runtime_secrets
            ],
        }
        for request in plan.requests
    ]
    if isinstance(payload.get("approval"), dict):
        payload["approval"].pop("approval_token_sha256", None)
    return payload


def _validation_payload(validation: ValidationRecord | None) -> dict[str, Any] | None:
    return validation.model_dump(mode="json") if validation is not None else None


def _evidence_metadata(paths: WorkspacePaths) -> list[EvidenceMetadata]:
    if not (paths.root / "evidence").is_dir():
        return []
    records: list[EvidenceMetadata] = []
    for metadata_path in sorted((paths.root / "evidence").glob("HYP-*/metadata.yaml")):
        try:
            records.append(EvidenceMetadata.model_validate(load_yaml(metadata_path)))
        except (OSError, ValidationError, TypeError):
            continue
    return records


def _report_files(paths: WorkspacePaths) -> list[Path]:
    if not paths.reports.is_dir():
        return []
    return sorted(path for path in paths.reports.glob("HYP-*-report-v*.md") if path.is_file())


def _yaml_list_count(path: Path, key: str) -> int:
    if not path.is_file():
        return 0
    data = load_yaml(path)
    records = data.get(key) if isinstance(data, dict) else None
    return len(records) if isinstance(records, list) else 0


def _active_hypotheses(records: list[HypothesisRecord]) -> list[HypothesisRecord]:
    return [
        item
        for item in records
        if item.kind == "SECURITY_HYPOTHESIS"
        and item.disposition == "ACTIVE"
        and presentation_visible(item)
    ]


def _hypothesis_sort_key(item: HypothesisRecord) -> tuple[int, int, str]:
    return ({"P1": 0, "P2": 1, "P3": 2}[item.priority], -item.scores.total, item.id)


def _counter_payload(values: Any) -> list[dict[str, Any]]:
    counts = Counter(str(value) for value in values)
    return [
        {"label": label, "count": count}
        for label, count in sorted(counts.items(), key=lambda item: (-item[1], item[0]))
    ]


def _stage_summaries(readiness: ReadinessReport) -> list[dict[str, Any]]:
    """Adapt the canonical twelve-stage report to the existing dashboard cards."""

    return [
        {
            "id": stage.id,
            "label": stage.id.value.replace("_", " ").title(),
            "count": stage.result_count,
            "status": stage.status,
            "blocker_codes": [item.code for item in stage.blockers],
            "state": (
                "complete"
                if stage.status == LifecycleStatus.COMPLETE
                else "current"
                if stage.status in {LifecycleStatus.READY, LifecycleStatus.STALE}
                else "waiting"
            ),
        }
        for stage in readiness.stages
    ]


def _next_action(readiness: ReadinessReport) -> dict[str, str | None]:
    """Adapt the first canonical remediation without deriving new readiness rules."""

    if readiness.next_actions:
        action = readiness.next_actions[0]
        next_stage = readiness.overall.next_stage
        stage = next((item for item in readiness.stages if item.id == next_stage), None)
        return {
            "eyebrow": next_stage.value.upper() if next_stage is not None else "READINESS",
            "title": action.label,
            "description": stage.summary if stage is not None else "Review workspace readiness.",
            "command": action.command,
            "action_type": action.type,
            "safety": action.safety,
        }
    return {
        "eyebrow": readiness.overall.status,
        "title": "Review the canonical readiness report",
        "description": "No automated remediation is currently available.",
        "command": None,
        "action_type": "manual",
        "safety": "requires_review",
    }


def _workspace_updated_at(paths: WorkspacePaths) -> str | None:
    candidates = [
        paths.target,
        paths.observations,
        paths.endpoints,
        paths.hypotheses,
        paths.test_plans,
        paths.validations,
    ]
    existing = [path for path in candidates if path.is_file()]
    if not existing:
        return None
    latest = max(path.stat().st_mtime for path in existing)
    return datetime.fromtimestamp(latest, tz=UTC).isoformat()


def _timestamp(path: Path) -> str:
    return datetime.fromtimestamp(path.stat().st_mtime, tz=UTC).isoformat()


def _snapshot_signature(paths: WorkspacePaths) -> tuple[tuple[str, int, int], ...]:
    source_paths = (
        paths.target,
        paths.observations,
        paths.endpoints,
        paths.actors,
        paths.resources,
        paths.invariants,
        paths.hypotheses,
        paths.test_plans,
        paths.validations,
        paths.readiness_provenance,
    )
    signature: list[tuple[str, int, int]] = []
    for path in source_paths:
        try:
            stat = path.stat()
        except FileNotFoundError:
            signature.append((str(path), -1, -1))
        else:
            signature.append((str(path), stat.st_mtime_ns, stat.st_size))
    return tuple(signature)
