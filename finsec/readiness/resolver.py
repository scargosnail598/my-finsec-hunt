"""Read-only canonical workspace readiness resolution."""

from __future__ import annotations

import json
import os
import shlex
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ValidationError

from finsec.auth.store import SecretStore
from finsec.config.models import AccountConfig, TargetDocument
from finsec.config.scope import host_is_covered
from finsec.config.workspace import WorkspacePaths
from finsec.errors import FinsecError
from finsec.evidence.domain import EvidenceMetadata
from finsec.execution.domain import ExecutionAuditRecord
from finsec.execution.policy import plan_checksum, target_policy_checksum
from finsec.hypotheses.domain import HypothesisRecord, HypothesisStore
from finsec.modeling.domain import ActorStore, InvariantStore, ResourceStore
from finsec.modeling.merge import stable_fingerprint
from finsec.modeling.models import EndpointStore, ObservationStore
from finsec.readiness.domain import (
    PIPELINE_ORDER,
    ActorCapabilities,
    ActorReadiness,
    ArtifactReadiness,
    BlockerCode,
    BlockerScope,
    CredentialReadiness,
    IdentityConfirmationReadiness,
    LifecycleStatus,
    NextAction,
    OverallReadiness,
    OwnershipReadiness,
    PipelineStage,
    ReadinessBlocker,
    ReadinessContext,
    ReadinessEvidence,
    ReadinessMetrics,
    ReadinessReport,
    StageReadiness,
    TargetValidationReadiness,
)
from finsec.readiness.provenance import (
    ProvenanceStore,
    hypothesis_source_fingerprint,
    invariant_source_fingerprint,
    inventory_source_fingerprint,
    load_provenance,
    model_source_fingerprint,
    output_fingerprint,
    report_source_fingerprint,
    validation_source_fingerprint,
)
from finsec.testing.domain import TestPlanRecord, TestPlanStore
from finsec.testing.planner import plan_source_fingerprint
from finsec.utils.yaml_store import load_yaml
from finsec.validation.domain import ValidationRecord, ValidationStore

SUPPORTED_STORE_VERSION = 1

STAGE_DEPENDENCIES: dict[PipelineStage, list[PipelineStage]] = {
    PipelineStage.SETUP: [],
    PipelineStage.AUTH: [PipelineStage.SETUP],
    PipelineStage.INGEST: [PipelineStage.SETUP],
    PipelineStage.CLASSIFY: [PipelineStage.INGEST],
    PipelineStage.NORMALIZE: [PipelineStage.INGEST, PipelineStage.CLASSIFY],
    PipelineStage.MODEL: [PipelineStage.NORMALIZE],
    PipelineStage.INVARIANTS: [PipelineStage.NORMALIZE, PipelineStage.MODEL],
    PipelineStage.HYPOTHESIZE: [
        PipelineStage.INGEST,
        PipelineStage.NORMALIZE,
        PipelineStage.MODEL,
        PipelineStage.INVARIANTS,
    ],
    PipelineStage.PLAN: [PipelineStage.HYPOTHESIZE],
    PipelineStage.EXECUTE: [PipelineStage.AUTH, PipelineStage.PLAN],
    PipelineStage.VALIDATE: [PipelineStage.HYPOTHESIZE, PipelineStage.PLAN],
    PipelineStage.REPORT: [PipelineStage.VALIDATE],
}

InterfaceName = Literal["cli", "web", "mcp"]
ActionSafety = Literal["safe_to_automate", "requires_review", "requires_human_approval"]
BlockerSeverity = Literal["error", "warning"]
CredentialExpiration = Literal["valid", "expiring_soon", "expired", "unknown", "not_applicable"]

DEFAULT_CAPABILITIES: dict[PipelineStage, tuple[list[InterfaceName], bool]] = {
    PipelineStage.SETUP: (["cli", "web", "mcp"], True),
    PipelineStage.AUTH: (["cli"], False),
    PipelineStage.INGEST: (["cli", "web", "mcp"], True),
    PipelineStage.CLASSIFY: (["cli", "web", "mcp"], True),
    PipelineStage.NORMALIZE: (["cli", "web", "mcp"], True),
    PipelineStage.MODEL: (["cli", "web", "mcp"], True),
    PipelineStage.INVARIANTS: (["cli", "web", "mcp"], True),
    PipelineStage.HYPOTHESIZE: (["cli", "web", "mcp"], True),
    PipelineStage.PLAN: (["cli"], False),
    PipelineStage.EXECUTE: (["cli"], False),
    PipelineStage.VALIDATE: (["cli"], False),
    PipelineStage.REPORT: (["cli"], False),
}


@dataclass(frozen=True)
class _LoadedArtifact[VALUE_T: BaseModel]:
    """Internal safe load result that never carries raw validation input."""

    artifact: ArtifactReadiness
    value: VALUE_T | None
    error_code: BlockerCode | None = None


@dataclass(frozen=True)
class _ProvenanceState:
    """Internal provenance decision for one generated stage."""

    status: str
    blocker_code: BlockerCode | None


def _relative_path(workspace: WorkspacePaths, path: Path) -> str:
    try:
        return str(path.relative_to(workspace.root))
    except ValueError:
        return path.name


def _safe_yaml_list_count(path: Path, key: str) -> int:
    if not path.is_file():
        return 0
    try:
        document = load_yaml(path)
    except (OSError, TypeError, ValueError, yaml.YAMLError):
        return 0
    records = document.get(key) if isinstance(document, dict) else None
    return len(records) if isinstance(records, list) else 0


def _safe_workflow_count(path: Path) -> int:
    if not path.is_file():
        return 0
    try:
        content = path.read_text(encoding="utf-8")
    except OSError:
        return 0
    return sum(line.startswith("## Workflow:") for line in content.splitlines())


def _load_artifact[MODEL_T: BaseModel](
    workspace: WorkspacePaths,
    path: Path,
    model: type[MODEL_T],
    name: str,
    *,
    versioned: bool = True,
    supported_versions: frozenset[int] = frozenset({SUPPORTED_STORE_VERSION}),
) -> _LoadedArtifact[MODEL_T]:
    relative = _relative_path(workspace, path)
    if not path.is_file():
        return _LoadedArtifact(
            ArtifactReadiness(
                name=name,
                path=relative,
                exists=False,
                valid=False,
                provenance="MISSING",
            ),
            None,
            BlockerCode.ARTIFACT_MISSING,
        )
    try:
        document = load_yaml(path)
    except (OSError, TypeError, ValueError, yaml.YAMLError):
        return _LoadedArtifact(
            ArtifactReadiness(
                name=name,
                path=relative,
                exists=True,
                valid=False,
                provenance="MALFORMED",
            ),
            None,
            BlockerCode.ARTIFACT_MALFORMED,
        )
    version = document.get("version") if isinstance(document, dict) else None
    if versioned and version not in supported_versions:
        return _LoadedArtifact(
            ArtifactReadiness(
                name=name,
                path=relative,
                exists=True,
                valid=False,
                schema_version=version if isinstance(version, int) else None,
                provenance="MALFORMED",
            ),
            None,
            BlockerCode.ARTIFACT_SCHEMA_INCOMPATIBLE,
        )
    try:
        value = model.model_validate(document)
    except (TypeError, ValueError, ValidationError):
        return _LoadedArtifact(
            ArtifactReadiness(
                name=name,
                path=relative,
                exists=True,
                valid=False,
                schema_version=version if isinstance(version, int) else None,
                provenance="MALFORMED",
            ),
            None,
            BlockerCode.ARTIFACT_MALFORMED,
        )
    return _LoadedArtifact(
        ArtifactReadiness(
            name=name,
            path=relative,
            exists=True,
            valid=True,
            schema_version=version if isinstance(version, int) else None,
        ),
        value,
    )


def _workspace_command(command: str, workspace: WorkspacePaths) -> str:
    return f"{command} --workspace {shlex.quote(str(workspace.root))}"


def _cli_action(
    label: str,
    command: str,
    *,
    safety: ActionSafety = "safe_to_automate",
) -> NextAction:
    return NextAction(type="cli_command", label=label, command=command, safety=safety)


def _manual_action(
    label: str,
    *,
    safety: ActionSafety = "requires_review",
) -> NextAction:
    return NextAction(type="manual", label=label, safety=safety)


def _blocker(
    code: BlockerCode,
    stage: PipelineStage,
    summary: str,
    *,
    severity: BlockerSeverity = "error",
    scope: BlockerScope | None = None,
    details: str | None = None,
    evidence: ReadinessEvidence | None = None,
    actions: list[NextAction] | None = None,
) -> ReadinessBlocker:
    return ReadinessBlocker(
        code=code,
        stage=stage,
        severity=severity,
        scope=scope or BlockerScope(),
        summary=summary,
        details=details,
        evidence=evidence,
        next_actions=actions or [],
    )


def _blocker_sort_key(item: ReadinessBlocker) -> tuple[int, str, str]:
    scope = json.dumps(item.scope.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
    return (0 if item.severity == "error" else 1, item.code.value, scope)


def _deduplicate_blockers(items: list[ReadinessBlocker]) -> list[ReadinessBlocker]:
    result: dict[tuple[str, str, str], ReadinessBlocker] = {}
    for item in items:
        scope = json.dumps(
            item.scope.model_dump(mode="json"), sort_keys=True, separators=(",", ":")
        )
        result.setdefault((item.code.value, item.severity, scope), item)
    return sorted(result.values(), key=_blocker_sort_key)


def _deduplicate_actions(items: list[NextAction]) -> list[NextAction]:
    result: dict[tuple[str, str, str, str], NextAction] = {}
    for item in items:
        key = (item.type, item.label, item.command or "", item.safety)
        result.setdefault(key, item)
    return list(result.values())


def _capability(
    stage: PipelineStage, context: ReadinessContext | None
) -> tuple[list[InterfaceName], bool]:
    available, web_action = DEFAULT_CAPABILITIES[stage]
    if context is not None:
        available = list(context.available_via.get(stage, available))
        web_action = context.web_actions.get(stage, web_action)
    return available, web_action


def _stage(
    stage_id: PipelineStage,
    status: LifecycleStatus,
    summary: str,
    *,
    context: ReadinessContext | None,
    artifacts: list[ArtifactReadiness] | None = None,
    blockers: list[ReadinessBlocker] | None = None,
    warnings: list[ReadinessBlocker] | None = None,
    result_count: int = 0,
    actions: list[NextAction] | None = None,
) -> StageReadiness:
    available, web_action = _capability(stage_id, context)
    deduplicated_blockers = _deduplicate_blockers(blockers or [])
    deduplicated_warnings = _deduplicate_blockers(warnings or [])
    stage_actions = _deduplicate_actions(
        [*(actions or []), *(a for item in deduplicated_blockers for a in item.next_actions)]
    )
    return StageReadiness(
        id=stage_id,
        status=status,
        summary=summary,
        dependencies=STAGE_DEPENDENCIES[stage_id],
        artifacts=artifacts or [],
        blockers=deduplicated_blockers,
        warnings=deduplicated_warnings,
        available_via=available,
        web_action_available=web_action,
        result_count=result_count,
        next_actions=stage_actions,
    )


def _artifact_failure_blocker(
    workspace: WorkspacePaths,
    stage: PipelineStage,
    loaded: _LoadedArtifact[Any],
    action: NextAction | None = None,
) -> ReadinessBlocker:
    code = loaded.error_code or BlockerCode.ARTIFACT_MALFORMED
    summary = {
        BlockerCode.ARTIFACT_MISSING: "A required workspace artifact is missing.",
        BlockerCode.ARTIFACT_SCHEMA_INCOMPATIBLE: (
            "A workspace artifact uses an unsupported schema version."
        ),
    }.get(code, "A workspace artifact is malformed or unreadable.")
    return _blocker(
        code,
        stage,
        summary,
        scope=BlockerScope(
            workspace=workspace.root.name,
            artifact=loaded.artifact.path,
        ),
        details="The artifact was not discarded or rewritten.",
        actions=[action] if action is not None else [],
    )


def _provenance_state(
    store: ProvenanceStore | None,
    *,
    malformed: bool,
    key: str,
    input_fingerprint: str,
    output_fingerprint_value: str | None = None,
) -> _ProvenanceState:
    if malformed:
        return _ProvenanceState("MALFORMED", BlockerCode.ARTIFACT_MALFORMED)
    if store is None:
        return _ProvenanceState("LEGACY_UNKNOWN", BlockerCode.ARTIFACT_PROVENANCE_MISSING)
    entry = next((item for item in store.entries if item.key == key), None)
    if entry is None:
        return _ProvenanceState("LEGACY_UNKNOWN", BlockerCode.ARTIFACT_PROVENANCE_MISSING)
    if entry.input_fingerprint != input_fingerprint:
        return _ProvenanceState("STALE", BlockerCode.UPSTREAM_DEPENDENCY_CHANGED)
    if (
        output_fingerprint_value is not None
        and entry.output_fingerprint != output_fingerprint_value
    ):
        return _ProvenanceState("STALE", BlockerCode.ARTIFACT_INTEGRITY_FAILURE)
    return _ProvenanceState("CURRENT", None)


def _with_provenance(artifact: ArtifactReadiness, state: _ProvenanceState) -> ArtifactReadiness:
    return artifact.model_copy(
        update={
            "stale": state.status in {"STALE", "LEGACY_UNKNOWN", "MALFORMED"},
            "provenance": state.status,
        }
    )


def _record_integrity(record: BaseModel, ignored_fields: set[str]) -> bool:
    document = record.model_dump(mode="json", exclude_none=True)
    generation = document.get("generation")
    if not isinstance(generation, dict) or not generation.get("managed", True):
        return False
    payload = {
        key: value
        for key, value in document.items()
        if key != "generation" and key not in ignored_fields
    }
    return generation.get("generated_checksum") == stable_fingerprint(payload)


def _generated_store_integrity(records: list[BaseModel], ignored_fields: set[str]) -> bool:
    return all(_record_integrity(item, ignored_fields) for item in records)


def _provenance_blocker(
    workspace: WorkspacePaths,
    stage: PipelineStage,
    state: _ProvenanceState,
    artifact: ArtifactReadiness,
    action: NextAction,
) -> ReadinessBlocker:
    code = state.blocker_code or BlockerCode.UPSTREAM_DEPENDENCY_CHANGED
    summary = {
        BlockerCode.ARTIFACT_PROVENANCE_MISSING: (
            "The artifact has legacy or unverifiable provenance."
        ),
        BlockerCode.ARTIFACT_INTEGRITY_FAILURE: (
            "The artifact content no longer matches its recorded producer output."
        ),
        BlockerCode.ARTIFACT_MALFORMED: "Readiness provenance is malformed.",
    }.get(code, "A relevant upstream dependency changed after generation.")
    return _blocker(
        code,
        stage,
        summary,
        scope=BlockerScope(workspace=workspace.root.name, artifact=artifact.path),
        details="Regeneration is non-destructive and preserves supported researcher edits.",
        actions=[action],
    )


def _ownership_counts(endpoints: EndpointStore | None) -> dict[str, int]:
    counts: dict[str, int] = {}
    if endpoints is None:
        return counts
    for endpoint in endpoints.endpoints:
        for binding in endpoint.object_access:
            if not binding.actor_object_binding_observed:
                continue
            actors = {item.actor for item in binding.baselines}
            if binding.source == "CONTROLLED_LIFECYCLE":
                confirmed = min(
                    binding.distinct_actors,
                    binding.distinct_objects,
                    len({item.baseline_id for item in binding.baselines if item.baseline_id}),
                )
            else:
                confirmed = min(
                    binding.distinct_actors,
                    binding.distinct_objects,
                    binding.distinct_owner_values or binding.distinct_scope_values,
                )
            for actor in actors:
                counts[actor] = max(counts.get(actor, 0), confirmed)
    return counts


def _credential_available(workspace: WorkspacePaths, account: AccountConfig) -> bool:
    authentication = account.authentication
    if authentication is None:
        return False
    if authentication.auth_type == "none":
        return True
    if authentication.source.type == "legacy_environment":
        return any(
            bool(os.environ.get(name)) for name in authentication.legacy_environment.values()
        )
    if not authentication.components:
        return False
    try:
        store = SecretStore(workspace)
        return all(
            not item.replay_required or store.contains(item.credential_ref, account.id)
            for item in authentication.components
        )
    except (FinsecError, OSError):
        return False


def _actor_readiness(
    workspace: WorkspacePaths,
    account: AccountConfig,
    ownership_counts: dict[str, int],
) -> tuple[ActorReadiness, list[ReadinessBlocker], list[ReadinessBlocker]]:
    stage = PipelineStage.AUTH
    actor_scope = BlockerScope(workspace=workspace.root.name, actor_ids=[account.id])
    actor_type = account.actor_type or (
        "authenticated_user" if account.authenticated else "anonymous"
    )
    authentication = account.authentication
    if actor_type == "anonymous" or not account.authenticated:
        return (
            ActorReadiness(
                actor_id=account.id,
                credential=CredentialReadiness(
                    available=True,
                    type="none",
                    expiration="not_applicable",
                    locally_usable=True,
                ),
                target_validation=TargetValidationReadiness(recorded=True),
                identity_confirmation=IdentityConfirmationReadiness(confirmed=True),
                ownership=OwnershipReadiness(
                    confirmed_baselines=ownership_counts.get(account.id, 0)
                ),
                capabilities=ActorCapabilities(planning=True, authorization_execution=False),
            ),
            [],
            [],
        )

    blockers: list[ReadinessBlocker] = []
    warnings: list[ReadinessBlocker] = []
    available = _credential_available(workspace, account)
    auth_type = authentication.auth_type if authentication is not None else "legacy_unmanaged"
    expiration: CredentialExpiration = "unknown"
    expired = False
    expiring = False
    if authentication is not None and authentication.expiration.expires_at is not None:
        remaining = (
            authentication.expiration.expires_at.astimezone(UTC) - datetime.now(UTC)
        ).total_seconds()
        expired = remaining <= 0
        expiring = 0 < remaining <= 300
        expiration = "expired" if expired else "expiring_soon" if expiring else "valid"
    if not available:
        blockers.append(
            _blocker(
                BlockerCode.NO_ACTOR_CREDENTIAL,
                stage,
                "No locally usable actor credential is available.",
                scope=actor_scope,
                actions=[
                    _manual_action(
                        f"Import or set a reviewed credential for {account.id}",
                        safety="requires_human_approval",
                    )
                ],
            )
        )
    if expired:
        blockers.append(
            _blocker(
                BlockerCode.CREDENTIAL_EXPIRED,
                stage,
                "The actor credential has a known expiration in the past.",
                scope=actor_scope,
                actions=[
                    _manual_action(
                        f"Refresh or replace the credential for {account.id}",
                        safety="requires_human_approval",
                    )
                ],
            )
        )
    elif expiration == "unknown" and available:
        warnings.append(
            _blocker(
                BlockerCode.CREDENTIAL_EXPIRATION_UNKNOWN,
                stage,
                "Credential expiration is unknown, not expired.",
                severity="warning",
                scope=actor_scope,
            )
        )
    invalid_states = {
        "INVALID",
        "REFRESH_REQUIRED",
        "REFRESH_FAILED",
        "AUTH_CONTEXT_CHANGED",
        "MISSING",
        "EXPIRED",
    }
    unusable = authentication is None or authentication.status in invalid_states
    if unusable and available and not expired:
        blockers.append(
            _blocker(
                BlockerCode.CREDENTIAL_UNUSABLE,
                stage,
                "The stored credential metadata is not usable for bounded execution.",
                scope=actor_scope,
            )
        )
    target_validated = authentication is not None and authentication.last_validated_at is not None
    identity_confirmed = authentication is not None and authentication.identity.baseline_confirmed
    if available and not target_validated:
        blockers.append(
            _blocker(
                BlockerCode.TARGET_VALIDATION_MISSING,
                stage,
                "No target-side credential validation is recorded.",
                scope=actor_scope,
                actions=[
                    _cli_action(
                        f"Validate the read-only baseline for {account.id}",
                        _workspace_command(
                            f"hunt actor auth check {shlex.quote(account.id)} --network", workspace
                        ),
                        safety="requires_human_approval",
                    )
                ],
            )
        )
    if available and not identity_confirmed:
        blockers.append(
            _blocker(
                BlockerCode.ACTOR_IDENTITY_NOT_CONFIRMED,
                stage,
                "The validated baseline has not confirmed the intended actor identity.",
                scope=actor_scope,
                actions=[
                    _cli_action(
                        f"Confirm the read-only actor baseline for {account.id}",
                        _workspace_command(
                            f"hunt actor auth check {shlex.quote(account.id)} --network", workspace
                        ),
                        safety="requires_human_approval",
                    )
                ],
            )
        )
    locally_usable = available and not expired and not unusable
    confirmed_baselines = ownership_counts.get(account.id, 0)
    authorization_execution = (
        locally_usable and target_validated and identity_confirmed and confirmed_baselines >= 2
    )
    return (
        ActorReadiness(
            actor_id=account.id,
            credential=CredentialReadiness(
                available=available,
                type=auth_type,
                expiration=expiration,
                locally_usable=locally_usable,
            ),
            target_validation=TargetValidationReadiness(recorded=target_validated),
            identity_confirmation=IdentityConfirmationReadiness(confirmed=identity_confirmed),
            ownership=OwnershipReadiness(confirmed_baselines=confirmed_baselines),
            capabilities=ActorCapabilities(
                planning=locally_usable,
                authorization_execution=authorization_execution,
            ),
        ),
        blockers,
        warnings,
    )


def _active_hypotheses(store: HypothesisStore | None) -> list[HypothesisRecord]:
    if store is None:
        return []
    return sorted(
        (
            item
            for item in store.hypotheses
            if item.kind == "SECURITY_HYPOTHESIS" and item.disposition == "ACTIVE"
        ),
        key=lambda item: (item.priority, -item.scores.total, item.id),
    )


def _plan_current(
    plan: TestPlanRecord,
    target: TargetDocument,
    observations: ObservationStore,
    endpoints: EndpointStore,
    resources: ResourceStore,
    hypothesis: HypothesisRecord,
) -> bool:
    generation = plan.generation
    if generation is None or generation.generator != "phase3-test-planner":
        return False
    if generation.generated_checksum != plan_checksum(plan):
        return False
    return generation.source_fingerprint == plan_source_fingerprint(
        target,
        observations,
        endpoints,
        resources,
        hypothesis,
    )


def _load_evidence_sets(
    workspace: WorkspacePaths,
) -> tuple[dict[str, EvidenceMetadata], list[ReadinessBlocker]]:
    records: dict[str, EvidenceMetadata] = {}
    blockers: list[ReadinessBlocker] = []
    root = workspace.root / "evidence"
    if not root.is_dir():
        return records, blockers
    for directory in sorted(path for path in root.iterdir() if path.is_dir()):
        metadata_path = directory / "metadata.yaml"
        if not metadata_path.is_file():
            continue
        loaded = _load_artifact(
            workspace,
            metadata_path,
            EvidenceMetadata,
            f"Evidence {directory.name}",
            versioned=True,
        )
        if loaded.value is None:
            blockers.append(_artifact_failure_blocker(workspace, PipelineStage.VALIDATE, loaded))
            continue
        records[loaded.value.hypothesis_id] = loaded.value
    return records, blockers


def _load_execution_audits(
    workspace: WorkspacePaths,
) -> tuple[list[ExecutionAuditRecord], list[ReadinessBlocker]]:
    records: list[ExecutionAuditRecord] = []
    blockers: list[ReadinessBlocker] = []
    root = workspace.root / "tests" / "executions"
    if not root.is_dir():
        return records, blockers
    for path in sorted(root.glob("HYP-*/execution-v*.yaml")):
        loaded = _load_artifact(
            workspace,
            path,
            ExecutionAuditRecord,
            f"Execution audit {path.parent.name}",
            versioned=True,
        )
        if loaded.value is None:
            blockers.append(_artifact_failure_blocker(workspace, PipelineStage.EXECUTE, loaded))
            continue
        records.append(loaded.value)
    return records, blockers


def _authorization_ownership_blockers(
    workspace: WorkspacePaths,
    hypothesis: HypothesisRecord,
    endpoints: EndpointStore,
) -> list[ReadinessBlocker]:
    if hypothesis.category != "authorization":
        return []
    by_id = {item.id: item for item in endpoints.endpoints}
    selected = [by_id[item] for item in hypothesis.source.endpoints if item in by_id]
    actor_ids = sorted(
        {
            baseline.actor
            for endpoint in selected
            for binding in endpoint.object_access
            for baseline in binding.baselines
        }
    )
    applicable = any(
        binding.actor_object_binding_observed
        for endpoint in selected
        for binding in endpoint.object_access
    )
    if applicable:
        return []
    conflicting = any(
        "conflict" in reason.lower()
        for endpoint in selected
        for decision in endpoint.ownership_inference
        for reason in decision.reasons
    )
    code = (
        BlockerCode.OWNERSHIP_BASELINE_CONFLICTING
        if conflicting
        else BlockerCode.OWNERSHIP_BASELINES_MISSING
    )
    return [
        _blocker(
            code,
            PipelineStage.EXECUTE,
            (
                "Controlled ownership evidence is conflicting."
                if conflicting
                else "Controlled actor-object-owner baselines are incomplete."
            ),
            scope=BlockerScope(
                workspace=workspace.root.name,
                hypothesis_id=hypothesis.id,
                actor_ids=actor_ids,
            ),
            evidence=ReadinessEvidence(required=2, confirmed=0),
            details=("Observed account or object identifiers are not treated as ownership proof."),
            actions=[
                _manual_action(
                    "Import reviewed captures proving two controlled ownership relationships"
                ),
                _cli_action(
                    "Rebuild ownership evidence after capture review",
                    _workspace_command("hunt inventory", workspace),
                ),
            ],
        )
    ]


def _mapped_plan_blockers(
    workspace: WorkspacePaths,
    hypothesis: HypothesisRecord,
    plan: TestPlanRecord,
) -> list[ReadinessBlocker]:
    result: list[ReadinessBlocker] = []
    reasons = [*plan.risk.reasons, *plan.execution.blockers]
    for reason in reasons:
        lowered = reason.lower()
        if "two controlled actor-object-owner" in lowered or "distinct controlled" in lowered:
            code = BlockerCode.OWNERSHIP_BASELINES_MISSING
        elif "two researcher-controlled accounts" in lowered:
            code = BlockerCode.INSUFFICIENT_CONTROLLED_ACTORS
        elif "scope" in lowered or "host" in lowered or "destination" in lowered:
            code = BlockerCode.DESTINATION_SCOPE_VALIDATION_FAILURE
        elif "authentication" in lowered or "credential" in lowered:
            code = BlockerCode.CREDENTIAL_UNUSABLE
        elif "read-only" in lowered or "destructive" in lowered or "financial" in lowered:
            code = BlockerCode.READ_ONLY_POLICY_CONFLICT
        else:
            code = BlockerCode.PLAN_POLICY_BLOCKED
        result.append(
            _blocker(
                code,
                PipelineStage.EXECUTE,
                "The current plan is blocked by a safety or evidence policy.",
                scope=BlockerScope(
                    workspace=workspace.root.name,
                    hypothesis_id=hypothesis.id,
                    plan_id=plan.id,
                ),
                details=reason,
                actions=[
                    _cli_action(
                        f"Regenerate and review {hypothesis.id}",
                        _workspace_command(f"hunt plan {shlex.quote(hypothesis.id)}", workspace),
                        safety="requires_review",
                    )
                ],
            )
        )
    return result


def _execution_blockers(
    workspace: WorkspacePaths,
    target: TargetDocument,
    hypothesis: HypothesisRecord,
    plan: TestPlanRecord,
    endpoints: EndpointStore,
    actor_by_id: dict[str, ActorReadiness],
) -> list[ReadinessBlocker]:
    scope = BlockerScope(
        workspace=workspace.root.name,
        hypothesis_id=hypothesis.id,
        plan_id=plan.id,
    )
    blockers = _mapped_plan_blockers(workspace, hypothesis, plan)
    blockers.extend(_authorization_ownership_blockers(workspace, hypothesis, endpoints))
    controlled = {item.id for item in target.accounts if item.ownership == "researcher"}
    if hypothesis.category == "authorization" and len(controlled) < 2:
        blockers.append(
            _blocker(
                BlockerCode.INSUFFICIENT_CONTROLLED_ACTORS,
                PipelineStage.EXECUTE,
                "Two researcher-controlled actors are required for this authorization test.",
                scope=scope,
                evidence=ReadinessEvidence(required=2, confirmed=len(controlled)),
            )
        )
    if not target.testing.active_execution_enabled:
        blockers.append(
            _blocker(
                BlockerCode.ACTIVE_EXECUTION_DISABLED,
                PipelineStage.EXECUTE,
                "Active execution is disabled by target policy.",
                scope=scope,
                actions=[
                    _manual_action(
                        "Review target policy before enabling active execution",
                        safety="requires_human_approval",
                    )
                ],
            )
        )
    if not target.testing.read_only_only or any(
        item.method not in {"GET", "HEAD"} or item.body is not None for item in plan.requests
    ):
        blockers.append(
            _blocker(
                BlockerCode.READ_ONLY_POLICY_CONFLICT,
                PipelineStage.EXECUTE,
                "The plan conflicts with the read-only bounded runner policy.",
                scope=scope,
            )
        )
    request_count = len(plan.requests)
    if (
        request_count == 0
        or request_count != plan.execution.request_budget
        or request_count > plan.risk.request_budget
        or request_count > target.testing.maximum_requests_per_plan
    ):
        blockers.append(
            _blocker(
                BlockerCode.PLAN_REQUEST_BUDGET_MISMATCH,
                PipelineStage.EXECUTE,
                "The plan request count does not match the approved request budget.",
                scope=scope,
                evidence=ReadinessEvidence(
                    required=plan.execution.request_budget,
                    confirmed=request_count,
                ),
            )
        )
    if plan.approval_status != "APPROVED" or plan.approval is None:
        blockers.append(
            _blocker(
                BlockerCode.HUMAN_APPROVAL_MISSING,
                PipelineStage.EXECUTE,
                "Checksum-bound human approval is missing.",
                scope=scope,
                actions=[
                    _cli_action(
                        f"Review and approve {hypothesis.id}",
                        _workspace_command(f"hunt approve {shlex.quote(hypothesis.id)}", workspace),
                        safety="requires_human_approval",
                    )
                ],
            )
        )
    else:
        current_plan = plan_checksum(plan)
        current_policy = target_policy_checksum(target)
        if (
            plan.approval.plan_checksum != current_plan
            or plan.approval.target_policy_checksum != current_policy
        ):
            blockers.append(
                _blocker(
                    BlockerCode.APPROVAL_STALE,
                    PipelineStage.EXECUTE,
                    "The approval is not bound to the current plan and target policy.",
                    scope=scope,
                )
            )
    for request in plan.requests:
        if request.actor not in controlled:
            blockers.append(
                _blocker(
                    BlockerCode.INSUFFICIENT_CONTROLLED_ACTORS,
                    PipelineStage.EXECUTE,
                    "A planned request is assigned to an uncontrolled actor.",
                    scope=scope,
                )
            )
        if request.scheme not in {"http", "https"} or not host_is_covered(
            request.host, target.scope.hosts
        ):
            blockers.append(
                _blocker(
                    BlockerCode.DESTINATION_SCOPE_VALIDATION_FAILURE,
                    PipelineStage.EXECUTE,
                    "A planned destination is outside the statically validated target scope.",
                    scope=scope,
                )
            )
        actor = actor_by_id.get(request.actor)
        if actor is None or actor.credential.type == "none":
            continue
        actor_scope = scope.model_copy(update={"actor_ids": [request.actor]})
        if not actor.credential.available:
            blockers.append(
                _blocker(
                    BlockerCode.NO_ACTOR_CREDENTIAL,
                    PipelineStage.EXECUTE,
                    "A planned actor credential is unavailable.",
                    scope=actor_scope,
                )
            )
        elif actor.credential.expiration == "expired":
            blockers.append(
                _blocker(
                    BlockerCode.CREDENTIAL_EXPIRED,
                    PipelineStage.EXECUTE,
                    "A planned actor credential is expired.",
                    scope=actor_scope,
                )
            )
        elif not actor.credential.locally_usable:
            blockers.append(
                _blocker(
                    BlockerCode.CREDENTIAL_UNUSABLE,
                    PipelineStage.EXECUTE,
                    "A planned actor credential is not locally usable.",
                    scope=actor_scope,
                )
            )
        if not actor.target_validation.recorded:
            blockers.append(
                _blocker(
                    BlockerCode.TARGET_VALIDATION_MISSING,
                    PipelineStage.EXECUTE,
                    "Target-side credential validation is missing for a planned actor.",
                    scope=actor_scope,
                )
            )
        if not actor.identity_confirmation.confirmed:
            blockers.append(
                _blocker(
                    BlockerCode.ACTOR_IDENTITY_NOT_CONFIRMED,
                    PipelineStage.EXECUTE,
                    "The intended actor identity is not confirmed for execution.",
                    scope=actor_scope,
                )
            )
    return _deduplicate_blockers(blockers)


def _validation_current(
    validation: ValidationRecord,
    target: TargetDocument,
    endpoints: EndpointStore,
    hypothesis: HypothesisRecord,
    plan: TestPlanRecord | None,
    evidence: EvidenceMetadata,
) -> bool:
    generation = validation.generation
    if generation is None or generation.generator != "phase4-validator":
        return False
    if not _record_integrity(validation, {"notes"}):
        return False
    return generation.source_fingerprint == validation_source_fingerprint(
        target,
        endpoints,
        hypothesis,
        plan,
        evidence,
    )


def _state_evidence_missing(
    hypothesis: HypothesisRecord,
    endpoints: EndpointStore,
    evidence: EvidenceMetadata,
) -> bool:
    by_id = {item.id: item for item in endpoints.endpoints}
    state_changing = any(
        by_id[item].state_change for item in hypothesis.source.endpoints if item in by_id
    )
    if not state_changing:
        return False
    kinds = {item.kind for item in evidence.artifacts}
    return not {"before", "after"}.issubset(kinds)


def _not_configured_report(
    workspace: WorkspacePaths,
    context: ReadinessContext | None,
    setup_stage: StageReadiness,
) -> ReadinessReport:
    stages = [setup_stage]
    for stage_id in PIPELINE_ORDER[1:]:
        stages.append(
            _stage(
                stage_id,
                LifecycleStatus.NOT_CONFIGURED,
                "Workspace target configuration is unavailable.",
                context=context,
                blockers=[
                    _blocker(
                        BlockerCode.WORKSPACE_NOT_CONFIGURED,
                        stage_id,
                        "Configure the workspace before evaluating this stage.",
                        scope=BlockerScope(workspace=workspace.root.name),
                    )
                ],
            )
        )
    return ReadinessReport(
        workspace=workspace.root.name,
        overall=OverallReadiness(
            status=LifecycleStatus.NOT_CONFIGURED, next_stage=PipelineStage.SETUP
        ),
        stages=stages,
        next_actions=setup_stage.next_actions,
    )


def resolve_workspace_readiness(
    workspace: WorkspacePaths | Path,
    context: ReadinessContext | None = None,
) -> ReadinessReport:
    """Resolve canonical readiness without modifying files, credentials, or network state."""

    paths = workspace if isinstance(workspace, WorkspacePaths) else WorkspacePaths(workspace)
    setup_action = _cli_action("Create or configure the workspace", "hunt setup")
    target_loaded = _load_artifact(
        paths, paths.target, TargetDocument, "Target configuration", versioned=False
    )
    if target_loaded.value is None:
        status = (
            LifecycleStatus.NOT_CONFIGURED
            if not target_loaded.artifact.exists
            else LifecycleStatus.BLOCKED
        )
        setup = _stage(
            PipelineStage.SETUP,
            status,
            "Target configuration is missing or invalid.",
            context=context,
            artifacts=[target_loaded.artifact],
            blockers=[
                _artifact_failure_blocker(paths, PipelineStage.SETUP, target_loaded, setup_action)
            ],
            actions=[setup_action],
        )
        return _not_configured_report(paths, context, setup)

    target = target_loaded.value
    observations_loaded = _load_artifact(
        paths, paths.observations, ObservationStore, "Observation store"
    )
    endpoints_loaded = _load_artifact(
        paths,
        paths.endpoints,
        EndpointStore,
        "Endpoint inventory",
        supported_versions=frozenset({1, 2}),
    )
    actors_loaded = _load_artifact(paths, paths.actors, ActorStore, "Actor model")
    resources_loaded = _load_artifact(paths, paths.resources, ResourceStore, "Resource model")
    invariants_loaded = _load_artifact(paths, paths.invariants, InvariantStore, "Invariant store")
    hypotheses_loaded = _load_artifact(
        paths,
        paths.hypotheses,
        HypothesisStore,
        "Hypothesis backlog",
        supported_versions=frozenset({1, 2, 3}),
    )
    plans_loaded = _load_artifact(paths, paths.test_plans, TestPlanStore, "Test plan store")
    validations_loaded = _load_artifact(
        paths, paths.validations, ValidationStore, "Validation store"
    )

    provenance: ProvenanceStore | None = None
    provenance_malformed = False
    try:
        provenance = load_provenance(paths)
    except (OSError, TypeError, ValueError, ValidationError, yaml.YAMLError):
        provenance_malformed = True

    setup_blockers: list[ReadinessBlocker] = []
    if not target.scope.hosts:
        setup_blockers.append(
            _blocker(
                BlockerCode.TARGET_NOT_CONFIGURED,
                PipelineStage.SETUP,
                "No authorized target host is configured.",
                scope=BlockerScope(workspace=paths.root.name, artifact="target.yaml"),
                actions=[_manual_action("Record authorized scope hosts in target.yaml")],
            )
        )
    setup = _stage(
        PipelineStage.SETUP,
        LifecycleStatus.BLOCKED if setup_blockers else LifecycleStatus.COMPLETE,
        (
            "Workspace exists, but target scope configuration is incomplete."
            if setup_blockers
            else "Workspace and target configuration are valid."
        ),
        context=context,
        artifacts=[target_loaded.artifact],
        blockers=setup_blockers,
        result_count=1,
    )

    observations = observations_loaded.value
    endpoints = endpoints_loaded.value
    actors = actors_loaded.value
    resources = resources_loaded.value
    invariants = invariants_loaded.value
    hypotheses = hypotheses_loaded.value
    plans = plans_loaded.value
    validations = validations_loaded.value

    inventory_state: _ProvenanceState | None = None
    endpoint_artifact = endpoints_loaded.artifact
    if observations is not None and endpoints is not None:
        inventory_input = inventory_source_fingerprint(target, observations)
        inventory_state = _provenance_state(
            provenance,
            malformed=provenance_malformed,
            key="normalize",
            input_fingerprint=inventory_input,
            output_fingerprint_value=output_fingerprint(
                endpoints.model_dump(mode="json", exclude_none=True)
            ),
        )
        endpoint_artifact = _with_provenance(endpoint_artifact, inventory_state)

    ownership_counts = _ownership_counts(
        endpoints if inventory_state is not None and inventory_state.status == "CURRENT" else None
    )
    actor_reports: list[ActorReadiness] = []
    auth_blockers: list[ReadinessBlocker] = []
    auth_warnings: list[ReadinessBlocker] = []
    for account in sorted(target.accounts, key=lambda item: item.id):
        actor_report, blockers, warnings = _actor_readiness(paths, account, ownership_counts)
        actor_reports.append(actor_report)
        auth_blockers.extend(blockers)
        auth_warnings.extend(warnings)
    authenticated = [
        item
        for item in target.accounts
        if (item.actor_type or ("authenticated_user" if item.authenticated else "anonymous"))
        != "anonymous"
        and item.authenticated
    ]
    auth_complete = bool(authenticated) and not auth_blockers
    auth_status = (
        LifecycleStatus.COMPLETE if auth_complete or not authenticated else LifecycleStatus.BLOCKED
    )
    auth = _stage(
        PipelineStage.AUTH,
        auth_status,
        (
            "All configured actor identities are confirmed for credential use."
            if auth_status == LifecycleStatus.COMPLETE
            else "Credential, target-validation, and identity facts remain incomplete."
        ),
        context=context,
        blockers=auth_blockers,
        warnings=auth_warnings,
        result_count=sum(item.credential.available for item in actor_reports),
    )

    ingest_action = _cli_action(
        "Import reviewed runtime captures",
        _workspace_command("hunt ingest-wizard", paths),
        safety="requires_review",
    )
    if observations is None:
        ingest = _stage(
            PipelineStage.INGEST,
            LifecycleStatus.BLOCKED,
            "The observation store cannot be evaluated.",
            context=context,
            artifacts=[observations_loaded.artifact],
            blockers=[
                _artifact_failure_blocker(
                    paths, PipelineStage.INGEST, observations_loaded, ingest_action
                )
            ],
            actions=[ingest_action],
        )
    elif observations.observations:
        ingest = _stage(
            PipelineStage.INGEST,
            LifecycleStatus.COMPLETE,
            "Redacted observations are available for offline analysis.",
            context=context,
            artifacts=[observations_loaded.artifact],
            result_count=len(observations.observations),
            actions=[ingest_action],
        )
    else:
        ingest = _stage(
            PipelineStage.INGEST,
            LifecycleStatus.READY,
            "The workspace is ready to ingest reviewed captures.",
            context=context,
            artifacts=[observations_loaded.artifact],
            warnings=[
                _blocker(
                    BlockerCode.NO_OBSERVATIONS,
                    PipelineStage.INGEST,
                    "No observations have been ingested.",
                    severity="warning",
                    scope=BlockerScope(workspace=paths.root.name),
                )
            ],
            actions=[ingest_action],
        )

    inventory_action = _cli_action(
        "Rebuild classification and normalization",
        _workspace_command("hunt inventory", paths),
    )
    analysis_stages: list[StageReadiness] = []
    for stage_id in (PipelineStage.CLASSIFY, PipelineStage.NORMALIZE):
        if observations is None or not observations.observations:
            analysis_stages.append(
                _stage(
                    stage_id,
                    LifecycleStatus.BLOCKED,
                    "Runtime or documentation observations are required.",
                    context=context,
                    artifacts=[endpoint_artifact],
                    blockers=[
                        _blocker(
                            BlockerCode.NO_OBSERVATIONS,
                            stage_id,
                            "No observations are available for endpoint analysis.",
                            scope=BlockerScope(workspace=paths.root.name),
                            actions=[ingest_action],
                        )
                    ],
                )
            )
        elif endpoints is None:
            if not endpoints_loaded.artifact.exists:
                analysis_stages.append(
                    _stage(
                        stage_id,
                        LifecycleStatus.READY,
                        "Inputs are current and the derived endpoint artifact can be generated.",
                        context=context,
                        artifacts=[endpoint_artifact],
                        warnings=[
                            _blocker(
                                BlockerCode.ARTIFACT_MISSING,
                                stage_id,
                                "The derived endpoint artifact does not exist yet.",
                                severity="warning",
                                scope=BlockerScope(
                                    workspace=paths.root.name,
                                    artifact=endpoints_loaded.artifact.path,
                                ),
                            )
                        ],
                        actions=[inventory_action],
                    )
                )
            else:
                analysis_stages.append(
                    _stage(
                        stage_id,
                        LifecycleStatus.BLOCKED,
                        "The endpoint artifact is invalid.",
                        context=context,
                        artifacts=[endpoint_artifact],
                        blockers=[
                            _artifact_failure_blocker(
                                paths, stage_id, endpoints_loaded, inventory_action
                            )
                        ],
                        actions=[inventory_action],
                    )
                )
        elif (
            inventory_state is not None
            and inventory_state.status == "LEGACY_UNKNOWN"
            and not endpoints.endpoints
        ):
            analysis_stages.append(
                _stage(
                    stage_id,
                    LifecycleStatus.READY,
                    "Inputs are current and the empty legacy scaffold is not a result.",
                    context=context,
                    artifacts=[endpoint_artifact],
                    warnings=[
                        _blocker(
                            BlockerCode.ARTIFACT_PROVENANCE_MISSING,
                            stage_id,
                            "The empty legacy scaffold has no current provenance.",
                            severity="warning",
                            scope=BlockerScope(
                                workspace=paths.root.name,
                                artifact=endpoints_loaded.artifact.path,
                            ),
                        )
                    ],
                    actions=[inventory_action],
                )
            )
        elif inventory_state is not None and inventory_state.status == "CURRENT":
            analysis_stages.append(
                _stage(
                    stage_id,
                    LifecycleStatus.COMPLETE,
                    "The endpoint artifact matches current observations and configuration.",
                    context=context,
                    artifacts=[endpoint_artifact],
                    result_count=len(endpoints.endpoints),
                    actions=[inventory_action],
                )
            )
        else:
            state = inventory_state or _ProvenanceState(
                "LEGACY_UNKNOWN", BlockerCode.ARTIFACT_PROVENANCE_MISSING
            )
            analysis_stages.append(
                _stage(
                    stage_id,
                    LifecycleStatus.STALE,
                    "The endpoint artifact exists but cannot be trusted as current.",
                    context=context,
                    artifacts=[endpoint_artifact],
                    blockers=[
                        _provenance_blocker(
                            paths, stage_id, state, endpoint_artifact, inventory_action
                        )
                    ],
                    result_count=len(endpoints.endpoints),
                    actions=[inventory_action],
                )
            )
    classify, normalize = analysis_stages

    model_action = _cli_action("Refresh the domain model", _workspace_command("hunt model", paths))
    model_artifacts = [actors_loaded.artifact, resources_loaded.artifact]
    model_input: str | None = None
    model_state: _ProvenanceState | None = None
    if observations is not None and endpoints is not None:
        model_input = model_source_fingerprint(target, observations, endpoints)
        model_state = _provenance_state(
            provenance,
            malformed=provenance_malformed,
            key="model",
            input_fingerprint=model_input,
        )
        model_artifacts = [_with_provenance(item, model_state) for item in model_artifacts]
    model_integrity = (
        actors is not None
        and resources is not None
        and _generated_store_integrity(list(actors.actors), set())
        and _generated_store_integrity(list(resources.resources), set())
    )
    model_has_result = bool(
        (actors is not None and actors.actors) or (resources is not None and resources.resources)
    )
    if normalize.status != LifecycleStatus.COMPLETE:
        model_status = LifecycleStatus.STALE if model_has_result else LifecycleStatus.BLOCKED
        model_blockers = [
            _blocker(
                BlockerCode.UPSTREAM_STAGE_BLOCKED,
                PipelineStage.MODEL,
                "Current normalized endpoints are required before modeling.",
                scope=BlockerScope(workspace=paths.root.name),
                actions=[inventory_action],
            )
        ]
    elif actors is None or resources is None:
        malformed = any(item.exists and not item.valid for item in model_artifacts)
        model_status = LifecycleStatus.BLOCKED if malformed else LifecycleStatus.READY
        model_blockers = [
            _artifact_failure_blocker(paths, PipelineStage.MODEL, loaded, model_action)
            for loaded in (actors_loaded, resources_loaded)
            if loaded.value is None and loaded.artifact.exists
        ]
    elif (
        model_state is not None and model_state.status == "LEGACY_UNKNOWN" and not model_has_result
    ):
        model_status = LifecycleStatus.READY
        model_blockers = []
    elif model_state is not None and model_state.status == "CURRENT" and model_integrity:
        model_status = LifecycleStatus.COMPLETE
        model_blockers = []
    else:
        model_status = LifecycleStatus.STALE
        code = (
            BlockerCode.ARTIFACT_INTEGRITY_FAILURE
            if model_state is not None and model_state.status == "CURRENT" and not model_integrity
            else (
                model_state
                or _ProvenanceState("LEGACY_UNKNOWN", BlockerCode.ARTIFACT_PROVENANCE_MISSING)
            ).blocker_code
        )
        model_blockers = [
            _blocker(
                code or BlockerCode.UPSTREAM_DEPENDENCY_CHANGED,
                PipelineStage.MODEL,
                "The domain model is stale or has unverifiable generated content.",
                scope=BlockerScope(workspace=paths.root.name),
                actions=[model_action],
            )
        ]
    model_stage = _stage(
        PipelineStage.MODEL,
        model_status,
        {
            LifecycleStatus.COMPLETE: "The actor and resource model matches current inputs.",
            LifecycleStatus.READY: "Current endpoint inputs are ready for modeling.",
            LifecycleStatus.STALE: "The existing model requires scoped regeneration.",
        }.get(model_status, "Modeling is blocked by invalid or incomplete inputs."),
        context=context,
        artifacts=model_artifacts,
        blockers=model_blockers,
        result_count=(len(actors.actors) + len(resources.resources)) if actors and resources else 0,
        actions=[model_action],
    )

    invariant_action = _cli_action(
        "Refresh security invariants", _workspace_command("hunt invariants", paths)
    )
    invariant_artifact = invariants_loaded.artifact
    invariant_state: _ProvenanceState | None = None
    if endpoints is not None and resources is not None:
        invariant_state = _provenance_state(
            provenance,
            malformed=provenance_malformed,
            key="invariants",
            input_fingerprint=invariant_source_fingerprint(endpoints, resources),
        )
        invariant_artifact = _with_provenance(invariant_artifact, invariant_state)
    invariant_integrity = invariants is not None and _generated_store_integrity(
        list(invariants.invariants), set()
    )
    if model_stage.status != LifecycleStatus.COMPLETE:
        invariant_status = (
            LifecycleStatus.STALE
            if invariants is not None and bool(invariants.invariants)
            else LifecycleStatus.BLOCKED
        )
        invariant_blockers = [
            _blocker(
                BlockerCode.UPSTREAM_STAGE_BLOCKED,
                PipelineStage.INVARIANTS,
                "A current domain model is required before invariant generation.",
                scope=BlockerScope(workspace=paths.root.name),
                actions=[model_action],
            )
        ]
    elif invariants is None:
        invariant_status = (
            LifecycleStatus.BLOCKED if invariant_artifact.exists else LifecycleStatus.READY
        )
        invariant_blockers = (
            [
                _artifact_failure_blocker(
                    paths, PipelineStage.INVARIANTS, invariants_loaded, invariant_action
                )
            ]
            if invariant_artifact.exists
            else []
        )
    elif (
        invariant_state is not None
        and invariant_state.status == "LEGACY_UNKNOWN"
        and not invariants.invariants
    ):
        invariant_status = LifecycleStatus.READY
        invariant_blockers = []
    elif (
        invariant_state is not None and invariant_state.status == "CURRENT" and invariant_integrity
    ):
        invariant_status = LifecycleStatus.COMPLETE
        invariant_blockers = []
    else:
        invariant_status = LifecycleStatus.STALE
        invariant_blockers = [
            _blocker(
                (
                    BlockerCode.ARTIFACT_INTEGRITY_FAILURE
                    if invariant_state is not None
                    and invariant_state.status == "CURRENT"
                    and not invariant_integrity
                    else (
                        invariant_state
                        or _ProvenanceState(
                            "LEGACY_UNKNOWN", BlockerCode.ARTIFACT_PROVENANCE_MISSING
                        )
                    ).blocker_code
                    or BlockerCode.UPSTREAM_DEPENDENCY_CHANGED
                ),
                PipelineStage.INVARIANTS,
                "The invariant artifact is stale or unverifiable.",
                scope=BlockerScope(workspace=paths.root.name),
                actions=[invariant_action],
            )
        ]
    invariant_stage = _stage(
        PipelineStage.INVARIANTS,
        invariant_status,
        {
            LifecycleStatus.COMPLETE: "Current evidence-linked invariants are available.",
            LifecycleStatus.READY: "The current model is ready for invariant generation.",
            LifecycleStatus.STALE: "Existing invariants require regeneration.",
        }.get(invariant_status, "Invariant generation is blocked by upstream state."),
        context=context,
        artifacts=[invariant_artifact],
        blockers=invariant_blockers,
        result_count=(
            sum(item.disposition == "ACTIVE" for item in invariants.invariants) if invariants else 0
        ),
        actions=[invariant_action],
    )

    hypothesis_action = _cli_action(
        "Refresh hypotheses and research tasks",
        _workspace_command("hunt hypotheses", paths),
    )
    hypothesis_artifact = hypotheses_loaded.artifact
    hypothesis_state: _ProvenanceState | None = None
    if (
        observations is not None
        and endpoints is not None
        and resources is not None
        and invariants is not None
    ):
        hypothesis_state = _provenance_state(
            provenance,
            malformed=provenance_malformed,
            key="hypothesize",
            input_fingerprint=hypothesis_source_fingerprint(
                target,
                observations,
                endpoints,
                resources,
                invariants,
            ),
        )
        hypothesis_artifact = _with_provenance(hypothesis_artifact, hypothesis_state)
    hypothesis_integrity = hypotheses is not None and _generated_store_integrity(
        list(hypotheses.hypotheses), {"status", "epistemic_status", "notes"}
    )
    if invariant_stage.status != LifecycleStatus.COMPLETE:
        hypothesis_status = (
            LifecycleStatus.STALE
            if hypotheses is not None and bool(hypotheses.hypotheses)
            else LifecycleStatus.BLOCKED
        )
        hypothesis_blockers = [
            _blocker(
                BlockerCode.UPSTREAM_STAGE_BLOCKED,
                PipelineStage.HYPOTHESIZE,
                "Current model and invariant artifacts are required.",
                scope=BlockerScope(workspace=paths.root.name),
                actions=[invariant_action],
            )
        ]
    elif hypotheses is None:
        hypothesis_status = (
            LifecycleStatus.BLOCKED if hypothesis_artifact.exists else LifecycleStatus.READY
        )
        hypothesis_blockers = (
            [
                _artifact_failure_blocker(
                    paths, PipelineStage.HYPOTHESIZE, hypotheses_loaded, hypothesis_action
                )
            ]
            if hypothesis_artifact.exists
            else []
        )
    elif (
        hypothesis_state is not None
        and hypothesis_state.status == "LEGACY_UNKNOWN"
        and not hypotheses.hypotheses
    ):
        hypothesis_status = LifecycleStatus.READY
        hypothesis_blockers = []
    elif (
        hypothesis_state is not None
        and hypothesis_state.status == "CURRENT"
        and hypothesis_integrity
    ):
        hypothesis_status = LifecycleStatus.COMPLETE
        hypothesis_blockers = []
    else:
        hypothesis_status = LifecycleStatus.STALE
        hypothesis_blockers = [
            _blocker(
                (
                    BlockerCode.ARTIFACT_INTEGRITY_FAILURE
                    if hypothesis_state is not None
                    and hypothesis_state.status == "CURRENT"
                    and not hypothesis_integrity
                    else (
                        hypothesis_state
                        or _ProvenanceState(
                            "LEGACY_UNKNOWN", BlockerCode.ARTIFACT_PROVENANCE_MISSING
                        )
                    ).blocker_code
                    or BlockerCode.UPSTREAM_DEPENDENCY_CHANGED
                ),
                PipelineStage.HYPOTHESIZE,
                "The hypothesis backlog is stale or unverifiable.",
                scope=BlockerScope(workspace=paths.root.name),
                actions=[hypothesis_action],
            )
        ]
    active_hypotheses = _active_hypotheses(hypotheses)
    research_tasks = (
        sum(item.kind == "RESEARCH_TASK" for item in hypotheses.hypotheses) if hypotheses else 0
    )
    hypothesis_stage = _stage(
        PipelineStage.HYPOTHESIZE,
        hypothesis_status,
        {
            LifecycleStatus.COMPLETE: "The current backlog is evidence-gated and traceable.",
            LifecycleStatus.READY: "Current invariants are ready for hypothesis generation.",
            LifecycleStatus.STALE: "The backlog requires regeneration from current evidence.",
        }.get(hypothesis_status, "Hypothesis generation is blocked by upstream state."),
        context=context,
        artifacts=[hypothesis_artifact],
        blockers=hypothesis_blockers,
        result_count=len(active_hypotheses) + research_tasks,
        actions=[hypothesis_action],
    )

    hypothesis_by_id = {item.id: item for item in active_hypotheses}
    current_plans: list[TestPlanRecord] = []
    stale_plans: list[TestPlanRecord] = []
    if (
        plans is not None
        and observations is not None
        and endpoints is not None
        and resources is not None
    ):
        for plan_record in sorted(plans.plans, key=lambda item: (item.hypothesis_id, item.id)):
            hypothesis = hypothesis_by_id.get(plan_record.hypothesis_id)
            if hypothesis is None:
                stale_plans.append(plan_record)
            elif _plan_current(plan_record, target, observations, endpoints, resources, hypothesis):
                current_plans.append(plan_record)
            else:
                stale_plans.append(plan_record)
    plan_actions = [
        _cli_action(
            f"Generate a plan for {item.id}",
            _workspace_command(f"hunt plan {shlex.quote(item.id)}", paths),
            safety="requires_review",
        )
        for item in active_hypotheses[:3]
    ]
    plan_blockers: list[ReadinessBlocker] = []
    plan_warnings: list[ReadinessBlocker] = []
    if hypothesis_stage.status != LifecycleStatus.COMPLETE:
        plan_status = LifecycleStatus.STALE if plans and plans.plans else LifecycleStatus.BLOCKED
        plan_blockers.append(
            _blocker(
                BlockerCode.UPSTREAM_STAGE_BLOCKED,
                PipelineStage.PLAN,
                "A current eligible hypothesis is required for planning.",
                scope=BlockerScope(workspace=paths.root.name),
                actions=[hypothesis_action],
            )
        )
    elif plans is None and plans_loaded.artifact.exists:
        plan_status = LifecycleStatus.BLOCKED
        plan_blockers.append(_artifact_failure_blocker(paths, PipelineStage.PLAN, plans_loaded))
    elif current_plans:
        plan_status = LifecycleStatus.COMPLETE
        for item in stale_plans:
            plan_warnings.append(
                _blocker(
                    BlockerCode.PLAN_STALE,
                    PipelineStage.PLAN,
                    "A plan for another hypothesis is stale.",
                    severity="warning",
                    scope=BlockerScope(
                        workspace=paths.root.name,
                        hypothesis_id=item.hypothesis_id,
                        plan_id=item.id,
                    ),
                )
            )
    elif stale_plans:
        plan_status = LifecycleStatus.STALE
        for item in stale_plans:
            plan_blockers.append(
                _blocker(
                    BlockerCode.PLAN_STALE,
                    PipelineStage.PLAN,
                    "Plan inputs or generated content changed after generation.",
                    scope=BlockerScope(
                        workspace=paths.root.name,
                        hypothesis_id=item.hypothesis_id,
                        plan_id=item.id,
                    ),
                    actions=[
                        _cli_action(
                            f"Regenerate {item.hypothesis_id}",
                            _workspace_command(
                                f"hunt plan {shlex.quote(item.hypothesis_id)}", paths
                            ),
                            safety="requires_review",
                        )
                    ],
                )
            )
    elif active_hypotheses:
        plan_status = LifecycleStatus.READY
        plan_warnings.append(
            _blocker(
                BlockerCode.PLAN_MISSING,
                PipelineStage.PLAN,
                "No plan has been generated for an eligible hypothesis.",
                severity="warning",
                scope=BlockerScope(
                    workspace=paths.root.name,
                    hypothesis_id=active_hypotheses[0].id,
                ),
            )
        )
    else:
        plan_status = LifecycleStatus.BLOCKED
        code = (
            BlockerCode.HYPOTHESIS_REQUIRES_MORE_EVIDENCE
            if research_tasks
            else BlockerCode.NO_ELIGIBLE_HYPOTHESIS
        )
        plan_blockers.append(
            _blocker(
                code,
                PipelineStage.PLAN,
                "No active security hypothesis is eligible for planning.",
                scope=BlockerScope(workspace=paths.root.name),
                actions=[
                    _cli_action(
                        "Review research tasks",
                        _workspace_command("hunt hypotheses --research-tasks", paths),
                        safety="requires_review",
                    )
                ],
            )
        )
    plan_stage = _stage(
        PipelineStage.PLAN,
        plan_status,
        {
            LifecycleStatus.COMPLETE: "At least one current policy-checked plan exists.",
            LifecycleStatus.READY: "An eligible hypothesis is ready for planning.",
            LifecycleStatus.STALE: "Existing plans no longer match current inputs.",
        }.get(plan_status, "Planning is blocked by evidence or artifact prerequisites."),
        context=context,
        artifacts=[plans_loaded.artifact],
        blockers=plan_blockers,
        warnings=plan_warnings,
        result_count=len(current_plans),
        actions=plan_actions,
    )

    evidence_sets, evidence_load_blockers = _load_evidence_sets(paths)
    audits, audit_load_blockers = _load_execution_audits(paths)
    actor_by_id = {item.actor_id: item for item in actor_reports}
    executable: list[tuple[HypothesisRecord, TestPlanRecord]] = []
    execute_blockers: list[ReadinessBlocker] = list(audit_load_blockers)
    for plan in current_plans:
        hypothesis = hypothesis_by_id.get(plan.hypothesis_id)
        if hypothesis is None or endpoints is None:
            continue
        blockers = _execution_blockers(
            paths,
            target,
            hypothesis,
            plan,
            endpoints,
            actor_by_id,
        )
        if blockers:
            execute_blockers.extend(blockers)
        else:
            executable.append((hypothesis, plan))
    current_audits = [
        audit
        for audit in audits
        for _, plan in executable
        if audit.plan_id == plan.id
        and audit.plan_checksum == plan_checksum(plan)
        and audit.target_policy_checksum == target_policy_checksum(target)
    ]
    execute_actions = [
        _cli_action(
            f"Dry-run {hypothesis.id}",
            _workspace_command(f"hunt execute {shlex.quote(hypothesis.id)} --dry-run", paths),
            safety="requires_human_approval",
        )
        for hypothesis, _ in executable[:3]
    ]
    if current_audits:
        execute_status = LifecycleStatus.COMPLETE
        execute_summary = "A current immutable execution audit exists."
    elif executable:
        execute_status = LifecycleStatus.READY
        execute_summary = "An approved plan satisfies local execution prerequisites."
    elif stale_plans and not current_plans:
        execute_status = LifecycleStatus.STALE
        execute_summary = "Execution is blocked because the available plan is stale."
        execute_blockers.extend(plan_blockers)
    else:
        execute_status = LifecycleStatus.BLOCKED
        execute_summary = "No plan currently satisfies all execution safety gates."
        if not current_plans:
            execute_blockers.append(
                _blocker(
                    BlockerCode.PLAN_MISSING,
                    PipelineStage.EXECUTE,
                    "A current plan is required before execution.",
                    scope=BlockerScope(workspace=paths.root.name),
                    actions=plan_actions[:1],
                )
            )
    execute_stage = _stage(
        PipelineStage.EXECUTE,
        execute_status,
        execute_summary,
        context=context,
        blockers=execute_blockers,
        result_count=len(current_audits),
        actions=execute_actions,
    )

    plan_by_hypothesis = {item.hypothesis_id: item for item in current_plans}
    validation_by_hypothesis = (
        {item.hypothesis_id: item for item in validations.validations} if validations else {}
    )
    current_validations: list[ValidationRecord] = []
    stale_validations: list[ValidationRecord] = []
    validation_blockers: list[ReadinessBlocker] = list(evidence_load_blockers)
    validation_actions: list[NextAction] = []
    validation_candidates = 0
    if validations is None and validations_loaded.artifact.exists:
        validation_blockers.append(
            _artifact_failure_blocker(paths, PipelineStage.VALIDATE, validations_loaded)
        )
    if endpoints is not None:
        for hypothesis in active_hypotheses:
            evidence = evidence_sets.get(hypothesis.id)
            validation_plan = plan_by_hypothesis.get(hypothesis.id)
            existing = validation_by_hypothesis.get(hypothesis.id)
            if evidence is not None and existing is not None:
                if _validation_current(
                    existing,
                    target,
                    endpoints,
                    hypothesis,
                    validation_plan,
                    evidence,
                ):
                    current_validations.append(existing)
                else:
                    stale_validations.append(existing)
            if evidence is None:
                continue
            if _state_evidence_missing(hypothesis, endpoints, evidence):
                validation_blockers.append(
                    _blocker(
                        BlockerCode.BEFORE_AFTER_STATE_EVIDENCE_MISSING,
                        PipelineStage.VALIDATE,
                        "A state-changing hypothesis lacks authoritative before/after evidence.",
                        scope=BlockerScope(
                            workspace=paths.root.name,
                            hypothesis_id=hypothesis.id,
                            evidence_set_id=hypothesis.id,
                        ),
                    )
                )
                continue
            if validation_plan is None or validation_plan.approval_status != "APPROVED":
                validation_blockers.append(
                    _blocker(
                        BlockerCode.HUMAN_APPROVAL_MISSING,
                        PipelineStage.VALIDATE,
                        "Validation requires a review-ready, explicitly approved plan.",
                        scope=BlockerScope(
                            workspace=paths.root.name,
                            hypothesis_id=hypothesis.id,
                        ),
                    )
                )
                continue
            validation_candidates += 1
            validation_actions.append(
                _cli_action(
                    f"Validate {hypothesis.id}",
                    _workspace_command(f"hunt validate {shlex.quote(hypothesis.id)}", paths),
                    safety="requires_review",
                )
            )
    incomplete_current = [
        item for item in current_validations if item.disposition == "NEEDS_MORE_EVIDENCE"
    ]
    decisive_current = [
        item for item in current_validations if item.disposition != "NEEDS_MORE_EVIDENCE"
    ]
    if decisive_current:
        validate_status = LifecycleStatus.COMPLETE
        validate_summary = "A current skeptical validation reached a decisive disposition."
    elif incomplete_current:
        validate_status = LifecycleStatus.BLOCKED
        validate_summary = "Current validation results require more evidence."
        for validation_record in incomplete_current:
            code = (
                BlockerCode.BEFORE_AFTER_STATE_EVIDENCE_MISSING
                if any(
                    "before" in value.lower() or "after" in value.lower()
                    for value in validation_record.missing_requirements
                )
                else BlockerCode.EVIDENCE_MISSING
            )
            validation_blockers.append(
                _blocker(
                    code,
                    PipelineStage.VALIDATE,
                    "The current validation result has unmet evidence requirements.",
                    scope=BlockerScope(
                        workspace=paths.root.name,
                        hypothesis_id=validation_record.hypothesis_id,
                        evidence_set_id=validation_record.hypothesis_id,
                    ),
                )
            )
    elif stale_validations:
        validate_status = LifecycleStatus.STALE
        validate_summary = "Existing validation results do not match current evidence."
        for validation_record in stale_validations:
            validation_blockers.append(
                _blocker(
                    BlockerCode.UPSTREAM_DEPENDENCY_CHANGED,
                    PipelineStage.VALIDATE,
                    "Validation inputs changed after the result was generated.",
                    scope=BlockerScope(
                        workspace=paths.root.name,
                        hypothesis_id=validation_record.hypothesis_id,
                    ),
                    actions=[
                        _cli_action(
                            f"Revalidate {validation_record.hypothesis_id}",
                            _workspace_command(
                                f"hunt validate {shlex.quote(validation_record.hypothesis_id)}",
                                paths,
                            ),
                            safety="requires_review",
                        )
                    ],
                )
            )
    elif validation_candidates:
        validate_status = LifecycleStatus.READY
        validate_summary = "Approved evidence packages are ready for skeptical validation."
    else:
        validate_status = LifecycleStatus.BLOCKED
        validate_summary = "No evidence package currently satisfies validation prerequisites."
        if not evidence_sets:
            validation_blockers.append(
                _blocker(
                    BlockerCode.EVIDENCE_MISSING,
                    PipelineStage.VALIDATE,
                    "No indexed evidence set is available for an active hypothesis.",
                    scope=BlockerScope(workspace=paths.root.name),
                )
            )
    validate_stage = _stage(
        PipelineStage.VALIDATE,
        validate_status,
        validate_summary,
        context=context,
        artifacts=[validations_loaded.artifact],
        blockers=validation_blockers,
        result_count=len(current_validations),
        actions=validation_actions,
    )

    report_files = (
        sorted(path for path in paths.reports.glob("HYP-*-report-v*.md") if path.is_file())
        if paths.reports.is_dir()
        else []
    )
    report_blockers: list[ReadinessBlocker] = []
    report_actions: list[NextAction] = []
    current_reports = 0
    stale_reports = 0
    validation_lookup = {item.hypothesis_id: item for item in current_validations}
    hypothesis_lookup = {item.id: item for item in active_hypotheses}
    for hypothesis_id, validation in sorted(validation_lookup.items()):
        if validation.disposition != "CONFIRMED" or not validation.report_ready:
            continue
        hypothesis = hypothesis_lookup.get(hypothesis_id)
        evidence = evidence_sets.get(hypothesis_id)
        if hypothesis is None or evidence is None or invariants is None:
            continue
        matching = [
            path for path in report_files if path.name.startswith(f"{hypothesis_id}-report-v")
        ]
        entry = (
            next(
                (item for item in provenance.entries if item.key == f"report:{hypothesis_id}"),
                None,
            )
            if provenance is not None
            else None
        )
        source = report_source_fingerprint(hypothesis, evidence, invariants, validation)
        current = bool(
            matching
            and entry is not None
            and entry.input_fingerprint == source
            and entry.output_fingerprint
            == output_fingerprint(matching[-1].read_text(encoding="utf-8"))
        )
        if current:
            current_reports += 1
        elif matching:
            stale_reports += 1
            report_blockers.append(
                _blocker(
                    (
                        BlockerCode.ARTIFACT_PROVENANCE_MISSING
                        if entry is None
                        else BlockerCode.UPSTREAM_DEPENDENCY_CHANGED
                    ),
                    PipelineStage.REPORT,
                    "An existing report cannot be trusted as current.",
                    scope=BlockerScope(
                        workspace=paths.root.name,
                        hypothesis_id=hypothesis_id,
                        artifact=matching[-1].name,
                    ),
                    actions=[
                        _cli_action(
                            f"Generate a current report for {hypothesis_id}",
                            _workspace_command(f"hunt report {shlex.quote(hypothesis_id)}", paths),
                            safety="requires_review",
                        )
                    ],
                )
            )
        else:
            report_actions.append(
                _cli_action(
                    f"Generate a report for {hypothesis_id}",
                    _workspace_command(f"hunt report {shlex.quote(hypothesis_id)}", paths),
                    safety="requires_review",
                )
            )
    if report_files and not current_reports and not stale_reports:
        stale_reports = len(report_files)
        report_blockers.append(
            _blocker(
                BlockerCode.ARTIFACT_PROVENANCE_MISSING,
                PipelineStage.REPORT,
                "Existing report files are not bound to a current confirmed validation.",
                scope=BlockerScope(workspace=paths.root.name, artifact="reports"),
            )
        )
    if current_reports:
        report_status = LifecycleStatus.COMPLETE
        report_summary = "A current report is bound to confirmed, report-ready validation."
    elif stale_reports:
        report_status = LifecycleStatus.STALE
        report_summary = "Existing reports are stale or have unverifiable legacy provenance."
    elif report_actions:
        report_status = LifecycleStatus.READY
        report_summary = "A confirmed, report-ready validation can be rendered."
    else:
        report_status = LifecycleStatus.BLOCKED
        report_summary = "No confirmed vulnerability is currently available for reporting."
        report_blockers.append(
            _blocker(
                BlockerCode.NO_CONFIRMED_VULNERABILITY,
                PipelineStage.REPORT,
                "HTTP success or execution alone is not a confirmed vulnerability.",
                scope=BlockerScope(workspace=paths.root.name),
                details=(
                    "Reporting requires current skeptical validation with CONFIRMED disposition."
                ),
            )
        )
    report_stage = _stage(
        PipelineStage.REPORT,
        report_status,
        report_summary,
        context=context,
        artifacts=[
            ArtifactReadiness(
                name="Reports",
                path="reports",
                exists=bool(report_files),
                valid=True,
                stale=bool(stale_reports),
                provenance=(
                    "CURRENT" if current_reports else "STALE" if stale_reports else "MISSING"
                ),
            )
        ],
        blockers=report_blockers,
        result_count=current_reports,
        actions=report_actions,
    )

    stages = [
        setup,
        auth,
        ingest,
        classify,
        normalize,
        model_stage,
        invariant_stage,
        hypothesis_stage,
        plan_stage,
        execute_stage,
        validate_stage,
        report_stage,
    ]
    if setup.status == LifecycleStatus.NOT_CONFIGURED:
        overall_status = LifecycleStatus.NOT_CONFIGURED
    elif any(item.status == LifecycleStatus.STALE for item in stages):
        overall_status = LifecycleStatus.STALE
    elif any(item.status == LifecycleStatus.BLOCKED for item in stages):
        overall_status = LifecycleStatus.BLOCKED
    elif any(item.status == LifecycleStatus.READY for item in stages):
        overall_status = LifecycleStatus.READY
    else:
        overall_status = LifecycleStatus.COMPLETE

    actionable_candidates = [
        (action, index, stage.id)
        for index, stage in enumerate(stages)
        for action in stage.next_actions
        if stage.status in {LifecycleStatus.READY, LifecycleStatus.STALE}
    ]
    blocked_candidates = [
        (action, index, stage.id)
        for index, stage in enumerate(stages)
        for action in stage.next_actions
        if stage.status == LifecycleStatus.BLOCKED
    ]
    safety_rank = {
        "safe_to_automate": 0,
        "requires_review": 1,
        "requires_human_approval": 2,
    }
    action_candidates = actionable_candidates or blocked_candidates
    action_candidates.sort(key=lambda item: (safety_rank[item[0].safety], item[1]))
    next_actions = _deduplicate_actions([item[0] for item in action_candidates])[:5]
    next_stage = action_candidates[0][2] if action_candidates else None

    metrics = ReadinessMetrics(
        observations=len(observations.observations) if observations else 0,
        endpoints=len(endpoints.endpoints) if endpoints else 0,
        suppressed_endpoints=(
            sum(item.disposition != "ACTIVE" for item in endpoints.endpoints) if endpoints else 0
        ),
        graphql_operations=_safe_yaml_list_count(paths.graphql, "operations"),
        mobile_discoveries=_safe_yaml_list_count(paths.mobile_discoveries, "discoveries"),
        actors=len(actors.actors) if actors else 0,
        resources=(
            sum(item.disposition == "ACTIVE" for item in resources.resources) if resources else 0
        ),
        workflows=_safe_workflow_count(paths.root / "model" / "workflows.md"),
        workflow_instances=_safe_yaml_list_count(paths.workflow_instances, "workflow_instances"),
        workflow_families=_safe_yaml_list_count(paths.workflow_families, "workflow_families"),
        inferred_states=_safe_yaml_list_count(paths.behavior_states, "states"),
        observed_transitions=_safe_yaml_list_count(paths.behavior_transitions, "transitions"),
        invariants=(
            sum(item.disposition == "ACTIVE" for item in invariants.invariants) if invariants else 0
        ),
        business_invariants=_safe_yaml_list_count(paths.business_invariants, "business_invariants"),
        active_hypotheses=len(active_hypotheses),
        research_tasks=research_tasks,
        logic_hypotheses=_safe_yaml_list_count(paths.business_logic_hypotheses, "hypotheses"),
        logic_research_tasks=sum(
            item.kind == "RESEARCH_TASK"
            for item in hypotheses.hypotheses
            if item.category == "business_logic"
        )
        if hypotheses
        else 0,
        plans=len(plans.plans) if plans else 0,
        executions=len(audits),
        evidence_sets=len(evidence_sets),
        validations=len(validations.validations) if validations else 0,
        reports=len(report_files),
        hypotheses_not_tested=sum(item.status == "NOT_TESTED" for item in active_hypotheses),
        hypotheses_test_planned=sum(item.status == "TEST_PLANNED" for item in active_hypotheses),
        hypotheses_refuted=sum(item.status == "REFUTED" for item in active_hypotheses),
        hypotheses_needs_evidence=sum(
            item.status == "NEEDS_EVIDENCE" for item in active_hypotheses
        ),
        hypotheses_confirmed=sum(item.status == "CONFIRMED" for item in active_hypotheses),
    )
    return ReadinessReport(
        workspace=target.target.slug or paths.root.name,
        overall=OverallReadiness(status=overall_status, next_stage=next_stage),
        stages=stages,
        actors=actor_reports,
        metrics=metrics,
        next_actions=next_actions,
    )
