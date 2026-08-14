"""Safe automated ingestion and offline analysis workflow."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from finsec.behavior.analysis import analyze_business_logic
from finsec.captures.domain import (
    CaptureAssignment,
    CaptureConfidence,
    CaptureIntent,
    CaptureMode,
    CaptureSourceType,
    MetadataSource,
)
from finsec.config.models import TargetDocument
from finsec.config.workspace import WorkspacePaths
from finsec.errors import FinsecError
from finsec.hypotheses.domain import HypothesisStore
from finsec.hypotheses.generator import generate_hypotheses
from finsec.hypotheses.population import hypothesis_population
from finsec.ingest.common import PassiveIngestResult
from finsec.ingest.har import IngestResult, ingest_har
from finsec.ingest.traffic import ingest_burp_xml
from finsec.modeling.domain import ActorStore, ResourceStore
from finsec.modeling.generator import generate_model
from finsec.modeling.invariants import generate_invariants
from finsec.modeling.models import ChannelType, EndpointStore, ObservationStore
from finsec.normalization.inventory import build_inventory
from finsec.utils.yaml_store import load_yaml, write_yaml

ManifestChannel = Literal[
    "WEB",
    "MOBILE",
    "API",
    "PARTNER_API",
    "PUBLIC_API",
    "UNKNOWN",
]
ProgressCallback = Callable[[str], None]


class StrictModel(BaseModel):
    """Keep workflow manifests deterministic and typo-resistant."""

    model_config = ConfigDict(extra="forbid")


class WorkflowCapture(StrictModel):
    """One explicitly assigned passive capture in the incoming directory."""

    file: str
    actor: str
    channel: ManifestChannel = "UNKNOWN"
    enabled: bool = True
    actor_source: MetadataSource | None = None
    capture_mode: CaptureMode | None = None
    capture_mode_source: MetadataSource | None = None
    intent: CaptureIntent | None = None

    @field_validator("file")
    @classmethod
    def file_is_a_safe_capture_name(cls, value: str) -> str:
        normalized = value.strip()
        path = Path(normalized)
        if (
            not normalized
            or path.name != normalized
            or path.suffix.lower() not in {".har", ".xml"}
            or normalized in {".", ".."}
        ):
            raise ValueError("file must be a .har or Burp .xml filename without directories")
        return normalized

    @field_validator("actor")
    @classmethod
    def actor_is_not_empty(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("actor cannot be empty")
        return normalized

    @property
    def source_type(self) -> CaptureSourceType:
        """Infer the source adapter from the validated filename."""

        return (
            CaptureSourceType.HAR
            if Path(self.file).suffix.lower() == ".har"
            else CaptureSourceType.BURP_XML
        )

    def assignment(self) -> CaptureAssignment:
        """Return persisted context without inventing missing metadata."""

        intent = self.intent
        if intent is not None and intent.source == MetadataSource.UNKNOWN:
            intent = intent.model_copy(
                update={
                    "source": MetadataSource.USER_SUPPLIED,
                    "confidence": CaptureConfidence.HIGH,
                }
            )
        return CaptureAssignment(
            actor_source=self.actor_source or MetadataSource.USER_SUPPLIED,
            actor_evidence=["Actor label was supplied by the workflow manifest."],
            capture_mode=self.capture_mode or CaptureMode.UNKNOWN,
            capture_mode_source=(
                self.capture_mode_source
                or (
                    MetadataSource.USER_SUPPLIED
                    if self.capture_mode is not None
                    else MetadataSource.UNKNOWN
                )
            ),
            intent=intent,
        )


class WorkflowManifest(StrictModel):
    """Versioned capture assignments consumed by ``hunt workflow``."""

    version: Literal[1] = 1
    captures: list[WorkflowCapture] = Field(default_factory=list)


@dataclass(frozen=True)
class WorkflowIngestResult:
    """Outcome for one manifest entry."""

    file: str
    actor: str
    channel: ChannelType
    imported: int
    skipped: int
    relabeled: int
    capture_id: str | None = None
    source_type: CaptureSourceType = CaptureSourceType.HAR


@dataclass(frozen=True)
class WorkflowResult:
    """Final counts from a completed safe offline workflow."""

    observations: int
    endpoints: int
    suppressed_endpoints: int
    actors: int
    resources: int
    workflows: int
    workflow_instances: int
    workflow_families: int
    states: int
    transitions: int
    invariants: int
    business_invariants: int
    active_hypotheses: int
    research_tasks: int
    raw_active_hypotheses: int
    raw_research_tasks: int
    logic_hypotheses: int
    logic_research_tasks: int
    hypotheses_generated: bool
    ingested: tuple[WorkflowIngestResult, ...]
    conflicts: tuple[str, ...]


def _notify(progress: ProgressCallback | None, message: str) -> None:
    if progress is not None:
        progress(message)


def _manifest_channel(channel: ManifestChannel) -> ChannelType:
    if channel == "API":
        return "PUBLIC_API"
    return channel


def load_workflow_manifest(path: Path) -> WorkflowManifest:
    """Load and validate an explicit capture-to-actor manifest."""

    try:
        document = load_yaml(path)
        return WorkflowManifest.model_validate(document)
    except (OSError, ValidationError) as error:
        raise FinsecError(f"Cannot load workflow manifest {path}: {error}") from error


def ensure_workflow_manifest(path: Path) -> None:
    """Create an empty, non-sensitive manifest without overwriting researcher edits."""

    if path.exists():
        return
    content = (
        "version: 1\n"
        "captures: []\n"
        "\n"
        "# Add one explicit assignment per file in incoming/. Example:\n"
        "# captures:\n"
        "#   - file: 01-account-a-login.har\n"
        "#     actor: ACCOUNT_A\n"
        "#     channel: WEB\n"
        "#     capture_mode: AUTHENTICATION\n"
        "#     intent:\n"
        "#       action: AUTHENTICATE\n"
        "#       resource_type: session\n"
    )
    path.write_text(content, encoding="utf-8", newline="\n")


def merge_workflow_assignments(path: Path, captures: list[WorkflowCapture]) -> None:
    """Merge confirmed assignments by filename and preserve unrelated entries."""

    manifest = load_workflow_manifest(path) if path.is_file() else WorkflowManifest()
    by_file = {capture.file: capture for capture in manifest.captures}
    for capture in captures:
        by_file[capture.file] = capture
    merged = WorkflowManifest(captures=[by_file[name] for name in sorted(by_file)])
    write_yaml(path, merged.model_dump(mode="json", exclude_none=True))


def _load_target(workspace: WorkspacePaths) -> TargetDocument:
    try:
        return TargetDocument.model_validate(load_yaml(workspace.target))
    except (OSError, ValidationError) as error:
        raise FinsecError(f"Cannot load workflow target configuration: {error}") from error


def _validate_manifest_actors(
    manifest: WorkflowManifest, target: TargetDocument
) -> list[WorkflowCapture]:
    enabled = [capture for capture in manifest.captures if capture.enabled]
    names = [capture.file for capture in enabled]
    if len(names) != len(set(names)):
        raise FinsecError("Workflow manifest contains duplicate HAR filenames.")
    allowed = {account.id for account in target.accounts} | {"ANONYMOUS", "UNKNOWN"}
    invalid = sorted({capture.actor for capture in enabled if capture.actor not in allowed})
    if invalid:
        raise FinsecError(
            "Workflow manifest uses unconfigured actors: "
            + ", ".join(invalid)
            + ". Use a target account label, ANONYMOUS, or UNKNOWN."
        )
    return enabled


def _ingest_manifest(
    workspace: WorkspacePaths,
    manifest_path: Path,
    progress: ProgressCallback | None,
) -> tuple[WorkflowIngestResult, ...]:
    manifest = load_workflow_manifest(manifest_path)
    captures = _validate_manifest_actors(manifest, _load_target(workspace))
    incoming = manifest_path.parent / "incoming"
    results: list[WorkflowIngestResult] = []
    failures: list[str] = []
    for capture in captures:
        source = incoming / capture.file
        _notify(
            progress,
            f"Ingesting {capture.file} as {capture.actor} "
            f"({capture.channel}, {capture.source_type.value})",
        )
        try:
            result: IngestResult | PassiveIngestResult
            if capture.source_type == CaptureSourceType.HAR:
                result = ingest_har(
                    source,
                    workspace,
                    actor=capture.actor,
                    channel=_manifest_channel(capture.channel),
                    capture_assignment=capture.assignment(),
                )
            else:
                result = ingest_burp_xml(
                    source,
                    workspace,
                    actor=capture.actor,
                    channel=_manifest_channel(capture.channel),
                    capture_assignment=capture.assignment(),
                )
        except (FinsecError, OSError, ValidationError) as error:
            failures.append(f"{capture.file}: {error}")
            _notify(progress, f"Failed {capture.file}: {error}")
            continue
        results.append(
            WorkflowIngestResult(
                file=capture.file,
                actor=capture.actor,
                channel=_manifest_channel(capture.channel),
                imported=result.imported,
                skipped=result.skipped,
                relabeled=result.relabeled,
                capture_id=result.capture.capture_id if result.capture is not None else None,
                source_type=capture.source_type,
            )
        )
    if failures:
        raise FinsecError(
            "Workflow stopped before analysis because HAR ingestion failed:\n- "
            + "\n- ".join(failures)
        )
    return tuple(results)


def run_offline_workflow(
    workspace: WorkspacePaths,
    *,
    manifest_path: Path | None = None,
    progress: ProgressCallback | None = None,
) -> WorkflowResult:
    """Run passive ingestion and every deterministic offline analysis stage."""

    ingested: tuple[WorkflowIngestResult, ...] = ()
    if manifest_path is not None:
        _notify(progress, f"Loading workflow manifest {manifest_path}")
        ingested = _ingest_manifest(workspace, manifest_path, progress)

    try:
        observations = ObservationStore.model_validate(load_yaml(workspace.observations))
    except (OSError, ValidationError) as error:
        raise FinsecError(f"Cannot load workflow observations: {error}") from error
    if not observations.observations:
        raise FinsecError(
            "No observations are available. Add explicit assignments to the capture workflow "
            "manifest or run 'hunt ingest' first."
        )

    _notify(progress, "Classifying observations and building endpoint inventory")
    inventory = build_inventory(workspace)
    endpoints = EndpointStore.model_validate(load_yaml(workspace.endpoints))

    _notify(progress, "Building actors, resources, authorization views, and workflows")
    model = generate_model(workspace)
    actors = ActorStore.model_validate(load_yaml(workspace.actors))
    resources = ResourceStore.model_validate(load_yaml(workspace.resources))

    invariant_count = 0
    invariant_conflicts: tuple[str, ...] = ()
    if resources.resources:
        _notify(progress, "Generating implementation-supported invariants")
        invariant_result = generate_invariants(workspace)
        invariant_count = invariant_result.invariants
        invariant_conflicts = invariant_result.conflicts
    else:
        _notify(progress, "No resources were modeled; invariant generation was skipped")

    hypotheses_generated = invariant_count > 0
    hypothesis_conflicts: tuple[str, ...] = ()
    if hypotheses_generated:
        _notify(progress, "Generating evidence-backed hypotheses and research tasks")
        hypothesis_result = generate_hypotheses(workspace)
        hypothesis_conflicts = hypothesis_result.conflicts
    else:
        _notify(progress, "No invariants were generated; hypothesis generation was skipped")
    _notify(progress, "Reconstructing application behavior and business-logic hypotheses")
    logic_result = analyze_business_logic(workspace)
    hypotheses = HypothesisStore.model_validate(load_yaml(workspace.hypotheses))
    behavior_instances = load_yaml(workspace.workflow_instances) or {}
    behavior_families = load_yaml(workspace.workflow_families) or {}
    behavior_states = load_yaml(workspace.behavior_states) or {}
    behavior_transitions = load_yaml(workspace.behavior_transitions) or {}

    population = hypothesis_population(hypotheses.hypotheses)
    active_hypotheses = len(population.visible_active_hypotheses)
    research_tasks = len(population.visible_research_tasks)
    conflicts = tuple(
        dict.fromkeys(
            [
                *model.conflicts,
                *invariant_conflicts,
                *hypothesis_conflicts,
                *logic_result.conflicts,
            ]
        )
    )
    return WorkflowResult(
        observations=len(observations.observations),
        endpoints=inventory.endpoints,
        suppressed_endpoints=sum(item.disposition != "ACTIVE" for item in endpoints.endpoints),
        actors=len(actors.actors),
        resources=len(resources.resources),
        workflows=model.workflows,
        workflow_instances=len(behavior_instances.get("workflow_instances", [])),
        workflow_families=len(behavior_families.get("workflow_families", [])),
        states=len(behavior_states.get("states", [])),
        transitions=len(behavior_transitions.get("transitions", [])),
        invariants=invariant_count,
        business_invariants=logic_result.business_invariants,
        active_hypotheses=active_hypotheses,
        research_tasks=research_tasks,
        raw_active_hypotheses=population.raw_active_hypotheses,
        raw_research_tasks=population.raw_research_tasks,
        logic_hypotheses=logic_result.hypotheses,
        logic_research_tasks=logic_result.research_tasks,
        hypotheses_generated=hypotheses_generated,
        ingested=ingested,
        conflicts=conflicts,
    )
