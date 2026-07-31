"""Safety-bounded setup, passive-ingestion, and workspace-retirement Web UI operations."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal, cast

from pydantic import BaseModel, ConfigDict, Field

from finsec.auth.store import SecretStore
from finsec.config.models import TargetDocument
from finsec.config.workspace import (
    CaptureDeletionTarget,
    WorkspaceDeletionTarget,
    WorkspacePaths,
    delete_capture_directory,
    resolve_capture_deletion_target,
    resolve_workspace_deletion_target,
    validate_target_name,
)
from finsec.config.workspace import (
    delete_workspace as remove_workspace_directory,
)
from finsec.errors import FinsecError, HarFormatError, WorkspaceError
from finsec.ingest.har import ingest_har
from finsec.modeling.models import ChannelType
from finsec.setup import AccountInput, build_setup_config, create_setup_workspace
from finsec.utils.yaml_store import load_yaml
from finsec.workflow import (
    ManifestChannel,
    WorkflowCapture,
    WorkflowIngestResult,
    WorkflowManifest,
    ensure_workflow_manifest,
    load_workflow_manifest,
    merge_workflow_assignments,
    run_offline_workflow,
)

MAX_HAR_UPLOAD_BYTES = 50 * 1024 * 1024


class StrictRequest(BaseModel):
    """Reject unexpected browser fields so write operations remain explicit."""

    model_config = ConfigDict(extra="forbid")


class SetupAccountRequest(StrictRequest):
    """Non-secret controlled actor metadata submitted by the setup form."""

    label: str = Field(min_length=1, max_length=64)
    role: str = Field(default="user", min_length=1, max_length=100)
    authenticated: bool = True
    verification_level: str = Field(default="unknown", min_length=1, max_length=100)
    channel: Literal["web", "mobile", "api", "unknown"] = "web"


class SetupWorkspaceRequest(StrictRequest):
    """Complete default-deny workspace setup submitted by the Web UI."""

    project_name: str = Field(min_length=1, max_length=100)
    slug: str = Field(min_length=1, max_length=64)
    hosts: list[str] = Field(min_length=1, max_length=100)
    accounts: list[SetupAccountRequest] = Field(min_length=1, max_length=25)
    production: bool = True
    base_url: str | None = Field(default=None, max_length=2048)


class IngestAssignmentRequest(StrictRequest):
    """One explicit browser-confirmed capture provenance assignment."""

    file: str
    actor: str | None = None
    channel: ManifestChannel | None = None
    enabled: bool = True


class IngestRunRequest(StrictRequest):
    """Passive ingest action with an explicit reviewed-file attestation."""

    assignments: list[IngestAssignmentRequest] = Field(min_length=1, max_length=250)
    run_analysis: bool = True
    reviewed: bool


class WorkspaceDeleteRequest(StrictRequest):
    """Exact destructive action confirmed in the browser Danger Zone."""

    mode: Literal["delete", "purge"]
    confirmation: str = Field(min_length=1, max_length=80)
    acknowledged: Literal[True]


class WebOperations:
    """Perform explicitly bounded local writes without enabling target execution."""

    def __init__(self, workspace_root: Path, capture_root: Path | None = None) -> None:
        self.workspace_root = workspace_root.expanduser().resolve()
        self.capture_root = (
            capture_root.expanduser().resolve()
            if capture_root is not None
            else self.workspace_root.parent / "captures"
        )

    def setup_workspace(self, request: SetupWorkspaceRequest) -> dict[str, Any]:
        """Create one validated default-deny workspace without collecting credentials."""

        accounts = [
            AccountInput(
                label=item.label,
                role=item.role,
                authenticated=item.authenticated,
                verification_level=item.verification_level,
                channel=item.channel,
            )
            for item in request.accounts
        ]
        config = build_setup_config(
            project_name=request.project_name,
            slug=request.slug,
            hosts=request.hosts,
            accounts=accounts,
            production=request.production,
            base_url=request.base_url,
        )
        result = create_setup_workspace(config, self.workspace_root, self.capture_root)
        return {
            "workspace": {
                "key": result.workspace.root.name,
                "name": config.target.target.name,
                "path": str(result.workspace.root),
            },
            "capture": {
                "path": str(result.capture_root),
                "incoming": str(result.capture_root / "incoming"),
            },
            "safety": {
                "active_execution_enabled": False,
                "human_approval_required": True,
                "destructive_testing": False,
                "read_only_only": True,
            },
        }

    def ingest_state(self, paths: WorkspacePaths) -> dict[str, Any]:
        """List sanitized capture metadata and current explicit provenance assignments."""

        target = self._target(paths)
        capture = self._capture_directory(paths, target)
        incoming = capture / "incoming"
        manifest_path = capture / "workflow.yaml"
        manifest = (
            load_workflow_manifest(manifest_path) if manifest_path.is_file() else WorkflowManifest()
        )
        assignments = {item.file: item for item in manifest.captures}
        files: list[dict[str, Any]] = []
        if incoming.is_dir():
            for path in sorted(incoming.iterdir()):
                if not path.is_file() or path.is_symlink() or path.suffix.lower() != ".har":
                    continue
                assignment = assignments.get(path.name)
                stat = path.stat()
                files.append(
                    {
                        "file": path.name,
                        "size": stat.st_size,
                        "updated_at": datetime.fromtimestamp(stat.st_mtime, tz=UTC).isoformat(),
                        "actor": assignment.actor if assignment is not None else None,
                        "channel": assignment.channel if assignment is not None else None,
                        "enabled": assignment.enabled if assignment is not None else True,
                        "assigned": assignment is not None,
                    }
                )
        present = {item["file"] for item in files}
        missing = [item.file for item in manifest.captures if item.file not in present]
        return {
            "workspace": {
                "key": paths.root.name,
                "name": target.target.name,
            },
            "capture": {
                "path": str(capture),
                "incoming": str(incoming),
                "available": incoming.is_dir() and manifest_path.is_file(),
                "maximum_upload_bytes": MAX_HAR_UPLOAD_BYTES,
            },
            "actors": [
                {
                    "id": account.id,
                    "role": account.role,
                    "authenticated": account.authenticated,
                    "default_channel": {
                        "web": "WEB",
                        "mobile": "MOBILE",
                        "api": "PUBLIC_API",
                        "unknown": "UNKNOWN",
                    }[account.attributes.channel],
                }
                for account in target.accounts
            ],
            "special_actors": ["ANONYMOUS", "UNKNOWN"],
            "channels": ["WEB", "MOBILE", "PARTNER_API", "PUBLIC_API", "UNKNOWN"],
            "files": files,
            "missing_manifest_files": missing,
        }

    def initialize_capture(self, paths: WorkspacePaths) -> dict[str, Any]:
        """Create the external capture input layout for an existing workspace."""

        target = self._target(paths)
        capture = self._capture_directory(paths, target)
        incoming = capture / "incoming"
        incoming.mkdir(parents=True, exist_ok=True)
        ensure_workflow_manifest(capture / "workflow.yaml")
        return self.ingest_state(paths)

    def store_har(self, paths: WorkspacePaths, filename: str, content: bytes) -> dict[str, Any]:
        """Store one reviewed HAR outside the workspace without overwriting an existing file."""

        if len(content) > MAX_HAR_UPLOAD_BYTES:
            raise HarFormatError("HAR upload exceeds the 50 MiB local safety limit.")
        WorkflowCapture(file=filename, actor="UNKNOWN", channel="UNKNOWN")
        self._validate_har_content(content)
        state = self.initialize_capture(paths)
        incoming = Path(cast(str, state["capture"]["incoming"]))
        destination = incoming / filename
        try:
            with destination.open("xb") as handle:
                handle.write(content)
        except FileExistsError as error:
            raise FinsecError(
                f"Capture already exists and was not overwritten: {filename}"
            ) from error
        return {
            "file": filename,
            "size": len(content),
            "incoming": str(incoming),
            "stored": True,
        }

    def run_ingest(self, paths: WorkspacePaths, request: IngestRunRequest) -> dict[str, Any]:
        """Persist explicit provenance and run ingestion, optionally through passive analysis."""

        if not request.reviewed:
            raise FinsecError(
                "Confirm that every selected HAR is authorized, sanitized, and assigned accurately."
            )
        captures: list[WorkflowCapture] = []
        for item in request.assignments:
            if item.enabled and (not item.actor or item.channel is None):
                raise FinsecError(f"Enabled HAR requires actor and channel: {item.file}")
            captures.append(
                WorkflowCapture(
                    file=item.file,
                    actor=item.actor or "UNKNOWN",
                    channel=item.channel or "UNKNOWN",
                    enabled=item.enabled,
                )
            )
        names = [item.file for item in captures]
        if len(names) != len(set(names)):
            raise FinsecError("Each HAR filename may be assigned only once.")
        enabled = [item for item in captures if item.enabled]
        if not enabled:
            raise FinsecError("Select at least one enabled HAR file for passive ingestion.")

        target = self._target(paths)
        allowed_actors = {item.id for item in target.accounts} | {"ANONYMOUS", "UNKNOWN"}
        invalid_actors = sorted(
            {item.actor for item in enabled if item.actor not in allowed_actors}
        )
        if invalid_actors:
            raise FinsecError("Unconfigured capture actors: " + ", ".join(invalid_actors))

        capture = self._capture_directory(paths, target)
        manifest_path = capture / "workflow.yaml"
        incoming = capture / "incoming"
        self._validate_capture_files(incoming, enabled)
        ensure_workflow_manifest(manifest_path)
        merge_workflow_assignments(manifest_path, captures)

        progress: list[str] = []
        if request.run_analysis:
            result = run_offline_workflow(
                paths,
                manifest_path=manifest_path,
                progress=progress.append,
            )
            ingested = list(result.ingested)
            analysis: dict[str, Any] | None = {
                "observations": result.observations,
                "endpoints": result.endpoints,
                "suppressed_endpoints": result.suppressed_endpoints,
                "actors": result.actors,
                "resources": result.resources,
                "workflows": result.workflows,
                "invariants": result.invariants,
                "active_hypotheses": result.active_hypotheses,
                "research_tasks": result.research_tasks,
                "conflicts": list(result.conflicts),
            }
        else:
            ingested = self._ingest_selected(paths, incoming, enabled, progress)
            analysis = None
        return {
            "ingested": [
                {
                    "file": item.file,
                    "actor": item.actor,
                    "channel": item.channel,
                    "imported": item.imported,
                    "skipped": item.skipped,
                    "relabeled": item.relabeled,
                }
                for item in ingested
            ],
            "analysis": analysis,
            "progress": progress,
            "network_requests_sent": 0,
        }

    def deletion_preview(self, paths: WorkspacePaths, *, purge: bool) -> dict[str, Any]:
        """Resolve and display only the exact paths eligible for permanent removal."""

        target, capture_target, secret_store, secret_targets = self._deletion_targets(
            paths,
            purge=purge,
        )
        return {
            "workspace": {
                "key": paths.root.name,
                "name": target.display_name,
                "slug": target.slug,
                "path": str(target.root),
            },
            "mode": "purge" if purge else "delete",
            "expected_confirmation": f"PURGE {target.slug}" if purge else target.slug,
            "targets": {
                "workspace": str(target.root),
                "credential_store": (
                    {
                        "path": str(secret_store.path),
                        "present": bool(secret_targets),
                        "files": len(secret_targets),
                    }
                    if secret_store is not None
                    else None
                ),
                "capture_directory": (
                    {"path": str(capture_target.root), "present": True}
                    if capture_target is not None
                    else (
                        {"path": str(self.capture_root / target.slug), "present": False}
                        if purge
                        else None
                    )
                ),
            },
            "preserves_related_data": not purge,
            "permanent": True,
        }

    def delete_workspace(
        self,
        paths: WorkspacePaths,
        request: WorkspaceDeleteRequest,
    ) -> dict[str, Any]:
        """Permanently remove one revalidated workspace and optional related project data."""

        purge = request.mode == "purge"
        target, capture_target, secret_store, _ = self._deletion_targets(paths, purge=purge)
        expected = f"PURGE {target.slug}" if purge else target.slug
        if request.confirmation != expected:
            raise FinsecError(f"Confirmation did not match {expected!r}; nothing was deleted.")

        removed_secrets: tuple[Path, ...] = ()
        if secret_store is not None:
            removed_secrets = secret_store.delete_store()
        if capture_target is not None:
            delete_capture_directory(capture_target)
        remove_workspace_directory(target)
        return {
            "workspace": str(target.root),
            "slug": target.slug,
            "mode": request.mode,
            "credential_files_removed": len(removed_secrets),
            "capture_removed": capture_target is not None,
            "permanent": True,
        }

    def _deletion_targets(
        self,
        paths: WorkspacePaths,
        *,
        purge: bool,
    ) -> tuple[
        WorkspaceDeletionTarget,
        CaptureDeletionTarget | None,
        SecretStore | None,
        tuple[Path, ...],
    ]:
        target = resolve_workspace_deletion_target(paths.root)
        resolved_root = target.root.resolve()
        if not resolved_root.is_relative_to(self.workspace_root):
            raise WorkspaceError(f"Workspace path escapes configured root: {resolved_root}")
        if not purge:
            return target, None, None, ()

        candidate = self.capture_root / target.slug
        capture_target = (
            resolve_capture_deletion_target(target, candidate)
            if candidate.exists() or candidate.is_symlink()
            else None
        )
        secret_store = SecretStore(WorkspacePaths(target.root))
        return target, capture_target, secret_store, secret_store.deletion_targets()

    def _capture_directory(self, paths: WorkspacePaths, target: TargetDocument) -> Path:
        slug = validate_target_name(target.target.slug or paths.root.name)
        candidate = (self.capture_root / slug).resolve()
        try:
            candidate.relative_to(self.capture_root)
        except ValueError as error:
            raise WorkspaceError(f"Capture path escapes configured root: {candidate}") from error
        return candidate

    @staticmethod
    def _target(paths: WorkspacePaths) -> TargetDocument:
        return TargetDocument.model_validate(load_yaml(paths.target))

    @staticmethod
    def _validate_har_content(content: bytes) -> None:
        try:
            document = json.loads(content)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise HarFormatError("Uploaded file is not valid UTF-8 HAR JSON.") from error
        log = document.get("log") if isinstance(document, dict) else None
        entries = log.get("entries") if isinstance(log, dict) else None
        if not isinstance(entries, list):
            raise HarFormatError("HAR must contain a log.entries array.")

    @staticmethod
    def _validate_capture_files(incoming: Path, captures: list[WorkflowCapture]) -> None:
        if not incoming.is_dir():
            raise WorkspaceError(f"Capture input directory not found: {incoming}")
        missing: list[str] = []
        unsafe: list[str] = []
        for capture in captures:
            source = incoming / capture.file
            if not source.is_file():
                missing.append(capture.file)
            elif source.is_symlink():
                unsafe.append(capture.file)
        if missing:
            raise WorkspaceError("Assigned HAR files are missing: " + ", ".join(sorted(missing)))
        if unsafe:
            raise WorkspaceError(
                "Symbolic-link HAR files are not accepted: " + ", ".join(sorted(unsafe))
            )

    @staticmethod
    def _ingest_selected(
        paths: WorkspacePaths,
        incoming: Path,
        captures: list[WorkflowCapture],
        progress: list[str],
    ) -> list[WorkflowIngestResult]:
        results: list[WorkflowIngestResult] = []
        for capture in captures:
            channel: ChannelType = "PUBLIC_API" if capture.channel == "API" else capture.channel
            progress.append(f"Ingesting {capture.file} as {capture.actor} ({channel})")
            result = ingest_har(
                incoming / capture.file,
                paths,
                actor=capture.actor,
                channel=channel,
            )
            results.append(
                WorkflowIngestResult(
                    file=capture.file,
                    actor=capture.actor,
                    channel=channel,
                    imported=result.imported,
                    skipped=result.skipped,
                    relabeled=result.relabeled,
                )
            )
        return results
