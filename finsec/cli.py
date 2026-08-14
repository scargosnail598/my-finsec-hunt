"""Typer command-line interface for the deterministic research pipeline."""

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Any, NoReturn, cast

import typer
from pydantic import ValidationError
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table

from finsec.auth.service import (
    AuthenticationRecommendation,
    actor_preflight,
    capture_from_burp,
    capture_from_har,
    capture_from_raw_request,
    clear_authentication,
    configure_refresh_from_har,
    migrate_legacy_authentication,
    recommend_burp_authentication,
    recommend_har_authentication,
    refresh_actor_authentication,
    set_manual_authentication,
    validate_actor_baseline,
)
from finsec.auth.store import SecretStore
from finsec.behavior.analysis import (
    analyze_business_logic,
    find_logic_cluster,
    find_logic_hypothesis,
    load_logic_presentation,
)
from finsec.behavior.hypothesis_precision import rank_hypothesis_clusters
from finsec.behavior.reconstruction import (
    build_behavior_model,
    find_workflow_family,
    load_propagation,
    load_workflow_families,
    load_workflow_graph,
    load_workflow_instances,
)
from finsec.behavior.rendering import render_graph
from finsec.captures.analysis import resource_family
from finsec.captures.domain import (
    Capture,
    CaptureAssignment,
    CaptureConfidence,
    CaptureIntent,
    CaptureMode,
    CaptureRelevance,
    CaptureSourceType,
    MetadataSource,
)
from finsec.captures.preview import CapturePreview, preview_capture
from finsec.captures.service import find_capture, list_captures
from finsec.config.models import TargetDocument
from finsec.config.workspace import (
    CaptureDeletionTarget,
    WorkspacePaths,
    clear_default_workspace,
    create_workspace,
    delete_capture_directory,
    delete_workspace,
    load_default_workspace,
    resolve_capture_deletion_target,
    resolve_workspace,
    resolve_workspace_deletion_target,
    set_default_workspace,
)
from finsec.errors import FinsecError
from finsec.evidence.manager import add_evidence, ensure_evidence
from finsec.execution.policy import (
    approve_plan,
    prepare_execution,
    review_execution_authority,
    review_plan_approval,
)
from finsec.execution.runner import execute_prepared
from finsec.hypotheses.clustering import presentation_title, presentation_visible
from finsec.hypotheses.contracts import HypothesisCampaign
from finsec.hypotheses.domain import HypothesisRecord, HypothesisStore
from finsec.hypotheses.generator import (
    find_hypothesis,
    generate_hypotheses,
    load_hypotheses,
)
from finsec.hypotheses.population import hypothesis_population
from finsec.ingest.har import ingest_har
from finsec.ingest.openapi import ingest_openapi
from finsec.ingest.traffic import ingest_burp_xml, ingest_caido_json
from finsec.modeling.generator import generate_model
from finsec.modeling.invariants import generate_invariants
from finsec.modeling.models import ChannelType, EndpointStore, ObservationStore
from finsec.normalization.inventory import build_inventory
from finsec.readiness.resolver import resolve_workspace_readiness
from finsec.recon.graphql import ingest_graphql
from finsec.recon.mobile import scan_mobile
from finsec.reporting.generator import generate_report
from finsec.setup import SetupResult, run_setup_wizard
from finsec.testing.burp import export_burp_requests
from finsec.testing.planner import generate_plan, inspect_plan_alignment
from finsec.utils.yaml_store import load_yaml
from finsec.validation.validator import validate_hypothesis
from finsec.workflow import (
    WorkflowCapture,
    load_workflow_manifest,
    merge_workflow_assignments,
    run_offline_workflow,
)
from finsec.workspace_analysis import WorkspaceAnalysisOrchestrator
from finsec.workspace_analysis.domain import WorkspaceAnalysisStageStatus

app = typer.Typer(
    name="hunt",
    help="Local-first, authorized fintech research workspace.",
    no_args_is_help=True,
)
workspace_app = typer.Typer(
    help="Select a default workspace or manage an explicit workspace lifecycle.",
    no_args_is_help=True,
)
app.add_typer(workspace_app, name="workspace")
actor_app = typer.Typer(help="Manage configured research actors.", no_args_is_help=True)
actor_auth_app = typer.Typer(help="Manage actor-owned authentication.", no_args_is_help=True)
actor_app.add_typer(actor_auth_app, name="auth")
app.add_typer(actor_app, name="actor")
workflows_app = typer.Typer(
    help="Reconstruct and inspect deterministic application workflows.",
    no_args_is_help=True,
)
app.add_typer(workflows_app, name="workflows")
logic_app = typer.Typer(
    help="Analyze business invariants and workflow-level security hypotheses.",
    no_args_is_help=True,
)
app.add_typer(logic_app, name="logic")
console = Console()

WorkspaceOption = Annotated[
    Path | None,
    typer.Option(
        "--workspace",
        "-w",
        help="Target workspace; defaults to the current or configured workspace.",
    ),
]

ALLOWED_CHANNELS = {"WEB", "MOBILE", "PARTNER_API", "PUBLIC_API", "UNKNOWN"}


def _abort(error: Exception) -> NoReturn:
    console.print(f"[bold red]Error:[/bold red] {error}")
    raise typer.Exit(code=1) from error


def _channel(value: str) -> ChannelType:
    normalized = value.upper()
    if normalized not in ALLOWED_CHANNELS:
        raise FinsecError("Channel must be WEB, MOBILE, PARTNER_API, PUBLIC_API, or UNKNOWN.")
    return cast(ChannelType, normalized)


def _offline_workflow_hint(paths: WorkspacePaths) -> str:
    return f"Run 'hunt workflow --no-ingest --workspace {paths.root}' to refresh offline analysis."


def _hypothesis_table(hypotheses: list[HypothesisRecord]) -> Table:
    table = Table(show_lines=False)
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("Priority", no_wrap=True)
    table.add_column("Score", justify="right", no_wrap=True)
    table.add_column("Readiness", no_wrap=True)
    table.add_column("Title")
    priority_style = {"P1": "bold red", "P2": "yellow", "P3": "dim"}
    for hypothesis in hypotheses:
        table.add_row(
            hypothesis.id,
            f"[{priority_style[hypothesis.priority]}]{hypothesis.priority}[/]",
            str(hypothesis.scores.total),
            hypothesis.readiness,
            hypothesis.title,
        )
    return table


def _canonical_backlog_presentation(
    paths: WorkspacePaths,
    hypotheses: list[HypothesisRecord],
    *,
    include_suppressed: bool = False,
) -> list[HypothesisRecord]:
    """Apply the common HYP/BLH presentation layer without changing source diagnostics."""

    del paths
    return [
        item.model_copy(update={"title": presentation_title(item)})
        for item in hypotheses
        if include_suppressed or presentation_visible(item)
    ]


@app.command("init")
def init_command(
    name: Annotated[str, typer.Argument(help="Portable target workspace name.")],
    workspace_root: Annotated[
        Path,
        typer.Option("--workspace-root", help="Directory that will contain target workspaces."),
    ] = Path("workspaces"),
) -> None:
    """Create an independent target workspace without credentials."""

    try:
        workspace = create_workspace(name, workspace_root)
    except FinsecError as error:
        _abort(error)
    console.print(f"[green]Created workspace:[/green] {workspace.root}")
    console.print("Review target.yaml and scope restrictions before any active research.")
    console.print(f"For guided configuration, run 'hunt setup --workspace {workspace.root}'.")


@app.command("setup")
def setup_command(
    name: Annotated[
        str | None,
        typer.Option("--name", help="Project display name; omit to be prompted."),
    ] = None,
    slug: Annotated[
        str | None,
        typer.Option("--slug", help="Path-safe workspace slug; defaults to the project name."),
    ] = None,
    host: Annotated[
        list[str] | None,
        typer.Option("--host", help="In-scope host. Repeat for multiple hosts."),
    ] = None,
    account: Annotated[
        list[str] | None,
        typer.Option("--account", help="Researcher-owned account label. Repeat as needed."),
    ] = None,
    anonymous_actor: Annotated[
        list[str] | None,
        typer.Option("--anonymous-actor", help="Explicit anonymous actor label. Repeat as needed."),
    ] = None,
    privileged_actor: Annotated[
        list[str] | None,
        typer.Option(
            "--privileged-actor", help="Explicit privileged actor label. Repeat as needed."
        ),
    ] = None,
    workspace_root: Annotated[
        Path,
        typer.Option("--workspace-root", help="Directory that contains target workspaces."),
    ] = Path("workspaces"),
    capture_root: Annotated[
        Path,
        typer.Option("--capture-root", help="Directory that contains sanitized HAR captures."),
    ] = Path("captures"),
    yes: Annotated[
        bool,
        typer.Option("--yes", "-y", help="Use safe defaults and skip confirmation prompts."),
    ] = False,
    synthetic: Annotated[
        bool,
        typer.Option("--synthetic", help="Create a synthetic/local workspace, not production."),
    ] = False,
    target_url: Annotated[
        str | None,
        typer.Option("--target-url", help="Scoped HTTP(S) base URL for the target."),
    ] = None,
    workspace: Annotated[
        Path | None,
        typer.Option("--workspace", "-w", help="Existing workspace to resume safely."),
    ] = None,
) -> None:
    """Create a validated workspace and optionally import available captures."""

    try:
        if workspace is not None:
            existing = resolve_workspace(workspace)
            existing_target = TargetDocument.model_validate(load_yaml(existing.target))
            workspace_root = existing.root.parent
            name = name or existing_target.target.name
            slug = slug or existing_target.target.slug or existing.root.name
            host = host or existing_target.scope.hosts
            account = account or [item.id for item in existing_target.accounts]
            target_url = target_url or existing_target.target.base_url
        actor_labels = list(
            dict.fromkeys([*(account or []), *(anonymous_actor or []), *(privileged_actor or [])])
        )
        run_setup_wizard(
            console,
            name=name,
            slug=slug,
            hosts=host,
            account_labels=actor_labels or None,
            workspace_root=workspace_root,
            capture_root=capture_root,
            assume_yes=yes,
            synthetic=synthetic,
            base_url=target_url,
            anonymous_labels=set(anonymous_actor or []),
            privileged_labels=set(privileged_actor or []),
            ingest_captures=_offer_setup_capture_ingestion,
        )
    except (KeyboardInterrupt, typer.Abort) as error:
        console.print("\nSetup cancelled; no partial workspace was created.")
        raise typer.Exit(code=130) from error
    except (FinsecError, OSError, ValidationError) as error:
        _abort(error)


@workspace_app.command("use")
def workspace_use_command(
    workspace: Annotated[
        Path,
        typer.Argument(help="Workspace directory to use by default."),
    ],
) -> None:
    """Select the default workspace for commands that omit --workspace."""

    try:
        selected = set_default_workspace(workspace)
    except (FinsecError, OSError) as error:
        _abort(error)
    console.print(f"[green]Default workspace:[/green] {selected.root}")


@workspace_app.command("current")
def workspace_current_command() -> None:
    """Show the configured default workspace selection."""

    try:
        selected = load_default_workspace()
    except FinsecError as error:
        _abort(error)
    if selected is None:
        console.print("No default workspace is configured.")
        return
    console.print(f"[green]Default workspace:[/green] {selected.root}")


@workspace_app.command("clear")
def workspace_clear_command() -> None:
    """Clear the configured default workspace selection."""

    try:
        removed = clear_default_workspace()
    except (FinsecError, OSError) as error:
        _abort(error)
    if removed:
        console.print("[green]Cleared the default workspace.[/green]")
    else:
        console.print("No default workspace was configured.")


@workspace_app.command("delete")
def workspace_delete_command(
    workspace: Annotated[
        Path,
        typer.Option(
            "--workspace",
            "-w",
            help="Exact workspace directory to permanently delete.",
        ),
    ],
    confirm: Annotated[
        str | None,
        typer.Option(
            "--confirm",
            help=(
                "Exact workspace slug, or 'PURGE <slug>' with --purge; bypasses the "
                "interactive confirmation prompt."
            ),
        ),
    ] = None,
    purge: Annotated[
        bool,
        typer.Option(
            "--purge",
            "--all-related",
            help=(
                "Also permanently delete the workspace credential store and its capture directory."
            ),
        ),
    ] = False,
    capture_directory: Annotated[
        Path | None,
        typer.Option(
            "--capture-directory",
            help=(
                "Explicit project capture directory for --purge; required when it cannot be "
                "derived as captures/<slug>."
            ),
        ),
    ] = None,
) -> None:
    """Delete one workspace, with an opt-in complete purge of related project data."""

    capture_target: CaptureDeletionTarget | None = None
    secret_store: SecretStore | None = None
    secret_targets: tuple[Path, ...] = ()
    try:
        target = resolve_workspace_deletion_target(workspace)
        if capture_directory is not None and not purge:
            raise FinsecError("--capture-directory requires --purge.")
        if purge:
            capture_target = resolve_capture_deletion_target(target, capture_directory)
            secret_store = SecretStore(WorkspacePaths(target.root))
            secret_targets = secret_store.deletion_targets()
        related_lines = ""
        if purge:
            capture_text = str(capture_target.root) if capture_target is not None else "not present"
            secret_text = str(secret_store.path) if secret_store is not None else "not present"
            related_lines = (
                f"\nCredential store: {secret_text}"
                f"{' (not present)' if not secret_targets else ''}\n"
                f"Capture directory: {capture_text}\n"
            )
        console.print(
            Panel.fit(
                f"Workspace: {target.display_name}\n"
                f"Slug: {target.slug}\n"
                f"Path: {target.root}\n"
                f"{related_lines}\n"
                "This permanently deletes the workspace directory and all observations, "
                "models, hypotheses, plans, evidence, validations, and reports inside it.\n"
                + (
                    "Purge mode also deletes the project credential store and capture directory."
                    if purge
                    else "The separate credential store and capture directory are not deleted."
                ),
                title="Complete Project Purge" if purge else "Permanent Workspace Deletion",
                border_style="red",
            )
        )
        expected = f"PURGE {target.slug}" if purge else target.slug
        confirmation = confirm
        if confirmation is None:
            confirmation = typer.prompt(f"Type '{expected}' to confirm deletion")
        if confirmation != expected:
            raise FinsecError(f"Confirmation did not match '{expected}'; nothing was deleted.")
        removed_secrets: tuple[Path, ...] = ()
        if secret_store is not None:
            removed_secrets = secret_store.delete_store()
        if capture_target is not None:
            delete_capture_directory(capture_target)
        delete_workspace(target)
    except (KeyboardInterrupt, typer.Abort) as error:
        console.print("\nWorkspace deletion cancelled; nothing was deleted.")
        raise typer.Exit(code=130) from error
    except (FinsecError, OSError, ValidationError) as error:
        _abort(error)

    if purge:
        console.print(f"[bold green]Purged workspace:[/bold green] {target.root}")
        console.print(
            "Credential store: "
            + (f"removed ({len(removed_secrets)} file(s))" if removed_secrets else "not present")
        )
        console.print(
            "Capture directory: "
            + (f"removed ({capture_target.root})" if capture_target is not None else "not present")
        )
        console.print("Complete project purge finished for the validated paths shown above.")
    else:
        console.print(f"[bold green]Deleted workspace:[/bold green] {target.root}")
        console.print(
            "Deletion is permanent. Separate credential and capture data were left untouched."
        )


@workspace_app.command("migrate-auth")
def workspace_migrate_auth_command(workspace: WorkspaceOption = None) -> None:
    """Add explicit actor authentication metadata to a legacy workspace."""

    try:
        paths = resolve_workspace(workspace)
        changed = migrate_legacy_authentication(paths)
    except FinsecError as error:
        _abort(error)
    console.print(f"[green]Migrated {changed} actor authentication record(s).[/green]")
    console.print(
        "Environment variables remain a temporary legacy fallback; import credentials next."
    )


@workspace_app.command("report")
def workspace_report_command(
    workspace: WorkspaceOption = None,
    output: Annotated[
        Path | None,
        typer.Option(
            "--output",
            "-o",
            help="Markdown output path; defaults to reports/workspace with a UTC timestamp.",
        ),
    ] = None,
    report_only: Annotated[
        bool,
        typer.Option(
            "--report-only",
            help="Read current artifacts without regenerating derived analysis.",
        ),
    ] = False,
    force: Annotated[
        bool,
        typer.Option(
            "--force",
            help="Rebuild every applicable deterministic safe offline stage.",
        ),
    ] = False,
    include_suppressed: Annotated[
        bool,
        typer.Option(
            "--include-suppressed/--no-include-suppressed",
            help="Include suppressed hypotheses and endpoints in the complete appendix.",
        ),
    ] = True,
    include_command_output: Annotated[
        bool,
        typer.Option(
            "--include-command-output",
            help="Include sanitized logical-stage diagnostics in the Markdown appendix.",
        ),
    ] = False,
    strict: Annotated[
        bool,
        typer.Option(
            "--strict",
            help="Return a failing exit code when required stages or data are unavailable.",
        ),
    ] = False,
) -> None:
    """Run safe offline analysis and write a preliminary whole-workspace report."""

    try:
        paths = resolve_workspace(workspace)
        result = WorkspaceAnalysisOrchestrator(paths).run(
            output=output,
            report_only=report_only,
            force=force,
            include_suppressed=include_suppressed,
            include_command_output=include_command_output,
            strict=strict,
        )
    except (FinsecError, OSError, ValidationError) as error:
        _abort(error)

    stage_counts = {
        status: sum(item.status == status for item in result.report.stages)
        for status in WorkspaceAnalysisStageStatus
    }
    metrics = result.report.metrics
    headline = (
        "[yellow]Partial workspace analysis report generated.[/yellow]"
        if result.partial
        else "[bold green]Workspace analysis report generated.[/bold green]"
    )
    console.print(headline)
    console.print(f"\nWorkspace: {paths.root}")
    console.print(
        "Pipeline: "
        f"{stage_counts[WorkspaceAnalysisStageStatus.SUCCESS]} succeeded, "
        f"{stage_counts[WorkspaceAnalysisStageStatus.WARNING]} warnings, "
        f"{stage_counts[WorkspaceAnalysisStageStatus.SKIPPED]} skipped, "
        f"{stage_counts[WorkspaceAnalysisStageStatus.FAILED]} failed"
    )
    for label, count in (
        ("Observations", metrics.observations),
        ("Endpoints", metrics.endpoint_families),
        ("Actors", metrics.actors),
        ("Workflows", metrics.workflow_instances),
        ("Invariants", metrics.active_invariants),
        ("Active hypotheses", metrics.active_hypotheses),
        ("Research tasks", metrics.research_tasks),
        ("TEST_READY", metrics.test_ready),
        ("REVIEW_REQUIRED", metrics.review_required),
        ("RESEARCH_ONLY", metrics.research_only),
    ):
        console.print(f"{label}: {count}")
    if result.report.primary_blocker:
        console.print(f"\nPrimary blocker:\n{result.report.primary_blocker}")
    console.print(f"\nReport:\n{result.path}")
    if result.strict_failure:
        raise typer.Exit(code=1)


def _print_authentication_preflight(preflight: Any) -> None:
    console.print(f"Actor: {preflight.actor_id}")
    console.print(f"Authentication type: {preflight.auth_type}")
    console.print("Credential available: " + ("yes" if preflight.credential_available else "no"))
    console.print(f"Known expiration: {preflight.expires_at or 'unknown'}")
    remaining = (
        f"{preflight.remaining_seconds} seconds"
        if preflight.remaining_seconds is not None
        else "unknown"
    )
    console.print(f"Remaining lifetime: {remaining}")
    console.print(f"Local status: {preflight.status}")
    console.print(
        "Target validation: " + ("recorded" if preflight.target_validated else "not validated")
    )
    console.print(
        "Baseline actor match: "
        + ("confirmed" if preflight.baseline_identity_confirmed else "not confirmed")
    )
    console.print(
        "Observed refresh flow: " + ("available" if preflight.refresh_available else "none")
    )
    console.print(f"Result: {preflight.result}")
    for reason in preflight.reasons:
        console.print(f"- {reason}")


@app.command("actors")
def actors_command(workspace: WorkspaceOption = None) -> None:
    """List configured actors and their redacted authentication readiness."""

    try:
        paths = resolve_workspace(workspace)
        target = TargetDocument.model_validate(load_yaml(paths.target))
    except (FinsecError, OSError, ValidationError) as error:
        _abort(error)
    table = Table("ACTOR", "TYPE", "AUTH TYPE", "AUTH STATUS")
    for actor in target.accounts:
        authentication = actor.authentication
        if authentication is None:
            auth_type, status = "legacy/unconfigured", "MISSING"
        else:
            auth_type = authentication.auth_type
            try:
                status = actor_preflight(paths, actor.id).status
            except FinsecError:
                status = "INVALID"
        actor_type = actor.actor_type or (
            "authenticated_user" if actor.authenticated else "anonymous"
        )
        table.add_row(actor.id, actor_type, auth_type, "READY" if status == "NONE" else status)
    console.print(table)


@actor_auth_app.command("status")
def actor_auth_status_command(
    actor_id: Annotated[str, typer.Argument(help="Configured actor ID.")],
    workspace: WorkspaceOption = None,
) -> None:
    """Show local availability, expiration, and validation metadata without network traffic."""

    try:
        paths = resolve_workspace(workspace)
        preflight = actor_preflight(paths, actor_id)
    except FinsecError as error:
        _abort(error)
    _print_authentication_preflight(preflight)
    store = SecretStore(paths)
    console.print(f"Credential storage: {store.backend_name}")
    permissions = store.permissions()
    if permissions is not None:
        console.print(f"Credential file permissions: {permissions:04o}")


@actor_auth_app.command("check")
def actor_auth_check_command(
    actor_id: Annotated[str, typer.Argument(help="Configured actor ID.")],
    workspace: WorkspaceOption = None,
    network: Annotated[
        bool,
        typer.Option(
            "--network",
            help="Send one previously observed in-scope read-only baseline request.",
        ),
    ] = False,
) -> None:
    """Run local preflight and optionally one observed read-only target validation."""

    try:
        paths = resolve_workspace(workspace)
        if network:
            if not typer.confirm(
                f"Send one observed read-only authentication baseline for {actor_id}?",
                default=False,
            ):
                raise FinsecError("Authentication network check was not approved.")
            result = validate_actor_baseline(paths, actor_id)
            preflight = result.preflight
            console.print(f"Network requests sent: {result.request_count}")
            console.print(f"Target response status: {result.status_code}")
            console.print(
                "Actor baseline matched: " + ("yes" if result.actor_baseline_matched else "no")
            )
        else:
            preflight = actor_preflight(paths, actor_id, for_execution=True)
    except FinsecError as error:
        _abort(error)
    console.print("[bold]Authentication preflight[/bold]")
    _print_authentication_preflight(preflight)
    if not network:
        console.print("Network requests sent: 0")
    if preflight.result == "BLOCKED_BY_AUTH":
        raise typer.Exit(code=1)


@actor_auth_app.command("import")
def actor_auth_import_command(
    actor_id: Annotated[str, typer.Argument(help="Configured actor ID.")],
    request: Annotated[Path, typer.Option("--request", help="Raw authenticated HTTP request.")],
    workspace: WorkspaceOption = None,
) -> None:
    """Import replay authentication from a raw HTTP request."""

    try:
        paths = resolve_workspace(workspace)
        authentication = capture_from_raw_request(paths, actor_id, request)
    except FinsecError as error:
        _abort(error)
    console.print(f"[green]Credential stored for {actor_id}.[/green]")
    console.print(f"Authentication status: {authentication.status}")


@actor_auth_app.command("set")
def actor_auth_set_command(
    actor_id: Annotated[str, typer.Argument(help="Configured actor ID.")],
    workspace: WorkspaceOption = None,
    auth_type: Annotated[
        str, typer.Option("--type", help="bearer, bearer_jwt, basic, api_key, or custom_header.")
    ] = "bearer",
    header: Annotated[str, typer.Option("--header", help="Replay header name.")] = "Authorization",
) -> None:
    """Enter a replacement credential without echoing it or placing it in shell history."""

    value = str(typer.prompt("Credential", hide_input=True, confirmation_prompt=True))
    try:
        paths = resolve_workspace(workspace)
        authentication = set_manual_authentication(
            paths,
            actor_id,
            auth_type=auth_type,
            header_name=header,
            secret_value=value,
        )
    except FinsecError as error:
        _abort(error)
    finally:
        value = ""
    console.print(f"[green]Credential stored for {actor_id}.[/green]")
    console.print(f"Authentication status: {authentication.status}")


@actor_auth_app.command("refresh")
def actor_auth_refresh_command(
    actor_id: Annotated[str, typer.Argument(help="Configured actor ID.")],
    workspace: WorkspaceOption = None,
    har: Annotated[Path | None, typer.Option("--har", help="New authenticated HAR.")] = None,
    burp: Annotated[
        Path | None, typer.Option("--burp", help="New authenticated Burp XML history export.")
    ] = None,
    request: Annotated[
        Path | None, typer.Option("--request", help="New authenticated raw HTTP request.")
    ] = None,
    auth_candidate: Annotated[
        int | None,
        typer.Option("--auth-candidate", help="1-based HAR or Burp candidate selection."),
    ] = None,
) -> None:
    """Replace authentication from a capture or run one configured observed refresh."""

    if sum(item is not None for item in (har, burp, request)) > 1:
        _abort(FinsecError("Choose exactly one of --har, --burp, or --request."))
    if auth_candidate is not None and har is None and burp is None:
        _abort(FinsecError("--auth-candidate requires --har or --burp."))
    try:
        paths = resolve_workspace(workspace)
        if har is not None:
            selected = auth_candidate
            recommendation = recommend_har_authentication(paths, actor_id, har)
            console.print("[bold]Authentication candidates detected[/bold]")
            _print_authentication_recommendation(recommendation)
            if selected is None:
                selected = recommendation.recommended_number
                if selected is None:
                    raise FinsecError(
                        "No safe fresh authentication request was recommended; use "
                        "--auth-candidate N only after reviewing the redacted candidates."
                    )
                console.print(
                    f"Automatically selected recommended authentication request {selected}."
                )
            authentication, _ = capture_from_har(
                paths,
                actor_id,
                har,
                candidate_number=selected,
                observed_renewal=True,
            )
            console.print(f"[green]Credential replaced for {actor_id}.[/green]")
            console.print(f"Authentication status: {authentication.status}")
        elif burp is not None:
            selected = auth_candidate
            recommendation = recommend_burp_authentication(paths, actor_id, burp)
            console.print("[bold]Authentication candidates detected[/bold]")
            _print_authentication_recommendation(recommendation)
            if selected is None:
                selected = recommendation.recommended_number
                if selected is None:
                    raise FinsecError(
                        "No safe fresh authentication request was recommended; use "
                        "--auth-candidate N only after reviewing the redacted candidates."
                    )
                console.print(
                    f"Automatically selected recommended authentication request {selected}."
                )
            authentication, _ = capture_from_burp(
                paths,
                actor_id,
                burp,
                candidate_number=selected,
                observed_renewal=True,
            )
            console.print(f"[green]Credential replaced for {actor_id}.[/green]")
            console.print(f"Authentication status: {authentication.status}")
        elif request is not None:
            authentication = capture_from_raw_request(paths, actor_id, request)
            console.print(f"[green]Credential replaced for {actor_id}.[/green]")
            console.print(f"Authentication status: {authentication.status}")
        else:
            result = refresh_actor_authentication(paths, actor_id)
            console.print("[green]Authentication refresh completed.[/green]")
            console.print(f"Actor: {result.actor_id}")
            console.print(f"Status: {result.status}")
            console.print(f"Refresh requests sent: {result.request_count}")
            console.print(f"Identity continuity: {result.identity_continuity}")
    except FinsecError as error:
        console.print("[bold red]Authentication refresh failed.[/bold red]")
        console.print(f"Actor: {actor_id}")
        console.print(f"Reason: {error}")
        console.print("Mutation requests sent: 0")
        raise typer.Exit(code=1) from error


@actor_auth_app.command("configure-refresh")
def actor_auth_configure_refresh_command(
    actor_id: Annotated[str, typer.Argument(help="Configured actor ID.")],
    har: Annotated[Path, typer.Option("--har", help="HAR containing an observed refresh request.")],
    workspace: WorkspaceOption = None,
    flow: Annotated[
        int | None, typer.Option("--flow", help="1-based refresh-flow selection.")
    ] = None,
    auto_refresh: Annotated[
        bool,
        typer.Option(
            "--auto-refresh", help="Allow bounded refresh during real execution preflight."
        ),
    ] = False,
) -> None:
    """Configure only a refresh request observed in authorized traffic."""

    try:
        paths = resolve_workspace(workspace)
        refresh = configure_refresh_from_har(
            paths,
            actor_id,
            har,
            entry_number=flow,
            auto_refresh=auto_refresh,
        )
    except FinsecError as error:
        _abort(error)
    console.print(f"[green]Observed refresh flow configured for {actor_id}.[/green]")
    console.print(f"Endpoint: {refresh.method} {refresh.scheme}://{refresh.host}{refresh.path}")
    console.print("Refresh request budget: 1")


@actor_auth_app.command("clear")
def actor_auth_clear_command(
    actor_id: Annotated[str, typer.Argument(help="Configured actor ID.")],
    workspace: WorkspaceOption = None,
    yes: Annotated[bool, typer.Option("--yes", "-y", help="Skip confirmation.")] = False,
) -> None:
    """Remove only one actor's authentication and invalidate affected approvals."""

    if not yes and not typer.confirm(f"Clear authentication for {actor_id}?", default=False):
        console.print("Authentication was not changed.")
        return
    try:
        paths = resolve_workspace(workspace)
        clear_authentication(paths, actor_id)
    except FinsecError as error:
        _abort(error)
    console.print(f"[green]Authentication cleared for {actor_id}.[/green]")


@app.command("workflow")
def workflow_command(
    workspace: WorkspaceOption = None,
    manifest: Annotated[
        Path | None,
        typer.Option(
            "--manifest",
            help="Explicit workflow.yaml containing HAR filename, actor, and channel mappings.",
        ),
    ] = None,
    capture_root: Annotated[
        Path | None,
        typer.Option(
            "--capture-root",
            help="Capture root used to locate <slug>/workflow.yaml when --manifest is omitted.",
        ),
    ] = None,
    no_ingest: Annotated[
        bool,
        typer.Option(
            "--no-ingest",
            help="Skip the capture manifest and analyze observations already in the workspace.",
        ),
    ] = False,
) -> None:
    """Run passive ingestion and the complete deterministic offline analysis workflow."""

    try:
        paths = resolve_workspace(workspace)
        target = TargetDocument.model_validate(load_yaml(paths.target))
        selected_manifest: Path | None = None
        if no_ingest and (manifest is not None or capture_root is not None):
            raise FinsecError("--no-ingest cannot be combined with --manifest or --capture-root.")
        if not no_ingest:
            if manifest is not None:
                selected_manifest = manifest.expanduser().resolve()
                if not selected_manifest.is_file():
                    raise FinsecError(f"Workflow manifest not found: {selected_manifest}")
            else:
                slug = target.target.slug or paths.root.name
                if capture_root is not None:
                    base = capture_root.expanduser().resolve()
                elif paths.root.parent.name == "workspaces":
                    base = paths.root.parent.parent / "captures"
                else:
                    base = Path("captures").resolve()
                candidate = base / slug / "workflow.yaml"
                if candidate.is_file():
                    selected_manifest = candidate
            if selected_manifest is None:
                raise FinsecError(
                    "No workflow manifest was found. Pass --manifest PATH, configure the default "
                    "captures/<slug>/workflow.yaml, or use --no-ingest to analyze existing "
                    "observations explicitly."
                )
        result = run_offline_workflow(
            paths,
            manifest_path=selected_manifest,
            progress=lambda message: console.print(f"[cyan]Workflow:[/cyan] {message}"),
        )
    except (FinsecError, OSError, ValidationError) as error:
        _abort(error)

    if selected_manifest is None:
        console.print("[dim]Ingestion was explicitly skipped with --no-ingest.[/dim]")
    if result.ingested:
        console.print("\n[bold]Passive ingestion[/bold]")
        ingest_table = Table(
            "File", "Actor", "Channel", "Imported", "Already present", "Labels refreshed"
        )
        for item in result.ingested:
            ingest_table.add_row(
                item.file,
                item.actor,
                item.channel,
                str(item.imported),
                str(item.skipped),
                str(item.relabeled),
            )
        console.print(ingest_table)

    console.print("\n[bold green]Automated offline workflow completed.[/bold green]")
    table = Table(show_header=False, box=None, pad_edge=False)
    table.add_column("Artifact")
    table.add_column("Count", justify="right")
    for label, count in (
        ("Observations", result.observations),
        ("Endpoint families", result.endpoints),
        ("Suppressed endpoints", result.suppressed_endpoints),
        ("Actors", result.actors),
        ("Resources", result.resources),
        ("Workflow instances", result.workflow_instances),
        ("Workflow families", result.workflow_families),
        ("Inferred states", result.states),
        ("Observed transitions", result.transitions),
        ("Endpoint invariants", result.invariants),
        ("Business invariants", result.business_invariants),
        ("Active hypotheses", result.active_hypotheses),
        ("Research tasks", result.research_tasks),
        ("Raw active hypotheses", result.raw_active_hypotheses),
        ("Raw research tasks", result.raw_research_tasks),
        ("Logic hypotheses", result.logic_hypotheses),
        ("Logic research tasks", result.logic_research_tasks),
    ):
        table.add_row(label, str(count))
    console.print(table)
    if result.conflicts:
        console.print(
            "[yellow]Preserved researcher-edited records:[/yellow] " + ", ".join(result.conflicts)
        )
    console.print(
        "\nThe automated workflow stops here. Active testing, evidence confirmation, and "
        "report generation still require explicit human review and supplied evidence."
    )


@dataclass(frozen=True)
class _InteractiveCaptureImport:
    path: Path
    source_type: CaptureSourceType
    actor: str
    channel: ChannelType
    assignment: CaptureAssignment
    auth_candidate: int | None = None
    observed_renewal: bool = False


@dataclass(frozen=True)
class _IngestWizardContext:
    target: TargetDocument
    capture_root: Path
    incoming: Path
    manifest_path: Path
    capture_files: tuple[Path, ...]

    @property
    def har_files(self) -> tuple[Path, ...]:
        """Backward-compatible alias retained for setup integrations."""

        return self.capture_files


def _print_authentication_recommendation(
    recommendation: AuthenticationRecommendation,
) -> None:
    table = Table("#", "Authentication-bearing request", "Assessment")
    for assessment in recommendation.assessments:
        if assessment.recommended:
            state = "[green]RECOMMENDED[/green]"
        elif assessment.eligible:
            state = "eligible"
        else:
            state = "[red]not eligible[/red]"
        table.add_row(str(assessment.number), escape(assessment.summary), state)
    console.print(table)
    if recommendation.recommended_number is None:
        console.print(
            "[yellow]No safe fresh authentication request can be recommended from this capture."
            "[/yellow]"
        )
        return
    selected = next(
        item
        for item in recommendation.assessments
        if item.number == recommendation.recommended_number
    )
    console.print(
        Panel(
            "\n".join(
                [
                    escape(selected.summary),
                    "",
                    *[f"- {escape(reason)}" for reason in selected.reasons],
                ]
            ),
            title=f"Recommended authentication request {selected.number}",
        )
    )


def _default_capture_directory(paths: WorkspacePaths, target: TargetDocument) -> Path:
    slug = target.target.slug or paths.root.name
    if paths.root.parent.name == "workspaces":
        return (paths.root.parent.parent / "captures" / slug).resolve()
    return (Path("captures").resolve() / slug).resolve()


def _resolve_ingest_wizard_context(
    paths: WorkspacePaths,
    capture_root: Path | None,
    *,
    include_assigned: bool,
) -> _IngestWizardContext:
    """Resolve available captures without inferring security-relevant provenance."""

    target = TargetDocument.model_validate(load_yaml(paths.target))
    selected_capture_root = (
        capture_root.expanduser().resolve()
        if capture_root is not None
        else _default_capture_directory(paths, target)
    )
    incoming = selected_capture_root / "incoming"
    manifest_path = selected_capture_root / "workflow.yaml"
    if not incoming.is_dir():
        raise FinsecError(f"Capture input directory not found: {incoming}")
    manifest = load_workflow_manifest(manifest_path) if manifest_path.is_file() else None
    assigned = {item.file for item in manifest.captures} if manifest is not None else set()
    capture_files = tuple(
        sorted(
            path
            for path in incoming.iterdir()
            if path.is_file()
            and path.suffix.lower() in {".har", ".xml"}
            and (include_assigned or path.name not in assigned)
        )
    )
    return _IngestWizardContext(
        target=target,
        capture_root=selected_capture_root,
        incoming=incoming,
        manifest_path=manifest_path,
        capture_files=capture_files,
    )


def _offer_setup_capture_ingestion(result: SetupResult) -> None:
    """Present passive capture ingestion before actor authentication setup."""

    console.print("\n[bold]Capture ingestion[/bold]")
    while True:
        context = _resolve_ingest_wizard_context(
            result.workspace,
            result.capture_root,
            include_assigned=False,
        )
        if context.capture_files:
            break
        console.print(f"No unassigned capture files were found in {context.incoming}.")
        console.print("1. Add authorized, reviewed HAR or Burp XML files and rescan")
        console.print("2. Continue to actor authentication without ingesting")
        choice = str(typer.prompt("Choose the next setup step", default="1")).strip()
        if choice == "2":
            return
        if choice != "1":
            console.print("[red]Choose 1 or 2.[/red]")
            continue
        console.print(f"Place the HAR or Burp XML files in: {context.incoming}")
        while True:
            ready = (
                str(
                    typer.prompt(
                        "After adding files, type RESCAN; type SKIP to continue without ingestion",
                        default="RESCAN",
                    )
                )
                .strip()
                .upper()
            )
            if ready == "RESCAN":
                break
            if ready == "SKIP":
                return
            console.print("[red]Type RESCAN or SKIP.[/red]")
    count = len(context.capture_files)
    console.print(
        f"[bold]Available capture{'s' if count != 1 else ''}:[/bold] "
        f"{count} unassigned capture file{'s' if count != 1 else ''}"
    )
    if not typer.confirm("Assign and import available captures now?", default=True):
        return
    _run_ingest_wizard(result.workspace, context)


def _default_actor_channel(target: TargetDocument, actor_id: str) -> str:
    actor = next((item for item in target.accounts if item.id == actor_id), None)
    if actor is None:
        return "UNKNOWN"
    return {
        "web": "WEB",
        "mobile": "MOBILE",
        "api": "PUBLIC_API",
        "unknown": "UNKNOWN",
    }[actor.attributes.channel]


def _prompt_har_actor(target: TargetDocument) -> str | None:
    configured = {item.id for item in target.accounts}
    while True:
        actor = str(typer.prompt("Actor label (or SKIP)", default="SKIP")).strip()
        if actor.upper() == "SKIP":
            return None
        if actor in configured or actor in {"ANONYMOUS", "UNKNOWN"}:
            return actor
        console.print(f"[red]Actor {escape(actor)!r} is not configured in target.yaml.[/red]")


def _prompt_har_channel(target: TargetDocument, actor_id: str) -> ChannelType:
    while True:
        try:
            return _channel(
                str(
                    typer.prompt(
                        "Channel",
                        default=_default_actor_channel(target, actor_id),
                    )
                )
            )
        except FinsecError as error:
            console.print(f"[red]{error}[/red]")


def _capture_mode(value: str | None) -> CaptureMode:
    """Normalize a capture-mode CLI value with a concise error."""

    if value is None:
        return CaptureMode.UNKNOWN
    try:
        return CaptureMode(value.strip().upper())
    except ValueError as error:
        allowed = ", ".join(item.value for item in CaptureMode)
        raise FinsecError(f"Capture mode must be one of: {allowed}.") from error


def _supplied_intent(action: str | None, resource: str | None) -> CaptureIntent | None:
    """Build a complete user-supplied intent or reject partial metadata."""

    if action is None and resource is None:
        return None
    if action is None or resource is None:
        raise FinsecError("--intent-action and --intent-resource must be supplied together.")
    intent = CaptureIntent(
        label=f"{action}_{resource}",
        action=action,
        resource_type=resource,
        confidence=CaptureConfidence.HIGH,
        source=MetadataSource.USER_SUPPLIED,
    )
    return intent


def _direct_capture_assignment(
    actor: str,
    mode: str | None,
    intent_action: str | None,
    intent_resource: str | None,
) -> CaptureAssignment:
    normalized_mode = _capture_mode(mode)
    return CaptureAssignment(
        actor_source=(
            MetadataSource.USER_SUPPLIED if actor != "UNKNOWN" else MetadataSource.UNKNOWN
        ),
        actor_confidence=(CaptureConfidence.HIGH if actor != "UNKNOWN" else CaptureConfidence.LOW),
        actor_evidence=(
            ["Actor label was supplied via command-line ingestion."] if actor != "UNKNOWN" else []
        ),
        capture_mode=normalized_mode,
        capture_mode_source=(
            MetadataSource.USER_SUPPLIED if mode is not None else MetadataSource.UNKNOWN
        ),
        intent=_supplied_intent(intent_action, intent_resource),
    )


def _intent_text(intent: CaptureIntent) -> str:
    if intent.action == "UNKNOWN" or intent.resource_type == "unknown":
        return "UNKNOWN"
    return f"{intent.action} {intent.resource_type}"


def _observed_capture_intent(capture: Capture) -> CaptureIntent:
    """Prefer independently observed semantics while retaining legacy capture compatibility."""

    if capture.observed_intent.action != "UNKNOWN":
        return capture.observed_intent
    return capture.intent


def _print_capture_diagnostics(capture: Capture) -> None:
    """Print a concise, secret-free summary that teaches better capture practice."""

    console.print(f"\n[bold green]Capture {capture.capture_id} ingested.[/bold green]")
    details = Table(show_header=False, box=None, pad_edge=False)
    details.add_column("Field")
    details.add_column("Value")
    details.add_row(
        "Actor",
        f"{capture.actor_id} ({capture.actor_confidence}, {capture.actor_source})",
    )
    details.add_row(
        "Mode",
        f"{capture.capture_mode} ({capture.capture_mode_source})",
    )
    observed_intent = _observed_capture_intent(capture)
    if capture.declared_intent is not None:
        details.add_row(
            "Declared intent",
            f"{_intent_text(capture.declared_intent)} ({capture.declared_intent.source})",
        )
    details.add_row(
        "Observed intent",
        f"{_intent_text(observed_intent)} ({observed_intent.source}, {observed_intent.confidence})",
    )
    details.add_row("Capture quality", ", ".join(capture.quality.labels) or "UNKNOWN")
    console.print(details)
    counts = capture.counts
    console.print(
        "Observations: "
        f"{counts.observations} total, {counts.first_party} first-party, "
        f"{counts.state_changing} state-changing, "
        f"{counts.primary} primary, {counts.supporting} supporting, "
        f"{counts.context} context, {counts.protocol_support} protocol support, "
        f"{counts.noise} noise"
    )
    for warning in capture.warnings:
        console.print(f"[yellow]Warning:[/yellow] {escape(warning)}")
    if capture.quality.recommendation:
        console.print(f"Recommendation: {escape(capture.quality.recommendation)}")


def _print_capture_preview(preview: CapturePreview) -> None:
    console.print(f"\n[bold]Found new capture:[/bold] {escape(preview.path.name)}")
    console.print(
        f"  {preview.first_party_requests} first-party requests\n"
        f"  {preview.state_changing_requests} state-changing requests"
    )
    console.print("\n[bold]Detected actor:[/bold]")
    console.print(f"  {preview.actor_id or 'Unknown'}")
    console.print(f"  Confidence: {preview.actor_confidence}")
    console.print("\n[bold]Likely intent:[/bold]")
    console.print(f"  {_intent_text(preview.intent)}")
    console.print(f"  Confidence: {preview.intent.confidence}")
    console.print("\n[bold]Capture mode:[/bold]")
    console.print(f"  {preview.capture_mode} ({preview.capture_mode_confidence})")
    if preview.quality.labels:
        console.print(f"\nCapture quality: {', '.join(preview.quality.labels)}")


def _prompt_capture_actor(target: TargetDocument, default: str | None = None) -> str | None:
    options = list(dict.fromkeys([item.id for item in target.accounts] + ["ANONYMOUS", "UNKNOWN"]))
    console.print("\nWho performed this capture?")
    for index, actor in enumerate(options, start=1):
        console.print(f"{index}. {actor}")
    console.print(f"{len(options) + 1}. Skip this file")
    default_value = str(options.index(default) + 1) if default in options else "1"
    while True:
        choice = str(typer.prompt("Choose actor", default=default_value)).strip()
        if choice.isdigit():
            selected = int(choice)
            if 1 <= selected <= len(options):
                return options[selected - 1]
            if selected == len(options) + 1:
                return None
        if choice in options:
            return choice
        console.print("[red]Choose one listed actor or number.[/red]")


def _prompt_capture_mode(default: CaptureMode) -> CaptureMode:
    options = [
        (CaptureMode.NORMAL_BEHAVIOR, "Normal application behavior"),
        (CaptureMode.RESEARCHER_PROBE, "Researcher security probe"),
        (CaptureMode.AUTHENTICATION, "Authentication/session setup"),
        (CaptureMode.MIXED, "Mixed normal and probe activity"),
        (CaptureMode.UNKNOWN, "Unknown"),
    ]
    console.print("\nWhat type of activity is this?")
    for index, (_mode, label) in enumerate(options, start=1):
        console.print(f"{index}. {label}")
    default_index = next(
        index for index, (mode, _label) in enumerate(options, start=1) if mode == default
    )
    while True:
        choice = str(typer.prompt("Choose activity type", default=str(default_index))).strip()
        if choice.isdigit() and 1 <= int(choice) <= len(options):
            return options[int(choice) - 1][0]
        console.print("[red]Choose a number from 1 to 5.[/red]")


def _parse_prompt_intent(value: str, source: MetadataSource) -> CaptureIntent:
    normalized = value.strip()
    if not normalized or normalized.upper() == "UNKNOWN":
        return CaptureIntent(source=source)
    action, separator, resource = normalized.partition(" ")
    if not separator or not resource.strip():
        raise FinsecError("Intent must use 'ACTION resource_type', for example CREATE dns_record.")
    return CaptureIntent(
        label=f"{action}_{resource}",
        action=action,
        resource_type=resource,
        confidence=CaptureConfidence.HIGH,
        source=source,
    )


def _prompt_capture_intent(preview: CapturePreview) -> CaptureIntent:
    proposed = preview.intent
    console.print("\nWhat were you mainly doing?")
    console.print(f"Detected: {_intent_text(proposed)} ({proposed.confidence})")
    if proposed.action != "UNKNOWN":
        while True:
            choice = (
                str(typer.prompt("Accept, edit, or mark unknown [Y/e/u]", default="Y"))
                .strip()
                .lower()
            )
            if choice in {"y", "yes"}:
                return proposed.model_copy(update={"source": MetadataSource.USER_CONFIRMED})
            if choice in {"u", "unknown"}:
                return CaptureIntent(source=MetadataSource.USER_SUPPLIED)
            if choice in {"e", "edit"}:
                break
            console.print("[red]Choose Y, e, or u.[/red]")
    while True:
        value = str(
            typer.prompt(
                "Main intent (ACTION resource_type or UNKNOWN)",
                default="UNKNOWN",
            )
        )
        try:
            return _parse_prompt_intent(value, MetadataSource.USER_SUPPLIED)
        except FinsecError as error:
            console.print(f"[red]{error}[/red]")


def _capture_selection(
    target: TargetDocument, preview: CapturePreview
) -> tuple[str, ChannelType, CaptureAssignment] | None:
    _print_capture_preview(preview)
    can_accept = preview.actor_id is not None and preview.intent.confidence != CaptureConfidence.LOW
    if can_accept and typer.confirm("Accept detected metadata?", default=True):
        actor = preview.actor_id
        assert actor is not None
        return (
            actor,
            cast(ChannelType, _default_actor_channel(target, actor)),
            CaptureAssignment(
                actor_source=MetadataSource.USER_CONFIRMED,
                actor_confidence=preview.actor_confidence,
                actor_evidence=[
                    *preview.actor_evidence,
                    "Researcher confirmed the detected actor.",
                ],
                capture_mode=preview.capture_mode,
                capture_mode_source=MetadataSource.USER_CONFIRMED,
                intent=preview.intent.model_copy(update={"source": MetadataSource.USER_CONFIRMED}),
            ),
        )

    actor = _prompt_capture_actor(target, preview.actor_id)
    if actor is None:
        return None
    mode = _prompt_capture_mode(preview.capture_mode)
    intent = _prompt_capture_intent(preview)
    return (
        actor,
        cast(ChannelType, _default_actor_channel(target, actor)),
        CaptureAssignment(
            actor_source=MetadataSource.USER_SUPPLIED,
            actor_confidence=CaptureConfidence.HIGH,
            actor_evidence=["Researcher selected the actor during ingest-wizard."],
            capture_mode=mode,
            capture_mode_source=MetadataSource.USER_SUPPLIED,
            intent=intent,
        ),
    )


@app.command("captures")
def captures_command(
    workspace: WorkspaceOption = None,
    explain: Annotated[
        str | None,
        typer.Option("--explain", help="Explain one capture ID such as CAP-12AB34CD56EF."),
    ] = None,
) -> None:
    """List session captures or explain one capture's provenance and relevance."""

    try:
        paths = resolve_workspace(workspace)
        if explain is None:
            captures = list_captures(paths)
            if not captures:
                console.print("No passive captures are registered in this workspace.")
                return
            table = Table("Capture", "Actor", "Mode", "Intent", "Requests", "Quality")
            table.columns[0].no_wrap = True
            for capture_row in captures:
                table.add_row(
                    capture_row.capture_id,
                    capture_row.actor_id,
                    capture_row.capture_mode,
                    _intent_text(_observed_capture_intent(capture_row)),
                    str(capture_row.counts.observations),
                    ", ".join(capture_row.quality.labels) or "UNKNOWN",
                )
            console.print(table)
            return

        capture = find_capture(paths, explain)
        if capture is None:
            raise FinsecError(f"Capture not found: {explain.strip().upper()}")
        observations = ObservationStore.model_validate(load_yaml(paths.observations))
    except (FinsecError, OSError, ValidationError) as error:
        _abort(error)

    observed_intent = _observed_capture_intent(capture)
    declared_text = (
        _intent_text(capture.declared_intent)
        if capture.declared_intent is not None
        else "not supplied"
    )
    details = [
        f"[bold]Source:[/bold] {escape(capture.source.file)} ({capture.source.type})",
        f"[bold]Redacted reference:[/bold] "
        f"{escape(capture.source.redacted_reference or 'not available')}",
        f"[bold]Actor:[/bold] {escape(capture.actor_id)}",
        f"[bold]Actor provenance:[/bold] {capture.actor_source} / {capture.actor_confidence}",
        f"[bold]Mode:[/bold] {capture.capture_mode} ({capture.capture_mode_source})",
        f"[bold]Declared intent:[/bold] {declared_text}",
        f"[bold]Provisional intent:[/bold] {_intent_text(capture.provisional_intent)}",
        f"[bold]Observed intent:[/bold] {_intent_text(observed_intent)}",
        f"[bold]Observed provenance:[/bold] {observed_intent.source} / "
        f"{observed_intent.confidence} / {capture.intent_analysis_stage}",
        f"[bold]Intent alignment:[/bold] {capture.intent_alignment}",
        f"[bold]Quality:[/bold] {', '.join(capture.quality.labels) or 'UNKNOWN'}",
        f"[bold]Requests:[/bold] {capture.counts.observations} total; "
        f"{capture.counts.primary} primary; {capture.counts.supporting} supporting; "
        f"{capture.counts.context} context; {capture.counts.protocol_support} protocol; "
        f"{capture.counts.noise} noise; {capture.counts.unknown} unknown",
    ]
    console.print(Panel("\n".join(details), title=capture.capture_id))
    if capture.actor_evidence:
        console.print("[bold]Actor evidence[/bold]")
        for evidence_text in capture.actor_evidence:
            console.print(f"- {escape(evidence_text)}")
    by_id = {item.id: item for item in observations.observations}
    primary_anchor = next(
        (item for item in capture.journey_anchors if item.anchor_id == capture.primary_anchor_id),
        None,
    )
    if primary_anchor is not None:
        console.print("[bold]Primary journey anchor[/bold]")
        anchor_observation = primary_anchor.observation_ids[0]
        console.print(
            f"- {anchor_observation} {primary_anchor.method} {escape(primary_anchor.path)} "
            f"-> {primary_anchor.status_code or 'unknown'}"
        )
        console.print(
            f"- Semantic intent: {primary_anchor.action} {primary_anchor.resource_type}; "
            f"score {primary_anchor.score}; confidence {primary_anchor.confidence}"
        )
        for evidence_text in primary_anchor.evidence:
            console.print(f"- Reason: {escape(evidence_text)}")
    competing = [
        item for item in capture.journey_anchors if item.anchor_id != capture.primary_anchor_id
    ]
    if competing:
        console.print("[bold]Competing journey anchors[/bold]")
        for anchor in competing[:5]:
            console.print(
                f"- {anchor.observation_ids[0]} {anchor.method} {escape(anchor.path)}: "
                f"{anchor.action} {anchor.resource_type}; score {anchor.score}; "
                f"confidence {anchor.confidence}"
            )
        if len(competing) > 5:
            console.print(f"- {len(competing) - 5} additional candidates omitted.")
    if capture.intent_inference.evidence:
        console.print("[bold]Observed intent evidence[/bold]")
        for evidence_text in capture.intent_inference.evidence:
            console.print(f"- {escape(evidence_text)}")
    relevant_resources = sorted(
        {
            resource_family(by_id[observation_id].path)
            for observation_id, relevance in capture.observation_relevance.items()
            if observation_id in by_id
            and relevance in {CaptureRelevance.PRIMARY, CaptureRelevance.SUPPORTING}
            and resource_family(by_id[observation_id].path) != "unknown"
        }
    )
    if relevant_resources:
        console.print(f"[bold]Relevant resources:[/bold] {', '.join(relevant_resources)}")

    def print_observation_section(
        title: str, relevance_value: CaptureRelevance, *, limit: int = 12
    ) -> None:
        selected = sorted(
            (
                by_id[observation_id]
                for observation_id, relevance in capture.observation_relevance.items()
                if observation_id in by_id and relevance == relevance_value
            ),
            key=lambda item: (
                item.sequence_position if item.sequence_position is not None else 10**9,
                item.id,
            ),
        )
        if not selected:
            return
        console.print(f"[bold]{title}[/bold]")
        for observation in selected[:limit]:
            console.print(
                f"- {observation.id} {observation.method} "
                f"{escape(observation.path)} -> {observation.status_code or 'unknown'}"
            )
        if len(selected) > limit:
            console.print(f"- {len(selected) - limit} additional observations omitted.")

    print_observation_section("PRIMARY observations", CaptureRelevance.PRIMARY)
    print_observation_section("SUPPORTING observations", CaptureRelevance.SUPPORTING)
    metrics = capture.analysis_metrics
    console.print("[bold]Protocol/background exclusions[/bold]")
    console.print(
        f"- Protocol requests excluded: {metrics.protocol_requests_excluded}; "
        f"background requests excluded: {metrics.background_requests_excluded}."
    )
    console.print(
        f"- Passive observations: {metrics.passive_observations} across "
        f"{metrics.passive_operation_groups} normalized operations; "
        f"{metrics.repeated_passive_observations_saturated} repeats saturated."
    )
    print_observation_section(
        "Protocol support examples", CaptureRelevance.PROTOCOL_SUPPORT, limit=5
    )
    print_observation_section("Background/noise examples", CaptureRelevance.NOISE, limit=5)
    if capture.quality.evidence:
        console.print("[bold]Quality evidence[/bold]")
        for evidence_text in capture.quality.evidence:
            console.print(f"- {escape(evidence_text)}")
    for warning in capture.warnings:
        console.print(f"[yellow]Warning:[/yellow] {escape(warning)}")


@app.command("ingest")
def ingest_command(
    har_file: Annotated[Path, typer.Argument(help="HAR file to import passively.")],
    workspace: WorkspaceOption = None,
    actor: Annotated[
        str,
        typer.Option("--actor", help="Non-secret account or actor label for these observations."),
    ] = "UNKNOWN",
    channel: Annotated[
        str,
        typer.Option(
            "--channel",
            help="Observed client channel: WEB, MOBILE, PARTNER_API, PUBLIC_API, or UNKNOWN.",
        ),
    ] = "UNKNOWN",
    capture_mode: Annotated[
        str | None,
        typer.Option(
            "--capture-mode",
            help="NORMAL_BEHAVIOR, RESEARCHER_PROBE, AUTHENTICATION, MIXED, or UNKNOWN.",
        ),
    ] = None,
    intent_action: Annotated[
        str | None,
        typer.Option("--intent-action", help="High-level action such as CREATE or UPDATE."),
    ] = None,
    intent_resource: Annotated[
        str | None,
        typer.Option("--intent-resource", help="High-level resource such as dns_record."),
    ] = None,
    capture_auth: Annotated[
        bool,
        typer.Option(
            "--capture-auth", help="Detect and securely store authentication for --actor."
        ),
    ] = False,
    update_auth: Annotated[
        bool,
        typer.Option(
            "--update-auth",
            help=(
                "Recommend the freshest token-bearing request and update --actor authentication; "
                "implies --capture-auth."
            ),
        ),
    ] = False,
    auth_candidate: Annotated[
        int | None,
        typer.Option("--auth-candidate", help="1-based replay profile selection for automation."),
    ] = None,
) -> None:
    """Import HAR entries as redacted, factual observations."""

    try:
        paths = resolve_workspace(workspace)
        should_capture_auth = capture_auth or update_auth
        if auth_candidate is not None and not should_capture_auth:
            raise FinsecError("--auth-candidate requires --capture-auth or --update-auth.")
        if should_capture_auth and actor == "UNKNOWN":
            raise FinsecError("Authentication capture requires an explicitly configured actor.")
        selected_candidate = auth_candidate
        recommendation: AuthenticationRecommendation | None = None
        if should_capture_auth:
            recommendation = recommend_har_authentication(paths, actor, har_file)
            console.print("[bold]Authentication candidates detected[/bold]")
            _print_authentication_recommendation(recommendation)
        if update_auth and selected_candidate is None:
            selected_candidate = recommendation.recommended_number if recommendation else None
            if selected_candidate is None:
                raise FinsecError(
                    "No safe fresh authentication request was recommended; select a reviewed "
                    "candidate explicitly with --capture-auth --auth-candidate N."
                )
            console.print(
                f"Automatically selected recommended authentication request {selected_candidate}."
            )
        elif capture_auth and selected_candidate is None:
            if recommendation is None:
                raise FinsecError("Authentication recommendation is unavailable.")
            default_candidate = recommendation.recommended_number or 1
            selected_candidate = int(
                typer.prompt(
                    "Select replay authentication",
                    type=int,
                    default=default_candidate,
                )
            )
        result = ingest_har(
            har_file,
            paths,
            actor=actor,
            channel=_channel(channel),
            capture_auth=should_capture_auth,
            auth_candidate=selected_candidate,
            auth_observed_renewal=update_auth,
            capture_assignment=_direct_capture_assignment(
                actor,
                capture_mode,
                intent_action,
                intent_resource,
            ),
        )
    except FinsecError as error:
        _abort(error)
    console.print(
        f"[green]Imported {result.imported}[/green] observations "
        f"({result.skipped} already present, {result.total} total)."
    )
    if result.relabeled:
        console.print(f"[yellow]Refreshed {result.relabeled} actor/channel assignments.[/yellow]")
    console.print(f"Redacted HAR: {result.redacted_har}")
    if result.capture is not None:
        _print_capture_diagnostics(result.capture)
    if result.authentication_status is not None:
        console.print(f"Credential storage: successful ({result.credential_profile_ref})")
        console.print(f"Actor status: {result.authentication_status}")
    console.print(_offline_workflow_hint(paths))


def _run_ingest_wizard(paths: WorkspacePaths, context: _IngestWizardContext) -> None:
    """Run the shared interactive import flow for one validated capture directory."""

    target = context.target
    console.print(f"[bold]Capture input directory:[/bold] {context.incoming}")
    console.print("Configured actors: " + ", ".join(item.id for item in target.accounts))
    console.print("Use ANONYMOUS or UNKNOWN only when that provenance is accurate.")
    selections: list[_InteractiveCaptureImport] = []
    accounts = {item.id: item for item in target.accounts}

    for capture_file in context.capture_files:
        try:
            preview = preview_capture(capture_file, target)
        except FinsecError as error:
            console.print(f"[red]{escape(capture_file.name)} cannot be previewed:[/red] {error}")
            continue
        selected = _capture_selection(target, preview)
        if selected is None:
            continue
        actor, channel, assignment = selected
        auth_candidate: int | None = None
        observed_renewal = False
        account = accounts.get(actor)
        if account is not None and account.authenticated and account.actor_type != "anonymous":
            try:
                recommendation = (
                    recommend_har_authentication(paths, actor, capture_file)
                    if preview.source_type == CaptureSourceType.HAR
                    else recommend_burp_authentication(paths, actor, capture_file)
                )
            except FinsecError as error:
                console.print(f"[yellow]Authentication unchanged:[/yellow] {error}")
            else:
                console.print("[bold]Authentication candidates detected[/bold]")
                _print_authentication_recommendation(recommendation)
                if recommendation.recommended_number is not None and typer.confirm(
                    "Update this actor from the recommended authentication request?",
                    default=True,
                ):
                    auth_candidate = recommendation.recommended_number
                    authentication = account.authentication
                    observed_renewal = (
                        authentication is not None
                        and authentication.auth_type not in {"none", "unconfigured"}
                    )
        selections.append(
            _InteractiveCaptureImport(
                path=capture_file,
                source_type=preview.source_type,
                actor=actor,
                channel=channel,
                assignment=assignment,
                auth_candidate=auth_candidate,
                observed_renewal=observed_renewal,
            )
        )

    if not selections:
        console.print("No capture files were selected.")
        return

    summary = Table("File", "Actor", "Mode", "Intent", "Authentication")
    for selection in selections:
        authentication_summary = (
            f"recommended request {selection.auth_candidate}"
            if selection.auth_candidate is not None
            else "unchanged"
        )
        summary.add_row(
            selection.path.name,
            selection.actor,
            selection.assignment.capture_mode,
            _intent_text(selection.assignment.intent or CaptureIntent()),
            authentication_summary,
        )
    console.print(summary)
    if not typer.confirm("Import these capture files passively?", default=False):
        console.print("No capture files were imported.")
        return

    successful_assignments: list[WorkflowCapture] = []
    imported_any = False
    for selection in selections:
        try:
            result: Any
            if selection.source_type == CaptureSourceType.HAR:
                result = ingest_har(
                    selection.path,
                    paths,
                    actor=selection.actor,
                    channel=selection.channel,
                    capture_assignment=selection.assignment,
                )
            else:
                result = ingest_burp_xml(
                    selection.path,
                    paths,
                    actor=selection.actor,
                    channel=selection.channel,
                    capture_assignment=selection.assignment,
                )
        except (FinsecError, OSError, ValidationError) as error:
            console.print(f"[red]{escape(selection.path.name)} failed:[/red] {error}")
            continue
        imported_any = True
        successful_assignments.append(
            WorkflowCapture(
                file=selection.path.name,
                actor=selection.actor,
                channel=selection.channel,
                actor_source=selection.assignment.actor_source,
                capture_mode=selection.assignment.capture_mode,
                capture_mode_source=selection.assignment.capture_mode_source,
                intent=selection.assignment.intent,
            )
        )
        console.print(
            f"[green]{escape(selection.path.name)}:[/green] {result.imported} imported, "
            f"{result.skipped} already present"
        )
        if result.capture is not None:
            _print_capture_diagnostics(result.capture)
        if selection.auth_candidate is not None:
            try:
                authentication, _ = (
                    capture_from_har(
                        paths,
                        selection.actor,
                        selection.path,
                        candidate_number=selection.auth_candidate,
                        observed_renewal=selection.observed_renewal,
                    )
                    if selection.source_type == CaptureSourceType.HAR
                    else capture_from_burp(
                        paths,
                        selection.actor,
                        selection.path,
                        candidate_number=selection.auth_candidate,
                        observed_renewal=selection.observed_renewal,
                    )
                )
            except FinsecError as error:
                console.print(f"[red]Authentication update failed:[/red] {error}")
            else:
                console.print(
                    "[green]Authentication updated[/green] from recommended request "
                    f"{selection.auth_candidate}; actor status: {authentication.status}"
                )

    if successful_assignments:
        merge_workflow_assignments(context.manifest_path, successful_assignments)
        console.print(f"Workflow assignments updated: {context.manifest_path}")
    if imported_any and typer.confirm("Run the offline analysis workflow now?", default=False):
        run_offline_workflow(
            paths,
            manifest_path=context.manifest_path,
            progress=lambda message: console.print(f"[cyan]Workflow:[/cyan] {message}"),
        )
        console.print("[bold green]Offline analysis workflow completed.[/bold green]")
    elif imported_any:
        console.print(
            f"Run 'hunt workflow -w {paths.root} --manifest {context.manifest_path}' when ready."
        )


@app.command("ingest-wizard")
def ingest_wizard_command(
    workspace: WorkspaceOption = None,
    capture_root: Annotated[
        Path | None,
        typer.Option(
            "--capture-root",
            help="Capture directory containing incoming/ and workflow.yaml.",
        ),
    ] = None,
    include_assigned: Annotated[
        bool,
        typer.Option(
            "--include-assigned",
            help="Offer capture files already present in workflow.yaml for relabeling or renewal.",
        ),
    ] = False,
) -> None:
    """Import new HAR/Burp captures with minimal actor, mode, and intent context."""

    try:
        paths = resolve_workspace(workspace)
        context = _resolve_ingest_wizard_context(
            paths,
            capture_root,
            include_assigned=include_assigned,
        )
        if not context.capture_files:
            console.print("No unassigned capture files were found.")
            console.print(f"Add captures to {context.incoming} and run this command again.")
            return
        _run_ingest_wizard(paths, context)
    except (FinsecError, OSError, ValidationError) as error:
        _abort(error)


@app.command("ingest-burp")
def ingest_burp_command(
    xml_file: Annotated[Path, typer.Argument(help="Burp XML history export to import passively.")],
    workspace: WorkspaceOption = None,
    actor: Annotated[
        str,
        typer.Option("--actor", help="Non-secret account or actor label for these observations."),
    ] = "UNKNOWN",
    channel: Annotated[
        str,
        typer.Option("--channel", help="Observed client channel for these exchanges."),
    ] = "UNKNOWN",
    capture_mode: Annotated[
        str | None,
        typer.Option(
            "--capture-mode",
            help="NORMAL_BEHAVIOR, RESEARCHER_PROBE, AUTHENTICATION, MIXED, or UNKNOWN.",
        ),
    ] = None,
    intent_action: Annotated[
        str | None,
        typer.Option("--intent-action", help="High-level action such as CREATE or UPDATE."),
    ] = None,
    intent_resource: Annotated[
        str | None,
        typer.Option("--intent-resource", help="High-level resource such as dns_record."),
    ] = None,
    capture_auth: Annotated[
        bool,
        typer.Option(
            "--capture-auth", help="Detect and securely store authentication for --actor."
        ),
    ] = False,
    update_auth: Annotated[
        bool,
        typer.Option(
            "--update-auth",
            help=(
                "Recommend the freshest authentication-bearing Burp item and update --actor; "
                "implies --capture-auth."
            ),
        ),
    ] = False,
    auth_candidate: Annotated[
        int | None,
        typer.Option("--auth-candidate", help="1-based replay profile selection for automation."),
    ] = None,
) -> None:
    """Import a Burp XML history export as redacted observations."""

    try:
        paths = resolve_workspace(workspace)
        should_capture_auth = capture_auth or update_auth
        if auth_candidate is not None and not should_capture_auth:
            raise FinsecError("--auth-candidate requires --capture-auth or --update-auth.")
        if should_capture_auth and actor == "UNKNOWN":
            raise FinsecError("Authentication capture requires an explicitly configured actor.")
        selected_candidate = auth_candidate
        recommendation: AuthenticationRecommendation | None = None
        if should_capture_auth:
            recommendation = recommend_burp_authentication(paths, actor, xml_file)
            console.print("[bold]Authentication candidates detected[/bold]")
            _print_authentication_recommendation(recommendation)
        if update_auth and selected_candidate is None:
            selected_candidate = recommendation.recommended_number if recommendation else None
            if selected_candidate is None:
                raise FinsecError(
                    "No safe fresh authentication request was recommended; select a reviewed "
                    "candidate explicitly with --capture-auth --auth-candidate N."
                )
            console.print(
                f"Automatically selected recommended authentication request {selected_candidate}."
            )
        elif capture_auth and selected_candidate is None:
            if recommendation is None:
                raise FinsecError("Authentication recommendation is unavailable.")
            default_candidate = recommendation.recommended_number or 1
            selected_candidate = int(
                typer.prompt(
                    "Select replay authentication",
                    type=int,
                    default=default_candidate,
                )
            )
        result = ingest_burp_xml(
            xml_file,
            paths,
            actor=actor,
            channel=_channel(channel),
            capture_auth=should_capture_auth,
            auth_candidate=selected_candidate,
            auth_observed_renewal=update_auth,
            capture_assignment=_direct_capture_assignment(
                actor,
                capture_mode,
                intent_action,
                intent_resource,
            ),
        )
    except FinsecError as error:
        _abort(error)
    console.print(
        f"[green]Imported {result.imported}[/green] Burp observations "
        f"({result.skipped} already present, {result.total} total)."
    )
    if result.relabeled:
        console.print(f"[yellow]Refreshed {result.relabeled} actor/channel assignments.[/yellow]")
    console.print(f"Redacted capture: {result.redacted_capture}")
    if result.capture is not None:
        _print_capture_diagnostics(result.capture)
    if result.authentication_status is not None:
        console.print(f"Credential storage: successful ({result.credential_profile_ref})")
        console.print(f"Actor status: {result.authentication_status}")
    console.print(_offline_workflow_hint(paths))


@app.command("ingest-caido")
def ingest_caido_command(
    json_file: Annotated[Path, typer.Argument(help="Caido-style JSON export to import passively.")],
    workspace: WorkspaceOption = None,
    actor: Annotated[
        str,
        typer.Option("--actor", help="Non-secret account or actor label for these observations."),
    ] = "UNKNOWN",
    channel: Annotated[
        str,
        typer.Option("--channel", help="Observed client channel for these exchanges."),
    ] = "UNKNOWN",
    capture_mode: Annotated[
        str | None,
        typer.Option(
            "--capture-mode",
            help="NORMAL_BEHAVIOR, RESEARCHER_PROBE, AUTHENTICATION, MIXED, or UNKNOWN.",
        ),
    ] = None,
    intent_action: Annotated[
        str | None,
        typer.Option("--intent-action", help="High-level action such as CREATE or UPDATE."),
    ] = None,
    intent_resource: Annotated[
        str | None,
        typer.Option("--intent-resource", help="High-level resource such as dns_record."),
    ] = None,
) -> None:
    """Import a Caido-style JSON exchange export as redacted observations."""

    try:
        paths = resolve_workspace(workspace)
        result = ingest_caido_json(
            json_file,
            paths,
            actor=actor,
            channel=_channel(channel),
            capture_assignment=_direct_capture_assignment(
                actor,
                capture_mode,
                intent_action,
                intent_resource,
            ),
        )
    except FinsecError as error:
        _abort(error)
    console.print(
        f"[green]Imported {result.imported}[/green] Caido observations "
        f"({result.skipped} already present, {result.total} total)."
    )
    if result.relabeled:
        console.print(f"[yellow]Refreshed {result.relabeled} actor/channel assignments.[/yellow]")
    console.print(f"Redacted capture: {result.redacted_capture}")
    if result.capture is not None:
        _print_capture_diagnostics(result.capture)
    console.print(_offline_workflow_hint(paths))


@app.command("ingest-openapi")
def ingest_openapi_command(
    api_file: Annotated[Path, typer.Argument(help="OpenAPI or Swagger JSON/YAML document.")],
    workspace: WorkspaceOption = None,
    base_url: Annotated[
        str | None,
        typer.Option("--base-url", help="Absolute server URL when the document omits one."),
    ] = None,
    channel: Annotated[
        str,
        typer.Option("--channel", help="Documented API channel for these operations."),
    ] = "PUBLIC_API",
) -> None:
    """Import documented API operations without treating them as runtime confirmations."""

    try:
        paths = resolve_workspace(workspace)
        result = ingest_openapi(api_file, paths, base_url=base_url, channel=_channel(channel))
    except FinsecError as error:
        _abort(error)
    console.print(
        f"[green]Imported {result.imported}[/green] documented operations "
        f"({result.skipped} already present, {result.total} total observations)."
    )
    if result.relabeled:
        console.print(f"[yellow]Refreshed {result.relabeled} channel assignments.[/yellow]")
    console.print(f"Redacted document: {result.redacted_capture}")
    console.print("Runtime behavior remains unconfirmed.")
    console.print(_offline_workflow_hint(paths))


@app.command("ingest-graphql")
def ingest_graphql_command(
    schema_file: Annotated[
        Path, typer.Argument(help="GraphQL SDL or introspection JSON document.")
    ],
    workspace: WorkspaceOption = None,
    endpoint: Annotated[
        str | None,
        typer.Option(
            "--endpoint", help="Optional absolute HTTP(S) endpoint associated with schema."
        ),
    ] = None,
) -> None:
    """Inventory GraphQL root fields from supplied schema evidence."""

    try:
        paths = resolve_workspace(workspace)
        result = ingest_graphql(schema_file, paths, endpoint=endpoint)
    except FinsecError as error:
        _abort(error)
    console.print(
        f"[green]GraphQL inventory contains {result.operations} operations[/green] "
        f"({result.added} added, {result.updated} refreshed)."
    )
    console.print(f"Inventory: {result.inventory_path}")
    console.print(f"Redacted schema evidence: {result.redacted_capture}")
    if result.conflicts:
        console.print(
            "[yellow]Preserved researcher-edited GraphQL records:[/yellow] "
            + ", ".join(result.conflicts)
        )
    console.print(
        "Schema presence does not confirm endpoint reachability or authorization behavior."
    )


@app.command("scan-mobile")
def scan_mobile_command(
    artifact: Annotated[
        Path, typer.Argument(help="Authorized APK, file, or static analysis directory.")
    ],
    workspace: WorkspaceOption = None,
) -> None:
    """Extract bounded static mobile architecture leads without executing an app."""

    try:
        paths = resolve_workspace(workspace)
        result = scan_mobile(artifact, paths)
    except FinsecError as error:
        _abort(error)
    console.print(
        f"[green]Mobile inventory contains {result.discoveries} discoveries[/green] "
        f"from {result.files_scanned} files ({result.added} added, {result.updated} refreshed)."
    )
    console.print(f"Inventory: {result.inventory_path}")
    if result.conflicts:
        console.print(
            "[yellow]Preserved researcher-edited mobile records:[/yellow] "
            + ", ".join(result.conflicts)
        )
    console.print("Static strings are architecture leads; backend behavior remains unconfirmed.")


@app.command("inventory")
def inventory_command(workspace: WorkspaceOption = None) -> None:
    """Build a conservative, evidence-linked endpoint inventory."""

    try:
        paths = resolve_workspace(workspace)
        result = build_inventory(paths)
    except FinsecError as error:
        _abort(error)
    console.print(
        f"[green]Inventory contains {result.endpoints} endpoints[/green] "
        f"from {result.observations} observations."
    )
    console.print("Run 'hunt model' to build the evidence-backed domain model.")


@app.command("classify")
def classify_command(workspace: WorkspaceOption = None) -> None:
    """Show deterministic endpoint classifications and dispositions."""

    try:
        paths = resolve_workspace(workspace)
        build_inventory(paths)
        endpoints = EndpointStore.model_validate(load_yaml(paths.endpoints))
    except (FinsecError, OSError, ValidationError) as error:
        _abort(error)
    table = Table(show_lines=False)
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("Classification")
    table.add_column("Relevance", justify="right")
    table.add_column("Disposition")
    table.add_column("Endpoint")
    for endpoint in endpoints.endpoints:
        table.add_row(
            endpoint.id,
            endpoint.classification.primary,
            str(endpoint.security_relevance),
            endpoint.disposition,
            f"{endpoint.method} {endpoint.path}",
        )
    console.print(table)


@app.command("noise")
def noise_command(workspace: WorkspaceOption = None) -> None:
    """Summarize suppressed traffic and normalization anomalies."""

    try:
        paths = resolve_workspace(workspace)
        endpoints = EndpointStore.model_validate(load_yaml(paths.endpoints))
    except (FinsecError, OSError, ValidationError) as error:
        _abort(error)
    suppressed = [item for item in endpoints.endpoints if item.disposition != "ACTIVE"]
    counts: dict[str, int] = {}
    for endpoint in suppressed:
        counts[endpoint.disposition] = counts.get(endpoint.disposition, 0) + 1
    console.print(f"[bold]Suppressed endpoint families:[/bold] {len(suppressed)}")
    for disposition, count in sorted(counts.items()):
        console.print(f"{disposition}: {count}")
    anomalies = [
        item
        for item in endpoints.endpoints
        if any("opaque" in rule for rule in item.normalization.rules) and item.confidence == "low"
    ]
    console.print(f"Normalization anomalies requiring review: {len(anomalies)}")


@app.command("explain")
def explain_endpoint_command(
    endpoint_id: Annotated[str, typer.Argument(help="Endpoint ID such as EP-001.")],
    workspace: WorkspaceOption = None,
) -> None:
    """Explain one endpoint's classification, action, and relevance."""

    try:
        paths = resolve_workspace(workspace)
        endpoints = EndpointStore.model_validate(load_yaml(paths.endpoints))
    except (FinsecError, OSError, ValidationError) as error:
        _abort(error)
    endpoint = next((item for item in endpoints.endpoints if item.id == endpoint_id), None)
    if endpoint is None:
        _abort(FinsecError(f"Endpoint not found: {endpoint_id}"))
    details = [
        f"[bold]Classification:[/bold] {endpoint.classification.primary}",
        f"[bold]Tags:[/bold] {', '.join(endpoint.classification.tags) or 'None'}",
        f"[bold]Resource:[/bold] {endpoint.resource.type}",
        f"[bold]Action:[/bold] {endpoint.action.name} ({endpoint.action.type})",
        f"[bold]State changing:[/bold] {endpoint.state_change}",
        f"[bold]Security relevance:[/bold] {endpoint.security_relevance}/10",
        f"[bold]Disposition:[/bold] {endpoint.disposition}",
        "",
        "[bold]Reasons[/bold]",
        "\n".join(
            f"- {item}"
            for item in [
                *endpoint.classification.reasons,
                *endpoint.action.reasons,
                *endpoint.relevance_reasons,
            ]
        ),
    ]
    observed_bindings = [
        item for item in endpoint.object_access if item.actor_object_binding_observed
    ]
    if observed_bindings:
        details.extend(["", "[bold]Ownership evidence[/bold]"])
        for binding in observed_bindings:
            label = (
                "controlled parent-scope baseline"
                if binding.source == "PATH_PARENT_SCOPE"
                else "response-body object/owner binding"
            )
            details.extend(
                [
                    f"- Evidence: {label}",
                    f"- Parameter: {binding.identifier}",
                    f"- Controlled actors: {binding.distinct_actors}",
                    (
                        f"- Distinct scoped values: {binding.distinct_scope_values}"
                        if binding.source == "PATH_PARENT_SCOPE"
                        else f"- Distinct owner values: {binding.distinct_owner_values}"
                    ),
                    "- Execution template evidence: OBJECT_SUBSTITUTION",
                ]
            )
    if endpoint.ownership_inference:
        details.extend(["", "[bold]Parent-scope inference[/bold]"])
        for decision in endpoint.ownership_inference:
            details.append(f"- {decision.parameter}: {decision.status} ({decision.classification})")
            details.extend(f"  - {reason}" for reason in decision.reasons)
    console.print(
        Panel("\n".join(details), title=f"{endpoint.id}: {endpoint.method} {endpoint.path}")
    )


@workflows_app.command("build")
def workflows_build_command(workspace: WorkspaceOption = None) -> None:
    """Reconstruct workflow instances, families, states, transitions, and graphs offline."""

    try:
        paths = resolve_workspace(workspace)
        result = build_behavior_model(paths)
    except FinsecError as error:
        _abort(error)
    console.print(
        f"[green]Built {result.workflow_instances} workflow instances in "
        f"{result.workflow_families} families.[/green]"
    )
    console.print(
        f"Actions: {result.actions}; resources: {result.resource_instances}; "
        f"transitions: {result.transitions}; propagation links: {result.propagation_links}."
    )
    if result.suppressed_noise:
        console.print(
            f"[dim]Suppressed {result.suppressed_noise} repeated polling/background "
            "observations from workflow paths.[/dim]"
        )
    console.print(f"Artifacts: {paths.root / 'behavior'}")


@workflows_app.command("list")
def workflows_list_command(workspace: WorkspaceOption = None) -> None:
    """List reconstructed workflow families without changing artifacts."""

    try:
        paths = resolve_workspace(workspace)
        families = load_workflow_families(paths).workflow_families
    except FinsecError as error:
        _abort(error)
    table = Table("ID", "Name", "Instances", "Confidence", "Common path")
    for family in sorted(families, key=lambda item: item.id):
        table.add_row(
            family.id,
            family.name,
            str(len(family.workflow_instance_ids)),
            family.inference_confidence,
            " -> ".join(family.common_path) or "Unresolved",
        )
    console.print(
        table if families else "No workflow families are available. Run 'hunt workflows build'."
    )


def _workflow_panel(paths: WorkspacePaths, workflow_id: str) -> Panel:
    family = find_workflow_family(paths, workflow_id)
    propagation = load_propagation(paths)
    instances = [
        item
        for item in load_workflow_instances(paths).workflow_instances
        if item.family_id == family.id
    ]
    lines = [
        f"[bold]Status:[/bold] {family.epistemic_status}",
        f"[bold]Confidence:[/bold] {family.inference_confidence}",
        f"[bold]Instances:[/bold] {', '.join(family.workflow_instance_ids)}",
        f"[bold]Actors:[/bold] {', '.join(family.actors) or 'UNKNOWN'}",
        f"[bold]Resources:[/bold] {', '.join(family.resource_types) or 'Unresolved'}",
        f"[bold]Common path:[/bold] {' -> '.join(family.common_path) or 'Unresolved'}",
        f"[bold]Required-looking:[/bold] {', '.join(family.required_looking_steps) or 'None'}",
        f"[bold]Optional:[/bold] {', '.join(family.optional_steps) or 'None'}",
        f"[bold]Branches:[/bold] {', '.join(family.branch_points) or 'None'}",
        "",
        "[bold]Inference explanation[/bold]",
        *[f"- {item}" for item in family.confidence_explanation],
        "",
        "[bold]Causal prerequisites[/bold]",
        *[
            f"- {item.prerequisite_action} -> {item.dependent_action} "
            f"(basis: {', '.join(value.value for value in item.causal_bases) or 'unavailable'})"
            for item in family.causal_prerequisites
        ],
        "",
        "[bold]Instance ambiguity[/bold]",
    ]
    if not family.causal_prerequisites:
        lines.insert(-2, "- None recorded.")
    ambiguous = [f"{item.id}: {reason}" for item in instances for reason in item.ambiguities]
    lines.extend(f"- {item}" for item in ambiguous or ["None recorded."])
    if propagation.version == 1 or any(
        link.causal_basis.value == "LEGACY_UNTYPED" for link in propagation.propagation_links
    ):
        lines.extend(
            [
                "",
                "[bold yellow]Legacy compatibility warning[/bold yellow]",
                "- Untyped v1 propagation is display-only and cannot merge workflows.",
                "- Rebuild from factual observations to obtain v2 typed producer evidence.",
            ]
        )
    return Panel("\n".join(lines), title=f"{family.id}: {family.name}")


@workflows_app.command("show")
def workflows_show_command(
    workflow_id: Annotated[str, typer.Argument(help="Workflow family ID such as WFAM-...")],
    workspace: WorkspaceOption = None,
) -> None:
    """Show one workflow family and its evidence basis."""

    try:
        paths = resolve_workspace(workspace)
        panel = _workflow_panel(paths, workflow_id)
    except FinsecError as error:
        _abort(error)
    console.print(panel)


@workflows_app.command("explain")
def workflows_explain_command(
    workflow_id: Annotated[str, typer.Argument(help="Workflow family ID such as WFAM-...")],
    workspace: WorkspaceOption = None,
) -> None:
    """Explain why one workflow family exists and where uncertainty remains."""

    workflows_show_command(workflow_id, workspace)


@workflows_app.command("graph")
def workflows_graph_command(
    workflow_id: Annotated[str, typer.Argument(help="Workflow family ID such as WFAM-...")],
    workspace: WorkspaceOption = None,
    output_format: Annotated[
        str,
        typer.Option("--format", help="Graph output: text, json, dot, or mermaid."),
    ] = "text",
) -> None:
    """Render one workflow graph as text, JSON, DOT, or Mermaid."""

    try:
        paths = resolve_workspace(workspace)
        graph = load_workflow_graph(paths, workflow_id)
        output = render_graph(graph, output_format)
    except (FinsecError, ValueError) as error:
        _abort(error)
    console.print(output, markup=False)


@logic_app.command("analyze")
def logic_analyze_command(workspace: WorkspaceOption = None) -> None:
    """Infer business invariants and workflow mutations without contacting the target."""

    try:
        paths = resolve_workspace(workspace)
        result = analyze_business_logic(paths)
    except FinsecError as error:
        _abort(error)
    console.print(
        f"[green]Generated {result.business_invariants} business invariants, "
        f"{result.hypotheses} plausible logic hypotheses, and "
        f"{result.research_tasks} research tasks.[/green]"
    )
    console.print(f"Ready for planning without current blockers: {result.ready_for_planning}")
    console.print(f"Rejected by semantic eligibility gates: {result.rejected_mutations}")
    console.print(
        f"Canonical clusters: {result.clusters}; visible research items: "
        f"{result.visible_research_items}; presentation-suppressed candidates: "
        f"{result.suppressed_candidates}."
    )
    console.print("Offline analysis did not confirm any vulnerability or send any request.")
    if result.conflicts:
        console.print(
            "[yellow]Preserved researcher-edited backlog records:[/yellow] "
            + ", ".join(result.conflicts)
        )


@logic_app.command("hypotheses")
def logic_hypotheses_command(
    workspace: WorkspaceOption = None,
    research_tasks: Annotated[
        bool,
        typer.Option("--research-tasks", help="Show under-evidenced or unsafe research tasks."),
    ] = False,
    all_candidates: Annotated[
        bool,
        typer.Option("--all-candidates", help="Show retained raw BLH provenance records."),
    ] = False,
    show_support: Annotated[
        bool,
        typer.Option("--show-support", help="Show cluster membership and support counts."),
    ] = False,
    show_suppressed: Annotated[
        bool,
        typer.Option(
            "--show-suppressed",
            help="Include low-priority and semantically suppressed clusters.",
        ),
    ] = False,
) -> None:
    """List canonical business-logic questions or retained raw candidates."""

    try:
        paths = resolve_workspace(workspace)
        store = load_logic_presentation(paths)
    except FinsecError as error:
        _abort(error)
    if all_candidates:
        selected_records = [
            item for item in store.hypotheses if (item.kind == "RESEARCH_TASK") == research_tasks
        ]
        table = Table("BLH ID", "Canonical ID", "Family", "Readiness", "Promotion", "Title")
        for item in sorted(selected_records, key=lambda value: value.id):
            semantics = item.semantics
            qualification = item.qualification
            table.add_row(
                item.id,
                semantics.canonical_id if semantics is not None else "legacy",
                item.family,
                item.readiness,
                qualification.promotion if qualification is not None else "legacy",
                item.title,
            )
        console.print(
            table if selected_records else "No matching business-logic records are available."
        )
        return

    by_id = {item.id: item for item in store.hypotheses}
    clusters = rank_hypothesis_clusters(
        store.clusters,
        include_suppressed=show_suppressed,
        include_low=show_suppressed,
    )
    selected_clusters = [
        cluster
        for cluster in clusters
        if (
            by_id.get(cluster.representative_hypothesis_id) is not None
            and (by_id[cluster.representative_hypothesis_id].kind == "RESEARCH_TASK")
            == research_tasks
        )
    ]
    table = Table(
        "Canonical ID",
        "Promotion",
        "Confidence",
        "Readiness",
        "Support",
        "Title",
    )
    for cluster in selected_clusters:
        table.add_row(
            cluster.id,
            cluster.promotion,
            cluster.hypothesis_confidence,
            cluster.readiness,
            f"{cluster.independent_support_count}/{cluster.context_count}",
            cluster.title,
        )
    console.print(
        table if selected_clusters else "No matching business-logic records are available."
    )
    if show_support:
        for cluster in selected_clusters:
            console.print(
                f"\n[bold]{cluster.id} support[/bold]: "
                f"members {', '.join(cluster.member_hypothesis_ids)}; "
                f"workflows {', '.join(cluster.workflow_family_ids)}; "
                f"independent {cluster.independent_support_count}."
            )


def _logic_panel(paths: WorkspacePaths, hypothesis_id: str) -> Panel:
    store = load_logic_presentation(paths)
    cluster = None
    if hypothesis_id.upper().startswith("HCL-"):
        cluster = find_logic_cluster(paths, hypothesis_id)
        item = next(
            value for value in store.hypotheses if value.id == cluster.representative_hypothesis_id
        )
    else:
        item = find_logic_hypothesis(paths, hypothesis_id)
        cluster = next(
            (value for value in store.clusters if item.id in value.member_hypothesis_ids),
            None,
        )
    score = item.score
    lines = [
        *(
            [
                f"[bold]Canonical ID:[/bold] {cluster.id}",
                f"[bold]Canonical security question:[/bold] {cluster.title}",
                f"[bold]Promotion:[/bold] {cluster.promotion}",
                f"[bold]Security confidence:[/bold] {cluster.hypothesis_confidence}",
                f"[bold]Evidence strength:[/bold] {cluster.evidence_strength}",
                f"[bold]Support:[/bold] {cluster.independent_support_count} independent / "
                f"{cluster.context_count} provenance context(s)",
                f"[bold]Member BLHs:[/bold] {', '.join(cluster.member_hypothesis_ids)}",
                "",
            ]
            if cluster is not None
            else []
        ),
        f"[bold]Epistemic status:[/bold] {item.epistemic_status}",
        f"[bold]Readiness:[/bold] {item.readiness}",
        f"[bold]Protected subject:[/bold] {item.domain_intent.subject_resource}",
        f"[bold]Parent/context:[/bold] {item.domain_intent.parent_resource or 'None'}",
        f"[bold]Operation:[/bold] {item.domain_intent.operation}",
        f"[bold]Visibility / binding:[/bold] {item.domain_intent.visibility} / "
        f"{item.domain_intent.binding}",
        f"[bold]Claim strength:[/bold] {item.claim_strength.current_level} -> "
        f"{item.claim_strength.target_level}",
        f"[bold]Common cluster / campaign:[/bold] {item.grouping.cluster_id or 'None'} / "
        f"{item.grouping.campaign_id or 'None'} ({item.grouping.relationship})",
        f"[bold]Family:[/bold] {item.family}",
        f"[bold]Workflow:[/bold] {item.workflow_family_id}",
        f"[bold]Invariant:[/bold] {item.invariant_statement}",
        f"[bold]Canonical behavior:[/bold] {item.canonical_behavior}",
        f"[bold]Mutated behavior:[/bold] {item.mutated_behavior}",
        f"[bold]Expected secure outcome:[/bold] {item.expected_secure_outcome}",
        f"[bold]Expected vulnerable outcome:[/bold] {item.expected_vulnerable_outcome}",
        f"[bold]Safety:[/bold] {item.safety_classification}",
        f"[bold]Request budget:[/bold] {item.estimated_request_budget}",
        "",
        "[bold]Scores[/bold]",
        f"- Likelihood: {score.likelihood}",
        f"- Impact: {score.impact}",
        f"- Test readiness: {score.test_readiness}",
        f"- Safety cost: {score.safety_cost}",
        f"- Confidence: {score.confidence}",
        *[f"- {part.points:+d}: {part.reason}" for part in score.breakdown],
        "",
        "[bold]Supporting evidence[/bold]",
        *[f"- {value}" for value in item.supporting_evidence],
        "",
        "[bold]Contradicting evidence[/bold]",
        *[f"- {value}" for value in item.contradicting_evidence or ["None recorded."]],
        "",
        "[bold]Uncertainty[/bold]",
        *[f"- {value}" for value in item.uncertainty],
        *[f"- {value}" for value in item.domain_intent.ambiguity],
        "",
        "[bold]Categorized readiness blockers[/bold]",
        *[
            f"- {blocker.stage}/{blocker.code}: {blocker.summary}"
            for blocker in item.readiness_assessment.blockers
        ],
        "",
        "[bold]Approval and execution gates[/bold]",
        *[
            f"- {warning.stage}/{warning.code}: {warning.summary}"
            for warning in item.readiness_assessment.warnings
        ],
    ]
    if item.qualification is not None:
        evidence = item.qualification.evidence.model_dump(mode="json")
        lines.extend(
            [
                "",
                "[bold]Evidence predicates[/bold]",
                *[
                    f"- {name.replace('_', ' ')}: {str(value).lower()}"
                    for name, value in evidence.items()
                ],
                "",
                "[bold]Qualification[/bold]",
                *[f"- {value}" for value in item.qualification.qualification_reasons],
            ]
        )
    if cluster is not None:
        lines.extend(
            [
                "",
                "[bold]Ranking rationale[/bold]",
                *[f"- {value}" for value in cluster.ranking_reasons],
                "",
                "[bold]Supporting contexts[/bold]",
                *[
                    f"- {context.hypothesis_id}: workflow {context.workflow_family_id}; "
                    f"instances {len(context.workflow_instance_ids)}; invariant "
                    f"{context.invariant_id}; observations {len(context.observation_ids)}; "
                    f"readiness {context.readiness}"
                    for context in cluster.support_contexts
                ],
            ]
        )
        if cluster.suppression_reasons:
            lines.extend(
                [
                    "",
                    "[bold]Suppressed[/bold]",
                    *[f"- {value}" for value in cluster.suppression_reasons],
                ]
            )
    return Panel("\n".join(lines), title=f"{item.id}: {item.title}")


@logic_app.command("explain")
def logic_explain_command(
    hypothesis_id: Annotated[str, typer.Argument(help="Business-logic ID such as BLH-...")],
    workspace: WorkspaceOption = None,
) -> None:
    """Explain one business-logic hypothesis, score, evidence, and uncertainty."""

    try:
        paths = resolve_workspace(workspace)
        panel = _logic_panel(paths, hypothesis_id)
    except FinsecError as error:
        _abort(error)
    console.print(panel)


@logic_app.command("blockers")
def logic_blockers_command(
    hypothesis_id: Annotated[str, typer.Argument(help="Business-logic ID such as BLH-...")],
    workspace: WorkspaceOption = None,
) -> None:
    """Show deterministic readiness blockers and evidence requirements."""

    try:
        paths = resolve_workspace(workspace)
        item = find_logic_hypothesis(paths, hypothesis_id)
    except FinsecError as error:
        _abort(error)
    console.print(f"[bold]{item.id}: {item.title}[/bold]")
    console.print(f"[bold]Readiness:[/bold] {item.readiness}")
    console.print("\n[bold]Readiness blockers[/bold]")
    if item.readiness_assessment.blockers:
        for blocker in item.readiness_assessment.blockers:
            console.print(f"- {blocker.stage}/{blocker.code}: {blocker.summary}")
    else:
        console.print("- None recorded.")
    console.print("\n[bold]Approval and execution gates[/bold]")
    if item.readiness_assessment.warnings:
        for warning in item.readiness_assessment.warnings:
            console.print(f"- {warning.stage}/{warning.code}: {warning.summary}")
    else:
        console.print("- None recorded.")
    console.print("\n[bold]State evidence required[/bold]")
    for requirement in item.state_evidence_requirements:
        console.print(f"- {requirement}")
    console.print("\nThis explanation does not grant execution authority.")


@logic_app.command("plan")
def logic_plan_command(
    hypothesis_id: Annotated[str, typer.Argument(help="Business-logic ID such as BLH-...")],
    workspace: WorkspaceOption = None,
) -> None:
    """Route one active logic hypothesis through the existing safe planner."""

    try:
        paths = resolve_workspace(workspace)
        resolved = find_logic_hypothesis(paths, hypothesis_id)
    except FinsecError as error:
        _abort(error)
    plan_command(resolved.id, paths.root)


@app.command("model")
def model_command(workspace: WorkspaceOption = None) -> None:
    """Build actors, resources, authorization views, and workflow maps."""

    try:
        paths = resolve_workspace(workspace)
        result = generate_model(paths)
    except FinsecError as error:
        _abort(error)
    console.print(
        f"[green]Modeled {result.actors} actors, {result.resources} resources, "
        f"and {result.workflows} workflows.[/green]"
    )
    if result.conflicts:
        console.print(
            "[yellow]Preserved researcher-edited records:[/yellow] " + ", ".join(result.conflicts)
        )
    console.print("Run 'hunt invariants' to extract traceable security properties.")


@app.command("invariants")
def invariants_command(workspace: WorkspaceOption = None) -> None:
    """Extract endpoint-specific security invariants without confirming them."""

    try:
        paths = resolve_workspace(workspace)
        result = generate_invariants(paths)
    except FinsecError as error:
        _abort(error)
    console.print(f"[green]Generated {result.invariants} invariants.[/green]")
    if result.conflicts:
        console.print(
            "[yellow]Preserved researcher-edited invariants:[/yellow] "
            + ", ".join(result.conflicts)
        )
    console.print("Run 'hunt hypotheses' to build the prioritized research backlog.")


@app.command("hypotheses")
def hypotheses_command(
    workspace: WorkspaceOption = None,
    priority: Annotated[
        str | None,
        typer.Option("--priority", help="Show only P1, P2, or P3 hypotheses."),
    ] = None,
    include_suppressed: Annotated[
        bool,
        typer.Option("--include-suppressed", help="Include suppressed candidates."),
    ] = False,
    research_tasks: Annotated[
        bool,
        typer.Option("--research-tasks", help="Show research tasks instead of hypotheses."),
    ] = False,
    explain: Annotated[
        str | None,
        typer.Option("--explain", help="Explain one hypothesis by ID."),
    ] = None,
    campaigns: Annotated[
        bool,
        typer.Option("--campaigns", help="List deterministic cross-generator campaigns."),
    ] = False,
) -> None:
    """Generate and display a prioritized, evidence-backed hypothesis backlog."""

    selected_priority = priority.upper() if priority else None
    if selected_priority not in {None, "P1", "P2", "P3"}:
        _abort(FinsecError("Priority must be P1, P2, or P3."))
    try:
        paths = resolve_workspace(workspace)
        result = generate_hypotheses(paths)
        stored = load_hypotheses(paths)
        stored_hypotheses = stored.hypotheses
    except FinsecError as error:
        _abort(error)
    if campaigns:
        table = Table("Campaign", "Relationship", "Members", "Services", "Primary", "Title")
        for campaign in stored.campaigns:
            table.add_row(
                campaign.id,
                campaign.relationship,
                str(len(campaign.member_ids)),
                ", ".join(campaign.target_services) or "unknown",
                campaign.primary_hypothesis_id,
                campaign.title,
            )
        console.print(table if stored.campaigns else "No multi-record campaigns are available.")
        return
    selected_campaign: HypothesisCampaign | None = None
    if explain:
        explained_id = explain
        if explain.upper().startswith("HCMP-"):
            selected_campaign = next(
                (item for item in stored.campaigns if item.id == explain.upper()), None
            )
            if selected_campaign is None:
                _abort(FinsecError(f"Hypothesis campaign not found: {explain}"))
            explained_id = selected_campaign.primary_hypothesis_id
        if explain.upper().startswith("HCL-"):
            try:
                explained_id = find_logic_cluster(paths, explain).representative_hypothesis_id
            except FinsecError as error:
                _abort(error)
        hypotheses = [item for item in stored_hypotheses if item.id == explained_id]
    elif research_tasks:
        hypotheses = _canonical_backlog_presentation(
            paths,
            stored_hypotheses,
            include_suppressed=include_suppressed,
        )
        hypotheses = [
            item
            for item in hypotheses
            if item.kind == "RESEARCH_TASK"
            and (include_suppressed or not item.disposition.startswith("SUPPRESSED_"))
        ]
    else:
        hypotheses = _canonical_backlog_presentation(
            paths,
            stored_hypotheses,
            include_suppressed=include_suppressed,
        )
        hypotheses = [
            item
            for item in hypotheses
            if item.kind == "SECURITY_HYPOTHESIS"
            and (include_suppressed or item.disposition == "ACTIVE")
        ]
    hypotheses = sorted(
        (
            item
            for item in hypotheses
            if selected_priority is None or item.priority == selected_priority
        ),
        key=lambda item: ({"P1": 0, "P2": 1, "P3": 2}[item.priority], -item.scores.total, item.id),
    )
    population = hypothesis_population(stored_hypotheses)
    active_count = len(population.visible_active_hypotheses)
    task_count = len(population.visible_research_tasks)
    console.print(
        f"[green]Backlog contains {active_count} active hypotheses and "
        f"{task_count} research tasks.[/green]"
    )
    if result.conflicts:
        console.print(
            "[yellow]Preserved researcher-edited hypotheses:[/yellow] "
            + ", ".join(result.conflicts)
        )
    if hypotheses:
        console.print(_hypothesis_table(hypotheses))
        if explain and explain.upper().startswith("HCL-"):
            console.print(_logic_panel(paths, explain))
        elif explain and len(hypotheses) == 1:
            item = hypotheses[0]
            intent = item.domain_intent
            readiness = item.readiness_assessment
            target = item.mutation_target
            semantics = target.semantics
            console.print("\n[bold]Object semantics and ownership[/bold]")
            console.print(
                f"- Mutation target: {target.parameter or 'None'}; location: "
                f"{target.location or 'None'}; JSON path: {target.json_path or 'None'}; endpoints: "
                f"{', '.join(target.endpoint_ids) or 'None'}"
            )
            console.print(
                f"- Semantic class: {semantics.semantic_class}; resource role: "
                f"{semantics.resource_role}; resource: {semantics.resource_type or 'Unknown'}; "
                f"parent: {semantics.parent_resource_type or 'None'}"
            )
            console.print(
                f"- Ownership: {semantics.ownership_state}; classifier confidence: "
                f"{semantics.confidence}; expected relationship: "
                f"{target.expected_authorization_relationship}"
            )
            console.print(f"- Explanation: {semantics.explanation}")
            for semantic_evidence in semantics.evidence:
                console.print(f"- Ownership evidence: {semantic_evidence}")
            for semantic_counterevidence in semantics.counterevidence:
                console.print(f"- Counterevidence: {semantic_counterevidence}")
            if semantics.sources:
                console.print(f"- Semantic sources: {', '.join(semantics.sources)}")
            console.print("\n[bold]Ranking rationale[/bold]")
            console.print(
                f"- Priority: {item.priority}; total score: {item.scores.total} "
                f"(impact {item.scores.impact}, likelihood {item.scores.likelihood}, "
                f"confidence {item.scores.confidence}, testability {item.scores.testability})"
            )
            for rationale in item.priority_rationale:
                console.print(f"- {rationale}")
            if semantics.counterevidence:
                console.print("- Semantic counterevidence lowers the likelihood score.")
            console.print("\n[bold]Resolved domain intent[/bold]")
            console.print(
                f"- Subject: {intent.subject_resource}; parent: "
                f"{intent.parent_resource or 'None'}; operation: {intent.operation}"
            )
            console.print(f"- Visibility: {intent.visibility}; binding: {intent.binding}")
            for evidence in intent.positive_evidence:
                console.print(
                    f"- Supports: {evidence.reference} ({evidence.source}) - {evidence.detail}"
                )
            for evidence in intent.counterevidence:
                console.print(
                    f"- Counterevidence: {evidence.reference} ({evidence.source}) - "
                    f"{evidence.detail}"
                )
            for ambiguity in intent.ambiguity:
                console.print(f"- Ambiguity: {ambiguity}")
            console.print("\n[bold]Claim strength[/bold]")
            console.print(
                f"- Current: {item.claim_strength.current_level}; "
                f"bounded target: {item.claim_strength.target_level}"
            )
            console.print(f"- {item.claim_strength.explanation}")
            for requirement in item.claim_strength.upgrade_requirements:
                console.print(f"- Upgrade evidence: {requirement}")
            console.print("\n[bold]Unified readiness[/bold]")
            console.print(f"- Decision: {readiness.readiness}")
            for reason in readiness.reasons:
                console.print(f"- {reason}")
            for missing in readiness.missing_prerequisites:
                console.print(f"- Missing prerequisite: {missing}")
            for blocker in readiness.blockers:
                console.print(f"- Blocker [{blocker.stage}/{blocker.code}]: {blocker.summary}")
                if blocker.next_action is not None:
                    console.print(f"  Next action: {blocker.next_action}")
            coverage = readiness.comparison_coverage
            if coverage.required_distinct_actors:
                console.print(
                    "- Comparison coverage: "
                    f"{coverage.observed_distinct_actors}/"
                    f"{coverage.required_distinct_actors} actors; "
                    f"{coverage.distinct_controlled_objects} distinct object(s)."
                )
                if coverage.baseline_actor_ids:
                    console.print("- Baseline actors: " + ", ".join(coverage.baseline_actor_ids))
                if coverage.missing_actor_ids:
                    console.print(
                        "- Missing baseline actors: " + ", ".join(coverage.missing_actor_ids)
                    )
            for warning in readiness.warnings:
                console.print(f"- Gate [{warning.stage}/{warning.code}]: {warning.summary}")
            grouping = item.grouping
            console.print("\n[bold]Cluster and campaign[/bold]")
            console.print(
                f"- Cluster: {grouping.cluster_id or 'None'}; campaign: "
                f"{grouping.campaign_id or 'None'}; relationship: {grouping.relationship}"
            )
            grouping_members = grouping.campaign_member_ids or grouping.cluster_member_ids
            console.print(
                f"- Primary: {grouping.primary_hypothesis_id or item.id}; members: "
                f"{', '.join(grouping_members) or item.id}"
            )
            console.print("\n[bold]Suppression and distinction[/bold]")
            console.print(f"- Visible: {str(item.presentation.visible).lower()}")
            if item.presentation.suppression_reason is not None:
                console.print(f"- Suppression reason: {item.presentation.suppression_reason}")
            for reason in item.presentation.retention_reasons:
                console.print(f"- Retained: {reason}")
            for reason in item.presentation.difference_reasons:
                console.print(f"- Distinct: {reason}")
            if selected_campaign is not None:
                console.print("\n[bold]Campaign details[/bold]")
                console.print(f"- Title: {selected_campaign.title}")
                console.print(
                    f"- Services: {', '.join(selected_campaign.target_services) or 'Unknown'}"
                )
                console.print(
                    "- Authentication schemes: "
                    f"{', '.join(selected_campaign.authentication_schemes) or 'Unknown'}"
                )
                console.print(
                    f"- Endpoints: {', '.join(selected_campaign.affected_endpoints) or 'None'}"
                )
                console.print(
                    f"- Resources: {', '.join(selected_campaign.affected_resources) or 'None'}"
                )
                for setup_item in selected_campaign.shared_setup:
                    console.print(f"- Shared setup: {setup_item}")
                for distinction in selected_campaign.distinctions:
                    console.print(f"- Distinction: {distinction}")
                for control in selected_campaign.missing_controls:
                    console.print(f"- Missing control: {control}")
                console.print(f"- Next action: {selected_campaign.next_action}")
            console.print("\n[bold]Eligibility evidence[/bold]")
            console.print(
                "\n".join(f"- {value}" for value in item.eligibility_evidence) or "- None"
            )
            console.print("\n[bold]Missing evidence[/bold]")
            console.print("\n".join(f"- {value}" for value in item.missing_evidence) or "- None")
            console.print(
                f"\nGeneration rule: {item.generation_rule.get('id', 'UNKNOWN')} "
                f"v{item.generation_rule.get('version', '?')}"
            )
            if item.kind == "SECURITY_HYPOTHESIS" and item.disposition == "ACTIVE":
                alignment = inspect_plan_alignment(paths, item.id)
                console.print("\n[bold]Planner agreement[/bold]")
                console.print(
                    f"- Planner status: {alignment.plan_status}; agrees: "
                    f"{str(alignment.agrees).lower()}"
                )
                if alignment.violation is not None:
                    console.print(f"- Invariant violation: {alignment.violation}")
    else:
        console.print("No hypotheses match the selected priority.")


@app.command("show")
def show_command(
    hypothesis_id: Annotated[str, typer.Argument(help="Hypothesis ID such as HYP-001.")],
    workspace: WorkspaceOption = None,
) -> None:
    """Display one complete hypothesis and its evidence chain."""

    try:
        paths = resolve_workspace(workspace)
        hypothesis = find_hypothesis(paths, hypothesis_id)
    except FinsecError as error:
        _abort(error)
    score = hypothesis.scores
    details = [
        f"[bold]Kind / Disposition:[/bold] {hypothesis.kind} / {hypothesis.disposition}",
        f"[bold]Readiness:[/bold] {hypothesis.readiness}",
        f"[bold]Category:[/bold] {hypothesis.category}",
        f"[bold]Component:[/bold] {hypothesis.component}",
        f"[bold]Priority / Score:[/bold] {hypothesis.priority} / {score.total} "
        f"(impact {score.impact}, likelihood {score.likelihood}, confidence {score.confidence}, "
        f"testability {score.testability})",
        f"[bold]Status:[/bold] {hypothesis.status}",
        f"[bold]Evidence status:[/bold] {hypothesis.evidence_status}",
        f"[bold]Mutations:[/bold] {', '.join(hypothesis.mutation_dimensions)}",
        f"[bold]Endpoints:[/bold] {', '.join(hypothesis.source.endpoints) or 'None'}",
        f"[bold]Invariants:[/bold] {', '.join(hypothesis.invariant) or 'None'}",
        f"[bold]Observations:[/bold] {', '.join(hypothesis.observations) or 'None'}",
        "",
        "[bold]Hypothesis[/bold]",
        hypothesis.hypothesis,
        "",
        "[bold]Reasoning[/bold]",
        hypothesis.reasoning,
        "",
        "[bold]Eligibility evidence[/bold]",
        "\n".join(f"- {item}" for item in hypothesis.eligibility_evidence) or "- None",
        "",
        "[bold]Missing evidence[/bold]",
        "\n".join(f"- {item}" for item in hypothesis.missing_evidence) or "- None",
        "",
        "[bold]Preconditions[/bold]",
        "\n".join(f"- {item}" for item in hypothesis.preconditions),
        "",
        "[bold]Expected secure behavior[/bold]",
        hypothesis.expected_secure_behavior,
        "",
        "[bold]Possible vulnerable behavior[/bold]",
        hypothesis.possible_vulnerable_behavior,
        "",
        "[bold]Safety[/bold]",
        "\n".join(f"- {item}" for item in hypothesis.safety_notes),
    ]
    console.print(Panel("\n".join(details), title=f"{hypothesis.id}: {hypothesis.title}"))


@app.command("plan")
def plan_command(
    hypothesis_id: Annotated[str, typer.Argument(help="Hypothesis ID such as HYP-001.")],
    workspace: WorkspaceOption = None,
) -> None:
    """Generate a safe, non-executing test plan for human review."""

    try:
        paths = resolve_workspace(workspace)
        result = generate_plan(paths, hypothesis_id)
    except FinsecError as error:
        _abort(error)
    plan = result.plan
    color = "red" if plan.status == "BLOCKED" else "yellow"
    console.print(
        f"[{color}]{plan.id} is {plan.status}; execution default is "
        f"{plan.execution_default}.[/{color}]"
    )
    console.print(f"Plan store: {result.path}")
    console.print("Research status: active hypothesis; this plan does not confirm a finding.")
    console.print(f"Policy decision: {plan.risk.decision}")
    console.print(
        "Mutation target: "
        f"{plan.mutation_target.location or 'unknown'}:"
        f"{plan.mutation_target.json_path or plan.mutation_target.parameter or 'unresolved'}"
    )
    if plan.risk.decision == "BLOCKED":
        console.print("[red]Policy blockers:[/red]")
        for reason in plan.risk.reasons:
            console.print(f"- {reason}")
    else:
        console.print("Policy checks passed; explicit human approval remains mandatory.")
    console.print("\n[bold]Actions[/bold]")
    for index, action in enumerate(plan.actions, start=1):
        console.print(f"{index}. {action}")
    if plan.execution.supported:
        console.print(
            f"\nBounded execution template: {plan.execution.pattern} "
            f"({plan.execution.request_budget} requests)"
        )
        if plan.approval_status == "APPROVED" and plan.approval is None:
            console.print(
                "[yellow]The manually edited approval_status is incomplete. "
                f"Run 'hunt approve {plan.hypothesis_id}' to bind approval to this plan.[/yellow]"
            )
        elif plan.approval is None:
            console.print(
                "Next: review the structured requests, then run "
                f"'hunt approve {plan.hypothesis_id}'."
            )
    elif plan.execution.blockers:
        console.print("\n[red]Automated bounded execution is unavailable:[/red]")
        for blocker in plan.execution.blockers:
            console.print(f"- {blocker}")
    if result.conflict:
        console.print("[yellow]A researcher-edited existing plan was preserved.[/yellow]")


@app.command("approve")
def approve_command(
    hypothesis_id: Annotated[str, typer.Argument(help="Hypothesis ID such as HYP-001.")],
    workspace: WorkspaceOption = None,
    approved_by: Annotated[
        str,
        typer.Option("--approved-by", help="Non-secret researcher label recorded in the audit."),
    ] = "researcher",
    approval_token: Annotated[
        str | None,
        typer.Option(
            "--approval-token",
            help="Environment variable whose value authorizes local-lab non-interactive execution.",
        ),
    ] = None,
) -> None:
    """Bind explicit human approval to the current plan and target policy."""

    token_value: str | None = None
    try:
        paths = resolve_workspace(workspace)
        if approval_token is not None:
            token_value = os.environ.get(approval_token)
            if not token_value:
                raise FinsecError(
                    f"Approval refused: environment variable {approval_token} is missing."
                )
        review_plan_approval(paths, hypothesis_id, approved_by=approved_by)
    except FinsecError as error:
        _abort(error)
    expected = f"APPROVE {hypothesis_id.upper()}"
    confirmation = typer.prompt(f"Type {expected} to record bounded-execution approval")
    if confirmation != expected:
        _abort(FinsecError("Approval refused: confirmation text did not match exactly."))
    try:
        plan = approve_plan(
            paths,
            hypothesis_id,
            approved_by=approved_by,
            approval_token=token_value,
        )
    except FinsecError as error:
        _abort(error)
    console.print(f"[green]{plan.id} approved for bounded execution.[/green]")
    console.print("Approval is bound to the current plan and target-policy checksums.")
    console.print("No request was sent.")


@app.command("export-burp")
def export_burp_command(
    hypothesis_id: Annotated[str, typer.Argument(help="Hypothesis ID such as HYP-001.")],
    workspace: WorkspaceOption = None,
) -> None:
    """Export an approved structured plan as secret-free Burp Repeater requests."""

    try:
        paths = resolve_workspace(workspace)
        result = export_burp_requests(paths, hypothesis_id)
    except FinsecError as error:
        _abort(error)
    action = "Created" if result.created else "Reused"
    console.print(f"[green]{action} {len(result.requests)} Burp Repeater request files.[/green]")
    console.print(f"Export: {escape(str(result.root))}")
    console.print(f"Manifest: {escape(str(result.manifest))}")
    for request in result.requests:
        console.print(f"- {escape(str(request))}")
    console.print("Runtime credentials remain actor-specific placeholders.")
    console.print("Sending from Burp is manual active execution; follow the approved plan.")
    console.print("No request was sent.")


def _execution_summary(prepared: Any) -> None:
    plan = prepared.plan
    console.print(f"[bold]Hypothesis:[/bold] {prepared.hypothesis.id}")
    console.print("[bold]Resolved host and scope match:[/bold] yes")
    for request in plan.requests:
        port = request.port or (443 if request.scheme == "https" else 80)
        console.print(
            f"- {request.id}: {request.method} {request.scheme}://{request.host}:{port}"
            f"{request.path} as {request.actor}"
        )
        for mutation in request.mutations:
            target = mutation.to_value if mutation.to_value is not None else "<removed>"
            console.print(
                f"  {mutation.dimension}: {mutation.parameter} {mutation.from_value} -> {target}"
            )
        for secret in request.runtime_secrets:
            if secret.source == "actor_store":
                console.print(
                    f"  Runtime credential: {secret.header} from actor profile reference "
                    f"{secret.reference}"
                )
            else:
                console.print(
                    f"  Legacy runtime credential: {secret.header} from environment variable "
                    f"{secret.variable}"
                )
    console.print("Mutation dimensions: " + ", ".join(plan.execution.mutation_dimensions))
    console.print(f"Requests: {len(plan.requests)} / budget {plan.execution.request_budget}")
    console.print(f"Parallelism: {plan.execution.parallelism}")
    console.print(
        f"Timeouts: connect {plan.execution.connection_timeout_seconds:g}s, "
        f"read {plan.execution.read_timeout_seconds:g}s"
    )
    console.print("Redirect policy: disabled")
    console.print("TLS verification: enabled")
    console.print(
        "Active execution enabled: "
        + ("yes" if prepared.target.testing.active_execution_enabled else "no")
    )
    console.print(
        "Checksum-bound approval present: "
        + ("yes" if prepared.plan.approval is not None else "no")
    )
    console.print("Stop conditions:")
    for item in plan.execution.stop_conditions:
        console.print(f"- {item}")
    console.print(f"Expected evidence: evidence/{prepared.hypothesis.id}/executions/")
    if prepared.authentication_preflight:
        console.print("\n[bold]Authentication preflight[/bold]")
        for preflight in prepared.authentication_preflight:
            _print_authentication_preflight(preflight)


@app.command("execute")
def execute_command(
    hypothesis_id: Annotated[str, typer.Argument(help="Hypothesis ID such as HYP-001.")],
    workspace: WorkspaceOption = None,
    dry_run: Annotated[
        bool,
        typer.Option("--dry-run", help="Validate and display the plan without sending HTTP."),
    ] = False,
    non_interactive: Annotated[
        bool,
        typer.Option(
            "--non-interactive",
            help="Local-lab CI mode; production targets are always rejected.",
        ),
    ] = False,
    approval_token: Annotated[
        str | None,
        typer.Option(
            "--approval-token",
            help="Environment variable containing the approved local-lab execution token.",
        ),
    ] = None,
) -> None:
    """Execute one explicitly approved, scope-checked, read-only comparison plan."""

    if non_interactive and approval_token is None and not dry_run:
        console.print("[bold red]Execution refused.[/bold red]")
        console.print("Reason: --approval-token is required with --non-interactive.")
        console.print("Mutation requests sent: 0")
        console.print("Requests sent: 0")
        raise typer.Exit(code=1)
    try:
        paths = resolve_workspace(workspace)
        prepared = (
            prepare_execution(
                paths,
                hypothesis_id,
                dry_run=True,
                non_interactive=non_interactive,
                approval_token_env=approval_token,
            )
            if dry_run
            else review_execution_authority(
                paths,
                hypothesis_id,
                non_interactive=non_interactive,
                approval_token_env=approval_token,
            )
        )
    except FinsecError as error:
        console.print("[bold red]Execution refused.[/bold red]")
        console.print(f"Reason: {error}")
        console.print("Mutation requests sent: 0")
        console.print("Requests sent: 0")
        raise typer.Exit(code=1) from error
    _execution_summary(prepared)
    if dry_run:
        console.print("\n[green]Execution dry run passed.[/green]")
        console.print(f"Requests that would be sent: {len(prepared.plan.requests)}")
        console.print(
            "Mutation dimensions: " + ", ".join(prepared.plan.execution.mutation_dimensions)
        )
        console.print("Safety decision: READY_FOR_EXECUTION_REVIEW")
        console.print("Mutation requests sent: 0")
        console.print("No request was sent.")
        return
    if not non_interactive:
        expected = f"EXECUTE {prepared.hypothesis.id}"
        confirmation = typer.prompt(f"Type {expected} to continue")
        if confirmation != expected:
            console.print("[bold red]Execution refused.[/bold red]")
            console.print("Reason: confirmation text did not match exactly.")
            console.print("Mutation requests sent: 0")
            console.print("Requests sent: 0")
            raise typer.Exit(code=1)
    try:
        prepared = prepare_execution(
            paths,
            hypothesis_id,
            dry_run=False,
            non_interactive=non_interactive,
            approval_token_env=approval_token,
        )
    except FinsecError as error:
        console.print("[bold red]Execution blocked before mutation.[/bold red]")
        console.print(f"Reason: {error}")
        console.print("Mutation requests sent: 0")
        raise typer.Exit(code=1) from error
    result = execute_prepared(prepared)
    if result.status == "STOPPED":
        console.print("\n[yellow]Execution stopped safely.[/yellow]")
    elif result.status == "INCONCLUSIVE":
        console.print("\n[yellow]Execution completed with an inconclusive result.[/yellow]")
    else:
        console.print("\n[green]Execution completed.[/green]")
    console.print(f"Requests sent: {result.requests_sent}")
    console.print(f"Execution status: {result.status}")
    console.print(f"Outcome: {result.comparison.outcome}")
    console.print(f"Evidence: {result.evidence_root}")
    console.print(f"Audit: {result.audit_path}")
    console.print("Final vulnerability status: NOT CONFIRMED")
    console.print(f"Run `hunt validate {prepared.hypothesis.id}` after reviewing evidence.")


@app.command("evidence")
def evidence_command(
    hypothesis_id: Annotated[str, typer.Argument(help="Hypothesis ID such as HYP-001.")],
    workspace: WorkspaceOption = None,
    add: Annotated[
        Path | None,
        typer.Option("--add", help="Import one evidence file into the redacted evidence store."),
    ] = None,
    kind: Annotated[
        str | None,
        typer.Option(
            "--kind",
            help=(
                "request, response, before, after, delayed_after, related_state, "
                "ledger_state, entitlement_state, inventory_state, workflow_state, "
                "screenshot, ownership, or other."
            ),
        ),
    ] = None,
    description: Annotated[
        str | None,
        typer.Option("--description", help="Non-secret description for the artifact index."),
    ] = None,
    already_redacted: Annotated[
        bool,
        typer.Option(
            "--already-redacted",
            help="Confirm a binary or manually reviewed artifact is safe to copy.",
        ),
    ] = False,
) -> None:
    """Create, inspect, or add redacted evidence for one hypothesis."""

    try:
        paths = resolve_workspace(workspace)
        if add is not None:
            if kind is None:
                raise FinsecError("--kind is required when using --add.")
            result = add_evidence(
                paths,
                hypothesis_id,
                add,
                kind,
                description=description,
                already_redacted=already_redacted,
            )
        else:
            if kind is not None or description is not None or already_redacted:
                raise FinsecError("--kind, --description, and --already-redacted require --add.")
            result = ensure_evidence(paths, hypothesis_id)
    except FinsecError as error:
        _abort(error)
    if result.added_artifact:
        console.print(f"[green]Added redacted artifact {result.added_artifact}.[/green]")
    metadata = result.metadata
    assessment = metadata.assessment.model_dump()
    answered = sum(value is not None for value in assessment.values())
    console.print(f"[bold]Evidence:[/bold] {metadata.hypothesis_id}")
    console.print(f"Metadata: {result.root / 'metadata.yaml'}")
    console.print(f"Artifacts: {len(metadata.artifacts)}")
    console.print(f"Validation checklist answered: {answered}/{len(assessment)}")
    if metadata.artifacts:
        table = Table(show_lines=False)
        table.add_column("ID", style="cyan", no_wrap=True)
        table.add_column("Kind", no_wrap=True)
        table.add_column("Redaction", no_wrap=True)
        table.add_column("Path")
        for artifact in metadata.artifacts:
            table.add_row(artifact.id, artifact.kind, artifact.redaction, artifact.path)
        console.print(table)
    console.print("Review metadata.yaml and conclusion.md before running 'hunt validate'.")


@app.command("validate")
def validate_command(
    hypothesis_id: Annotated[str, typer.Argument(help="Hypothesis ID such as HYP-001.")],
    workspace: WorkspaceOption = None,
) -> None:
    """Attempt to disprove one hypothesis using indexed evidence and controls."""

    try:
        paths = resolve_workspace(workspace)
        result = validate_hypothesis(paths, hypothesis_id)
    except FinsecError as error:
        _abort(error)
    validation = result.validation
    style = {
        "CONFIRMED": "bold red",
        "REFUTED": "green",
        "NEEDS_MORE_EVIDENCE": "yellow",
        "OUT_OF_SCOPE": "red",
        "EXPECTED_BEHAVIOR": "green",
    }[validation.disposition]
    console.print(f"[{style}]{validation.hypothesis_id}: {validation.disposition}[/{style}]")
    console.print(validation.summary)
    unresolved = [item for item in validation.checks if item.result in {"FAIL", "MISSING"}]
    if unresolved:
        console.print("\n[bold]Unresolved checks[/bold]")
        for check in unresolved:
            console.print(f"- {check.id} [{check.result}]: {check.detail}")
    console.print(f"Report ready: {'yes' if validation.report_ready else 'no'}")
    console.print(f"Validation store: {result.path}")
    if result.conflict:
        console.print("[yellow]A researcher-edited validation record was preserved.[/yellow]")


@app.command("report")
def report_command(
    hypothesis_id: Annotated[str, typer.Argument(help="Hypothesis ID such as HYP-001.")],
    workspace: WorkspaceOption = None,
) -> None:
    """Generate a versioned report only from currently confirmed evidence."""

    try:
        paths = resolve_workspace(workspace)
        result = generate_report(paths, hypothesis_id)
    except FinsecError as error:
        _abort(error)
    action = "Generated" if result.created else "Reused unchanged"
    console.print(f"[green]{action} report:[/green] {result.path}")


@app.command("status")
def status_command(
    workspace: WorkspaceOption = None,
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Emit the complete canonical readiness report as JSON."),
    ] = False,
) -> None:
    """Show canonical pipeline readiness for the selected target workspace."""

    try:
        paths = resolve_workspace(workspace)
        report = resolve_workspace_readiness(paths)
    except FinsecError as error:
        _abort(error)

    if json_output:
        typer.echo(json.dumps(report.model_dump(mode="json"), indent=2, sort_keys=True))
        return

    console.print(
        f"[bold]Target:[/bold] {report.workspace}\n[bold]Overall:[/bold] {report.overall.status}"
    )
    metric_table = Table(show_header=False, box=None, pad_edge=False)
    metric_table.add_column("Artifact")
    metric_table.add_column("Count", justify="right")
    for label, count in (
        ("Observations", report.metrics.observations),
        ("Endpoints", report.metrics.endpoints),
        ("GraphQL Operations", report.metrics.graphql_operations),
        ("Mobile Discoveries", report.metrics.mobile_discoveries),
        ("Active Resources", report.metrics.resources),
        ("Actors", report.metrics.actors),
        ("Workflows", report.metrics.workflows),
        ("Active Invariants", report.metrics.invariants),
        ("Active Hypotheses", report.metrics.active_hypotheses),
        ("Research Tasks", report.metrics.research_tasks),
        ("Raw Active Hypotheses", report.metrics.raw_active_hypotheses),
        ("Raw Research Tasks", report.metrics.raw_research_tasks),
        ("Suppressed Endpoints", report.metrics.suppressed_endpoints),
        ("Evidence Sets", report.metrics.evidence_sets),
        ("Validations", report.metrics.validations),
        ("Reports", report.metrics.reports),
    ):
        metric_table.add_row(label, str(count))
    console.print(metric_table)

    hypothesis_counts = (
        ("NOT_TESTED", report.metrics.hypotheses_not_tested),
        ("TEST_PLANNED", report.metrics.hypotheses_test_planned),
        ("REFUTED", report.metrics.hypotheses_refuted),
        ("NEEDS_EVIDENCE", report.metrics.hypotheses_needs_evidence),
        ("CONFIRMED", report.metrics.hypotheses_confirmed),
    )
    if any(count for _, count in hypothesis_counts):
        console.print("\n[bold]Hypotheses[/bold]")
        hypothesis_table = Table(show_header=False, box=None, pad_edge=False)
        hypothesis_table.add_column("Status")
        hypothesis_table.add_column("Count", justify="right")
        for status, count in hypothesis_counts:
            hypothesis_table.add_row(status, str(count))
        console.print(hypothesis_table)
        try:
            hypotheses = HypothesisStore.model_validate(load_yaml(paths.hypotheses))
        except (OSError, TypeError, ValueError, ValidationError):
            hypotheses = HypothesisStore()
        highest = sorted(
            hypothesis_population(hypotheses.hypotheses).visible_active_hypotheses,
            key=lambda item: (
                {"P1": 0, "P2": 1, "P3": 2}[item.priority],
                -item.scores.total,
                item.id,
            ),
        )[:5]
        if highest:
            console.print(_hypothesis_table(highest))
            console.print(f"Review: hunt show {highest[0].id} --workspace {paths.root}")

    table = Table(box=None, pad_edge=False)
    table.add_column("Stage")
    table.add_column("Status")
    table.add_column("Results", justify="right")
    table.add_column("Reason")
    for stage in report.stages:
        reason = ", ".join(item.code for item in stage.blockers[:2]) or stage.summary
        table.add_row(stage.id.value, stage.status.value, str(stage.result_count), reason)
    console.print(table)

    if report.actors:
        console.print("\n[bold]Actor readiness[/bold]")
        actor_table = Table(box=None, pad_edge=False)
        actor_table.add_column("Actor")
        actor_table.add_column("Credential", no_wrap=True)
        actor_table.add_column("Target")
        actor_table.add_column("Identity")
        actor_table.add_column("Ownership")
        actor_table.add_column("Authz execute")
        for actor in report.actors:
            ownership_context = actor.ownership.resource_type or "focused baseline"
            actor_table.add_row(
                actor.actor_id,
                actor.credential.status,
                "validated" if actor.target_validation.recorded else "unverified",
                "confirmed" if actor.identity_confirmation.confirmed else "unconfirmed",
                f"{ownership_context} {'yes' if actor.ownership.confirmed_baselines else 'no'}",
                "hypothesis-specific",
            )
        console.print(actor_table)
        for actor in report.actors:
            if actor.credential.status not in {"READY", "NOT_REQUIRED"} or not (
                actor.identity_confirmation.confirmed
            ):
                identity = "confirmed" if actor.identity_confirmation.confirmed else "unconfirmed"
                console.print(
                    f"{actor.actor_id} auth status: {actor.credential.status}; identity: {identity}"
                )
        if report.focused_comparison is not None:
            comparison = report.focused_comparison
            console.print(
                f"{comparison.hypothesis_id} comparison coverage = "
                f"{comparison.observed_distinct_actors}/"
                f"{comparison.required_distinct_actors} actors; "
                f"{comparison.distinct_controlled_objects} distinct object(s)."
            )

    if report.next_actions:
        console.print("\n[bold]Next actions[/bold]")
        for action in report.next_actions:
            detail = action.command or "manual review"
            console.print(f"- {action.label}: {detail} ({action.safety})")


@app.command("web")
def web_command(
    workspace: WorkspaceOption = None,
    workspace_root: Annotated[
        Path,
        typer.Option(
            "--workspace-root",
            help="Workspace directory root used when no explicit or default workspace is selected.",
        ),
    ] = Path("workspaces"),
    capture_root: Annotated[
        Path | None,
        typer.Option(
            "--capture-root",
            help="External directory containing <slug>/incoming HAR capture folders.",
        ),
    ] = None,
    host: Annotated[
        str,
        typer.Option("--host", help="Loopback address for the unauthenticated local UI."),
    ] = "127.0.0.1",
    port: Annotated[
        int,
        typer.Option("--port", min=1, max=65535, help="Local TCP port for the Web UI."),
    ] = 8765,
) -> None:
    """Serve the local setup, passive-ingestion, and research cockpit."""

    try:
        selected: Path | None
        if workspace is not None:
            selected = resolve_workspace(workspace).root
        else:
            configured = load_default_workspace()
            selected = configured.root if configured is not None else None
        from finsec.web.server import run_server

        console.print(f"[green]FinSec Hunt Web UI:[/green] http://{host}:{port}")
        console.print("The UI can set up workspaces and ingest passively; it cannot execute plans.")
        run_server(
            workspace_root=workspace_root,
            workspace=selected,
            capture_root=capture_root,
            host=host,
            port=port,
        )
    except FinsecError as error:
        _abort(error)


def main() -> Any:
    """Console-script entry point retained for direct invocation."""

    return app()


if __name__ == "__main__":
    main()
