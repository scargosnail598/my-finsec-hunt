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
from finsec.behavior.hypothesis_precision import cluster_is_visible, rank_hypothesis_clusters
from finsec.behavior.reconstruction import (
    build_behavior_model,
    find_workflow_family,
    load_propagation,
    load_workflow_families,
    load_workflow_graph,
    load_workflow_instances,
)
from finsec.behavior.rendering import render_graph
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
from finsec.hypotheses.domain import HypothesisRecord, HypothesisStore
from finsec.hypotheses.generator import (
    find_hypothesis,
    generate_hypotheses,
    load_hypotheses,
)
from finsec.ingest.har import ingest_har
from finsec.ingest.openapi import ingest_openapi
from finsec.ingest.traffic import ingest_burp_xml, ingest_caido_json
from finsec.modeling.generator import generate_model
from finsec.modeling.invariants import generate_invariants
from finsec.modeling.models import ChannelType, EndpointStore
from finsec.normalization.inventory import build_inventory
from finsec.readiness.resolver import resolve_workspace_readiness
from finsec.recon.graphql import ingest_graphql
from finsec.recon.mobile import scan_mobile
from finsec.reporting.generator import generate_report
from finsec.setup import SetupResult, run_setup_wizard
from finsec.testing.burp import export_burp_requests
from finsec.testing.planner import generate_plan
from finsec.utils.yaml_store import load_yaml
from finsec.validation.validator import validate_hypothesis
from finsec.workflow import (
    WorkflowCapture,
    load_workflow_manifest,
    merge_workflow_assignments,
    run_offline_workflow,
)

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
    """Overlay canonical BLH clusters without migrating the persisted backlog."""

    if not paths.business_logic_hypotheses.is_file():
        return hypotheses
    try:
        logic = load_logic_presentation(paths)
    except FinsecError:
        return hypotheses
    by_id = {item.id: item for item in hypotheses}
    presented = [item for item in hypotheses if item.category != "business_logic"]
    for cluster in rank_hypothesis_clusters(
        logic.clusters,
        include_suppressed=True,
        include_low=True,
    ):
        record = by_id.get(cluster.representative_hypothesis_id)
        if record is None:
            continue
        visible = cluster_is_visible(cluster)
        if not visible and not include_suppressed:
            continue
        disposition = (
            "ACTIVE"
            if visible and record.kind == "SECURITY_HYPOTHESIS"
            else "NEEDS_RESEARCH"
            if visible
            else "SUPPRESSED_INSUFFICIENT_EVIDENCE"
        )
        presented.append(
            record.model_copy(
                deep=True,
                update={
                    "title": cluster.title,
                    "disposition": disposition,
                    "readiness": cluster.readiness,
                },
            )
        )
    return presented


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
class _InteractiveHarImport:
    path: Path
    actor: str
    channel: ChannelType
    auth_candidate: int | None = None
    observed_renewal: bool = False


@dataclass(frozen=True)
class _IngestWizardContext:
    target: TargetDocument
    capture_root: Path
    incoming: Path
    manifest_path: Path
    har_files: tuple[Path, ...]


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
        raise FinsecError(f"HAR input directory not found: {incoming}")
    manifest = load_workflow_manifest(manifest_path) if manifest_path.is_file() else None
    assigned = {item.file for item in manifest.captures} if manifest is not None else set()
    har_files = tuple(
        sorted(
            path
            for path in incoming.iterdir()
            if path.is_file()
            and path.suffix.lower() == ".har"
            and (include_assigned or path.name not in assigned)
        )
    )
    return _IngestWizardContext(
        target=target,
        capture_root=selected_capture_root,
        incoming=incoming,
        manifest_path=manifest_path,
        har_files=har_files,
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
        if context.har_files:
            break
        console.print(f"No unassigned HAR files were found in {context.incoming}.")
        console.print("1. Add authorized, reviewed HAR files and rescan")
        console.print("2. Continue to actor authentication without ingesting")
        choice = str(typer.prompt("Choose the next setup step", default="1")).strip()
        if choice == "2":
            return
        if choice != "1":
            console.print("[red]Choose 1 or 2.[/red]")
            continue
        console.print(f"Place the HAR files in: {context.incoming}")
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
    count = len(context.har_files)
    console.print(
        f"[bold]Available capture{'s' if count != 1 else ''}:[/bold] "
        f"{count} unassigned HAR file{'s' if count != 1 else ''}"
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
    if result.authentication_status is not None:
        console.print(f"Credential storage: successful ({result.credential_profile_ref})")
        console.print(f"Actor status: {result.authentication_status}")
    console.print(_offline_workflow_hint(paths))


def _run_ingest_wizard(paths: WorkspacePaths, context: _IngestWizardContext) -> None:
    """Run the shared interactive import flow for one validated capture directory."""

    target = context.target
    console.print(f"[bold]HAR input directory:[/bold] {context.incoming}")
    console.print("Configured actors: " + ", ".join(item.id for item in target.accounts))
    console.print("Use ANONYMOUS or UNKNOWN only when that provenance is accurate.")
    selections: list[_InteractiveHarImport] = []
    accounts = {item.id: item for item in target.accounts}

    for har_file in context.har_files:
        console.print(f"\n[bold]Capture:[/bold] {escape(har_file.name)}")
        actor = _prompt_har_actor(target)
        if actor is None:
            continue
        channel = _prompt_har_channel(target, actor)
        auth_candidate: int | None = None
        observed_renewal = False
        account = accounts.get(actor)
        if account is not None and account.authenticated and account.actor_type != "anonymous":
            try:
                recommendation = recommend_har_authentication(paths, actor, har_file)
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
            _InteractiveHarImport(
                path=har_file,
                actor=actor,
                channel=channel,
                auth_candidate=auth_candidate,
                observed_renewal=observed_renewal,
            )
        )

    if not selections:
        console.print("No HAR files were selected.")
        return

    summary = Table("File", "Actor", "Channel", "Authentication")
    for selection in selections:
        authentication_summary = (
            f"recommended request {selection.auth_candidate}"
            if selection.auth_candidate is not None
            else "unchanged"
        )
        summary.add_row(
            selection.path.name,
            selection.actor,
            selection.channel,
            authentication_summary,
        )
    console.print(summary)
    if not typer.confirm("Import these HAR files passively?", default=False):
        console.print("No HAR files were imported.")
        return

    successful_assignments: list[WorkflowCapture] = []
    imported_any = False
    for selection in selections:
        try:
            result = ingest_har(
                selection.path,
                paths,
                actor=selection.actor,
                channel=selection.channel,
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
            )
        )
        console.print(
            f"[green]{escape(selection.path.name)}:[/green] {result.imported} imported, "
            f"{result.skipped} already present"
        )
        if selection.auth_candidate is not None:
            try:
                authentication, _ = capture_from_har(
                    paths,
                    selection.actor,
                    selection.path,
                    candidate_number=selection.auth_candidate,
                    observed_renewal=selection.observed_renewal,
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
            help="Offer HAR files already present in workflow.yaml for relabeling or renewal.",
        ),
    ] = False,
) -> None:
    """Interactively import newly added HAR files and recommend fresh actor authentication."""

    try:
        paths = resolve_workspace(workspace)
        context = _resolve_ingest_wizard_context(
            paths,
            capture_root,
            include_assigned=include_assigned,
        )
        if not context.har_files:
            console.print("No unassigned HAR files were found.")
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
) -> None:
    """Import a Caido-style JSON exchange export as redacted observations."""

    try:
        paths = resolve_workspace(workspace)
        result = ingest_caido_json(json_file, paths, actor=actor, channel=_channel(channel))
    except FinsecError as error:
        _abort(error)
    console.print(
        f"[green]Imported {result.imported}[/green] Caido observations "
        f"({result.skipped} already present, {result.total} total)."
    )
    if result.relabeled:
        console.print(f"[yellow]Refreshed {result.relabeled} actor/channel assignments.[/yellow]")
    console.print(f"Redacted capture: {result.redacted_capture}")
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
    for blocker in item.readiness_blockers or ["None recorded."]:
        console.print(f"- {blocker}")
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
) -> None:
    """Generate and display a prioritized, evidence-backed hypothesis backlog."""

    selected_priority = priority.upper() if priority else None
    if selected_priority not in {None, "P1", "P2", "P3"}:
        _abort(FinsecError("Priority must be P1, P2, or P3."))
    try:
        paths = resolve_workspace(workspace)
        result = generate_hypotheses(paths)
        stored_hypotheses = load_hypotheses(paths).hypotheses
    except FinsecError as error:
        _abort(error)
    if explain:
        explained_id = explain
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
    presented_store = _canonical_backlog_presentation(paths, stored_hypotheses)
    active_count = sum(
        item.kind == "SECURITY_HYPOTHESIS" and item.disposition == "ACTIVE"
        for item in presented_store
    )
    task_count = sum(
        item.kind == "RESEARCH_TASK" and not item.disposition.startswith("SUPPRESSED_")
        for item in presented_store
    )
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
            (
                item
                for item in hypotheses.hypotheses
                if item.kind == "SECURITY_HYPOTHESIS" and item.disposition == "ACTIVE"
            ),
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
        actor_table.add_column("Credential")
        actor_table.add_column("Target")
        actor_table.add_column("Identity")
        actor_table.add_column("Ownership")
        actor_table.add_column("Authz execute")
        for actor in report.actors:
            actor_table.add_row(
                actor.actor_id,
                "available" if actor.credential.available else "missing",
                "validated" if actor.target_validation.recorded else "unverified",
                "confirmed" if actor.identity_confirmation.confirmed else "unconfirmed",
                f"{actor.ownership.confirmed_baselines}/{actor.ownership.required_baselines}",
                "ready" if actor.capabilities.authorization_execution else "blocked",
            )
        console.print(actor_table)

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
