"""Typer command-line interface for the deterministic research pipeline."""

import os
import re
from pathlib import Path
from typing import Annotated, Any, NoReturn, cast

import typer
from pydantic import ValidationError
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from finsec.auth.capture import detect_har_authentication
from finsec.auth.service import (
    actor_preflight,
    capture_from_har,
    capture_from_raw_request,
    clear_authentication,
    configure_refresh_from_har,
    migrate_legacy_authentication,
    refresh_actor_authentication,
    set_manual_authentication,
    validate_actor_baseline,
)
from finsec.auth.store import SecretStore
from finsec.config.models import TargetDocument
from finsec.config.workspace import (
    create_workspace,
    delete_workspace,
    resolve_workspace,
    resolve_workspace_deletion_target,
)
from finsec.errors import FinsecError
from finsec.evidence.manager import add_evidence, ensure_evidence
from finsec.execution.policy import approve_plan, prepare_execution, review_execution_authority
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
from finsec.modeling.models import ChannelType, EndpointStore, ObservationStore
from finsec.normalization.inventory import build_inventory
from finsec.recon.graphql import ingest_graphql
from finsec.recon.mobile import scan_mobile
from finsec.reporting.generator import generate_report
from finsec.setup import run_setup_wizard
from finsec.testing.planner import generate_plan
from finsec.utils.yaml_store import load_yaml
from finsec.validation.validator import validate_hypothesis
from finsec.workflow import run_offline_workflow

app = typer.Typer(
    name="hunt",
    help="Local-first, authorized fintech research workspace.",
    no_args_is_help=True,
)
workspace_app = typer.Typer(
    help="Manage an explicitly selected workspace lifecycle.",
    no_args_is_help=True,
)
app.add_typer(workspace_app, name="workspace")
actor_app = typer.Typer(help="Manage configured research actors.", no_args_is_help=True)
actor_auth_app = typer.Typer(help="Manage actor-owned authentication.", no_args_is_help=True)
actor_app.add_typer(actor_auth_app, name="auth")
app.add_typer(actor_app, name="actor")
console = Console()

WorkspaceOption = Annotated[
    Path | None,
    typer.Option("--workspace", "-w", help="Target workspace containing target.yaml."),
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


def _count_yaml_list(path: Path, key: str) -> int:
    if not path.is_file():
        return 0
    data = load_yaml(path)
    if not isinstance(data, dict) or not isinstance(data.get(key), list):
        return 0
    return len(data[key])


def _count_active_yaml_records(path: Path, key: str) -> int:
    """Count records that are active or predate explicit dispositions."""

    if not path.is_file():
        return 0
    data = load_yaml(path)
    records = data.get(key) if isinstance(data, dict) else None
    if not isinstance(records, list):
        return 0
    return sum(
        isinstance(item, dict) and item.get("disposition", "ACTIVE") == "ACTIVE" for item in records
    )


def _count_workflows(path: Path) -> int:
    if not path.is_file():
        return 0
    content = path.read_text(encoding="utf-8")
    return len(re.findall(r"^## Workflow:", content, flags=re.MULTILINE))


def _count_evidence_sets(path: Path) -> int:
    if not path.is_dir():
        return 0
    return sum(1 for item in path.iterdir() if (item / "metadata.yaml").is_file())


def _count_reports(path: Path) -> int:
    return len(list(path.glob("HYP-*-report-v*.md"))) if path.is_dir() else 0


def _hypothesis_table(hypotheses: list[HypothesisRecord]) -> Table:
    table = Table(show_lines=False)
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("Priority", no_wrap=True)
    table.add_column("Score", justify="right", no_wrap=True)
    table.add_column("Status", no_wrap=True)
    table.add_column("Title")
    priority_style = {"P1": "bold red", "P2": "yellow", "P3": "dim"}
    for hypothesis in hypotheses:
        table.add_row(
            hypothesis.id,
            f"[{priority_style[hypothesis.priority]}]{hypothesis.priority}[/]",
            str(hypothesis.scores.total),
            hypothesis.status,
            hypothesis.title,
        )
    return table


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
    """Create a validated workspace and configure actor authentication readiness."""

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
        )
    except (KeyboardInterrupt, typer.Abort) as error:
        console.print("\nSetup cancelled; no partial workspace was created.")
        raise typer.Exit(code=130) from error
    except (FinsecError, OSError, ValidationError) as error:
        _abort(error)


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
            help="Exact workspace slug; bypasses the interactive confirmation prompt.",
        ),
    ] = None,
) -> None:
    """Permanently delete one validated workspace, but never its capture directory."""

    try:
        target = resolve_workspace_deletion_target(workspace)
        console.print(
            Panel.fit(
                f"Workspace: {target.display_name}\n"
                f"Slug: {target.slug}\n"
                f"Path: {target.root}\n\n"
                "This permanently deletes the workspace directory and all observations, "
                "models, hypotheses, plans, evidence, validations, and reports inside it.\n"
                "The separate capture directory is not deleted.",
                title="Permanent Workspace Deletion",
                border_style="red",
            )
        )
        confirmation = confirm
        if confirmation is None:
            confirmation = typer.prompt(
                f"Type the workspace slug '{target.slug}' to confirm deletion"
            )
        if confirmation != target.slug:
            raise FinsecError(
                f"Confirmation did not match workspace slug '{target.slug}'; nothing was deleted."
            )
        delete_workspace(target)
    except (KeyboardInterrupt, typer.Abort) as error:
        console.print("\nWorkspace deletion cancelled; nothing was deleted.")
        raise typer.Exit(code=130) from error
    except (FinsecError, OSError, ValidationError) as error:
        _abort(error)

    console.print(f"[bold green]Deleted workspace:[/bold green] {target.root}")
    console.print("Deletion is permanent. Separate capture directories were left untouched.")


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
    request: Annotated[
        Path | None, typer.Option("--request", help="New authenticated raw HTTP request.")
    ] = None,
    auth_candidate: Annotated[
        int | None, typer.Option("--auth-candidate", help="1-based HAR candidate selection.")
    ] = None,
) -> None:
    """Replace authentication from a capture or run one configured observed refresh."""

    if har is not None and request is not None:
        _abort(FinsecError("Choose exactly one of --har or --request."))
    try:
        paths = resolve_workspace(workspace)
        if har is not None:
            selected = auth_candidate
            candidates = detect_har_authentication(har)
            if not candidates:
                raise FinsecError("No replay authentication candidate was detected in the HAR.")
            if selected is None:
                for index, candidate in enumerate(candidates, start=1):
                    console.print(f"[{index}] {candidate.redacted_summary()}")
                selected = (
                    1
                    if len(candidates) == 1
                    else int(typer.prompt("Select replay authentication", type=int))
                )
            authentication, _ = capture_from_har(
                paths,
                actor_id,
                har,
                candidate_number=selected,
                observed_renewal=False,
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
        ("Workflows", result.workflows),
        ("Invariants", result.invariants),
        ("Active hypotheses", result.active_hypotheses),
        ("Research tasks", result.research_tasks),
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
    auth_candidate: Annotated[
        int | None,
        typer.Option("--auth-candidate", help="1-based replay profile selection for automation."),
    ] = None,
) -> None:
    """Import HAR entries as redacted, factual observations."""

    try:
        paths = resolve_workspace(workspace)
        selected_candidate = auth_candidate
        if capture_auth and selected_candidate is None:
            candidates = detect_har_authentication(har_file)
            if not candidates:
                raise FinsecError("No replay authentication candidate was detected in the HAR.")
            console.print("[bold]Authentication candidates detected[/bold]")
            for index, candidate in enumerate(candidates, start=1):
                console.print(f"[{index}] {candidate.redacted_summary()}")
                if candidate.expiration.expires_at is not None:
                    console.print(f"    Expires at: {candidate.expiration.expires_at}")
            selected_candidate = (
                1
                if len(candidates) == 1
                else int(typer.prompt("Select replay authentication", type=int))
            )
        result = ingest_har(
            har_file,
            paths,
            actor=actor,
            channel=_channel(channel),
            capture_auth=capture_auth,
            auth_candidate=selected_candidate,
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
    console.print("Run 'hunt inventory' to rebuild the endpoint inventory.")


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
) -> None:
    """Import a Burp XML history export as redacted observations."""

    try:
        paths = resolve_workspace(workspace)
        result = ingest_burp_xml(xml_file, paths, actor=actor, channel=_channel(channel))
    except FinsecError as error:
        _abort(error)
    console.print(
        f"[green]Imported {result.imported}[/green] Burp observations "
        f"({result.skipped} already present, {result.total} total)."
    )
    if result.relabeled:
        console.print(f"[yellow]Refreshed {result.relabeled} actor/channel assignments.[/yellow]")
    console.print(f"Redacted capture: {result.redacted_capture}")
    console.print("Run 'hunt inventory' to rebuild the endpoint inventory.")


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
    console.print("Run 'hunt inventory' to rebuild the endpoint inventory.")


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
    console.print("Runtime behavior remains unconfirmed; run 'hunt inventory' to normalize paths.")


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
    console.print(
        Panel("\n".join(details), title=f"{endpoint.id}: {endpoint.method} {endpoint.path}")
    )


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
        hypotheses = load_hypotheses(paths).hypotheses
    except FinsecError as error:
        _abort(error)
    if explain:
        hypotheses = [item for item in hypotheses if item.id == explain]
    elif research_tasks:
        hypotheses = [item for item in hypotheses if item.kind == "RESEARCH_TASK"]
    else:
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
    store = load_hypotheses(paths)
    active_count = sum(
        item.kind == "SECURITY_HYPOTHESIS" and item.disposition == "ACTIVE"
        for item in store.hypotheses
    )
    task_count = sum(item.kind == "RESEARCH_TASK" for item in store.hypotheses)
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
        if explain and len(hypotheses) == 1:
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
    console.print(f"Safety decision: {plan.risk.decision}")
    for reason in plan.risk.reasons:
        console.print(f"- {reason}")
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

    expected = f"APPROVE {hypothesis_id.upper()}"
    confirmation = typer.prompt(f"Type {expected} to record bounded-execution approval")
    if confirmation != expected:
        _abort(FinsecError("Approval refused: confirmation text did not match exactly."))
    token_value: str | None = None
    if approval_token is not None:
        token_value = os.environ.get(approval_token)
        if not token_value:
            _abort(
                FinsecError(f"Approval refused: environment variable {approval_token} is missing.")
            )
    try:
        paths = resolve_workspace(workspace)
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
            help="request, response, before, after, screenshot, ownership, or other.",
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
def status_command(workspace: WorkspaceOption = None) -> None:
    """Show deterministic counts for the selected target workspace."""

    try:
        paths = resolve_workspace(workspace)
        target = TargetDocument.model_validate(load_yaml(paths.target))
        observations = ObservationStore.model_validate(load_yaml(paths.observations))
        endpoints = EndpointStore.model_validate(load_yaml(paths.endpoints))
        hypotheses = HypothesisStore.model_validate(load_yaml(paths.hypotheses))
    except (FinsecError, OSError, ValidationError) as error:
        _abort(error)

    console.print(f"[bold]Target:[/bold] {target.target.name}\n")
    table = Table(show_header=False, box=None, pad_edge=False)
    table.add_column("Artifact")
    table.add_column("Count", justify="right")
    counts: list[tuple[str, int]] = [
        ("Observations", len(observations.observations)),
        ("Endpoints", len(endpoints.endpoints)),
        ("GraphQL Operations", _count_yaml_list(paths.graphql, "operations")),
        ("Mobile Discoveries", _count_yaml_list(paths.mobile_discoveries, "discoveries")),
        (
            "Active Resources",
            _count_active_yaml_records(paths.root / "model/resources.yaml", "resources"),
        ),
        ("Actors", _count_yaml_list(paths.root / "model/actors.yaml", "actors")),
        ("Workflows", _count_workflows(paths.root / "model/workflows.md")),
        (
            "Active Invariants",
            _count_active_yaml_records(paths.root / "model/invariants.yaml", "invariants"),
        ),
        (
            "Active Hypotheses",
            sum(
                item.kind == "SECURITY_HYPOTHESIS" and item.disposition == "ACTIVE"
                for item in hypotheses.hypotheses
            ),
        ),
        ("Research Tasks", sum(item.kind == "RESEARCH_TASK" for item in hypotheses.hypotheses)),
        (
            "Suppressed Endpoints",
            sum(item.disposition != "ACTIVE" for item in endpoints.endpoints),
        ),
        ("Evidence Sets", _count_evidence_sets(paths.root / "evidence")),
        ("Validations", _count_yaml_list(paths.validations, "validations")),
        ("Reports", _count_reports(paths.reports)),
    ]
    for label, count in counts:
        table.add_row(label, str(count))
    console.print(table)

    if hypotheses.hypotheses:
        console.print("\n[bold]Hypotheses[/bold]")
        status_table = Table(show_header=False, box=None, pad_edge=False)
        status_table.add_column("Status")
        status_table.add_column("Count", justify="right")
        for status in ("NOT_TESTED", "TEST_PLANNED", "REFUTED", "NEEDS_EVIDENCE", "CONFIRMED"):
            count = sum(
                1
                for item in hypotheses.hypotheses
                if item.kind == "SECURITY_HYPOTHESIS"
                and item.disposition == "ACTIVE"
                and item.status == status
            )
            status_table.add_row(status, str(count))
        console.print(status_table)
        highest = sorted(
            [
                item
                for item in hypotheses.hypotheses
                if item.kind == "SECURITY_HYPOTHESIS" and item.disposition == "ACTIVE"
            ],
            key=lambda item: (
                {"P1": 0, "P2": 1, "P3": 2}[item.priority],
                -item.scores.total,
                item.id,
            ),
        )[:5]
        console.print("\n[bold]Highest priority[/bold]")
        console.print(_hypothesis_table(highest))


def main() -> Any:
    """Console-script entry point retained for direct invocation."""

    return app()


if __name__ == "__main__":
    main()
