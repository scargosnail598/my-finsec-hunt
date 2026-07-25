"""Typer command-line interface for the deterministic research pipeline."""

import re
from pathlib import Path
from typing import Annotated, Any, cast

import typer
from pydantic import ValidationError
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from finsec.config.models import TargetDocument
from finsec.config.workspace import create_workspace, resolve_workspace
from finsec.errors import FinsecError
from finsec.evidence.manager import add_evidence, ensure_evidence
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
from finsec.testing.planner import generate_plan
from finsec.utils.yaml_store import load_yaml
from finsec.validation.validator import validate_hypothesis

app = typer.Typer(
    name="hunt",
    help="Local-first, authorized fintech research workspace.",
    no_args_is_help=True,
)
console = Console()

WorkspaceOption = Annotated[
    Path | None,
    typer.Option("--workspace", "-w", help="Target workspace containing target.yaml."),
]

ALLOWED_CHANNELS = {"WEB", "MOBILE", "PARTNER_API", "PUBLIC_API", "UNKNOWN"}


def _abort(error: Exception) -> None:
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
) -> None:
    """Import HAR entries as redacted, factual observations."""

    try:
        paths = resolve_workspace(workspace)
        result = ingest_har(
            har_file,
            paths,
            actor=actor,
            channel=_channel(channel),
        )
    except FinsecError as error:
        _abort(error)
    console.print(
        f"[green]Imported {result.imported}[/green] observations "
        f"({result.skipped} already present, {result.total} total)."
    )
    console.print(f"Redacted HAR: {result.redacted_har}")
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
    hypotheses = sorted(
        (
            item
            for item in hypotheses
            if selected_priority is None or item.priority == selected_priority
        ),
        key=lambda item: ({"P1": 0, "P2": 1, "P3": 2}[item.priority], -item.scores.total, item.id),
    )
    console.print(f"[green]Backlog contains {result.hypotheses} hypotheses.[/green]")
    if result.conflicts:
        console.print(
            "[yellow]Preserved researcher-edited hypotheses:[/yellow] "
            + ", ".join(result.conflicts)
        )
    if hypotheses:
        console.print(_hypothesis_table(hypotheses))
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
    if result.conflict:
        console.print("[yellow]A researcher-edited existing plan was preserved.[/yellow]")


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
        ("Resources", _count_yaml_list(paths.root / "model/resources.yaml", "resources")),
        ("Actors", _count_yaml_list(paths.root / "model/actors.yaml", "actors")),
        ("Workflows", _count_workflows(paths.root / "model/workflows.md")),
        ("Invariants", _count_yaml_list(paths.root / "model/invariants.yaml", "invariants")),
        ("Hypotheses", _count_yaml_list(paths.root / "hypotheses/backlog.yaml", "hypotheses")),
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
            count = sum(1 for item in hypotheses.hypotheses if item.status == status)
            status_table.add_row(status, str(count))
        console.print(status_table)
        highest = sorted(
            hypotheses.hypotheses,
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
