#!/usr/bin/env python3
"""Build a non-destructive synthetic demo and run the offline workflow."""

from __future__ import annotations

import argparse
import shutil
import sys
import tempfile
from pathlib import Path

from finsec.errors import FinsecError
from finsec.hypotheses.generator import load_hypotheses
from finsec.setup import AccountInput, build_setup_config, create_setup_workspace
from finsec.testing.planner import generate_plan
from finsec.workflow import WorkflowCapture, merge_workflow_assignments, run_offline_workflow


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Create a new synthetic workspace, ingest examples/demo.har, run the deterministic "
            "offline pipeline, and generate one non-executing plan. Existing workspaces are never "
            "deleted or overwritten."
        )
    )
    parser.add_argument(
        "--root",
        type=Path,
        help="Output root containing workspaces/ and captures/ (default: a unique /tmp directory).",
    )
    parser.add_argument("--slug", default="finsec-demo", help="Path-safe demo workspace slug.")
    return parser.parse_args()


def main() -> None:
    args = _arguments()
    repository = Path(__file__).resolve().parents[1]
    root = (
        args.root.expanduser().resolve()
        if args.root is not None
        else Path(tempfile.mkdtemp(prefix="finsec-hunt-demo-"))
    )
    root.mkdir(parents=True, exist_ok=True)

    config = build_setup_config(
        project_name="FinSec Hunt Synthetic Demo",
        slug=args.slug,
        hosts=["api.example.test"],
        accounts=[AccountInput("ACCOUNT_A"), AccountInput("ACCOUNT_B")],
        production=False,
    )
    created = create_setup_workspace(config, root / "workspaces", root / "captures")
    source = repository / "examples" / "demo.har"
    incoming = created.capture_root / "incoming" / "demo.har"
    shutil.copy2(source, incoming)
    manifest = created.capture_root / "workflow.yaml"
    merge_workflow_assignments(
        manifest,
        [WorkflowCapture(file=incoming.name, actor="ACCOUNT_A", channel="WEB")],
    )

    result = run_offline_workflow(
        created.workspace,
        manifest_path=manifest,
        progress=lambda message: print(f"Workflow: {message}"),
    )
    active = sorted(
        (
            item
            for item in load_hypotheses(created.workspace).hypotheses
            if item.kind == "SECURITY_HYPOTHESIS" and item.disposition == "ACTIVE"
        ),
        key=lambda item: ({"P1": 0, "P2": 1, "P3": 2}[item.priority], -item.scores.total, item.id),
    )
    plan = generate_plan(created.workspace, active[0].id).plan if active else None

    print("\nSynthetic demo completed.")
    print(f"Workspace: {created.workspace.root}")
    print(f"Manifest: {manifest}")
    print(f"Observations: {result.observations}")
    print(f"Endpoints: {result.endpoints}")
    print(f"Active hypotheses: {result.active_hypotheses}")
    print(f"Research tasks: {result.research_tasks}")
    if plan is not None:
        print(f"Review-only plan: {plan.id} ({plan.status}, {plan.execution_default})")
    else:
        print("Review-only plan: none; inspect research tasks for missing evidence.")


if __name__ == "__main__":
    try:
        main()
    except (FinsecError, OSError) as error:
        print(f"Demo workflow failed: {error}", file=sys.stderr)
        raise SystemExit(1) from error
