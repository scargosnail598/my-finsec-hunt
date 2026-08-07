#!/usr/bin/env python3
"""Run the checked-in deterministic workflow benchmark quality gates."""

from __future__ import annotations

import argparse
import tempfile
from pathlib import Path

from finsec.behavior.benchmark import (
    evaluate_quality_gate_configuration,
    render_markdown,
)


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--configuration",
        type=Path,
        default=Path("tests/fixtures/workflow_precision/quality-gates.json"),
    )
    return parser.parse_args()


def main() -> None:
    args = _arguments()
    with tempfile.TemporaryDirectory(prefix="finsec-workflow-quality-gates-") as temporary:
        report, _repeated = evaluate_quality_gate_configuration(args.configuration, Path(temporary))
    print(render_markdown(report), end="")
    print("Workflow benchmark quality gates passed.")


if __name__ == "__main__":
    main()
