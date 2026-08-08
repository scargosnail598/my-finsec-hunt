#!/usr/bin/env python3
"""Run the production-backed realistic corpus quality gates."""

from __future__ import annotations

import argparse
import tempfile
from pathlib import Path

from finsec.behavior.corpus_evaluator import (
    evaluate_realistic_quality_gate_configuration,
    render_realistic_markdown,
)


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--configuration",
        type=Path,
        default=Path("tests/fixtures/workflow_realistic/quality-gates.yaml"),
    )
    return parser.parse_args()


def main() -> None:
    args = _arguments()
    with tempfile.TemporaryDirectory(prefix="finsec-realistic-quality-gates-") as temporary:
        report, _repeated = evaluate_realistic_quality_gate_configuration(
            args.configuration, Path(temporary)
        )
    print(render_realistic_markdown(report), end="")
    print("Realistic corpus quality gates passed.")


if __name__ == "__main__":
    main()
