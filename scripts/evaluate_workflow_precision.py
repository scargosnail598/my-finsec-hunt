#!/usr/bin/env python3
"""Run the compact workflow-precision benchmark without network access."""

from __future__ import annotations

import argparse
import json
import tempfile
from pathlib import Path

from finsec.behavior.benchmark import (
    evaluate_benchmark,
    load_benchmark,
    render_markdown,
    write_report,
)


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--fixture",
        type=Path,
        default=Path("tests/fixtures/workflow_precision/benchmark.json"),
    )
    parser.add_argument("--json-output", type=Path)
    parser.add_argument("--markdown-output", type=Path)
    return parser.parse_args()


def main() -> None:
    args = _arguments()
    definition = load_benchmark(args.fixture)
    with tempfile.TemporaryDirectory(prefix="finsec-workflow-benchmark-") as temporary:
        report = evaluate_benchmark(definition, Path(temporary))
    if args.json_output is not None or args.markdown_output is not None:
        if args.json_output is None or args.markdown_output is None:
            raise SystemExit("--json-output and --markdown-output must be provided together")
        write_report(report, args.json_output, args.markdown_output)
    print(json.dumps(report.model_dump(mode="json"), indent=2, sort_keys=True))
    print(render_markdown(report), end="")


if __name__ == "__main__":
    main()
