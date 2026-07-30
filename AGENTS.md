# Repository Guidelines

## Project Structure & Module Organization

`finsec/` contains the Python 3.12 package, grouped by pipeline stage: ingestion, normalization, recon, modeling, hypotheses, testing, evidence, validation, and reporting. The Typer entry point is `finsec/cli.py`; shared configuration and utilities live in `finsec/config/` and `finsec/utils/`.

Tests under `tests/` generally mirror feature areas (for example, `tests/test_ingest.py`). JSON contracts are in `schemas/`, the packaged report template is in `finsec/reporting/templates/`, and synthetic fixtures are in `examples/`. `workspaces/` contains researcher-editable target data and may include sensitive artifacts; it is not application source.

## Build, Test, and Development Commands

- `./install.sh --dev`: create `.venv` and install the package with development tools.
- `python -m pip install -e ".[dev]"`: install manually in an activated virtual environment.
- `ruff format --check .`: verify formatting without changing files.
- `ruff check .`: run configured lint rules, including import sorting and bug-risk checks.
- `mypy finsec`: run strict static type checking.
- `pytest`: run the full test suite configured in `pyproject.toml`.
- `hunt --help`: verify the installed CLI and inspect commands.

## Coding Style & Naming Conventions

Use four-space indentation, Python 3.12 syntax, and a 100-character line limit. Ruff controls formatting and linting; mypy runs in strict mode. Type all functions. Use `snake_case` for modules, functions, and variables; `PascalCase` for classes and Pydantic models; and `UPPER_CASE` for constants. Keep behavior deterministic and preserve the separation between observations, inferences, hypotheses, evidence, and findings.

## Testing Guidelines

Name pytest files `test_<feature>.py` and functions `test_<behavior>()`. Use `tmp_path` for filesystem workflows and `typer.testing.CliRunner` for CLI coverage. Add regression tests for behavioral fixes. There is no declared coverage threshold; prioritize boundary cases, redaction, stable IDs, non-destructive regeneration, and safety gates.

## Commit & Pull Request Guidelines

Git history is currently minimal and does not establish a formal convention. Use concise, imperative commit subjects such as `add GraphQL import validation`, and keep each commit focused. Pull requests should explain the user-visible change, list validation commands run, link relevant issues, and include sample CLI output when behavior changes. Call out schema or workspace-format migrations explicitly.

## Security & Configuration

Never commit credentials, tokens, cookies, raw captures, or unredacted evidence. Keep originals outside the repository and review generated workspace data before sharing. Do not add live request execution or weaken human-approval gates without explicit design review.
