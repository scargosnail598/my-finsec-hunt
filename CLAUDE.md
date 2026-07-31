# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

### Setup & Installation
- Install dev environment: `./install.sh --dev` or `python -m pip install -e ".[dev]"` (Python >= 3.12 required)

### Linting & Type Checking
- Run linter: `ruff check .`
- Check formatting: `ruff format --check .`
- Apply formatting: `ruff format .`
- Type check: `mypy finsec`

### Testing
- Run full test suite: `pytest` (or `.venv/bin/pytest`)
- Run a single test file: `pytest tests/test_ingest.py`
- Run a specific test function: `pytest tests/test_ingest.py -k test_name`

### Running the Application
- CLI interface: `hunt --help`
- Local Web Cockpit: `hunt web --workspace-root workspaces --capture-root captures`
- Local MCP Server: `hunt-mcp`

## Architecture & Code Structure

### High-Level Architecture
FinSec Hunt is a local-first research workspace for fintech security analysis built around strict **separation of knowledge states**:

1. **Ingestion & Normalization (`finsec/ingest/`, `finsec/normalization/`)**: Converts HAR files, Burp XML, Caido JSON, and OpenAPI specs into redacted factual observations (`ObservationStore`) and classified endpoint inventories (`EndpointStore`).
2. **Recon (`finsec/recon/`)**: Processes static artifacts (GraphQL schemas, mobile app strings) without active runtime probes.
3. **Modeling (`finsec/modeling/`)**: Derives actors, resources, operation maps, ownership, and invariants from observations.
4. **Hypotheses (`finsec/hypotheses/`)**: Generates evidence-gated research hypotheses based on inferred domain models and invariants.
5. **Testing & Execution (`finsec/testing/`, `finsec/execution/`)**: Generates structured test plans. Plans default to `DO_NOT_EXECUTE` and `human_approval_required: true`. Execution is restricted to checksum-approved read-only HTTP requests via `hunt execute`.
6. **Evidence & Validation (`finsec/evidence/`, `finsec/validation/`)**: Indexes evidence and runs skeptical completeness and domain integrity checks.
7. **Reporting (`finsec/reporting/`)**: Renders versioned audit reports using Jinja2 templates (`report.md.j2`).

### Entry Points & Interfaces
- `finsec/cli.py`: Main CLI entry point powered by Typer (`hunt` command).
- `finsec/workflow.py`: Orchestrates the offline passive ingestion and analysis pipeline.
- `finsec/web/`: Starlette/Uvicorn local web server (`hunt web`) and operations service.
- `finsec/mcp/` & `finsec/mcp_server.py`: Stdio Model Context Protocol (MCP) server providing sanitized research state.
- `finsec/config/`: Target document parsing (`target.yaml`), workspace path resolution, and scope management.
- `finsec/utils/`: Global redaction rules (`redaction.py`) and YAML persistence helpers (`yaml_store.py`).

### Development Guidelines & Constraints
- **Python Version & Type Safety**: Target Python 3.12+. Enforce strict Mypy typing (`mypy finsec`). Annotate all function signatures explicitly.
- **Formatting & Linting**: 100-character line limit, four-space indentation, enforced via Ruff (`select = ["E", "F", "I", "UP", "B", "SIM"]`).
- **Safety Boundaries**: Passive pipeline stages must never initiate network connections. Active execution is disabled by default in `target.yaml` and requires explicit checksum-matching human approval.
