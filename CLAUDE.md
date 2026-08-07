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
- Integration tests: `pytest tests/integration/`

### Running the Application
- CLI interface: `hunt --help`
- Interactive setup wizard: `hunt setup`
- Local Web Cockpit: `hunt web --workspace-root workspaces --capture-root captures`
- Standalone Web server: `hunt-web`
- Local MCP Server: `hunt-mcp` (alias: `finsec-hunt-operator`)

### Utility Scripts
- `scripts/check.sh`: Run linter + type checker in one pass.
- `scripts/generate_synthetic_fintech_hars.py`: Generate synthetic HAR fixtures for testing.
- `scripts/evaluate_workflow_precision.py`: Benchmark workflow and hypothesis precision.
- `scripts/run_demo_workflow.py`: Run the demo ingestion-to-report pipeline.

## Architecture & Code Structure

### High-Level Architecture
FinSec Hunt is a local-first research workspace for fintech security analysis built around strict **separation of knowledge states**:

1. **Ingestion & Normalization (`finsec/ingest/`, `finsec/normalization/`)**: Converts HAR files, Burp XML, Caido JSON, and OpenAPI specs into redacted factual observations (`ObservationStore`) and classified endpoint inventories (`EndpointStore`). Sub-modules: `har.py`, `har_io.py` (HAR parsing), `traffic.py` (Burp XML), `openapi.py`, `common.py` (shared utilities). Normalization covers `classification.py` (endpoint categorization), `inventory.py`, `paths.py` (path normalization), and `ownership.py` (ownership-scope detection).
2. **Recon (`finsec/recon/`)**: Processes static artifacts (GraphQL schemas, mobile app strings) without active runtime probes. `graphql.py` (SDL/introspection inventory), `mobile.py` (APK/IPA string extraction), `domain.py` (typed discovery models).
3. **Authentication (`finsec/auth/`)**: Actor-owned authentication capture, storage, and lifecycle management. `capture.py` (detect/extract auth from HAR/Burp/raw requests, JWT decoding), `store.py` (permission-restricted local secret store), `service.py` (auth lifecycle, continuity checks, preflight validation, observed refresh handling).
4. **Modeling (`finsec/modeling/`)**: Derives actors, resources, operation maps, ownership, and invariants from observations. `generator.py` (model generation), `merge.py` (stable fingerprinting and merge logic), `invariants.py` (traceable invariant extraction), `models.py` and `domain.py` (typed domain contracts).
5. **Behavior Analysis (`finsec/behavior/`)**: Deterministic business-logic behavior analysis. `extraction.py` (redacted signal extraction from observations), `reconstruction.py` (workflow reconstruction, state inference, graph persistence), `analysis.py` (business invariant inference, mutation hypothesis generation), `rendering.py` (human-readable and DOT graph output), `domain.py` (typed contracts for workflows, invariants, hypotheses), `benchmark.py` (labeled precision benchmarking).
6. **Hypotheses (`finsec/hypotheses/`)**: Generates evidence-gated research hypotheses based on inferred domain models and invariants. `generator.py` (hypothesis generation), `domain.py` (typed hypothesis records and stores).
7. **Testing & Execution (`finsec/testing/`, `finsec/execution/`)**: Generates structured test plans. Plans default to `DO_NOT_EXECUTE` and `human_approval_required: true`. Execution is restricted to checksum-approved read-only HTTP requests via `hunt execute`. Testing sub-modules: `planner.py`, `templates.py` (bounded request templates), `burp.py` (Burp Repeater export), `domain.py`. Execution sub-modules: `runner.py` (sequential HTTP runner with audit trail), `policy.py` (checksum-based approval), `domain.py`.
8. **Evidence & Validation (`finsec/evidence/`, `finsec/validation/`)**: Indexes evidence and runs skeptical completeness and domain integrity checks. Evidence: `manager.py`, `domain.py`. Validation: `validator.py`, `domain.py`.
9. **Readiness (`finsec/readiness/`)**: Canonical workspace readiness resolution. `resolver.py` (read-only pipeline readiness evaluation), `provenance.py` (semantic fingerprints and stage provenance persistence), `domain.py` (pipeline stage enum, readiness models).
10. **Reporting (`finsec/reporting/`)**: Renders versioned audit reports using Jinja2 templates (`reporting/templates/*.j2`).

### Entry Points & Interfaces
- `finsec/cli.py`: Main CLI entry point powered by Typer (`hunt` command). Major subcommand groups: `init`, `setup`, `workspace` (use/current/clear/delete/migrate-auth), `actors`, `actor-auth` (status/check/import/set/refresh/configure-refresh/clear), `ingest` (HAR/Burp/Caido/OpenAPI/GraphQL/wizard), `classify`, `noise`, `inventory`, `workflows` (build/list/show/explain/graph), `logic` (analyze/hypotheses/explain/blockers/plan), `model`, `invariants`, `hypotheses`, `show`, `plan`, `approve`, `execute`, `evidence`, `validate`, `report`, `status`, `web`, `export-burp`, `explain-endpoint`, `scan-mobile`.
- `finsec/setup.py`: Interactive, safety-first workspace setup wizard orchestration (target.yaml creation, scope configuration, account setup, capture ingestion).
- `finsec/workflow.py`: Orchestrates the offline passive ingestion and analysis pipeline (includes behavior analysis).
- `finsec/errors.py`: Application-specific exceptions (`FinsecError`, `WorkspaceError`, `HarFormatError`).
- `finsec/web/`: Starlette/Uvicorn local web server (`hunt web`). `server.py` (loopback-only entry point), `app.py` (ASGI app factory), `service.py` (sanitized read models), `operations.py` (setup/ingestion/retirement operations), `static/` (CSS/HTML/JS assets).
- `finsec/mcp/` & `finsec/mcp_server.py`: Stdio Model Context Protocol (MCP) server providing sanitized research state. `service.py` (safety-bounded application service), `models.py` (typed JSON response contracts), `sanitization.py` (centralized credential sanitization).
- `finsec/config/`: Target document parsing (`models.py` for `TargetDocument` and related Pydantic models), workspace path resolution (`workspace.py`), and scope management (`scope.py`).
- `finsec/utils/`: Global redaction rules (`redaction.py`) and YAML persistence helpers (`yaml_store.py`).

### Key Data Contracts
- **Pydantic models** are used throughout for serializable domain contracts with `extra="forbid"` to prevent schema drift (e.g., `BehaviorModel`, `ReadinessModel`, `ProvenanceModel`).
- **JSON Schemas** in `schemas/` define canonical formats: `target.schema.json`, `observation.schema.json`, `endpoint.schema.json`, `hypothesis.schema.json`, `actor-authentication.schema.json`, `behavior-workflow.schema.json`, `business-invariant.schema.json`, `business-logic-hypothesis.schema.json`, `graphql-operation.schema.json`, `mobile-discovery.schema.json`, `workflow.schema.json`.

### Test Structure
- `tests/conftest.py`: Shared fixtures (workspace creation, sample data).
- Unit tests: `test_ingest.py`, `test_modeling.py`, `test_hypotheses.py`, `test_evidence.py`, `test_execution.py`, `test_validation.py`, `test_reporting.py`, `test_recon.py`, `test_cli.py`, `test_web.py`, `test_workflow.py`, `test_setup.py`, `test_readiness.py`, `test_authentication.py`, `test_business_logic.py`, `test_planner.py`, `test_mcp_server.py`, `test_mcp_service.py`, `test_mcp_sanitization.py`.
- Specialized tests: `test_invariants.py`, `test_inventory.py`, `test_noise_reduction.py`, `test_path_scope_ownership.py`, `test_phase5_ingest.py`, `test_burp_export.py`, `test_divar_domain.py`, `test_project_contract.py`, `test_install_script.py`.
- Workspace tests: `test_workspace.py`, `test_workspace_default.py`, `test_workspace_delete.py`.
- Precision benchmarks: `test_hypothesis_precision.py`, `test_workflow_precision_benchmark.py`.
- Integration tests: `tests/integration/test_synthetic_fintech_workspace.py`.

### Development Guidelines & Constraints
- **Python Version & Type Safety**: Target Python 3.12+. Enforce strict Mypy typing (`mypy finsec`). Annotate all function signatures explicitly.
- **Formatting & Linting**: 100-character line limit, four-space indentation, enforced via Ruff (`select = ["E", "F", "I", "UP", "B", "SIM"]`). Excluded directories: `.agents`, `.codex`, `workspaces`.
- **Safety Boundaries**: Passive pipeline stages must never initiate network connections. Active execution is disabled by default in `target.yaml` and requires explicit checksum-matching human approval. The Web UI binds only to loopback interfaces (no authentication).
- **Error Handling**: Use `FinsecError` subclasses for expected user-facing failures (rendered as concise CLI errors by Typer). Never raise bare `Exception`.
- **Pydantic Discipline**: All serializable domain models use `extra="forbid"` to reject accidental schema drift. Use `model_validator` for cross-field validation.
- **StrEnum for Taxonomies**: Use `StrEnum` for typed enumerations (e.g., `PipelineStage`, `EpistemicStatus`, `InferenceConfidence`, `SafetyClassification`).
