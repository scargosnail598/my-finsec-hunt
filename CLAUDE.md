# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Development & Test Commands

- **Environment Setup**:
  - Python >= 3.12 required.
  - Install dependencies in dev mode: `python -m pip install -e ".[dev]"` (or `./install.sh --dev`).

- **Full Verification**:
  - Run all automated quality checks (formatting, linter, mypy, pytest, CLI check, shell syntax): `./scripts/check.sh`
  - Run checks with synthetic validation suite: `./scripts/check.sh --synthetic`

- **Linting & Formatting**:
  - Format code: `.venv/bin/ruff format .`
  - Check linter: `.venv/bin/ruff check .`
  - Type checking: `.venv/bin/mypy finsec`

- **Running Tests**:
  - Run all tests: `.venv/bin/pytest`
  - Run a specific test file: `.venv/bin/pytest tests/test_execution.py`
  - Run a specific test by name: `.venv/bin/pytest tests/test_execution.py -k test_function_name`

- **Demo & Synthetic Workflows**:
  - Run non-destructive demo workflow: `python scripts/run_demo_workflow.py`
  - Run standalone synthetic validation harness: `./scripts/run_synthetic_validation.sh`

---

## High-Level Architecture & Domain Model

FinSec Hunt is a local-first, passive-by-default research workspace for fintech Web, API, and mobile security analysis. It turns researcher-supplied traffic and static artifacts into traceable observations, conservative models, evidence-gated hypotheses, human-reviewed test plans, redacted evidence, and immutable reports.

### Passive Workflow Pipeline

1. **Ingestion & Redaction** (`finsec/ingest/`): Imports HAR, Burp XML, Caido JSON, and OpenAPI artifacts. Automatically redacts credentials/secrets into factual observation data.
2. **Normalization & Endpoint Inventory** (`finsec/normalization/`): Classifies endpoints deterministically, groups paths, and maintains the endpoint inventory.
3. **Recon** (`finsec/recon/`): Extracts static findings from GraphQL schemas and mobile artifacts (APK/strings). GraphQL and mobile results remain static leads and are tracked in separate inventories.
4. **Target Modeling** (`finsec/modeling/`): Maps actors, resources, operation channels, state invariants, and security boundaries. Edit-preserving merges ensure human edits in workspace YAML files are preserved across reruns.
5. **Evidence-Gated Hypotheses** (`finsec/hypotheses/`): Generates candidate hypotheses (e.g., IDOR, privilege escalation, cross-actor access) scored by impact, likelihood, confidence, and testability (P1/P2/P3 queue).
6. **Plan Generation** (`finsec/testing/`): Constructs structured test plans with `DO_NOT_EXECUTE` and `human_approval_required: true` as safe defaults.
7. **Bounded Execution** (`finsec/execution/`, `finsec/auth/`): Active HTTP engine (disabled by default). Requires explicit target policy activation, actor secret resolution, cryptographic plan/policy checksum binding (`hunt approve`), and manual confirmation. Supports read-only object substitution and auth marker comparisons only—no mutation, payload fuzzing, or automated redirection.
8. **Evidence & Validation** (`finsec/evidence/`, `finsec/validation/`): Scaffolds redacted evidence, validates integrity, scope, and control coverage before disposition (`CONFIRMED`, `REFUTED`, etc.).
9. **Reporting & MCP** (`finsec/reporting/`, `finsec/mcp/`, `finsec/mcp_server.py`): Renders immutable markdown report revisions (`reports/HYP-xxx-report-vN.md`) and serves sanitized workspace data over stdio MCP (`hunt-mcp`).

---

## Key Design Principles & Data Rules

- **Separation of Knowledge States**: Raw observed traffic (fact) $\rightarrow$ normalized route (inference) $\rightarrow$ invariant (expected property) $\rightarrow$ hypothesis (question) $\rightarrow$ evidence (supplied artifact) $\rightarrow$ report finding (validated state).
- **Passive Safety Default**: Offline pipeline (`hunt setup`, `hunt workflow`, `hunt hypotheses`, `hunt plan`) never connects to network targets.
- **Data Isolation**: Workspace state lives in `workspaces/<slug>/` and is decoupled from raw source captures in `captures/<slug>/`. Confidential secrets are stored in actor-bound local secret stores, never exported to Git, YAML plans, evidence, or reports.
- **Contract Enforcement**: Data contracts across target models, workflows, observations, and hypotheses are specified via JSON schemas in `schemas/`.
