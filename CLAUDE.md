# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

Follow `AGENTS.md` as the primary repository-wide source of truth.

## Environment & Commands

Python 3.12+ is required.

### Setup & Activation
```bash
./install.sh --dev
source .venv/bin/activate
```

### Verification & Testing
```bash
# Run standard CI check suite (formatting, linting, type checks, pytest, cli check)
./scripts/check.sh

# Run full check suite including synthetic validation workflow
./scripts/check.sh --synthetic

# Run linting and formatting individually
ruff format --check .
ruff check .
mypy finsec

# Run tests
pytest                                 # Run all tests
pytest tests/test_ingest.py            # Run a single test file
pytest tests/test_ingest.py -k test_har # Run a specific test function
```

### Executing CLI & Demos
```bash
hunt --help                             # CLI entry point
python scripts/run_demo_workflow.py    # Non-destructive safe synthetic demo
```

## Architecture & Knowledge Separation

FinSec Hunt is a local-first, deterministic security research pipeline with a strict safety boundary: it reads local files only, never contacts live targets, and contains no request execution capability.

### Pipeline Stages
```text
config -> ingest -> normalization -> modeling -> invariants -> hypotheses
       -> non-executing plans -> evidence -> validation -> reporting
```

Knowledge states are explicitly separated:
- **Observations (Facts)**: Imported passive HAR/Burp XML/Caido JSON captures with automatic secret redaction.
- **Endpoint Inventory (Inferences)**: Route normalization and classifications.
- **Side Inventories**: GraphQL schemas (`finsec/recon/graphql.py`) and mobile artifacts (`finsec/recon/mobile.py`) remain passive static inventories — they are never auto-promoted to active hypotheses without runtime traffic evidence.
- **Modeling**: Domain actors, resources, operation maps, invariants, and edit-preserving YAML state merges.
- **Hypotheses & Tasks**: Evidence-gated hypothesis scoring (`total = impact + likelihood + confidence + testability`).
- **Testing**: Non-executing plan generation requiring explicit human approval (`approval_status: APPROVED`).
- **Evidence & Validation**: Redacted evidence management, checksum integrity, scope validation, and disposition assignment (`CONFIRMED`, `REFUTED`, etc.).
- **Reporting**: Versioned immutable reports (`reports/HYP-xxx-report-vN.md`).

### Key Modules
- `finsec/config/`: Target models, workspace management, and wildcard scope matching (`*.domain` subdomains vs apex host).
- `finsec/ingest/`: Passive traffic importers (HAR, Burp, Caido, OpenAPI) and credential/token redaction (`finsec/utils/redaction.py`).
- `finsec/normalization/`: Endpoint inventory classification and REST path parameter normalization.
- `finsec/recon/`: Passive GraphQL and APK/mobile static string discovery.
- `finsec/modeling/`: Domain artifacts, invariants, and edit-preserving merges.
- `finsec/hypotheses/`: Traffic evidence gates, mutation candidates, and priority scoring.
- `finsec/testing/`: Safety-gated non-executing test procedure generation.
- `finsec/evidence/`, `finsec/validation/`, `finsec/reporting/`: Proof handling, validator checks, and Jinja report output.
- `finsec/utils/yaml_store.py`: Atomic YAML persistence preserving manual researcher edits.

## Safety & Workspace Guardrails

- **Workspace Preservation**: Never delete, reset, or overwrite real workspaces (`workspaces/` and `captures/`). Treat workspace data as potentially sensitive target artifacts.
- **Testing Isolation**: Always use `tmp_path` in pytest or isolated `/tmp` subdirectories (via `scripts/run_demo_workflow.py`).
- **No Live Execution**: Do not add live request execution, browser automation, credential handling, or request replay capabilities.
