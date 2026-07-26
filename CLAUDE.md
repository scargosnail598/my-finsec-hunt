# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

### Development Setup & Virtual Environment
A virtual environment is required (Python >= 3.12). If using the local virtual environment `.myvenv2`:
- Use Python binaries from `.myvenv2/bin/` (e.g., `.myvenv2/bin/pytest`, `.myvenv2/bin/ruff`, `.myvenv2/bin/mypy`).

### Testing & Quality Controls
- **Run all tests**: `.myvenv2/bin/pytest`
- **Run a specific test file**: `.myvenv2/bin/pytest tests/test_ingest.py`
- **Run a single test**: `.myvenv2/bin/pytest tests/test_ingest.py -k test_har_ingestion`
- **Lint check**: `.myvenv2/bin/ruff check .`
- **Type check**: `.myvenv2/bin/mypy finsec`

### CLI Tool Usage
- **Run CLI commands directly**: `python -m finsec.cli --help` or `hunt --help` (when environment is activated)
- **Initialize a workspace**: `python -m finsec.cli init <workspace_name>`

## Code Architecture & Design Principles

FinSec Hunt is a local-first, file-based research workspace for authorized fintech Web/API/Mobile bug bounty analysis. It operates strictly via a deterministic pipeline over local YAML files and network captures. It does not send live network requests, run active attacks, or execute database operations.

### High-Level Architecture & Pipeline Stages

1. **`finsec/config/`**: Target configuration, workspace creation, discovery, and file paths.
2. **`finsec/ingest/`**: Ingestion modules for HAR, Burp XML, Caido JSON, and OpenAPI specs. Handles data sanitization, shared secret redaction, and deterministic observation ID generation.
3. **`finsec/normalization/`**: Path parameter grouping and endpoint inventory construction.
4. **`finsec/recon/`**: Schema/GraphQL inventory parsing and static mobile/APK architecture discovery.
5. **`finsec/modeling/`**: Domain model creation (actors, resources, workflows, state invariants) and non-destructive YAML model merging.
6. **`finsec/hypotheses/`**: Mutation-based attack hypothesis generation and transparent prioritization rules.
7. **`finsec/testing/`**: Policy-checked, non-executing test-plan generator enforcing safety gates.
8. **`finsec/evidence/`**: Evidence scaffold creation, checksum tracking, and secret sanitization.
9. **`finsec/validation/`**: Disproof/validation engines verifying proof requirements against evidence.
10. **`finsec/reporting/`**: Jinja2-based versioned markdown report compilation from validated evidence.
11. **`finsec/utils/`**: Atomic YAML reading/writing and string/dict secret redaction utilities.

### Core Architecture Concepts
- **Workspace Memory**: `workspaces/<target>/` acts as human-editable shared memory consisting of YAML files (e.g., `target.yaml`, `observations.yaml`, `endpoints.yaml`, `model.yaml`, `hypotheses.yaml`, `test_plan.yaml`, `evidence.yaml`, `findings.yaml`).
- **Data Isolation**: Facts (observations), inferences (endpoints/models), hypotheses, test plans, evidence, and confirmed findings remain strictly isolated across separate YAML artifacts.
- **Atomic Operations**: All file persistence uses atomic write/replace patterns (`finsec/utils/yaml.py`) to prevent corrupting workspace state.
