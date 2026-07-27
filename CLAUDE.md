# Claude Code Guidance

Follow `AGENTS.md` as the repository-wide source of truth. This file adds a concise operational map
for Claude Code sessions.

## Environment

Python 3.12+ is required. Prefer the project environment:

```bash
./install.sh --dev
source .venv/bin/activate
```

Run all checks with:

```bash
./scripts/check.sh
```

Run the deeper offline validation with:

```bash
./scripts/check.sh --synthetic
```

## Architecture

The runtime is deterministic, local-first, and file-based:

```text
config -> ingest -> normalization -> modeling -> invariants -> hypotheses
       -> non-executing plans -> evidence -> validation -> reporting
```

GraphQL and mobile discovery are passive side inventories. They do not become runtime observations
or active hypotheses without traffic evidence.

Key modules:

- `finsec/config/`: target models, workspace paths, setup, and wildcard scope matching.
- `finsec/ingest/`: bounded HAR/Burp/Caido/OpenAPI ingestion and redaction.
- `finsec/normalization/`: classification, path normalization, and endpoint inventory.
- `finsec/modeling/`: domain artifacts, invariants, checksums, and edit-preserving merges.
- `finsec/hypotheses/`: runtime-evidence gates, mutation candidates, and scoring.
- `finsec/testing/`: safety-gated procedures with no execution capability.
- `finsec/evidence/`, `finsec/validation/`, `finsec/reporting/`: proof handling and reports.
- `finsec/utils/yaml_store.py`: atomic YAML persistence.

## Safety And Workspace Handling

- Never delete, reset, or regenerate a real workspace as part of a demo or test.
- Treat `workspaces/` and `captures/` as potentially sensitive user data.
- Use `tmp_path` in tests and `/tmp` only through the guarded synthetic harness.
- Do not add live requests, browser execution, credential handling, or weakened approval gates.
- Preserve generated-record conflicts and researcher text outside managed Markdown blocks.

The agent driver at `.claude/skills/run-finsec-hunt/driver.py` delegates to the non-destructive
`scripts/run_demo_workflow.py`. It creates a new synthetic root and never removes an existing
workspace.

See `docs/workflow-rationale.md` before changing stage boundaries or evidence requirements.
