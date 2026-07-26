---
name: run-finsec-hunt
description: Initialize, ingest, model, generate hypotheses, and execute test planning on a target using FinSec Hunt. Use when asked to run, test, analyze, or process a target with finsec-hunt.
---

# Run FinSec Hunt

Drive the FinSec Hunt pipeline to analyze fintech Web/API/Mobile traffic and generate evidence-backed attack hypotheses and test plans.

## Driver Harness (Agent Path)

The primary interface for driving this pipeline is the driver script located at `.claude/skills/run-finsec-hunt/driver.py`.

```bash
# Run the automated pipeline driver for a target workspace
.claude/skills/run-finsec-hunt/driver.py <target-name>
```

This runs the full sequence of deterministic pipeline steps:
1. Workspace initialization (`init`)
2. Traffic ingestion (`ingest`)
3. Endpoint inventory (`inventory`)
4. Architecture modeling (`model`)
5. Invariant extraction (`invariants`)
6. Prioritized hypothesis backlog generation (`hypotheses`)
7. Safety-gated test plan creation (`plan`)
8. Workspace summary output (`status`)

## Prerequisites

Python 3.12+ and virtual environment `.myvenv2` (or project `.venv`):

```bash
python3.12 -m venv .myvenv2
.myvenv2/bin/python -m pip install -e ".[dev]"
```

## Manual / Step-by-Step CLI Execution

If custom parameters or single-step executions are required:

```bash
# 1. Initialize workspace
.myvenv2/bin/python -m finsec.cli init mytarget

# 2. Ingest HAR file
.myvenv2/bin/python -m finsec.cli ingest examples/demo.har -w workspaces/mytarget --actor ACCOUNT_A --channel WEB

# 3. Build endpoint inventory
.myvenv2/bin/python -m finsec.cli inventory -w workspaces/mytarget

# 4. Build domain models
.myvenv2/bin/python -m finsec.cli model -w workspaces/mytarget

# 5. Generate invariants
.myvenv2/bin/python -m finsec.cli invariants -w workspaces/mytarget

# 6. Generate attack hypotheses
.myvenv2/bin/python -m finsec.cli hypotheses -w workspaces/mytarget

# 7. Generate safety-gated test plan
.myvenv2/bin/python -m finsec.cli plan HYP-001 -w workspaces/mytarget

# 8. Check status
.myvenv2/bin/python -m finsec.cli status -w workspaces/mytarget
```

## Gotchas & Considerations

- **Strict Redaction**: Tokens, cookies, and secrets in HAR/traffic captures are automatically redacted into placeholder tokens. Never check unredacted secrets into `target.yaml`.
- **Blocked Test Plans**: Test plans will show `BLOCKED` safety status until `target.yaml` is configured with authorized scope hosts and researcher-owned account IDs. This is expected default behavior to ensure authorization safety.
- **Offline Operation**: FinSec Hunt does not perform outbound HTTP requests or execute active attacks.
