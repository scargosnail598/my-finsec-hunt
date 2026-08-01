---
name: finsec-hunt-operator
description: Skill to operate FinSec Hunt safely and end-to-end: workspace setup, capture ingestion, actor/auth management, inventory/modeling, hypothesis planning, approval, dry-run/live execution, evidence collection, report generation, Burp integration, MCP use, and troubleshooting. Activate when asked to perform or guide FinSec Hunt operations on a repository or workspace.
---

This skill teaches an AI agent to operate the FinSec Hunt repository and any configured workspace using only implemented, verified commands and tools. Follow these rules:

- Always locate the repository root (file `pyproject.toml`) and use the installed `hunt` CLI entry point (`finsec.cli:app`). Confirm paths before any mutating action.
- Inspect workspace state before suggesting changes. Use non-mutating inspection commands first and map observed artifacts to pipeline stages (observations, model, hypotheses, plans, approvals, evidence, reports).
- Route user requests to the appropriate reference document under `finsec-hunt-operator/references/`.
- Use only implemented commands, CLI options, and MCP tools discovered in source. Re-check `hunt --help` or source files if the installed package version differs.
- Default to offline and non-mutating operations. Stop at any human-approval, safety, or policy boundary.

Canonical quick workflow (verified stages)

1. Identify repo and workspace:
   - Confirm repository root contains `pyproject.toml` and package `finsec/`.
   - Confirm workspace path under `workspaces/<slug>` or via `target.yaml` in the workspace root.
2. Inspect (non-mutating):
   - `hunt workspace status -w workspaces/<slug>` or `hunt --help` then the appropriate `status`/`show` commands. Refer to `cli-reference.md`.
3. Import captures (offline):
   - `hunt ingest-burp <file.xml> -w workspaces/<slug> --actor ACCOUNT --channel WEB` (Burp XML)
   - `hunt ingest <file.har> -w workspaces/<slug> --actor ACCOUNT --channel WEB` (HAR)
4. Build inventory and models:
   - Run `hunt workflow --workspace workspaces/<slug>` to run offline modeling and hypothesis generation. This is non-mutating except for writing derived artifacts into the workspace.
5. Plan and approve:
   - Create plans via generated hypothesis records; approvals require checksum-bound approval files. Use `hunt` subcommands documented in `cli-reference.md`.
6. Dry-run and execution:
   - Always dry-run using CLI dry-run options where available; enable live execution only after explicit human approval and after confirming safety gates.
7. Evidence and reporting:
   - Follow `execution-evidence-reporting.md` for required evidence artifact shapes and `hunt report` commands.

Never expose or copy credentials. Always redact secrets in outputs.

For a specific task, consult these reference files (use exact filenames):

- `references/cli-reference.md`
- `references/workflow-and-gates.md`
- `references/workspace-and-artifacts.md`
- `references/actors-auth-and-ownership.md`
- `references/ingest-and-burp.md`
- `references/modeling-and-hypotheses.md`
- `references/execution-evidence-reporting.md`
- `references/mcp-reference.md`
- `references/troubleshooting.md`
- `references/implementation-status.md`

Before executing any mutating command show the exact copy-paste command and the files/status changes you expect. After execution, verify the effect and map it to the next minimal step.

If the installed `hunt` version differs from this skill's captured version, re-run `hunt --help` and treat that output as authoritative for available flags and subcommands.
