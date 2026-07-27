---
name: run-finsec-hunt
description: Run a safe synthetic FinSec Hunt workflow or guide an authorized target through the passive deterministic pipeline.
---

# Run FinSec Hunt

Use the repository's non-destructive driver for a synthetic demonstration:

```bash
.claude/skills/run-finsec-hunt/driver.py
```

Choose an output root or slug when useful:

```bash
.claude/skills/run-finsec-hunt/driver.py \
  --root /tmp/finsec-agent-demo \
  --slug agent-demo
```

The driver delegates to `scripts/run_demo_workflow.py`. It creates validated synthetic scope,
researcher-owned account labels, a capture manifest, offline analysis artifacts, and one
non-executing plan. It never deletes or overwrites an existing workspace.

For a real authorized target, do not use the demo artifact as target evidence. Guide the user
through:

```bash
hunt setup
hunt workflow --workspace workspaces/<slug>
hunt hypotheses --research-tasks --workspace workspaces/<slug>
hunt status --workspace workspaces/<slug>
```

Use `--manifest PATH` for a non-default capture layout. Use `--no-ingest` only when the researcher
explicitly wants to analyze observations that were already imported.

Safety rules:

- Never request, store, print, or infer credentials or personal account identifiers.
- Never remove an existing workspace or capture directory.
- Never send requests or execute generated plan steps.
- Treat OpenAPI, GraphQL, and mobile artifacts as static/documentation evidence.
- Stop automation at hypotheses/status unless the user explicitly requests a review-only plan.
- Preserve conflicts and researcher edits; do not force regeneration.

See `README.md`, `how-to-use.md`, and `docs/workflow-rationale.md` for the complete contracts.
