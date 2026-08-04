Execution, Evidence, and Reporting (verified)

Sources: `finsec/execution/`, `finsec/evidence/manager.py`, `finsec/reporting/`.

Execution:
- Runner enforces policy checks (destinations, budgets, approval). Live execution requires explicit human approval and checksum-bound approvals.
- Dry-run options should be used where available.

Evidence:
- Evidence directories live under `workspaces/<slug>/evidence/HYP-xxx/`.
- Required state snapshots (`before.json`, `after.json`) must be generated from real request/response comparisons; skill must not fabricate them.
- Business-logic state evidence also supports `delayed_after`, `related_state`, `ledger_state`,
  `entitlement_state`, `inventory_state`, and `workflow_state`. Confirmation requires the kinds
  applicable to every affected resource.

Reporting:
- Reports are rendered from Jinja2 templates and require validated evidence and passing validators. `hunt report` (or equivalent) must be used.
