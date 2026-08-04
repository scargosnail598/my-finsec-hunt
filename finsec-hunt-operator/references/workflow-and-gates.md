Workflow and Safety Gates (verified)

Sources: `finsec/workflow.py`, `finsec/execution/policy.py`, `finsec/testing/burp.py`, `finsec/cli.py`.

Key stages (implemented):
- Ingestion (passive): imports HAR, Burp, Caido, OpenAPI into observations.
- Normalization & Inventory: endpoint classification and parameterization.
- Modeling: derive actors, resources, workflows, and invariants.
- Hypothesis generation: rule-based generation requiring runtime observations for active hypotheses.
- Business-logic analysis: offline workflow reconstruction, state/transition inference, business
  invariants, and minimal mutation candidates synchronized into the canonical backlog.
- Planning: test plans generated with `DO_NOT_EXECUTE` default and `human_approval_required: true`.
- Execution: bounded runner enforces policy and approval checks (`finsec/execution/runner.py`, `policy.py`).

Safety gates:
- Active execution disabled by default in new `target.yaml` and requires explicit enabling and checksum-bound approvals.
- Runner validates destination addresses, request budgets, and actor credentials before sending HTTP.
- Burp exports refuse unsafe requests and require checksum-bound approval.
- Business-logic state changes and concurrency remain manual-only and unsupported by the bounded
  runner; planning does not weaken execution or approval checks.

Behavior on refusals:
- The system prints actionable refusal messages (e.g., missing approval, unsafe headers, invalid destination). Do not bypass; recommend smallest corrective step.
