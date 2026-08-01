# Hunt Web UI Future Implementation TODO

This checklist records the gaps between the documented 12-stage Hunt pipeline and the current
local Web UI. It separates safe passive features that can be added to the browser from intentional
CLI-only security boundaries.

## Current Web Scope

The current Web UI is an onboarding, HAR-ingestion, passive-analysis, and sanitized review
cockpit. Its writable operations are limited to:

- Workspace setup.
- Capture-directory initialization.
- Non-overwriting reviewed HAR upload.
- Explicit actor/channel provenance assignment.
- Complete passive workflow execution through hypothesis generation.
- Confirmed workspace deletion or project purge.

The dashboard currently renders this reduced eight-stage pipeline:

```text
Observe -> Normalize -> Model -> Hypothesize -> Plan -> Evidence -> Validate -> Report
```

The documented pipeline has twelve stages:

```text
Setup -> Auth -> Ingest -> Classify -> Normalize -> Model -> Invariants -> Hypothesize
      -> Plan -> Execute -> Validate -> Report
```

## P0: Reconcile The Pipeline Model

- [ ] Replace the reduced eight-stage dashboard with a representation of all twelve canonical
  stages.
- [ ] Show `Setup` as complete when a valid workspace and target configuration exist.
- [ ] Show `Authentication` readiness independently for each controlled actor.
- [ ] Keep authentication separate from passive-analysis completion so the UI cannot imply that
  credentials are ready merely because hypotheses exist.
- [ ] Split `Classification` from `Normalization`, even if both are produced by one workflow call.
- [ ] Split `Invariants` from `Model`, while retaining the combined Model view if useful.
- [ ] Add an `Execution` stage between Plan and Evidence.
- [ ] Represent execution as `not configured`, `blocked`, `approved`, `executed`, or `CLI-only`
  without adding browser execution controls.
- [ ] Base stage state on artifact validity and prerequisites, not only non-zero record counts.
- [ ] Handle stale or out-of-order artifacts without marking later stages complete incorrectly.
- [ ] Add tests covering empty, partial, complete, stale, and conflicting pipeline states.

## P1: Safe Passive Workflow Actions

### Stage-Level Controls

- [ ] Add explicit browser actions for safe, offline stages where partial regeneration is useful:
  inventory, classification, noise analysis, modeling, invariants, and hypotheses.
- [ ] Show exact inputs, expected file changes, and the no-network guarantee before each action.
- [ ] Preserve stable IDs and researcher edits when a stage is regenerated.
- [ ] Display generation conflicts and preserved researcher edits after each run.
- [ ] Retain a single `Run complete passive workflow` action for the normal path.
- [ ] Document when a complete workflow rerun is safer than an individual stage rerun.

### Planning

- [ ] Add safe Web UI plan generation for an active hypothesis.
- [ ] Show plan status, policy decision, blockers, supported mutation dimensions, request budget,
  stop conditions, and `DO_NOT_EXECUTE` default before writing the plan.
- [ ] Require an explicit local confirmation that generating a plan does not approve or execute it.
- [ ] Preserve researcher-edited existing plans and report conflicts.
- [ ] Add plan-generation API routes with the same local-write and same-origin protections used by
  passive ingestion.
- [ ] Add regression tests proving plan generation sends zero target requests.

### Evidence Management

- [ ] Add evidence-package scaffolding for a selected hypothesis.
- [ ] Support evidence artifact import with an explicit kind, description, and redaction review.
- [ ] Require `already redacted` confirmation for binary or manually reviewed artifacts.
- [ ] Never render original evidence file bodies in browser responses.
- [ ] Show artifact metadata, hashes, integrity state, assessment completeness, and required gaps.
- [ ] Design a bounded editor for researcher assessments and conclusion metadata.
- [ ] Preserve the distinction between researcher assertions and independently derived facts.
- [ ] Add size limits, filename validation, non-overwrite behavior, symlink rejection, and path
  containment checks.

### Validation

- [ ] Add a local Web UI action to run skeptical validation for one hypothesis.
- [ ] Preview the evidence package and missing prerequisites before validation.
- [ ] Render every validation check, result, detail, and missing requirement.
- [ ] Make clear that validation attempts to disprove or downgrade a hypothesis.
- [ ] Preserve edited validation records and expose regeneration conflicts.
- [ ] Add tests proving validation is offline and cannot contact a target.

### Reporting

- [ ] Add report generation for a currently confirmed, report-ready validation.
- [ ] Refuse report generation for unvalidated, stale, or non-confirmed findings.
- [ ] Preserve immutable, versioned report revisions.
- [ ] Preview the validation checksum/state that will be used to generate the report.
- [ ] Continue allowing existing report revisions to be read without exposing unrelated files.
- [ ] Add tests for report refusal, revision reuse, and immutable new revisions.

## P2: Expand Passive Ingestion And Recon

### Multi-Format Runtime And Documentation Ingestion

- [ ] Add reviewed Burp XML history import.
- [ ] Add reviewed Caido JSON import.
- [ ] Add OpenAPI/Swagger JSON or YAML import with an optional base URL and channel.
- [ ] Keep documentation-derived operations visibly separate from runtime-confirmed observations.
- [ ] Apply file-size limits, type validation, redaction, non-overwrite behavior, and authorization
  attestations consistently across formats.
- [ ] Preserve explicit actor/channel assignment for runtime captures.
- [ ] Do not infer actor or channel from filenames.

### GraphQL Recon

- [ ] Add GraphQL SDL and introspection JSON import.
- [ ] Add an optional associated endpoint field without claiming reachability.
- [ ] Add a GraphQL inventory view for root operations, provenance, confidence, and conflicts.
- [ ] Render the existing `graphql_operations` count on the Overview page.
- [ ] Keep GraphQL schema evidence separate from runtime authorization proof.

### Mobile Recon

- [ ] Add a bounded local mobile-artifact scan workflow for an authorized file or static-analysis
  directory.
- [ ] Add a mobile discoveries view with source provenance and confidence.
- [ ] Render the existing `mobile_discoveries` count on the Overview page.
- [ ] Keep mobile strings and static discoveries separate from runtime observations.
- [ ] Define safe archive/directory limits before accepting large APK or analysis-tree inputs.

### Authentication During Ingestion

- [ ] Keep automatic credential capture disabled in the browser by default.
- [ ] Evaluate whether a reviewed, local-only authentication-candidate flow can expose redacted
  candidate metadata without returning secret values.
- [ ] If implemented, require a separate terminal confirmation before persisting any credential.
- [ ] Do not silently make actor authentication `READY` after ordinary Web UI ingestion.

## P2: Improve Existing Review Views

### Classification And Noise

- [ ] Add a dedicated classification summary rather than relying only on endpoint filters.
- [ ] Show suppressed static assets, telemetry, analytics, third-party traffic, public resources,
  and insufficient-evidence dispositions.
- [ ] Add a normalization-anomaly queue for low-confidence opaque path families.
- [ ] Show classification and suppression reasons without returning concrete request values.

### Normalization And Endpoints

- [ ] Show observed path-shape counts and normalization rules more prominently.
- [ ] Highlight low-confidence parameterization decisions that require researcher review.
- [ ] Add provenance links from an endpoint family to sanitized observation IDs.
- [ ] Continue excluding raw query values, body values, cookies, and authorization headers.

### Model And Invariants

- [ ] Give invariants a dedicated filterable section or view.
- [ ] Show invariant category, source endpoints, evidence links, knowledge status, and validation
  status.
- [ ] Improve access to generated authorization, workflow, and state-machine documents.
- [ ] Make the distinction between inferred model records and expected invariants explicit.

### Hypotheses

- [ ] Add an independent safe hypothesis-regeneration action.
- [ ] Show suppressed candidates when explicitly requested.
- [ ] Preserve a distinct research-task view for leads that fail active-hypothesis evidence gates.
- [ ] Add lifecycle history and conflict indicators without allowing premature finding promotion.

### Execution And Audit Visibility

- [ ] Add read-only visibility for existing execution summaries and append-only audit revisions.
- [ ] Show request count, outcome, stop reason, evidence path, and validation handoff without showing
  runtime credentials or sensitive request values.
- [ ] Keep browser execution controls absent unless a separate security design review explicitly
  approves them.

## P3: Configuration And Research-State Editing

- [ ] Design a safe editor for non-secret target metadata, scope hosts, focus areas, and documented
  restrictions.
- [ ] Require explicit review when a target-policy change invalidates existing approvals.
- [ ] Add bounded account-label and actor-metadata editing without accepting credential values.
- [ ] Add safe editing for allowlisted scope and model Markdown documents.
- [ ] Add hypothesis notes and lifecycle-status editing with provenance and conflict preservation.
- [ ] Add validation-assessment editing only after defining which fields are researcher assertions.
- [ ] Never provide a generic filesystem editor or arbitrary workspace-path API.

## Intentional CLI-Only Boundaries

The following operations should remain CLI-only unless an explicit security design review changes
the boundary:

- [ ] Credential set, import, refresh, refresh-flow configuration, and credential clearing.
- [ ] Network-backed actor authentication checks.
- [ ] Checksum-bound plan approval and approval-token handling.
- [ ] Live target execution.
- [ ] Execution confirmation and active-execution authority review.
- [ ] Runtime credential resolution or export.
- [ ] Any operation that sends requests to a target.

The Web UI may provide sanitized readiness, blockers, copyable CLI commands, and read-only results
for these operations.

## Burp Export Decision

- [ ] Decide whether secret-free Burp Repeater export belongs in the Web UI.
- [ ] If added, require an already checksum-approved plan and show the exact request budget and stop
  conditions.
- [ ] Keep actor credentials as placeholders only.
- [ ] State clearly that sending the exported request from Burp is manual active execution outside
  Hunt.
- [ ] Do not add direct Burp sending or Burp MCP execution to the Web UI.

## Raw Data And Privacy Boundaries

- [ ] Continue excluding raw captures from all API responses.
- [ ] Continue excluding credential profile references and secret-store keys.
- [ ] Continue excluding concrete path, query, header, cookie, and body values where they can contain
  secrets or personal data.
- [ ] Continue excluding evidence file bodies by default.
- [ ] If sanitized artifact previews are added, define a second redaction pass and strict content
  limits.
- [ ] Keep browser caching disabled and retain the restrictive content security policy.
- [ ] Continue loopback-only binding while the server has no authentication.
- [ ] Add threat-model tests for cross-origin writes, traversal, symlinks, oversized uploads, unsafe
  filenames, and secret leakage.

## API, Testing, And Documentation

- [ ] Add a documented API contract for every new Web UI read and write route.
- [ ] Require the existing same-origin custom header for every new local write.
- [ ] Use strict request models with unknown fields rejected.
- [ ] Run filesystem and CPU-heavy operations through a worker thread.
- [ ] Invalidate workspace snapshots after every successful write.
- [ ] Add Web UI tests for every success path, refusal path, and zero-network guarantee.
- [ ] Add secret-canary tests for every new response model.
- [ ] Update `docs/web-ui.md`, `docs/manual.md`, and `README.md` as features are added.
- [ ] Keep the displayed pipeline aligned with the canonical workflow documentation.
- [ ] Run `ruff format --check .`, `ruff check .`, `mypy finsec`, and `pytest` before merging.

## Suggested Delivery Order

1. Correct the twelve-stage visualization and readiness model.
2. Add passive plan generation, validation, and report generation.
3. Add evidence scaffolding and carefully bounded artifact import.
4. Add Burp, Caido, and OpenAPI ingestion.
5. Add GraphQL and mobile recon views and actions.
6. Add classification/noise and execution-audit review improvements.
7. Add bounded non-secret configuration and research-state editing.
8. Revisit secret-free Burp export only after the passive workflow is complete.

