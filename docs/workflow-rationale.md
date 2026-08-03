# Architecture And Workflow Rationale

This document explains how FinSec Hunt works, why the stages are ordered as they are, and which
claims the system can and cannot justify.

## Design Objective

The tool is a deterministic research organizer for authorized security work. Its job is to reduce
noise and preserve provenance without crossing the line into active execution or automated
vulnerability confirmation.

Three constraints shape the architecture:

1. Passive evidence may contain credentials and personal data, so retention must be minimized and
   redacted derivatives must be reviewable.
2. Traffic shows what happened once; it does not automatically reveal intended policy, ownership,
   lifecycle rules, or exploitability.
3. Researcher notes must survive regeneration, so generated data cannot be treated as disposable
   build output.

## Stage Contracts

| Stage | Input | Output | Why it exists |
|---|---|---|---|
| Setup | Researcher-entered scope and labels | `target.yaml`, scope docs, capture layout | Makes authorization and account ownership explicit before analysis. |
| Ingestion | Local passive artifact | Redacted derivative and `OBS-*` facts | Removes stored values while retaining method, host, path, field names, status, actor, channel, and provenance. |
| Classification | Observations plus policy | Traffic role and disposition | Keeps static, telemetry, analytics, and third-party noise auditable without promoting it. |
| Normalization | Classified observations | Stable `EP-*` endpoint families | Groups only strongly supported identifiers so hypotheses target semantic routes instead of individual instances. |
| Modeling | Endpoints plus configured labels | Actors, resources, operation maps, trust-boundary views | Converts route structure into reviewable domain language while marking ownership and roles unconfirmed. |
| Invariants | Endpoints and resources | Authentication, authorization, state, and single-execution properties | States what should hold without claiming the property is implemented. |
| Hypotheses | Runtime evidence, invariants, resources, gates | Active hypotheses, research tasks, suppressed candidates | Promotes only specific, testable questions and routes missing evidence into research tasks. |
| Planning | One active hypothesis plus target policy | `BLOCKED` or `READY_FOR_REVIEW` structured plan | Separates research validity from template availability and applies scope, ownership-baseline, destructive, financial, lifecycle, and bounded-execution checks before approval. |
| Bounded execution | One checksum-approved structured plan | Redacted comparison evidence plus immutable audit revision | Sends only the reviewed sequential read-only requests; it cannot invent payloads or confirm a vulnerability. |
| Evidence | Researcher-supplied files | Redacted artifacts, checksums, assessment, narrative | Keeps proof separate from predictions and records integrity metadata. |
| Validation | Plan, evidence, endpoints, target policy | Skeptical disposition and missing requirements | Tries to disprove or downgrade the claim before a report can exist. |
| Reporting | Current confirmed validation | Immutable Markdown revision | Prevents stale or unvalidated narratives from becoming reports and preserves report history. |

Interactive setup may hand off directly to the ingestion wizard when unassigned HAR files are
already available. This is a user-interface shortcut, not a collapsed stage boundary: ingestion
still requires an explicit actor and channel for every file, writes redacted observations, and
offers downstream analysis as a separate reviewed choice. An empty capture directory produces an
explicit add-and-rescan or skip decision instead of silently advancing. Setup then offers actor
authentication as the next independent step only for actors that remain incomplete. When ingestion
makes every authenticated actor `READY`, setup reports that state and suppresses the redundant
prompt. Non-interactive setup skips both prompts and does not import captures.

## Canonical Readiness Contract

`finsec.readiness.resolve_workspace_readiness()` is the domain-layer source of truth for pipeline
status. It evaluates all twelve stages without modifying the workspace, resolving credentials,
refreshing authentication, approving plans, or sending network traffic. `hunt status`, the Web
overview, and the MCP workspace summary consume the same serializable `ReadinessReport` instead of
deriving readiness from separate file and count checks.

The lifecycle states have intentionally narrow meanings:

| State | Meaning |
|---|---|
| `NOT_CONFIGURED` | Required workspace or target configuration is absent. |
| `BLOCKED` | Configuration exists, but a mandatory prerequisite, integrity rule, evidence requirement, or safety gate is unmet. |
| `READY` | Current dependencies allow the stage to run, but no valid current result exists. |
| `COMPLETE` | A valid result exists for the current relevant inputs. |
| `STALE` | A result exists, but its relevant inputs changed or its provenance cannot be trusted. |

Interface availability is separate metadata. A stage can be `READY` while `available_via` contains
only `cli`; the Web UI must not replace that lifecycle state with `CLI_ONLY`. Warnings are also kept
separate from mandatory blockers so, for example, unknown credential expiration does not block an
otherwise safe offline analysis command.

Dependencies are explicit rather than a forced display-order chain. Authentication and ingestion
both depend on setup, but offline ingestion and classification do not depend on live credentials.
Execution depends on authentication and planning, validation depends on the relevant hypothesis,
plan, and evidence contract, and reporting depends on a current confirmed validation.

Actor readiness preserves the distinction between credential availability, local usability and
expiration, recorded target validation, confirmed actor identity, controlled ownership baselines,
and hypothesis-specific execution capability. Captures that happen to contain two actor or object
identifiers never manufacture ownership proof. Planning can remain available while authorization
execution is blocked for missing identity or ownership evidence.

Every mandatory reason uses a stable code, deterministic ordering, optional actor/hypothesis/plan/
artifact scope, secret-free evidence counts, and honest next actions. Current codes are:

```text
WORKSPACE_NOT_CONFIGURED, TARGET_NOT_CONFIGURED, NO_OBSERVATIONS,
ARTIFACT_MISSING, ARTIFACT_MALFORMED, ARTIFACT_SCHEMA_INCOMPATIBLE,
ARTIFACT_PROVENANCE_MISSING, ARTIFACT_INTEGRITY_FAILURE,
UPSTREAM_DEPENDENCY_CHANGED, UPSTREAM_STAGE_BLOCKED,
NO_ACTOR_CREDENTIAL, CREDENTIAL_EXPIRED, CREDENTIAL_EXPIRATION_UNKNOWN,
CREDENTIAL_UNUSABLE, TARGET_VALIDATION_MISSING, ACTOR_IDENTITY_NOT_CONFIRMED,
INSUFFICIENT_CONTROLLED_ACTORS, OWNERSHIP_BASELINES_MISSING,
OWNERSHIP_BASELINE_STALE, OWNERSHIP_BASELINE_CONFLICTING,
NO_ELIGIBLE_HYPOTHESIS, HYPOTHESIS_REQUIRES_MORE_EVIDENCE,
PLAN_MISSING, PLAN_STALE, PLAN_REQUEST_BUDGET_MISMATCH, PLAN_POLICY_BLOCKED,
HUMAN_APPROVAL_MISSING, APPROVAL_STALE, ACTIVE_EXECUTION_DISABLED,
READ_ONLY_POLICY_CONFLICT, DESTINATION_SCOPE_VALIDATION_FAILURE,
EVIDENCE_MISSING, BEFORE_AFTER_STATE_EVIDENCE_MISSING,
NO_CONFIRMED_VULNERABILITY
```

Readiness combines existing per-record generation metadata with semantic input fingerprints in the
non-secret `.finsec/readiness-provenance.yaml` sidecar. Inventory fingerprints cover observations
and only the target settings that affect classification/normalization; credential lifecycle changes
therefore do not stale offline analysis. Modeling, invariants, hypotheses, validation, plans, and
reports each bind to their own relevant inputs. Output fingerprints detect changed generated
artifacts, validation fingerprints ignore mutable hypothesis lifecycle annotations, and report
fingerprints bind the current hypothesis, evidence, invariants, validation, and rendered output.

Old workspaces remain readable and are never rewritten by status calculation. A non-empty derived
artifact without trusted readiness provenance is conservatively `STALE`; an empty legacy scaffold
with valid inputs is `READY`. Regenerating the affected producer records current provenance without
deleting researcher-authored evidence, notes, approvals, or report revisions.

## Why Documentation And Runtime Evidence Are Separate

OpenAPI describes declared operations and security schemes, but it does not prove that a route is
reachable or that enforcement matches the document. GraphQL schemas and mobile strings are even
further from runtime behavior.

Therefore:

- OpenAPI may feed the endpoint model and invariants as documentation evidence.
- Active security hypotheses require at least one HAR, Burp, or Caido runtime observation.
- Authentication hypotheses require an authenticated runtime baseline plus an anonymous runtime
  success signal with structured data.
- Object-authorization hypotheses require an authenticated runtime baseline and a mutable object
  identifier.
- Channel parity uses channels directly observed in runtime traffic, not labels from documentation.
- GraphQL and mobile discoveries remain in separate inventories until a researcher supplies
  runtime evidence.

This policy favors false negatives over fabricated attack claims.

## Scope Logic

Hosts are matched against exact entries and leading wildcards:

```text
api.example.test      matches only api.example.test
*.example.test        matches api.example.test and nested.api.example.test
*.example.test        does not match example.test
```

The same matching function is used by classification, test planning, and validation. This avoids a
route being treated as first-party during inventory but out-of-scope during planning, or vice
versa. Every host in a multi-host endpoint family must be covered.

Mixed classification ties resolve conservatively. For example, a family containing equal
first-party and third-party observations is treated as third-party, preventing an unsafe active
hypothesis at the cost of a possible false negative.

## Why Workflow Ingestion Is Explicit

Actor and channel labels influence authorization and channel-parity reasoning. Guessing them from
filenames would turn naming conventions into security facts. The workflow therefore requires an
explicit manifest.

A missing manifest is not silently interpreted as "analyze existing observations." Researchers
must use `--no-ingest` for that mode. This makes logs and automation unambiguous.

Source fingerprints identify the passive entry. Rerunning the same source does not create a new
observation. If its manifest assignment changes, the existing observation ID is retained and only
the actor/channel labels are refreshed. Stable IDs preserve downstream links while allowing a
researcher to correct metadata.

## Stable IDs And Edit Preservation

Observation IDs are monotonic within a workspace. Endpoint IDs are preserved for stable
method/path families. Generated model, invariant, hypothesis, plan, recon, and validation records
use semantic keys plus generation checksums.

On regeneration:

- Untouched generated records refresh and keep their IDs.
- Explicit lifecycle fields such as hypothesis status, plan approval, and notes survive.
- Other edited generated records are preserved and reported as conflicts.
- Unsupported generated records are retained with a suppressed disposition instead of deleted.
- Researcher-created records without generation metadata are preserved.
- Managed Markdown blocks refresh while text outside the blocks remains intact.

This treats the workspace as shared human/tool memory rather than disposable output.

## Safety Gate Rationale

A test plan is blocked when the system cannot justify the minimum safe automated experiment.
Typical blockers include unresolved source endpoints, incomplete scope, insufficient or ambiguous
researcher-owned baselines, public/shared scope parameters, unconfirmed lifecycle states,
destructive operations, and production financial effects. The underlying hypothesis may remain an
active manual research candidate.

`READY_FOR_REVIEW` means static checks passed and a supported bounded-execution template exists; it
is not authorization. A manually edited `APPROVED` value is not sufficient for active execution.
`hunt approve` checks deterministic blockers before prompting, then binds the human decision to the
exact generated plan and target-policy checksums, while `DO_NOT_EXECUTE` remains the default.

Only `hunt execute` crosses the network boundary. It requires `active_execution_enabled: true`, a
complete approval record, an active in-scope hypothesis, one supported mutation dimension, a
bounded sequential request budget, current DNS/scope validation, and an exact final confirmation.
Every other command remains passive. Execution writes redacted evidence and an append-only audit
record, but skeptical validation remains a separate step and no execution outcome automatically
confirms a vulnerability.

## Workspace Deletion Boundary

Workspace deletion is intentionally separate from setup and analysis. `hunt workspace delete`
requires an explicit workspace path and exact slug confirmation. Before removal, it validates the
target document, expected directory structure, path breadth, current working directory boundary,
symbolic-link status, and absence of a nested `.git` repository.

Normal deletion removes only the selected workspace directory. Credential and capture directories
remain separate because they may contain sensitive or original researcher-controlled artifacts
requiring an independent retention decision.

The explicit `--purge` mode is the complete-retirement boundary. It requires `PURGE <slug>`,
validates the workspace-specific credential file and exact-slug capture directory before changing
state, rejects symbolic links and unrecognized capture layouts, and removes only those validated
project paths. Custom capture layouts require an explicit `--capture-directory` because the
workspace does not persist arbitrary external capture roots.

## Validation Rationale And Limits

The validator is intentionally skeptical. It checks whether the claimed experiment was in scope,
approved, controlled, reproducible, integrity-protected, redacted, and supported by required
artifacts and assessments. Decisive secure controls can refute the hypothesis; intended or
client-side-only behavior can become `EXPECTED_BEHAVIOR`; scope failure becomes `OUT_OF_SCOPE`.

However, this is not cryptographic attestation of a remote interaction. Checksums prove that stored
files match their index, not that the server produced them. Assessment booleans and narrative text
are researcher assertions. `CONFIRMED` therefore means the local evidence package satisfies the
declared deterministic contract, not that FinSec Hunt independently observed or reproduced the
target behavior.

## Automation Boundaries

The standard CI workflow runs formatting, lint, strict typing, unit/integration tests, CLI startup,
shell syntax checks, and a wheel build. A scheduled/manual workflow runs the isolated SyntheticPay
validation under `/tmp` and uploads its report.

The demo runner and agent driver are non-destructive. They create new synthetic roots and refuse to
overwrite existing workspaces. The deeper synthetic validation runner deletes only its fixed,
guarded `/tmp/finsec-synthetic-validation` directory and verifies that tracked research workspaces
retain identical checksums.

## Residual Tradeoffs

- Conservative grouping and evidence gates can miss legitimate findings.
- Redaction cannot recognize every business secret or personal identifier.
- Product semantics still require researcher annotations.
- Multi-host endpoint families can hide host-specific behavior; downstream scope checks cover all
  hosts, and conservative classification prevents unsafe promotion.
- The file-based model favors transparency and portability over concurrent writers and database
  transactions.

These tradeoffs are deliberate for a local-first research assistant whose primary failure mode to
avoid is turning incomplete evidence into an unjustified security claim.
