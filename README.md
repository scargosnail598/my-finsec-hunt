# FinSec Hunt

FinSec Hunt is a local-first, file-based research workspace for authorized fintech Web/API/Mobile bug bounty analysis. It is not a vulnerability scanner: the deterministic pipeline organizes evidence, generates research hypotheses, drafts safety-gated test procedures, validates researcher-supplied proof skeptically, and produces versioned reports without sending requests or requiring an LLM.

```text
HAR / Burp XML / Caido JSON / OpenAPI / GraphQL / mobile artifacts
  -> redacted observations and static architecture leads
  -> conservative endpoint inventory
  -> actors, resources, workflows, and invariants
  -> evidence-backed attack hypotheses
  -> safe test plan
  -> human approval and manual test
  -> redacted evidence
  -> skeptical validation
  -> versioned report
```

Facts, inferences, assumptions, hypotheses, tests, evidence, and findings remain separate throughout the workspace.

For setup and usage instructions, see [quick-install.md](quick-install.md) and [how-to-use.md](how-to-use.md).

## Architecture

- `finsec/config/`: target configuration and workspace creation/discovery.
- `finsec/ingest/`: bounded HAR, Burp XML, Caido-style JSON, and OpenAPI ingestion with shared redaction and stable observation IDs.
- `finsec/normalization/`: conservative path grouping and endpoint inventory generation.
- `finsec/recon/`: GraphQL schema inventory and bounded static mobile/APK architecture discovery.
- `finsec/modeling/`: typed domain models, non-destructive merging, model generation, and invariant extraction.
- `finsec/hypotheses/`: deterministic mutation-based hypothesis generation and transparent prioritization.
- `finsec/testing/`: policy-checked, non-executing test-plan generation.
- `finsec/evidence/`: evidence scaffolds, indexing, checksum tracking, and secret redaction.
- `finsec/validation/`: deterministic controls that attempt to disprove suspected findings.
- `finsec/reporting/`: Jinja-based, versioned report generation from confirmed evidence.
- `finsec/utils/`: atomic YAML persistence and reusable redaction helpers.
- `workspaces/<target>/`: researcher-editable files that act as shared memory.

There is no database, background service, browser automation, live target connection, attack execution, or provider-specific AI integration.

## Install

Python 3.12 or newer is required.

Automated Linux/macOS installation:

```bash
./install.sh
source .venv/bin/activate
```

Use `./install.sh --dev` to include pytest, Ruff, mypy, and type stubs. See [quick-install.md](quick-install.md) for all options and manual installation steps.

Linux/macOS:

```bash
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
```

Windows PowerShell:

```powershell
py -3.12 -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
```

## Quick Start

Create a target workspace:

```bash
hunt init demo
```

Before planning any active experiment, edit `workspaces/demo/target.yaml` and record authoritative scope plus researcher-controlled account labels. Never put passwords, JWTs, cookies, API keys, OTPs, or other credentials in target files.

```yaml
scope:
  hosts:
    - api.example.test

accounts:
  - id: ACCOUNT_A
    ownership: researcher
  - id: ACCOUNT_B
    ownership: researcher
```

Import the included synthetic HAR with a non-secret actor and channel label:

```bash
hunt ingest examples/demo.har \
  --workspace workspaces/demo \
  --actor ACCOUNT_A \
  --channel WEB
```

Build the deterministic knowledge pipeline:

```bash
hunt inventory --workspace workspaces/demo
hunt model --workspace workspaces/demo
hunt invariants --workspace workspaces/demo
hunt hypotheses --workspace workspaces/demo
hunt status --workspace workspaces/demo
```

Import other authorized passive artifacts when available:

```bash
hunt ingest-burp examples/demo-burp.xml \
  --workspace workspaces/demo --actor ACCOUNT_A --channel WEB
hunt ingest-caido examples/demo-caido.json \
  --workspace workspaces/demo --actor ACCOUNT_A --channel WEB
hunt ingest-openapi examples/demo-openapi.yaml --workspace workspaces/demo
hunt ingest-graphql examples/demo-schema.graphql \
  --workspace workspaces/demo --endpoint https://api.example.test/graphql
hunt scan-mobile examples/demo-mobile-strings.txt --workspace workspaces/demo
```

These commands read local files only. They never contact a target, replay a request, execute an APK, or confirm that a documented/static route is reachable.

Inspect and plan one hypothesis:

```bash
hunt hypotheses --priority P1 --workspace workspaces/demo
hunt show HYP-002 --workspace workspaces/demo
hunt plan HYP-002 --workspace workspaces/demo
hunt evidence HYP-002 --workspace workspaces/demo
```

After a human approves the plan and performs the manual test, add redacted evidence:

```bash
hunt evidence HYP-002 --workspace workspaces/demo \
  --add request.txt --kind request
hunt evidence HYP-002 --workspace workspaces/demo \
  --add response.json --kind response
```

Review and complete `evidence/HYP-002/metadata.yaml`, including the skeptical assessment and factual report narrative. Then validate and, only if appropriate, report:

```bash
hunt validate HYP-002 --workspace workspaces/demo
hunt report HYP-002 --workspace workspaces/demo
```

When the current directory is inside a target workspace, `--workspace` is optional. It is also optional from a project directory containing exactly one target under `workspaces/`.

## Phase 3 Commands

- `hunt hypotheses`: regenerates and displays the evidence-linked backlog.
- `hunt hypotheses --priority P1`: displays only the selected priority after regeneration.
- `hunt show HYP-xxx`: shows the complete hypothesis, evidence chain, scoring, and safety notes.
- `hunt plan HYP-xxx`: creates or updates a review-only test plan and never executes it.
- `hunt status`: includes hypothesis lifecycle counts and the five highest-priority items.

Hypotheses use seven mutation dimensions only when matching evidence exists:

```text
ACTOR  OBJECT  STATE  TIME  VALUE  CHANNEL  VERSION
```

Examples include cross-account object substitution, invalid-state operations, one-time request replay, observed financial value fields, equivalent version routes, and endpoints directly observed through multiple labeled channels. The generator does not emit generic advice such as “test for IDOR.”

## Transparent Prioritization

Each hypothesis receives four scores from 1 to 5:

```text
total = impact + likelihood + confidence + testability
```

- `P1`: impact is at least 4 and total is at least 14.
- `P2`: total is at least 10.
- `P3`: all remaining hypotheses.

This is a research queue, not a vulnerability severity rating. No hypothesis becomes a finding without controlled evidence and skeptical validation.

## Safety Gate

Every generated plan has:

```yaml
human_approval_required: true
execution_default: DO_NOT_EXECUTE
status: BLOCKED | READY_FOR_REVIEW
```

Planning is blocked when scope is missing or does not cover every source endpoint, required researcher-controlled accounts are absent, lifecycle evidence is insufficient, destructive actions are disallowed, or a financial-effect experiment targets production without explicit policy approval. Differential version plans validate all compared endpoint hosts.

An `APPROVED` annotation records researcher review; it does not cause FinSec Hunt to execute anything. FinSec Hunt contains no request executor.

## Phase 4 Evidence and Validation

- `hunt evidence HYP-xxx`: creates or displays an evidence workspace.
- `hunt evidence HYP-xxx --add FILE --kind request`: imports a redacted text/JSON artifact.
- `hunt validate HYP-xxx`: attempts to disprove the hypothesis using scope, plan, artifact, control, boundary, and impact checks.
- `hunt report HYP-xxx`: revalidates current evidence and reports only a `CONFIRMED`, report-ready result.

Text and JSON evidence is copied into the workspace only after automatic redaction. Screenshots, PDFs, archives, and other binary artifacts require `--already-redacted`, which records that the researcher manually reviewed them. Originals are never modified or copied as raw source material.

The validator can return:

```text
CONFIRMED
REFUTED
NEEDS_MORE_EVIDENCE
OUT_OF_SCOPE
EXPECTED_BEHAVIOR
```

Confirmation requires an in-scope source endpoint, a `READY_FOR_REVIEW` plan marked `APPROVED`, researcher-controlled accounts, a verified security boundary, request/response artifacts with matching checksums, negative controls, clean-session reproduction, authoritative result verification, meaningful impact, ruled-out alternative explanations, and completed redaction review. State-changing endpoints additionally require `before.json` and `after.json`; channel/version comparisons require matched requests and responses for both paths.

Ambiguous or missing fields always produce `NEEDS_MORE_EVIDENCE`. Secure controls produce `REFUTED`; documented or client-side-only behavior produces `EXPECTED_BEHAVIOR`; scope failures produce `OUT_OF_SCOPE`.

## Phase 5 Passive Integrations

- `hunt ingest-burp FILE`: imports bounded Burp XML history, including base64 request/response nodes, into redacted `BURP_XML` observations.
- `hunt ingest-caido FILE`: imports an array or top-level `entries`, `requests`, or `items` collection from a Caido-style JSON export.
- `hunt ingest-openapi FILE`: imports OpenAPI 3 or Swagger 2 operations as documented `OPENAPI` observations. Use `--base-url` when no absolute server is declared.
- `hunt ingest-graphql FILE`: inventories root query, mutation, and subscription fields from SDL or introspection JSON.
- `hunt scan-mobile PATH`: scans an APK, file, or static-analysis directory for bounded string-level URLs, API paths, GraphQL/WebSocket endpoints, deep links, and custom headers.

Traffic and OpenAPI imports feed `hunt inventory`. GraphQL and mobile discoveries remain separate passive inventories so schema declarations and APK strings cannot silently become runtime observations, hypotheses, or findings. Untouched generated recon records refresh with stable IDs; researcher edits are preserved and reported as conflicts.

Burp and Caido imports retain only redacted derivatives. OpenAPI and GraphQL derivatives omit examples, descriptions, default values, and credential-bearing raw content. Mobile scans never extract archives to disk or copy the supplied application into the workspace.

## Files Produced

- `observations/normalized/observations.yaml`: factual HAR/Burp/Caido records and documented OpenAPI operations, with explicit source provenance.
- `observations/har/*-redacted.har`: redacted traceability copy; the source HAR is never copied.
- `observations/raw/*-redacted.*`: bounded redacted derivatives for Burp, Caido, OpenAPI, and GraphQL imports.
- `observations/mobile/discoveries.yaml`: static mobile architecture leads with artifact references and reachability explicitly unconfirmed.
- `api/endpoints.yaml`: normalized endpoints with observation IDs, channels, and normalization evidence.
- `api/graphql.yaml`: schema-derived root operations, typed arguments, return types, sources, and optional endpoint context.
- `model/actors.yaml`: observed/configured account labels without invented roles.
- `model/resources.yaml`: endpoint-derived resources, identifiers, operations, fields, and evidence.
- `model/architecture.md`: hosts, inferred components, trust boundaries, and unknowns.
- `model/authorization.md`: endpoint authentication view with authorization explicitly unconfirmed.
- `model/workflows.md`: endpoint-derived operation maps without invented transition order.
- `model/state-machines.md`: state evidence gaps and planning constraints.
- `model/invariants.yaml`: traceable `INFERRED` or `ASSUMED` security properties.
- `hypotheses/backlog.yaml`: specific hypotheses with provenance, scores, impact, status, and safety notes.
- `tests/plans/plans.yaml`: non-executing procedures, assertions, evidence requirements, stop conditions, and cleanup.
- `evidence/HYP-xxx/metadata.yaml`: artifact index, skeptical assessment, and researcher-authored report facts.
- `evidence/HYP-xxx/conclusion.md`: manual observed-result, negative-control, and uncertainty notes.
- `evidence/HYP-xxx/requests/` and `responses/`: automatically redacted request/response evidence.
- `findings/validations.yaml`: generated validation checks, disposition, missing requirements, and report readiness.
- `reports/HYP-xxx-report-vN.md`: immutable report revisions generated only from confirmed evidence.

## Researcher Edit Preservation

Generated YAML records contain `generation.generated_checksum`. On rerun:

- Untouched records refresh while retaining stable IDs.
- Hypothesis `status`/`notes` and plan `approval_status`/`notes` are preserved as lifecycle fields.
- Other researcher-edited generated content is preserved exactly and reported as a conflict.
- Generated records that disappear from current evidence are retained rather than deleted automatically.
- Researcher-created records without generation metadata are preserved.
- Reports are never overwritten; changed confirmed narratives create the next `vN` report.

Markdown artifacts use `FINSEC-GENERATED` blocks. Generated blocks refresh while researcher text outside them remains untouched. To intentionally regenerate an edited YAML record, first preserve its notes, remove only that record, and rerun the relevant command.

## Conservative Normalization

FinSec Hunt normalizes UUIDs, ULIDs, long hexadecimal IDs, and long opaque identifiers using high-confidence patterns. Numeric path segments normalize only when at least two distinct values occur in the same structural position. Explicit OpenAPI path templates are preserved and labeled `documented_template`. Four-digit years and common paging/version segments remain literal.

Version-parity hypotheses are more conservative still: routes must share the same resource, HTTP method, and path signature after replacing only the explicit version segment.

## Secret Handling

Shared redaction covers common authorization headers, cookies, URL credentials, API keys, CSRF tokens, passwords, OTPs, JWTs, and token fields. Normalized observations store request/response field names rather than bodies or header values. OpenAPI/GraphQL derivatives retain normalized structure rather than raw examples or defaults. Sensitive capture and evidence directories are ignored by Git.

Redaction is defense in depth, not a guarantee. Review generated data before sharing it, and keep original captures outside the repository.

## Development

```bash
ruff format --check .
ruff check .
mypy finsec
pytest
```

## Current Limitations

- Burp support is XML-history import only; no Montoya extension or live proxy integration exists.
- Caido JSON layouts vary by version/plugin; the importer supports common array and `entries`/`requests`/`items` shapes, not every export dialect.
- OpenAPI ingestion supports inline request/response schemas but does not resolve `$ref`, callbacks, links, or external documents.
- GraphQL ingestion inventories root fields from SDL or introspection; it does not validate full schema semantics or test resolver authorization.
- Mobile scanning is bounded static string extraction, not decompilation, device instrumentation, reachability validation, or an APK security verdict.
- Path and resource inference intentionally miss ambiguous identifiers and product semantics.
- Actor labels do not imply roles; ownership, delegation, tenant, and KYC relationships remain unconfirmed.
- Lifecycle states are not inferred from field names alone, so state-transition plans remain blocked until reviewed evidence is added.
- Value hypotheses identify observed field names but never generate or execute dangerous values.
- Hypothesis scores prioritize research; they do not confirm exploitability or severity.
- Test plans are static procedures. There is no active testing, concurrency runner, browser automation, or autonomous exploitation.
- Evidence acquisition remains manual; FinSec Hunt indexes and redacts supplied files but does not capture target traffic itself.
- Deterministic validation verifies evidence completeness and explicit researcher assessments; it cannot independently prove that a narrative is truthful.
- Binary evidence cannot be automatically inspected and requires explicit researcher redaction confirmation.
- No LLM provider is required or integrated into the runtime pipeline.

Live Burp/Caido plugins, Playwright, background analysis, active GraphQL/OpenAPI requests, richer APK decompilation, and optional LLM assistance remain out of scope for this local-first release.
