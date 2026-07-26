# How to Use FinSec Hunt

FinSec Hunt turns authorized passive evidence into a structured research workspace. It separates facts, inferences, hypotheses, test plans, evidence, validation decisions, and reports.

```text
Passive artifact
  -> redacted observation or static lead
  -> endpoint and product model
  -> security invariant
  -> attack hypothesis
  -> human-reviewed test plan
  -> manually collected evidence
  -> skeptical validation
  -> versioned report
```

FinSec Hunt does not send requests or execute proposed tests.

Install and activate it first:

```bash
./install.sh
source .venv/bin/activate
```

See `quick-install.md` for manual, development, offline, and Windows installation options.

## 1. Create a Target Workspace

```bash
hunt init example-fintech
```

This creates:

```text
workspaces/example-fintech/
├── target.yaml
├── scope/
├── observations/
├── api/
├── model/
├── hypotheses/
├── tests/
├── evidence/
├── findings/
└── reports/
```

## 2. Record Scope and Accounts

Edit `workspaces/example-fintech/target.yaml` before planning tests:

```yaml
scope:
  hosts:
    - api.example.test

accounts:
  - id: ACCOUNT_A
    ownership: researcher
  - id: ACCOUNT_B
    ownership: researcher

testing:
  production: true
  human_approval_required: true
  destructive_testing: false
```

Also record the authoritative program rules in:

```text
scope/program.md
scope/scope.md
scope/restrictions.md
```

Never place passwords, cookies, JWTs, API keys, OTPs, or other credentials in `target.yaml` or research notes.

## 3. Import Passive Evidence

Use only artifacts obtained within the program's authorization and restrictions.

### HAR traffic

```bash
hunt ingest traffic.har \
  --workspace workspaces/example-fintech \
  --actor ACCOUNT_A \
  --channel WEB
```

### Burp XML history

```bash
hunt ingest-burp burp-history.xml \
  --workspace workspaces/example-fintech \
  --actor ACCOUNT_A \
  --channel WEB
```

### Caido-style JSON

```bash
hunt ingest-caido caido-export.json \
  --workspace workspaces/example-fintech \
  --actor ACCOUNT_A \
  --channel WEB
```

### OpenAPI or Swagger

```bash
hunt ingest-openapi openapi.yaml \
  --workspace workspaces/example-fintech
```

If the document has no absolute server URL:

```bash
hunt ingest-openapi openapi.yaml \
  --workspace workspaces/example-fintech \
  --base-url https://api.example.test
```

OpenAPI operations are labeled as documentation evidence. They are not proof that an endpoint is reachable or behaves as documented.

### GraphQL SDL or introspection JSON

```bash
hunt ingest-graphql schema.graphql \
  --workspace workspaces/example-fintech \
  --endpoint https://api.example.test/graphql
```

GraphQL operations are stored in `api/graphql.yaml`. They remain schema-derived leads and do not become confirmed runtime observations.

### Static mobile or APK artifact

```bash
hunt scan-mobile authorized-app.apk \
  --workspace workspaces/example-fintech
```

You may also scan a JADX output directory or an individual text/binary artifact:

```bash
hunt scan-mobile jadx-output \
  --workspace workspaces/example-fintech
```

The scanner performs bounded string discovery only. It does not execute, install, or extract the application to the workspace.

Supported channel labels are:

```text
WEB
MOBILE
PARTNER_API
PUBLIC_API
UNKNOWN
```

Use non-secret actor labels such as `ACCOUNT_A`, `ACCOUNT_B`, or `ANONYMOUS`.

## 4. Build the Endpoint Inventory

After importing HAR, Burp, Caido, or OpenAPI evidence:

```bash
hunt inventory --workspace workspaces/example-fintech
```

Review:

```text
observations/normalized/observations.yaml
api/endpoints.yaml
api/graphql.yaml
observations/mobile/discoveries.yaml
```

Check the source observation IDs and normalization rules before relying on a grouped endpoint. Numeric paths are grouped only when repeated evidence supports the inference; explicit OpenAPI templates are labeled `documented_template`.

## 5. Build the Product Model

```bash
hunt model --workspace workspaces/example-fintech
```

Review the generated actor, resource, authorization, architecture, and workflow files under `model/`. Generated content distinguishes observed and inferred knowledge and preserves researcher edits.

To run passive ingestion and every deterministic offline stage with one command, record explicit
HAR filename, actor, and channel assignments in `captures/<slug>/workflow.yaml`, then run:

```bash
hunt workflow --workspace workspaces/<slug>
```

Use `--manifest PATH` when the capture directory is not `captures/<slug>/`. The workflow ends at
hypotheses and status. Active tests, evidence conclusions, validation, and reporting remain
human-controlled.

Do not treat an inferred owner, role, workflow state, or authorization relationship as confirmed without evidence.

## 6. Generate Security Invariants

```bash
hunt invariants --workspace workspaces/example-fintech
```

Review `model/invariants.yaml`. Invariants describe properties that should hold, such as ownership enforcement, authentication requirements, state integrity, and single execution. They are not findings.

## 7. Generate and Prioritize Hypotheses

```bash
hunt hypotheses --workspace workspaces/example-fintech
```

Show only the highest-priority queue:

```bash
hunt hypotheses --priority P1 \
  --workspace workspaces/example-fintech
```

Inspect one hypothesis:

```bash
hunt show HYP-002 --workspace workspaces/example-fintech
```

Every hypothesis should identify its endpoint, invariant, observations, mutation dimensions, preconditions, expected secure behavior, possible vulnerable behavior, and safety constraints.

A hypothesis is not a vulnerability.

## 8. Generate a Safe Test Plan

```bash
hunt plan HYP-002 --workspace workspaces/example-fintech
```

Plans default to:

```yaml
human_approval_required: true
execution_default: DO_NOT_EXECUTE
```

Review `tests/plans/plans.yaml`. Confirm that the plan uses researcher-controlled accounts, minimal requests, reversible actions, small values, and no unrelated users. A plan may remain `BLOCKED` when scope, account ownership, lifecycle evidence, or financial-testing authorization is incomplete.

FinSec Hunt never executes the plan. The researcher must independently confirm program authorization and perform any allowed test manually.

## 9. Create and Add Evidence

Create the evidence workspace:

```bash
hunt evidence HYP-002 --workspace workspaces/example-fintech
```

Add request and response evidence:

```bash
hunt evidence HYP-002 \
  --workspace workspaces/example-fintech \
  --add request.txt \
  --kind request

hunt evidence HYP-002 \
  --workspace workspaces/example-fintech \
  --add response.json \
  --kind response
```

Supported evidence kinds include:

```text
request
response
before
after
screenshot
ownership
other
```

Text and JSON evidence is automatically redacted before storage. Binary artifacts require manual review and explicit confirmation:

```bash
hunt evidence HYP-002 \
  --workspace workspaces/example-fintech \
  --add screenshot.png \
  --kind screenshot \
  --already-redacted
```

Review `evidence/HYP-002/metadata.yaml` and `conclusion.md`. Record negative controls, clean-session reproduction, ownership evidence, actual behavior, uncertainties, and realistic impact without exaggeration.

## 10. Validate Skeptically

```bash
hunt validate HYP-002 --workspace workspaces/example-fintech
```

The validator returns one of:

```text
CONFIRMED
REFUTED
NEEDS_MORE_EVIDENCE
OUT_OF_SCOPE
EXPECTED_BEHAVIOR
```

Ambiguous evidence must remain `NEEDS_MORE_EVIDENCE`. Documentation, intended delegation, caching, UI-only behavior, missing boundary evidence, unrealistic prerequisites, or incomplete controls can refute or downgrade a suspected issue.

## 11. Generate a Report

Reports are available only for a currently validated, report-ready `CONFIRMED` result:

```bash
hunt report HYP-002 --workspace workspaces/example-fintech
```

Reports are written as immutable revisions:

```text
reports/HYP-002-report-v1.md
reports/HYP-002-report-v2.md
```

The report includes prerequisites, root cause, expected and actual behavior, violated invariant, evidence, impact, severity rationale, and remediation guidance.

## 12. Check Workspace Status

```bash
hunt status --workspace workspaces/example-fintech
```

Status includes counts for observations, endpoints, GraphQL operations, mobile discoveries, resources, actors, workflows, invariants, hypotheses, evidence sets, validations, and reports.

## Included Synthetic Demo

The repository includes safe synthetic artifacts:

```bash
hunt init demo

hunt ingest examples/demo.har \
  --workspace workspaces/demo --actor ACCOUNT_A --channel WEB
hunt ingest-burp examples/demo-burp.xml \
  --workspace workspaces/demo --actor ACCOUNT_A --channel WEB
hunt ingest-caido examples/demo-caido.json \
  --workspace workspaces/demo --actor ACCOUNT_A --channel WEB
hunt ingest-openapi examples/demo-openapi.yaml \
  --workspace workspaces/demo
hunt ingest-graphql examples/demo-schema.graphql \
  --workspace workspaces/demo \
  --endpoint https://api.example.test/graphql
hunt scan-mobile examples/demo-mobile-strings.txt \
  --workspace workspaces/demo

hunt inventory --workspace workspaces/demo
hunt status --workspace workspaces/demo
```

## Operational Safety Rules

- Work only on explicitly authorized targets and features.
- Use researcher-controlled accounts whenever possible.
- Do not access unrelated user data beyond minimal proof.
- Do not create financial loss, denial of service, spam, destructive changes, or persistent access.
- Keep request volume minimal and within program rules.
- Keep original captures and credentials outside Git.
- Review all redacted derivatives before sharing them.
- Never turn a suspicious endpoint directly into a vulnerability claim.

The required research progression is:

```text
Observation
  -> hypothesis
  -> controlled manual test
  -> evidence
  -> skeptical validation
  -> finding
```

## Current Limitations

- OpenAPI `$ref`, callbacks, links, and external documents are not resolved.
- GraphQL processing inventories root fields but does not test resolver behavior.
- Caido export layouts vary; only common structures are supported.
- Mobile scanning is string-based static discovery, not full decompilation.
- Redaction is defense in depth and still requires human review.
- There is no live proxy plugin, browser automation, request executor, autonomous exploitation, or active scanner.
