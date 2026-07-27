# FinSec Hunt

FinSec Hunt is a local-first research workspace for authorized fintech Web, API, and mobile
security analysis. It is not a scanner and contains no request executor. It turns researcher-
supplied passive artifacts into traceable observations, conservative models, reviewable
hypotheses, non-executing test plans, indexed evidence, skeptical validation results, and
versioned reports.

```text
HAR / Burp XML / Caido JSON / OpenAPI
  -> redacted factual observations
  -> classified endpoint inventory
  -> actors, resources, operation maps, and invariants
  -> evidence-gated hypotheses or research tasks
  -> human-reviewed plan (DO_NOT_EXECUTE)
  -> manually collected redacted evidence
  -> skeptical completeness and integrity checks
  -> immutable report revision

GraphQL schema / mobile artifact
  -> separate static discovery inventories
  -> researcher review (never runtime confirmation)
```

The central design rule is separation of knowledge states. An observed request is a fact; a
normalized route is an inference; an invariant is a property that should hold; a hypothesis is a
research question; evidence is researcher-supplied; and a finding is reportable only after the
validation gates pass. See [docs/workflow-rationale.md](docs/workflow-rationale.md) for the full
mechanism and the rationale behind every stage.

## Safety Boundary

FinSec Hunt:

- Reads local files only and never contacts a target.
- Never replays requests, opens browsers, executes APKs, or runs active tests.
- Requires explicit capture-to-actor assignments for automated ingestion.
- Generates plans with `human_approval_required: true` and `DO_NOT_EXECUTE`.
- Treats OpenAPI, GraphQL, and mobile strings as documentation/static evidence, not runtime proof.
- Preserves researcher edits and reports conflicts instead of overwriting them.

Use it only for work that is explicitly authorized by the applicable program rules. Redaction is
defense in depth, not a guarantee; review generated artifacts before sharing them.

## Install

Python 3.12 or newer is required.

```bash
./install.sh --dev
source .venv/bin/activate
```

Manual installation:

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

See [quick-install.md](quick-install.md) for installer options and troubleshooting.

## Safe Synthetic Demo

Run a complete, non-destructive offline demo:

```bash
python scripts/run_demo_workflow.py
```

The script creates a unique directory under `/tmp`, configures synthetic scope and two account
labels, ingests `examples/demo.har`, runs the offline pipeline, and generates one review-only plan.
It never deletes or overwrites an existing workspace. To choose the output location:

```bash
python scripts/run_demo_workflow.py --root /tmp/my-finsec-demo --slug demo
```

## Create A Real Workspace

The setup wizard validates scope hosts, account labels, safe defaults, capture paths, and analysis
policy without asking for credentials or personal identifiers.

```bash
hunt setup
```

Non-interactive setup with the same default-deny safety policy:

```bash
hunt setup \
  --name "Example Fintech" \
  --slug example-fintech \
  --host api.example.test \
  --host '*.services.example.test' \
  --account ACCOUNT_A \
  --account ACCOUNT_B \
  --yes
```

Leading wildcards cover subdomains, not the apex host. For example,
`*.example.test` covers `api.example.test` but not `example.test`; record both when both are in
scope.

The wizard creates:

```text
workspaces/example-fintech/       structured research memory
captures/example-fintech/         researcher-controlled input area
  incoming/                       sanitized HAR inputs
  processed/                      optional researcher filing area
  rejected/                       optional researcher filing area
  workflow.yaml                   explicit file/actor/channel assignments
```

Original captures stay outside the workspace. Generated redacted derivatives live under the
workspace and sensitive paths are added to `.gitignore`.

## Automated Offline Workflow

Place sanitized HAR files in `captures/<slug>/incoming/` and edit
`captures/<slug>/workflow.yaml`:

```yaml
version: 1
captures:
  - file: 01-account-a-login.har
    actor: ACCOUNT_A
    channel: WEB
  - file: 02-account-b-payments.har
    actor: ACCOUNT_B
    channel: MOBILE
```

Then run:

```bash
hunt workflow --workspace workspaces/<slug>
```

Use an explicit non-default manifest when necessary:

```bash
hunt workflow \
  --workspace workspaces/<slug> \
  --manifest /authorized/captures/workflow.yaml
```

If observations were imported manually and ingestion must be skipped, say so explicitly:

```bash
hunt workflow --workspace workspaces/<slug> --no-ingest
```

Without a manifest or `--no-ingest`, the command fails instead of silently choosing a mode. Reruns
are idempotent. If an actor or channel assignment is corrected for the same source capture, the
existing observation IDs are retained and only those labels are refreshed.

The workflow stops after hypotheses and research tasks. It does not approve or execute a plan,
collect evidence, confirm a finding, or generate a report.

## Manual Passive Imports

```bash
hunt ingest traffic.har -w workspaces/example-fintech --actor ACCOUNT_A --channel WEB
hunt ingest-burp burp.xml -w workspaces/example-fintech --actor ACCOUNT_A --channel WEB
hunt ingest-caido caido.json -w workspaces/example-fintech --actor ACCOUNT_A --channel MOBILE
hunt ingest-openapi openapi.yaml -w workspaces/example-fintech
hunt ingest-graphql schema.graphql -w workspaces/example-fintech \
  --endpoint https://api.example.test/graphql
hunt scan-mobile authorized-app.apk -w workspaces/example-fintech
```

HAR, Burp, Caido, and OpenAPI records feed the endpoint inventory. Active hypotheses require
runtime traffic evidence from HAR, Burp, or Caido; OpenAPI-only routes remain research leads.
GraphQL and mobile results stay in separate inventories.

## Review And Research

```bash
hunt classify -w workspaces/example-fintech
hunt noise -w workspaces/example-fintech
hunt explain EP-001 -w workspaces/example-fintech
hunt hypotheses -w workspaces/example-fintech
hunt hypotheses --research-tasks -w workspaces/example-fintech
hunt show HYP-002 -w workspaces/example-fintech
hunt plan HYP-002 -w workspaces/example-fintech
```

Hypothesis priority is a queue, not a vulnerability severity rating:

```text
total = impact + likelihood + confidence + testability
P1 = impact >= 4 and total >= 14
P2 = total >= 10
P3 = everything else
```

Plans are static procedures. A researcher must review the plan and, only after independently
confirming authorization, manually set `approval_status: APPROVED` in
`tests/plans/plans.yaml`. Approval records review; it still does not execute anything.

## Evidence, Validation, And Reports

```bash
hunt evidence HYP-002 -w workspaces/example-fintech
hunt evidence HYP-002 -w workspaces/example-fintech \
  --add request.txt --kind request
hunt evidence HYP-002 -w workspaces/example-fintech \
  --add response.json --kind response
hunt validate HYP-002 -w workspaces/example-fintech
hunt report HYP-002 -w workspaces/example-fintech
```

Text and JSON evidence is automatically redacted before storage. Screenshots, PDFs, archives, and
other binary evidence require `--already-redacted` after manual privacy review. The validator
checks scope coverage, plan approval, artifact presence and checksums, required controls,
researcher assessments, and report completeness. It cannot independently prove that supplied
evidence or narrative claims are truthful.

Possible dispositions are:

```text
CONFIRMED
REFUTED
NEEDS_MORE_EVIDENCE
OUT_OF_SCOPE
EXPECTED_BEHAVIOR
```

Reports require a current `CONFIRMED`, report-ready validation and are written as immutable
`reports/HYP-xxx-report-vN.md` revisions.

## Repository Layout

- `finsec/config/`: target models, workspace discovery, and wildcard scope matching.
- `finsec/ingest/`: bounded passive importers and shared redaction.
- `finsec/normalization/`: deterministic classification, path grouping, and endpoint inventory.
- `finsec/recon/`: GraphQL schema and bounded static mobile discovery.
- `finsec/modeling/`: actors, resources, operation maps, invariants, and edit-preserving merges.
- `finsec/hypotheses/`: evidence gates, mutation-based candidates, and transparent scoring.
- `finsec/testing/`: safety policy checks and non-executing plan generation.
- `finsec/evidence/`: evidence scaffolds, redaction, indexing, and checksums.
- `finsec/validation/`: skeptical completeness, integrity, scope, and control checks.
- `finsec/reporting/`: packaged Jinja template and immutable report generation.
- `schemas/`: target, workflow, observation, endpoint, recon, and hypothesis JSON contracts.
- `scripts/`: development checks, safe demo automation, and isolated synthetic validation.
- `workspaces/`: researcher-editable target data; not application source.

## Development And Automation

Run the standard checks:

```bash
./scripts/check.sh
```

Include the isolated SyntheticPay validation:

```bash
./scripts/check.sh --synthetic
```

GitHub Actions runs the standard suite on pushes and pull requests. A separate scheduled/manual
workflow runs the full synthetic validation and uploads its report. Both workflows use read-only
repository permissions.

## Current Limitations

- Redaction targets common secrets and credential shapes; it is not a complete PII classifier.
- OpenAPI ingestion does not resolve `$ref`, callbacks, links, or external documents.
- GraphQL ingestion inventories root fields but does not validate resolver authorization.
- Mobile scanning extracts bounded strings; it is not decompilation or a security verdict.
- Path, resource, action, and state inference intentionally prefer false negatives.
- Endpoint families may aggregate the same method/path across hosts; scope checks cover every host
  and mixed classifications resolve conservatively.
- Evidence collection and truth assessment remain researcher responsibilities.
- There is no live proxy integration, browser automation, concurrency engine, active request
  execution, autonomous exploitation, or runtime LLM dependency.

For detailed operational steps, see [how-to-use.md](how-to-use.md). For the isolated end-to-end
test harness, see [synthetic-validation-how-to.md](synthetic-validation-how-to.md).
