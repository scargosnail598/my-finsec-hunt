# FinSec Hunt

FinSec Hunt is a local-first research workspace for authorized fintech Web, API, and mobile
security analysis. It is not a scanner or autonomous exploitation engine. It turns researcher-
supplied passive artifacts into traceable observations, conservative models, reviewable
hypotheses, human-approved bounded test plans, indexed evidence, skeptical validation results,
and versioned reports.

```text
HAR / Burp XML / Caido JSON / OpenAPI
  -> redacted factual observations
  -> classified endpoint inventory
  -> actors, resources, operation maps, and invariants
  -> evidence-gated hypotheses or research tasks
  -> human-reviewed plan (DO_NOT_EXECUTE by default)
  -> optional checksum-approved bounded read-only execution
  -> manually or automatically collected redacted evidence
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

FinSec Hunt remains passive by default:

- `workflow`, ingestion, inventory, modeling, hypothesis, planning, evidence, validation, and
  reporting commands never contact a target.
- Only `hunt execute` can send HTTP, and only for an explicitly approved structured plan.
- Active execution is disabled in every new `target.yaml`.
- The bounded runner cannot invent payloads, enumerate identifiers, fuzz, brute force, or follow
  redirects automatically.
- Requires explicit capture-to-actor assignments for automated ingestion.
- Generates plans with `human_approval_required: true` and `DO_NOT_EXECUTE` as the default.
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

Run `./install.sh --help` for custom interpreter, virtual-environment, offline, and development
options.

## Local Web UI

FinSec Hunt includes a bundled, read-only research cockpit for browsing the selected workspace's
pipeline state, normalized endpoints, inferred model, hypotheses, plans, evidence metadata,
validations, reports, and scope documents:

```bash
hunt web --workspace workspaces/example-fintech
```

Then open `http://127.0.0.1:8765`. Omit `--workspace` to select among direct children of the
`workspaces/` directory, or pass `--workspace-root PATH`. The server binds only to a loopback
address because it has no login screen. It never returns credential profile references, raw
request values, evidence file contents, or secret material, and it exposes no approval or active
execution action.

## Local MCP Server

FinSec Hunt includes a safety-bounded stdio MCP server. It exposes sanitized research context and
can create one configured workspace, import allowlisted HAR files, and run the passive offline
pipeline:

```bash
FINSEC_HUNT_WORKSPACE=/absolute/path/to/workspace \
FINSEC_HUNT_IMPORT_ROOT=/absolute/path/to/sanitized-hars \
  /absolute/path/to/.venv/bin/hunt-mcp
```

The MCP server cannot execute requests, approve plans, overwrite an existing workspace, return raw
traffic, or accept filesystem paths from a model. See [docs/mcp-server.md](docs/mcp-server.md) for
the threat model, Inspector usage, Linux and Windows/WSL host configuration, and cloud-model
privacy notes.

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

The setup wizard validates the target URL, scope hosts, actor labels and roles, safe defaults,
capture paths, analysis policy, and actor authentication readiness. If unassigned HAR files are
already present in the capture directory, setup offers to assign and import them before offering
authentication for any actors that remain incomplete. If ingestion makes every authenticated actor
`READY`, the duplicate authentication prompt is skipped. Credential entry is optional and hidden;
workspace metadata stores only secret references and redacted lifecycle information.

When the capture directory is empty, interactive setup pauses at the ingestion stage and offers to
rescan after reviewed HAR files are added. The user may explicitly continue without ingestion; only
then does setup move to actor authentication.

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
  --anonymous-actor ANONYMOUS \
  --yes
```

Leading wildcards cover subdomains, not the apex host. For example,
`*.example.test` covers `api.example.test` but not `example.test`; record both when both are in
scope.

The wizard creates:

```text
workspaces/example-fintech/       structured research memory
captures/example-fintech/         researcher-controlled input area
  incoming/                       authorized HAR inputs kept out of Git
  workflow.yaml                   explicit file/actor/channel assignments
```

Original captures stay outside the workspace. Generated redacted derivatives live under the
workspace and sensitive paths are added to `.gitignore`.

## From Setup To Workflow: First-Time Guide

`hunt setup` prepares the project and can hand off to passive capture ingestion, but it never
guesses capture provenance or automatically analyzes HAR files. In a normal first run,
`captures/<slug>/workflow.yaml` starts with an empty list:

```yaml
version: 1
captures: []
```

This is intentional. The tool must not guess which account produced a capture or whether it came
from the web, mobile app, or an API client. Those labels affect authorization and channel-parity
analysis.

Use this sequence:

1. Run `hunt setup` to create the workspace and capture directories.
2. Export a sanitized HAR and place it in `captures/<slug>/incoming/`.
3. Run `hunt ingest-wizard -w workspaces/<slug>` to assign and import new HARs, or edit
   `captures/<slug>/workflow.yaml` directly.
4. Run `hunt workflow --workspace workspaces/<slug>`.
5. Review active hypotheses and research tasks; the workflow stops before active testing.

If sanitized HAR files are staged in `captures/<slug>/incoming/` before interactive setup finishes,
setup offers to launch the ingest wizard immediately. The wizard still requires an explicit actor
and channel for every selected file and can optionally update authentication from a reviewed
request. If no HAR is present, setup can wait while the user adds files and then rescan the capture
directory. After that ingestion step is completed or explicitly skipped, setup separately offers
authentication from a HAR, raw HTTP request, hidden secret prompt, or an explicit incomplete state
only for actors that are not already `READY`. Resume incomplete authentication with
`hunt setup -w workspaces/<slug>` without overwriting existing scope or credential references.
Non-interactive `hunt setup --yes` skips both interactive steps, never imports captures, and creates
authenticated actors in `MISSING` state until authentication is supplied explicitly.

For example, after placing two HAR files in `incoming/`, edit `workflow.yaml` to contain:

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

Capture actor-owned replay authentication during HAR or Burp import:

```bash
hunt ingest account-a.har -w workspaces/example-fintech \
  --actor ACCOUNT_A --channel WEB --capture-auth
hunt ingest account-a-new.har -w workspaces/example-fintech \
  --actor ACCOUNT_A --channel WEB --update-auth
hunt ingest-burp account-a.xml -w workspaces/example-fintech \
  --actor ACCOUNT_A --channel WEB --capture-auth
hunt ingest-wizard -w workspaces/example-fintech
hunt actors -w workspaces/example-fintech
hunt actor auth status ACCOUNT_A -w workspaces/example-fintech
hunt actor auth check ACCOUNT_A -w workspaces/example-fintech
```

Use `hunt actor auth import ACCOUNT_A --request request.txt` for a raw request, or
`hunt actor auth set ACCOUNT_A` for hidden interactive entry. Configure refresh only from an
observed HAR with `hunt actor auth configure-refresh ACCOUNT_A --har refresh.har`; replace an
expired credential with `hunt actor auth refresh ACCOUNT_A --har new.har` or
`hunt actor auth refresh ACCOUNT_A --burp new.xml` when no observed refresh flow exists. HAR- and
Burp-based replacement rank only redacted request metadata and automatically recommend the freshest
in-scope candidate matching the actor's identity hints and replay components. Standard Burp internal
DTDs are removed before parsing; entity declarations and external DTDs remain rejected.

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

Plans remain static until the researcher separately enables bounded execution and records a
checksum-bound approval. Editing `approval_status` alone is intentionally insufficient.

## Bounded Active Execution

FinSec Hunt supports only reviewed read-only object substitution, authentication-marker removal,
and matched version/channel comparisons. It does not support mutations, payments, withdrawals,
refunds, password changes, OTP consumption, enumeration, or arbitrary request scripts.

First generate and review the structured requests:

```bash
hunt plan HYP-002 -w workspaces/example-fintech
```

For an explicitly authorized local lab, configure the target policy before approval:

```yaml
testing:
  production: false
  local_lab: true
  active_execution_enabled: true
  human_approval_required: true
  maximum_parallel_requests: 1
  maximum_requests_per_plan: 2
  read_only_only: true
```

Then bind approval to the exact plan and target policy:

```bash
hunt approve HYP-002 -w workspaces/example-fintech --approved-by researcher
```

Unsupported plans remain `BLOCKED` even when the hypothesis is still worth manual research.
`hunt approve` checks template, ownership-baseline, method, scope, and policy blockers before it
asks for the typed approval phrase.

To work through the exact approved comparison manually in Burp Repeater, export secret-free raw
HTTP messages:

```bash
hunt export-burp HYP-002 -w workspaces/example-fintech
```

Exports are revisioned beneath `tests/burp/HYP-002/export-vN/`. Each request contains an
actor-specific placeholder instead of Authorization, Cookie, API-key, or other credential values.
The manifest binds the files to the approved plan and target-policy checksums and records the exact
mutation, request budget, and stop conditions. Sending a file from Burp is manual active execution
outside FinSec Hunt; insert only the current credential for the labeled controlled actor and follow
the approved plan.

Then run the no-network dry-run, which verifies both approval binding and actor authentication
preflight:

```bash
hunt execute HYP-002 -w workspaces/example-fintech --dry-run
```

If execution reports that the plan has no complete approval record, do not edit
`approval_status` manually. Plans are stored together in `tests/plans/plans.yaml`; review the
structured requests and run `hunt approve` so the CLI writes the required reviewer, timestamp,
plan checksum, and target-policy checksum. Reapprove after any approved plan or policy change.

The command requires the exact phrase `APPROVE HYP-002`. Execution separately requires
`EXECUTE HYP-002`:

```bash
hunt execute HYP-002 -w workspaces/example-fintech
```

Runtime Authorization, Cookie, API-key, CSRF, and custom authentication values come from the
actor-bound local secret store referenced by the plan. They are never written to YAML, evidence,
logs, reports, plan hashes, or approval records. Legacy environment-variable references remain
readable after `hunt workspace migrate-auth`, but new plans do not require manual credential
exports. Non-interactive execution is restricted to non-production local labs and still requires a
separate approval token whose hash was captured by `hunt approve --approval-token ENV_VARIABLE`.

Execution writes redacted revisioned evidence under `evidence/HYP-xxx/executions/` and an
append-only audit record under `tests/executions/HYP-xxx/`. An execution outcome never changes a
hypothesis to `CONFIRMED`; review the evidence and run `hunt validate` separately.

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

## Delete A Workspace Safely

Workspace deletion is permanent and must always name the exact workspace directory:

```bash
hunt workspace delete --workspace workspaces/example-fintech
```

The command displays the resolved name, slug, and path, then asks you to type the exact workspace
slug. It deletes observations, models, hypotheses, plans, evidence, validations, and reports stored
inside that workspace. By default it preserves the separate credential store and
`captures/example-fintech/` directory.

For an intentional non-interactive deletion, supply the exact slug:

```bash
hunt workspace delete \
  --workspace workspaces/example-fintech \
  --confirm example-fintech
```

The command refuses symbolic-link paths, filesystem/home-level paths, the current directory or one
of its parents, directories containing `.git`, and directories that do not validate as FinSec Hunt
workspaces. Run it from outside the selected workspace.

To completely remove the workspace, its workspace-specific credential file, and its capture
directory, use the explicit purge mode:

```bash
hunt workspace delete \
  --workspace workspaces/example-fintech \
  --purge
```

Purge requires the stronger confirmation `PURGE example-fintech`. For non-interactive use, pass
`--confirm 'PURGE example-fintech'`. The standard layout resolves
`captures/example-fintech/` automatically. For a custom layout, also pass
`--capture-directory /exact/path/to/example-fintech`. Purge validates every path before deleting
anything and preserves sibling workspaces, credential files, and capture directories.

## Repository Layout

- `finsec/config/`: target models, workspace discovery, and wildcard scope matching.
- `finsec/ingest/`: bounded passive importers and shared redaction.
- `finsec/normalization/`: deterministic classification, path grouping, and endpoint inventory.
- `finsec/recon/`: GraphQL schema and bounded static mobile discovery.
- `finsec/modeling/`: actors, resources, operation maps, invariants, and edit-preserving merges.
- `finsec/hypotheses/`: evidence gates, mutation-based candidates, and transparent scoring.
- `finsec/testing/`: safety policy checks, structured plans, and secret-free Burp exports.
- `finsec/execution/`: explicit approval, scope/DNS enforcement, bounded HTTP, and audit records.
- `finsec/evidence/`: evidence scaffolds, redaction, indexing, and checksums.
- `finsec/mcp/`: safety-bounded workspace service, structured MCP responses, and centralized
  sanitization.
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
- Bounded execution supports only sequential read-only comparisons; there is no live proxy
  integration, browser automation, concurrency engine, payload generation, autonomous
  exploitation, or runtime LLM dependency.

For detailed operational steps, see [docs/how-to-use.md](docs/how-to-use.md). For the isolated
end-to-end test harness, see
[docs/synthetic-validation-how-to.md](docs/synthetic-validation-how-to.md).
