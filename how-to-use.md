# How To Use FinSec Hunt

This guide covers the intended workflow from authorized passive evidence to a report. FinSec Hunt
is passive by default; only the explicit `hunt execute` command can send a bounded request after
the target policy and exact generated plan have both been approved.

## 1. Install And Verify

```bash
./install.sh --dev
source .venv/bin/activate
hunt --help
```

For an isolated demonstration before using target data:

```bash
python scripts/run_demo_workflow.py
```

The script creates a unique `/tmp/finsec-hunt-demo-*` root, leaves it available for inspection,
and refuses to overwrite an existing target workspace.

## 2. Create The Workspace

Prefer the validated setup wizard:

```bash
hunt setup
```

The wizard asks for:

- A display name and path-safe slug.
- Exact or leading-wildcard in-scope hosts.
- Non-secret labels for researcher-owned accounts.
- Optional analysis and capture-directory settings.

It does not ask for usernames, email addresses, phone numbers, passwords, cookies, tokens, OTPs,
or API keys.

Non-interactive example:

```bash
hunt setup \
  --name "Example Fintech" \
  --slug example-fintech \
  --host example.test \
  --host '*.example.test' \
  --account ACCOUNT_A \
  --account ACCOUNT_B \
  --yes
```

`*.example.test` covers subdomains such as `api.example.test`; it does not cover the apex
`example.test`. Record both if both are authorized.

### Why `workflow.yaml` May Be Empty

Setup creates `captures/<slug>/workflow.yaml`, but its normal initial content is:

```yaml
version: 1
captures: []
```

That does not mean setup failed. At setup time, HAR files often do not exist yet, and FinSec Hunt
cannot safely infer their actor or channel from a filename. Actor labels affect authorization
analysis, while channel labels affect web/mobile/API comparison.

Interactive setup offers `Search the incoming HAR directory now?` after creating the workspace. If
HAR files are already present and you answer yes, the wizard asks for an actor and channel and then
populates the manifest. The prompt defaults to no. With `hunt setup --yes`, discovery is skipped and
the manifest remains empty; add assignments after copying the HAR files.

The lower-level `hunt init NAME` command remains available for scripts and migrations, but it
creates an intentionally incomplete target that must be edited before useful analysis.

## 3. Record Authoritative Rules

Review `workspaces/<slug>/target.yaml` and the files under `scope/`:

```text
scope/program.md        official program source and review date
scope/scope.md          included and excluded assets
scope/restrictions.md   rate, transaction, account, and technique restrictions
```

The `target.yaml` booleans are default-deny policy inputs. The setup wizard keeps destructive
testing, real-user testing, denial of service, brute force, spam, and social engineering disabled.
Do not loosen them without an explicit program-policy review.

Analysis settings include:

```yaml
analysis:
  include_hosts:
    - example.test
    - '*.example.test'
  exclude_hosts:
    - telemetry.vendor.test
  suppress:
    static_assets: true
    telemetry: true
    analytics: true
    third_party: true
  excluded_path_patterns:
    - /internal-noise/
  hypothesis_gates:
    bola_minimum_score: 6
    state_transition_minimum_score: 7
    financial_minimum_score: 5
```

Custom excluded path patterns are enforced as `SUPPRESSED_INSUFFICIENT_EVIDENCE`. Exact path
classification overrides take precedence and must use a documented classification value.
Hypothesis gates accept scores from 0 to 10.

The `focus` list records researcher emphasis for review and reporting. It does not override the
evidence and safety gates.

## 4. Prepare Passive Captures

Export sanitized HAR files obtained within program authorization. Place them in:

```text
captures/<slug>/incoming/
```

Recommended practice:

- Use one account and one coherent workflow per HAR.
- Prefer Fetch/XHR traffic when possible.
- Remove unrelated browsing and third-party noise before import.
- Keep original captures outside the repository.
- Review every file for credentials and personal data.

For a normal first run:

1. Copy each sanitized `.har` file into `captures/<slug>/incoming/`.
2. Open `captures/<slug>/workflow.yaml`.
3. Add one entry per HAR using a configured account label, `ANONYMOUS`, or `UNKNOWN`.
4. Set the channel that actually produced the traffic.
5. Save the file and continue with `hunt workflow` in the next section.

Assign every imported HAR in `captures/<slug>/workflow.yaml`:

```yaml
version: 1
captures:
  - file: 01-account-a-profile.har
    actor: ACCOUNT_A
    channel: WEB
  - file: 02-account-b-profile.har
    actor: ACCOUNT_B
    channel: WEB
  - file: 03-account-a-mobile.har
    actor: ACCOUNT_A
    channel: MOBILE
```

Valid manifest channels are `WEB`, `MOBILE`, `API`, `PARTNER_API`, `PUBLIC_API`, and `UNKNOWN`.
`API` is normalized to `PUBLIC_API`. Disabled entries may use `enabled: false`.

The manifest accepts filenames only, never directories, so each source resolves beneath the
manifest's `incoming/` directory. Actors must be configured account labels, `ANONYMOUS`, or
`UNKNOWN`.

## 5. Run The Offline Workflow

With the default capture layout:

```bash
hunt workflow --workspace workspaces/<slug>
```

With a custom manifest:

```bash
hunt workflow \
  --workspace workspaces/<slug> \
  --manifest /path/to/captures/workflow.yaml
```

To analyze already imported observations without reading a manifest:

```bash
hunt workflow --workspace workspaces/<slug> --no-ingest
```

The choice is explicit. A missing manifest without `--no-ingest` is an error. `--no-ingest`
cannot be combined with `--manifest` or `--capture-root`.

The workflow performs, in order:

1. Passive HAR ingestion and redacted derivative creation.
2. Classification and conservative endpoint normalization.
3. Actor, resource, authorization-view, and operation-map generation.
4. Invariant extraction.
5. Evidence-gated security hypotheses and research tasks.
6. Final deterministic counts.

The command stops at the human-review boundary. It never plans all hypotheses automatically,
approves a plan, sends a request, collects evidence, validates a claim, or writes a report.

Rerunning the same manifest does not duplicate observations. If the same capture is reassigned to
a different actor or channel, the existing observation IDs remain stable and the labels are
refreshed. If one capture fails after earlier captures succeeded, the successful passive imports
remain in the workspace; fix the failed input and rerun.

## 6. Import Other Passive Artifacts

HAR:

```bash
hunt ingest traffic.har -w workspaces/<slug> --actor ACCOUNT_A --channel WEB
```

Burp XML history:

```bash
hunt ingest-burp burp-history.xml -w workspaces/<slug> \
  --actor ACCOUNT_A --channel WEB
```

Caido JSON:

```bash
hunt ingest-caido caido-export.json -w workspaces/<slug> \
  --actor ACCOUNT_A --channel MOBILE
```

OpenAPI or Swagger:

```bash
hunt ingest-openapi openapi.yaml -w workspaces/<slug>
hunt ingest-openapi openapi.yaml -w workspaces/<slug> \
  --base-url https://api.example.test
```

OpenAPI operations feed the endpoint inventory as documentation evidence. They can create model
and invariant leads, but they cannot create an active security hypothesis without matching runtime
traffic evidence from HAR, Burp, or Caido.

GraphQL schema:

```bash
hunt ingest-graphql schema.graphql -w workspaces/<slug> \
  --endpoint https://api.example.test/graphql
```

Static mobile artifact:

```bash
hunt scan-mobile authorized-app.apk -w workspaces/<slug>
hunt scan-mobile jadx-output -w workspaces/<slug>
```

GraphQL and mobile discoveries remain separate from runtime observations. Mobile scanning is
bounded string extraction and never executes or installs the application.

## 7. Review Classification And Models

```bash
hunt classify -w workspaces/<slug>
hunt noise -w workspaces/<slug>
hunt explain EP-001 -w workspaces/<slug>
hunt status -w workspaces/<slug>
```

Review these artifacts before relying on downstream output:

```text
observations/normalized/observations.yaml
api/endpoints.yaml
model/architecture.md
model/authorization.md
model/workflows.md
model/state-machines.md
model/invariants.yaml
```

Path normalization replaces UUIDs, ULIDs, strong opaque identifiers, and repeated numeric values
only when the evidence supports grouping. API version segments and four-digit years remain
literal. Endpoint families that contain mixed classifications resolve ties conservatively.

Generated YAML records contain checksums. Untouched records refresh with stable IDs; edited
generated records are preserved and reported as conflicts. Generated records no longer supported
by evidence are retained with a suppressed disposition rather than deleted.

## 8. Review Hypotheses And Research Tasks

```bash
hunt hypotheses -w workspaces/<slug>
hunt hypotheses --priority P1 -w workspaces/<slug>
hunt hypotheses --research-tasks -w workspaces/<slug>
hunt hypotheses --include-suppressed -w workspaces/<slug>
hunt hypotheses --explain HYP-002 -w workspaces/<slug>
hunt show HYP-002 -w workspaces/<slug>
```

Active hypotheses require specific evidence for one or more mutation dimensions:

```text
ACTOR  OBJECT  STATE  TIME  VALUE  CHANNEL  VERSION
```

Under-evidenced routes become research tasks instead of generic vulnerability claims. A high
priority means the question is important and testable; it does not mean a vulnerability exists.

## 9. Generate And Approve A Plan

```bash
hunt plan HYP-002 -w workspaces/<slug>
```

Every plan contains:

```yaml
human_approval_required: true
execution_default: DO_NOT_EXECUTE
approval_status: NOT_REQUESTED
status: BLOCKED  # or READY_FOR_REVIEW
```

`BLOCKED` means a safety prerequisite is missing, such as complete host scope, two controlled
accounts, lifecycle evidence, or production financial-testing permission. Resolve the prerequisite
and regenerate; do not simply edit `status`.

For a `READY_FOR_REVIEW` plan, independently verify current program authorization and review every
structured request, request budget, stop condition, and cleanup step. Editing only the lifecycle
field is not sufficient for active execution:

```yaml
approval_status: APPROVED
notes: "Approved by the researcher for the stated accounts and minimum request budget."
```

That legacy annotation remains valid for manual evidence workflows, but the bounded runner also
requires a checksum-bound approval record.

## 10. Dry Run, Approve, And Execute A Bounded Plan

All new workspaces contain these default-deny settings:

```yaml
testing:
  active_execution_enabled: false
  human_approval_required: true
  maximum_parallel_requests: 1
  maximum_requests_per_plan: 3
  read_only_only: true
```

Dry-run validates the structured requests, exact/wildcard scope, DNS destination, method, single
mutation dimension, request budget, timeout, redirect policy, and expected evidence paths. It does
not require credentials and sends no HTTP:

```bash
hunt execute HYP-002 -w workspaces/<slug> --dry-run
```

For a deliberately vulnerable local lab, set `production: false`, `local_lab: true`, and
`active_execution_enabled: true`. Do not enable local-lab policy for a production target.

Record approval only after reviewing the current plan:

```bash
hunt approve HYP-002 -w workspaces/<slug> --approved-by researcher
```

Type the exact phrase requested by the command. Approval stores the current plan checksum and
target-policy checksum; changing scope, accounts, safety settings, or request templates invalidates
it. A manually edited `approval_status: APPROVED` without the generated `approval:` record is
refused.

If you see `Execution refused: the plan does not have a complete approval record`, do not populate
the fields by hand. The plan store is `workspaces/<slug>/tests/plans/plans.yaml`, not a standalone
`plan.yml`. Review the dry-run and then run the `hunt approve` command above. It records
`approved_by`, `approved_at`, `plan_checksum`, and `target_policy_checksum` as one complete,
checksum-bound approval. Run approval again after an approved plan or target policy changes.

Execute interactively:

```bash
hunt execute HYP-002 -w workspaces/<slug>
```

The final prompt requires `EXECUTE HYP-002`, not `y`. The runner sends the baseline first and stops
before mutation if the baseline fails, redirects, exceeds the response limit, or does not match the
expected controlled object.

For local-lab CI only, place a random approval token in an environment variable when approving and
provide the variable name again during execution:

```bash
export FINSEC_EXECUTION_APPROVAL='local-secret-value'
hunt approve HYP-002 -w workspaces/<slug> \
  --approved-by researcher --approval-token FINSEC_EXECUTION_APPROVAL
hunt execute HYP-002 -w workspaces/<slug> \
  --non-interactive --approval-token FINSEC_EXECUTION_APPROVAL
```

Credential-bearing plans name actor-specific environment variables such as
`FINSEC_ACCOUNT_B_AUTH`; the secret values are never stored or printed. Execution evidence is
written beneath `evidence/HYP-002/executions/execution-vN/`, and immutable transport audit records
are written beneath `tests/executions/HYP-002/`.

Execution outcomes such as `CROSS_OBJECT_RESPONSE_OBSERVED`, `NO_CROSS_OBJECT_ACCESS`, or
`BASELINE_MISMATCH` are observations, not vulnerability verdicts. The hypothesis status is not
automatically confirmed.

## 11. Add Redacted Evidence

Create the evidence scaffold:

```bash
hunt evidence HYP-002 -w workspaces/<slug>
```

Add artifacts:

```bash
hunt evidence HYP-002 -w workspaces/<slug> --add request.txt --kind request
hunt evidence HYP-002 -w workspaces/<slug> --add response.json --kind response
hunt evidence HYP-002 -w workspaces/<slug> --add before.json --kind before
hunt evidence HYP-002 -w workspaces/<slug> --add after.json --kind after
```

Screenshots and binary files require manual review:

```bash
hunt evidence HYP-002 -w workspaces/<slug> \
  --add screenshot.png --kind screenshot --already-redacted
```

Review `evidence/HYP-002/metadata.yaml` and `conclusion.md`. Complete the skeptical assessment and
report narrative with factual, non-secret text. State-changing endpoints require before/after JSON;
version and channel comparisons require matched request/response pairs for both paths.

## 12. Validate Skeptically

```bash
hunt validate HYP-002 -w workspaces/<slug>
```

The validator checks:

- Source endpoint resolution and exact/wildcard scope coverage.
- A `READY_FOR_REVIEW`, explicitly `APPROVED` plan.
- Artifact existence, path containment, and SHA-256 integrity.
- Request/response counts and required state evidence.
- Negative controls, clean-session reproduction, authoritative verification, impact, redaction,
  intended-behavior review, and alternative explanations recorded by the researcher.

It returns `CONFIRMED`, `REFUTED`, `NEEDS_MORE_EVIDENCE`, `OUT_OF_SCOPE`, or
`EXPECTED_BEHAVIOR`. The validator checks structure, consistency, and explicit researcher claims;
it cannot independently authenticate the truth of an external system interaction.

## 13. Generate A Versioned Report

Complete every narrative field in `evidence/HYP-002/metadata.yaml`, then run:

```bash
hunt report HYP-002 -w workspaces/<slug>
```

The command revalidates current inputs. It refuses to report a non-confirmed or conflicted result.
Unchanged content reuses the existing report; changed confirmed content creates the next immutable
revision:

```text
reports/HYP-002-report-v1.md
reports/HYP-002-report-v2.md
```

## 13. Delete A Workspace

To permanently remove a workspace, run the command from outside that workspace and pass its exact
path:

```bash
hunt workspace delete --workspace workspaces/<slug>
```

Before deleting anything, FinSec Hunt validates `target.yaml` and the expected workspace structure,
shows the resolved path, and asks you to type the exact slug. A wrong value cancels the operation
without deleting anything.

For non-interactive use, confirmation must still match the exact slug:

```bash
hunt workspace delete \
  --workspace workspaces/<slug> \
  --confirm <slug>
```

Deletion removes everything inside `workspaces/<slug>/`, including observations, evidence, and
reports. It is not recoverable through FinSec Hunt. The separate `captures/<slug>/` directory and
its HAR files are deliberately preserved and must be reviewed or removed separately.

The command refuses to operate on symbolic links, broad protected paths, the current directory or
its parents, a directory containing `.git`, or a directory without the expected FinSec Hunt
workspace markers.

## 14. Troubleshooting

`No workflow manifest was found`:

- Create/edit `captures/<slug>/workflow.yaml`, pass `--manifest PATH`, or use `--no-ingest` when
  observations were already imported intentionally.

`Multiple workspaces found`:

- Pass `--workspace workspaces/<slug>` explicitly.

`The plan does not have a complete approval record`:

- Run `hunt execute HYP-xxx -w workspaces/<slug> --dry-run`, review the two bounded requests, then
  run `hunt approve HYP-xxx -w workspaces/<slug>`. Editing `approval_status` alone is never enough.

`Preserved researcher-edited records`:

- Review the reported keys. Preserve notes, remove only the record you intentionally want
  regenerated, and rerun the relevant stage.

`No active hypotheses`:

- Review `hunt hypotheses --research-tasks`; missing runtime baselines, ownership, lifecycle, or
  channel evidence is intentionally not promoted to a vulnerability hypothesis.

`Report template is missing` should not occur in a normal install; the template is packaged with
the Python module and verified by tests and CI.

For the design reasoning behind these decisions, see
[docs/workflow-rationale.md](docs/workflow-rationale.md).
