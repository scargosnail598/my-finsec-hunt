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

- A display name, path-safe slug, and scoped target base URL.
- Exact or leading-wildcard in-scope hosts.
- Actor labels, roles, and whether each actor is authenticated, privileged, or anonymous.
- An optional HAR, raw request, or securely entered credential for each authenticated actor.
- Optional analysis and capture-directory settings.

Secret entry uses a hidden prompt. Setup metadata stores only credential references and redacted
lifecycle information; credentials are never written to `target.yaml`.

Non-interactive example:

```bash
hunt setup \
  --name "Example Fintech" \
  --slug example-fintech \
  --host example.test \
  --host '*.example.test' \
  --account ACCOUNT_A \
  --account ACCOUNT_B \
  --anonymous-actor ANONYMOUS \
  --privileged-actor ADMIN \
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

Interactive setup offers `Configure actor authentication now?` after creating the workspace. The
prompt defaults to no so an interrupted setup remains safe and resumable. Resume only incomplete
authentication sections with:

```bash
hunt setup -w workspaces/<slug>
```

Choose `Resume actor authentication setup`; existing scope, actor definitions, credential
references, and refresh configuration are preserved.

The lower-level `hunt init NAME` command remains available for scripts and migrations, but it
creates an intentionally incomplete target that must be edited before useful analysis.

## 3. Configure Actor Authentication

Capture replay authentication while importing actor traffic:

```bash
hunt ingest account-a.har -w workspaces/<slug> \
  --actor ACCOUNT_A --channel WEB --capture-auth
```

HAR imports accept files up to 256 MiB by default. For an unusually large local capture, set a
bounded byte limit up to 512 MiB for that command, or split the HAR to reduce memory use:

```bash
FINSEC_MAX_HAR_BYTES=419430400 hunt ingest large-account-a.har \
  -w workspaces/<slug> --actor ACCOUNT_A --capture-auth
```

If the HAR contains multiple distinct sessions, the CLI displays only redacted candidates and
requires a selection. Other supported paths are:

```bash
hunt actor auth import ACCOUNT_A --request account-a-request.txt -w workspaces/<slug>
hunt actor auth set ACCOUNT_A -w workspaces/<slug>
hunt actor auth status ACCOUNT_A -w workspaces/<slug>
hunt actor auth check ACCOUNT_A -w workspaces/<slug>
hunt actors -w workspaces/<slug>
```

`auth check` is local by default. Add `--network` only when you explicitly want to send one
previously observed, in-scope, read-only baseline request; active execution must already be enabled.

Credentials are stored in a `0600` actor-bound secret file under
`workspaces/.finsec-secrets/`, outside the selected workspace. The directory is Git-ignored and is
not included in workspace evidence, reports, or exports. `target.yaml` stores only references,
expiration metadata, observed baseline metadata, and a non-secret authentication-context
fingerprint.

Anonymous actors have `auth_type: none` and cannot receive a credential. JWT expiration is read
locally without signature verification; unverified `sub`, role, and tenant claims are continuity
hints only and require baseline confirmation where possible. Opaque tokens and session cookies with
no expiration metadata remain unknown until a safe baseline validation succeeds.

Configure automatic refresh only from an observed authorized flow:

```bash
hunt actor auth configure-refresh ACCOUNT_A \
  --har account-a-refresh.har -w workspaces/<slug>
hunt actor auth refresh ACCOUNT_A -w workspaces/<slug>
```

Replacement without a refresh flow uses a new capture:

```bash
hunt actor auth refresh ACCOUNT_A --har account-a-new.har -w workspaces/<slug>
hunt actor auth refresh ACCOUNT_A --request account-a-new.txt -w workspaces/<slug>
```

The tool never invents refresh endpoints or submits passwords, MFA codes, CAPTCHA responses, or
unknown login forms. A changed subject, role, tenant, or authentication method invalidates plan
approval; a verified same-context token renewal preserves approval because secret values are not
part of plan or policy hashes.

Legacy workspaces can add explicit compatibility metadata without copying environment values:

```bash
hunt workspace migrate-auth -w workspaces/<slug>
```

Actor-specific environment variables remain a temporary debugging fallback for legacy plans only.
New plans use actor credential-profile references.

## 4. Record Authoritative Rules

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

## 5. Prepare Passive Captures

Export authorized HAR files and keep the originals outside the repository. When using
`--capture-auth`, the source may contain the selected actor session; FinSec Hunt stores the secret
components outside the workspace and writes only a redacted HAR derivative. Place input files in:

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

## 6. Run The Offline Workflow

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

## 7. Import Other Passive Artifacts

HAR:

```bash
hunt ingest traffic.har -w workspaces/<slug> --actor ACCOUNT_A --channel WEB
```

Add `--capture-auth` to securely bind the selected replay profile to `ACCOUNT_A`.

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

## 8. Review Classification And Models

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

## 9. Review Hypotheses And Research Tasks

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

## 10. Generate And Approve A Plan

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

## 11. Approve, Dry Run, And Execute A Bounded Plan

All new workspaces contain these default-deny settings:

```yaml
testing:
  active_execution_enabled: false
  human_approval_required: true
  maximum_parallel_requests: 1
  maximum_requests_per_plan: 3
  read_only_only: true
```

For a deliberately vulnerable local lab, set `production: false`, `local_lab: true`, and
`active_execution_enabled: true`. Do not enable local-lab policy for a production target.

Record approval only after reviewing the current plan:

```bash
hunt approve HYP-002 -w workspaces/<slug> --approved-by researcher
```

Dry-run validates the checksum-bound approval, actor credential references, local secret
resolution, expiration margin, refresh availability, exact/wildcard scope, DNS destination,
method, mutation dimension, request budget, timeout, redirect policy, and expected evidence paths.
It sends no HTTP:

```bash
hunt execute HYP-002 -w workspaces/<slug> --dry-run
```

Type the exact phrase requested by the command. Approval stores the current plan checksum and
target-policy checksum; changing scope, accounts, safety settings, or request templates invalidates
it. A manually edited `approval_status: APPROVED` without the generated `approval:` record is
refused.

If you see `Execution refused: the plan does not have a complete approval record`, do not populate
the fields by hand. The plan store is `workspaces/<slug>/tests/plans/plans.yaml`, not a standalone
`plan.yml`. Review the generated plan and then run the `hunt approve` command above. It records
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

Credential-bearing plans reference actor profiles such as `actor-account-b-default`. Dry-run
resolves every referenced secret locally, checks actor binding and expiration, and sends zero
requests. Real execution establishes the authenticated actor baseline first and stops before the
mutation on `401`, session-expired signals, a login redirect, or a login page returned with HTTP
200. A `403` remains distinct as an authorization denial. Execution evidence is written beneath
`evidence/HYP-002/executions/execution-vN/`, and immutable transport audit records are written
beneath `tests/executions/HYP-002/`.

Execution outcomes such as `CROSS_OBJECT_RESPONSE_OBSERVED`, `NO_CROSS_OBJECT_ACCESS`, or
`BASELINE_MISMATCH` are observations, not vulnerability verdicts. The hypothesis status is not
automatically confirmed.

## 12. Add Redacted Evidence

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

## 13. Validate Skeptically

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

## 14. Generate A Versioned Report

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

## 15. Delete A Workspace

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

## 16. Troubleshooting

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
