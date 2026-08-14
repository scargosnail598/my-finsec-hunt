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
- Optional import of unassigned HAR files already present in the capture directory.
- Optional standalone authentication from a HAR, raw request, or securely entered credential.
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

When unassigned HAR files already exist under `captures/<slug>/incoming/`, interactive setup offers
to launch the same capture-import wizard used by `hunt ingest-wizard`. Every file still requires an
explicit actor and channel, authentication updates remain optional, and offline analysis requires
a separate confirmation. If the directory is empty, setup lets the user add reviewed HAR files and
rescan without leaving the wizard, or explicitly continue without ingestion. After completing or
skipping that step, setup reloads actor authentication status. It skips the authentication prompt
when every authenticated actor is already `READY`; otherwise it offers configuration only for the
remaining actors. Non-interactive `hunt setup --yes` skips both interactive steps and never imports
captures because it cannot safely guess their provenance.

Resume only incomplete authentication sections with:

```bash
hunt setup -w workspaces/<slug>
```

Choose `Resume onboarding (ingestion, then actor authentication)`; setup checks for unassigned
captures first and then offers authentication while preserving existing scope, actor definitions,
credential references, and refresh configuration.

The lower-level `hunt init NAME` command remains available for scripts and migrations, but it
creates an intentionally incomplete target that must be edited before useful analysis.

### Select A Default Workspace

Select a workspace once to omit `-w workspaces/<slug>` from normal workspace-aware commands:

```bash
hunt workspace use workspaces/<slug>
hunt workspace current
hunt status
hunt workflow --no-ingest
```

FinSec Hunt resolves workspaces in this order:

1. An explicit `--workspace` or `-w` option.
2. A workspace containing the current directory or one of its ancestors.
3. The configured default workspace.
4. The only workspace under `./workspaces`, when exactly one exists.

This means an explicit option always overrides the default, and changing into another workspace
temporarily selects that workspace without changing the saved default. The selection is stored as
an absolute path in `$XDG_CONFIG_HOME/finsec-hunt/default-workspace`, normally
`~/.config/finsec-hunt/default-workspace`. Set `FINSEC_HUNT_CONFIG_DIR` to relocate this small
configuration file for automation.

To remove the saved selection:

```bash
hunt workspace clear
```

`hunt web` opens the configured default when present and otherwise serves the workspace root.
`hunt setup`, `hunt init`, and `hunt workspace delete` keep their explicit behavior; permanent
deletion never infers the configured default.

## 3. Configure Actor Authentication

Capture replay authentication while importing actor traffic:

```bash
hunt ingest account-a.har -w workspaces/<slug> \
  --actor ACCOUNT_A --channel WEB --capture-auth
hunt ingest-burp account-a.xml -w workspaces/<slug> \
  --actor ACCOUNT_A --channel WEB --capture-auth
```

HAR imports accept files up to 256 MiB by default. For an unusually large local capture, set a
bounded byte limit up to 512 MiB for that command, or split the HAR to reduce memory use:

```bash
FINSEC_MAX_HAR_BYTES=419430400 hunt ingest large-account-a.har \
  -w workspaces/<slug> --actor ACCOUNT_A --capture-auth
```

If the HAR or Burp XML contains multiple distinct sessions, the CLI displays only redacted candidates and
recommends the freshest in-scope request that matches the actor's existing identity and replay
components. The prompt defaults to that request but still allows an explicit reviewed selection.
Other supported paths are:

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
hunt ingest account-a-new.har -w workspaces/<slug> \
  --actor ACCOUNT_A --channel WEB --update-auth
hunt actor auth refresh ACCOUNT_A --har account-a-new.har -w workspaces/<slug>
hunt actor auth refresh ACCOUNT_A --burp account-a-new.xml -w workspaces/<slug>
hunt actor auth refresh ACCOUNT_A --request account-a-new.txt -w workspaces/<slug>
```

`--update-auth`, `actor auth refresh --har`, and `actor auth refresh --burp` automatically select
the recommended fresh request.
The recommendation prefers an unexpired, newer credential with matching actor identity hints,
matching replay components, an in-scope host, and a successful read-only baseline. Token values are
never displayed. If no candidate passes these checks, automatic replacement stops and requires an
explicit reviewed `--auth-candidate N` selection.

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
  ownership_inference:
    trusted_parent_parameters:
      - accountId
      - tenantId
      - organizationId
    public_shared_parameters:
      - regionId
      - zoneId
      - productId
```

Custom excluded path patterns are enforced as `SUPPRESSED_INSUFFICIENT_EVIDENCE`. Exact path
classification overrides take precedence and must use a documented classification value.
Hypothesis gates accept scores from 0 to 10. Parent-scope ownership inference is fail-closed: only
explicitly trusted parameters may use authenticated, successful, non-empty controlled baselines.
The public/shared list takes precedence, and response-body ownership evidence remains stronger.

## 5. Prepare Session Captures

A Session Capture is one researcher-observed application journey with lightweight context: actor,
capture mode, and high-level intent. HAR and Burp parsing remains generic; the context is associated
with redacted observations afterward and used as a soft prior during deterministic reconstruction.

Export authorized HAR or Burp XML files and keep originals outside the repository. When using
`--capture-auth`, the source may contain the selected actor session; FinSec Hunt stores secret
components outside the workspace and writes only a redacted derivative. Place input files in:

```text
captures/<slug>/incoming/
```

Recommended practice:

- Use one controlled actor and one primary business journey per capture.
- Record normal behavior first and keep researcher probes in separate files.
- Prefer Fetch/XHR traffic when possible.
- Stop after observing the authoritative result of the journey.
- Keep original captures outside the repository.
- Review every file for credentials and personal data.

A good DNS capture is: open a domain, list records, create one record, read the result, stop. A
broad capture that mixes login, CDN, billing, DNS, IAM, profile changes, and server deletion is
still accepted, but it will be marked `BROAD` or `MULTI_INTENT` and provide weaker reconstruction.

For a normal first run:

1. Copy each sanitized `.har` or Burp `.xml` file into `captures/<slug>/incoming/`.
2. Open `captures/<slug>/workflow.yaml`.
3. Add one entry per capture using a configured account label, `ANONYMOUS`, or `UNKNOWN`.
4. Set its channel, capture mode, and high-level intent.
5. Save the file and continue with `hunt workflow` in the next section.

Alternatively, let the interactive importer discover files that are not yet assigned:

```bash
hunt ingest-wizard --workspace workspaces/<slug>
```

The wizard scans `captures/<slug>/incoming/`, proposes actor, mode, and explainable intent, and asks
only for missing confirmation. It can recommend a redacted authentication request, optionally
update the actor credential, import observations, and merge assignments into `workflow.yaml`. Add
more files later and run the same command again. Use
`--include-assigned` only when deliberately relabeling or renewing from an existing manifest entry.

Assign every imported HAR in `captures/<slug>/workflow.yaml`:

```yaml
version: 1
captures:
  - file: 01-account-a-profile.har
    actor: ACCOUNT_A
    channel: WEB
    capture_mode: NORMAL_BEHAVIOR
    intent:
      action: READ
      resource_type: profile
  - file: 02-account-b-create-dns.xml
    actor: ACCOUNT_B
    channel: WEB
    capture_mode: NORMAL_BEHAVIOR
    intent:
      action: CREATE
      resource_type: dns_record
  - file: 03-account-b-probe-account-a-dns.har
    actor: ACCOUNT_B
    channel: WEB
    capture_mode: RESEARCHER_PROBE
    intent:
      action: READ
      resource_type: dns_record
```

Valid manifest channels are `WEB`, `MOBILE`, `API`, `PARTNER_API`, `PUBLIC_API`, and `UNKNOWN`.
`API` is normalized to `PUBLIC_API`. Disabled entries may use `enabled: false`.

The manifest accepts filenames only, never directories, so each source resolves beneath the
manifest's `incoming/` directory. Actors must be configured account labels, `ANONYMOUS`, or
`UNKNOWN`.

Inspect the persisted registry and inference evidence before modeling:

```bash
hunt captures -w workspaces/<slug>
hunt captures --explain CAP-12AB34CD56EF -w workspaces/<slug>
```

`NORMAL_BEHAVIOR` primary/supporting observations may contribute to workflows, lifecycle, and
ownership. `RESEARCHER_PROBE` and `MIXED` observations remain available for replay/comparison
evidence but are excluded from normal ownership and workflow baselines. `AUTHENTICATION` is kept
out of ordinary workflow reconstruction. Explicit new `UNKNOWN` captures cannot establish new
ownership claims; legacy unlinked observations retain historical behavior. Capture intent never
creates causality by itself, and cross-capture hard links still require typed identity evidence.

Direct imports accept the same minimal context:

```bash
hunt ingest account-a-create-dns.har -w workspaces/<slug> \
  --actor ACCOUNT_A --channel WEB --capture-mode NORMAL_BEHAVIOR \
  --intent-action CREATE --intent-resource dns_record
```

See [session-captures.md](session-captures.md) for the complete model and mode semantics.

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

### Create The Preliminary Post-Ingest Report

The normal post-ingest workflow can produce one consolidated Markdown report without manually
running each inspection command:

```bash
hunt ingest-wizard \
  -w workspaces/<slug> \
  --capture-root captures/<slug>

hunt workspace report \
  -w workspaces/<slug>
```

`hunt workspace report` validates the workspace, runs missing or stale deterministic offline
analysis in dependency order, and writes a timestamped report under `reports/workspace/`. It does
not ingest captures, send target requests, create or approve plans, execute hypotheses, promote
evidence, change hypothesis status, or confirm vulnerabilities.

Useful modes are:

```bash
# Read existing artifacts without regenerating derived analysis
hunt workspace report -w workspaces/<slug> --report-only

# Rebuild every applicable safe offline derived stage
hunt workspace report -w workspaces/<slug> --force

# Write to a stable path and include sanitized stage diagnostics
hunt workspace report -w workspaces/<slug> \
  --output workspaces/<slug>/reports/workspace/initial-analysis.md \
  --include-command-output
```

The report is preliminary even when a hypothesis is `TEST_READY`; test readiness, human approval,
environment policy, active execution permission, and confirmed evidence remain separate facts.
Use `--strict` when automation should fail for unavailable required stages, and
`--no-include-suppressed` only when the complete suppressed appendix is not wanted.

This command is intentionally distinct from `hunt report HYP-002`. The hypothesis command still
requires current `CONFIRMED` evidence and produces an immutable version under `reports/` for one
finding. The workspace command requires no confirmation and produces a whole-workspace analysis
under `reports/workspace/`.

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

Add `--capture-auth` to store a reviewed authentication candidate, or `--update-auth` to replace
the actor's current credential with the recommended fresh candidate. Standard schema-only internal
DTDs emitted by Burp are stripped before XML parsing; entity declarations and external DTDs are
still rejected.

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

`BLOCKED` means either a policy prerequisite is missing or no safe automated execution template can
be built. Examples include incomplete host scope, insufficient controlled accounts, ambiguous
ownership baselines, a public/shared scope identifier, lifecycle evidence, or production
financial-testing permission. The hypothesis can remain a valid research candidate while automated
execution is unavailable. Resolve the evidence or policy prerequisite and regenerate; do not edit
`status`.

`READY_FOR_REVIEW` is emitted only when `execution.supported: true` and static policy checks pass.
Independently verify current program authorization and review every structured request, request
budget, stop condition, and cleanup step. Editing only the lifecycle field is not sufficient for
active execution:

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

The command validates deterministic blockers before showing the typed confirmation prompt. A
blocked or unsupported plan exits immediately with the ownership, template, scope, method, or
policy reason and does not ask for `APPROVE HYP-xxx`.

Export the exact approved requests for manual use in Burp Repeater when desired:

```bash
hunt export-burp HYP-002 -w workspaces/<slug>
```

The command sends no request and never resolves or writes credential values. It creates immutable,
revisioned raw HTTP files under `tests/burp/HYP-002/export-vN/` plus a manifest containing the plan
checksum, target-policy checksum, mutation, request budget, and stop conditions. Authorization,
Cookie, API-key, and other runtime headers appear only as actor-specific placeholders. Replace a
placeholder inside Burp with the current credential for that controlled actor. Sending from Burp
is manual active execution outside FinSec Hunt's bounded runner.

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

Execution outcomes such as `CROSS_OBJECT_RESPONSE_OBSERVED`,
`CROSS_SCOPE_RESPONSE_OBSERVED`, `NO_CROSS_OBJECT_ACCESS`, or `BASELINE_MISMATCH` are
observations, not vulnerability verdicts. A cross-scope outcome records a non-empty response under
another controlled parent scope without claiming response-body ownership. The hypothesis status is
not automatically confirmed.

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

Do not use this command for preliminary post-ingest review. The separate whole-workspace command is
`hunt workspace report -w workspaces/<slug>`; it never weakens this confirmed-evidence gate or
writes into the immutable hypothesis-report namespace.

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
reports. It is not recoverable through FinSec Hunt. By default, the workspace-specific credential
file and separate `captures/<slug>/` directory are preserved.

To remove all project data managed through the standard layout, including credentials and
captures, use:

```bash
hunt workspace delete \
  --workspace workspaces/<slug> \
  --purge
```

Type `PURGE <slug>` when prompted. For non-interactive deletion, pass
`--confirm 'PURGE <slug>'`. If the capture directory is not the standard `captures/<slug>` path,
identify it explicitly:

```bash
hunt workspace delete \
  --workspace /path/to/workspaces/<slug> \
  --purge \
  --capture-directory /path/to/authorized-captures/<slug>
```

Purge validates the workspace, exact-slug capture directory, capture markers, symbolic-link
boundaries, and credential-store ownership before deleting anything. Sibling project data remains
untouched.

The command refuses to operate on symbolic links, broad protected paths, the current directory or
its parents, a directory containing `.git`, or a directory without the expected FinSec Hunt
workspace or capture markers.

## 16. Troubleshooting

`No workflow manifest was found`:

- Create/edit `captures/<slug>/workflow.yaml`, pass `--manifest PATH`, or use `--no-ingest` when
  observations were already imported intentionally.

`Multiple workspaces found`:

- Select one with `hunt workspace use workspaces/<slug>`, or pass
  `--workspace workspaces/<slug>` explicitly for a one-command override.

`Configured default workspace is unavailable`:

- The selected directory was moved or deleted. Run `hunt workspace use PATH` with its new path, or
  run `hunt workspace clear` to return to automatic discovery.

`Cannot infer the capture directory` during purge:

- Pass the exact project capture path with `--capture-directory`. Its final directory name must
  match the workspace slug and it must contain `incoming/` and `workflow.yaml`.

`The plan does not have a complete approval record`:

- Run `hunt plan HYP-xxx -w workspaces/<slug>`, review the bounded requests, then run
  `hunt approve HYP-xxx -w workspaces/<slug>`. After approval, verify with `hunt execute HYP-xxx
  -w workspaces/<slug> --dry-run`. Editing `approval_status` alone is never enough.

`Preserved researcher-edited records`:

- Review the reported keys. Preserve notes, remove only the record you intentionally want
  regenerated, and rerun the relevant stage.

`No active hypotheses`:

- Review `hunt hypotheses --research-tasks`; missing runtime baselines, ownership, lifecycle, or
  channel evidence is intentionally not promoted to a vulnerability hypothesis.

`Report template is missing` should not occur in a normal install; the template is packaged with
the Python module and verified by tests and CI.

For the design reasoning behind these decisions, see
[workflow-rationale.md](workflow-rationale.md).
