# Local Web UI

The FinSec Hunt Web UI is a local onboarding, passive-ingestion, and research cockpit for one or
more workspaces. It keeps the same knowledge-state boundaries as the CLI and does not add an
active-testing surface.

## Start The Server

Serve one exact workspace:

```bash
hunt web --workspace workspaces/example-fintech
```

Serve every direct workspace beneath a root:

```bash
hunt web --workspace-root workspaces --capture-root captures
```

The default address is `http://127.0.0.1:8765`. The server refuses non-loopback bind addresses
because it has no authentication. Use local SSH port forwarding if the interface must be viewed
from another machine without exposing it on a network interface.

The standalone entry point accepts the same server options:

```bash
hunt-web --workspace workspaces/example-fintech --capture-root captures --port 9000
```

The theme control in the top bar supports light, dark, and system-following modes. Explicit light
or dark selections are stored only in the browser's local storage.

## Available Views

- **Setup** creates a validated default-deny workspace and external capture layout from explicit
  hosts and non-secret researcher-controlled actor labels. Its Danger Zone can permanently delete
  only the workspace or purge the workspace, credential store, and validated capture directory
  after previewing exact paths and requiring typed confirmation.
- **Ingest HARs** accepts reviewed local HAR files, never overwrites an existing capture, requires
  an explicit actor and channel for every enabled file, and can run or rerun the complete passive
  workflow. Reruns reuse the reviewed manifest, preserve stable records and researcher edits, and
  still stop before planning or target execution.
- **Authentication** runs a redacted local preflight for every actor, showing secret availability,
  expiration, refresh configuration, identity continuity, and blockers without sending requests.
  Credential-changing and one-request target-validation steps are presented as explicit CLI
  handoffs; the browser never receives or collects credential values.
- **Overview** shows deterministic artifact totals, passive provenance coverage, pipeline state,
  target policy, scope hosts, and a suggested CLI next step.
- **Hypotheses** separates active security hypotheses from research tasks and links each record to
  its current plan, evidence, and validation state.
- **Endpoints** explores normalized route families without returning concrete query values or raw
  observations.
- **Model** presents inferred actors and resources separately from expected invariants.
- **Evidence** shows artifact indexes, researcher assessment state, skeptical validation results,
  and immutable report revisions without returning evidence file contents.
- **Scope & Notes** renders only the allowlisted Markdown documents under `scope/` and `model/`.

## Security Boundary

The Web UI exposes narrowly scoped local writes for workspace setup, external capture-directory
initialization, non-overwriting HAR upload, provenance assignment, passive deterministic analysis,
and explicitly confirmed workspace retirement. JSON writes require a same-origin custom header, so
cross-origin form posts cannot reach them without a browser preflight that the server does not
authorize. HAR upload separately requires an authorization-and-sanitization attestation. Permanent
deletion additionally requires a destructive-action header, an exact slug or `PURGE <slug>` value,
and revalidation of every removal target immediately before deletion.

The UI cannot collect credentials, configure actor authentication, edit researcher finding
judgments, approve plans, export credentials, or execute target requests. Account responses include
only non-secret labels and authentication lifecycle status. Plan responses replace runtime secret
references with configured/not-configured indicators. Browser responses use a restrictive content
security policy and disable caching.

Uploaded captures are stored under the configured external `captures/<slug>/incoming/` directory,
never inside the workspace, and are not returned by the API. Credential stores, raw traffic bodies,
and evidence file bodies remain outside the Web UI response model.
