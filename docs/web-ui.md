# Local Web UI

The FinSec Hunt Web UI is a read-only research cockpit for one or more local workspaces. It keeps
the same knowledge-state boundaries as the CLI and does not add an active-testing surface.

## Start The Server

Serve one exact workspace:

```bash
hunt web --workspace workspaces/example-fintech
```

Serve every direct workspace beneath a root:

```bash
hunt web --workspace-root workspaces
```

The default address is `http://127.0.0.1:8765`. The server refuses non-loopback bind addresses
because it has no authentication. Use local SSH port forwarding if the interface must be viewed
from another machine without exposing it on a network interface.

The standalone entry point accepts the same server options:

```bash
hunt-web --workspace workspaces/example-fintech --port 9000
```

## Available Views

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

The Web UI intentionally has no write routes. It cannot ingest files, edit researcher judgments,
approve plans, export credentials, or execute requests. Account responses include only non-secret
labels and authentication lifecycle status. Plan responses replace runtime secret references with
configured/not-configured indicators. Browser responses use a restrictive content security policy
and disable caching.

Original captures, credential stores, raw traffic, and evidence file bodies remain outside the
Web UI response model.
