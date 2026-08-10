# Session Captures

Session Capture preserves the small amount of human context that HTTP traffic cannot reliably
reconstruct: who performed a journey, whether it was normal behavior or a security probe, and the
main business intent. HTTP evidence remains authoritative.

```text
HAR / Burp XML / Caido JSON
        -> generic parser and redaction
        -> canonical OBS-* facts
human context + deterministic HTTP inference
        -> stable CAP-* registry and observation relevance
        -> workflow, lifecycle, ownership, and hypothesis analysis
```

The capture layer is source-independent and runs after generic parsing. It does not add browser
automation, live requests, an LLM dependency, or automatic attack execution.

## Recommended Workflow

Record one primary business journey per file when practical:

```bash
hunt setup

# Record ACCOUNT_A using the application normally, then export HAR or Burp XML.
hunt ingest-wizard -w workspaces/<slug>
hunt captures -w workspaces/<slug>

# Record a second focused journey or actor and import again.
hunt ingest-wizard -w workspaces/<slug>
hunt workflow -w workspaces/<slug>
hunt hypotheses -w workspaces/<slug>
```

Good capture: open a domain, list DNS records, create one record, read the result, stop.

Broad capture: login, browse CDN, open billing, create DNS, change IAM, visit profile, delete a
server, and read notifications. Broad captures are accepted, retained, and marked with quality
warnings; they are not an ingest error.

Keep normal behavior and researcher probes in separate captures. This is the most important way to
prevent deliberately manipulated traffic from contaminating baseline reconstruction.

## Model

The human-readable registry is `workspaces/<slug>/captures/captures.yaml`:

```yaml
capture_id: CAP-12AB34CD56EF
source:
  type: HAR
  file: account-a-create-dns.har
  fingerprint: <sha256>
  redacted_reference: observations/har/account-a-create-dns-redacted.har
actor_id: ACCOUNT_A
actor_source: USER_CONFIRMED
actor_confidence: HIGH
actor_evidence:
  - Filename contains configured actor label ACCOUNT_A.
  - Researcher confirmed the detected actor.
capture_mode: NORMAL_BEHAVIOR
capture_mode_source: USER_CONFIRMED
intent:
  label: create_dns_record
  action: CREATE
  resource_type: dns_record
  confidence: HIGH
  source: USER_CONFIRMED
intent_inference:
  proposed_action: CREATE
  proposed_resource: dns_record
  confidence: HIGH
  evidence:
    - POST /domains/101/dns-records supports CREATE dns_record.
observation_relevance:
  OBS-000001: SUPPORTING
  OBS-000002: PRIMARY
  OBS-000003: PRIMARY
  OBS-000004: CONTEXT
quality:
  labels: [FOCUSED]
```

`capture_id` is deterministic from source type and source-content fingerprint. Reingesting the
same source refreshes its capture metadata without duplicating observations. Raw source files are
not copied into the registry, and metadata contains no credential values.

Metadata provenance is explicit:

- `ENGINE_INFERRED`: deterministic HTTP or workspace-policy proposal.
- `USER_CONFIRMED`: the researcher accepted a proposal.
- `USER_SUPPLIED`: the researcher entered or edited the value.
- `UNKNOWN`: no reliable provenance exists.

Confirmed intent is context, not causality. It does not make every request in a file part of the
journey, prove resource identity, or override relationship gates.

## Capture Modes

| Mode | Downstream behavior |
|---|---|
| `NORMAL_BEHAVIOR` | Primary/supporting observations may support normal workflows, lifecycle, ownership, and passive baselines. Context/noise remains retained but does not enter the focused workflow. |
| `RESEARCHER_PROBE` | Retained as testing evidence and typed replay/comparison context; excluded from normal workflow, ownership, and passive baselines. |
| `AUTHENTICATION` | Retained for session establishment and authentication evidence; excluded from ordinary workflow and ownership reconstruction. |
| `MIXED` | Conservatively treated like probe traffic because normal and manipulated activity cannot be separated safely. |
| `UNKNOWN` | Explicit new unknown captures cannot establish new ownership claims. Legacy unlinked observations retain historical analysis behavior without being rewritten. |

Unannotated direct imports inherit `capture_policy.default_mode` from `target.yaml`, which defaults
to `NORMAL_BEHAVIOR` for backward-compatible operation. An explicit `--capture-mode UNKNOWN`
remains conservative. Engine-only intent remains inspectable but does not narrow historical-style
imports until the researcher supplies or confirms capture context. Set `capture_policy.infer_intent`
to `false` to keep automatic proposals from becoming the selected capture intent.

## Intent, Relevance, And Quality

Intent inference uses deterministic method, path, status, order, and first-party classification.
Evidence strings are persisted. Out-of-scope or suppressed telemetry cannot create an intent or a
false `MULTI_INTENT` warning.

Observation relevance is a soft prior:

- `PRIMARY`: directly matches the main action/resource family.
- `SUPPORTING`: parent, prerequisite-looking, or closely related resource traffic.
- `CONTEXT`: retained first-party traffic outside the main journey.
- `NOISE`: out-of-scope or suppressed traffic.
- `UNKNOWN`: insufficient classification.

Quality labels are advisory: `FOCUSED`, `BROAD`, `MIXED`, `LOW_SIGNAL`, `AUTH_HEAVY`, and
`MULTI_INTENT`. They never block ingestion.

## CLI

Interactive import:

```bash
hunt ingest-wizard -w workspaces/<slug>
```

Direct import with explicit context:

```bash
hunt ingest account-a-create-dns.har -w workspaces/<slug> \
  --actor ACCOUNT_A --channel WEB \
  --capture-mode NORMAL_BEHAVIOR \
  --intent-action CREATE --intent-resource dns_record

hunt ingest-burp account-b-probe.xml -w workspaces/<slug> \
  --actor ACCOUNT_B --channel WEB \
  --capture-mode RESEARCHER_PROBE \
  --intent-action READ --intent-resource dns_record
```

Inspection:

```bash
hunt captures -w workspaces/<slug>
hunt captures --explain CAP-12AB34CD56EF -w workspaces/<slug>
```

The explanation includes source reference, actor/mode/intent provenance, inference evidence,
primary/supporting observations, quality evidence, counts, and warnings.

## Reconstruction Safety

Same capture does not mean same resource or causal workflow. Different captures are not joined by
hard causality merely because scalar values or route order match. Hard links still require existing
typed producer-consumer or explicit state-transition evidence and compatible boundaries.

Probe observations remain in the observation and capture registries and may support typed replay
or cross-actor comparison records. They cannot silently claim that the probing actor owns the
target object or that the manipulated sequence is a normal application workflow.

Equivalent normal journeys by two controlled actors remain separate instances but may share a
structural workflow family. That supports higher-quality ownership and comparison evidence without
automatically creating a BOLA hypothesis or bypassing readiness gates.

## Backward Compatibility

Existing observations load because capture fields have additive defaults. Workspaces without a
capture registry synthesize in-memory `CAP-LEGACY-*` entries with `UNKNOWN` mode and intent; raw
files and historical observations are not rewritten. Existing workflow manifests without capture
fields remain valid and use workspace policy defaults for new ingestion.

The feature changes evidence interpretation only. Approval checks, ownership requirements,
production/local-lab protections, request budgets, and bounded execution remain unchanged.
