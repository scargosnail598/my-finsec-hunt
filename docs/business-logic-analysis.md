# Business Logic Analysis Engine

FinSec Hunt does not guess whether arbitrary requests might work. It reconstructs observed
application behavior, identifies evidence-backed business invariants, generates minimal deviations
from those behaviors, and uses controlled backend validation to determine whether the inferred
invariants are actually enforced.

## Why endpoint-only analysis is insufficient

An endpoint inventory can identify client-controlled identifiers, authentication differences, and
state-changing operations. It cannot by itself represent rules that exist across time, actors, or
resources. Step skipping, replay, invalid ordering, token reuse, terminal-state bypass, partial
rollback, and incompatible role combinations are properties of workflows rather than isolated
routes.

The Business Logic Analysis Engine adds a structured offline layer:

```text
redacted observations
  -> semantic actions and redacted resource instances
  -> propagation links and conservative workflow segmentation
  -> workflow families, states, transitions, and stable graphs
  -> inferred business invariants with contradictions
  -> minimal workflow mutations
  -> hypotheses or research tasks with explicit blockers
  -> existing plan, approval, evidence, validation, and report gates
```

It is not a generic scanner. It sends no requests and does not invent arbitrary payloads.

## Architecture

The subsystem extends the existing pipeline instead of introducing a separate execution path:

- `finsec/behavior/extraction.py` converts already-redacted observations into actions, resource
  instances, state facts, and fingerprint-only propagation links.
- `finsec/behavior/reconstruction.py` segments instances, derives families and transitions, and
  persists stable JSON workflow graphs.
- `finsec/behavior/analysis.py` infers business invariants, applies controlled mutations, explains
  scores and blockers, and synchronizes `BLH-*` records into the canonical backlog.
- `finsec/behavior/rendering.py` renders the same canonical graph as text, JSON, DOT, or Mermaid.
- The existing planner, approval policy, evidence manager, validator, readiness resolver, and
  reporter remain authoritative after offline analysis.

## Knowledge boundaries

The engine uses explicit epistemic states:

- `OBSERVED_FACT`: capture-derived facts or redacted value propagation.
- `INFERRED_PATTERN`: actions, workflow segmentation, states derived from action semantics, and
  business invariants.
- `RESEARCH_TASK`: useful but weak, suppressed, unsafe, destructive, or concurrency-sensitive work.
- `TEST_CANDIDATE`: an evidence-backed offline hypothesis eligible for planning.
- `TEST_PLANNED`: a plan exists, but no vulnerable backend behavior has been demonstrated.
- `NEEDS_EVIDENCE`: empirical controls or state evidence are incomplete.
- `REJECTED_BY_BACKEND`: controlled evidence shows that the backend enforced the invariant.
- `CONFIRMED`: an approved empirical mutation plus authoritative state and impact evidence passed
  skeptical validation.

Offline analysis never emits `CONFIRMED`.

## Workflow reconstruction

`hunt workflows build` combines several deterministic signals:

- timestamps and capture sequence;
- actor, session/capture identity, and channel;
- normalized endpoints and semantic route actions;
- concrete resource-identifier fingerprints;
- response-to-request propagation links;
- explicit response state fields;
- correlation and idempotency identifiers;
- workflow references retained only as SHA-256 fingerprints;
- temporal proximity when stronger identifiers are absent.

Static assets, analytics, telemetry, third-party traffic, OpenAPI-only observations, and repeated
polling are excluded from business paths. Interleaved journeys remain separate when they use
different concrete identifiers. Workflow references do not automatically merge journeys because a
cross-workflow reference is itself a security-relevant condition.

When grouping is weak, the engine records ambiguity instead of forcing certainty. A single capture
cannot establish that a step is mandatory.

## Actions, resources, states, and transitions

Actions retain endpoint and observation provenance. Examples include `CREATE_ORDER`, `PAY_ORDER`,
`CLAIM_REWARD`, `ACCEPT_INVITATION`, and `REFUND_PAYMENT`.

Concrete resource values are not copied into behavior artifacts. The engine stores a type, a stable
fingerprint, a short fingerprint reference, actors, observations, and evidence-backed relationships
such as `owned_by` or `linked_to`.

States come from either:

- explicit response fields such as `status`, `state`, `paymentStatus`, or `entitlementStatus`; or
- deterministic action semantics such as `CANCEL_ORDER -> CANCELLED`.

Every transition records:

```text
source state + action + actor/resource context -> destination state
```

The record includes frequency, examples, contradictions, confidence, and evidence IDs. An
unresolved state remains `UNRESOLVED`.

## Workflow families and graphs

Similar instances are grouped into stable workflow families such as order lifecycle, payment
lifecycle, refund, reward claim, team invitation, and money transfer. A family records observed
paths, the most common path, required-looking intersections, optional actions, branches, outcomes,
and its confidence explanation.

The most frequent path is not declared authorized or mandatory. `required_looking_steps` is
populated only from the intersection of at least two instances.

Graph output is available as text, JSON, Graphviz DOT, or Mermaid:

```bash
hunt workflows list -w workspaces/logic-demo
hunt workflows graph WFAM-A5344DFCA8019BA9 -w workspaces/logic-demo --format text
hunt workflows graph WFAM-A5344DFCA8019BA9 -w workspaces/logic-demo --format json
hunt workflows graph WFAM-A5344DFCA8019BA9 -w workspaces/logic-demo --format dot
hunt workflows graph WFAM-A5344DFCA8019BA9 -w workspaces/logic-demo --format mermaid
```

Example graph:

```text
CREATED --ADD_ORDER--> ITEM_ADDED
ITEM_ADDED --PAY_ORDER--> PAID
PAID --SHIP_ORDER--> SHIPPED
```

Each edge retains supporting observation IDs and workflow-instance IDs.

## Business invariants

The engine currently derives these invariant types:

- ordering and prerequisite patterns;
- single execution and one-time effects;
- terminal-state integrity;
- actor and resource binding;
- workflow-reference scope;
- rollback consistency across linked resources;
- amount, quantity, and financial-state consistency;
- protection of server-controlled fields from undocumented update methods;
- role separation for initiation and approval.

Example:

```text
SHIP_ORDER appears to require PAY_ORDER to occur first in order lifecycle.
```

The invariant remains `INFERRED_PATTERN`, includes supporting and contradicting observations, and
states exactly what empirical validation would require.

## Mutation operators

`hunt logic analyze` applies only mutations supported by an inferred invariant:

- `STEP_SKIPPING`
- `OUT_OF_ORDER_EXECUTION`
- `REPLAY`
- `DUPLICATE_ACTION`
- `CONCURRENT_EXECUTION`
- `TERMINAL_STATE_BYPASS`
- `ACTOR_SWITCH`
- `RESOURCE_SWITCH`
- `CROSS_WORKFLOW_TOKEN_REUSE`
- `PARTIAL_ROLLBACK`
- `QUANTITY_VALUE_INVARIANT`
- `SHADOW_ENDPOINT`
- `ROLE_APPROVAL_BYPASS`

It does not generate arbitrary fuzz values. Value hypotheses refer only to observed amount,
quantity, total, balance, price, fee, or discount fields.

Example generated hypothesis:

```text
Title: Ship order may succeed without pay order
Canonical: ADD_ORDER -> PAY_ORDER -> SHIP_ORDER
Mutation:  ADD_ORDER -> SHIP_ORDER
Invariant: SHIP_ORDER appears to require PAY_ORDER to occur first
Secure:    backend rejects the mutation or produces no unauthorized state change
Vulnerable: backend accepts it and authoritative state shows an unintended effect
Status:    RESEARCH_TASK
Safety:    EXTERNAL_SIDE_EFFECT
Blocker:   explicit target-policy permission is required
```

For the included synthetic fixture this candidate is a `RESEARCH_TASK`, because a directly
observed `CREATE_ORDER -> SHIP_ORDER` path contradicts mandatory-payment inference and shipment is
an external side effect. Other captures can produce a `TEST_CANDIDATE` only when their evidence
and safety controls support planning.

## Refund workflow coverage

The crAPI return flow is represented as a financial workflow rather than an isolated endpoint.
Passive order-detail observations can produce a `SHADOW_ENDPOINT` research task for predictable
`PATCH` and `PUT` variants of the item route, with observed server-controlled fields such as
`status`, `quantity`, and `price` retained as bounded research metadata.

Observed `RETURN_ORDER` actions produce replay, duplicate, concurrency, actor/resource binding,
partial rollback, and value-conservation research tasks. The value-conservation task connects
order price and quantity with authoritative credit or balance fields so a larger-than-purchase
refund is reviewed explicitly. These remain `RESEARCH_TASK` records classified as
`FINANCIAL_STATE_CHANGE` (or `CONCURRENT` for the race variant); they are not proof that either
crAPI challenge is exploitable.

## Scoring and false-positive control

Scores are deterministic and separated into likelihood, impact, test readiness, safety cost, and
confidence. Every contribution is stored, including negative points for contradictions or missing
controls.

Candidates are downgraded when:

- only one workflow instance exists;
- segmentation remains ambiguous;
- an action is polling or background traffic;
- a path branch is observed as optional;
- an endpoint-level object-authorization hypothesis already covers a resource switch;
- controlled actors, authentication, ownership, baseline state, or reset strategy are missing;
- the mutation is concurrent, destructive, externally visible, or otherwise unsafe.

Evidence is retained even when a candidate becomes a research task.

## Readiness and safety

Safety classes are `READ_ONLY`, `LOW_RISK_STATE_CHANGE`, `REVERSIBLE_STATE_CHANGE`,
`FINANCIAL_STATE_CHANGE`, `DESTRUCTIVE`, `CONCURRENT`, `EXTERNAL_SIDE_EFFECT`, and
`UNSAFE_OR_UNBOUNDED`.

Concurrency, destructive actions, external side effects, and high-risk state changes never become
autonomous requests. The current bounded runner supports only its established read-only comparison
shapes. Business-logic plans therefore remain manual-only and blocked from `hunt execute`; this is
intentional and preserves the existing execution policy.

`hunt logic plan` still uses the canonical planner. It creates `DO_NOT_EXECUTE` instructions,
minimum request budgets, controlled actor/resource requirements, state queries, stop conditions,
and cleanup guidance. A research task cannot be planned as an active hypothesis.

Example blocker explanation:

```text
- Insufficient workflow observations to treat the pattern as mandatory.
- Missing actor authentication for one or more controlled workflow actors.
- Controlled resource ownership baseline is missing.
- Concurrency testing is not permitted by the offline engine.
```

## State evidence

State-changing logic validation requires more than a response code. Evidence kinds include:

- `before`
- `after`
- `delayed_after`
- `related_state`
- `ledger_state`
- `entitlement_state`
- `inventory_state`
- `workflow_state`

Business-logic validation requires request and response evidence plus before, after, and delayed
after state. When several resource types are involved, related-resource state is also mandatory.
Artifacts retain checksums, provenance, and redaction metadata.

## Persistence and compatibility

The existing YAML workspace convention is preserved:

```text
behavior/
  actions.yaml
  resource-instances.yaml
  propagation-links.yaml
  workflow-instances.yaml
  workflow-families.yaml
  states.yaml
  transitions.yaml
  graphs/<WFAM-ID>.json
model/
  business-invariants.yaml
hypotheses/
  business-logic.yaml
  backlog.yaml                 # canonical adapter records for existing gates
```

All files are versioned and deterministically ordered. Existing workspaces are compatible: missing
behavior directories and files are created lazily on the next build. No migration rewrites factual
observations or older model artifacts.

Collection schemas are in `schemas/behavior-workflow.schema.json`,
`schemas/business-invariant.schema.json`, and
`schemas/business-logic-hypothesis.schema.json`. Pydantic models in `finsec/behavior/domain.py` are
the runtime authority.

## CLI workflow

Run the complete offline pipeline:

```bash
hunt workflow --no-ingest -w workspaces/<slug>
```

Or inspect each new stage directly:

```bash
hunt workflows build -w workspaces/<slug>
hunt workflows list -w workspaces/<slug>
hunt workflows show <WFAM-ID> -w workspaces/<slug>
hunt workflows explain <WFAM-ID> -w workspaces/<slug>
hunt workflows graph <WFAM-ID> -w workspaces/<slug> --format mermaid

hunt logic analyze -w workspaces/<slug>
hunt logic hypotheses -w workspaces/<slug>
hunt logic hypotheses -w workspaces/<slug> --research-tasks
hunt logic explain <BLH-ID> -w workspaces/<slug>
hunt logic blockers <BLH-ID> -w workspaces/<slug>
hunt logic plan <BLH-ID> -w workspaces/<slug>
```

## Synthetic demonstration

The included fixture never contacts a server:

```bash
hunt setup \
  --name "Logic Demo" \
  --slug logic-demo \
  --host api.logic-demo.test \
  --account ACCOUNT_A \
  --synthetic \
  --yes

hunt ingest examples/business-logic-demo.har \
  -w workspaces/logic-demo \
  --actor ACCOUNT_A \
  --channel WEB

hunt workflow --no-ingest -w workspaces/logic-demo
hunt workflows list -w workspaces/logic-demo
hunt logic hypotheses -w workspaces/logic-demo
```

The fixture contains two observed `CREATE -> ADD -> PAY -> SHIP` order lifecycles and one
`CREATE -> SHIP` deviation. The engine reconstructs the graph, records the deviation as
contradicting evidence, and emits specific ordering and step-skip hypotheses without claiming a
vulnerability.

To continue at the safety boundary:

```bash
hunt logic explain <BLH-ID> -w workspaces/logic-demo
hunt logic blockers <BLH-ID> -w workspaces/logic-demo
hunt logic plan <BLH-ID> -w workspaces/logic-demo
```

The generated plan remains `DO_NOT_EXECUTE` and the current runner refuses the state-changing
shape.

## Rejection and confirmation lifecycle

A complete empirical lifecycle is:

1. ingest passive observations;
2. reconstruct workflows and infer an invariant;
3. generate a `TEST_CANDIDATE`;
4. create and review a bounded plan;
5. obtain explicit target-policy and human approval using supported execution or an authorized
   external/manual collection process;
6. collect redacted mutation request, response, before, after, delayed-after, and related state;
7. run `hunt validate`;
8. receive `REJECTED_BY_BACKEND` when the secure control is observed, or `CONFIRMED` only when the
   mutation and authoritative state demonstrate meaningful impact;
9. generate a report only from the confirmed validation record.

The synthetic test suite covers both dispositions. It also verifies that missing state evidence
cannot confirm a hypothesis.

## Troubleshooting incomplete captures

- **One-step workflows:** capture the predecessor and an authoritative state read; until then the
  instance remains weak and related hypotheses remain research tasks.
- **Interleaved journeys merged unexpectedly:** ensure concrete identifiers or correlation fields
  are present in the capture. The engine does not use URL order alone.
- **Separate journeys not linked:** capture the response that creates the identifier/reference and
  the later request that consumes it.
- **Polling dominates a path:** retain timestamps and stable response state fields; repeated
  read-only status traffic is then suppressed deterministically.
- **No explicit state:** capture response status/state fields or an independent state query. Action
  semantics remain weaker than explicit fields.
- **A step appears required from one path:** collect another complete successful workflow. One
  instance is never treated as mandatory policy.
- **Plan remains blocked:** inspect `hunt logic blockers`. Do not edit away missing ownership,
  authentication, state, policy, concurrency, or side-effect controls.

## Current limitations

- Generic cookie-level browser-session reconstruction is unavailable because credential values are
  intentionally redacted; actor plus capture identity and stronger correlation signals are used.
- Request/response body values are read only from already-redacted local capture copies. Captures
  that omit bodies provide correspondingly weaker propagation and state evidence.
- Asynchronous workflows without a shared identifier remain ambiguous.
- The bounded runner does not execute business-logic POST/PUT/PATCH/DELETE or concurrent mutations.
- No LLM is required or used for canonical records. Semantic action coverage is deterministic and
  rule-based, so unusual product terminology may need future explicit rules.
