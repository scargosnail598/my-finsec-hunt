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

`hunt workflows build` extracts typed, fingerprint-only values with semantic field role, resource
type and role, request/response location, primitive type, actor, session, capture, host, temporal
direction, and evidence reason. Matching scalar text alone is never sufficient to merge journeys.

Relationships have explicit semantics:

- `CAUSAL_HARD`: an earlier response produced a distinctive typed identifier or workflow token
  consumed by a compatible later request. Only this relationship may union components.
- `CONTEXT_SOFT`: correlation IDs, collection-member identifiers, low-entropy values, or other
  useful context that cannot establish a workflow boundary.
- `REPLAY_RELATED`: repeated use of a state-changing action, primary resource, or idempotency key;
  it does not establish prerequisite order.
- `CROSS_ACTOR_COMPARISON`: compatible typed input on separate controlled actors, retained for
  ownership testing without merging their journeys.

Hard relationships require known temporal direction, compatible semantic roles, a known actor,
compatible session and capture continuity, sufficient distinctiveness, and stronger explicit
evidence for cross-host correlation. Missing actor, session, capture, or semantic type is not a
wildcard.

Static assets, analytics, telemetry, third-party traffic, OpenAPI-only observations, and repeated
polling are excluded from business paths. Interleaved journeys remain separate when they use
different concrete identifiers. Workflow references do not automatically merge journeys because a
cross-workflow reference is itself a security-relevant condition.

Booleans, nulls, empty values, pagination values, common statuses, timestamp-like fields, HTTP
statuses, and incompatible numeric fields are suppressed or retained only as soft context.
Collection response identifiers are also soft because one catalog result can feed several separate
journeys. When grouping is weak, the engine records ambiguity instead of forcing certainty.

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

Workflow families use an exact canonical structural signature: ordered method/route/action tuples,
resource roles, state transitions, hard-edge topology, and terminal or mutating positions. Repeated
steps remain distinct by position. Journeys that touch the same resource type but have different
orders, branches, or terminal actions remain separate; the display name does not control grouping.

Family IDs derive from that signature. `required_looking_steps` and ordering invariants come from
typed hard producer-consumer prerequisites, not adjacency or the most frequent path. Unsupported
adjacency is retained as a research clue rather than promoted to a step-skipping candidate.

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

It does not generate arbitrary fuzz values. Value hypotheses require a client-controlled request
field with a recognized business role such as amount, refund amount, quantity, price, balance,
credit, limit, fee, or cumulative value. Response-only values, IDs, dimensions, counters, pages,
and unrelated numeric fields cannot make another action value-mutable.

Example generated hypothesis:

```text
Title: Ship order may succeed without pay order
Canonical: PAY_ORDER -> SHIP_ORDER
Mutation:  omit PAY_ORDER and invoke SHIP_ORDER
Invariant: SHIP_ORDER appears to require PAY_ORDER to occur first
Secure:    backend rejects the mutation or produces no unauthorized state change
Vulnerable: backend accepts it and authoritative state shows an unintended effect
Status:    RESEARCH_TASK
Safety:    EXTERNAL_SIDE_EFFECT
Blocker:   explicit target-policy permission is required
```

For the included synthetic fixture this candidate is a `RESEARCH_TASK` because shipment is an
external side effect and the exact structural family has insufficient executable evidence. A
separately observed `CREATE_ORDER -> SHIP_ORDER` journey remains a distinct family instead of being
used to distort the canonical checkout family.

## Refund workflow coverage

The crAPI return flow is represented as a financial workflow rather than an isolated endpoint.
Passive order-detail observations can produce a `SHADOW_ENDPOINT` research task for predictable
`PATCH` and `PUT` variants of the item route, with observed server-controlled fields such as
`status`, `quantity`, and `price` retained as bounded research metadata.

Observed `RETURN_ORDER` actions can produce replay, duplicate, and concurrency research tasks.
Actor/resource switching additionally requires typed request identifiers and cross-actor
comparison evidence. Partial rollback requires at least two affected resource states. A
value-conservation task is generated only when the return/refund request itself exposes a
recognized client-controlled value; response-only price, quantity, credit, or balance fields are
authoritative comparison evidence, not mutation inputs. These records are not proof that a target
is exploitable.

## Scoring and false-positive control

Scores are deterministic and separated into likelihood, impact, test readiness, safety cost, and
confidence. Every contribution is stored, including negative points for contradictions or missing
controls.

Mutation eligibility is evaluated separately for each family and action. Rejected mutations are
persisted in `hypotheses/business-logic.yaml` with their evidence and deterministic reasons, such
as "adjacency alone is not a prerequisite," "no typed client-controlled resource identifier," or
"partial rollback requires at least two linked state effects."

Plausibility and execution readiness are separate:

- `RESEARCH_ONLY`: speculative, unsafe, or semantically under-supported;
- `REVIEW_REQUIRED`: plausible, but ownership, authentication, policy, or state blockers remain;
- `TEST_READY`: no current eligibility or safety blocker remains.

A record with any blocker cannot be `TEST_READY`. Candidates are downgraded when:

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

Relationship, workflow instance/family, business invariant, logic hypothesis, and canonical backlog
stores now write schema version 2. Their readers accept version 1 and fill conservative defaults,
so existing workspaces remain readable. Missing behavior files are created lazily on the next
build; status and readiness inspection never rewrites factual observations or user data.

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

## Precision benchmark

The compact sanitized benchmark covers actor/session/capture boundaries, incompatible and generic
scalars, typed tokens and resource IDs, false adjacency, family structure, actor comparison,
replay, value conservation, and partial rollback. Unknown labels are excluded from denominators.

```bash
python scripts/evaluate_workflow_precision.py \
  --json-output /tmp/finsec-workflow-precision.json \
  --markdown-output /tmp/finsec-workflow-precision.md
```

It reports workflow and family boundary pairwise precision/recall/F1, causal-edge metrics,
forbidden hard edges, prerequisite precision/recall, precision@10, expected-mutation recall@10,
unsupported-hypothesis rate, relationship recall, and test-ready records that still have blockers.
The evaluator is deterministic, offline, and separate from production CLI surface area.

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
`CREATE -> SHIP` journey. The engine reconstructs them as two structural families, derives
prerequisites only from typed producer-consumer links, and emits specific ordering and step-skip
research tasks without claiming a vulnerability.

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
3. generate a hypothesis with `RESEARCH_ONLY`, `REVIEW_REQUIRED`, or `TEST_READY` readiness;
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
- **Interleaved journeys merged unexpectedly:** inspect relationship types and reasons. Correlation
  IDs, route adjacency, collection IDs, replay links, and cross-actor comparisons cannot merge.
- **Separate journeys not linked:** capture the response that creates the identifier/reference and
  the later request that consumes it.
- **Polling dominates a path:** retain timestamps and stable response state fields; repeated
  read-only status traffic is then suppressed deterministically.
- **No explicit state:** capture response status/state fields or an independent state query. Action
  semantics remain weaker than explicit fields.
- **A step appears required:** inspect `causal_prerequisites`; adjacency and frequency without a
  typed dependency remain research clues.
- **Plan remains blocked:** inspect `hunt logic blockers`. Do not edit away missing ownership,
  authentication, state, policy, concurrency, or side-effect controls.

## Current limitations

- Generic cookie-level browser-session reconstruction is unavailable because credential values are
  intentionally redacted; actor plus capture identity and stronger correlation signals are used.
- Request/response body values are read only from already-redacted local capture copies. Captures
  that omit bodies provide correspondingly weaker propagation and state evidence.
- Asynchronous workflows without a shared identifier remain ambiguous.
- Conservative exact family signatures can split journeys that a researcher considers related;
  false separation is preferred to false merging at this stage.
- The bounded runner does not execute business-logic POST/PUT/PATCH/DELETE or concurrent mutations.
- No LLM is required or used for canonical records. Semantic action coverage is deterministic and
  rule-based, so unusual product terminology may need future explicit rules.
