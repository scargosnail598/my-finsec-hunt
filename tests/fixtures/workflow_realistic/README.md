# Realistic Workflow Validation Corpus

## Purpose

This corpus contains realistic, sanitized fintech and web API journeys designed to validate workflow reconstruction recall while maintaining zero false merges and perfect precision.

Unlike the compact `workflow_precision/` benchmark which is fully labeled but minimalist, this corpus:

- Models realistic multi-step flows from real protocols
- Contains unfamiliar state names, capability field names, and resource ID conventions
- Includes complex scenarios: multi-service handoffs, nested resources, token aliases, cross-capture continuation
- Provides complete ground-truth labels for every causal relationship
- Explicitly marks forbidden and unknown relationships
- Enables stratified metrics by difficulty and relationship type

## Structure

```
workflow_realistic/
├── README.md                          (this file)
├── journeys/                          (sanitized HAR-like fixtures)
│   ├── resource-lifecycle/
│   │   ├── README.md
│   │   └── journeys.json
│   ├── capability-handoff/
│   │   ├── README.md
│   │   └── journeys.json
│   ├── multi-service-payment/
│   │   ├── README.md
│   │   └── journeys.json
│   ├── nested-resource/
│   │   ├── README.md
│   │   └── journeys.json
│   ├── unfamiliar-state-transitions/
│   │   ├── README.md
│   │   └── journeys.json
│   ├── token-aliases/
│   │   ├── README.md
│   │   └── journeys.json
│   ├── replay-and-fanout/
│   │   ├── README.md
│   │   └── journeys.json
│   ├── cross-capture-continuation/
│   │   ├── README.md
│   │   └── journeys.json
│   └── adversarial/
│       ├── README.md
│       └── journeys.json
├── labels/
│   ├── README.md
│   ├── causal-edges.yaml            (ground truth for all edges)
│   ├── journeys.yaml                (ground truth for journey membership)
│   ├── prerequisites.yaml           (ground truth for ordering)
│   └── resources.yaml               (ground truth for resource relationships)
└── metrics/
    └── .gitkeep                      (output dir for benchmark results)
```

## Corpus Categories

### 1. resource-lifecycle/
**Tests:** Recognition of resources created through producer operations and tracked through subsequent state transitions.

Example: 
```
POST /orders -> orderId
GET /orders/{orderId} -> status=PENDING
POST /orders/{orderId}/confirm
GET /orders/{orderId} -> status=CONFIRMED
```

**Challenges:**
- State field may be named `state`, `status`, `workflow_state`, `condition`
- Lifecycle verbs may be unfamiliar: `RESERVED`, `CAPTURED`, `LOCKED`, `RELEASED`
- Must not confuse read-before-write patterns with causality

---

### 2. capability-handoff/
**Tests:** Recognition of capabilities issued in one response and immediately consumed in the next request (challenge-response, nonce, CSRF token flows).

Example:
```
GET /checkout -> challengeToken / nonce / verificationCode
POST /payment/authorize <- challengeToken
```

**Challenges:**
- Capability field may be named: `challenge`, `nonce`, `authorization`, `reference`, `handle`, `ticket`, `receipt`, `intent`, `sessionReference`, `continuation`
- Capabilities are distinctive but not resource IDs
- Must not confuse with request echoes
- Recognition requires understanding that token is consumed, not just passed

---

### 3. multi-service-payment/
**Tests:** Workflow continuation across service boundaries using workflow tokens.

Example:
```
api.example.test -> transactionId
payments.example.test <- transactionId
api.example.test <- paymentId
```

**Challenges:**
- Requires maintaining workflow identity across host boundaries
- Token must be distinctive (not just a common business value)
- Same actor, but different service contexts

---

### 4. nested-resource/
**Tests:** Parent-child resource relationships and nested workflow identities.

Example:
```
POST /accounts/{accountId}/orders -> orderId
POST /accounts/{accountId}/orders/{orderId}/items -> itemId
```

**Challenges:**
- Reconstruction must track that itemId depends on orderId contextually
- accountId and orderId must not create spurious prerequisite confusion
- Multi-level resource paths

---

### 5. unfamiliar-state-transitions/
**Tests:** State transitions using verbs and state names NOT in the current ACTION_STATE_HINTS hardcoded list.

Examples:
- `CREATED → RESERVED → CAPTURED`
- `DRAFT → SUBMITTED → SETTLED`
- `OPEN → LOCKED → RELEASED`
- `INITIATED → VERIFIED → FINALIZED`
- `REQUESTED → ACCEPTED → COMPLETED`

**Challenges:**
- The engine must infer state transitions from observed values, not verb matching
- Requires detecting that the same resource is referenced at different times with different state values
- Must not assume every changed scalar field is state

---

### 6. token-aliases/
**Tests:** Recognizing semantic equivalence across different field names for the same logical token.

Example:
```
Response: { "continuation": "abc123" }
Request: { "sessionReference": "abc123" }
```

**Challenges:**
- Field names differ but value is reused
- Requires understanding resource/capability roles contextually, not just by name
- Must handle aliasing without hard-coding vocabularies

---

### 7. replay-and-fanout/
**Tests:** Legitimate multi-use scenarios vs. illegitimate replay.

Examples:
- One output consumed once (normal)
- One output consumed multiple times with different context (pagination, listing)
- Replay that should be suspicious
- Repeated scalar values that are merely observational (enums, timestamps)

**Challenges:**
- Same value appearing in multiple requests must not always create merges
- Context must disambiguate legitimate re-use from suspicious replay
- Idempotency keys must not be treated as causal edges

---

### 8. cross-capture-continuation/
**Tests:** Workflow continuation across capture files while maintaining isolation.

Example:
```
Capture 1: actor=A, session=S1
  POST /orders -> orderId

Capture 2: actor=A, session=S2
  POST /orders/{orderId}/pay <- orderId (different capture, same actor)
```

**Challenges:**
- Same actor may have multiple captures/sessions
- Capability-based tokens can bridge captures
- Non-distinctive resource IDs must not bridge captures unless explicitly tokenized
- Session boundaries matter

---

### 9. adversarial/
**Tests:** Scenarios specifically designed to tempt false merges.

#### Subcases:
- **Coincidental scalar equality:** `quantity=10` and `report_id=10` must not merge
- **Read-before-write IDs:** `GET /orders/123` followed by `POST /orders/123/cancel` must not prove causality
- **Echoed IDs:** `POST {"orderId":"123"} -> {"orderId":"123"}` must not be treated as production
- **Common state strings:** `status=ACTIVE` across unrelated resources
- **Pagination tokens:** `page=2, cursor=abc` must not create merges
- **Reused business values:** amount, price, quantity across different payment contexts
- **Cross-actor equality:** Same scalar observed by different controlled actors must not merge workflows
- **Cross-session accidental reuse:** Must remain isolated

---

## Label Files

### causal-edges.yaml
Specifies all expected and forbidden edges.

Structure:
```yaml
edges:
  - id: "edge-001"
    producer: "obs-id"
    consumer: "obs-id"
    relationship: CAUSAL_HARD  # or CONTEXT_SOFT, REPLAY_RELATED, CROSS_ACTOR_COMPARISON
    expected_basis: RESOURCE_CREATED  # or CAPABILITY_ISSUED, STATE_TRANSITION_PRODUCED, etc.
    status: "expected"  # or "forbidden", "unknown"
    reason: "brief explanation"
    field_name: "orderId"
    resource_type: "order"
    actor: "ACCOUNT_A"
    session: "session-abc"
    capture: "capture-name"
    host: "api.example.test"
```

### journeys.yaml
Specifies expected workflow membership and component count.

Structure:
```yaml
journeys:
  - id: "journey-checkout"
    name: "Checkout with Payment"
    description: "..."
    expected_components: 1  # expect a single workflow component (no fragmentation)
    expected_steps:
      - obs-001
      - obs-003
      - obs-005
    expected_order: true  # steps must appear in this order
    expected_resource_lineage:
      orderId:
        source: obs-001
        produced_basis: RESOURCE_CREATED
    status: "fully_labeled"  # or "partial_label", "exploratory"
    difficulty: "obvious"  # or "indirect", "ambiguous"
    category: "resource-lifecycle"
```

### prerequisites.yaml
Specifies true prerequisites and false adjacencies.

Structure:
```yaml
prerequisites:
  - id: "prereq-001"
    action: "CONFIRM_ORDER"
    precondition_action: "CREATE_ORDER"
    status: "expected"  # or "forbidden"
    confidence: "HIGH_EVIDENCE"
    reason: "orderId flows from creation to confirmation"
```

### resources.yaml
Specifies resource relationships and ownership.

Structure:
```yaml
resources:
  - id: "rinst-001"
    type: "order"
    instances: ["obs-001_value", "obs-003_value"]
    expected_state_transitions:
      - from: "PENDING"
        to: "CONFIRMED"
        evidence: "obs-003"
    owned_by: "account"  # or null
```

---

## Label Coverage Levels

### FULLY_LABELED (quality corpus)
- Every expected hard edge is explicitly labeled
- Every forbidden edge is explicitly labeled
- Every resource identity is confirmed
- Every state transition is documented
- All prerequisites are marked
- Expected journey fragmentation is 0

### EXPLORATORY (partial label)
- Known edges are labeled
- Unknown and ambiguous edges are marked `unknown` or `exploratory`
- Used for measuring what the system discovers
- Not part of precision gates

---

## Metrics

After running the benchmark, `metrics/` will contain:

```
workflow_realistic_report.json
├── corpus_statistics
│   ├── total_journeys
│   ├── total_observations
│   ├── total_expected_hard_edges
│   ├── total_expected_soft_edges
│   ├── total_forbidden_edges
├── precision_recall_by_category
│   ├── resource-lifecycle
│   │   ├── hard_edge_precision
│   │   ├── hard_edge_recall
│   │   ├── forbidden_edges_found
│   ├── capability-handoff
│   │   ├── ...
├── missed_edges
│   ├── - producer: obs-id
│   │   consumer: obs-id
│   │   expected_basis: CAPABILITY_ISSUED
│   │   actual_basis: AMBIGUOUS_ORIGIN
│   │   reason_rejected: "capability_semantics_not_proven"
├── false_merges
│   ├── - left: component-1
│   │   right: component-2
│   │   forbidden_merge_reason: "different_actors"
├── journey_fragmentation_analysis
│   ├── - journey_id: "checkout"
│   │   expected_components: 1
│   │   observed_components: 3
│   │   breaks:
│   │     - between: [obs-id, obs-id]
│   │       reason: "missing_causal_basis"
```

---

## Design Principles

1. **Realistic but Sanitized**: Based on real protocol patterns, but all credentials, PII, and sensitive values are fictional.

2. **Self-Documenting**: Each journey subdirectory explains the business scenario and labeled relationships.

3. **Structural, Not Lexical**: Recognition rules should not depend on specific field names or keywords. They should handle unknown field names as long as structural evidence is present.

4. **Conservative Labeling**: Unknown relationships are marked as `unknown`, not guessed.

5. **Complete Coverage**: Once labeled, this corpus is the ground truth for "correct" reconstruction.

6. **Adversarial Design**: Includes anti-patterns specifically chosen to prevent over-generalization.

---

## Usage

### Load and evaluate:
```python
from finsec.behavior.benchmark import load_realistic_benchmark, evaluate_realistic_benchmark

benchmark = load_realistic_benchmark(Path(__file__).parent / "workflow_realistic")
report = evaluate_realistic_benchmark(benchmark, tmp_path)
```

### Inspect missed edges:
```python
for edge in report.missed_edges:
    print(f"Producer: {edge.producer}")
    print(f"Consumer: {edge.consumer}")
    print(f"Expected: {edge.expected_basis}")
    print(f"Actual: {edge.actual_basis}")
    print(f"Reason: {edge.rejection_reason}")
```

### Check safety gates:
```python
assert report.forbidden_hard_edges == 0
assert report.forbidden_merges == 0
assert report.test_ready_with_blockers == 0
```

---

## Independent Review

This corpus is designed so that a reviewer unfamiliar with the reconstruction engine can:

1. Read the journey README to understand the business scenario
2. Inspect `labels/causal-edges.yaml` to see what relationships are expected/forbidden
3. Verify that labeled edges make sense from a protocol perspective
4. Suggest additions or corrections

The reviewer does not need to understand implementation details.
