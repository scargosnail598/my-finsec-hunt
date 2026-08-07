# Unfamiliar State Transitions Journey

## Scenario

A payment system uses a custom state machine: CREATED → RESERVED → CAPTURED → SETTLED. None of these state names appear in the ACTION_STATE_HINTS hard-coded dictionary. The reconstruction engine must infer the state transitions from structural evidence (same resource, different values) without relying on verb matching.

### Business Flow
1. **POST /payments** → Returns paymentId + state=CREATED
2. **POST /payments/{paymentId}/reserve** → state transitions to RESERVED
3. **POST /payments/{paymentId}/capture** → state transitions to CAPTURED
4. **GET /payments/{paymentId}** → Confirms state=CAPTURED
5. **POST /payments/{paymentId}/settle** → state transitions to SETTLED

## Key Challenges for Reconstruction

### 1. Unknown State Values
- CREATED, RESERVED, CAPTURED, SETTLED are NOT in ACTION_STATE_HINTS
- ACTION_STATE_HINTS has CONFIRMED, COMPLETED, etc., but not these names
- Reconstruction must infer without verb hints

### 2. Semantic State Vs Unrelated Fields
- `state` field contains lifecycle values (CREATED, RESERVED, etc.)
- Response may also include `errorCode`, `retryCount`, `sequenceNumber`
- Must NOT assume every changed scalar is state
- Must detect that `state` field specifically changes in predictable ways

### 3. Temporal and Semantic Evidence
- Reconstruct must infer: same resource (paymentId) + same state field + different values + intervening state-changing action = state transition
- Doesn't need to know the specific state names in advance
- Must verify the sequence is logical (no backwards transitions)

## Labeled Relationships

| Relationship | Producer Obs | Consumer Obs | Expected Basis | Status |
|---|---|---|---|---|
| paymentId creation | create_payment | reserve_payment | RESOURCE_CREATED | expected |
| state CREATED→RESERVED | create_payment (impl state) | reserve_payment (action) | STATE_TRANSITION_PRODUCED | expected |
| state RESERVED→CAPTURED | reserve_payment (impl state) | capture_payment (action) | STATE_TRANSITION_PRODUCED | expected |
| paymentId read confirmation | capture_payment | read_payment | EXISTING_VALUE_OBSERVED | forbidden |
| state CAPTURED→SETTLED | capture_payment (impl state) or read_payment | settle_payment (action) | STATE_TRANSITION_PRODUCED | expected |

## Validation

1. **Journey integrity**: All operations in a single workflow component
2. **Ordering**: create_payment → reserve_payment → capture_payment → read_payment → settle_payment
3. **State chain**: CREATED → RESERVED → CAPTURED → SETTLED (inferred, not hard-coded)
4. **No false states**: Changed fields that aren't `state` must not be treated as state transitions

## Notes

- This is the critical test for generalized state transition recognition.
- The engine must learn to recognize state-like behavior from structural evidence.
- Contrast with business values: amount, count, retryCount that also change but aren't lifecycle state.
