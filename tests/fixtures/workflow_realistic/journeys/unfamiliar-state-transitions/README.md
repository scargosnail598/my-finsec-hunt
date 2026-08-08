# Unfamiliar State Transitions Journey

## Scenario

A payment system uses a deliberately unfamiliar state machine: FROZEN → CRYSTALLIZED → SEALED
→ ARCHIVED. The reconstruction engine must infer transitions from structural evidence without
relying on a vocabulary of known lifecycle words.

### Business Flow
1. **POST /payments** → Returns paymentId + state=FROZEN
2. **POST /payments/{paymentId}/reserve** → state transitions to CRYSTALLIZED
3. **POST /payments/{paymentId}/capture** → state transitions to SEALED
4. **GET /payments/{paymentId}** → Confirms state=SEALED
5. **POST /payments/{paymentId}/settle** → state transitions to ARCHIVED

## Key Challenges for Reconstruction

### 1. Unknown State Values
- FROZEN, CRYSTALLIZED, SEALED, and ARCHIVED are intentionally unfamiliar
- Reconstruction must infer without verb hints

### 2. Semantic State Vs Unrelated Fields
- `state` field contains the unfamiliar lifecycle values
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
| state FROZEN→CRYSTALLIZED | create_payment | reserve_payment | STATE_TRANSITION_PRODUCED | expected |
| state CRYSTALLIZED→SEALED | reserve_payment | capture_payment | STATE_TRANSITION_PRODUCED | expected |
| paymentId read confirmation | capture_payment | read_payment | EXISTING_VALUE_OBSERVED | forbidden |
| state SEALED→ARCHIVED | capture_payment | settle_payment | STATE_TRANSITION_PRODUCED | expected |

## Validation

1. **Journey integrity**: All operations in a single workflow component
2. **Ordering**: create_payment → reserve_payment → capture_payment → read_payment → settle_payment
3. **State chain**: FROZEN → CRYSTALLIZED → SEALED → ARCHIVED
4. **No false states**: Changed fields that aren't `state` must not be treated as state transitions

## Notes

- This is the critical test for generalized state transition recognition.
- The engine must learn to recognize state-like behavior from structural evidence.
- Contrast with business values: amount, count, retryCount that also change but aren't lifecycle state.
