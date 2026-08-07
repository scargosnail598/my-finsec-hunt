# Resource Lifecycle Journey

## Scenario

A user creates an order on an e-commerce API, polls the order status, and confirms the order. Each step explicitly transitions the resource through a lifecycle.

### Business Flow
1. **POST /orders** → Returns order ID + initial state (PENDING)
2. **GET /orders/{orderId}** → Confirms order exists with PENDING state
3. **POST /orders/{orderId}/confirm** → Changes state to CONFIRMED
4. **GET /orders/{orderId}** → Confirms final state (CONFIRMED)

## Key Challenges for Reconstruction

### 1. Unfamiliar State Names
The state field may be named:
- `status`
- `state`
- `workflow_state`
- `condition`
- `lifecycle_phase`

And state values may be:
- Standard: `PENDING`, `ACTIVE`, `CONFIRMED`, `COMPLETED`
- Unfamiliar: `RESERVED`, `PROVISIONED`, `ACTIVATED`, `SETTLED`

### 2. Producer Identification
- The initial POST must be recognized as producing both the resource ID and the initial state
- ACTION_STATE_HINTS may not contain the action verb used (e.g., "INITIATE", "RESERVE", "STAGE")
- Must infer production from output-only presence + state-changing operation

### 3. State Transition Recognition
- Same resource (same ID) at different times with different state values
- Intervening action must be semantic (e.g., "confirm", "authorize", "activate")
- Must NOT assume every changed field is state
- Must distinguish state-carrying fields from business values (amount, price, count)

### 4. Read Operations Must Not Prove Production
- `GET /orders/{orderId}` returns the order, but does NOT produce it
- The same order ID consumed in GET must link back to POST production
- Simply reading an ID does not make the GET a prerequisite; the POST is

## Labeled Relationships

| Relationship | Producer Obs | Consumer Obs | Expected Basis | Status |
|---|---|---|---|---|
| orderId creation | create_order | confirm_order | RESOURCE_CREATED | expected |
| orderId echo in confirm | confirm_order | confirm_order (response) | REQUEST_VALUE_ECHOED | forbidden |
| state transition PENDING→CONFIRMED | create_order (initial state) | confirm_order (action implies state) | STATE_TRANSITION_PRODUCED | expected |
| read before write (GET then POST) | read_order_1 | confirm_order | - | forbidden |
| state observation | read_order_1 | confirm_order | EXISTING_VALUE_OBSERVED | forbidden |
| final state confirmation | confirm_order | read_order_2 | EXISTING_VALUE_OBSERVED | forbidden |

## Validation

1. **Journey integrity**: All 4 observations should remain in a single workflow component
2. **Ordering**: create_order → (read_order_1) → confirm_order → read_order_2
3. **Forbidden edges**: No edges to unrelated resources
4. **Prerequisite chain**: 
   - create_order must precede confirm_order (because orderId must be known)
   - create_order implicitly precedes read_order_1 and read_order_2 (resource must exist)

## Notes

- The GET calls are informational, not causal producers. They must not create new workflow edges.
- Cross-observation state comparison is crucial: PENDING in obs-1 response vs CONFIRMED in obs-3 action.
- The state field name is NOT hard-coded; it's inferred from semantic role classification.
