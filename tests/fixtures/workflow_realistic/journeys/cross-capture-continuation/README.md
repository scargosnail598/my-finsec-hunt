# Cross-Capture Continuation Journey

## Scenario

A workflow spans multiple captured HAR/traffic files due to timing or capture boundaries. The same actor performs operations in capture A and capture B, and they must be correctly linked.

### Business Flow
1. **Capture 1 (session S1)**: POST /orders → orderId
2. **Capture 2 (session S2)**: POST /orders/{orderId}/pay → Response includes paymentId
3. **Capture 3 (session S3)**: POST /orders/{orderId}/confirm → Complete

All operations are by the same actor (ACCOUNT_X) but captured at different times with potentially different sessions.

## Key Challenges for Reconstruction

### 1. Cross-Capture Continuation
- Captures are separate files; sequence must be inferred from timestamps
- Session IDs may differ across captures (S1, S2, S3)
- Actor is the same; this is a continuation, not a cross-actor issue

### 2. Non-Distinctive Resource IDs in Cross-Capture
- If orderId is not distinctive enough, it should NOT bridge captures without explicit capability evidence
- If orderId IS distinctive (unlikely for cross-capture) AND same actor, it may bridge

### 3. Capability-Based Bridging
- paymentId is distinctive and capability-like
- It may bridge capture boundaries if output-only and consumed

## Labeled Relationships

| Relationship | Producer Obs | Consumer Obs | Expected Basis | Status | Captures |
|---|---|---|---|---|---|
| orderId creation | create_order | pay_order | RESOURCE_CREATED | expected | C1→C2 |
| paymentId creation | pay_order | confirm_order | CAPABILITY_ISSUED | expected | C2→C3 |
| orderId echo in pay | pay_order (req) | pay_order (resp) | REQUEST_VALUE_ECHOED | forbidden | - |

## Validation

1. **Journey integrity**: Despite 3 captures, all 3 operations in single component
2. **Cross-capture edges**: orderId bridges C1→C2; paymentId bridges C2→C3
3. **Same actor**: No cross-actor comparison needed
4. **Session isolation**: Different sessions don't prevent continuity if same actor

## Notes

- This tests that the engine can follow workflows across capture boundaries.
- Same actor is sufficient IF the value is distinctive enough (capability).
- Non-distinctive IDs alone should NOT bridge without additional evidence.
