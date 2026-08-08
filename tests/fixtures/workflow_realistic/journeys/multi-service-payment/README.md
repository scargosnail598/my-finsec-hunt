# Multi-Service Payment Journey

## Scenario

A fintech application creates a persistent transaction on the main API. That transaction identity
is consumed by a dedicated payment service, which creates a payment identity used by settlement.

### Business Flow
1. **api.example.test POST /transactions** → Creates transaction + returns transactionId
2. **payments.example.test POST /payments** → Submit transactionId → Receive paymentId
3. **api.example.test POST /transactions/{transactionId}/settle** → Supply paymentId to settle

## Key Challenges for Reconstruction

### 1. Cross-Service Token Continuation
- Same actor, different hosts
- transactionId is a typed persistent resource identity, not a generic business value
- The payment service consumes that created transaction identity
- Must bridge captures across service boundaries using token

### 2. Service Boundaries Are Not Actor Boundaries
- Both services see the same controlled actor
- Not a cross-actor relationship; still same logical principal
- Cross-host continuation requires distinctive evidence

### 3. Token Role Distinction
- transactionId is NOT a request echo (not in payments.POST request params if payments creates it)
- transactionId IS output-only from api.example.test
- paymentId is output-only from payments.example.test
- Both are produced (RESOURCE_CREATED or CAPABILITY_ISSUED)

### 4. Workflow Identity Across Captures
- Captures may have separate traffic logs, but they represent sequential operations
- The API→Payments→API flow must remain coherent
- No accidental merge with concurrent operations

## Labeled Relationships

| Relationship | Producer Obs | Consumer Obs | Expected Basis | Status |
|---|---|---|---|---|
| transactionId creation | create_transaction | call_payments | RESOURCE_CREATED | expected |
| transactionId lineage | create_transaction | settle_transaction | RESOURCE_CREATED | expected |
| paymentId creation | call_payments | settle_transaction | RESOURCE_CREATED | expected |
| transactionId path param echo | call_payments | call_payments (response) | REQUEST_VALUE_ECHOED | forbidden (if echoed) |

## Validation

1. **Journey integrity**: All 3 operations in a single workflow component
2. **Service continuity**: Cross-host edges permitted if token is distinctive
3. **Ordering**: create_transaction → call_payments → settle_transaction
4. **Forbidden**: No merge if token is not distinctive; no merge if actors differ

## Notes

- This tests that the reconstruction engine can follow typed resource lineage across reviewed
  first-party service boundaries.
- Cross-host continuation still requires the same controlled actor and logical session.
- Same actor is key; different authenticated identities would break the flow.
