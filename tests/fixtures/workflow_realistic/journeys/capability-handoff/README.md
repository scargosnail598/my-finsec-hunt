# Capability Handoff Journey

## Scenario

A user checks out, receives a verification token (challenge), and uses it to authorize payment. This is a classic capability-based workflow where the first operation issues a capability that the second operation must present.

### Business Flow
1. **GET /checkout** → Returns checkout session + distinctive verification challenge
2. **POST /payment/authorize** → Supply the challenge to prove authorization
3. **POST /payment/confirm** → Finalize payment using authorization reference

## Key Challenges for Reconstruction

### 1. Distinctive Capability Recognition
- Capability is output-only (not in request)
- Distinctive: not a low-entropy enum, not a common business value
- Semantically consumed: used as a prerequisite, not just passed through
- Examples of field names: `challenge`, `nonce`, `verificationCode`, `authorizationToken`, `sessionReference`, `continuation`, `ticket`, `receipt`

### 2. Not Request Echoes
- Distinguish between:
  - **Echoed value**: response includes a value from the request → REQUEST_VALUE_ECHOED
  - **Issued capability**: response includes a NEW value not from request → CAPABILITY_ISSUED
- Distinctive check must be output-only

### 3. Semantic Role Ambiguity
- Same value could be:
  - A session ID (CONTEXT_SOFT, not causal)
  - A correlation ID (CONTEXT_SOFT, not causal)
  - A workflow token (CAUSAL_HARD, explicit prerequisite)
- Recognition must rely on: output-only + consumer reuse + semantic meaning of intermediate action

### 4. Application-Specific Semantics
- The field name `challenge` may not appear in hardcoded capability lists
- Must infer from structural behavior: output → immediate consumption with action that would naturally use it

## Labeled Relationships

| Relationship | Producer Obs | Consumer Obs | Expected Basis | Status |
|---|---|---|---|---|
| challenge → authorize | get_checkout | authorize_payment | CAPABILITY_ISSUED | expected |
| authorizationId → confirm | authorize_payment | confirm_payment | CAPABILITY_ISSUED | expected |
| nonce carried through | get_checkout | authorize_payment | CAPABILITY_ISSUED | expected |
| echo check (challenge not from req) | authorize_payment (req side) | authorize_payment (resp) | REQUEST_VALUE_ECHOED | forbidden |

## Validation

1. **Journey integrity**: All 3 operations should be in a single workflow component
2. **Ordering**: get_checkout → authorize_payment → confirm_payment
3. **Capability chain**: challenge is an intermediate; authorizationId is final
4. **Forbidden edges**: No cross-actor merging, no unrelated resource IDs

## Notes

- The first operation is a read (GET /checkout), but it produces a capability, so it is causal.
- The verify and confirm steps don't echo the challenge; it's new output.
- Authorization flow may have multiple tokens (challenge, authCode, sessionRef) all of which must be tracked.
