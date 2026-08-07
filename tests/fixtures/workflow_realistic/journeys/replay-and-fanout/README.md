# Replay and Fanout Journey

## Scenario

Tests legitimate multi-use of output values vs. suspicious replay. Includes:
1. One output consumed once (normal flow)
2. One output consumed multiple times in legitimate contexts (pagination, enumeration)
3. Repeated scalar values that are merely observational (status enums, timestamps)

### Business Flow (Legitimate)
1. **POST /search** → Returns searchId (distinctive token)
2. **POST /search/{searchId}/next** → Fetch next page (reuse searchId)
3. **POST /search/{searchId}/count** → Get count (reuse searchId)
4. **POST /search/{searchId}/close** → Clean up (reuse searchId)

Additional observations:
- `status=ACTIVE` appears in multiple unrelated resource responses (not a causal token)
- Timestamps repeat across multiple operations (not causally linked)

## Key Challenges for Reconstruction

### 1. Legitimate Multi-Use
- searchId appears in 4 operations sequentially
- NOT a replay attack; context determines each use is valid
- Must create edges for each operation (searchId → next, searchId → count, searchId → close)

### 2. Observational Repetition
- `status=ACTIVE` may appear in:
  - User object response
  - Account object response
  - Session object response
- Same enum value does NOT create workflow edges
- Must be distinguished from distinctive tokens

### 3. Idempotency Keys
- Idempotency-Key header repeated across retries
- Must not create causal edges

## Labeled Relationships

| Relationship | Producer Obs | Consumer Obs | Expected Basis | Status |
|---|---|---|---|---|
| searchId → next | create_search | next_page | CAPABILITY_ISSUED | expected |
| searchId → count | create_search | count_results | CAPABILITY_ISSUED | expected |
| searchId → close | create_search | close_search | CAPABILITY_ISSUED | expected |
| status=ACTIVE (user) | user_response | account_response | CONTEXT_SOFT | forbidden (generic enum) |
| status=ACTIVE (account) | account_response | session_response | CONTEXT_SOFT | forbidden (generic enum) |

## Validation

1. **Journey integrity**: All 4 search operations in single component
2. **Multi-use handling**: searchId creates 3 separate expected causal edges (→next, →count, →close)
3. **No false merges**: status=ACTIVE must not create cross-resource workflow edges
4. **Idempotency isolation**: Retries don't create new edges

## Notes

- This tests that distinctive tokens can be legitimately reused without triggering suspicious replay detection.
- Generic enum values must be isolated from distinctive workflow tokens.
- Temporal order and context (URL path vs body field) help disambiguate usage patterns.
