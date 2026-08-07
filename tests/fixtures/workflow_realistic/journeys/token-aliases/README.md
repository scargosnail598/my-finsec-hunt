# Token Aliases Journey

## Scenario

A payment service uses different field names for the same semantic token across requests and responses. For example:
- Response field: `continuation`
- Request field: `sessionReference`
- Both carry the same logical workflow token

The challenge is recognizing they refer to the same capability despite name differences.

### Business Flow
1. **GET /auth/start** → Returns continuation token (new name)
2. **POST /auth/verify** → Accept sessionReference (alias name) → Returns verifyToken
3. **POST /auth/confirm** → Accept verifyToken → Complete

## Key Challenges for Reconstruction

### 1. Field Name Aliasing
- Same logical token appears with different names
- Recognition cannot rely on matching field names alone
- Must rely on: value fingerprint matching + temporal proximity + semantic role compatibility

### 2. Semantic Role Classification
- The field `continuation` may be classified with role: "WORKFLOW_TOKEN"
- The field `sessionReference` may be classified with different role or generic "SCALAR"
- Both must be recognized as the same token through value matching

### 3. Generic Names
- Field names like `reference`, `handle`, `ticket`, `receipt`, `intent` are all synonyms
- No enumerated list of aliases should be hard-coded
- Structural evidence (output-only, consumed, temporal) is the key

## Labeled Relationships

| Relationship | Producer Obs | Consumer Obs | Expected Basis | Status |
|---|---|---|---|---|
| continuation → sessionReference | start_auth | verify_auth | CAPABILITY_ISSUED | expected |
| verifyToken → confirm_auth | verify_auth | confirm_auth | CAPABILITY_ISSUED | expected |

## Validation

1. **Journey integrity**: All 3 operations in single component
2. **Alias handling**: continuation & sessionReference matched by value, not name
3. **Ordering**: start_auth → verify_auth → confirm_auth

## Notes

- This tests that generic semantic role classification, combined with value matching, can handle field name variations.
- Recognition of capabilities should NOT depend on field name vocabularies.
