# Nested Resource Journey

## Scenario

A user manages multiple orders within an account, and each order can have multiple line items. The nested resource structure is:
- `/accounts/{accountId}/orders` → orderId
- `/accounts/{accountId}/orders/{orderId}/items` → itemId

### Business Flow
1. **POST /accounts/{accountId}/orders** → Creates orderId
2. **POST /accounts/{accountId}/orders/{orderId}/items** → Creates itemId
3. **POST /accounts/{accountId}/orders/{orderId}/items/{itemId}/confirm** → Confirms item

## Key Challenges for Reconstruction

### 1. Multi-Level Resource Hierarchy
- Reconstruction must understand that itemId depends on orderId contextually
- Path parameters create implicit resource relationships
- Must not assume accountId is a prerequisite for orderId (accountId may be scope, not producer)

### 2. Contextual Resource Propagation
- itemId must link to orderId even if orderId is not explicitly in the create_item request body
- orderId must link to accountId only as scope context, not prerequisite
- Path params are inferred from the operation context

### 3. Prerequisite vs Scope Distinction
- accountId: **scope** (constrains which items can be accessed, but not a prerequisite for workflow causality)
- orderId: **prerequisite** (must be created before items can be added)
- itemId: **created resource** (new output)

## Labeled Relationships

| Relationship | Producer Obs | Consumer Obs | Expected Basis | Status |
|---|---|---|---|---|
| orderId creation | create_order | create_item | RESOURCE_CREATED | expected |
| itemId creation | create_item | confirm_item | RESOURCE_CREATED | expected |
| accountId scope | create_order | create_item | AMBIGUOUS_ORIGIN | forbidden (scope, not causal) |
| accountId scope | create_order | confirm_item | AMBIGUOUS_ORIGIN | forbidden (scope, not causal) |

## Validation

1. **Journey integrity**: All 3 operations in a single workflow component
2. **Ordering**: create_order → create_item → confirm_item
3. **Resource lineage**: orderId → itemId chain
4. **Scope handling**: accountId must not be treated as a prerequisite

## Notes

- This tests that scope parameters (path parameters used for authorization) are not confused with causal prerequisites.
- Nested paths are common in REST APIs; the engine must handle hierarchy without false prerequisites.
