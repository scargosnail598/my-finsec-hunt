# Adversarial Journey

## Purpose

This journey intentionally includes scenarios designed to tempt false merges or incorrect causal edges. It validates that the reconstruction engine maintains precision even when values coincidentally match or patterns suggest causality incorrectly.

## Scenario

A complex workflow with multiple independent transactions, interleaved operations, and coincidental value overlaps.

### Operations (Independent Workflows)

**Workflow 1: Order Fulfillment (Actor: CUSTOMER_A)**
1. POST /orders → orderId=ORDER-100, total=50.00
2. POST /shipments → shipmentId=SHIP-X, status=ACTIVE

**Workflow 2: Report Generation (Actor: CUSTOMER_A)**
1. POST /reports → reportId=100 (same numeric value!)
2. GET /reports/100/details → status=ACTIVE (same status!)

**Workflow 3: Payment Setup (Cross-Actor)**
1. Actor B: POST /payments → paymentId=PAY-501, status=ACTIVE
2. Actor A: POST /payments → paymentId=PAY-502, status=ACTIVE

**Workflow 4: Read-Before-Write (Actor: CUSTOMER_A)**
1. GET /accounts/ACC-500 → status=ACTIVE
2. POST /accounts/ACC-500/transfer

---

## Anti-Patterns Included

### 1. Coincidental Numeric Equality
```
POST /orders → total=50.00
POST /reports → total=50.00 (different semantics)
→ Must NOT create edge
```

### 2. Coincidental ID Equality
```
POST /orders → orderId=ORDER-100
GET /reports/100/details → reportId=100 (matching numeric part)
→ Must NOT create edge (different resource types)
```

### 3. Common Status Values
```
status=ACTIVE in order response
status=ACTIVE in report response
status=ACTIVE in payment response
→ Must NOT create cross-resource edges
→ May create CONTEXT_SOFT soft associations only
```

### 4. Read-Before-Write Pattern
```
GET /accounts/ACC-500 → Returns account
POST /accounts/ACC-500/transfer → Modifies account
→ Must NOT prove production
→ GET does NOT become a prerequisite
```

### 5. Cross-Actor Equality
```
Actor B: paymentId=PAY-501, status=ACTIVE
Actor A: paymentId=PAY-502, status=ACTIVE
→ Different actors, so separate workflows
→ status=ACTIVE match must not merge them
```

### 6. Echoed Identifiers
```
POST /orders with { orderId: "ORDER-100" } in request
→ Response echoes { orderId: "ORDER-100" }
→ Must be classified as REQUEST_VALUE_ECHOED
→ Not production (RESOURCE_CREATED)
```

## Labeled Relationships (Forbidden Edges)

| From Observation | To Observation | Reason | Status |
|---|---|---|---|
| post_order | post_report | coincidental numeric value (50) | forbidden |
| post_order | get_report_details | coincidental ID (100) | forbidden |
| post_shipment | post_report | common status=ACTIVE | forbidden |
| post_shipment | get_report_details | common status=ACTIVE | forbidden |
| get_account | post_transfer | read-before-write (not production) | forbidden |
| payment_user_b | payment_user_a | cross-actor equality in ID | forbidden (cross-actor) |
| get_account | post_payment | unrelated actors | forbidden (cross-actor) |

## Labeled Relationships (Expected Isolated)

| Observation | Expected Component | Notes |
|---|---|---|
| post_order, post_shipment | Workflow-1 | same actor, temporal order |
| post_report, get_report_details | Workflow-2 | same actor, explicit resource link |
| payment_user_b (paymentId) | Workflow-3a | isolated by actor |
| payment_user_a (paymentId) | Workflow-3b | different actor from 3a |
| get_account, post_transfer | Workflow-4 | same resource, same actor |

## Validation

1. **No forbidden edges**: All listed forbidden edges must NOT be created as CAUSAL_HARD
2. **Actor isolation**: paymentId from B must not merge with paymentId from A
3. **Numeric isolation**: total=50 and reportId=100 must not create cross-resource edges
4. **Read isolation**: GET must not establish production evidence
5. **Workflow separation**: 4+ independent workflow components expected

## Notes

- This is the **precision quality gate**.
- Any forbidden edge appearing as CAUSAL_HARD causes a test failure.
- False positives (forbidden merges) are more harmful than false negatives (missed edges).
