# Architecture

<!-- FINSEC-GENERATED:architecture:START -->
## Evidence Basis

- HAR-derived hosts and account labels are `OBSERVED`.
- Endpoint aggregation and resource names are `INFERRED`.
- Backend services, ownership, roles, and financial flows remain `NOT CONFIRMED`.

## Hosts

| Host | Evidence status |
|---|---|
| `juice-shop.local` | OBSERVED in HAR, OBSERVED in target configuration |

## Components

| Resource | Endpoints | Identifiers | Status |
|---|---:|---|---|
| Addresss | 3 | addresssId | INFERRED |
| ApplicationConfiguration | 1 | None observed | INFERRED |
| ApplicationVersion | 1 | None observed | INFERRED |
| Basket | 2 | basketId, paymentId | INFERRED |
| Basketitem | 2 | basketitemId | INFERRED |
| Card | 3 | cardId | INFERRED |
| Challenge | 1 | None observed | INFERRED |
| ChangePassword | 1 | None observed | INFERRED |
| Complaint | 1 | UserId | INFERRED |
| ContinueCode | 1 | None observed | INFERRED |
| Delivery | 2 | None observed | INFERRED |
| Feedback | 1 | None observed | INFERRED |
| File | 1 | None observed | INFERRED |
| FileUpload | 1 | None observed | INFERRED |
| Hint | 1 | None observed | INFERRED |
| Language | 1 | None observed | INFERRED |
| OrderHistory | 1 | None observed | INFERRED |
| Product | 4 | productId | INFERRED |
| Profile | 2 | None observed | INFERRED |
| Quantity | 1 | None observed | INFERRED |
| Saveloginip | 1 | None observed | INFERRED |
| Securityquestion | 1 | None observed | INFERRED |
| Socket.Io | 2 | None observed | INFERRED |
| TrackOrder | 1 | trackOrderId | INFERRED |
| Url | 1 | None observed | INFERRED |
| Wallet | 2 | paymentId | INFERRED |
| Whoami | 1 | None observed | INFERRED |

## Trust Boundaries

- Client to API host: 1 host(s) directly observed.
- Authentication context to endpoint: 56 endpoint(s) inferred to require it.
- Actor-to-object ownership and tenant boundaries: `NOT CONFIRMED`.
- Backend-to-bank, payment, KYC, queue, webhook, or settlement boundaries: `NOT CONFIRMED`.
<!-- FINSEC-GENERATED:architecture:END -->

## Researcher Notes
