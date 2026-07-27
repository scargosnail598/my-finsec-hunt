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
| ApplicationConfiguration | 1 | None observed | INFERRED |
| ApplicationVersion | 1 | None observed | INFERRED |
| Basket | 1 | basketId | INFERRED |
| Basketitem | 1 | None observed | INFERRED |
| Challenge | 1 | None observed | INFERRED |
| Language | 1 | None observed | INFERRED |
| Product | 2 | productId | INFERRED |
| Quantity | 1 | None observed | INFERRED |
| Socket.Io | 2 | None observed | INFERRED |
| Whoami | 1 | None observed | INFERRED |

## Trust Boundaries

- Client to API host: 1 host(s) directly observed.
- Authentication context to endpoint: 0 endpoint(s) inferred to require it.
- Actor-to-object ownership and tenant boundaries: `NOT CONFIRMED`.
- Backend-to-bank, payment, KYC, queue, webhook, or settlement boundaries: `NOT CONFIRMED`.
<!-- FINSEC-GENERATED:architecture:END -->

## Researcher Notes
