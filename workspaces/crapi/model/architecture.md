# Architecture

<!-- FINSEC-GENERATED:architecture:START -->
## Evidence Basis

- HAR-derived hosts and account labels are `OBSERVED`.
- Endpoint aggregation and resource names are `INFERRED`.
- Backend services, ownership, roles, and financial flows remain `NOT CONFIRMED`.

## Hosts

| Host | Evidence status |
|---|---|
| `crapi.local` | OBSERVED in HAR, OBSERVED in target configuration |
| `fonts.googleapis.com` | OBSERVED in HAR |
| `fonts.gstatic.com` | OBSERVED in HAR |
| `lh3.googleusercontent.com` | OBSERVED in HAR |
| `maps.google.com` | OBSERVED in HAR |
| `maps.googleapis.com` | OBSERVED in HAR |
| `maps.gstatic.com` | OBSERVED in HAR |
| `ogs.google.com` | OBSERVED in HAR |
| `play.google.com` | OBSERVED in HAR |
| `ssl.gstatic.com` | OBSERVED in HAR |
| `www.google.com` | OBSERVED in HAR |
| `www.gstatic.com` | OBSERVED in HAR |

## Components

| Resource | Endpoints | Identifiers | Status |
|---|---:|---|---|
| %F0%9F%91%A4 | 1 | None observed | INFERRED |
| %F0%9F%A4%96 | 1 | None observed | INFERRED |
| Auth | 1 | None observed | INFERRED |
| Coupon | 1 | None observed | INFERRED |
| Dashboard | 1 | None observed | INFERRED |
| Email | 1 | None observed | INFERRED |
| Manifest.Json | 1 | None observed | INFERRED |
| Mechanic | 3 | None observed | INFERRED |
| MechanicReport | 1 | report_id | INFERRED |
| Order | 3 | order_id | INFERRED |
| PhoneNumber | 1 | None observed | INFERRED |
| Picture | 1 | None observed | INFERRED |
| Post | 4 | postId | INFERRED |
| Product | 1 | None observed | INFERRED |
| ServiceReport | 1 | id | INFERRED |
| ServiceRequest | 1 | serviceRequestId | INFERRED |
| Shop | 1 | None observed | INFERRED |
| State | 1 | None observed | INFERRED |
| Vehicle | 2 | None observed | INFERRED |
| VehicleServiceDashboard | 1 | None observed | INFERRED |
| Video | 1 | videoId | INFERRED |

## Trust Boundaries

- Client to API host: 12 host(s) directly observed.
- Authentication context to endpoint: 27 endpoint(s) inferred to require it.
- Actor-to-object ownership and tenant boundaries: `NOT CONFIRMED`.
- Backend-to-bank, payment, KYC, queue, webhook, or settlement boundaries: `NOT CONFIRMED`.
<!-- FINSEC-GENERATED:architecture:END -->

## Researcher Notes
