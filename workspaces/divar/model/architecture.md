# Architecture

<!-- FINSEC-GENERATED:architecture:START -->
## Evidence Basis

- HAR-derived hosts and account labels are `OBSERVED`.
- Endpoint aggregation and resource names are `INFERRED`.
- Backend services, ownership, roles, and financial flows remain `NOT CONFIRMED`.

## Hosts

| Host | Evidence status |
|---|---|
| `api.divar.ir` | OBSERVED in HAR, OBSERVED in target configuration |
| `app.733.ir` | OBSERVED in HAR |
| `divar.ir` | OBSERVED in HAR, OBSERVED in target configuration |
| `fonts.gstatic.com` | OBSERVED in HAR |
| `map.divar.ir` | OBSERVED in HAR |
| `map.divarcdn.com` | OBSERVED in HAR |
| `mapimage.divarcdn.com` | OBSERVED in HAR |
| `postimage01.divarcdn.com` | OBSERVED in HAR |
| `s100.divarcdn.com` | OBSERVED in HAR |
| `sentry.divar.cloud` | OBSERVED in HAR |
| `tiles.raah.ir` | OBSERVED in HAR |
| `touch.radif.ai` | OBSERVED in HAR |
| `trustseal.enamad.ir` | OBSERVED in HAR |
| `www.google.com` | OBSERVED in HAR |
| `www.googleadservices.com` | OBSERVED in HAR |
| `www.gstatic.com` | OBSERVED in HAR |

## Components

| Resource | Endpoints | Identifiers | Status |
|---|---:|---|---|
| AuthenticationCode | 2 | None observed | INFERRED |
| FpStore | 2 | None observed | INFERRED |
| GetSearchBarEmptyState | 2 | None observed | INFERRED |
| Manifest.Json | 1 | None observed | INFERRED |
| Mapview | 2 | None observed | INFERRED |
| OpenInitiatePage | 2 | None observed | INFERRED |
| PostCollection | 2 | None observed | INFERRED |
| Postlist | 6 | None observed | INFERRED |
| ReceivePostStatsBatch | 2 | None observed | INFERRED |
| ShouldStoreFp | 2 | None observed | INFERRED |
| UnactedBundleCount | 2 | None observed | INFERRED |
| Unread | 2 | None observed | INFERRED |
| UserRegistrationPage | 2 | None observed | INFERRED |
| UserVerification | 2 | None observed | INFERRED |
| V8 | 2 | v8Id | INFERRED |
| Wallet | 7 | None observed | INFERRED |
| Web | 2 | None observed | INFERRED |

## Trust Boundaries

- Client to API host: 16 host(s) directly observed.
- Authentication context to endpoint: 0 endpoint(s) inferred to require it.
- Actor-to-object ownership and tenant boundaries: `NOT CONFIRMED`.
- Backend-to-bank, payment, KYC, queue, webhook, or settlement boundaries: `NOT CONFIRMED`.
<!-- FINSEC-GENERATED:architecture:END -->

## Researcher Notes
