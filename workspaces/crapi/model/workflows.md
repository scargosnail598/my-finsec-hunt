# Workflows

<!-- FINSEC-GENERATED:workflows:START -->
Operation maps are endpoint-derived. Lifecycle states and transition ordering are not inferred without direct evidence.

## Workflow: %F0%9F%91%A4

- Evidence status: `INFERRED`
- Identifiers: None observed
- Owner / tenant: unknown (`ASSUMED`)
- Operations:
  - `read` via `GET /%F0%9F%91%A4` (EP-001, INFERRED)
- Observed states: None
- Transition order: `NOT CONFIRMED`

## Workflow: %F0%9F%A4%96

- Evidence status: `INFERRED`
- Identifiers: None observed
- Owner / tenant: unknown (`ASSUMED`)
- Operations:
  - `read` via `GET /%F0%9F%A4%96` (EP-002, INFERRED)
- Observed states: None
- Transition order: `NOT CONFIRMED`

## Workflow: Auth

- Evidence status: `INFERRED`
- Identifiers: None observed
- Owner / tenant: unknown (`ASSUMED`)
- Operations:
  - `verify` via `POST /identity/api/auth/verify` (EP-017, INFERRED)
- Observed states: None
- Transition order: `NOT CONFIRMED`

## Workflow: Coupon

- Evidence status: `INFERRED`
- Identifiers: None observed
- Owner / tenant: unknown (`ASSUMED`)
- Operations:
  - `validate` via `POST /community/api/v2/coupon/validate-coupon` (EP-015, INFERRED)
- Observed states: None
- Transition order: `NOT CONFIRMED`

## Workflow: Dashboard

- Evidence status: `INFERRED`
- Identifiers: None observed
- Owner / tenant: unknown (`ASSUMED`)
- Operations:
  - `read` via `GET /identity/api/v2/user/dashboard` (EP-005, INFERRED)
- Observed states: None
- Transition order: `NOT CONFIRMED`

## Workflow: Email

- Evidence status: `INFERRED`
- Identifiers: None observed
- Owner / tenant: unknown (`ASSUMED`)
- Operations:
  - `resend` via `POST /identity/api/v2/vehicle/resend_email` (EP-063, INFERRED)
- Observed states: None
- Transition order: `NOT CONFIRMED`

## Workflow: Manifest.Json

- Evidence status: `INFERRED`
- Identifiers: None observed
- Owner / tenant: unknown (`ASSUMED`)
- Operations:
  - `read` via `GET /manifest.json` (EP-024, INFERRED)
- Observed states: None
- Transition order: `NOT CONFIRMED`

## Workflow: Mechanic

- Evidence status: `INFERRED`
- Identifiers: None observed
- Owner / tenant: unknown (`ASSUMED`)
- Operations:
  - `read` via `GET /workshop/api/mechanic` (EP-052, INFERRED)
  - `read` via `GET /workshop/api/mechanic/` (EP-053, INFERRED)
  - `contact` via `POST /workshop/api/merchant/contact_mechanic` (EP-065, INFERRED)
- Observed states: None
- Transition order: `NOT CONFIRMED`

## Workflow: MechanicReport

- Evidence status: `INFERRED`
- Identifiers: report_id
- Owner / tenant: unknown (`ASSUMED`)
- Operations:
  - `read` via `GET /workshop/api/mechanic/mechanic_report` (EP-054, INFERRED)
- Observed states: None
- Transition order: `NOT CONFIRMED`

## Workflow: Order

- Evidence status: `INFERRED`
- Identifiers: order_id
- Owner / tenant: unknown (`ASSUMED`)
- Operations:
  - `create` via `POST /workshop/api/shop/orders` (EP-020, INFERRED)
  - `all` via `GET /workshop/api/shop/orders/all` (EP-010, INFERRED)
  - `return` via `POST /workshop/api/shop/orders/return_order` (EP-021, INFERRED)
- Observed states: None
- Transition order: `NOT CONFIRMED`

## Workflow: PhoneNumber

- Evidence status: `INFERRED`
- Identifiers: None observed
- Owner / tenant: unknown (`ASSUMED`)
- Operations:
  - `change` via `POST /identity/api/v2/user/change-phone-number` (EP-018, INFERRED)
- Observed states: None
- Transition order: `NOT CONFIRMED`

## Workflow: Picture

- Evidence status: `INFERRED`
- Identifiers: None observed
- Owner / tenant: unknown (`ASSUMED`)
- Operations:
  - `create` via `POST /identity/api/v2/user/pictures` (EP-019, INFERRED)
- Observed states: None
- Transition order: `NOT CONFIRMED`

## Workflow: Post

- Evidence status: `INFERRED`
- Identifiers: postId
- Owner / tenant: unknown (`ASSUMED`)
- Operations:
  - `create` via `POST /community/api/v2/community/posts` (EP-013, INFERRED)
  - `recent` via `GET /community/api/v2/community/posts/recent` (EP-003, INFERRED)
  - `read` via `GET /community/api/v2/community/posts/{postId}` (EP-004, INFERRED)
  - `comment` via `POST /community/api/v2/community/posts/{postId}/comment` (EP-014, INFERRED)
- Observed states: None
- Transition order: `NOT CONFIRMED`

## Workflow: Product

- Evidence status: `INFERRED`
- Identifiers: None observed
- Owner / tenant: unknown (`ASSUMED`)
- Operations:
  - `read` via `GET /workshop/api/shop/products` (EP-011, INFERRED)
- Observed states: None
- Transition order: `NOT CONFIRMED`

## Workflow: ServiceReport

- Evidence status: `INFERRED`
- Identifiers: id
- Owner / tenant: unknown (`ASSUMED`)
- Operations:
  - `read` via `GET /service-report` (EP-048, INFERRED)
- Observed states: None
- Transition order: `NOT CONFIRMED`

## Workflow: ServiceRequest

- Evidence status: `INFERRED`
- Identifiers: serviceRequestId
- Owner / tenant: unknown (`ASSUMED`)
- Operations:
  - `read` via `GET /workshop/api/merchant/service_requests/{serviceRequestId}` (EP-067, INFERRED)
- Observed states: None
- Transition order: `NOT CONFIRMED`

## Workflow: Shop

- Evidence status: `INFERRED`
- Identifiers: None observed
- Owner / tenant: unknown (`ASSUMED`)
- Operations:
  - `read` via `GET /shop` (EP-049, INFERRED)
- Observed states: None
- Transition order: `NOT CONFIRMED`

## Workflow: State

- Evidence status: `INFERRED`
- Identifiers: None observed
- Owner / tenant: unknown (`ASSUMED`)
- Operations:
  - `read` via `GET /chatbot/genai/state` (EP-023, INFERRED)
- Observed states: None
- Transition order: `NOT CONFIRMED`

## Workflow: Vehicle

- Evidence status: `INFERRED`
- Identifiers: None observed
- Owner / tenant: unknown (`ASSUMED`)
- Operations:
  - `add` via `POST /identity/api/v2/vehicle/add_vehicle` (EP-062, INFERRED)
  - `read` via `GET /identity/api/v2/vehicle/vehicles` (EP-007, INFERRED)
- Observed states: None
- Transition order: `NOT CONFIRMED`

## Workflow: VehicleServiceDashboard

- Evidence status: `INFERRED`
- Identifiers: None observed
- Owner / tenant: unknown (`ASSUMED`)
- Operations:
  - `read` via `GET /vehicle-service-dashboard` (EP-051, INFERRED)
- Observed states: None
- Transition order: `NOT CONFIRMED`

## Workflow: Video

- Evidence status: `INFERRED`
- Identifiers: videoId
- Owner / tenant: unknown (`ASSUMED`)
- Operations:
  - `read` via `GET /identity/api/v2/user/videos/{videoId}` (EP-066, INFERRED)
- Observed states: None
- Transition order: `NOT CONFIRMED`
<!-- FINSEC-GENERATED:workflows:END -->

## Researcher Notes
