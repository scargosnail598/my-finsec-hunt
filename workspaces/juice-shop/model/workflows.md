# Workflows

<!-- FINSEC-GENERATED:workflows:START -->
Operation maps are endpoint-derived. Lifecycle states and transition ordering are not inferred without direct evidence.

## Workflow: Addresss

- Evidence status: `INFERRED`
- Identifiers: addresssId
- Owner / tenant: unknown (`ASSUMED`)
- Operations:
  - `read` via `GET /api/Addresss` (EP-003, INFERRED)
  - `create` via `POST /api/Addresss/` (EP-044, INFERRED)
  - `read` via `GET /api/Addresss/{addresssId}` (EP-004, INFERRED)
- Observed states: None
- Transition order: `NOT CONFIRMED`

## Workflow: ApplicationConfiguration

- Evidence status: `INFERRED`
- Identifiers: None observed
- Owner / tenant: unknown (`ASSUMED`)
- Operations:
  - `read` via `GET /rest/admin/application-configuration` (EP-025, INFERRED)
- Observed states: None
- Transition order: `NOT CONFIRMED`

## Workflow: ApplicationVersion

- Evidence status: `INFERRED`
- Identifiers: None observed
- Owner / tenant: unknown (`ASSUMED`)
- Operations:
  - `read` via `GET /rest/admin/application-version` (EP-026, INFERRED)
- Observed states: None
- Transition order: `NOT CONFIRMED`

## Workflow: Basket

- Evidence status: `INFERRED`
- Identifiers: basketId, paymentId
- Owner / tenant: unknown (`ASSUMED`)
- Operations:
  - `read` via `GET /rest/basket/{basketId}` (EP-027, INFERRED)
  - `create_or_execute` via `POST /rest/basket/{basketId}/checkout` (EP-052, INFERRED)
- Observed states: None
- Transition order: `NOT CONFIRMED`

## Workflow: Basketitem

- Evidence status: `INFERRED`
- Identifiers: basketitemId
- Owner / tenant: unknown (`ASSUMED`)
- Operations:
  - `create` via `POST /api/BasketItems/` (EP-045, INFERRED)
  - `delete` via `DELETE /api/BasketItems/{basketitemId}` (EP-001, INFERRED)
- Observed states: None
- Transition order: `NOT CONFIRMED`

## Workflow: Card

- Evidence status: `INFERRED`
- Identifiers: cardId
- Owner / tenant: unknown (`ASSUMED`)
- Operations:
  - `read` via `GET /api/Cards` (EP-005, INFERRED)
  - `create` via `POST /api/Cards/` (EP-046, INFERRED)
  - `read` via `GET /api/Cards/{cardId}` (EP-006, INFERRED)
- Observed states: None
- Transition order: `NOT CONFIRMED`

## Workflow: Challenge

- Evidence status: `INFERRED`
- Identifiers: None observed
- Owner / tenant: unknown (`ASSUMED`)
- Operations:
  - `read` via `GET /api/Challenges/` (EP-007, INFERRED)
- Observed states: None
- Transition order: `NOT CONFIRMED`

## Workflow: Complaint

- Evidence status: `INFERRED`
- Identifiers: UserId
- Owner / tenant: unknown (`ASSUMED`)
- Operations:
  - `create` via `POST /api/Complaints/` (EP-047, INFERRED)
- Observed states: None
- Transition order: `NOT CONFIRMED`

## Workflow: ContinueCode

- Evidence status: `INFERRED`
- Identifiers: None observed
- Owner / tenant: unknown (`ASSUMED`)
- Operations:
  - `read` via `GET /rest/continue-code` (EP-028, INFERRED)
- Observed states: None
- Transition order: `NOT CONFIRMED`

## Workflow: Delivery

- Evidence status: `INFERRED`
- Identifiers: deliveryId
- Owner / tenant: unknown (`ASSUMED`)
- Operations:
  - `read` via `GET /api/Deliverys` (EP-008, INFERRED)
  - `read` via `GET /api/Deliverys/{deliveryId}` (EP-057, INFERRED)
- Observed states: None
- Transition order: `NOT CONFIRMED`

## Workflow: Feedback

- Evidence status: `INFERRED`
- Identifiers: None observed
- Owner / tenant: unknown (`ASSUMED`)
- Operations:
  - `read` via `GET /api/Feedbacks/` (EP-010, INFERRED)
- Observed states: None
- Transition order: `NOT CONFIRMED`

## Workflow: File

- Evidence status: `INFERRED`
- Identifiers: None observed
- Owner / tenant: unknown (`ASSUMED`)
- Operations:
  - `create_or_execute` via `POST /profile/image/file` (EP-050, INFERRED)
- Observed states: None
- Transition order: `NOT CONFIRMED`

## Workflow: FileUpload

- Evidence status: `INFERRED`
- Identifiers: None observed
- Owner / tenant: unknown (`ASSUMED`)
- Operations:
  - `create_or_execute` via `POST /file-upload` (EP-048, INFERRED)
- Observed states: None
- Transition order: `NOT CONFIRMED`

## Workflow: Hint

- Evidence status: `INFERRED`
- Identifiers: None observed
- Owner / tenant: unknown (`ASSUMED`)
- Operations:
  - `read` via `GET /api/Hints/` (EP-011, INFERRED)
- Observed states: None
- Transition order: `NOT CONFIRMED`

## Workflow: Language

- Evidence status: `INFERRED`
- Identifiers: None observed
- Owner / tenant: unknown (`ASSUMED`)
- Operations:
  - `read` via `GET /rest/languages` (EP-029, INFERRED)
- Observed states: None
- Transition order: `NOT CONFIRMED`

## Workflow: OrderHistory

- Evidence status: `INFERRED`
- Identifiers: None observed
- Owner / tenant: unknown (`ASSUMED`)
- Operations:
  - `history` via `GET /rest/order-history` (EP-030, INFERRED)
- Observed states: None
- Transition order: `NOT CONFIRMED`

## Workflow: Password

- Evidence status: `INFERRED`
- Identifiers: None observed
- Owner / tenant: unknown (`ASSUMED`)
- Operations:
  - `change` via `GET /rest/user/change-password` (EP-035, INFERRED)
- Observed states: None
- Transition order: `NOT CONFIRMED`

## Workflow: Product

- Evidence status: `INFERRED`
- Identifiers: productId
- Owner / tenant: unknown (`ASSUMED`)
- Operations:
  - `read` via `GET /api/Products/{productId}` (EP-012, INFERRED)
  - `search` via `GET /rest/products/search` (EP-031, INFERRED)
  - `read` via `GET /rest/products/{productId}/reviews` (EP-032, INFERRED)
  - `replace` via `PUT /rest/products/{productId}/reviews` (EP-055, INFERRED)
- Observed states: None
- Transition order: `NOT CONFIRMED`

## Workflow: Profile

- Evidence status: `INFERRED`
- Identifiers: None observed
- Owner / tenant: unknown (`ASSUMED`)
- Operations:
  - `read` via `GET /profile` (EP-024, INFERRED)
  - `create_or_execute` via `POST /profile` (EP-049, INFERRED)
- Observed states: None
- Transition order: `NOT CONFIRMED`

## Workflow: Quantity

- Evidence status: `INFERRED`
- Identifiers: None observed
- Owner / tenant: unknown (`ASSUMED`)
- Operations:
  - `read` via `GET /api/Quantitys/` (EP-013, INFERRED)
- Observed states: None
- Transition order: `NOT CONFIRMED`

## Workflow: Saveloginip

- Evidence status: `INFERRED`
- Identifiers: None observed
- Owner / tenant: unknown (`ASSUMED`)
- Operations:
  - `read` via `GET /rest/saveLoginIp` (EP-033, INFERRED)
- Observed states: None
- Transition order: `NOT CONFIRMED`

## Workflow: Securityquestion

- Evidence status: `INFERRED`
- Identifiers: None observed
- Owner / tenant: unknown (`ASSUMED`)
- Operations:
  - `read` via `GET /api/SecurityQuestions/` (EP-014, INFERRED)
- Observed states: None
- Transition order: `NOT CONFIRMED`

## Workflow: Socket.Io

- Evidence status: `INFERRED`
- Identifiers: None observed
- Owner / tenant: unknown (`ASSUMED`)
- Operations:
  - `read` via `GET /socket.io/` (EP-038, INFERRED)
  - `create_or_execute` via `POST /socket.io/` (EP-054, INFERRED)
- Observed states: None
- Transition order: `NOT CONFIRMED`

## Workflow: TrackOrder

- Evidence status: `INFERRED`
- Identifiers: trackOrderId
- Owner / tenant: unknown (`ASSUMED`)
- Operations:
  - `read` via `GET /rest/track-order/{trackOrderId}` (EP-034, INFERRED)
- Observed states: None
- Transition order: `NOT CONFIRMED`

## Workflow: Url

- Evidence status: `INFERRED`
- Identifiers: None observed
- Owner / tenant: unknown (`ASSUMED`)
- Operations:
  - `create_or_execute` via `POST /profile/image/url` (EP-051, INFERRED)
- Observed states: None
- Transition order: `NOT CONFIRMED`

## Workflow: Wallet

- Evidence status: `INFERRED`
- Identifiers: paymentId
- Owner / tenant: unknown (`ASSUMED`)
- Operations:
  - `read` via `GET /rest/wallet/balance` (EP-037, INFERRED)
  - `replace` via `PUT /rest/wallet/balance` (EP-056, INFERRED)
- Observed states: None
- Transition order: `NOT CONFIRMED`

## Workflow: Whoami

- Evidence status: `INFERRED`
- Identifiers: None observed
- Owner / tenant: unknown (`ASSUMED`)
- Operations:
  - `read` via `GET /rest/user/whoami` (EP-036, INFERRED)
- Observed states: None
- Transition order: `NOT CONFIRMED`
<!-- FINSEC-GENERATED:workflows:END -->

## Researcher Notes
