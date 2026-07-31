# Workflows

<!-- FINSEC-GENERATED:workflows:START -->
Operation maps are endpoint-derived. Lifecycle states and transition ordering are not inferred without direct evidence.

## Workflow: Addresss

- Evidence status: `INFERRED`
- Identifiers: addresssId
- Owner / tenant: unknown (`ASSUMED`)
- Operations:
  - `read` via `GET /api/Addresss` (EP-002, INFERRED)
  - `create_or_execute` via `POST /api/Addresss/` (EP-047, INFERRED)
  - `read` via `GET /api/Addresss/{addresssId}` (EP-003, INFERRED)
  - `replace` via `PUT /api/Addresss/{addresssId}` (EP-037, INFERRED)
- Observed states: None
- Transition order: `NOT CONFIRMED`

## Workflow: ApplicationConfiguration

- Evidence status: `INFERRED`
- Identifiers: None observed
- Owner / tenant: unknown (`ASSUMED`)
- Operations:
  - `read` via `GET /rest/admin/application-configuration` (EP-018, INFERRED)
- Observed states: None
- Transition order: `NOT CONFIRMED`

## Workflow: ApplicationVersion

- Evidence status: `INFERRED`
- Identifiers: None observed
- Owner / tenant: unknown (`ASSUMED`)
- Operations:
  - `read` via `GET /rest/admin/application-version` (EP-019, INFERRED)
- Observed states: None
- Transition order: `NOT CONFIRMED`

## Workflow: Basket

- Evidence status: `INFERRED`
- Identifiers: basketId, paymentId
- Owner / tenant: unknown (`ASSUMED`)
- Operations:
  - `read` via `GET /rest/basket/{basketId}` (EP-020, INFERRED)
  - `create_or_execute` via `POST /rest/basket/{basketId}/checkout` (EP-034, INFERRED)
- Observed states: None
- Transition order: `NOT CONFIRMED`

## Workflow: Basketitem

- Evidence status: `INFERRED`
- Identifiers: basketitemId
- Owner / tenant: unknown (`ASSUMED`)
- Operations:
  - `create_or_execute` via `POST /api/BasketItems/` (EP-033, INFERRED)
  - `read` via `GET /api/BasketItems/{basketitemId}` (EP-038, INFERRED)
  - `replace` via `PUT /api/BasketItems/{basketitemId}` (EP-052, INFERRED)
- Observed states: None
- Transition order: `NOT CONFIRMED`

## Workflow: Card

- Evidence status: `INFERRED`
- Identifiers: cardId
- Owner / tenant: unknown (`ASSUMED`)
- Operations:
  - `read` via `GET /api/Cards` (EP-004, INFERRED)
  - `create_or_execute` via `POST /api/Cards/` (EP-048, INFERRED)
  - `read` via `GET /api/Cards/{cardId}` (EP-039, INFERRED)
- Observed states: None
- Transition order: `NOT CONFIRMED`

## Workflow: Challenge

- Evidence status: `INFERRED`
- Identifiers: None observed
- Owner / tenant: unknown (`ASSUMED`)
- Operations:
  - `read` via `GET /api/Challenges/` (EP-005, INFERRED)
- Observed states: None
- Transition order: `NOT CONFIRMED`

## Workflow: ChangePassword

- Evidence status: `INFERRED`
- Identifiers: None observed
- Owner / tenant: unknown (`ASSUMED`)
- Operations:
  - `change` via `GET /rest/user/change-password` (EP-046, INFERRED)
- Observed states: None
- Transition order: `NOT CONFIRMED`

## Workflow: Delivery

- Evidence status: `INFERRED`
- Identifiers: deliveryId
- Owner / tenant: unknown (`ASSUMED`)
- Operations:
  - `read` via `GET /api/Deliverys` (EP-006, INFERRED)
  - `read` via `GET /api/Deliverys/{deliveryId}` (EP-040, INFERRED)
- Observed states: None
- Transition order: `NOT CONFIRMED`

## Workflow: Language

- Evidence status: `INFERRED`
- Identifiers: None observed
- Owner / tenant: unknown (`ASSUMED`)
- Operations:
  - `read` via `GET /rest/languages` (EP-021, INFERRED)
- Observed states: None
- Transition order: `NOT CONFIRMED`

## Workflow: OrderHistory

- Evidence status: `INFERRED`
- Identifiers: None observed
- Owner / tenant: unknown (`ASSUMED`)
- Operations:
  - `history` via `GET /rest/order-history` (EP-022, INFERRED)
- Observed states: None
- Transition order: `NOT CONFIRMED`

## Workflow: Product

- Evidence status: `INFERRED`
- Identifiers: productId
- Owner / tenant: unknown (`ASSUMED`)
- Operations:
  - `read` via `GET /api/Products/{productId}` (EP-008, INFERRED)
  - `search` via `GET /rest/products/search` (EP-023, INFERRED)
- Observed states: None
- Transition order: `NOT CONFIRMED`

## Workflow: Profile

- Evidence status: `INFERRED`
- Identifiers: None observed
- Owner / tenant: unknown (`ASSUMED`)
- Operations:
  - `read` via `GET /profile` (EP-017, INFERRED)
  - `create_or_execute` via `POST /profile` (EP-051, INFERRED)
- Observed states: None
- Transition order: `NOT CONFIRMED`

## Workflow: Quantity

- Evidence status: `INFERRED`
- Identifiers: None observed
- Owner / tenant: unknown (`ASSUMED`)
- Operations:
  - `read` via `GET /api/Quantitys/` (EP-009, INFERRED)
- Observed states: None
- Transition order: `NOT CONFIRMED`

## Workflow: Recycle

- Evidence status: `INFERRED`
- Identifiers: None observed
- Owner / tenant: unknown (`ASSUMED`)
- Operations:
  - `read` via `GET /api/Recycles/` (EP-041, INFERRED)
- Observed states: None
- Transition order: `NOT CONFIRMED`

## Workflow: Review

- Evidence status: `INFERRED`
- Identifiers: None observed
- Owner / tenant: unknown (`ASSUMED`)
- Operations:
  - `read` via `GET /rest/products/42/reviews` (EP-044, INFERRED)
- Observed states: None
- Transition order: `NOT CONFIRMED`

## Workflow: Saveloginip

- Evidence status: `INFERRED`
- Identifiers: None observed
- Owner / tenant: unknown (`ASSUMED`)
- Operations:
  - `read` via `GET /rest/saveLoginIp` (EP-045, INFERRED)
- Observed states: None
- Transition order: `NOT CONFIRMED`

## Workflow: Securityanswer

- Evidence status: `INFERRED`
- Identifiers: UserId
- Owner / tenant: unknown (`ASSUMED`)
- Operations:
  - `create_or_execute` via `POST /api/SecurityAnswers/` (EP-049, INFERRED)
- Observed states: None
- Transition order: `NOT CONFIRMED`

## Workflow: Securityquestion

- Evidence status: `INFERRED`
- Identifiers: None observed
- Owner / tenant: unknown (`ASSUMED`)
- Operations:
  - `read` via `GET /api/SecurityQuestions/` (EP-042, INFERRED)
- Observed states: None
- Transition order: `NOT CONFIRMED`

## Workflow: Socket.Io

- Evidence status: `INFERRED`
- Identifiers: None observed
- Owner / tenant: unknown (`ASSUMED`)
- Operations:
  - `read` via `GET /socket.io/` (EP-027, INFERRED)
  - `create_or_execute` via `POST /socket.io/` (EP-036, INFERRED)
- Observed states: None
- Transition order: `NOT CONFIRMED`

## Workflow: TrackOrder

- Evidence status: `INFERRED`
- Identifiers: trackOrderId
- Owner / tenant: unknown (`ASSUMED`)
- Operations:
  - `read` via `GET /rest/track-order/{trackOrderId}` (EP-024, INFERRED)
- Observed states: None
- Transition order: `NOT CONFIRMED`

## Workflow: User

- Evidence status: `INFERRED`
- Identifiers: id
- Owner / tenant: unknown (`ASSUMED`)
- Operations:
  - `create_or_execute` via `POST /api/Users/` (EP-050, INFERRED)
- Observed states: None
- Transition order: `NOT CONFIRMED`

## Workflow: Wallet

- Evidence status: `INFERRED`
- Identifiers: paymentId
- Owner / tenant: unknown (`ASSUMED`)
- Operations:
  - `read` via `GET /rest/wallet/balance` (EP-026, INFERRED)
  - `replace` via `PUT /rest/wallet/balance` (EP-053, INFERRED)
- Observed states: None
- Transition order: `NOT CONFIRMED`

## Workflow: Whoami

- Evidence status: `INFERRED`
- Identifiers: None observed
- Owner / tenant: unknown (`ASSUMED`)
- Operations:
  - `read` via `GET /rest/user/whoami` (EP-025, INFERRED)
- Observed states: None
- Transition order: `NOT CONFIRMED`
<!-- FINSEC-GENERATED:workflows:END -->

## Researcher Notes
