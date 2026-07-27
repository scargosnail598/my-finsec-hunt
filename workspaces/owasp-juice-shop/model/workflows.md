# Workflows

<!-- FINSEC-GENERATED:workflows:START -->
Operation maps are endpoint-derived. Lifecycle states and transition ordering are not inferred without direct evidence.

## Workflow: ApplicationConfiguration

- Evidence status: `INFERRED`
- Identifiers: None observed
- Owner / tenant: unknown (`ASSUMED`)
- Operations:
  - `read` via `GET /rest/admin/application-configuration` (EP-010, INFERRED)
- Observed states: None
- Transition order: `NOT CONFIRMED`

## Workflow: ApplicationVersion

- Evidence status: `INFERRED`
- Identifiers: None observed
- Owner / tenant: unknown (`ASSUMED`)
- Operations:
  - `read` via `GET /rest/admin/application-version` (EP-011, INFERRED)
- Observed states: None
- Transition order: `NOT CONFIRMED`

## Workflow: Basket

- Evidence status: `INFERRED`
- Identifiers: basketId
- Owner / tenant: unknown (`ASSUMED`)
- Operations:
  - `read` via `GET /rest/basket/{basketId}` (EP-012, INFERRED)
- Observed states: None
- Transition order: `NOT CONFIRMED`

## Workflow: Basketitem

- Evidence status: `INFERRED`
- Identifiers: None observed
- Owner / tenant: unknown (`ASSUMED`)
- Operations:
  - `create_or_execute` via `POST /api/BasketItems/` (EP-018, INFERRED)
- Observed states: None
- Transition order: `NOT CONFIRMED`

## Workflow: Challenge

- Evidence status: `INFERRED`
- Identifiers: None observed
- Owner / tenant: unknown (`ASSUMED`)
- Operations:
  - `read` via `GET /api/Challenges/` (EP-002, INFERRED)
- Observed states: None
- Transition order: `NOT CONFIRMED`

## Workflow: Language

- Evidence status: `INFERRED`
- Identifiers: None observed
- Owner / tenant: unknown (`ASSUMED`)
- Operations:
  - `read` via `GET /rest/languages` (EP-013, INFERRED)
- Observed states: None
- Transition order: `NOT CONFIRMED`

## Workflow: Product

- Evidence status: `INFERRED`
- Identifiers: productId
- Owner / tenant: unknown (`ASSUMED`)
- Operations:
  - `read` via `GET /api/Products/{productId}` (EP-003, INFERRED)
  - `search` via `GET /rest/products/search` (EP-014, INFERRED)
- Observed states: None
- Transition order: `NOT CONFIRMED`

## Workflow: Quantity

- Evidence status: `INFERRED`
- Identifiers: None observed
- Owner / tenant: unknown (`ASSUMED`)
- Operations:
  - `read` via `GET /api/Quantitys/` (EP-004, INFERRED)
- Observed states: None
- Transition order: `NOT CONFIRMED`

## Workflow: Socket.Io

- Evidence status: `INFERRED`
- Identifiers: None observed
- Owner / tenant: unknown (`ASSUMED`)
- Operations:
  - `read` via `GET /socket.io/` (EP-016, INFERRED)
  - `create_or_execute` via `POST /socket.io/` (EP-019, INFERRED)
- Observed states: None
- Transition order: `NOT CONFIRMED`

## Workflow: Whoami

- Evidence status: `INFERRED`
- Identifiers: None observed
- Owner / tenant: unknown (`ASSUMED`)
- Operations:
  - `read` via `GET /rest/user/whoami` (EP-015, INFERRED)
- Observed states: None
- Transition order: `NOT CONFIRMED`
<!-- FINSEC-GENERATED:workflows:END -->

## Researcher Notes
