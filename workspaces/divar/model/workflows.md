# Workflows

<!-- FINSEC-GENERATED:workflows:START -->
Operation maps are endpoint-derived. Lifecycle states and transition ordering are not inferred without direct evidence.

## Workflow: AuthenticationCode

- Evidence status: `INFERRED`
- Identifiers: None observed
- Owner / tenant: unknown (`ASSUMED`)
- Operations:
  - `consume` via `OPTIONS /v8/authenticate/signinup/code/consume` (EP-067, INFERRED)
  - `consume` via `POST /v8/authenticate/signinup/code/consume` (EP-092, INFERRED)
- Observed states: None
- Transition order: `NOT CONFIRMED`

## Workflow: FpStore

- Evidence status: `INFERRED`
- Identifiers: None observed
- Owner / tenant: unknown (`ASSUMED`)
- Operations:
  - `read` via `OPTIONS /v8/users/fp-store` (EP-079, INFERRED)
  - `create_or_execute` via `POST /v8/users/fp-store` (EP-103, INFERRED)
- Observed states: None
- Transition order: `NOT CONFIRMED`

## Workflow: GetSearchBarEmptyState

- Evidence status: `INFERRED`
- Identifiers: None observed
- Owner / tenant: unknown (`ASSUMED`)
- Operations:
  - `search` via `OPTIONS /v8/search-bookmark/web/get-search-bar-empty-state` (EP-077, INFERRED)
  - `search` via `POST /v8/search-bookmark/web/get-search-bar-empty-state` (EP-101, INFERRED)
- Observed states: None
- Transition order: `NOT CONFIRMED`

## Workflow: Manifest.Json

- Evidence status: `INFERRED`
- Identifiers: None observed
- Owner / tenant: unknown (`ASSUMED`)
- Operations:
  - `read` via `GET /manifest.json` (EP-009, INFERRED)
- Observed states: None
- Transition order: `NOT CONFIRMED`

## Workflow: Mapview

- Evidence status: `INFERRED`
- Identifiers: None observed
- Owner / tenant: unknown (`ASSUMED`)
- Operations:
  - `viewport` via `OPTIONS /v8/mapview/viewport` (EP-069, INFERRED)
  - `viewport` via `POST /v8/mapview/viewport` (EP-093, INFERRED)
- Observed states: None
- Transition order: `NOT CONFIRMED`

## Workflow: OpenInitiatePage

- Evidence status: `INFERRED`
- Identifiers: None observed
- Owner / tenant: unknown (`ASSUMED`)
- Operations:
  - `page` via `OPTIONS /v8/auth/open-initiate-page` (EP-066, INFERRED)
  - `page` via `POST /v8/auth/open-initiate-page` (EP-091, INFERRED)
- Observed states: None
- Transition order: `NOT CONFIRMED`

## Workflow: PostCollection

- Evidence status: `INFERRED`
- Identifiers: None observed
- Owner / tenant: unknown (`ASSUMED`)
- Operations:
  - `list` via `OPTIONS /v8/my-posts/w/list` (EP-071, INFERRED)
  - `list` via `POST /v8/my-posts/w/list` (EP-095, INFERRED)
- Observed states: None
- Transition order: `NOT CONFIRMED`

## Workflow: Postlist

- Evidence status: `INFERRED`
- Identifiers: None observed
- Owner / tenant: unknown (`ASSUMED`)
- Operations:
  - `filters` via `OPTIONS /v8/postlist/w/filters` (EP-073, INFERRED)
  - `filters` via `POST /v8/postlist/w/filters` (EP-097, INFERRED)
  - `places` via `OPTIONS /v8/postlist/w/places` (EP-074, INFERRED)
  - `places` via `POST /v8/postlist/w/places` (EP-098, INFERRED)
  - `search` via `OPTIONS /v8/postlist/w/search` (EP-075, INFERRED)
  - `search` via `POST /v8/postlist/w/search` (EP-099, INFERRED)
- Observed states: None
- Transition order: `NOT CONFIRMED`

## Workflow: ReceivePostStatsBatch

- Evidence status: `INFERRED`
- Identifiers: None observed
- Owner / tenant: unknown (`ASSUMED`)
- Operations:
  - `read` via `OPTIONS /v8/post-stats/receive-post-stats-batch` (EP-072, INFERRED)
  - `create_or_execute` via `POST /v8/post-stats/receive-post-stats-batch` (EP-096, INFERRED)
- Observed states: None
- Transition order: `NOT CONFIRMED`

## Workflow: ShouldStoreFp

- Evidence status: `INFERRED`
- Identifiers: None observed
- Owner / tenant: unknown (`ASSUMED`)
- Operations:
  - `read` via `OPTIONS /v8/users/should-store-fp` (EP-080, INFERRED)
  - `create_or_execute` via `POST /v8/users/should-store-fp` (EP-104, INFERRED)
- Observed states: None
- Transition order: `NOT CONFIRMED`

## Workflow: UnactedBundleCount

- Evidence status: `INFERRED`
- Identifiers: None observed
- Owner / tenant: unknown (`ASSUMED`)
- Operations:
  - `history` via `GET /v8/call/call-history/unacted-bundle-count` (EP-054, INFERRED)
  - `history` via `OPTIONS /v8/call/call-history/unacted-bundle-count` (EP-068, INFERRED)
- Observed states: None
- Transition order: `NOT CONFIRMED`

## Workflow: Unread

- Evidence status: `INFERRED`
- Identifiers: None observed
- Owner / tenant: unknown (`ASSUMED`)
- Operations:
  - `read` via `OPTIONS /chat/api/unread` (EP-065, INFERRED)
  - `create_or_execute` via `POST /chat/api/unread` (EP-087, INFERRED)
- Observed states: None
- Transition order: `NOT CONFIRMED`

## Workflow: UserRegistrationPage

- Evidence status: `INFERRED`
- Identifiers: None observed
- Owner / tenant: unknown (`ASSUMED`)
- Operations:
  - `page` via `OPTIONS /v8/premium-user/user-registration-page` (EP-076, INFERRED)
  - `page` via `POST /v8/premium-user/user-registration-page` (EP-100, INFERRED)
- Observed states: None
- Transition order: `NOT CONFIRMED`

## Workflow: UserVerification

- Evidence status: `INFERRED`
- Identifiers: None observed
- Owner / tenant: unknown (`ASSUMED`)
- Operations:
  - `read` via `OPTIONS /v8/user-profile/user_verification` (EP-078, INFERRED)
  - `create_or_execute` via `POST /v8/user-profile/user_verification` (EP-102, INFERRED)
- Observed states: None
- Transition order: `NOT CONFIRMED`

## Workflow: V8

- Evidence status: `INFERRED`
- Identifiers: v8Id
- Owner / tenant: unknown (`ASSUMED`)
- Operations:
  - `read` via `GET /v8/{v8Id}/web/gahoUVea` (EP-056, INFERRED)
  - `read` via `OPTIONS /v8/{v8Id}/web/gahoUVea` (EP-084, INFERRED)
- Observed states: None
- Transition order: `NOT CONFIRMED`

## Workflow: Wallet

- Evidence status: `INFERRED`
- Identifiers: None observed
- Owner / tenant: unknown (`ASSUMED`)
- Operations:
  - `read` via `GET /my-divar/wallet-and-payments` (EP-010, INFERRED)
  - `page` via `OPTIONS /v8/wallet/change-wallet-page` (EP-081, INFERRED)
  - `page` via `POST /v8/wallet/change-wallet-page` (EP-105, INFERRED)
  - `change` via `OPTIONS /v8/wallet/change-wallet/ASAN_PARDAKHT` (EP-082, INFERRED)
  - `change` via `POST /v8/wallet/change-wallet/ASAN_PARDAKHT` (EP-106, INFERRED)
  - `read` via `OPTIONS /v8/wallet/wallet-and-payments` (EP-083, INFERRED)
  - `create_or_execute` via `POST /v8/wallet/wallet-and-payments` (EP-107, INFERRED)
- Observed states: None
- Transition order: `NOT CONFIRMED`

## Workflow: Web

- Evidence status: `INFERRED`
- Identifiers: None observed
- Owner / tenant: unknown (`ASSUMED`)
- Operations:
  - `menu` via `OPTIONS /v8/my-divar/web/menu` (EP-070, INFERRED)
  - `menu` via `POST /v8/my-divar/web/menu` (EP-094, INFERRED)
- Observed states: None
- Transition order: `NOT CONFIRMED`
<!-- FINSEC-GENERATED:workflows:END -->

## Researcher Notes
