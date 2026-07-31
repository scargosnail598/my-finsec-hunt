# Authorization Model

<!-- FINSEC-GENERATED:authorization:START -->
## Endpoint Authorization View

Authentication presence does not prove object or function authorization.

| Endpoint | Operation | Resource | Authentication | Observed actors | Ownership/role condition |
|---|---|---|---|---|---|
| EP-001 | `GET /` | Unknown | Required (`cookie`, INFERRED) | mrscargo, saeedmehmandoust | NOT CONFIRMED |
| EP-002 | `GET /api/Addresss` | Addresss | Required (`mixed`, INFERRED) | mrscargo, saeedmehmandoust | NOT CONFIRMED |
| EP-003 | `GET /api/Addresss/{addresssId}` | Addresss | Required (`mixed`, INFERRED) | mrscargo, saeedmehmandoust | NOT CONFIRMED |
| EP-038 | `GET /api/BasketItems/{basketitemId}` | Basketitem | Required (`mixed`, INFERRED) | saeedmehmandoust | NOT CONFIRMED |
| EP-004 | `GET /api/Cards` | Card | Required (`mixed`, INFERRED) | mrscargo, saeedmehmandoust | NOT CONFIRMED |
| EP-039 | `GET /api/Cards/{cardId}` | Card | Required (`mixed`, INFERRED) | mrscargo, saeedmehmandoust | NOT CONFIRMED |
| EP-005 | `GET /api/Challenges/` | Challenge | Required (`mixed`, INFERRED) | mrscargo, saeedmehmandoust | NOT CONFIRMED |
| EP-006 | `GET /api/Deliverys` | Delivery | Required (`mixed`, INFERRED) | mrscargo, saeedmehmandoust | NOT CONFIRMED |
| EP-040 | `GET /api/Deliverys/{deliveryId}` | Delivery | Required (`mixed`, INFERRED) | mrscargo, saeedmehmandoust | NOT CONFIRMED |
| EP-008 | `GET /api/Products/{productId}` | Product | Required (`mixed`, INFERRED) | mrscargo, saeedmehmandoust | NOT CONFIRMED |
| EP-009 | `GET /api/Quantitys/` | Quantity | Required (`mixed`, INFERRED) | mrscargo, saeedmehmandoust | NOT CONFIRMED |
| EP-041 | `GET /api/Recycles/` | Recycle | Required (`mixed`, INFERRED) | saeedmehmandoust | NOT CONFIRMED |
| EP-042 | `GET /api/SecurityQuestions/` | Securityquestion | Required (`cookie`, INFERRED) | saeedmehmandoust | NOT CONFIRMED |
| EP-017 | `GET /profile` | Profile | Required (`cookie`, INFERRED) | mrscargo, saeedmehmandoust | NOT CONFIRMED |
| EP-018 | `GET /rest/admin/application-configuration` | ApplicationConfiguration | Required (`mixed`, INFERRED) | mrscargo, saeedmehmandoust | NOT CONFIRMED |
| EP-019 | `GET /rest/admin/application-version` | ApplicationVersion | Required (`mixed`, INFERRED) | mrscargo, saeedmehmandoust | NOT CONFIRMED |
| EP-020 | `GET /rest/basket/{basketId}` | Basket | Required (`mixed`, INFERRED) | mrscargo, saeedmehmandoust | NOT CONFIRMED |
| EP-021 | `GET /rest/languages` | Language | Required (`mixed`, INFERRED) | mrscargo, saeedmehmandoust | NOT CONFIRMED |
| EP-022 | `GET /rest/order-history` | OrderHistory | Required (`mixed`, INFERRED) | mrscargo, saeedmehmandoust | NOT CONFIRMED |
| EP-044 | `GET /rest/products/42/reviews` | Review | Required (`mixed`, INFERRED) | saeedmehmandoust | NOT CONFIRMED |
| EP-023 | `GET /rest/products/search` | Product | Required (`mixed`, INFERRED) | mrscargo, saeedmehmandoust | NOT CONFIRMED |
| EP-045 | `GET /rest/saveLoginIp` | Saveloginip | Required (`mixed`, INFERRED) | mrscargo | NOT CONFIRMED |
| EP-024 | `GET /rest/track-order/{trackOrderId}` | TrackOrder | Required (`mixed`, INFERRED) | mrscargo, saeedmehmandoust | NOT CONFIRMED |
| EP-046 | `GET /rest/user/change-password` | ChangePassword | Required (`mixed`, INFERRED) | saeedmehmandoust | NOT CONFIRMED |
| EP-025 | `GET /rest/user/whoami` | Whoami | Required (`mixed`, INFERRED) | mrscargo, saeedmehmandoust | NOT CONFIRMED |
| EP-026 | `GET /rest/wallet/balance` | Wallet | Required (`mixed`, INFERRED) | mrscargo, saeedmehmandoust | NOT CONFIRMED |
| EP-027 | `GET /socket.io/` | Socket.Io | Required (`cookie`, INFERRED) | mrscargo, saeedmehmandoust | NOT CONFIRMED |
| EP-047 | `POST /api/Addresss/` | Addresss | Required (`mixed`, INFERRED) | saeedmehmandoust | NOT CONFIRMED |
| EP-033 | `POST /api/BasketItems/` | Basketitem | Required (`mixed`, INFERRED) | mrscargo, saeedmehmandoust | NOT CONFIRMED |
| EP-048 | `POST /api/Cards/` | Card | Required (`mixed`, INFERRED) | saeedmehmandoust | NOT CONFIRMED |
| EP-049 | `POST /api/SecurityAnswers/` | Securityanswer | Required (`cookie`, INFERRED) | saeedmehmandoust | NOT CONFIRMED |
| EP-050 | `POST /api/Users/` | User | Required (`cookie`, INFERRED) | saeedmehmandoust | NOT CONFIRMED |
| EP-051 | `POST /profile` | Profile | Required (`cookie`, INFERRED) | saeedmehmandoust | NOT CONFIRMED |
| EP-034 | `POST /rest/basket/{basketId}/checkout` | Basket | Required (`mixed`, INFERRED) | mrscargo, saeedmehmandoust | NOT CONFIRMED |
| EP-035 | `POST /rest/user/login` | Login | Required (`cookie`, INFERRED) | mrscargo, saeedmehmandoust | NOT CONFIRMED |
| EP-036 | `POST /socket.io/` | Socket.Io | Required (`cookie`, INFERRED) | mrscargo, saeedmehmandoust | NOT CONFIRMED |
| EP-037 | `PUT /api/Addresss/{addresssId}` | Addresss | Required (`mixed`, INFERRED) | mrscargo, saeedmehmandoust | NOT CONFIRMED |
| EP-052 | `PUT /api/BasketItems/{basketitemId}` | Basketitem | Required (`mixed`, INFERRED) | saeedmehmandoust | NOT CONFIRMED |
| EP-053 | `PUT /rest/wallet/balance` | Wallet | Required (`mixed`, INFERRED) | mrscargo, saeedmehmandoust | NOT CONFIRMED |
<!-- FINSEC-GENERATED:authorization:END -->

## Researcher Notes
