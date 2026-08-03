# Authorization Model

<!-- FINSEC-GENERATED:authorization:START -->
## Endpoint Authorization View

Authentication presence does not prove object or function authorization.

| Endpoint | Operation | Resource | Authentication | Observed actors | Ownership/role condition |
|---|---|---|---|---|---|
| EP-001 | `DELETE /api/BasketItems/{basketitemId}` | Basketitem | Required (`mixed`, INFERRED) | mrscargo, saeedmehmandoust | NOT CONFIRMED |
| EP-002 | `GET /` | Unknown | Required (`cookie`, INFERRED) | mrscargo, saeedmehmandoust | NOT CONFIRMED |
| EP-003 | `GET /api/Addresss` | Addresss | Required (`mixed`, INFERRED) | mrscargo, saeedmehmandoust | NOT CONFIRMED |
| EP-004 | `GET /api/Addresss/{addresssId}` | Addresss | Required (`mixed`, INFERRED) | mrscargo, saeedmehmandoust | NOT CONFIRMED |
| EP-005 | `GET /api/Cards` | Card | Required (`mixed`, INFERRED) | mrscargo, saeedmehmandoust | NOT CONFIRMED |
| EP-006 | `GET /api/Cards/{cardId}` | Card | Required (`mixed`, INFERRED) | mrscargo, saeedmehmandoust | NOT CONFIRMED |
| EP-007 | `GET /api/Challenges/` | Challenge | Required (`mixed`, INFERRED) | mrscargo, saeedmehmandoust | NOT CONFIRMED |
| EP-008 | `GET /api/Deliverys` | Delivery | Required (`mixed`, INFERRED) | mrscargo, saeedmehmandoust | NOT CONFIRMED |
| EP-057 | `GET /api/Deliverys/{deliveryId}` | Delivery | Required (`mixed`, INFERRED) | mrscargo, saeedmehmandoust | NOT CONFIRMED |
| EP-010 | `GET /api/Feedbacks/` | Feedback | Required (`mixed`, INFERRED) | mrscargo | NOT CONFIRMED |
| EP-011 | `GET /api/Hints/` | Hint | Required (`mixed`, INFERRED) | mrscargo | NOT CONFIRMED |
| EP-012 | `GET /api/Products/{productId}` | Product | Required (`mixed`, INFERRED) | mrscargo, saeedmehmandoust | NOT CONFIRMED |
| EP-013 | `GET /api/Quantitys/` | Quantity | Required (`mixed`, INFERRED) | mrscargo, saeedmehmandoust | NOT CONFIRMED |
| EP-014 | `GET /api/SecurityQuestions/` | Securityquestion | Required (`cookie`, INFERRED) | saeedmehmandoust | NOT CONFIRMED |
| EP-024 | `GET /profile` | Profile | Required (`cookie`, INFERRED) | mrscargo, saeedmehmandoust | NOT CONFIRMED |
| EP-025 | `GET /rest/admin/application-configuration` | ApplicationConfiguration | Required (`mixed`, INFERRED) | mrscargo, saeedmehmandoust | NOT CONFIRMED |
| EP-026 | `GET /rest/admin/application-version` | ApplicationVersion | Required (`mixed`, INFERRED) | mrscargo, saeedmehmandoust | NOT CONFIRMED |
| EP-027 | `GET /rest/basket/{basketId}` | Basket | Required (`mixed`, INFERRED) | mrscargo, saeedmehmandoust | NOT CONFIRMED |
| EP-028 | `GET /rest/continue-code` | ContinueCode | Required (`mixed`, INFERRED) | mrscargo | NOT CONFIRMED |
| EP-029 | `GET /rest/languages` | Language | Required (`mixed`, INFERRED) | mrscargo, saeedmehmandoust | NOT CONFIRMED |
| EP-030 | `GET /rest/order-history` | OrderHistory | Required (`mixed`, INFERRED) | mrscargo, saeedmehmandoust | NOT CONFIRMED |
| EP-031 | `GET /rest/products/search` | Product | Required (`mixed`, INFERRED) | mrscargo, saeedmehmandoust | NOT CONFIRMED |
| EP-032 | `GET /rest/products/{productId}/reviews` | Product | Required (`mixed`, INFERRED) | mrscargo, saeedmehmandoust | NOT CONFIRMED |
| EP-033 | `GET /rest/saveLoginIp` | Saveloginip | Required (`mixed`, INFERRED) | mrscargo | NOT CONFIRMED |
| EP-034 | `GET /rest/track-order/{trackOrderId}` | TrackOrder | Required (`mixed`, INFERRED) | mrscargo, saeedmehmandoust | NOT CONFIRMED |
| EP-035 | `GET /rest/user/change-password` | Password | Required (`mixed`, INFERRED) | mrscargo, saeedmehmandoust | NOT CONFIRMED |
| EP-036 | `GET /rest/user/whoami` | Whoami | Required (`mixed`, INFERRED) | mrscargo, saeedmehmandoust | NOT CONFIRMED |
| EP-037 | `GET /rest/wallet/balance` | Wallet | Required (`mixed`, INFERRED) | mrscargo, saeedmehmandoust | NOT CONFIRMED |
| EP-038 | `GET /socket.io/` | Socket.Io | Required (`cookie`, INFERRED) | mrscargo, saeedmehmandoust | NOT CONFIRMED |
| EP-044 | `POST /api/Addresss/` | Addresss | Required (`mixed`, INFERRED) | mrscargo, saeedmehmandoust | NOT CONFIRMED |
| EP-045 | `POST /api/BasketItems/` | Basketitem | Required (`mixed`, INFERRED) | mrscargo, saeedmehmandoust | NOT CONFIRMED |
| EP-046 | `POST /api/Cards/` | Card | Required (`mixed`, INFERRED) | mrscargo, saeedmehmandoust | NOT CONFIRMED |
| EP-047 | `POST /api/Complaints/` | Complaint | Required (`mixed`, INFERRED) | mrscargo, saeedmehmandoust | NOT CONFIRMED |
| EP-048 | `POST /file-upload` | FileUpload | Required (`mixed`, INFERRED) | mrscargo, saeedmehmandoust | NOT CONFIRMED |
| EP-049 | `POST /profile` | Profile | Required (`cookie`, INFERRED) | mrscargo, saeedmehmandoust | NOT CONFIRMED |
| EP-050 | `POST /profile/image/file` | File | Required (`cookie`, INFERRED) | mrscargo, saeedmehmandoust | NOT CONFIRMED |
| EP-051 | `POST /profile/image/url` | Url | Required (`cookie`, INFERRED) | mrscargo, saeedmehmandoust | NOT CONFIRMED |
| EP-052 | `POST /rest/basket/{basketId}/checkout` | Basket | Required (`mixed`, INFERRED) | mrscargo, saeedmehmandoust | NOT CONFIRMED |
| EP-053 | `POST /rest/user/login` | Login | Required (`cookie`, INFERRED) | mrscargo, saeedmehmandoust | NOT CONFIRMED |
| EP-054 | `POST /socket.io/` | Socket.Io | Required (`cookie`, INFERRED) | mrscargo, saeedmehmandoust | NOT CONFIRMED |
| EP-055 | `PUT /rest/products/{productId}/reviews` | Product | Required (`mixed`, INFERRED) | mrscargo, saeedmehmandoust | NOT CONFIRMED |
| EP-056 | `PUT /rest/wallet/balance` | Wallet | Required (`mixed`, INFERRED) | saeedmehmandoust | NOT CONFIRMED |
<!-- FINSEC-GENERATED:authorization:END -->

## Researcher Notes
