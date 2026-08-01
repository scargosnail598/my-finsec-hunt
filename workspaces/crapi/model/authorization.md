# Authorization Model

<!-- FINSEC-GENERATED:authorization:START -->
## Endpoint Authorization View

Authentication presence does not prove object or function authorization.

| Endpoint | Operation | Resource | Authentication | Observed actors | Ownership/role condition |
|---|---|---|---|---|---|
| EP-022 | `GET /` | Unknown | Not established (INFERRED) | mrscargo, saeedmehmandoust | NOT CONFIRMED |
| EP-001 | `GET /%F0%9F%91%A4` | %F0%9F%91%A4 | Not established (INFERRED) | mrscargo, saeedmehmandoust | NOT CONFIRMED |
| EP-002 | `GET /%F0%9F%A4%96` | %F0%9F%A4%96 | Not established (INFERRED) | mrscargo, saeedmehmandoust | NOT CONFIRMED |
| EP-023 | `GET /chatbot/genai/state` | State | Required (`bearer`, INFERRED) | mrscargo, saeedmehmandoust | NOT CONFIRMED |
| EP-003 | `GET /community/api/v2/community/posts/recent` | Post | Required (`bearer`, INFERRED) | mrscargo, saeedmehmandoust | NOT CONFIRMED |
| EP-004 | `GET /community/api/v2/community/posts/{postId}` | Post | Required (`bearer`, INFERRED) | mrscargo, saeedmehmandoust | NOT CONFIRMED |
| EP-005 | `GET /identity/api/v2/user/dashboard` | Dashboard | Required (`bearer`, INFERRED) | mrscargo, saeedmehmandoust | NOT CONFIRMED |
| EP-066 | `GET /identity/api/v2/user/videos/{videoId}` | Video | Required (`bearer`, INFERRED) | mrscargo, saeedmehmandoust | NOT CONFIRMED |
| EP-007 | `GET /identity/api/v2/vehicle/vehicles` | Vehicle | Required (`bearer`, INFERRED) | mrscargo, saeedmehmandoust | NOT CONFIRMED |
| EP-024 | `GET /manifest.json` | Manifest.Json | Not established (INFERRED) | mrscargo, saeedmehmandoust | NOT CONFIRMED |
| EP-048 | `GET /service-report` | ServiceReport | Not established (INFERRED) | mrscargo, saeedmehmandoust | NOT CONFIRMED |
| EP-049 | `GET /shop` | Shop | Not established (INFERRED) | mrscargo | NOT CONFIRMED |
| EP-051 | `GET /vehicle-service-dashboard` | VehicleServiceDashboard | Not established (INFERRED) | saeedmehmandoust | NOT CONFIRMED |
| EP-052 | `GET /workshop/api/mechanic` | Mechanic | Required (`bearer`, INFERRED) | mrscargo, saeedmehmandoust | NOT CONFIRMED |
| EP-053 | `GET /workshop/api/mechanic/` | Mechanic | Required (`bearer`, INFERRED) | mrscargo, saeedmehmandoust | NOT CONFIRMED |
| EP-054 | `GET /workshop/api/mechanic/mechanic_report` | MechanicReport | Required (`bearer`, INFERRED) | mrscargo, saeedmehmandoust | NOT CONFIRMED |
| EP-067 | `GET /workshop/api/merchant/service_requests/{serviceRequestId}` | ServiceRequest | Required (`bearer`, INFERRED) | mrscargo, saeedmehmandoust | NOT CONFIRMED |
| EP-010 | `GET /workshop/api/shop/orders/all` | Order | Required (`bearer`, INFERRED) | mrscargo, saeedmehmandoust | NOT CONFIRMED |
| EP-011 | `GET /workshop/api/shop/products` | Product | Required (`bearer`, INFERRED) | mrscargo, saeedmehmandoust | NOT CONFIRMED |
| EP-013 | `POST /community/api/v2/community/posts` | Post | Required (`bearer`, INFERRED) | mrscargo, saeedmehmandoust | NOT CONFIRMED |
| EP-014 | `POST /community/api/v2/community/posts/{postId}/comment` | Post | Required (`bearer`, INFERRED) | mrscargo, saeedmehmandoust | NOT CONFIRMED |
| EP-015 | `POST /community/api/v2/coupon/validate-coupon` | Coupon | Required (`bearer`, INFERRED) | mrscargo | NOT CONFIRMED |
| EP-016 | `POST /identity/api/auth/login` | Login | Not established (INFERRED) | mrscargo, saeedmehmandoust | NOT CONFIRMED |
| EP-017 | `POST /identity/api/auth/verify` | Auth | Not established (INFERRED) | mrscargo, saeedmehmandoust | NOT CONFIRMED |
| EP-018 | `POST /identity/api/v2/user/change-phone-number` | PhoneNumber | Required (`bearer`, INFERRED) | mrscargo, saeedmehmandoust | NOT CONFIRMED |
| EP-019 | `POST /identity/api/v2/user/pictures` | Picture | Required (`bearer`, INFERRED) | mrscargo, saeedmehmandoust | NOT CONFIRMED |
| EP-062 | `POST /identity/api/v2/vehicle/add_vehicle` | Vehicle | Required (`bearer`, INFERRED) | saeedmehmandoust | NOT CONFIRMED |
| EP-063 | `POST /identity/api/v2/vehicle/resend_email` | Email | Required (`bearer`, INFERRED) | saeedmehmandoust | NOT CONFIRMED |
| EP-065 | `POST /workshop/api/merchant/contact_mechanic` | Mechanic | Required (`bearer`, INFERRED) | mrscargo, saeedmehmandoust | NOT CONFIRMED |
| EP-020 | `POST /workshop/api/shop/orders` | Order | Required (`bearer`, INFERRED) | mrscargo, saeedmehmandoust | NOT CONFIRMED |
| EP-021 | `POST /workshop/api/shop/orders/return_order` | Order | Required (`bearer`, INFERRED) | mrscargo, saeedmehmandoust | NOT CONFIRMED |
<!-- FINSEC-GENERATED:authorization:END -->

## Researcher Notes
