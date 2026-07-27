# SyntheticPay Validation Report

## Environment

- Python: 3.12.13
- FinSec Hunt commit: `1f65de1`
- Workspace: `/tmp/finsec-synthetic-validation/run-1/workspaces/syntheticpay`
- Execution: offline synthetic HAR ingestion only

### Commands Executed

- `hunt init`, `hunt ingest`, `hunt classify`, `hunt inventory`
- `hunt model`, `hunt invariants`, `hunt hypotheses`, `hunt status`
- `hunt plan`, `hunt explain`, `hunt noise`
- `hunt hypotheses --research-tasks --include-suppressed`
- `python scripts/validate_synthetic_workspace.py validate ...`

## Input

- HAR files: 10
- Observations: 37
- Actors: ACCOUNT_A, ACCOUNT_B, ANONYMOUS
- Hosts: api.syntheticpay.test, app.syntheticpay.test, static.syntheticpay.test, telemetry.syntheticpay.test, thirdparty.invalid
- Workflows: 7
- Active resources: 7
- Active invariants: 15

## Classification Results

- FIRST_PARTY_API: 15
- STATIC_ASSET: 4
- TELEMETRY: 4
- THIRD_PARTY: 1
- AUTHENTICATION tag: 3
- FINANCIAL tag: 8
- UNKNOWN: 0

## Normalization Results

- Raw observations: 37
- Endpoint families: 24
- Observations merged into families: 13
- Suppressed families: 9
- Version preservation: verified by model assertions

## Hypothesis Results

- Active hypotheses: 5
- Research tasks: 11
- Candidate dispositions: {'NEEDS_RESEARCH': 11, 'ACTIVE': 5}
- Endpoint suppression: {'ACTIVE': 15, 'SUPPRESSED_STATIC_ASSET': 4, 'SUPPRESSED_TELEMETRY': 4, 'SUPPRESSED_THIRD_PARTY': 1}
- Suppression reasons: static asset, telemetry pattern, excluded third-party host

## Required Scenarios

| Scenario | Expected | Actual | Result |
|---|---|---|---|
| Static asset suppression | All static families suppressed | 4 static; 4 suppressed | PASS |
| Telemetry suppression | Telemetry/analytics suppressed | 4 telemetry/analytics | PASS |
| Third-party classification | thirdparty.invalid is THIRD_PARTY | thirdparty.invalid | PASS |
| Version preservation | v2/v3 remain literal and no version ID placeholder | v3 asset=True | PASS |
| Endpoint deduplication | One payment family with all literal instances | sources=8 | PASS |
| Read-like POST classification | Read actions are not state changes | 6 read-like POST families | PASS |
| JSON body identifier | walletId body parameter with $.walletId object semantics | {'name': 'walletId', 'location': 'body', 'source': 'request', 'inferred_type': 'string', 'confidence': 'high', 'evidence': ['OBS-000007', 'OBS-000008'], 'knowledge_status': 'OBSERVED', 'json_path': '$.walletId', 'semantic_type': 'object_identifier', 'client_controlled': True, 'original_examples': [], 'normalization_reasons': ['request JSON contains field $.walletId']} | PASS |
| Path BOLA | One semantic Payment authorization family | 4 candidates | PASS |
| Body BOLA | Wallet payment-history authorization candidate | 1 candidates | PASS |
| Authentication replay/binding | Replay, challenge, session, account, and purpose questions | whether a consumed code can be replayed after successful consumption. whether the code is bound to its challenge, session, account, and purpose. matched account a and account b challenge baselines without brute force. code consumption is security-sensitive, but replay, challenge, session, and account binding have not been observed together. | PASS |
| State-transition specificity | Specific cancel/confirm research questions, no generic active claim | determine whether the cancel operation rejects confirmed payment objects determine whether the confirm operation rejects cancelled payment objects | PASS |
| Authentication enforcement gate | Authenticated baselines become grouped research tasks | active=0, tasks=3 | PASS |
| Response-only value exclusion | Response monetary fields retain provenance and create no mutation candidate | response_fields=3, active_values=0 | PASS |
| Research-task generation | change-wallet and verification tasks | determine whether authentication is enforced on sensitive payment endpoints determine whether authentication is enforced on sensitive verification endpoints determine whether authentication is enforced on sensitive wallet endpoints determine security semantics of post /api/v2/auth/challenge/initiate determine authentication code replay and binding semantics determine security semantics of post /api/v2/payment-methods/lookup determine security semantics of post /api/v2/payments/list determine lifecycle and security impact of user verification determine whether change-wallet persists server-side state determine whether the cancel operation rejects confirmed payment objects determine whether the confirm operation rejects cancelled payment objects | PASS |
| Noise exclusion | No static, telemetry, third-party, or generic read-state hypotheses | noisy=0, generic_state=0 | PASS |
| Hypothesis explainability | Every active hypothesis has required quality fields | active=5 | PASS |
| Determinism | Clean runs have identical semantic snapshots | identical | PASS |
| Regeneration preservation | Note, TEST_PLANNED status, lifecycle annotation, and override survive | status=TEST_PLANNED; override=['researcher classification override'] | PASS |
| Redaction | No synthetic tokens, cookies, or OTP values in workspace | leaks=[] | PASS |
| Safety gates | Plans require approval and propose no brute force/destructive automation | plans=1 | PASS |
| Real workspace isolation | Existing workspace checksums unchanged | unchanged | PASS |

## Active Hypotheses

- `HYP-004` Potential cross-account Payment access through paymentId on GET /api/v2/payments/{paymentId}/receipt
- `HYP-005` Potential cross-account Payment access through paymentId on GET /api/v2/payments/{paymentId}
- `HYP-006` Potential cross-account Payment modification through paymentId on POST /api/v2/payments/{paymentId}/cancel
- `HYP-007` Potential cross-account Payment modification through paymentId on POST /api/v2/payments/{paymentId}/confirm
- `HYP-008` Potential cross-account Wallet access through walletId on POST /api/v2/wallet/payment-history

## Research Tasks

- `HYP-001` Determine whether authentication is enforced on sensitive Payment endpoints
- `HYP-002` Determine whether authentication is enforced on sensitive Verification endpoints
- `HYP-003` Determine whether authentication is enforced on sensitive Wallet endpoints
- `HYP-009` Determine security semantics of POST /api/v2/auth/challenge/initiate
- `HYP-010` Determine authentication code replay and binding semantics
- `HYP-011` Determine security semantics of POST /api/v2/payment-methods/lookup
- `HYP-012` Determine security semantics of POST /api/v2/payments/list
- `HYP-013` Determine lifecycle and security impact of user verification
- `HYP-014` Determine whether change-wallet persists server-side state
- `HYP-015` Determine whether the cancel operation rejects confirmed Payment objects
- `HYP-016` Determine whether the confirm operation rejects cancelled Payment objects

## Failures and Limitations

- No validation failures. Lifecycle semantics are synthetic researcher annotations, not proof about any real system.
