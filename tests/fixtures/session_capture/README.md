# Session Capture Acceptance Corpus

This directory contains deterministic, synthetic HAR fixtures for session-aware ingestion. The
files contain no real hosts, credentials, cookies, or user data.

The order scenario includes two normal journeys for each controlled actor and one explicit
researcher probe:

- `order-a1-create.har`: ACCOUNT_A creates and reads order 1001.
- `order-a2-return.har`: ACCOUNT_A requests a return for order 1001.
- `order-b1-create.har`: ACCOUNT_B creates and reads order 3001.
- `order-b2-return.har`: ACCOUNT_B requests a return for order 3001.
- `order-b-probe-a.har`: ACCOUNT_B deliberately reads ACCOUNT_A's order.

The Arvan-style scenario contains independent DNS-record creation journeys for ACCOUNT_A and
ACCOUNT_B. Each includes profile, notifications, billing, and out-of-scope telemetry traffic so
the relevance engine must retain peripheral observations without treating them as the main
workflow.

Regenerate the HAR files deterministically with:

```bash
.venv/bin/python tests/fixtures/session_capture/generate.py
```

`corpus.yaml` records the intended actor, mode, and high-level intent for every source.
