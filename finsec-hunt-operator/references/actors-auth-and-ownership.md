Actors, Authentication, and Ownership (verified)

Sources: `finsec/auth/`, `finsec/auth/service.py`, `finsec/cli.py`, tests.

Key states:
- `credential available`: a secret-candidate was detected in a capture and stored as metadata.
- `credential locally ready`: a credential record exists in the workspace secret store (externalized, not echoed).
- `target validation recorded`: the workspace recorded evidence that a request produced a server-side change (requires validated evidence).
- `actor ready for planning`: the actor has sufficient observations and credential metadata to generate hypotheses.
- `actor ready for execution`: requires credential fidelity, ownership baseline, safety gates, and human approval.

Authentication sources implemented:
- Burp XML and HAR detection (`detect_burp_authentication`, `capture_from_burp`, capture-from-har equivalents).
- Raw request files and manual capture inputs via CLI options.

What is not automatic:
- Automatic token refresh flows are not implemented unless a refresh flow is explicitly observed and the code provides a handler; do not assume refresh capability.
- Ownership baselines require two controlled actor-object-owner confirmations and may need manual verification; code enforces ownership checks in hypothesis eligibility.

Diagnostics:
- To debug "baseline actor match not confirmed": inspect the observation fingerprints, compare actor identity hints, and ensure two distinct captures show the controlled actor making reproducible action on the object.
