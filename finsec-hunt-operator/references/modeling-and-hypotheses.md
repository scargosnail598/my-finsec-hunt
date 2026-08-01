Modeling and Hypotheses (verified)

Sources: `finsec/modeling/`, `finsec/hypotheses/generator.py`, `finsec/workflow.py`.

Pipeline:
- Observations -> Endpoint families -> Resources -> Workflows -> Invariants -> Hypotheses.
- Active hypotheses require runtime evidence sources (`HAR`, `BURP_XML`, `CAIDO_JSON`). OpenAPI-only routes remain research leads.

Hypothesis states:
- `generated` (candidate), `ineligible` (missing precondition), `requires_ownership`, `planned`, `approved`, `executed`, `confirmed`.

Eligibility rules and common blockers:
- Missing runtime observations prevents active hypothesis generation.
- Ownership baseline and credential fidelity required for executable hypotheses.
