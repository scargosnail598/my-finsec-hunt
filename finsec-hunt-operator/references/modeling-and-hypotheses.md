Modeling and Hypotheses (verified)

Sources: `finsec/modeling/`, `finsec/hypotheses/generator.py`, `finsec/workflow.py`.

Pipeline:
- Observations -> Endpoint families -> Resources -> Workflows -> Invariants -> Hypotheses.
- Redacted observations -> actions/resources -> workflow instances/families -> states/transitions
  -> business invariants -> `BLH-*` hypotheses or research tasks.
- Active hypotheses require runtime evidence sources (`HAR`, `BURP_XML`, `CAIDO_JSON`). OpenAPI-only routes remain research leads.
- Behavior reconstruction uses typed producer-consumer provenance. Only `CAUSAL_HARD` links merge;
  soft context, replay relations, and cross-actor comparisons stay separate.
- Workflow families use exact ordered method/route/action/state/topology signatures. Causal
  prerequisites replace adjacency-based required steps.

Hypothesis states:
- `generated` (candidate), `ineligible` (missing precondition), `requires_ownership`, `planned`, `approved`, `executed`, `confirmed`.
- Business-logic readiness is separate: `RESEARCH_ONLY`, `REVIEW_REQUIRED`, or `TEST_READY`.
  Mutation gate failures are persisted as explainable rejection records.

Eligibility rules and common blockers:
- Missing runtime observations prevents active hypothesis generation.
- Ownership baseline and credential fidelity required for executable hypotheses.
- Offline logic analysis never emits `CONFIRMED`; empirical request/response and authoritative
  state evidence are required, and unsafe candidates remain `RESEARCH_TASK` records.
