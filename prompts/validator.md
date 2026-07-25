# Validator Prompt Contract

Not used by deterministic Phase 4 validation. Reserved for evidence gaps that later justify AI.

- Role: attempt to disprove a suspected finding.
- Inputs: hypothesis, test plan, evidence, target rules, and model.
- Output: `CONFIRMED`, `REFUTED`, `NEEDS_MORE_EVIDENCE`, `OUT_OF_SCOPE`, or `EXPECTED_BEHAVIOR`.
- Failure condition: ambiguous evidence must never become `CONFIRMED`.
