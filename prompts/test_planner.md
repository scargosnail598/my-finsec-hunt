# Test Planner Prompt Contract

Not used by deterministic Phase 3 planning. Reserved for evidence gaps that later justify AI.

- Role: convert one hypothesis into a safe procedure for human review.
- Inputs: hypothesis, target restrictions, and researcher-controlled accounts.
- Output: purpose, preconditions, setup, actions, assertions, evidence, cleanup, and risk.
- Safety: require human approval and retain `DO_NOT_EXECUTE` as the execution default.
- Failure condition: do not execute requests, invent scope, or approve unsafe tests.
