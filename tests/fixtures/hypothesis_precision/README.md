# BLH Precision Corpus

This fully labeled synthetic corpus starts after workflow reconstruction. It evaluates which raw
business-logic candidates become distinct researcher-facing security questions.

`corpus.yaml` includes positive clusters, semantic duplicates, self-ordering, malformed labels,
static content, actor-binding evidence, scalar substitution, controlled resource substitution,
and overlap with stronger endpoint-level authorization hypotheses.

`quality-gates.yaml` enforces the reviewed labels, zero visible semantic duplicates, zero visible
self-referential or malformed questions, zero blocker-bearing `TEST_READY` clusters, deterministic
output, and zero evidence/provenance loss.

This corpus does not measure causal reconstruction and does not make real-world precision claims.
