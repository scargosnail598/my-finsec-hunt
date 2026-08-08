# Realistic Corpus Labels - Documentation

## Overview

This directory contains the complete ground truth labels for the realistic workflow corpus. All files use YAML format for readability and are designed to be language-agnostic.

## Label Files

### causal-edges.yaml

Defines all expected and forbidden causal edges.

**Structure:**
```yaml
edges:
  - id: "unique-edge-id"
    journey: "journey-name"
    producer: "observation-label"
    consumer: "observation-label"
    field_name: "field-name"
    resource_type: "order|payment|capability|..."
    value: "actual-value"
    relationship: "CAUSAL_HARD | CONTEXT_SOFT | REPLAY_RELATED | CROSS_ACTOR_COMPARISON"
    expected_basis: "RESOURCE_CREATED | CAPABILITY_ISSUED | STATE_TRANSITION_PRODUCED | ..."
    status: "expected | forbidden | unknown"
    reason: "human-readable explanation"
    [optional fields for metadata]
```

**Key Fields:**
- `producer`: Label of the observation that produces the value
- `consumer`: Label of the observation that consumes the value
- `relationship`: The type of causal relationship
- `expected_basis`: The reason why this relationship should exist
- `status`: Whether this edge is expected, forbidden, or unknown
- `distinctive`: Boolean; whether the value is distinctive enough for causality
- `cross_host`: Boolean; whether the edge crosses service boundaries
- `state_transition`: Boolean; whether this is a state transition edge

**Usage:**
- `status: "expected"` → Engine MUST create this edge with the specified relationship
- `status: "forbidden"` → Engine MUST NOT create this edge as CAUSAL_HARD
- `status: "unknown"` → Edge may or may not be discovered (exploratory labeling)

### journeys.yaml

Defines expected workflow membership, component count, and journey integrity.

**Structure:**
```yaml
journeys:
  - id: "journey-id"
    name: "Human-readable name"
    description: "What this workflow tests"
    expected_observations: [list of observation labels]
    expected_components: 1  # expected number of workflow components
    expected_order: true  # whether steps should maintain order
    expected_steps: [ordered list of observation labels]
    expected_resource_lineage:
      resourceId:
        created_by: "observation-label"
        created_basis: "RESOURCE_CREATED"
        consumed_by: ["observation-label", ...]
    status: "fully_labeled | partial_label | exploratory"
    difficulty: "obvious | indirect | ambiguous"
    category: "resource-lifecycle | capability-handoff | ..."
```

**Key Fields:**
- `expected_components`: The number of independent workflow components expected
- `expected_steps`: The observations that should be in the same workflow, in order
- `difficulty`: Categorizes the test for stratified metrics
- `status`: Labeling coverage level

### prerequisites.yaml

Defines true prerequisites and false adjacencies.

**Structure:**
```yaml
prerequisites:
  - id: "prereq-id"
    journey: "journey-id"
    dependent_action: "action-name"
    prerequisite_action: "action-name"
    field: "field-name"
    status: "expected | forbidden"
    confidence: "HIGH_EVIDENCE | MODERATE_EVIDENCE | WEAK_EVIDENCE"
    reason: "explanation"
    evidence: [list of supporting evidence]
```

**Key Fields:**
- `dependent_action`: The action that depends on something
- `prerequisite_action`: The action that must happen first
- `status`: Whether this is a true prerequisite or a forbidden false adjacency
- `confidence`: How strong the evidence is

### state-transitions.yaml

Defines lifecycle transitions independently from causal-edge labels. Each record names the
producer and consumer observations, typed resource, state field, and exact before/after values.

---

## Labeling Conventions

### Observation Labels

Each observation in a journey is labeled with a concise, descriptive name:
- `create_order` - POST that creates a resource
- `read_order` - GET that reads a resource
- `confirm_order` - POST that transitions state
- Format: `{verb}_{resource}_{disambiguator}`

### Field Names

- If a value appears under a field like `orderId`, use `"orderId"` as the field name
- If the same value appears in different fields (aliasing), use both names or `"orderId (in different field names)"`
- Generic fields: `"id"`, `"reference"`, `"handle"`, `"token"`, etc.

### Values

- Actual values are provided for specificity
- Value fingerprints or patterns can be used if exact values change
- For state transitions: use `value_from` and `value_to`

### Resource Types

Standard types:
- `order`, `payment`, `account`, `user`, `session`, `transaction`
- `capability` - for workflow tokens, nonces, challenges
- `item`, `shipment`, `report`, `search`, etc.
- Use lowercase, singular form

### Relationship Types

- `CAUSAL_HARD` - Edges that merge workflow components
- `CONTEXT_SOFT` - Soft associations that don't merge
- `REPLAY_RELATED` - Repeated use of same value (not a prerequisite edge)
- `CROSS_ACTOR_COMPARISON` - Cross-actor values (never merge)

### Causal Bases

- `RESOURCE_CREATED` - Value produced as a new resource ID
- `CAPABILITY_ISSUED` - Value produced as a transient capability
- `STATE_TRANSITION_PRODUCED` - Inferred from state field changes
- `EXISTING_VALUE_OBSERVED` - Value observed in a read operation
- `REQUEST_VALUE_ECHOED` - Value repeated from the request
- `AMBIGUOUS_ORIGIN` - Origin is unclear
- `LEGACY_UNTYPED` - No evidence available

### Status Codes

- `expected` - This relationship SHOULD be discovered by the engine
- `forbidden` - This relationship MUST NOT be created as CAUSAL_HARD
- `unknown` - Uncertain; exploratory labeling

### Difficulty Levels

- `obvious` - Simple, unambiguous cases
- `indirect` - Requires multiple evidence types or temporal inference
- `ambiguous` - State names unknown, field name variants, edge cases

---

## Validation Process

To validate that the engine correctly reconstructs a journey:

1. Load all observations from the journey fixtures
2. Run the reconstruction engine
3. Check each expected edge is created as CAUSAL_HARD
4. Check each forbidden edge is NOT created as CAUSAL_HARD
5. Verify all observations are in the expected number of components
6. Verify observation order is maintained
7. Compare resource-scoped lifecycle transitions with `state-transitions.yaml`

---

## Review Checklist (for Independent Reviewers)

- [ ] Are the expected edges logically correct from a protocol perspective?
- [ ] Would a security researcher expect these edges?
- [ ] Are the forbidden edges actually dangerous if merged?
- [ ] Do the journey descriptions match the observations?
- [ ] Are the difficulty levels reasonable?
- [ ] Are there any labeled edges that contradict each other?
- [ ] Does the adversarial corpus actually test the claimed anti-patterns?

---

## Extension Points

### Adding New Journeys

1. Create a new subdirectory under `journeys/`
2. Add `README.md` explaining the scenario and challenges
3. Add `journeys.json` with fixture data (entries with actor, offset, method, path, request, response)
4. Update `causal-edges.yaml` with all edges
5. Update `journeys.yaml` with journey metadata
6. Update `prerequisites.yaml` with prerequisites
7. Update `state-transitions.yaml` with any reviewed lifecycle transitions

### Adding New Categories

New categories should be added to `journeys/` following the same pattern. They should:
- Test a specific recall gap or false negative pattern
- Include both positive cases (expected edges) and negative cases (forbidden edges)
- Use sanitized, realistic data
- Be fully labeled with explicit ground truth

---

## Statistics

Current corpus:
- **Journeys**: 9
- **Categories**: 9 (resource-lifecycle, capability-handoff, multi-service, nested, state-transitions, aliases, fanout, cross-capture, adversarial)
- **Observations**: 36 total
- **Expected hard edges**: 28
- **Expected soft edges**: 0
- **Forbidden edges**: 9
- **Expected prerequisites**: 19
- **Forbidden prerequisites**: 7
- **Expected state transitions**: 3
- **Expected components**: 14
- **Fully labeled coverage**: 100%

---

## Notes

### Why Full Labeling Matters

Without complete labeling:
- False negatives (missed edges) can't be measured
- An engine could hide poor recall by not reconstructing enough edges
- Precision and recall must be separately measurable

With complete labeling:
- Every expected edge is documented
- Every forbidden edge is explicit
- Recall can be measured as: (recovered expected edges) / (total expected edges)
- Precision can be measured as: 1 - (forbidden edges found)

### Labeling Philosophy

Labels are **ground truth**, not heuristics. They represent:
- What SHOULD happen from a protocol correctness perspective
- What MUST NOT happen to maintain safety
- What we DON'T know and need to explore

Labels do NOT:
- Depend on implementation details
- Hard-code engine behavior
- Change based on what the engine currently does
- Use fuzzy metrics or probabilistic confidence

### Maintaining Label Quality

- Every label has a reason
- Reasons reference concrete protocol evidence
- New labels should go through review
- Labels should be updated if real-world protocols reveal new patterns
