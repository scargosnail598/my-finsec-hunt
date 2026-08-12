"""Regression coverage for the compact labeled workflow benchmark."""

from __future__ import annotations

from pathlib import Path

import pytest

from finsec.behavior.benchmark import (
    BenchmarkLabelError,
    ClassificationMetrics,
    HypothesisExpectation,
    _build_dataset,
    _classification,
    _validate_static_labels,
    evaluate_benchmark,
    evaluate_quality_gate_configuration,
    load_benchmark,
    load_quality_gate_configuration,
    quality_gate_failures,
)
from finsec.behavior.domain import (
    CausalBasis,
    CausalEvidence,
    InferenceConfidence,
    PropagationLink,
    PropagationStore,
    RelationshipType,
    WorkflowStep,
)
from finsec.behavior.reconstruction import (
    _structural_signature,
    is_merge_capable_relationship,
    load_propagation,
    load_workflow_instances,
)

FIXTURE = Path(__file__).parent / "fixtures" / "workflow_precision" / "benchmark.json"
GATE_FIXTURE = Path(__file__).parent / "fixtures" / "workflow_precision" / "precision-gate.json"
GATE_CONFIGURATION = (
    Path(__file__).parent / "fixtures" / "workflow_precision" / "quality-gates.json"
)


@pytest.fixture(scope="module")
def exploratory_reports(
    tmp_path_factory: pytest.TempPathFactory,
) -> tuple[object, object]:
    definition = load_benchmark(FIXTURE)
    root = tmp_path_factory.mktemp("exploratory-benchmark")
    return (
        evaluate_benchmark(definition, root / "first"),
        evaluate_benchmark(definition, root / "second"),
    )


@pytest.fixture(scope="module")
def quality_reports(
    tmp_path_factory: pytest.TempPathFactory,
) -> tuple[object, object]:
    root = tmp_path_factory.mktemp("quality-benchmark")
    return evaluate_quality_gate_configuration(GATE_CONFIGURATION, root)


def test_unknown_labels_are_excluded_from_metric_denominators() -> None:
    metrics = _classification(
        [("a", "b")],
        [("c", "d")],
        {("a", "b"), ("unknown", "pair")},
        directed=True,
    )

    assert metrics == ClassificationMetrics(
        precision=1.0,
        recall=1.0,
        f1=1.0,
        counts={"true_positive": 1, "false_positive": 0, "false_negative": 0},
    )


def test_forbidden_edge_and_merge_reduce_precision() -> None:
    edge_metrics = _classification(
        [("producer", "consumer")],
        [("unrelated", "consumer")],
        {("producer", "consumer"), ("unrelated", "consumer")},
        directed=True,
    )
    merge_metrics = _classification(
        [("left", "right")],
        [("left", "other")],
        {("left", "right"), ("left", "other")},
    )

    assert edge_metrics.precision == 0.5
    assert edge_metrics.counts.false_positive == 1
    assert merge_metrics.precision == 0.5
    assert merge_metrics.counts.false_positive == 1


def test_benchmark_is_deterministic(exploratory_reports: tuple[object, object]) -> None:
    first, second = exploratory_reports
    assert first.model_dump(mode="json") == second.model_dump(mode="json")


def test_hypothesis_metrics_report_unknowns_and_raw_denominators_honestly(
    exploratory_reports: tuple[object, object],
) -> None:
    report, _repeated = exploratory_reports
    aggregate = report.aggregate
    counts = aggregate.hypothesis_counts_at_k["10"]

    assert aggregate.labeled_precision_at_k["10"] == 1.0
    assert aggregate.hypothesis_precision_at_k["10"] == 1.0
    assert aggregate.label_coverage_at_k["10"] == pytest.approx(7 / 39)
    assert aggregate.unknown_rate_at_k["10"] == pytest.approx(32 / 39)
    assert aggregate.precision_lower_bound_at_k["10"] == pytest.approx(7 / 39)
    assert counts.emitted_predictions == 39
    assert counts.labeled_predictions == 7
    assert counts.expected_predictions == 7
    assert counts.forbidden_predictions == 0
    assert counts.unknown_predictions == 32
    assert counts.emitted_predictions == (
        counts.expected_predictions + counts.forbidden_predictions + counts.unknown_predictions
    )


def test_fragmentation_diagnostics_measure_retention_without_gating_singletons(
    exploratory_reports: tuple[object, object],
) -> None:
    report, _repeated = exploratory_reports
    aggregate = report.aggregate

    assert aggregate.total_reconstructed_workflows == 20
    assert aggregate.singleton_workflow_count == 12
    assert aggregate.singleton_workflow_rate == 0.6
    assert aggregate.expected_multi_step_journey_count == 8
    assert aggregate.fully_retained_multi_step_journey_count == 8
    assert aggregate.fragmented_expected_journey_count == 0
    assert aggregate.under_merge_pair_count == 0
    assert aggregate.over_merge_pair_count == 0
    assert aggregate.known_journey_component_recall == 1.0


def test_soft_and_cross_actor_relationships_do_not_merge(tmp_path: Path) -> None:
    definition = load_benchmark(FIXTURE)
    dataset = next(item for item in definition.datasets if item.id == "boundary_noise")
    workspace, labels = _build_dataset(dataset, tmp_path)
    links = load_propagation(workspace).propagation_links

    soft = next(
        item
        for item in links
        if item.source_observation_id == labels["payment_for_comment"]
        and item.destination_observation_id == labels["comment_create"]
    )
    comparison = next(
        item for item in links if item.relationship_type == RelationshipType.CROSS_ACTOR_COMPARISON
    )
    observation_instance = {
        step.observation_id: instance.id
        for instance in load_workflow_instances(workspace).workflow_instances
        for step in instance.steps
    }

    assert soft.relationship_type == RelationshipType.CONTEXT_SOFT
    assert "Correlation identifiers" in soft.evidence_reason
    assert soft.causal_evidence.later_consumed
    assert soft.rejection_reasons == ["correlation_identifier_display_only"]
    assert comparison.evidence_reason
    assert not comparison.causal_evidence.same_controlled_actor
    assert comparison.rejection_reasons == ["controlled_actor_mismatch"]
    assert (
        observation_instance[labels["payment_for_comment"]]
        != observation_instance[labels["comment_create"]]
    )
    assert (
        observation_instance[comparison.source_observation_id]
        != observation_instance[comparison.destination_observation_id]
    )


def test_complete_top_k_labels_reject_missing_duplicate_and_orphan_entries(
    tmp_path: Path,
) -> None:
    definition = load_benchmark(GATE_FIXTURE)

    duplicate = definition.model_copy(deep=True)
    duplicate_label = duplicate.datasets[0].labels.expected_hypotheses[0]
    duplicate.datasets[0].labels.expected_hypotheses.append(duplicate_label)
    with pytest.raises(BenchmarkLabelError, match="duplicate hypothesis label keys"):
        _validate_static_labels(duplicate)

    missing = definition.model_copy(deep=True)
    missing.datasets[0].labels.expected_hypotheses.pop()
    with pytest.raises(BenchmarkLabelError, match="missing labels for emitted top-K"):
        evaluate_benchmark(missing, tmp_path / "missing")

    orphan = definition.model_copy(deep=True)
    orphan.datasets[0].labels.expected_hypotheses.append(
        HypothesisExpectation(
            key="orphan-semantic-label",
            family="REPLAY",
            affected_action="UNOBSERVED_ACTION",
            semantic_key="not-an-emitted-semantic-key",
        )
    )
    with pytest.raises(BenchmarkLabelError, match="orphan top-K label"):
        evaluate_benchmark(orphan, tmp_path / "orphan")


@pytest.mark.parametrize(
    ("updates", "failure_code"),
    [
        ({"forbidden_edge_violations": 1}, "FORBIDDEN_HARD_EDGES"),
        ({"forbidden_workflow_merge_count": 1}, "FORBIDDEN_WORKFLOW_MERGES"),
        ({"labeled_precision_at_k": {"10": 0.9}}, "LABELED_PRECISION_AT_K"),
        ({"label_coverage_at_k": {"10": 0.9}}, "LABEL_COVERAGE_AT_K"),
        (
            {"expected_mutation_recall_at_k": {"10": 0.9}},
            "EXPECTED_MUTATION_RECALL_AT_K",
        ),
        ({"test_ready_with_blockers": 1}, "TEST_READY_WITH_BLOCKERS"),
        ({"fragmented_expected_journey_count": 1}, "FRAGMENTED_EXPECTED_JOURNEYS"),
        ({"journey_order_violation_count": 1}, "JOURNEY_ORDER_VIOLATIONS"),
    ],
)
def test_quality_gates_fail_for_deliberate_regressions(
    quality_reports: tuple[object, object],
    updates: dict[str, object],
    failure_code: str,
) -> None:
    report, _repeated = quality_reports
    configuration = load_quality_gate_configuration(GATE_CONFIGURATION)
    mutated = report.model_copy(update={"aggregate": report.aggregate.model_copy(update=updates)})

    failures = quality_gate_failures(mutated, configuration.thresholds, repeated_report=mutated)

    assert failure_code in failures


def test_quality_gate_detects_non_deterministic_output(
    quality_reports: tuple[object, object],
) -> None:
    report, repeated = quality_reports
    configuration = load_quality_gate_configuration(GATE_CONFIGURATION)
    changed = repeated.model_copy(
        update={
            "aggregate": repeated.aggregate.model_copy(
                update={"singleton_workflow_count": repeated.aggregate.singleton_workflow_count + 1}
            )
        }
    )

    assert "NON_DETERMINISTIC_OUTPUT" in quality_gate_failures(
        report, configuration.thresholds, repeated_report=changed
    )


def test_repeated_positions_change_structural_family_signature() -> None:
    def step(position: int, action: str) -> WorkflowStep:
        return WorkflowStep(
            position=position,
            action_id=f"ACTN-{position}",
            action_name=action,
            observation_id=f"OBS-{position}",
            actor="ACCOUNT_A",
            method="POST",
            route="/api/orders/{orderId}/item",
            resource_role="PRIMARY:order",
            state_changing=True,
        )

    single = [step(1, "CREATE_ORDER"), step(2, "ADD_ORDER")]
    repeated = [step(1, "CREATE_ORDER"), step(2, "ADD_ORDER"), step(3, "ADD_ORDER")]

    single_hash, single_order, _, _ = _structural_signature(single, [])
    repeated_hash, repeated_order, _, _ = _structural_signature(repeated, [])

    assert single_hash != repeated_hash
    assert repeated_order[-1].startswith("3:POST:")
    assert repeated_order[-1].endswith(":ADD_ORDER:PRIMARY:order:MUTATING:UNRESOLVED->UNRESOLVED")


def test_v1_relationship_store_loads_while_new_store_defaults_to_v2() -> None:
    legacy = PropagationStore.model_validate(
        {
            "version": 1,
            "propagation_links": [
                {
                    "id": "PROP-LEGACY",
                    "value_fingerprint": "a" * 64,
                    "value_kind": "RESOURCE_IDENTIFIER",
                    "source_observation_id": "OBS-1",
                    "source_field": "$.orderId",
                    "destination_observation_id": "OBS-2",
                    "destination_field": "$.orderId",
                    "confidence": InferenceConfidence.MODERATE_EVIDENCE,
                }
            ],
        }
    )

    assert legacy.version == 1
    link = legacy.propagation_links[0]
    assert link.relationship_type == RelationshipType.CONTEXT_SOFT
    assert link.causal_basis == CausalBasis.LEGACY_UNTYPED
    assert not is_merge_capable_relationship(link)
    assert "cannot merge workflows" in link.evidence_reason
    assert PropagationStore().version == 2


def test_v2_relationship_store_round_trips_deterministically() -> None:
    evidence = CausalEvidence(
        output_only=True,
        later_consumed=True,
        compatible_resource_type=True,
        temporal_order=True,
        same_controlled_actor=True,
        distinctive_value=True,
        same_session=True,
        same_capture=True,
        same_host=True,
        session_compatible=True,
        capture_compatible=True,
        host_compatible=True,
        source_successful=True,
        source_created_resource=True,
        consumed_as_path_identifier=True,
        persistent_resource_identity=True,
    )
    link = PropagationLink(
        id="PROP-MODERN",
        relationship_type=RelationshipType.CAUSAL_HARD,
        causal_basis=CausalBasis.RESOURCE_CREATED,
        value_fingerprint="b" * 64,
        value_kind="RESOURCE_IDENTIFIER",
        source_observation_id="OBS-1",
        source_field="$.orderId",
        destination_observation_id="OBS-2",
        destination_field="$.orderId",
        causal_evidence=evidence,
        evidence_reason="RESOURCE_CREATED: output-only identifier.",
        confidence=InferenceConfidence.MODERATE_EVIDENCE,
    )
    first = PropagationStore(propagation_links=[link]).model_dump(mode="json")
    second = PropagationStore.model_validate(first).model_dump(mode="json")

    assert first == second
    assert is_merge_capable_relationship(link)


def test_v2_hard_relationship_without_canonical_evidence_cannot_merge() -> None:
    link = PropagationLink(
        id="PROP-UNSUPPORTED",
        relationship_type=RelationshipType.CAUSAL_HARD,
        causal_basis=CausalBasis.RESOURCE_CREATED,
        value_fingerprint="c" * 64,
        value_kind="RESOURCE_IDENTIFIER",
        source_observation_id="OBS-1",
        source_field="$.orderId",
        destination_observation_id="OBS-2",
        destination_field="$.orderId",
        confidence=InferenceConfidence.MODERATE_EVIDENCE,
    )

    assert not is_merge_capable_relationship(link)
