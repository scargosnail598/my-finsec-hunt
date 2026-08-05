"""Regression coverage for the compact labeled workflow benchmark."""

from __future__ import annotations

from pathlib import Path

from finsec.behavior.benchmark import (
    ClassificationMetrics,
    _build_dataset,
    _classification,
    evaluate_benchmark,
    load_benchmark,
)
from finsec.behavior.domain import (
    InferenceConfidence,
    PropagationStore,
    RelationshipType,
    WorkflowStep,
)
from finsec.behavior.reconstruction import (
    _structural_signature,
    load_propagation,
    load_workflow_instances,
)

FIXTURE = Path(__file__).parent / "fixtures" / "workflow_precision" / "benchmark.json"


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


def test_benchmark_is_deterministic(tmp_path: Path) -> None:
    definition = load_benchmark(FIXTURE)

    first = evaluate_benchmark(definition, tmp_path / "first")
    second = evaluate_benchmark(definition, tmp_path / "second")

    assert first.model_dump(mode="json") == second.model_dump(mode="json")


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
    assert comparison.evidence_reason
    assert (
        observation_instance[labels["payment_for_comment"]]
        != observation_instance[labels["comment_create"]]
    )
    assert (
        observation_instance[comparison.source_observation_id]
        != observation_instance[comparison.destination_observation_id]
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
    assert legacy.propagation_links[0].relationship_type == RelationshipType.CAUSAL_HARD
    assert PropagationStore().version == 2
