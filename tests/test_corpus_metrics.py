"""Test metrics module."""

import pytest

from finsec.behavior.corpus_metrics import (
    EdgeEvaluation,
    EdgeResult,
    JourneyEvaluation,
    CorpusEvaluation,
)


def test_edge_evaluation_correct():
    """Test TP edge is marked correct."""
    edge = EdgeEvaluation(
        edge_id="e-001",
        journey_id="resource-lifecycle",
        producer_obs="create_order",
        consumer_obs="read_order",
        field_name="order_id",
        expected_basis=None,
        result=EdgeResult.TRUE_POSITIVE,
    )
    assert edge.is_correct


def test_edge_evaluation_incorrect():
    """Test non-TP edge is not marked correct."""
    edge = EdgeEvaluation(
        edge_id="e-002",
        journey_id="resource-lifecycle",
        producer_obs="create_order",
        consumer_obs="read_order",
        field_name="order_id",
        expected_basis=None,
        result=EdgeResult.FALSE_POSITIVE,
    )
    assert not edge.is_correct


def test_journey_evaluation_perfect():
    """Test perfect journey evaluation."""
    edges = [
        EdgeEvaluation(
            edge_id="e-001",
            journey_id="test",
            producer_obs="a",
            consumer_obs="b",
            field_name="id",
            expected_basis=None,
            result=EdgeResult.TRUE_POSITIVE,
        ),
        EdgeEvaluation(
            edge_id="e-002",
            journey_id="test",
            producer_obs="b",
            consumer_obs="c",
            field_name="id",
            expected_basis=None,
            result=EdgeResult.TRUE_POSITIVE,
        ),
    ]

    j = JourneyEvaluation(
        journey_id="test",
        name="Test Journey",
        expected_edges=2,
        expected_observations=3,
        expected_components=1,
        edge_results=edges,
        workflow_components=1,
    )

    assert j.true_positives == 2
    assert j.false_positives == 0
    assert j.false_negatives == 0
    assert j.recall == 1.0
    assert j.precision == 1.0
    assert j.f1_score == 1.0
    assert j.component_correctness


def test_journey_evaluation_partial_recall():
    """Test journey with missed edges."""
    edges = [
        EdgeEvaluation(
            edge_id="e-001",
            journey_id="test",
            producer_obs="a",
            consumer_obs="b",
            field_name="id",
            expected_basis=None,
            result=EdgeResult.TRUE_POSITIVE,
        ),
        EdgeEvaluation(
            edge_id="e-002",
            journey_id="test",
            producer_obs="b",
            consumer_obs="c",
            field_name="id",
            expected_basis=None,
            result=EdgeResult.FALSE_NEGATIVE,
        ),
    ]

    j = JourneyEvaluation(
        journey_id="test",
        name="Test Journey",
        expected_edges=2,
        expected_observations=3,
        expected_components=1,
        edge_results=edges,
        workflow_components=1,
    )

    assert j.true_positives == 1
    assert j.recall == 0.5
    assert j.false_negatives == 1


def test_journey_evaluation_false_positives():
    """Test journey with incorrect edges."""
    edges = [
        EdgeEvaluation(
            edge_id="e-001",
            journey_id="test",
            producer_obs="a",
            consumer_obs="b",
            field_name="id",
            expected_basis=None,
            result=EdgeResult.TRUE_POSITIVE,
        ),
        EdgeEvaluation(
            edge_id="e-002",
            journey_id="test",
            producer_obs="x",
            consumer_obs="y",
            field_name="id",
            expected_basis=None,
            result=EdgeResult.FALSE_POSITIVE,
        ),
    ]

    j = JourneyEvaluation(
        journey_id="test",
        name="Test Journey",
        expected_edges=1,
        expected_observations=2,
        expected_components=1,
        edge_results=edges,
        workflow_components=2,
    )

    assert j.true_positives == 1
    assert j.false_positives == 1
    assert j.precision == 0.5
    assert not j.component_correctness


def test_corpus_evaluation_aggregate():
    """Test corpus aggregates journey metrics correctly."""
    journey1_edges = [
        EdgeEvaluation(
            edge_id="e-001",
            journey_id="j1",
            producer_obs="a",
            consumer_obs="b",
            field_name="id",
            expected_basis=None,
            result=EdgeResult.TRUE_POSITIVE,
        )
    ]

    journey2_edges = [
        EdgeEvaluation(
            edge_id="e-002",
            journey_id="j2",
            producer_obs="x",
            consumer_obs="y",
            field_name="id",
            expected_basis=None,
            result=EdgeResult.TRUE_POSITIVE,
        ),
        EdgeEvaluation(
            edge_id="e-003",
            journey_id="j2",
            producer_obs="y",
            consumer_obs="z",
            field_name="id",
            expected_basis=None,
            result=EdgeResult.FALSE_NEGATIVE,
        ),
    ]

    j1 = JourneyEvaluation(
        journey_id="j1",
        name="J1",
        expected_edges=1,
        expected_observations=2,
        expected_components=1,
        edge_results=journey1_edges,
        workflow_components=1,
    )

    j2 = JourneyEvaluation(
        journey_id="j2",
        name="J2",
        expected_edges=2,
        expected_observations=3,
        expected_components=1,
        edge_results=journey2_edges,
        workflow_components=1,
    )

    corpus = CorpusEvaluation(journey_evaluations=[j1, j2])

    assert corpus.total_journeys == 2
    assert corpus.total_expected_edges == 3
    assert corpus.total_true_positives == 2
    assert corpus.total_false_negatives == 1
    assert corpus.overall_recall == pytest.approx(2 / 3)
    assert corpus.overall_precision == 1.0
    assert corpus.perfect_component_journeys == 2


def test_corpus_evaluation_report_formatting():
    """Test report formatting doesn't crash."""
    j = JourneyEvaluation(
        journey_id="test",
        name="Test",
        expected_edges=1,
        expected_observations=2,
        expected_components=1,
        edge_results=[],
        workflow_components=1,
    )

    corpus = CorpusEvaluation(journey_evaluations=[j])
    report = corpus.format_report()

    assert "REALISTIC CORPUS EVALUATION REPORT" in report
    assert "Overall Recall:" in report
    assert "Overall Precision:" in report
