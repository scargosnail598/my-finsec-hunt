"""Test corpus evaluator module."""

import pytest

from finsec.behavior.corpus_evaluator import RealisticCorpusEvaluator
from finsec.behavior.corpus_metrics import EdgeResult


def test_evaluator_loads_corpus():
    """Test evaluator can load the corpus."""
    evaluator = RealisticCorpusEvaluator()
    journey_ids = evaluator.get_journey_ids()
    assert len(journey_ids) > 0
    assert "resource-lifecycle" in journey_ids


def test_evaluator_gets_expected_edges():
    """Test evaluator retrieves expected edges."""
    evaluator = RealisticCorpusEvaluator()
    edges = evaluator.get_expected_edges_for_journey("resource-lifecycle")
    assert len(edges) > 0
    assert all(len(e) == 3 for e in edges)


def test_evaluator_perfect_journey():
    """Test evaluating a journey with perfect reconstruction."""
    evaluator = RealisticCorpusEvaluator()

    # Get expected edges for a journey
    expected = evaluator.get_expected_edges_for_journey("resource-lifecycle")
    assert len(expected) > 0

    # Evaluate with all expected edges found
    result = evaluator.evaluate_journey(
        "resource-lifecycle",
        found_causal_edges=expected,
        workflow_components_count=1,
    )

    assert result.recall == 1.0
    assert result.false_negatives == 0
    assert result.true_positives > 0


def test_evaluator_partial_recall():
    """Test evaluating a journey with missed edges."""
    evaluator = RealisticCorpusEvaluator()

    # Get expected edges but omit the first one
    expected = evaluator.get_expected_edges_for_journey("resource-lifecycle")
    if len(expected) > 1:
        found = expected[1:]  # Miss the first edge

        result = evaluator.evaluate_journey(
            "resource-lifecycle",
            found_causal_edges=found,
            workflow_components_count=1,
        )

        assert result.recall < 1.0
        assert result.false_negatives > 0
        assert result.true_positives == len(found)


def test_evaluator_false_positives():
    """Test evaluating with incorrect edges."""
    evaluator = RealisticCorpusEvaluator()

    # Get expected edges and add a spurious edge
    expected = evaluator.get_expected_edges_for_journey("resource-lifecycle")
    found = expected + [("fake_producer", "fake_consumer", "fake_field")]

    result = evaluator.evaluate_journey(
        "resource-lifecycle",
        found_causal_edges=found,
        workflow_components_count=2,  # Wrong component count
    )

    assert result.false_positives > 0
    assert result.precision < 1.0
    assert result.component_correctness == False


def test_evaluator_aggregate():
    """Test aggregating multiple journey evaluations."""
    evaluator = RealisticCorpusEvaluator()

    journey_ids = evaluator.get_journey_ids()[:2]  # Test first 2 journeys
    journey_evals = []

    for jid in journey_ids:
        expected = evaluator.get_expected_edges_for_journey(jid)
        # Evaluate with all edges found
        eval_result = evaluator.evaluate_journey(
            jid, found_causal_edges=expected, workflow_components_count=1
        )
        journey_evals.append(eval_result)

    corpus_eval = evaluator.evaluate_corpus(journey_evals)
    assert corpus_eval.total_journeys == len(journey_ids)
    assert corpus_eval.overall_recall > 0


def test_evaluator_report():
    """Test report generation."""
    evaluator = RealisticCorpusEvaluator()

    expected = evaluator.get_expected_edges_for_journey("resource-lifecycle")
    result = evaluator.evaluate_journey(
        "resource-lifecycle",
        found_causal_edges=expected,
        workflow_components_count=1,
    )

    corpus_eval = evaluator.evaluate_corpus([result])
    report = corpus_eval.format_report()

    assert "REALISTIC CORPUS EVALUATION REPORT" in report
    assert "resource-lifecycle" in report
