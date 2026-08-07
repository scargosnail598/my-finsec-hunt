"""Evaluate workflow reconstruction on realistic corpus."""

from pathlib import Path

from finsec.behavior.corpus_metrics import (
    CorpusEvaluation,
    EdgeEvaluation,
    EdgeResult,
    JourneyEvaluation,
)
from finsec.behavior.realistic_corpus import load_realistic_corpus


class RealisticCorpusEvaluator:
    """Evaluate reconstruction engine against realistic corpus."""

    def __init__(self, corpus_root: Path | None = None):
        """Initialize evaluator with corpus."""
        self.corpus = load_realistic_corpus(corpus_root)

    def evaluate_journey(
        self,
        journey_id: str,
        found_causal_edges: list[tuple[str, str, str]],
        workflow_components_count: int = 1,
    ) -> JourneyEvaluation:
        """Evaluate a single journey.

        Args:
            journey_id: Journey identifier
            found_causal_edges: List of (producer, consumer, field) tuples found
            workflow_components_count: Actual workflow component count

        Returns:
            JourneyEvaluation with recall/precision metrics
        """
        # Load expected edges for this journey
        expected_edges = self.corpus.load_causal_edges()
        journey_edges = [e for e in expected_edges if e.journey == journey_id]

        # Load journey labels
        journey_labels = self.corpus.load_journey_labels()
        journey_label = next(
            (j for j in journey_labels if j.id == journey_id), None
        )

        if not journey_label:
            raise ValueError(f"Journey not found: {journey_id}")

        # Get expected edges for this journey
        expected_edge_set = {
            (e.producer, e.consumer, e.field_name)
            for e in journey_edges
            if e.status == "expected"
        }

        # Get forbidden edges
        forbidden_edge_set = {
            (e.producer, e.consumer, e.field_name)
            for e in journey_edges
            if e.status == "forbidden"
        }

        # Convert found edges to set for comparison
        found_set = {(p, c, f) for p, c, f in found_causal_edges}

        # Classify each expected edge
        edge_results = []
        for edge in journey_edges:
            if edge.status != "expected":
                continue

            edge_key = (edge.producer, edge.consumer, edge.field_name)
            if edge_key in found_set:
                result = EdgeResult.TRUE_POSITIVE
            else:
                result = EdgeResult.FALSE_NEGATIVE

            edge_results.append(
                EdgeEvaluation(
                    edge_id=edge.id,
                    journey_id=journey_id,
                    producer_obs=edge.producer,
                    consumer_obs=edge.consumer,
                    field_name=edge.field_name,
                    expected_basis=edge.expected_basis,
                    result=result,
                    expected_relationship=edge.relationship,
                )
            )

        # Count false positives (found but not expected)
        false_positive_count = len(found_set - expected_edge_set)

        # Check for forbidden edges that were found
        found_forbidden = found_set & forbidden_edge_set
        if found_forbidden:
            false_positive_count += len(found_forbidden)
            for prod, cons, field in found_forbidden:
                edge_results.append(
                    EdgeEvaluation(
                        edge_id=f"fp-{prod}-{cons}",
                        journey_id=journey_id,
                        producer_obs=prod,
                        consumer_obs=cons,
                        field_name=field,
                        expected_basis=None,
                        result=EdgeResult.FALSE_POSITIVE,
                        reason="Forbidden edge was created",
                    )
                )

        # Count other false positives (found but not in expected or forbidden)
        for prod, cons, field in found_set - expected_edge_set - forbidden_edge_set:
            edge_results.append(
                EdgeEvaluation(
                    edge_id=f"fp-{prod}-{cons}",
                    journey_id=journey_id,
                    producer_obs=prod,
                    consumer_obs=cons,
                    field_name=field,
                    expected_basis=None,
                    result=EdgeResult.FALSE_POSITIVE,
                    reason="Unexpected edge was created",
                )
            )

        return JourneyEvaluation(
            journey_id=journey_id,
            name=journey_label.name,
            expected_edges=len([e for e in journey_edges if e.status == "expected"]),
            expected_observations=len(journey_label.expected_observations),
            expected_components=journey_label.expected_components,
            edge_results=edge_results,
            workflow_components=workflow_components_count,
        )

    def evaluate_corpus(
        self, journey_evaluations: list[JourneyEvaluation]
    ) -> CorpusEvaluation:
        """Aggregate journey evaluations into corpus metrics.

        Args:
            journey_evaluations: List of journey evaluation results

        Returns:
            CorpusEvaluation with aggregate metrics
        """
        return CorpusEvaluation(journey_evaluations=journey_evaluations)

    def get_journey_ids(self) -> list[str]:
        """Get all journey IDs in corpus."""
        labels = self.corpus.load_journey_labels()
        return [j.id for j in labels]

    def get_expected_edges_for_journey(
        self, journey_id: str
    ) -> list[tuple[str, str, str]]:
        """Get expected edges for journey.

        Args:
            journey_id: Journey identifier

        Returns:
            List of (producer, consumer, field) tuples
        """
        edges = self.corpus.load_causal_edges()
        journey_edges = [e for e in edges if e.journey == journey_id]
        return [
            (e.producer, e.consumer, e.field_name)
            for e in journey_edges
            if e.status == "expected"
        ]
