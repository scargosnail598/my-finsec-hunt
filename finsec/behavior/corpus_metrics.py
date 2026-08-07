"""Recall/precision metrics for realistic corpus evaluation."""

from dataclasses import dataclass, field
from enum import Enum

from finsec.behavior.domain import CausalBasis


class EdgeResult(Enum):
    """Classification of edge reconstruction result."""

    TRUE_POSITIVE = "TP"
    FALSE_POSITIVE = "FP"
    FALSE_NEGATIVE = "FN"
    TRUE_NEGATIVE = "TN"


@dataclass
class EdgeEvaluation:
    """Per-edge evaluation result."""

    edge_id: str
    journey_id: str
    producer_obs: str
    consumer_obs: str
    field_name: str
    expected_basis: CausalBasis | None
    result: EdgeResult
    created_relationship: str = ""
    expected_relationship: str = "CAUSAL_HARD"
    reason: str = ""

    @property
    def is_correct(self) -> bool:
        """True if edge result is TP."""
        return self.result == EdgeResult.TRUE_POSITIVE


@dataclass
class JourneyEvaluation:
    """Per-journey evaluation result."""

    journey_id: str
    name: str
    expected_edges: int
    expected_observations: int
    expected_components: int
    edge_results: list[EdgeEvaluation] = field(default_factory=list)
    found_observations: int = 0
    workflow_components: int = 0

    @property
    def true_positives(self) -> int:
        """Count of correctly found edges."""
        return sum(1 for e in self.edge_results if e.result == EdgeResult.TRUE_POSITIVE)

    @property
    def false_positives(self) -> int:
        """Count of incorrect edges found."""
        return sum(1 for e in self.edge_results if e.result == EdgeResult.FALSE_POSITIVE)

    @property
    def false_negatives(self) -> int:
        """Count of missed expected edges."""
        return sum(1 for e in self.edge_results if e.result == EdgeResult.FALSE_NEGATIVE)

    @property
    def recall(self) -> float:
        """Fraction of expected edges that were found."""
        if self.expected_edges == 0:
            return 1.0
        return self.true_positives / self.expected_edges

    @property
    def precision(self) -> float:
        """Fraction of found edges that were expected."""
        found = self.true_positives + self.false_positives
        if found == 0:
            return 1.0 if self.expected_edges == 0 else 0.0
        return self.true_positives / found

    @property
    def component_correctness(self) -> bool:
        """True if workflow reconstructed with correct number of components."""
        return self.workflow_components == self.expected_components

    @property
    def f1_score(self) -> float:
        """Harmonic mean of precision and recall."""
        if self.recall + self.precision == 0:
            return 0.0
        return 2 * (self.precision * self.recall) / (self.precision + self.recall)


@dataclass
class CorpusEvaluation:
    """Aggregate metrics across all journeys."""

    journey_evaluations: list[JourneyEvaluation] = field(default_factory=list)

    @property
    def total_journeys(self) -> int:
        """Total number of journeys evaluated."""
        return len(self.journey_evaluations)

    @property
    def total_expected_edges(self) -> int:
        """Sum of expected edges across all journeys."""
        return sum(j.expected_edges for j in self.journey_evaluations)

    @property
    def total_true_positives(self) -> int:
        """Sum of TP across all journeys."""
        return sum(j.true_positives for j in self.journey_evaluations)

    @property
    def total_false_positives(self) -> int:
        """Sum of FP across all journeys."""
        return sum(j.false_positives for j in self.journey_evaluations)

    @property
    def total_false_negatives(self) -> int:
        """Sum of FN across all journeys."""
        return sum(j.false_negatives for j in self.journey_evaluations)

    @property
    def overall_recall(self) -> float:
        """Recall across corpus."""
        if self.total_expected_edges == 0:
            return 1.0
        return self.total_true_positives / self.total_expected_edges

    @property
    def overall_precision(self) -> float:
        """Precision across corpus."""
        found = self.total_true_positives + self.total_false_positives
        if found == 0:
            return 1.0 if self.total_expected_edges == 0 else 0.0
        return self.total_true_positives / found

    @property
    def overall_f1(self) -> float:
        """F1 score across corpus."""
        if self.overall_recall + self.overall_precision == 0:
            return 0.0
        return (
            2
            * (self.overall_precision * self.overall_recall)
            / (self.overall_precision + self.overall_recall)
        )

    @property
    def perfect_component_journeys(self) -> int:
        """Count of journeys with correct component count."""
        return sum(
            1 for j in self.journey_evaluations if j.component_correctness
        )

    def recall_by_category(self, category: str) -> float | None:
        """Recall for journeys in given category."""
        journeys = [j for j in self.journey_evaluations if category in j.journey_id]
        if not journeys:
            return None
        total_expected = sum(j.expected_edges for j in journeys)
        if total_expected == 0:
            return 1.0
        total_tp = sum(j.true_positives for j in journeys)
        return total_tp / total_expected

    def recall_by_difficulty(self, difficulty: str) -> float | None:
        """Recall for journeys of given difficulty."""
        # Difficulty would need to be stored in JourneyEvaluation
        # This is a placeholder for future enhancement
        return None

    def format_report(self) -> str:
        """Generate human-readable report."""
        lines = [
            "╔════════════════════════════════════════════════════════════╗",
            "║           REALISTIC CORPUS EVALUATION REPORT               ║",
            "╚════════════════════════════════════════════════════════════╝",
            "",
            f"Total Journeys:        {self.total_journeys}",
            f"Expected Edges:        {self.total_expected_edges}",
            f"Found Edges (TP+FP):   {self.total_true_positives + self.total_false_positives}",
            f"True Positives:        {self.total_true_positives}",
            f"False Positives:       {self.total_false_positives}",
            f"False Negatives:       {self.total_false_negatives}",
            "",
            f"Overall Recall:        {self.overall_recall:.2%}",
            f"Overall Precision:     {self.overall_precision:.2%}",
            f"Overall F1 Score:      {self.overall_f1:.3f}",
            "",
            f"Perfect Components:    {self.perfect_component_journeys}/{self.total_journeys}",
            "",
            "Per-Journey Breakdown:",
            "─" * 60,
        ]

        for j in self.journey_evaluations:
            lines.append(
                f"{j.journey_id:30} Recall:{j.recall:5.1%} "
                f"Precision:{j.precision:5.1%} F1:{j.f1_score:.3f} "
                f"Components:{'✓' if j.component_correctness else '✗'}"
            )

        return "\n".join(lines)
