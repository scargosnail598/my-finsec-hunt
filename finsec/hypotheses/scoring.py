"""Canonical hypothesis score, priority, and ranking decisions."""

from dataclasses import dataclass

from finsec.hypotheses.domain import HypothesisPriority, HypothesisScores


@dataclass(frozen=True)
class CanonicalScoringResult:
    """One additive score and the only supported priority interpretation."""

    scores: HypothesisScores
    priority: HypothesisPriority

    @property
    def ranking_key(self) -> tuple[int, int, int, int, int, int]:
        priority_rank = {"P1": 0, "P2": 1, "P3": 2}
        return (
            priority_rank[self.priority],
            -self.scores.total,
            -self.scores.impact,
            -self.scores.confidence,
            -self.scores.likelihood,
            -self.scores.testability,
        )


def canonical_scoring(
    impact: int,
    likelihood: int,
    confidence: int,
    testability: int,
) -> CanonicalScoringResult:
    """Build a validated additive score and apply the documented P1 threshold."""

    scores = HypothesisScores(
        impact=impact,
        likelihood=likelihood,
        confidence=confidence,
        testability=testability,
        total=impact + likelihood + confidence + testability,
    )
    priority: HypothesisPriority
    if scores.impact >= 4 and scores.total >= 14:
        priority = "P1"
    elif scores.total >= 10:
        priority = "P2"
    else:
        priority = "P3"
    return CanonicalScoringResult(scores=scores, priority=priority)


def canonicalize_scores(scores: HypothesisScores) -> CanonicalScoringResult:
    """Re-evaluate an existing score through the canonical priority rule."""

    return canonical_scoring(
        scores.impact,
        scores.likelihood,
        scores.confidence,
        scores.testability,
    )
