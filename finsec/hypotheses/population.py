"""Canonical raw and presentation-visible hypothesis queue populations."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from finsec.hypotheses.clustering import presentation_visible
from finsec.hypotheses.domain import HypothesisRecord


@dataclass(frozen=True)
class HypothesisPopulation:
    """One queue measured with stable raw and visible definitions."""

    raw_records: tuple[HypothesisRecord, ...]
    visible_records: tuple[HypothesisRecord, ...]
    visible_active_hypotheses: tuple[HypothesisRecord, ...]
    visible_research_tasks: tuple[HypothesisRecord, ...]

    @property
    def raw_active_hypotheses(self) -> int:
        return sum(
            item.kind == "SECURITY_HYPOTHESIS" and item.disposition == "ACTIVE"
            for item in self.raw_records
        )

    @property
    def raw_research_tasks(self) -> int:
        return sum(item.kind == "RESEARCH_TASK" for item in self.raw_records)


def hypothesis_population(records: Iterable[HypothesisRecord]) -> HypothesisPopulation:
    """Return the shared queue population used by every ordinary surface."""

    raw = tuple(sorted(records, key=lambda item: item.id))
    visible = tuple(item for item in raw if presentation_visible(item))
    active = tuple(
        item
        for item in visible
        if item.kind == "SECURITY_HYPOTHESIS" and item.disposition == "ACTIVE"
    )
    research = tuple(item for item in visible if item.kind == "RESEARCH_TASK")
    return HypothesisPopulation(
        raw_records=raw,
        visible_records=visible,
        visible_active_hypotheses=active,
        visible_research_tasks=research,
    )
