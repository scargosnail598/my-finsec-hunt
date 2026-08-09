"""Like-for-like evaluation for unified hypothesis queue presentation."""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from finsec.config.workspace import WorkspacePaths
from finsec.hypotheses.clustering import presentation_visible
from finsec.hypotheses.domain import HypothesisRecord, HypothesisStore
from finsec.hypotheses.generator import load_hypotheses
from finsec.utils.yaml_store import load_yaml

POPULATION_POLICY: Literal["ALL_BACKLOG_RECORDS_COMMON_PRESENTATION_V1"] = (
    "ALL_BACKLOG_RECORDS_COMMON_PRESENTATION_V1"
)


class QueueEvaluationModel(BaseModel):
    """Keep comparison artifacts deterministic and typo-resistant."""

    model_config = ConfigDict(extra="forbid")


class GeneratorBreakdown(QueueEvaluationModel):
    """Raw and presented counts for one stable ID namespace."""

    raw_records: int = 0
    visible_records: int = 0
    suppressed_records: int = 0
    visible_active_hypotheses: int = 0
    visible_research_tasks: int = 0


class QueueSnapshot(QueueEvaluationModel):
    """One queue measured with the same raw/visible/suppressed population policy."""

    population_policy: Literal["ALL_BACKLOG_RECORDS_COMMON_PRESENTATION_V1"] = POPULATION_POLICY
    total_generated_records: int
    visible_records: int
    visible_active_hypotheses: int
    visible_research_tasks: int
    suppressed_records: int
    suppressed_by_reason: dict[str, int] = Field(default_factory=dict)
    exact_duplicates_collapsed: int
    campaigns: int
    campaign_member_count: int
    campaign_members_by_id: dict[str, int] = Field(default_factory=dict)
    breakdown: dict[Literal["HYP", "BLH"], GeneratorBreakdown]
    readiness_counts: dict[str, int] = Field(default_factory=dict)
    grouping_provenance_loss: int = 0


class ReadinessTransition(QueueEvaluationModel):
    """One stable record whose serialized readiness changed between snapshots."""

    hypothesis_id: str
    before: str
    after: str
    causes: list[str] = Field(default_factory=list)


class QueueComparison(QueueEvaluationModel):
    """Two workspaces evaluated with identical population and visibility rules."""

    version: Literal[2] = 2
    workspace: str
    baseline_workspace: str
    scope: str = "QUEUE_QUALITY_ONLY_NOT_REAL_WORLD_PRECISION"
    population_policy: Literal["ALL_BACKLOG_RECORDS_COMMON_PRESENTATION_V1"] = POPULATION_POLICY
    before: QueueSnapshot
    after: QueueSnapshot
    readiness_transitions: list[ReadinessTransition] = Field(default_factory=list)
    added_record_ids: list[str] = Field(default_factory=list)
    removed_record_ids: list[str] = Field(default_factory=list)
    provenance_loss_count: int = 0


@dataclass(frozen=True)
class _SnapshotDetails:
    snapshot: QueueSnapshot
    ids: frozenset[str]
    readiness_by_id: dict[str, str]
    blocker_codes_by_id: dict[str, tuple[str, ...]]


def _namespace(record: HypothesisRecord) -> Literal["HYP", "BLH"]:
    return "BLH" if record.id.startswith("BLH-") else "HYP"


def _suppression_reason(record: HypothesisRecord) -> str:
    if (
        record.grouping.relationship == "EXACT_DUPLICATE"
        and record.grouping.primary_hypothesis_id != record.id
    ):
        return "EXACT_DUPLICATE"
    if record.presentation.suppression_reason:
        if "authentication-coverage campaign" in record.presentation.suppression_reason.lower():
            return "AUTHENTICATION_COVERAGE_CAMPAIGN"
        if "campaign" in record.presentation.suppression_reason.lower():
            return "CAMPAIGN_PRESENTATION"
        return record.presentation.suppression_reason
    if record.disposition.startswith("SUPPRESSED_"):
        return record.disposition
    return "COMMON_PRESENTATION_FILTER"


def _serialized_readiness(workspace: WorkspacePaths, store: HypothesisStore) -> dict[str, str]:
    """Retain pre-migration readiness values when evaluating a legacy baseline."""

    document = load_yaml(workspace.hypotheses)
    records = document.get("hypotheses") if isinstance(document, dict) else None
    raw = {
        str(item.get("id")): str(item.get("readiness"))
        for item in records or []
        if isinstance(item, dict)
        and isinstance(item.get("id"), str)
        and isinstance(item.get("readiness"), str)
    }
    return {record.id: raw.get(record.id, record.readiness) for record in store.hypotheses}


def _grouping_provenance_loss(store: HypothesisStore) -> int:
    ids = {record.id for record in store.hypotheses}
    referenced: set[str] = set()
    loss: set[str] = set()
    for record in store.hypotheses:
        grouping = record.grouping
        referenced.update(grouping.cluster_member_ids)
        referenced.update(grouping.campaign_member_ids)
        if (
            not record.presentation.visible
            and record.presentation.suppression_reason is not None
            and (
                "duplicate" in record.presentation.suppression_reason.lower()
                or "campaign" in record.presentation.suppression_reason.lower()
            )
            and record.id not in grouping.cluster_member_ids
            and record.id not in grouping.campaign_member_ids
        ):
            loss.add(record.id)
    loss.update(referenced - ids)
    return len(loss)


def _snapshot_details(workspace: WorkspacePaths) -> _SnapshotDetails:
    store = load_hypotheses(workspace)
    records = sorted(store.hypotheses, key=lambda item: item.id)
    visible = [record for record in records if presentation_visible(record)]
    visible_ids = {record.id for record in visible}
    suppressed = [record for record in records if record.id not in visible_ids]
    suppressed_ids = {record.id for record in suppressed}
    readiness_by_id = _serialized_readiness(workspace, store)

    breakdown: dict[Literal["HYP", "BLH"], GeneratorBreakdown] = {}
    for namespace in ("HYP", "BLH"):
        raw_namespace = [record for record in records if _namespace(record) == namespace]
        visible_namespace = [record for record in visible if _namespace(record) == namespace]
        breakdown[namespace] = GeneratorBreakdown(
            raw_records=len(raw_namespace),
            visible_records=len(visible_namespace),
            suppressed_records=len(raw_namespace) - len(visible_namespace),
            visible_active_hypotheses=sum(
                record.kind == "SECURITY_HYPOTHESIS" and record.disposition == "ACTIVE"
                for record in visible_namespace
            ),
            visible_research_tasks=sum(
                record.kind == "RESEARCH_TASK" for record in visible_namespace
            ),
        )

    campaign_members = {
        campaign.id: len(campaign.member_ids)
        for campaign in sorted(store.campaigns, key=lambda x: x.id)
    }
    exact_duplicates = sum(
        record.grouping.relationship == "EXACT_DUPLICATE"
        and record.grouping.primary_hypothesis_id != record.id
        and record.id in suppressed_ids
        for record in records
    )
    blocker_codes = {
        record.id: tuple(sorted(item.code for item in record.readiness_assessment.blockers))
        for record in records
    }
    snapshot = QueueSnapshot(
        total_generated_records=len(records),
        visible_records=len(visible),
        visible_active_hypotheses=sum(
            record.kind == "SECURITY_HYPOTHESIS" and record.disposition == "ACTIVE"
            for record in visible
        ),
        visible_research_tasks=sum(record.kind == "RESEARCH_TASK" for record in visible),
        suppressed_records=len(suppressed),
        suppressed_by_reason=dict(
            sorted(Counter(_suppression_reason(record) for record in suppressed).items())
        ),
        exact_duplicates_collapsed=exact_duplicates,
        campaigns=len(store.campaigns),
        campaign_member_count=sum(campaign_members.values()),
        campaign_members_by_id=campaign_members,
        breakdown=breakdown,
        readiness_counts=dict(sorted(Counter(readiness_by_id.values()).items())),
        grouping_provenance_loss=_grouping_provenance_loss(store),
    )
    return _SnapshotDetails(
        snapshot=snapshot,
        ids=frozenset(record.id for record in records),
        readiness_by_id=readiness_by_id,
        blocker_codes_by_id=blocker_codes,
    )


def snapshot_workspace_queue(workspace: WorkspacePaths) -> QueueSnapshot:
    """Measure one workspace without writing or applying a different visibility filter."""

    return _snapshot_details(workspace).snapshot


def compare_workspace_queues(
    baseline_workspace: WorkspacePaths,
    workspace: WorkspacePaths,
) -> QueueComparison:
    """Compare identical-input workspaces with one shared population and visibility policy."""

    before = _snapshot_details(baseline_workspace)
    after = _snapshot_details(workspace)
    transitions: list[ReadinessTransition] = []
    for hypothesis_id in sorted(before.ids & after.ids):
        previous = before.readiness_by_id[hypothesis_id]
        current = after.readiness_by_id[hypothesis_id]
        if previous == current:
            continue
        blocker_codes = after.blocker_codes_by_id.get(hypothesis_id, ())
        causes = list(blocker_codes) or ["PREREQUISITES_SATISFIED_OR_RECORD_RECLASSIFIED"]
        transitions.append(
            ReadinessTransition(
                hypothesis_id=hypothesis_id,
                before=previous,
                after=current,
                causes=causes,
            )
        )
    removed = sorted(before.ids - after.ids)
    grouping_loss = after.snapshot.grouping_provenance_loss
    return QueueComparison(
        workspace=workspace.root.name,
        baseline_workspace=baseline_workspace.root.name,
        before=before.snapshot,
        after=after.snapshot,
        readiness_transitions=transitions,
        added_record_ids=sorted(after.ids - before.ids),
        removed_record_ids=removed,
        provenance_loss_count=len(removed) + grouping_loss,
    )


def evaluate_workspace_queue(
    workspace: WorkspacePaths,
    *,
    baseline_workspace: WorkspacePaths | None = None,
) -> QueueComparison:
    """Evaluate a workspace against an explicit baseline, or itself for one snapshot report."""

    return compare_workspace_queues(baseline_workspace or workspace, workspace)


def render_queue_comparison_markdown(comparison: QueueComparison) -> str:
    """Render the required like-for-like queue metrics deterministically."""

    rows = [
        (
            "Total generated records",
            comparison.before.total_generated_records,
            comparison.after.total_generated_records,
        ),
        ("Visible records", comparison.before.visible_records, comparison.after.visible_records),
        (
            "Visible active hypotheses",
            comparison.before.visible_active_hypotheses,
            comparison.after.visible_active_hypotheses,
        ),
        (
            "Visible research tasks",
            comparison.before.visible_research_tasks,
            comparison.after.visible_research_tasks,
        ),
        (
            "Suppressed records",
            comparison.before.suppressed_records,
            comparison.after.suppressed_records,
        ),
        (
            "Exact duplicates collapsed",
            comparison.before.exact_duplicates_collapsed,
            comparison.after.exact_duplicates_collapsed,
        ),
        ("Campaigns", comparison.before.campaigns, comparison.after.campaigns),
        (
            "Campaign member count",
            comparison.before.campaign_member_count,
            comparison.after.campaign_member_count,
        ),
        (
            "Grouping provenance loss",
            comparison.before.grouping_provenance_loss,
            comparison.after.grouping_provenance_loss,
        ),
    ]
    lines = [
        f"# Queue Quality Comparison: {comparison.workspace}",
        "",
        "This is a read-only queue-quality comparison, not a real-world precision claim.",
        f"Population policy: `{comparison.population_policy}`.",
        "",
        "| Metric | Before | After |",
        "| --- | ---: | ---: |",
        *[f"| {label} | {before} | {after} |" for label, before, after in rows],
        "",
        "## HYP / BLH Breakdown",
        "",
        "```json",
        json.dumps(
            {
                "before": {
                    key: value.model_dump(mode="json")
                    for key, value in comparison.before.breakdown.items()
                },
                "after": {
                    key: value.model_dump(mode="json")
                    for key, value in comparison.after.breakdown.items()
                },
            },
            indent=2,
            sort_keys=True,
        ),
        "```",
        "",
        "## Suppression Reasons",
        "",
        f"Before: `{json.dumps(comparison.before.suppressed_by_reason, sort_keys=True)}`",
        "",
        f"After: `{json.dumps(comparison.after.suppressed_by_reason, sort_keys=True)}`",
        "",
        "## Readiness Transitions",
        "",
        *(
            [
                f"- {item.hypothesis_id}: {item.before} -> {item.after} ({', '.join(item.causes)})"
                for item in comparison.readiness_transitions
            ]
            or ["- None."]
        ),
        "",
        f"Provenance loss count: **{comparison.provenance_loss_count}**.",
        "",
    ]
    return "\n".join(lines)


def write_queue_comparison(
    comparison: QueueComparison,
    json_path: Path,
    markdown_path: Path,
) -> None:
    """Write deterministic comparison artifacts to explicit paths."""

    json_path.parent.mkdir(parents=True, exist_ok=True)
    markdown_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(
        json.dumps(comparison.model_dump(mode="json"), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    markdown_path.write_text(
        render_queue_comparison_markdown(comparison), encoding="utf-8", newline="\n"
    )
