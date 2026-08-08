"""Read-only before/after evaluation for BLH research queue presentation."""

from __future__ import annotations

import json
import re
from collections import Counter
from collections.abc import Mapping
from pathlib import Path

from pydantic import BaseModel, ConfigDict

from finsec.behavior.analysis import load_business_invariants, load_logic_presentation
from finsec.behavior.domain import HypothesisCluster, HypothesisReadiness, LogicHypothesis
from finsec.behavior.hypothesis_precision import cluster_is_visible, rank_hypothesis_clusters
from finsec.config.workspace import WorkspacePaths
from finsec.hypotheses.generator import load_hypotheses


class QueueEvaluationModel(BaseModel):
    """Keep comparison artifacts deterministic and typo-resistant."""

    model_config = ConfigDict(extra="forbid")


class QueueSnapshot(QueueEvaluationModel):
    active_hypotheses: int
    research_tasks: int
    raw_candidates: int
    unique_semantic_hypotheses: int
    clusters: int
    visible_research_items: int
    exact_duplicates: int
    semantic_duplicates: int
    self_referential_hypotheses: int
    malformed_label_hypotheses: int
    actor_binding_visible_items: int
    resource_switch_visible_items: int
    test_ready_with_blockers: int
    top_10_family_distribution: dict[str, int]
    top_20_family_distribution: dict[str, int]
    research_queue_compression_ratio: float
    evidence_provenance_loss: int


class QueueComparison(QueueEvaluationModel):
    version: int = 1
    workspace: str
    scope: str = "QUEUE_QUALITY_ONLY_NOT_REAL_WORLD_PRECISION"
    before: QueueSnapshot
    after: QueueSnapshot


def _score(item: LogicHypothesis) -> int:
    return (
        item.score.impact
        + item.score.likelihood
        + item.score.confidence
        + item.score.test_readiness
    )


def _malformed(value: str) -> bool:
    lowered = value.lower()
    return bool(
        re.search(r"(?:^|\s)(?:f0|e[0-9a-f])(?:\s+[0-9a-f]{2}){2,}", lowered)
        or re.search(r"%[0-9a-f]{2}", lowered)
    )


def _old_visible_backlog_record(item: object) -> bool:
    kind = getattr(item, "kind", None)
    disposition = getattr(item, "disposition", None)
    return kind == "RESEARCH_TASK" or (kind == "SECURITY_HYPOTHESIS" and disposition == "ACTIVE")


def _self_referential(
    hypotheses: list[LogicHypothesis], invariant_by_id: Mapping[str, object]
) -> int:
    count = 0
    for item in hypotheses:
        if item.family not in {"OUT_OF_ORDER_EXECUTION", "STEP_SKIPPING"}:
            continue
        invariant = invariant_by_id.get(item.invariant_id)
        prerequisite = getattr(invariant, "prerequisite_action", None)
        dependent = getattr(invariant, "dependent_action", None)
        if prerequisite is not None and prerequisite == dependent:
            count += 1
    return count


def _family_distribution_hypotheses(
    hypotheses: list[LogicHypothesis], limit: int
) -> dict[str, int]:
    ranked = sorted(hypotheses, key=lambda item: (-_score(item), item.id))[:limit]
    return dict(sorted(Counter(item.family for item in ranked).items()))


def _family_distribution_clusters(clusters: list[HypothesisCluster], limit: int) -> dict[str, int]:
    return dict(
        sorted(
            Counter(
                item.semantics.vulnerability_family
                for item in rank_hypothesis_clusters(clusters)[:limit]
            ).items()
        )
    )


def evaluate_workspace_queue(workspace: WorkspacePaths) -> QueueComparison:
    """Compare legacy row presentation with canonical clusters without writing the workspace."""

    store = load_logic_presentation(workspace)
    backlog = load_hypotheses(workspace).hypotheses
    invariant_by_id = {
        item.id: item for item in load_business_invariants(workspace).business_invariants
    }
    visible_clusters = [item for item in store.clusters if cluster_is_visible(item)]
    visible_cluster_ids = {item.id for item in visible_clusters}
    members = {
        member_id for cluster in store.clusters for member_id in cluster.member_hypothesis_ids
    }
    hypothesis_by_id = {item.id: item for item in store.hypotheses}
    non_logic = [item for item in backlog if item.category != "business_logic"]
    after_active = sum(
        item.kind == "SECURITY_HYPOTHESIS" and item.disposition == "ACTIVE" for item in non_logic
    ) + sum(
        hypothesis_by_id[cluster.representative_hypothesis_id].kind == "SECURITY_HYPOTHESIS"
        for cluster in visible_clusters
    )
    after_tasks = sum(
        item.kind == "RESEARCH_TASK" and not item.disposition.startswith("SUPPRESSED_")
        for item in non_logic
    ) + sum(
        hypothesis_by_id[cluster.representative_hypothesis_id].kind == "RESEARCH_TASK"
        for cluster in visible_clusters
    )
    before_visible_backlog = [item for item in backlog if _old_visible_backlog_record(item)]
    before_fingerprints = [item.fingerprint for item in store.hypotheses]
    before = QueueSnapshot(
        active_hypotheses=sum(
            item.kind == "SECURITY_HYPOTHESIS" and item.disposition == "ACTIVE" for item in backlog
        ),
        research_tasks=sum(item.kind == "RESEARCH_TASK" for item in backlog),
        raw_candidates=len(store.hypotheses),
        unique_semantic_hypotheses=len(set(before_fingerprints)),
        clusters=0,
        visible_research_items=len(store.hypotheses),
        exact_duplicates=len(before_fingerprints) - len(set(before_fingerprints)),
        semantic_duplicates=len(store.hypotheses) - len(store.clusters),
        self_referential_hypotheses=_self_referential(store.hypotheses, invariant_by_id),
        malformed_label_hypotheses=sum(_malformed(item.title) for item in before_visible_backlog),
        actor_binding_visible_items=sum(item.family == "ACTOR_SWITCH" for item in store.hypotheses),
        resource_switch_visible_items=sum(
            item.family == "RESOURCE_SWITCH" for item in store.hypotheses
        ),
        test_ready_with_blockers=sum(
            item.readiness == HypothesisReadiness.TEST_READY and bool(item.readiness_blockers)
            for item in store.hypotheses
        ),
        top_10_family_distribution=_family_distribution_hypotheses(store.hypotheses, 10),
        top_20_family_distribution=_family_distribution_hypotheses(store.hypotheses, 20),
        research_queue_compression_ratio=1.0 if store.hypotheses else 0.0,
        evidence_provenance_loss=0,
    )
    after = QueueSnapshot(
        active_hypotheses=after_active,
        research_tasks=after_tasks,
        raw_candidates=len(store.hypotheses),
        unique_semantic_hypotheses=len(store.clusters),
        clusters=len(store.clusters),
        visible_research_items=len(visible_clusters),
        exact_duplicates=0,
        semantic_duplicates=len(visible_cluster_ids) - len(set(visible_cluster_ids)),
        self_referential_hypotheses=sum(
            item.semantics.vulnerability_family in {"OUT_OF_ORDER_EXECUTION", "STEP_SKIPPING"}
            and len(item.semantics.prerequisite_dimension) == 2
            and item.semantics.prerequisite_dimension[0] == item.semantics.prerequisite_dimension[1]
            for item in visible_clusters
        ),
        malformed_label_hypotheses=sum(_malformed(item.title) for item in visible_clusters),
        actor_binding_visible_items=sum(
            item.semantics.vulnerability_family == "ACTOR_SWITCH" for item in visible_clusters
        ),
        resource_switch_visible_items=sum(
            item.semantics.vulnerability_family == "RESOURCE_SWITCH" for item in visible_clusters
        ),
        test_ready_with_blockers=sum(
            item.readiness == HypothesisReadiness.TEST_READY and bool(item.readiness_blockers)
            for item in visible_clusters
        ),
        top_10_family_distribution=_family_distribution_clusters(store.clusters, 10),
        top_20_family_distribution=_family_distribution_clusters(store.clusters, 20),
        research_queue_compression_ratio=(
            len(visible_clusters) / len(store.hypotheses) if store.hypotheses else 0.0
        ),
        evidence_provenance_loss=len({item.id for item in store.hypotheses} - members),
    )
    return QueueComparison(workspace=workspace.root.name, before=before, after=after)


def render_queue_comparison_markdown(comparison: QueueComparison) -> str:
    """Render a deterministic queue-quality comparison table."""

    rows = [
        (
            "Active hypotheses",
            comparison.before.active_hypotheses,
            comparison.after.active_hypotheses,
        ),
        ("Research tasks", comparison.before.research_tasks, comparison.after.research_tasks),
        ("Raw candidates", comparison.before.raw_candidates, comparison.after.raw_candidates),
        (
            "Unique semantic hypotheses",
            comparison.before.unique_semantic_hypotheses,
            comparison.after.unique_semantic_hypotheses,
        ),
        (
            "Visible research items",
            comparison.before.visible_research_items,
            comparison.after.visible_research_items,
        ),
        (
            "Semantic duplicates",
            comparison.before.semantic_duplicates,
            comparison.after.semantic_duplicates,
        ),
        (
            "Self-referential hypotheses",
            comparison.before.self_referential_hypotheses,
            comparison.after.self_referential_hypotheses,
        ),
        (
            "Malformed-label hypotheses",
            comparison.before.malformed_label_hypotheses,
            comparison.after.malformed_label_hypotheses,
        ),
        (
            "Actor-binding visible items",
            comparison.before.actor_binding_visible_items,
            comparison.after.actor_binding_visible_items,
        ),
        (
            "Resource-switch visible items",
            comparison.before.resource_switch_visible_items,
            comparison.after.resource_switch_visible_items,
        ),
        (
            "Evidence/provenance loss",
            comparison.before.evidence_provenance_loss,
            comparison.after.evidence_provenance_loss,
        ),
    ]
    lines = [
        f"# Queue Quality Comparison: {comparison.workspace}",
        "",
        "This is a read-only queue-quality comparison, not a real-world precision claim.",
        "",
        "| Metric | Before | After |",
        "| --- | ---: | ---: |",
        *[f"| {label} | {before} | {after} |" for label, before, after in rows],
        "",
        "## Top-20 Family Distribution",
        "",
        f"Before: `{json.dumps(comparison.before.top_20_family_distribution, sort_keys=True)}`",
        "",
        f"After: `{json.dumps(comparison.after.top_20_family_distribution, sort_keys=True)}`",
        "",
    ]
    return "\n".join(lines)


def write_queue_comparison(
    comparison: QueueComparison,
    json_path: Path,
    markdown_path: Path,
) -> None:
    """Write deterministic queue comparison artifacts to explicit paths."""

    json_path.parent.mkdir(parents=True, exist_ok=True)
    markdown_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(
        json.dumps(comparison.model_dump(mode="json"), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    markdown_path.write_text(
        render_queue_comparison_markdown(comparison), encoding="utf-8", newline="\n"
    )
