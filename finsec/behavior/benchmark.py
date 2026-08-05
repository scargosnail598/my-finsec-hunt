"""Deterministic labeled benchmark for workflow and hypothesis precision."""

from __future__ import annotations

import json
import re
from collections import Counter
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlencode

from pydantic import BaseModel, ConfigDict, Field

from finsec.behavior.analysis import (
    analyze_business_logic,
    load_business_invariants,
    load_logic_hypotheses,
)
from finsec.behavior.reconstruction import (
    load_propagation,
    load_workflow_instances,
)
from finsec.config.workspace import WorkspacePaths, create_workspace
from finsec.hypotheses.generator import generate_hypotheses, load_hypotheses
from finsec.ingest.har import ingest_har
from finsec.modeling.generator import generate_model
from finsec.modeling.invariants import generate_invariants
from finsec.modeling.models import ObservationStore
from finsec.normalization.inventory import build_inventory
from finsec.utils.yaml_store import load_yaml, write_yaml

RelationshipType = Literal[
    "CAUSAL_HARD",
    "CONTEXT_SOFT",
    "REPLAY_RELATED",
    "CROSS_ACTOR_COMPARISON",
]


class BenchmarkModel(BaseModel):
    """Reject accidental drift in the compact benchmark contract."""

    model_config = ConfigDict(extra="forbid")


class BenchmarkEntry(BenchmarkModel):
    label: str
    offset_seconds: int = Field(ge=0)
    method: str
    path: str
    query: dict[str, list[str]] = Field(default_factory=dict)
    request: dict[str, Any] | None = None
    response: dict[str, Any]
    request_headers: dict[str, str] = Field(default_factory=dict)
    response_headers: dict[str, str] = Field(default_factory=dict)
    status: int = Field(default=200, ge=100, le=599)


class BenchmarkCapture(BenchmarkModel):
    name: str
    actor: str
    entries: list[BenchmarkEntry]


class RelationshipExpectation(BenchmarkModel):
    left: str
    right: str
    relationship_type: RelationshipType


class HypothesisExpectation(BenchmarkModel):
    key: str
    family: str
    affected_action: str
    evidence_any: list[str] = Field(default_factory=list)


class DatasetLabels(BenchmarkModel):
    same_workflow: list[tuple[str, str]] = Field(default_factory=list)
    different_workflow: list[tuple[str, str]] = Field(default_factory=list)
    unknown_workflow: list[tuple[str, str]] = Field(default_factory=list)
    expected_causal_edges: list[tuple[str, str]] = Field(default_factory=list)
    forbidden_edges: list[tuple[str, str]] = Field(default_factory=list)
    unknown_edges: list[tuple[str, str]] = Field(default_factory=list)
    same_family: list[tuple[str, str]] = Field(default_factory=list)
    different_family: list[tuple[str, str]] = Field(default_factory=list)
    expected_relationships: list[RelationshipExpectation] = Field(default_factory=list)
    true_prerequisites: list[tuple[str, str]] = Field(default_factory=list)
    false_adjacency: list[tuple[str, str]] = Field(default_factory=list)
    unknown_prerequisites: list[tuple[str, str]] = Field(default_factory=list)
    expected_hypotheses: list[HypothesisExpectation] = Field(default_factory=list)
    forbidden_hypotheses: list[HypothesisExpectation] = Field(default_factory=list)
    unknown_hypotheses: list[HypothesisExpectation] = Field(default_factory=list)


class BenchmarkDataset(BenchmarkModel):
    id: str
    host: str
    notes: list[str] = Field(default_factory=list)
    captures: list[BenchmarkCapture]
    labels: DatasetLabels


class BenchmarkDefinition(BenchmarkModel):
    version: Literal[1] = 1
    datasets: list[BenchmarkDataset]


class ClassificationCounts(BenchmarkModel):
    true_positive: int = 0
    false_positive: int = 0
    false_negative: int = 0


class ClassificationMetrics(BenchmarkModel):
    precision: float
    recall: float
    f1: float
    counts: ClassificationCounts


class HypothesisKCounts(BenchmarkModel):
    expected_predictions: int = 0
    forbidden_predictions: int = 0
    expected_labels_found: int = 0
    expected_labels_total: int = 0


class DatasetMetrics(BenchmarkModel):
    dataset: str
    workflow_boundary: ClassificationMetrics
    workflow_family_boundary: ClassificationMetrics
    causal_edges: ClassificationMetrics
    forbidden_edge_violations: int
    prerequisites: ClassificationMetrics
    relationship_recall: float
    relationship_found_count: int
    relationship_expected_count: int
    hypothesis_precision_at_k: dict[str, float]
    expected_mutation_recall_at_k: dict[str, float]
    hypothesis_counts_at_k: dict[str, HypothesisKCounts]
    unsupported_hypothesis_rate: float
    unsupported_hypothesis_count: int
    labeled_hypothesis_count: int
    test_ready_with_blockers: int
    hard_link_count: int
    weak_link_count: int
    workflow_instance_count: int
    workflow_family_count: int
    hypothesis_count_by_mutation: dict[str, int]
    disposition_counts: dict[str, int]
    blocker_counts: dict[str, int]
    top_ranked_hypotheses: list[dict[str, Any]]


class BenchmarkReport(BenchmarkModel):
    version: Literal[1] = 1
    k_values: list[int]
    datasets: list[DatasetMetrics]
    aggregate: DatasetMetrics


def load_benchmark(path: Path) -> BenchmarkDefinition:
    """Load fixed labels without treating missing labels as negatives."""

    return BenchmarkDefinition.model_validate_json(path.read_text(encoding="utf-8"))


def _har_entry(host: str, entry: BenchmarkEntry) -> dict[str, Any]:
    timestamp = datetime(2026, 8, 5, 10, tzinfo=UTC) + timedelta(seconds=entry.offset_seconds)
    query_items = [(name, value) for name, values in entry.query.items() for value in values]
    url = f"https://{host}{entry.path}"
    if query_items:
        url = f"{url}?{urlencode(query_items)}"
    request_headers = [
        {"name": name, "value": value} for name, value in sorted(entry.request_headers.items())
    ]
    request: dict[str, Any] = {
        "method": entry.method,
        "url": url,
        "headers": request_headers,
        "queryString": [{"name": name, "value": value} for name, value in query_items],
    }
    if entry.request is not None:
        request_headers.append({"name": "Content-Type", "value": "application/json"})
        request["postData"] = {
            "mimeType": "application/json",
            "text": json.dumps(entry.request, sort_keys=True),
        }
    response_headers = [
        {"name": "Content-Type", "value": "application/json"},
        *[{"name": name, "value": value} for name, value in sorted(entry.response_headers.items())],
    ]
    return {
        "startedDateTime": timestamp.isoformat().replace("+00:00", "Z"),
        "request": request,
        "response": {
            "status": entry.status,
            "headers": response_headers,
            "redirectURL": "",
            "content": {
                "mimeType": "application/json",
                "text": json.dumps(entry.response, sort_keys=True),
            },
        },
    }


def _configure_workspace(workspace: WorkspacePaths, dataset: BenchmarkDataset) -> None:
    target = load_yaml(workspace.target)
    target["scope"]["hosts"] = [dataset.host]
    actors = sorted({capture.actor for capture in dataset.captures})
    target["accounts"] = [
        {
            "id": actor,
            "ownership": "researcher",
            "role": "user",
            "authentication": {
                "auth_type": "none",
                "source": {"type": "none"},
                "status": "NONE",
            },
        }
        for actor in actors
    ]
    target["testing"]["synthetic"] = True
    target["testing"]["local_lab"] = True
    target["testing"]["maximum_requests_per_plan"] = 6
    write_yaml(workspace.target, target)


def _build_dataset(dataset: BenchmarkDataset, root: Path) -> tuple[WorkspacePaths, dict[str, str]]:
    workspace = create_workspace(dataset.id.replace("_", "-"), root / "workspaces")
    _configure_workspace(workspace, dataset)
    captures_root = root / "captures"
    captures_root.mkdir(parents=True, exist_ok=True)
    label_references: dict[str, tuple[str, int]] = {}
    for capture in dataset.captures:
        document = {
            "log": {
                "version": "1.2",
                "creator": {"name": "finsec-workflow-precision-benchmark"},
                "entries": [_har_entry(dataset.host, entry) for entry in capture.entries],
            }
        }
        capture_path = captures_root / f"{capture.name}.har"
        capture_path.write_text(
            json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        result = ingest_har(capture_path, workspace, actor=capture.actor, channel="WEB")
        for index, entry in enumerate(capture.entries):
            label_references[entry.label] = (result.redacted_har.name, index)

    build_inventory(workspace)
    generate_model(workspace)
    generate_invariants(workspace)
    generate_hypotheses(workspace)
    analyze_business_logic(workspace)

    observations = ObservationStore.model_validate(load_yaml(workspace.observations))
    observation_ids: dict[str, str] = {}
    for label, (capture_name, index) in label_references.items():
        suffix = f"{capture_name}#entry-{index}"
        observation = next(
            item for item in observations.observations if item.source_reference.endswith(suffix)
        )
        observation_ids[label] = observation.id
    return workspace, observation_ids


def _unordered(left: str, right: str) -> tuple[str, str]:
    first, second = sorted((left, right))
    return first, second


def _classification(
    positive: list[tuple[str, str]],
    negative: list[tuple[str, str]],
    predicted: set[tuple[str, str]],
    *,
    directed: bool = False,
) -> ClassificationMetrics:
    normalize = (lambda pair: pair) if directed else (lambda pair: _unordered(*pair))
    positive_set = {normalize(pair) for pair in positive}
    negative_set = {normalize(pair) for pair in negative}
    true_positive = len(positive_set & predicted)
    false_positive = len(negative_set & predicted)
    false_negative = len(positive_set - predicted)
    counts = ClassificationCounts(
        true_positive=true_positive,
        false_positive=false_positive,
        false_negative=false_negative,
    )
    precision = (
        true_positive / (true_positive + false_positive) if true_positive + false_positive else 0.0
    )
    recall = (
        true_positive / (true_positive + false_negative) if true_positive + false_negative else 1.0
    )
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return ClassificationMetrics(precision=precision, recall=recall, f1=f1, counts=counts)


def _prerequisite_pairs(workspace: WorkspacePaths) -> set[tuple[str, str]]:
    pairs: set[tuple[str, str]] = set()
    pattern = re.compile(
        r"^(?P<dependent>[A-Z0-9_]+) appears to require "
        r"(?P<prerequisite>[A-Z0-9_]+) to occur first"
    )
    for invariant in load_business_invariants(workspace).business_invariants:
        if invariant.invariant_type != "ORDERING":
            continue
        prerequisite = getattr(invariant, "prerequisite_action", None)
        dependent = getattr(invariant, "dependent_action", None)
        if isinstance(prerequisite, str) and isinstance(dependent, str):
            pairs.add((prerequisite, dependent))
            continue
        match = pattern.match(invariant.statement)
        if match is not None:
            pairs.add((match.group("prerequisite"), match.group("dependent")))
    return pairs


def _matches_hypothesis(
    expectation: HypothesisExpectation,
    item: Any,
    observation_ids: dict[str, str],
) -> bool:
    if item.family != expectation.family or item.affected_action != expectation.affected_action:
        return False
    expected_evidence = {observation_ids[label] for label in expectation.evidence_any}
    return not expected_evidence or bool(expected_evidence.intersection(item.observation_ids))


def _hypothesis_metrics(
    workspace: WorkspacePaths,
    labels: DatasetLabels,
    observation_ids: dict[str, str],
    k_values: tuple[int, ...],
) -> tuple[
    dict[str, float],
    dict[str, float],
    dict[str, HypothesisKCounts],
    float,
    int,
    int,
    int,
    list[dict[str, Any]],
]:
    hypotheses = load_logic_hypotheses(workspace).hypotheses
    ranked = sorted(
        hypotheses,
        key=lambda item: (
            -(
                item.score.impact
                + item.score.likelihood
                + item.score.confidence
                + item.score.test_readiness
            ),
            item.id,
        ),
    )

    def classification(item: Any) -> str:
        if any(
            _matches_hypothesis(label, item, observation_ids)
            for label in labels.expected_hypotheses
        ):
            return "expected"
        if any(
            _matches_hypothesis(label, item, observation_ids)
            for label in labels.forbidden_hypotheses
        ):
            return "forbidden"
        return "unknown"

    precision_at_k: dict[str, float] = {}
    recall_at_k: dict[str, float] = {}
    counts_at_k: dict[str, HypothesisKCounts] = {}
    for k in k_values:
        selected = ranked[:k]
        classified = [classification(item) for item in selected]
        labeled = [value for value in classified if value != "unknown"]
        precision_at_k[str(k)] = labeled.count("expected") / len(labeled) if labeled else 1.0
        found = {
            expectation.key
            for expectation in labels.expected_hypotheses
            if any(_matches_hypothesis(expectation, item, observation_ids) for item in selected)
        }
        recall_at_k[str(k)] = (
            len(found) / len(labels.expected_hypotheses) if labels.expected_hypotheses else 1.0
        )
        counts_at_k[str(k)] = HypothesisKCounts(
            expected_predictions=labeled.count("expected"),
            forbidden_predictions=labeled.count("forbidden"),
            expected_labels_found=len(found),
            expected_labels_total=len(labels.expected_hypotheses),
        )

    all_classified = [classification(item) for item in ranked]
    labeled_all = [value for value in all_classified if value != "unknown"]
    unsupported_rate = labeled_all.count("forbidden") / len(labeled_all) if labeled_all else 0.0
    unsupported_count = labeled_all.count("forbidden")
    labeled_count = len(labeled_all)
    test_ready_with_blockers = 0
    for item in hypotheses:
        readiness = getattr(item, "readiness", None)
        presented_ready = (
            readiness == "TEST_READY"
            if readiness is not None
            else item.kind == "SECURITY_HYPOTHESIS"
            and item.epistemic_status.value == "TEST_CANDIDATE"
        )
        if presented_ready and item.readiness_blockers:
            test_ready_with_blockers += 1
    top_ranked = [
        {
            "id": item.id,
            "family": item.family,
            "affected_action": item.affected_action,
            "kind": item.kind,
            "readiness": getattr(item, "readiness", None),
            "score_total": item.score.impact
            + item.score.likelihood
            + item.score.confidence
            + item.score.test_readiness,
            "title": item.title,
            "label": classification(item),
        }
        for item in ranked[: max(k_values)]
    ]
    return (
        precision_at_k,
        recall_at_k,
        counts_at_k,
        unsupported_rate,
        unsupported_count,
        labeled_count,
        test_ready_with_blockers,
        top_ranked,
    )


def _evaluate_dataset(
    dataset: BenchmarkDataset, root: Path, k_values: tuple[int, ...]
) -> DatasetMetrics:
    workspace, observation_ids = _build_dataset(dataset, root / dataset.id)
    instances = load_workflow_instances(workspace).workflow_instances
    observation_instance = {
        step.observation_id: instance.id for instance in instances for step in instance.steps
    }
    observation_family = {
        step.observation_id: instance.family_id for instance in instances for step in instance.steps
    }
    predicted_same: set[tuple[str, str]] = set()
    predicted_family: set[tuple[str, str]] = set()
    labels = sorted(observation_ids)
    for index, left in enumerate(labels):
        for right in labels[index + 1 :]:
            left_id = observation_ids[left]
            right_id = observation_ids[right]
            if (
                observation_instance.get(left_id) == observation_instance.get(right_id)
                and observation_instance.get(left_id) is not None
            ):
                predicted_same.add(_unordered(left, right))
            if (
                observation_family.get(left_id) == observation_family.get(right_id)
                and observation_family.get(left_id) is not None
            ):
                predicted_family.add(_unordered(left, right))

    propagation = load_propagation(workspace).propagation_links
    reverse_labels = {value: key for key, value in observation_ids.items()}
    predicted_edges: set[tuple[str, str]] = set()
    predicted_relationships: set[tuple[str, str, str]] = set()
    hard_links = 0
    weak_links = 0
    for link in propagation:
        source_label = reverse_labels.get(link.source_observation_id)
        destination_label = reverse_labels.get(link.destination_observation_id)
        if source_label is None or destination_label is None:
            continue
        relationship_type = str(getattr(link, "relationship_type", "CAUSAL_HARD"))
        predicted_relationships.add(
            (*_unordered(source_label, destination_label), relationship_type)
        )
        if relationship_type == "CAUSAL_HARD":
            predicted_edges.add((source_label, destination_label))
            hard_links += 1
        else:
            weak_links += 1

    relationship_expected = {
        (*_unordered(item.left, item.right), item.relationship_type)
        for item in dataset.labels.expected_relationships
    }
    relationship_found = len(relationship_expected & predicted_relationships)
    relationship_recall = (
        relationship_found / len(relationship_expected) if relationship_expected else 1.0
    )
    workflow_boundary = _classification(
        dataset.labels.same_workflow, dataset.labels.different_workflow, predicted_same
    )
    family_boundary = _classification(
        dataset.labels.same_family, dataset.labels.different_family, predicted_family
    )
    causal_edges = _classification(
        dataset.labels.expected_causal_edges,
        dataset.labels.forbidden_edges,
        predicted_edges,
        directed=True,
    )
    prerequisites = _classification(
        dataset.labels.true_prerequisites,
        dataset.labels.false_adjacency,
        _prerequisite_pairs(workspace),
        directed=True,
    )
    (
        precision_at_k,
        recall_at_k,
        hypothesis_counts,
        unsupported_rate,
        unsupported_count,
        labeled_count,
        ready_blocked,
        top_ranked,
    ) = _hypothesis_metrics(workspace, dataset.labels, observation_ids, k_values)
    logic = load_logic_hypotheses(workspace).hypotheses
    backlog = load_hypotheses(workspace).hypotheses
    return DatasetMetrics(
        dataset=dataset.id,
        workflow_boundary=workflow_boundary,
        workflow_family_boundary=family_boundary,
        causal_edges=causal_edges,
        forbidden_edge_violations=causal_edges.counts.false_positive,
        prerequisites=prerequisites,
        relationship_recall=relationship_recall,
        relationship_found_count=relationship_found,
        relationship_expected_count=len(relationship_expected),
        hypothesis_precision_at_k=precision_at_k,
        expected_mutation_recall_at_k=recall_at_k,
        hypothesis_counts_at_k=hypothesis_counts,
        unsupported_hypothesis_rate=unsupported_rate,
        unsupported_hypothesis_count=unsupported_count,
        labeled_hypothesis_count=labeled_count,
        test_ready_with_blockers=ready_blocked,
        hard_link_count=hard_links,
        weak_link_count=weak_links,
        workflow_instance_count=len(instances),
        workflow_family_count=len({item.family_id for item in instances}),
        hypothesis_count_by_mutation=dict(sorted(Counter(item.family for item in logic).items())),
        disposition_counts=dict(
            sorted(
                Counter(
                    item.disposition for item in backlog if item.category == "business_logic"
                ).items()
            )
        ),
        blocker_counts=dict(
            sorted(
                Counter(blocker for item in logic for blocker in item.readiness_blockers).items()
            )
        ),
        top_ranked_hypotheses=top_ranked,
    )


def _sum_classification(
    datasets: list[DatasetMetrics],
    field: Literal[
        "workflow_boundary", "workflow_family_boundary", "causal_edges", "prerequisites"
    ],
) -> ClassificationMetrics:
    counts = ClassificationCounts(
        true_positive=sum(getattr(item, field).counts.true_positive for item in datasets),
        false_positive=sum(getattr(item, field).counts.false_positive for item in datasets),
        false_negative=sum(getattr(item, field).counts.false_negative for item in datasets),
    )
    precision = (
        counts.true_positive / (counts.true_positive + counts.false_positive)
        if counts.true_positive + counts.false_positive
        else 0.0
    )
    recall = (
        counts.true_positive / (counts.true_positive + counts.false_negative)
        if counts.true_positive + counts.false_negative
        else 1.0
    )
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return ClassificationMetrics(precision=precision, recall=recall, f1=f1, counts=counts)


def evaluate_benchmark(
    definition: BenchmarkDefinition,
    workspace_root: Path,
    *,
    k_values: tuple[int, ...] = (10,),
) -> BenchmarkReport:
    """Run every labeled dataset through the offline deterministic pipeline."""

    datasets = [
        _evaluate_dataset(dataset, workspace_root, k_values) for dataset in definition.datasets
    ]
    hypothesis_counts = {
        str(k): HypothesisKCounts(
            expected_predictions=sum(
                item.hypothesis_counts_at_k[str(k)].expected_predictions for item in datasets
            ),
            forbidden_predictions=sum(
                item.hypothesis_counts_at_k[str(k)].forbidden_predictions for item in datasets
            ),
            expected_labels_found=sum(
                item.hypothesis_counts_at_k[str(k)].expected_labels_found for item in datasets
            ),
            expected_labels_total=sum(
                item.hypothesis_counts_at_k[str(k)].expected_labels_total for item in datasets
            ),
        )
        for k in k_values
    }
    aggregate_relationship_found = sum(item.relationship_found_count for item in datasets)
    aggregate_relationship_expected = sum(item.relationship_expected_count for item in datasets)
    aggregate_unsupported = sum(item.unsupported_hypothesis_count for item in datasets)
    aggregate_labeled = sum(item.labeled_hypothesis_count for item in datasets)
    aggregate = DatasetMetrics(
        dataset="aggregate",
        workflow_boundary=_sum_classification(datasets, "workflow_boundary"),
        workflow_family_boundary=_sum_classification(datasets, "workflow_family_boundary"),
        causal_edges=_sum_classification(datasets, "causal_edges"),
        forbidden_edge_violations=sum(item.forbidden_edge_violations for item in datasets),
        prerequisites=_sum_classification(datasets, "prerequisites"),
        relationship_recall=(
            aggregate_relationship_found / aggregate_relationship_expected
            if aggregate_relationship_expected
            else 1.0
        ),
        relationship_found_count=aggregate_relationship_found,
        relationship_expected_count=aggregate_relationship_expected,
        hypothesis_precision_at_k={
            str(k): (
                hypothesis_counts[str(k)].expected_predictions
                / (
                    hypothesis_counts[str(k)].expected_predictions
                    + hypothesis_counts[str(k)].forbidden_predictions
                )
                if hypothesis_counts[str(k)].expected_predictions
                + hypothesis_counts[str(k)].forbidden_predictions
                else 1.0
            )
            for k in k_values
        },
        expected_mutation_recall_at_k={
            str(k): (
                hypothesis_counts[str(k)].expected_labels_found
                / hypothesis_counts[str(k)].expected_labels_total
                if hypothesis_counts[str(k)].expected_labels_total
                else 1.0
            )
            for k in k_values
        },
        hypothesis_counts_at_k=hypothesis_counts,
        unsupported_hypothesis_rate=(
            aggregate_unsupported / aggregate_labeled if aggregate_labeled else 0.0
        ),
        unsupported_hypothesis_count=aggregate_unsupported,
        labeled_hypothesis_count=aggregate_labeled,
        test_ready_with_blockers=sum(item.test_ready_with_blockers for item in datasets),
        hard_link_count=sum(item.hard_link_count for item in datasets),
        weak_link_count=sum(item.weak_link_count for item in datasets),
        workflow_instance_count=sum(item.workflow_instance_count for item in datasets),
        workflow_family_count=sum(item.workflow_family_count for item in datasets),
        hypothesis_count_by_mutation=dict(
            sorted(
                sum(
                    (Counter(item.hypothesis_count_by_mutation) for item in datasets), Counter()
                ).items()
            )
        ),
        disposition_counts=dict(
            sorted(sum((Counter(item.disposition_counts) for item in datasets), Counter()).items())
        ),
        blocker_counts=dict(
            sorted(sum((Counter(item.blocker_counts) for item in datasets), Counter()).items())
        ),
        top_ranked_hypotheses=[],
    )
    return BenchmarkReport(k_values=list(k_values), datasets=datasets, aggregate=aggregate)


def render_markdown(report: BenchmarkReport) -> str:
    """Render a concise deterministic summary suitable for CI logs or review notes."""

    lines = [
        "# Workflow Precision Benchmark",
        "",
        "| Dataset | Boundary P/R/F1 | Edge P/R/F1 | Forbidden edges | "
        "Prerequisite P/R | P@10 | Mutation recall@10 | Unsupported | Ready + blockers |",
        "| --- | --- | --- | ---: | --- | ---: | ---: | ---: | ---: |",
    ]
    for item in [*report.datasets, report.aggregate]:
        lines.append(
            "| "
            + " | ".join(
                [
                    item.dataset,
                    f"{item.workflow_boundary.precision:.3f}/{item.workflow_boundary.recall:.3f}/{item.workflow_boundary.f1:.3f}",
                    f"{item.causal_edges.precision:.3f}/{item.causal_edges.recall:.3f}/{item.causal_edges.f1:.3f}",
                    str(item.forbidden_edge_violations),
                    f"{item.prerequisites.precision:.3f}/{item.prerequisites.recall:.3f}",
                    f"{item.hypothesis_precision_at_k.get('10', 0.0):.3f}",
                    f"{item.expected_mutation_recall_at_k.get('10', 0.0):.3f}",
                    f"{item.unsupported_hypothesis_rate:.3f}",
                    str(item.test_ready_with_blockers),
                ]
            )
            + " |"
        )
    return "\n".join(lines) + "\n"


def write_report(report: BenchmarkReport, json_path: Path, markdown_path: Path) -> None:
    """Persist machine-readable and human-readable benchmark output."""

    json_path.parent.mkdir(parents=True, exist_ok=True)
    markdown_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(
        json.dumps(report.model_dump(mode="json"), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    markdown_path.write_text(render_markdown(report), encoding="utf-8")
