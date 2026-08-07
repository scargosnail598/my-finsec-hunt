"""Deterministic labeled benchmark for workflow and hypothesis precision."""

from __future__ import annotations

import json
import re
from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from itertools import combinations
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
    load_workflow_families,
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
    host: str | None = None
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
    semantic_key: str | None = None


class JourneyExpectation(BenchmarkModel):
    key: str
    steps: list[str] = Field(min_length=2)
    max_fragments: int = Field(default=1, ge=1)


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
    expected_journeys: list[JourneyExpectation] = Field(default_factory=list)


class BenchmarkDataset(BenchmarkModel):
    id: str
    host: str
    notes: list[str] = Field(default_factory=list)
    captures: list[BenchmarkCapture]
    labels: DatasetLabels
    label_policy: Literal["EXPLORATORY", "COMPLETE_TOP_K"] = "EXPLORATORY"


class BenchmarkDefinition(BenchmarkModel):
    version: Literal[1, 2] = 1
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
    emitted_predictions: int = 0
    labeled_predictions: int = 0
    expected_predictions: int = 0
    forbidden_predictions: int = 0
    unknown_predictions: int = 0
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
    labeled_precision_at_k: dict[str, float]
    label_coverage_at_k: dict[str, float]
    unknown_rate_at_k: dict[str, float]
    precision_lower_bound_at_k: dict[str, float]
    known_forbidden_hypothesis_rate_at_k: dict[str, float]
    # Deprecated alias: this is labeled precision, not precision over every emitted output.
    hypothesis_precision_at_k: dict[str, float]
    expected_mutation_recall_at_k: dict[str, float]
    hypothesis_counts_at_k: dict[str, HypothesisKCounts]
    unsupported_hypothesis_rate: float
    unsupported_hypothesis_count: int
    labeled_hypothesis_count: int
    test_ready_with_blockers: int
    hard_link_count: int
    weak_link_count: int
    total_reconstructed_workflows: int
    singleton_workflow_count: int
    singleton_workflow_rate: float
    expected_multi_step_journey_count: int
    fully_retained_multi_step_journey_count: int
    fully_retained_multi_step_journey_rate: float
    fragmented_expected_journey_count: int
    fragments_per_labeled_journey: dict[str, int]
    under_merge_pair_count: int
    over_merge_pair_count: int
    known_journey_pair_count: int
    known_journey_retained_pair_count: int
    known_journey_component_recall: float
    journey_order_violation_count: int
    forbidden_workflow_merge_count: int
    workflow_instance_count: int
    workflow_family_count: int
    hypothesis_count_by_mutation: dict[str, int]
    disposition_counts: dict[str, int]
    blocker_counts: dict[str, int]
    top_ranked_hypotheses: list[dict[str, Any]]


class BenchmarkReport(BenchmarkModel):
    version: Literal[2] = 2
    k_values: list[int]
    datasets: list[DatasetMetrics]
    aggregate: DatasetMetrics


class QualityGateThresholds(BenchmarkModel):
    k: int = Field(default=10, ge=1)
    max_forbidden_hard_edges: int = Field(default=0, ge=0)
    max_forbidden_workflow_merges: int = Field(default=0, ge=0)
    min_labeled_precision_at_k: float = Field(default=1.0, ge=0, le=1)
    min_label_coverage_at_k: float = Field(default=1.0, ge=0, le=1)
    min_expected_mutation_recall_at_k: float = Field(default=1.0, ge=0, le=1)
    max_test_ready_with_blockers: int = Field(default=0, ge=0)
    max_fragmented_expected_journeys: int = Field(default=0, ge=0)
    max_journey_order_violations: int = Field(default=0, ge=0)
    require_deterministic_output: bool = True


class QualityGateConfiguration(BenchmarkModel):
    version: Literal[1] = 1
    fixture: str
    thresholds: QualityGateThresholds


class BenchmarkLabelError(ValueError):
    """Raised when checked-in labels are ambiguous, incomplete, or orphaned."""


class BenchmarkQualityGateError(AssertionError):
    """Raised when the deterministic benchmark violates a declared CI threshold."""


@dataclass(frozen=True)
class _HypothesisEvaluation:
    labeled_precision_at_k: dict[str, float]
    label_coverage_at_k: dict[str, float]
    unknown_rate_at_k: dict[str, float]
    precision_lower_bound_at_k: dict[str, float]
    known_forbidden_rate_at_k: dict[str, float]
    recall_at_k: dict[str, float]
    counts_at_k: dict[str, HypothesisKCounts]
    unsupported_rate: float
    unsupported_count: int
    labeled_count: int
    test_ready_with_blockers: int
    top_ranked: list[dict[str, Any]]


@dataclass(frozen=True)
class _JourneyEvaluation:
    total_workflows: int
    singleton_count: int
    singleton_rate: float
    expected_count: int
    retained_count: int
    retained_rate: float
    fragmented_count: int
    fragments: dict[str, int]
    under_merge_pairs: int
    over_merge_pairs: int
    known_pairs: int
    retained_pairs: int
    component_recall: float
    order_violations: int


def _hypothesis_selector(expectation: HypothesisExpectation) -> tuple[Any, ...]:
    return (
        expectation.semantic_key,
        expectation.family,
        expectation.affected_action,
        tuple(sorted(expectation.evidence_any)),
    )


def _validate_static_labels(definition: BenchmarkDefinition) -> None:
    for dataset in definition.datasets:
        entry_labels = [entry.label for capture in dataset.captures for entry in capture.entries]
        if len(entry_labels) != len(set(entry_labels)):
            raise BenchmarkLabelError(f"{dataset.id}: duplicate capture entry labels are invalid")
        known_entries = set(entry_labels)
        referenced_entries = {
            value
            for pairs in (
                dataset.labels.same_workflow,
                dataset.labels.different_workflow,
                dataset.labels.unknown_workflow,
                dataset.labels.expected_causal_edges,
                dataset.labels.forbidden_edges,
                dataset.labels.unknown_edges,
                dataset.labels.same_family,
                dataset.labels.different_family,
            )
            for pair in pairs
            for value in pair
        }
        referenced_entries.update(
            value
            for item in dataset.labels.expected_relationships
            for value in (item.left, item.right)
        )
        referenced_entries.update(
            value for journey in dataset.labels.expected_journeys for value in journey.steps
        )
        hypothesis_labels = [
            *dataset.labels.expected_hypotheses,
            *dataset.labels.forbidden_hypotheses,
            *dataset.labels.unknown_hypotheses,
        ]
        referenced_entries.update(
            value for label in hypothesis_labels for value in label.evidence_any
        )
        missing_entries = sorted(referenced_entries - known_entries)
        if missing_entries:
            raise BenchmarkLabelError(
                f"{dataset.id}: labels reference missing entries: {', '.join(missing_entries)}"
            )
        keys = [item.key for item in hypothesis_labels]
        if len(keys) != len(set(keys)):
            raise BenchmarkLabelError(f"{dataset.id}: duplicate hypothesis label keys are invalid")
        selectors = [_hypothesis_selector(item) for item in hypothesis_labels]
        if len(selectors) != len(set(selectors)):
            raise BenchmarkLabelError(
                f"{dataset.id}: duplicate semantic hypothesis selectors are invalid"
            )
        journey_keys = [item.key for item in dataset.labels.expected_journeys]
        if len(journey_keys) != len(set(journey_keys)):
            raise BenchmarkLabelError(f"{dataset.id}: duplicate journey keys are invalid")
        if dataset.label_policy == "COMPLETE_TOP_K" and dataset.labels.unknown_hypotheses:
            raise BenchmarkLabelError(
                f"{dataset.id}: complete top-K gates may label only expected or forbidden outputs"
            )


def load_benchmark(path: Path) -> BenchmarkDefinition:
    """Load fixed labels without treating missing labels as negatives."""

    definition = BenchmarkDefinition.model_validate_json(path.read_text(encoding="utf-8"))
    _validate_static_labels(definition)
    return definition


def load_quality_gate_configuration(path: Path) -> QualityGateConfiguration:
    """Load the checked-in benchmark fixture and executable CI thresholds."""

    return QualityGateConfiguration.model_validate_json(path.read_text(encoding="utf-8"))


def _har_entry(host: str, entry: BenchmarkEntry) -> dict[str, Any]:
    timestamp = datetime(2026, 8, 5, 10, tzinfo=UTC) + timedelta(seconds=entry.offset_seconds)
    query_items = [(name, value) for name, values in entry.query.items() for value in values]
    url = f"https://{entry.host or host}{entry.path}"
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
    target["scope"]["hosts"] = sorted(
        {dataset.host}
        | {
            entry.host
            for capture in dataset.captures
            for entry in capture.entries
            if entry.host is not None
        }
    )
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
    semantic_key: str,
) -> bool:
    if expectation.semantic_key is not None:
        return expectation.semantic_key == semantic_key
    if item.family != expectation.family or item.affected_action != expectation.affected_action:
        return False
    expected_evidence = {observation_ids[label] for label in expectation.evidence_any}
    return not expected_evidence or bool(expected_evidence.intersection(item.observation_ids))


def _hypothesis_semantic_key(
    item: Any,
    family_signatures: Mapping[str, str],
    invariant_types: Mapping[str, str],
) -> str:
    return ":".join(
        [
            family_signatures.get(item.workflow_family_id, "unknown-workflow"),
            invariant_types.get(item.invariant_id, "unknown-invariant"),
            str(item.family),
            item.affected_action,
        ]
    )


def _hypothesis_metrics(
    workspace: WorkspacePaths,
    dataset_id: str,
    label_policy: Literal["EXPLORATORY", "COMPLETE_TOP_K"],
    labels: DatasetLabels,
    observation_ids: dict[str, str],
    k_values: tuple[int, ...],
) -> _HypothesisEvaluation:
    hypotheses = load_logic_hypotheses(workspace).hypotheses
    family_signatures = {
        item.id: item.structural_signature
        for item in load_workflow_families(workspace).workflow_families
    }
    invariant_types = {
        item.id: item.invariant_type
        for item in load_business_invariants(workspace).business_invariants
    }
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
    semantic_keys = {
        item.id: _hypothesis_semantic_key(item, family_signatures, invariant_types)
        for item in ranked
    }

    def classification(item: Any) -> str:
        semantic_key = semantic_keys[item.id]
        expected = [
            label
            for label in labels.expected_hypotheses
            if _matches_hypothesis(label, item, observation_ids, semantic_key)
        ]
        forbidden = [
            label
            for label in labels.forbidden_hypotheses
            if _matches_hypothesis(label, item, observation_ids, semantic_key)
        ]
        unknown = [
            label
            for label in labels.unknown_hypotheses
            if _matches_hypothesis(label, item, observation_ids, semantic_key)
        ]
        if len(expected) + len(forbidden) + len(unknown) > 1:
            raise BenchmarkLabelError(
                f"{dataset_id}: hypothesis {semantic_key} matches multiple labels"
            )
        if expected:
            return "expected"
        if forbidden:
            return "forbidden"
        return "unknown"

    labeled_precision_at_k: dict[str, float] = {}
    label_coverage_at_k: dict[str, float] = {}
    unknown_rate_at_k: dict[str, float] = {}
    precision_lower_bound_at_k: dict[str, float] = {}
    known_forbidden_rate_at_k: dict[str, float] = {}
    recall_at_k: dict[str, float] = {}
    counts_at_k: dict[str, HypothesisKCounts] = {}
    for k in k_values:
        selected = ranked[:k]
        classified = [classification(item) for item in selected]
        emitted = len(selected)
        expected_count = classified.count("expected")
        forbidden_count = classified.count("forbidden")
        unknown_count = classified.count("unknown")
        labeled_count = expected_count + forbidden_count
        labeled_precision_at_k[str(k)] = expected_count / labeled_count if labeled_count else 1.0
        label_coverage_at_k[str(k)] = labeled_count / emitted if emitted else 1.0
        unknown_rate_at_k[str(k)] = unknown_count / emitted if emitted else 0.0
        precision_lower_bound_at_k[str(k)] = expected_count / emitted if emitted else 1.0
        known_forbidden_rate_at_k[str(k)] = forbidden_count / emitted if emitted else 0.0
        found = {
            expectation.key
            for expectation in labels.expected_hypotheses
            if any(
                _matches_hypothesis(expectation, item, observation_ids, semantic_keys[item.id])
                for item in selected
            )
        }
        recall_at_k[str(k)] = (
            len(found) / len(labels.expected_hypotheses) if labels.expected_hypotheses else 1.0
        )
        counts_at_k[str(k)] = HypothesisKCounts(
            emitted_predictions=emitted,
            labeled_predictions=labeled_count,
            expected_predictions=expected_count,
            forbidden_predictions=forbidden_count,
            unknown_predictions=unknown_count,
            expected_labels_found=len(found),
            expected_labels_total=len(labels.expected_hypotheses),
        )

    if label_policy == "COMPLETE_TOP_K":
        selected = ranked[: max(k_values)]
        selected_keys = {semantic_keys[item.id] for item in selected}
        if len(selected_keys) != len(selected):
            raise BenchmarkLabelError(f"{dataset_id}: emitted top-K semantic keys are not unique")
        output_labels = [*labels.expected_hypotheses, *labels.forbidden_hypotheses]
        for expectation in output_labels:
            matches = [
                item
                for item in selected
                if _matches_hypothesis(expectation, item, observation_ids, semantic_keys[item.id])
            ]
            if not matches:
                raise BenchmarkLabelError(f"{dataset_id}: orphan top-K label {expectation.key!r}")
            if len(matches) > 1:
                raise BenchmarkLabelError(
                    f"{dataset_id}: label {expectation.key!r} matches multiple top-K outputs"
                )
        missing = [semantic_keys[item.id] for item in selected if classification(item) == "unknown"]
        if missing:
            raise BenchmarkLabelError(
                f"{dataset_id}: missing labels for emitted top-K outputs: {', '.join(missing)}"
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
            "semantic_key": semantic_keys[item.id],
        }
        for item in ranked[: max(k_values)]
    ]
    return _HypothesisEvaluation(
        labeled_precision_at_k=labeled_precision_at_k,
        label_coverage_at_k=label_coverage_at_k,
        unknown_rate_at_k=unknown_rate_at_k,
        precision_lower_bound_at_k=precision_lower_bound_at_k,
        known_forbidden_rate_at_k=known_forbidden_rate_at_k,
        recall_at_k=recall_at_k,
        counts_at_k=counts_at_k,
        unsupported_rate=unsupported_rate,
        unsupported_count=unsupported_count,
        labeled_count=labeled_count,
        test_ready_with_blockers=test_ready_with_blockers,
        top_ranked=top_ranked,
    )


def _expected_journeys(labels: DatasetLabels) -> list[JourneyExpectation]:
    if labels.expected_journeys:
        return labels.expected_journeys
    graph: dict[str, set[str]] = {}
    for left, right in labels.same_workflow:
        graph.setdefault(left, set()).add(right)
        graph.setdefault(right, set()).add(left)
    journeys: list[JourneyExpectation] = []
    seen: set[str] = set()
    for start in sorted(graph):
        if start in seen:
            continue
        pending = [start]
        component: set[str] = set()
        while pending:
            current = pending.pop()
            if current in component:
                continue
            component.add(current)
            pending.extend(sorted(graph.get(current, set()) - component))
        seen.update(component)
        steps = sorted(component)
        if len(steps) >= 2:
            journeys.append(JourneyExpectation(key=f"derived:{'|'.join(steps)}", steps=steps))
    return journeys


def _journey_metrics(
    instances: list[Any],
    labels: DatasetLabels,
    observation_ids: dict[str, str],
) -> _JourneyEvaluation:
    observation_instance: dict[str, str] = {}
    observation_position: dict[str, int] = {}
    for instance in instances:
        for step in instance.steps:
            observation_instance[step.observation_id] = instance.id
            observation_position[step.observation_id] = step.position
    journeys = _expected_journeys(labels)
    fragments: dict[str, int] = {}
    retained = 0
    fragmented = 0
    under_merge_pairs = 0
    known_pairs = 0
    retained_pairs = 0
    order_violations = 0
    for journey in journeys:
        observation_sequence = [observation_ids[label] for label in journey.steps]
        instance_sequence = [observation_instance.get(value) for value in observation_sequence]
        component_ids = {value for value in instance_sequence if value is not None}
        fragment_count = len(component_ids) + sum(value is None for value in instance_sequence)
        fragments[journey.key] = fragment_count
        if fragment_count > journey.max_fragments:
            fragmented += 1
        same_component = fragment_count == 1 and None not in instance_sequence
        ordered = same_component and (
            journey.key.startswith("derived:")
            or all(
                observation_position[left] < observation_position[right]
                for left, right in zip(observation_sequence, observation_sequence[1:], strict=False)
            )
        )
        if same_component and not ordered:
            order_violations += 1
        if same_component and ordered:
            retained += 1
        for left, right in combinations(observation_sequence, 2):
            known_pairs += 1
            if observation_instance.get(left) == observation_instance.get(right) and (
                observation_instance.get(left) is not None
            ):
                retained_pairs += 1
            else:
                under_merge_pairs += 1
    over_merge_pairs = sum(
        observation_instance.get(observation_ids[left])
        == observation_instance.get(observation_ids[right])
        and observation_instance.get(observation_ids[left]) is not None
        for left, right in labels.different_workflow
    )
    total = len(instances)
    singletons = sum(len(instance.steps) == 1 for instance in instances)
    return _JourneyEvaluation(
        total_workflows=total,
        singleton_count=singletons,
        singleton_rate=singletons / total if total else 0.0,
        expected_count=len(journeys),
        retained_count=retained,
        retained_rate=retained / len(journeys) if journeys else 1.0,
        fragmented_count=fragmented,
        fragments=dict(sorted(fragments.items())),
        under_merge_pairs=under_merge_pairs,
        over_merge_pairs=over_merge_pairs,
        known_pairs=known_pairs,
        retained_pairs=retained_pairs,
        component_recall=retained_pairs / known_pairs if known_pairs else 1.0,
        order_violations=order_violations,
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
    hypothesis = _hypothesis_metrics(
        workspace,
        dataset.id,
        dataset.label_policy,
        dataset.labels,
        observation_ids,
        k_values,
    )
    journey = _journey_metrics(instances, dataset.labels, observation_ids)
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
        labeled_precision_at_k=hypothesis.labeled_precision_at_k,
        label_coverage_at_k=hypothesis.label_coverage_at_k,
        unknown_rate_at_k=hypothesis.unknown_rate_at_k,
        precision_lower_bound_at_k=hypothesis.precision_lower_bound_at_k,
        known_forbidden_hypothesis_rate_at_k=hypothesis.known_forbidden_rate_at_k,
        hypothesis_precision_at_k=hypothesis.labeled_precision_at_k,
        expected_mutation_recall_at_k=hypothesis.recall_at_k,
        hypothesis_counts_at_k=hypothesis.counts_at_k,
        unsupported_hypothesis_rate=hypothesis.unsupported_rate,
        unsupported_hypothesis_count=hypothesis.unsupported_count,
        labeled_hypothesis_count=hypothesis.labeled_count,
        test_ready_with_blockers=hypothesis.test_ready_with_blockers,
        hard_link_count=hard_links,
        weak_link_count=weak_links,
        total_reconstructed_workflows=journey.total_workflows,
        singleton_workflow_count=journey.singleton_count,
        singleton_workflow_rate=journey.singleton_rate,
        expected_multi_step_journey_count=journey.expected_count,
        fully_retained_multi_step_journey_count=journey.retained_count,
        fully_retained_multi_step_journey_rate=journey.retained_rate,
        fragmented_expected_journey_count=journey.fragmented_count,
        fragments_per_labeled_journey=journey.fragments,
        under_merge_pair_count=journey.under_merge_pairs,
        over_merge_pair_count=journey.over_merge_pairs,
        known_journey_pair_count=journey.known_pairs,
        known_journey_retained_pair_count=journey.retained_pairs,
        known_journey_component_recall=journey.component_recall,
        journey_order_violation_count=journey.order_violations,
        forbidden_workflow_merge_count=workflow_boundary.counts.false_positive,
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
        top_ranked_hypotheses=hypothesis.top_ranked,
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
            emitted_predictions=sum(
                item.hypothesis_counts_at_k[str(k)].emitted_predictions for item in datasets
            ),
            labeled_predictions=sum(
                item.hypothesis_counts_at_k[str(k)].labeled_predictions for item in datasets
            ),
            expected_predictions=sum(
                item.hypothesis_counts_at_k[str(k)].expected_predictions for item in datasets
            ),
            forbidden_predictions=sum(
                item.hypothesis_counts_at_k[str(k)].forbidden_predictions for item in datasets
            ),
            unknown_predictions=sum(
                item.hypothesis_counts_at_k[str(k)].unknown_predictions for item in datasets
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
        labeled_precision_at_k={
            str(k): (
                hypothesis_counts[str(k)].expected_predictions
                / hypothesis_counts[str(k)].labeled_predictions
                if hypothesis_counts[str(k)].labeled_predictions
                else 1.0
            )
            for k in k_values
        },
        label_coverage_at_k={
            str(k): (
                hypothesis_counts[str(k)].labeled_predictions
                / hypothesis_counts[str(k)].emitted_predictions
                if hypothesis_counts[str(k)].emitted_predictions
                else 1.0
            )
            for k in k_values
        },
        unknown_rate_at_k={
            str(k): (
                hypothesis_counts[str(k)].unknown_predictions
                / hypothesis_counts[str(k)].emitted_predictions
                if hypothesis_counts[str(k)].emitted_predictions
                else 0.0
            )
            for k in k_values
        },
        precision_lower_bound_at_k={
            str(k): (
                hypothesis_counts[str(k)].expected_predictions
                / hypothesis_counts[str(k)].emitted_predictions
                if hypothesis_counts[str(k)].emitted_predictions
                else 1.0
            )
            for k in k_values
        },
        known_forbidden_hypothesis_rate_at_k={
            str(k): (
                hypothesis_counts[str(k)].forbidden_predictions
                / hypothesis_counts[str(k)].emitted_predictions
                if hypothesis_counts[str(k)].emitted_predictions
                else 0.0
            )
            for k in k_values
        },
        hypothesis_precision_at_k={
            str(k): (
                hypothesis_counts[str(k)].expected_predictions
                / hypothesis_counts[str(k)].labeled_predictions
                if hypothesis_counts[str(k)].labeled_predictions
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
        total_reconstructed_workflows=sum(item.total_reconstructed_workflows for item in datasets),
        singleton_workflow_count=sum(item.singleton_workflow_count for item in datasets),
        singleton_workflow_rate=(
            sum(item.singleton_workflow_count for item in datasets)
            / sum(item.total_reconstructed_workflows for item in datasets)
            if sum(item.total_reconstructed_workflows for item in datasets)
            else 0.0
        ),
        expected_multi_step_journey_count=sum(
            item.expected_multi_step_journey_count for item in datasets
        ),
        fully_retained_multi_step_journey_count=sum(
            item.fully_retained_multi_step_journey_count for item in datasets
        ),
        fully_retained_multi_step_journey_rate=(
            sum(item.fully_retained_multi_step_journey_count for item in datasets)
            / sum(item.expected_multi_step_journey_count for item in datasets)
            if sum(item.expected_multi_step_journey_count for item in datasets)
            else 1.0
        ),
        fragmented_expected_journey_count=sum(
            item.fragmented_expected_journey_count for item in datasets
        ),
        fragments_per_labeled_journey={
            f"{item.dataset}:{key}": value
            for item in datasets
            for key, value in item.fragments_per_labeled_journey.items()
        },
        under_merge_pair_count=sum(item.under_merge_pair_count for item in datasets),
        over_merge_pair_count=sum(item.over_merge_pair_count for item in datasets),
        known_journey_pair_count=sum(item.known_journey_pair_count for item in datasets),
        known_journey_retained_pair_count=sum(
            item.known_journey_retained_pair_count for item in datasets
        ),
        known_journey_component_recall=(
            sum(item.known_journey_retained_pair_count for item in datasets)
            / sum(item.known_journey_pair_count for item in datasets)
            if sum(item.known_journey_pair_count for item in datasets)
            else 1.0
        ),
        journey_order_violation_count=sum(item.journey_order_violation_count for item in datasets),
        forbidden_workflow_merge_count=sum(
            item.forbidden_workflow_merge_count for item in datasets
        ),
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


def quality_gate_failures(
    report: BenchmarkReport,
    thresholds: QualityGateThresholds,
    *,
    repeated_report: BenchmarkReport | None = None,
) -> tuple[str, ...]:
    """Return stable failure codes for every violated checked-in quality threshold."""

    aggregate = report.aggregate
    key = str(thresholds.k)
    failures: list[str] = []
    if aggregate.forbidden_edge_violations > thresholds.max_forbidden_hard_edges:
        failures.append("FORBIDDEN_HARD_EDGES")
    if aggregate.forbidden_workflow_merge_count > thresholds.max_forbidden_workflow_merges:
        failures.append("FORBIDDEN_WORKFLOW_MERGES")
    if aggregate.labeled_precision_at_k.get(key, 0.0) < thresholds.min_labeled_precision_at_k:
        failures.append("LABELED_PRECISION_AT_K")
    if aggregate.label_coverage_at_k.get(key, 0.0) < thresholds.min_label_coverage_at_k:
        failures.append("LABEL_COVERAGE_AT_K")
    if (
        aggregate.expected_mutation_recall_at_k.get(key, 0.0)
        < thresholds.min_expected_mutation_recall_at_k
    ):
        failures.append("EXPECTED_MUTATION_RECALL_AT_K")
    if aggregate.test_ready_with_blockers > thresholds.max_test_ready_with_blockers:
        failures.append("TEST_READY_WITH_BLOCKERS")
    if aggregate.fragmented_expected_journey_count > thresholds.max_fragmented_expected_journeys:
        failures.append("FRAGMENTED_EXPECTED_JOURNEYS")
    if aggregate.journey_order_violation_count > thresholds.max_journey_order_violations:
        failures.append("JOURNEY_ORDER_VIOLATIONS")
    if thresholds.require_deterministic_output and (
        repeated_report is None
        or report.model_dump(mode="json") != repeated_report.model_dump(mode="json")
    ):
        failures.append("NON_DETERMINISTIC_OUTPUT")
    return tuple(failures)


def assert_quality_gates(
    report: BenchmarkReport,
    thresholds: QualityGateThresholds,
    *,
    repeated_report: BenchmarkReport | None = None,
) -> None:
    """Fail CI when an explicit benchmark quality gate is violated."""

    failures = quality_gate_failures(report, thresholds, repeated_report=repeated_report)
    if failures:
        raise BenchmarkQualityGateError(
            "Workflow benchmark quality gates failed: " + ", ".join(failures)
        )


def evaluate_quality_gate_configuration(
    configuration_path: Path, workspace_root: Path
) -> tuple[BenchmarkReport, BenchmarkReport]:
    """Evaluate the configured fully labeled fixture twice and enforce every CI gate."""

    configuration = load_quality_gate_configuration(configuration_path)
    fixture = (configuration_path.parent / configuration.fixture).resolve()
    definition = load_benchmark(fixture)
    first = evaluate_benchmark(
        definition, workspace_root / "first", k_values=(configuration.thresholds.k,)
    )
    second = evaluate_benchmark(
        definition, workspace_root / "second", k_values=(configuration.thresholds.k,)
    )
    assert_quality_gates(first, configuration.thresholds, repeated_report=second)
    return first, second


def render_markdown(report: BenchmarkReport) -> str:
    """Render a concise deterministic summary suitable for CI logs or review notes."""

    key = "10" if 10 in report.k_values else str(max(report.k_values))
    lines = [
        "# Workflow Precision Benchmark",
        "",
        f"| Dataset | Labeled precision@{key} | Coverage@{key} | Unknown@{key} | "
        f"Lower bound@{key} | Raw E/F/U/N | Recall@{key} | Forbidden edges/merges | "
        "Journey retention | Fragmented | Singleton diagnostic | Ready + blockers |",
        "| --- | ---: | ---: | ---: | ---: | --- | ---: | --- | ---: | ---: | ---: | ---: |",
    ]
    for item in [*report.datasets, report.aggregate]:
        counts = item.hypothesis_counts_at_k[key]
        lines.append(
            "| "
            + " | ".join(
                [
                    item.dataset,
                    f"{item.labeled_precision_at_k[key]:.3f}",
                    f"{item.label_coverage_at_k[key]:.3f}",
                    f"{item.unknown_rate_at_k[key]:.3f}",
                    f"{item.precision_lower_bound_at_k[key]:.3f}",
                    f"{counts.expected_predictions}/{counts.forbidden_predictions}/"
                    f"{counts.unknown_predictions}/{counts.emitted_predictions}",
                    f"{item.expected_mutation_recall_at_k[key]:.3f}",
                    f"{item.forbidden_edge_violations}/{item.forbidden_workflow_merge_count}",
                    f"{item.fully_retained_multi_step_journey_count}/"
                    f"{item.expected_multi_step_journey_count}",
                    str(item.fragmented_expected_journey_count),
                    f"{item.singleton_workflow_rate:.3f}",
                    str(item.test_ready_with_blockers),
                ]
            )
            + " |"
        )
    lines.extend(
        [
            "",
            "Definitions:",
            "",
            "- Labeled precision excludes unknown outputs from its denominator.",
            "- Coverage is labeled outputs divided by all emitted top-K outputs.",
            "- Lower-bound precision is expected outputs divided by all emitted top-K outputs.",
            "- Singleton rate is diagnostic only; CI fragmentation gates use labeled journeys.",
        ]
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
