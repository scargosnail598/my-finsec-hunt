"""Run and evaluate realistic traffic against independent ground-truth labels."""

from __future__ import annotations

import json
from dataclasses import dataclass
from itertools import combinations
from pathlib import Path

import yaml

from finsec.behavior.corpus_metrics import (
    AggregateMetrics,
    ClassificationMetrics,
    CorpusEvaluation,
    CorpusStatistics,
    FragmentationBreak,
    FragmentationDiagnostic,
    JourneyEvaluation,
    MissedEdgeDiagnostic,
    RealisticQualityGateConfiguration,
    RealisticQualityGateThresholds,
)
from finsec.behavior.corpus_runner import CorpusRunResult, run_realistic_corpus_journey
from finsec.behavior.domain import (
    CausalBasis,
    CausalEvidence,
    HypothesisReadiness,
    PropagationLink,
    RelationshipType,
    WorkflowStep,
)
from finsec.behavior.realistic_corpus import (
    CausalEdgeLabel,
    JourneyLabel,
    PrerequisiteLabel,
    StateTransitionLabel,
    load_realistic_corpus,
)

type MetricKey = tuple[str, ...]


class RealisticCorpusQualityGateError(AssertionError):
    """Raised when reviewed realistic-corpus thresholds regress."""


@dataclass(frozen=True)
class _JourneyDetails:
    evaluation: JourneyEvaluation
    expected_edges: set[MetricKey]
    actual_edges: set[MetricKey]
    labeled_actual_edges: int
    unknown_actual_edges: int
    category_expected: dict[str, set[MetricKey]]
    category_actual: dict[str, set[MetricKey]]
    cross_actor_violations: int
    cross_session_violations: int
    request_echo_violations: int
    read_existing_id_violations: int


def _classification(expected: set[MetricKey], actual: set[MetricKey]) -> ClassificationMetrics:
    true_positive = len(expected & actual)
    false_positive = len(actual - expected)
    false_negative = len(expected - actual)
    precision = true_positive / len(actual) if actual else (1.0 if not expected else 0.0)
    recall = true_positive / len(expected) if expected else 1.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return ClassificationMetrics(
        expected=len(expected),
        actual=len(actual),
        true_positive=true_positive,
        false_positive=false_positive,
        false_negative=false_negative,
        precision=precision,
        recall=recall,
        f1=f1,
    )


def _sum_classifications(items: list[ClassificationMetrics]) -> ClassificationMetrics:
    expected = sum(item.expected for item in items)
    actual = sum(item.actual for item in items)
    true_positive = sum(item.true_positive for item in items)
    false_positive = sum(item.false_positive for item in items)
    false_negative = sum(item.false_negative for item in items)
    precision = true_positive / actual if actual else (1.0 if not expected else 0.0)
    recall = true_positive / expected if expected else 1.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return ClassificationMetrics(
        expected=expected,
        actual=actual,
        true_positive=true_positive,
        false_positive=false_positive,
        false_negative=false_negative,
        precision=precision,
        recall=recall,
        f1=f1,
    )


def _field(value: str | None) -> str:
    return (value or "").rsplit(".", 1)[-1].replace("[]", "").lower()


def _edge_key(journey: str, label: CausalEdgeLabel) -> MetricKey:
    return (
        journey,
        label.producer,
        label.consumer,
        _field(label.field_name),
        label.expected_basis.value if label.expected_basis else "",
    )


def _actual_edge_key(
    journey: str,
    reverse_ids: dict[str, str],
    link: PropagationLink,
) -> MetricKey:
    return (
        journey,
        reverse_ids[link.source_observation_id],
        reverse_ids[link.destination_observation_id],
        _field(link.source_field),
        link.causal_basis.value,
    )


def _label_triple(journey: str, label: CausalEdgeLabel) -> MetricKey:
    return (journey, label.producer, label.consumer, _field(label.field_name))


def _actual_triple(journey: str, reverse_ids: dict[str, str], link: PropagationLink) -> MetricKey:
    return (
        journey,
        reverse_ids[link.source_observation_id],
        reverse_ids[link.destination_observation_id],
        _field(link.source_field),
    )


def _candidate_link(
    run: CorpusRunResult,
    producer: str,
    consumer: str,
    field_name: str,
) -> PropagationLink | None:
    reverse_ids = {value: key for key, value in run.label_observation_ids.items()}
    candidates = [
        link
        for link in run.propagation_links
        if reverse_ids.get(link.source_observation_id) == producer
        and reverse_ids.get(link.destination_observation_id) == consumer
    ]
    ordered = sorted(candidates, key=lambda item: item.id)
    if not field_name:
        return ordered[0] if ordered else None
    return next(
        (link for link in ordered if _field(link.source_field) == _field(field_name)),
        None,
    )


def _missed_diagnostic(run: CorpusRunResult, label: CausalEdgeLabel) -> MissedEdgeDiagnostic:
    candidate = _candidate_link(run, label.producer, label.consumer, label.field_name)
    rejection_reasons = (
        list(candidate.rejection_reasons)
        if candidate is not None and candidate.rejection_reasons
        else ["causal_basis_mismatch"]
        if candidate is not None
        else ["matching_value_not_extracted_or_consumed"]
    )
    return MissedEdgeDiagnostic(
        edge_id=label.id,
        journey=label.journey,
        producer=label.producer,
        consumer=label.consumer,
        producer_field=label.field_name,
        consumer_field=candidate.destination_field if candidate is not None else "",
        expected_basis=label.expected_basis or CausalBasis.AMBIGUOUS_ORIGIN,
        expected_relationship=label.relationship,
        actual_basis=candidate.causal_basis if candidate is not None else None,
        actual_relationship=candidate.relationship_type if candidate is not None else None,
        evidence=candidate.causal_evidence if candidate is not None else CausalEvidence(),
        rejection_reasons=rejection_reasons,
    )


def _component_assignments(run: CorpusRunResult) -> tuple[dict[str, str], dict[str, int]]:
    reverse_ids = {value: key for key, value in run.label_observation_ids.items()}
    components: dict[str, str] = {}
    positions: dict[str, int] = {}
    for instance in run.workflow_instances:
        for step in instance.steps:
            label = reverse_ids[step.observation_id]
            components[label] = instance.id
            positions[label] = step.position
    return components, positions


def _fragmentation_diagnostic(
    run: CorpusRunResult,
    label: JourneyLabel,
    components: dict[str, str],
    expected_edges: list[CausalEdgeLabel],
) -> FragmentationDiagnostic | None:
    breaks: list[FragmentationBreak] = []
    for group in label.expected_component_groups:
        for producer, consumer in zip(group, group[1:], strict=False):
            if components[producer] == components[consumer]:
                continue
            expected = next(
                (
                    edge
                    for edge in expected_edges
                    if edge.producer == producer and edge.consumer == consumer
                ),
                None,
            )
            candidate = _candidate_link(
                run,
                producer,
                consumer,
                expected.field_name if expected is not None else "",
            )
            breaks.append(
                FragmentationBreak(
                    producer=producer,
                    consumer=consumer,
                    expected_basis=expected.expected_basis if expected is not None else None,
                    actual_basis=candidate.causal_basis if candidate is not None else None,
                    actual_relationship=(
                        candidate.relationship_type if candidate is not None else None
                    ),
                    evidence=(
                        candidate.causal_evidence if candidate is not None else CausalEvidence()
                    ),
                    rejection_reasons=(
                        candidate.rejection_reasons
                        if candidate is not None and candidate.rejection_reasons
                        else ["no_admissible_causal_bridge"]
                    ),
                )
            )
    if not breaks:
        return None
    return FragmentationDiagnostic(
        journey=label.id,
        expected_components=label.expected_components,
        actual_components=len(
            {components[observation] for observation in label.expected_observations}
        ),
        breaks=breaks,
    )


def _prerequisite_keys(
    run: CorpusRunResult,
    journey: str,
) -> set[MetricKey]:
    reverse_ids = {value: key for key, value in run.label_observation_ids.items()}
    links = {link.id: link for link in run.propagation_links}
    return {
        (
            journey,
            reverse_ids[links[link_id].source_observation_id],
            reverse_ids[links[link_id].destination_observation_id],
            _field(links[link_id].source_field),
        )
        for prerequisite in run.prerequisites
        for link_id in prerequisite.causal_link_ids
    }


def _prerequisite_label_key(journey: str, label: PrerequisiteLabel) -> MetricKey:
    return (
        journey,
        label.prerequisite_action,
        label.dependent_action,
        _field(label.field.split("/", 1)[0].strip()),
    )


def _step_advances(step: WorkflowStep) -> bool:
    return step.method not in {"GET", "HEAD", "OPTIONS"}


def _state_transition_keys(
    run: CorpusRunResult,
    journey: str,
    labels: list[StateTransitionLabel],
) -> set[MetricKey]:
    if not labels:
        return set()
    relevant = {(item.resource_type.lower(), _field(item.field)) for item in labels}
    reverse_ids = {value: key for key, value in run.label_observation_ids.items()}
    transitions: set[MetricKey] = set()
    for instance in run.workflow_instances:
        for index, step in enumerate(instance.steps):
            consumer = reverse_ids[step.observation_id]
            for state in step.state_observations:
                if (
                    state.state_before is None
                    or state.state_before == state.state_after
                    or (state.resource_type.lower(), _field(state.field)) not in relevant
                ):
                    continue
                producer: str | None = None
                for previous in reversed(instance.steps[:index]):
                    if not _step_advances(previous):
                        continue
                    if any(
                        item.resource_type == state.resource_type
                        and item.state_after == state.state_before
                        for item in previous.state_observations
                    ):
                        producer = reverse_ids[previous.observation_id]
                        break
                if producer is not None:
                    transitions.add(
                        (
                            journey,
                            producer,
                            consumer,
                            state.resource_type.lower(),
                            _field(state.field),
                            state.state_before,
                            state.state_after,
                        )
                    )
    return transitions


def _state_label_key(journey: str, label: StateTransitionLabel) -> MetricKey:
    return (
        journey,
        label.producer,
        label.consumer,
        label.resource_type.lower(),
        _field(label.field),
        label.from_state,
        label.to_state,
    )


def _edge_categories(label: CausalEdgeLabel) -> set[str]:
    categories = {
        CausalBasis.RESOURCE_CREATED: "resource_creation",
        CausalBasis.CAPABILITY_ISSUED: "capability_issuance",
        CausalBasis.STATE_TRANSITION_PRODUCED: "state_transition",
    }
    result = {categories[label.expected_basis]} if label.expected_basis in categories else set()
    if label.cross_host:
        result.add("multi_service_handoff")
    if label.cross_capture:
        result.add("cross_capture_continuation")
    if label.journey == "nested-resource":
        result.add("nested_resource")
    return result


def _actual_edge_categories(journey: str, link: PropagationLink) -> set[str]:
    categories = {
        CausalBasis.RESOURCE_CREATED: "resource_creation",
        CausalBasis.CAPABILITY_ISSUED: "capability_issuance",
        CausalBasis.STATE_TRANSITION_PRODUCED: "state_transition",
    }
    result = {categories[link.causal_basis]} if link.causal_basis in categories else set()
    if link.source_host != link.destination_host:
        result.add("multi_service_handoff")
    if link.source_capture != link.destination_capture:
        result.add("cross_capture_continuation")
    if journey == "nested-resource":
        result.add("nested_resource")
    return result


def _evaluate_run(
    run: CorpusRunResult,
    journey_label: JourneyLabel,
    edge_labels: list[CausalEdgeLabel],
    prerequisite_labels: list[PrerequisiteLabel],
    state_labels: list[StateTransitionLabel],
) -> _JourneyDetails:
    reverse_ids = {value: key for key, value in run.label_observation_ids.items()}
    hard_links = [
        link
        for link in run.propagation_links
        if link.relationship_type == RelationshipType.CAUSAL_HARD
    ]
    actual_edges = {_actual_edge_key(journey_label.id, reverse_ids, link) for link in hard_links}
    expected_edge_labels = [
        label
        for label in edge_labels
        if label.status == "expected" and label.relationship == RelationshipType.CAUSAL_HARD
    ]
    expected_edges = {_edge_key(journey_label.id, label) for label in expected_edge_labels}
    all_label_triples = {_label_triple(journey_label.id, label) for label in edge_labels}
    actual_by_key = {
        _actual_edge_key(journey_label.id, reverse_ids, link): link for link in hard_links
    }
    actual_triples = {
        _actual_edge_key(journey_label.id, reverse_ids, link): _actual_triple(
            journey_label.id, reverse_ids, link
        )
        for link in hard_links
    }
    labeled_actual = sum(triple in all_label_triples for triple in actual_triples.values())
    unknown_actual = len(actual_edges) - labeled_actual
    forbidden_labels = [label for label in edge_labels if label.status == "forbidden"]
    forbidden_triples = {_label_triple(journey_label.id, label) for label in forbidden_labels}
    request_echo_triples = {
        _label_triple(journey_label.id, label) for label in forbidden_labels if label.request_echo
    }
    read_existing_triples = {
        _label_triple(journey_label.id, label)
        for label in forbidden_labels
        if label.read_before_write
    }
    forbidden_hard = sum(triple in forbidden_triples for triple in actual_triples.values())
    edge_metrics = _classification(expected_edges, actual_edges)
    missed = [
        _missed_diagnostic(run, label)
        for label in expected_edge_labels
        if _edge_key(journey_label.id, label) not in actual_edges
    ]

    components, positions = _component_assignments(run)
    expected_same: set[MetricKey] = set()
    for group in journey_label.expected_component_groups:
        expected_same.update((journey_label.id, *sorted(pair)) for pair in combinations(group, 2))
    actual_same = {
        (journey_label.id, *sorted((left, right)))
        for left, right in combinations(journey_label.expected_observations, 2)
        if components[left] == components[right]
    }
    component_metrics = _classification(expected_same, actual_same)
    retained_groups = sum(
        len({components[observation] for observation in group}) == 1
        for group in journey_label.expected_component_groups
    )
    order_expected = 0
    order_recovered = 0
    if journey_label.expected_order:
        sequences = (
            [journey_label.expected_steps]
            if journey_label.expected_steps is not None
            else journey_label.expected_component_groups
        )
        for sequence in sequences:
            if sequence is None:
                continue
            for left, right in zip(sequence, sequence[1:], strict=False):
                order_expected += 1
                order_recovered += int(
                    components[left] == components[right] and positions[left] < positions[right]
                )
    order_retention = order_recovered / order_expected if order_expected else 1.0

    actual_prerequisites = _prerequisite_keys(run, journey_label.id)
    expected_prerequisites = {
        _prerequisite_label_key(journey_label.id, label)
        for label in prerequisite_labels
        if label.status == "expected"
    }
    forbidden_prerequisite_keys = {
        _prerequisite_label_key(journey_label.id, label)
        for label in prerequisite_labels
        if label.status == "forbidden"
    }
    prerequisite_metrics = _classification(expected_prerequisites, actual_prerequisites)
    forbidden_prerequisites = len(actual_prerequisites & forbidden_prerequisite_keys)
    unexpected_prerequisites = len(
        actual_prerequisites - expected_prerequisites - forbidden_prerequisite_keys
    )

    expected_states = {
        _state_label_key(journey_label.id, label)
        for label in state_labels
        if label.status == "expected"
    }
    actual_states = _state_transition_keys(run, journey_label.id, state_labels)
    state_metrics = _classification(expected_states, actual_states)
    actual_components = len({components[item] for item in journey_label.expected_observations})
    singletons = sum(len(instance.steps) == 1 for instance in run.workflow_instances)
    test_ready_with_blockers = sum(
        hypothesis.readiness == HypothesisReadiness.TEST_READY
        and bool(hypothesis.readiness_blockers)
        for hypothesis in run.hypotheses
    )
    labeled_precision = edge_metrics.true_positive / labeled_actual if labeled_actual else 1.0
    label_coverage = labeled_actual / len(actual_edges) if actual_edges else 1.0
    unknown_rate = unknown_actual / len(actual_edges) if actual_edges else 0.0
    precision_lower_bound = (
        edge_metrics.true_positive / len(actual_edges)
        if actual_edges
        else (1.0 if not expected_edges else 0.0)
    )
    fragmentation = _fragmentation_diagnostic(run, journey_label, components, expected_edge_labels)
    evaluation = JourneyEvaluation(
        journey_id=journey_label.id,
        name=journey_label.name,
        category=journey_label.category,
        difficulty=journey_label.difficulty,
        observation_count=len(run.observations),
        causal_edges=edge_metrics,
        forbidden_hard_edges=forbidden_hard,
        unexpected_hard_edges=edge_metrics.false_positive - forbidden_hard,
        labeled_precision=labeled_precision,
        label_coverage=label_coverage,
        unknown_rate=unknown_rate,
        precision_lower_bound=precision_lower_bound,
        expected_components=journey_label.expected_components,
        actual_components=actual_components,
        component_membership=component_metrics,
        expected_component_groups=len(journey_label.expected_component_groups),
        retained_component_groups=retained_groups,
        fragmented=retained_groups != len(journey_label.expected_component_groups),
        incorrect_merges=component_metrics.false_positive,
        order_pairs_expected=order_expected,
        order_pairs_recovered=order_recovered,
        order_retention=order_retention,
        prerequisites=prerequisite_metrics,
        forbidden_prerequisites=forbidden_prerequisites,
        unexpected_prerequisites=unexpected_prerequisites,
        state_transitions=state_metrics,
        hard_link_count=len(hard_links),
        soft_link_count=len(run.propagation_links) - len(hard_links),
        workflow_instance_count=len(run.workflow_instances),
        workflow_family_count=len(run.workflow_families),
        singleton_count=singletons,
        singleton_rate=singletons / len(run.workflow_instances) if run.workflow_instances else 0.0,
        invariant_count=len(run.invariants),
        hypothesis_count=len(run.hypotheses),
        test_ready_with_blockers=test_ready_with_blockers,
        missed_edges=missed,
        fragmentation=fragmentation,
    )

    category_expected: dict[str, set[MetricKey]] = {}
    for label in expected_edge_labels:
        key = _edge_key(journey_label.id, label)
        for category in _edge_categories(label):
            category_expected.setdefault(category, set()).add(key)
    category_actual: dict[str, set[MetricKey]] = {}
    for key, link in actual_by_key.items():
        for category in _actual_edge_categories(journey_label.id, link):
            category_actual.setdefault(category, set()).add(key)
    return _JourneyDetails(
        evaluation=evaluation,
        expected_edges=expected_edges,
        actual_edges=actual_edges,
        labeled_actual_edges=labeled_actual,
        unknown_actual_edges=unknown_actual,
        category_expected=category_expected,
        category_actual=category_actual,
        cross_actor_violations=sum(
            link.source_actor != link.destination_actor for link in hard_links
        ),
        cross_session_violations=sum(
            link.source_session != link.destination_session for link in hard_links
        ),
        request_echo_violations=sum(
            triple in request_echo_triples for triple in actual_triples.values()
        ),
        read_existing_id_violations=sum(
            triple in read_existing_triples for triple in actual_triples.values()
        ),
    )


def evaluate_realistic_corpus(
    corpus_root: Path,
    output_root: Path,
) -> CorpusEvaluation:
    """Run every traffic journey first, then load labels and evaluate production output."""

    loader = load_realistic_corpus(corpus_root)
    journey_ids = sorted(
        path.name
        for path in loader.journeys_root.iterdir()
        if path.is_dir() and (path / "journeys.json").is_file()
    )
    runs = {
        journey_id: run_realistic_corpus_journey(
            loader.load_journey(journey_id), output_root / journey_id
        )
        for journey_id in journey_ids
    }
    journey_labels = sorted(loader.load_journey_labels(), key=lambda item: item.id)
    if {item.id for item in journey_labels} != set(runs):
        raise ValueError("Traffic journey directories and journey labels must match exactly")
    edge_labels = loader.load_causal_edges()
    prerequisite_labels = loader.load_prerequisites()
    state_labels = loader.load_state_transitions()
    details: list[_JourneyDetails] = []
    for journey_label in journey_labels:
        run = runs[journey_label.id]
        details.append(
            _evaluate_run(
                run,
                journey_label,
                [label for label in edge_labels if label.journey == journey_label.id],
                [label for label in prerequisite_labels if label.journey == journey_label.id],
                [label for label in state_labels if label.journey == journey_label.id],
            )
        )
    journeys = [item.evaluation for item in details]
    causal_edges = _sum_classifications([item.causal_edges for item in journeys])
    component_membership = _sum_classifications([item.component_membership for item in journeys])
    prerequisites = _sum_classifications([item.prerequisites for item in journeys])
    state_transitions = _sum_classifications([item.state_transitions for item in journeys])
    labeled_actual = sum(item.labeled_actual_edges for item in details)
    unknown_actual = sum(item.unknown_actual_edges for item in details)
    categories = sorted(
        {
            category
            for item in details
            for category in {*item.category_expected, *item.category_actual}
        }
    )
    category_metrics = {
        category: _classification(
            set().union(*(item.category_expected.get(category, set()) for item in details)),
            set().union(*(item.category_actual.get(category, set()) for item in details)),
        )
        for category in categories
    }
    expected_groups = sum(item.expected_component_groups for item in journeys)
    retained_groups = sum(item.retained_component_groups for item in journeys)
    workflow_instances = sum(item.workflow_instance_count for item in journeys)
    singletons = sum(item.singleton_count for item in journeys)
    hard_links = sum(item.hard_link_count for item in journeys)
    aggregate = AggregateMetrics(
        causal_edges=causal_edges,
        recovered_hard_edges=causal_edges.true_positive,
        missed_hard_edges=causal_edges.false_negative,
        forbidden_hard_edges=sum(item.forbidden_hard_edges for item in journeys),
        unexpected_hard_edges=sum(item.unexpected_hard_edges for item in journeys),
        labeled_precision=(causal_edges.true_positive / labeled_actual if labeled_actual else 1.0),
        label_coverage=labeled_actual / hard_links if hard_links else 1.0,
        unknown_rate=unknown_actual / hard_links if hard_links else 0.0,
        precision_lower_bound=(
            causal_edges.true_positive / hard_links
            if hard_links
            else (1.0 if not causal_edges.expected else 0.0)
        ),
        metrics_by_causal_category=category_metrics,
        expected_components=sum(item.expected_components for item in journeys),
        actual_components=sum(item.actual_components for item in journeys),
        component_membership=component_membership,
        expected_component_groups=expected_groups,
        retained_component_groups=retained_groups,
        journey_retention=retained_groups / expected_groups if expected_groups else 1.0,
        fragmented_journeys=sum(item.fragmented for item in journeys),
        incorrect_merges=component_membership.false_positive,
        forbidden_merges=component_membership.false_positive,
        order_pairs_expected=sum(item.order_pairs_expected for item in journeys),
        order_pairs_recovered=sum(item.order_pairs_recovered for item in journeys),
        order_retention=(
            sum(item.order_pairs_recovered for item in journeys)
            / sum(item.order_pairs_expected for item in journeys)
            if sum(item.order_pairs_expected for item in journeys)
            else 1.0
        ),
        prerequisites=prerequisites,
        forbidden_prerequisites=sum(item.forbidden_prerequisites for item in journeys),
        unexpected_prerequisites=sum(item.unexpected_prerequisites for item in journeys),
        state_transitions=state_transitions,
        singleton_count=singletons,
        workflow_instance_count=workflow_instances,
        singleton_rate=singletons / workflow_instances if workflow_instances else 0.0,
        hard_link_count=hard_links,
        soft_link_count=sum(item.soft_link_count for item in journeys),
        invariant_count=sum(item.invariant_count for item in journeys),
        hypothesis_count=sum(item.hypothesis_count for item in journeys),
        test_ready_with_blockers=sum(item.test_ready_with_blockers for item in journeys),
        cross_actor_violations=sum(item.cross_actor_violations for item in details),
        cross_session_violations=sum(item.cross_session_violations for item in details),
        request_echo_violations=sum(item.request_echo_violations for item in details),
        read_existing_id_violations=sum(item.read_existing_id_violations for item in details),
    )
    edges = edge_labels
    statistics = CorpusStatistics(
        journey_count=len(journeys),
        observation_count=sum(item.observation_count for item in journeys),
        expected_hard_edges=sum(
            item.status == "expected" and item.relationship == RelationshipType.CAUSAL_HARD
            for item in edges
        ),
        expected_soft_edges=sum(
            item.status == "expected" and item.relationship != RelationshipType.CAUSAL_HARD
            for item in edges
        ),
        forbidden_edges=sum(item.status == "forbidden" for item in edges),
        expected_prerequisites=sum(item.status == "expected" for item in prerequisite_labels),
        expected_state_transitions=sum(item.status == "expected" for item in state_labels),
    )
    return CorpusEvaluation(statistics=statistics, journeys=journeys, aggregate=aggregate)


def load_realistic_quality_gate_configuration(
    path: Path,
) -> RealisticQualityGateConfiguration:
    """Load checked-in thresholds for the fully labeled realistic corpus."""

    return RealisticQualityGateConfiguration.model_validate(
        yaml.safe_load(path.read_text(encoding="utf-8"))
    )


def realistic_quality_gate_failures(
    report: CorpusEvaluation,
    thresholds: RealisticQualityGateThresholds,
    *,
    repeated_report: CorpusEvaluation | None = None,
) -> tuple[str, ...]:
    """Return stable failure codes without weakening precision-first priorities."""

    aggregate = report.aggregate
    failures: list[str] = []
    if aggregate.causal_edges.precision < thresholds.min_causal_edge_precision:
        failures.append("CAUSAL_EDGE_PRECISION")
    if aggregate.causal_edges.recall < thresholds.min_causal_edge_recall:
        failures.append("CAUSAL_EDGE_RECALL")
    if aggregate.label_coverage < thresholds.min_label_coverage:
        failures.append("LABEL_COVERAGE")
    if aggregate.component_membership.precision < thresholds.min_component_precision:
        failures.append("COMPONENT_PRECISION")
    if aggregate.component_membership.recall < thresholds.min_component_recall:
        failures.append("COMPONENT_RECALL")
    if aggregate.prerequisites.precision < thresholds.min_prerequisite_precision:
        failures.append("PREREQUISITE_PRECISION")
    if aggregate.prerequisites.recall < thresholds.min_prerequisite_recall:
        failures.append("PREREQUISITE_RECALL")
    if aggregate.state_transitions.precision < thresholds.min_state_transition_precision:
        failures.append("STATE_TRANSITION_PRECISION")
    if aggregate.state_transitions.recall < thresholds.min_state_transition_recall:
        failures.append("STATE_TRANSITION_RECALL")
    if aggregate.order_retention < thresholds.min_order_retention:
        failures.append("ORDER_RETENTION")
    if aggregate.forbidden_hard_edges > thresholds.max_forbidden_hard_edges:
        failures.append("FORBIDDEN_HARD_EDGES")
    if aggregate.forbidden_merges > thresholds.max_forbidden_merges:
        failures.append("FORBIDDEN_MERGES")
    if aggregate.forbidden_prerequisites > thresholds.max_forbidden_prerequisites:
        failures.append("FORBIDDEN_PREREQUISITES")
    if aggregate.fragmented_journeys > thresholds.max_fragmented_journeys:
        failures.append("FRAGMENTED_JOURNEYS")
    if aggregate.test_ready_with_blockers > thresholds.max_test_ready_with_blockers:
        failures.append("TEST_READY_WITH_BLOCKERS")
    if aggregate.cross_actor_violations > thresholds.max_cross_actor_violations:
        failures.append("CROSS_ACTOR_VIOLATIONS")
    if aggregate.cross_session_violations > thresholds.max_cross_session_violations:
        failures.append("CROSS_SESSION_VIOLATIONS")
    if aggregate.request_echo_violations > thresholds.max_request_echo_violations:
        failures.append("REQUEST_ECHO_VIOLATIONS")
    if aggregate.read_existing_id_violations > thresholds.max_read_existing_id_violations:
        failures.append("READ_EXISTING_ID_VIOLATIONS")
    if thresholds.require_deterministic_output and (
        repeated_report is None
        or report.model_dump(mode="json") != repeated_report.model_dump(mode="json")
    ):
        failures.append("NON_DETERMINISTIC_OUTPUT")
    return tuple(failures)


def evaluate_realistic_quality_gate_configuration(
    configuration_path: Path,
    output_root: Path,
) -> tuple[CorpusEvaluation, CorpusEvaluation]:
    """Run the fully labeled corpus twice and enforce deterministic quality gates."""

    configuration = load_realistic_quality_gate_configuration(configuration_path)
    corpus_root = (configuration_path.parent / configuration.corpus).resolve()
    first = evaluate_realistic_corpus(corpus_root, output_root / "first")
    second = evaluate_realistic_corpus(corpus_root, output_root / "second")
    failures = realistic_quality_gate_failures(
        first, configuration.thresholds, repeated_report=second
    )
    if failures:
        raise RealisticCorpusQualityGateError(
            "Realistic corpus quality gates failed: " + ", ".join(failures)
        )
    deterministic_first = first.model_copy(
        update={"aggregate": first.aggregate.model_copy(update={"deterministic_output": True})}
    )
    deterministic_second = second.model_copy(
        update={"aggregate": second.aggregate.model_copy(update={"deterministic_output": True})}
    )
    return deterministic_first, deterministic_second


def render_realistic_markdown(report: CorpusEvaluation) -> str:
    """Render a deterministic CI and review summary."""

    aggregate = report.aggregate
    lines = [
        "# Realistic Corpus End-to-End Validation",
        "",
        "| Metric | Value |",
        "| --- | ---: |",
        f"| Expected hard edges | {report.statistics.expected_hard_edges} |",
        f"| Recovered hard edges | {aggregate.recovered_hard_edges} |",
        f"| Missed hard edges | {aggregate.missed_hard_edges} |",
        f"| Unexpected hard edges | {aggregate.unexpected_hard_edges} |",
        f"| Causal edge precision | {aggregate.causal_edges.precision:.3f} |",
        f"| Causal edge recall | {aggregate.causal_edges.recall:.3f} |",
        f"| Label coverage | {aggregate.label_coverage:.3f} |",
        f"| Forbidden hard edges | {aggregate.forbidden_hard_edges} |",
        f"| Forbidden merges | {aggregate.forbidden_merges} |",
        f"| Expected components | {aggregate.expected_components} |",
        f"| Actual components | {aggregate.actual_components} |",
        f"| Component precision | {aggregate.component_membership.precision:.3f} |",
        f"| Component recall | {aggregate.component_membership.recall:.3f} |",
        f"| Journey retention | {aggregate.journey_retention:.3f} |",
        f"| Fragmented journeys | {aggregate.fragmented_journeys} |",
        f"| Order retention | {aggregate.order_retention:.3f} |",
        f"| Prerequisite precision | {aggregate.prerequisites.precision:.3f} |",
        f"| Prerequisite recall | {aggregate.prerequisites.recall:.3f} |",
        f"| Forbidden prerequisites | {aggregate.forbidden_prerequisites} |",
        f"| State-transition precision | {aggregate.state_transitions.precision:.3f} |",
        f"| State-transition recall | {aggregate.state_transitions.recall:.3f} |",
        f"| Singleton rate | {aggregate.singleton_rate:.3f} |",
        f"| Cross-actor violations | {aggregate.cross_actor_violations} |",
        f"| Cross-session violations | {aggregate.cross_session_violations} |",
        f"| Request-echo violations | {aggregate.request_echo_violations} |",
        f"| Read-existing-ID violations | {aggregate.read_existing_id_violations} |",
        f"| TEST_READY with blockers | {aggregate.test_ready_with_blockers} |",
        f"| Deterministic output | {str(aggregate.deterministic_output).lower()} |",
        "",
        "## Causal Categories",
        "",
        "| Category | Precision | Recall | Expected | Actual |",
        "| --- | ---: | ---: | ---: | ---: |",
    ]
    for category, metrics in sorted(aggregate.metrics_by_causal_category.items()):
        lines.append(
            f"| {category} | {metrics.precision:.3f} | {metrics.recall:.3f} | "
            f"{metrics.expected} | {metrics.actual} |"
        )
    return "\n".join(lines) + "\n"


def write_realistic_report(
    report: CorpusEvaluation,
    json_path: Path,
    markdown_path: Path,
) -> None:
    """Write byte-stable JSON and Markdown artifacts."""

    json_path.parent.mkdir(parents=True, exist_ok=True)
    markdown_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(
        json.dumps(report.model_dump(mode="json"), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    markdown_path.write_text(render_realistic_markdown(report), encoding="utf-8", newline="\n")
