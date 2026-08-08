"""End-to-end regression coverage for the realistic workflow corpus."""

from __future__ import annotations

import json
import shutil
from dataclasses import replace
from pathlib import Path

import pytest

from finsec.behavior.corpus_evaluator import (
    _evaluate_run,
    evaluate_realistic_quality_gate_configuration,
    load_realistic_quality_gate_configuration,
    realistic_quality_gate_failures,
    render_realistic_markdown,
    write_realistic_report,
)
from finsec.behavior.corpus_metrics import CorpusEvaluation
from finsec.behavior.corpus_runner import CorpusRunResult, run_realistic_corpus_journey
from finsec.behavior.domain import (
    CausalBasis,
    HypothesisReadiness,
    PropagationLink,
    RelationshipType,
)
from finsec.behavior.realistic_corpus import (
    CausalEdgeLabel,
    CorpusCapture,
    CorpusJourney,
    CorpusTrafficEntry,
    RealisticCorpusLoader,
    load_realistic_corpus,
)

CORPUS_ROOT = Path(__file__).parent / "fixtures" / "workflow_realistic"
GATE_CONFIGURATION = CORPUS_ROOT / "quality-gates.yaml"
RUN_JOURNEYS = (
    "adversarial",
    "capability-handoff",
    "cross-capture-continuation",
    "multi-service-payment",
    "resource-lifecycle",
    "token-aliases",
    "unfamiliar-state-transitions",
)


@pytest.fixture(scope="module")
def loader() -> RealisticCorpusLoader:
    return load_realistic_corpus(CORPUS_ROOT)


@pytest.fixture(scope="module")
def runs(
    loader: RealisticCorpusLoader,
    tmp_path_factory: pytest.TempPathFactory,
) -> dict[str, CorpusRunResult]:
    root = tmp_path_factory.mktemp("realistic-runs")
    return {
        journey_id: run_realistic_corpus_journey(loader.load_journey(journey_id), root / journey_id)
        for journey_id in RUN_JOURNEYS
    }


@pytest.fixture(scope="module")
def quality_reports(
    tmp_path_factory: pytest.TempPathFactory,
) -> tuple[CorpusEvaluation, CorpusEvaluation]:
    root = tmp_path_factory.mktemp("realistic-quality-gates")
    return evaluate_realistic_quality_gate_configuration(GATE_CONFIGURATION, root)


def _link(
    run: CorpusRunResult,
    producer: str,
    consumer: str,
    basis: CausalBasis | None = None,
) -> PropagationLink:
    reverse_ids = {value: key for key, value in run.label_observation_ids.items()}
    return next(
        link
        for link in run.propagation_links
        if reverse_ids[link.source_observation_id] == producer
        and reverse_ids[link.destination_observation_id] == consumer
        and (basis is None or link.causal_basis == basis)
    )


def _canonical_run(run: CorpusRunResult) -> bytes:
    return json.dumps(
        run.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
    ).encode()


def _boundary_journey(
    journey_id: str,
    *,
    source_session: str,
    destination_session: str,
) -> CorpusJourney:
    identifier = "ORD_BOUNDARY_7C9M2Q5R8T1V4X6Z"
    return CorpusJourney(
        id=journey_id,
        name=journey_id,
        first_party_hosts=["api.boundary.test"],
        captures=[
            CorpusCapture(
                name="producer",
                actor="ACCOUNT_A",
                session=source_session,
                entries=[
                    CorpusTrafficEntry(
                        label="create_order",
                        offset_seconds=0,
                        method="POST",
                        path="/api/orders",
                        host="api.boundary.test",
                        request={"quantity": 1},
                        response={"orderId": identifier, "status": "CREATED"},
                        status=201,
                    )
                ],
            ),
            CorpusCapture(
                name="consumer",
                actor="ACCOUNT_A",
                session=destination_session,
                entries=[
                    CorpusTrafficEntry(
                        label="confirm_order",
                        offset_seconds=2,
                        method="POST",
                        path=f"/api/orders/{identifier}/confirm",
                        host="api.boundary.test",
                        request={},
                        response={"orderId": identifier, "status": "CONFIRMED"},
                    )
                ],
            ),
        ],
    )


def test_real_corpus_traffic_runs_through_production_pipeline(
    runs: dict[str, CorpusRunResult],
) -> None:
    run = runs["resource-lifecycle"]

    assert len(run.observations) == 4
    assert set(run.label_observation_ids) == {
        "create_order",
        "read_order_1",
        "confirm_order",
        "read_order_2",
    }
    assert all("-redacted.har#entry-" in item.source_reference for item in run.observations)
    assert run.actions
    assert run.resources
    assert run.propagation_links
    assert run.workflow_instances
    assert run.workflow_families
    assert run.prerequisites
    assert run.invariants
    assert run.hypotheses


def test_mutating_expected_labels_cannot_change_reconstruction_output(tmp_path: Path) -> None:
    copied_corpus = tmp_path / "workflow-realistic"
    shutil.copytree(CORPUS_ROOT, copied_corpus)
    loader = load_realistic_corpus(copied_corpus)
    first = run_realistic_corpus_journey(
        loader.load_journey("resource-lifecycle"), tmp_path / "first"
    )

    labels = copied_corpus / "labels" / "causal-edges.yaml"
    labels.write_text("this is deliberately not valid label data\n", encoding="utf-8")
    second = run_realistic_corpus_journey(
        load_realistic_corpus(copied_corpus).load_journey("resource-lifecycle"),
        tmp_path / "second",
    )

    assert _canonical_run(first) == _canonical_run(second)


def test_fully_labeled_corpus_recovers_graph_structure_and_order(
    quality_reports: tuple[CorpusEvaluation, CorpusEvaluation],
) -> None:
    report, _repeated = quality_reports
    statistics = report.statistics
    aggregate = report.aggregate

    assert statistics.model_dump(mode="json") == {
        "journey_count": 9,
        "observation_count": 36,
        "expected_hard_edges": 28,
        "expected_soft_edges": 0,
        "forbidden_edges": 9,
        "expected_prerequisites": 19,
        "expected_state_transitions": 3,
    }
    assert aggregate.causal_edges.true_positive == 28
    assert aggregate.causal_edges.precision == 1.0
    assert aggregate.causal_edges.recall == 1.0
    assert aggregate.label_coverage == 1.0
    assert aggregate.component_membership.precision == 1.0
    assert aggregate.component_membership.recall == 1.0
    assert aggregate.expected_components == 14
    assert aggregate.actual_components == 14
    assert aggregate.journey_retention == 1.0
    assert aggregate.fragmented_journeys == 0
    assert aggregate.order_retention == 1.0
    assert aggregate.prerequisites.true_positive == 19
    assert aggregate.prerequisites.precision == 1.0
    assert aggregate.prerequisites.recall == 1.0
    assert aggregate.state_transitions.true_positive == 3
    assert aggregate.state_transitions.precision == 1.0
    assert aggregate.state_transitions.recall == 1.0
    assert aggregate.singleton_count == 4
    assert aggregate.workflow_instance_count == 14
    assert aggregate.singleton_rate == pytest.approx(2 / 7)


def test_causal_metrics_are_stratified_with_complete_recall(
    quality_reports: tuple[CorpusEvaluation, CorpusEvaluation],
) -> None:
    report, _repeated = quality_reports
    expected_counts = {
        "resource_creation": 21,
        "capability_issuance": 4,
        "state_transition": 3,
        "multi_service_handoff": 2,
        "cross_capture_continuation": 6,
        "nested_resource": 3,
    }

    assert set(report.aggregate.metrics_by_causal_category) == set(expected_counts)
    for category, expected in expected_counts.items():
        metrics = report.aggregate.metrics_by_causal_category[category]
        assert metrics.expected == expected
        assert metrics.actual == expected
        assert metrics.precision == 1.0
        assert metrics.recall == 1.0


def test_unfamiliar_capabilities_are_recovered_from_structural_evidence(
    runs: dict[str, CorpusRunResult],
) -> None:
    challenge = _link(
        runs["capability-handoff"],
        "get_checkout",
        "authorize_payment",
        CausalBasis.CAPABILITY_ISSUED,
    )
    alias = _link(
        runs["token-aliases"],
        "start_auth",
        "verify_auth",
        CausalBasis.CAPABILITY_ISSUED,
    )

    assert challenge.relationship_type == RelationshipType.CAUSAL_HARD
    assert challenge.causal_evidence.output_only
    assert challenge.causal_evidence.later_consumed
    assert challenge.causal_evidence.capability_semantics
    assert challenge.causal_evidence.consumer_state_changing
    assert not challenge.causal_evidence.persistent_resource_identity
    assert challenge.causal_evidence.hard_causal_admissibility(challenge.causal_basis)
    assert alias.source_field == "$.continuation"
    assert alias.destination_field == "$.sessionReference"
    assert alias.causal_evidence.field_alias_compatible
    assert alias.causal_evidence.hard_causal_admissibility(alias.causal_basis)


def test_resource_creation_evidence_does_not_mark_post_201_as_read_only(
    runs: dict[str, CorpusRunResult],
) -> None:
    run = runs["resource-lifecycle"]
    link = _link(run, "create_order", "confirm_order", CausalBasis.RESOURCE_CREATED)

    assert link.causal_evidence.source_created_resource
    assert not link.causal_evidence.source_is_read
    assert link.causal_evidence.hard_causal_admissibility(link.causal_basis)


def test_same_identifier_field_is_classified_from_behavior_not_name(
    runs: dict[str, CorpusRunResult],
    tmp_path: Path,
) -> None:
    persistent = _link(
        runs["multi-service-payment"],
        "create_transaction",
        "call_payments",
        CausalBasis.RESOURCE_CREATED,
    )
    identifier = "TXN_CONTEXT_7C9M2Q5R8T1V4X6Z"
    capability_journey = CorpusJourney(
        id="same-name-capability",
        name="same-name-capability",
        first_party_hosts=["auth.example.test"],
        captures=[
            CorpusCapture(
                name="auth",
                actor="ACCOUNT_A",
                session="auth-flow",
                entries=[
                    CorpusTrafficEntry(
                        label="start_auth",
                        offset_seconds=0,
                        method="GET",
                        path="/api/auth/start",
                        host="auth.example.test",
                        response={"transactionId": identifier},
                    ),
                    CorpusTrafficEntry(
                        label="complete_auth",
                        offset_seconds=2,
                        method="POST",
                        path="/api/auth/complete",
                        host="auth.example.test",
                        request={"transactionId": identifier},
                        response={"status": "COMPLETE"},
                    ),
                ],
            )
        ],
    )
    capability_run = run_realistic_corpus_journey(capability_journey, tmp_path)
    capability = _link(
        capability_run,
        "start_auth",
        "complete_auth",
        CausalBasis.CAPABILITY_ISSUED,
    )

    assert persistent.source_field == "$.transactionId"
    assert persistent.causal_evidence.persistent_resource_identity
    assert capability.source_field == "$.transactionId"
    assert not capability.causal_evidence.persistent_resource_identity
    assert capability.causal_evidence.capability_semantics


def test_unknown_state_names_are_reconstructed_structurally(
    runs: dict[str, CorpusRunResult],
) -> None:
    run = runs["unfamiliar-state-transitions"]
    observed_states = {item.name for item in run.states if item.resource_type == "payment"}
    transitions = {
        (item.source_state, item.destination_state)
        for item in run.state_transitions
        if item.resource_types == ["payment"]
    }

    assert {"FROZEN", "CRYSTALLIZED", "SEALED", "ARCHIVED"} <= observed_states
    assert {
        ("FROZEN", "CRYSTALLIZED"),
        ("CRYSTALLIZED", "SEALED"),
        ("SEALED", "ARCHIVED"),
    } <= transitions
    state_link = _link(
        run,
        "capture_payment",
        "settle_payment",
        CausalBasis.STATE_TRANSITION_PRODUCED,
    )
    assert state_link.causal_evidence.state_transition_evidence
    assert state_link.causal_evidence.direct_state_transition
    assert state_link.causal_evidence.hard_causal_admissibility(state_link.causal_basis)


def test_cross_capture_and_multi_service_edges_require_admissible_boundaries(
    runs: dict[str, CorpusRunResult],
) -> None:
    cross_capture = runs["cross-capture-continuation"]
    cross_capture_hard = [
        link
        for link in cross_capture.propagation_links
        if link.relationship_type == RelationshipType.CAUSAL_HARD
    ]
    assert len(cross_capture_hard) == 4
    assert all(link.source_capture != link.destination_capture for link in cross_capture_hard)
    assert all(link.causal_evidence.same_session for link in cross_capture_hard)
    assert all(link.causal_evidence.capture_compatible for link in cross_capture_hard)

    multi_service = runs["multi-service-payment"]
    cross_host_hard = [
        link
        for link in multi_service.propagation_links
        if link.relationship_type == RelationshipType.CAUSAL_HARD
        and link.source_host != link.destination_host
    ]
    assert len(cross_host_hard) == 2
    assert all(link.causal_evidence.same_session for link in cross_host_hard)
    assert all(link.causal_evidence.host_compatible for link in cross_host_hard)


def test_cross_session_reuse_remains_soft_and_non_merging(tmp_path: Path) -> None:
    run = run_realistic_corpus_journey(
        _boundary_journey(
            "cross-session-negative",
            source_session="session-a",
            destination_session="session-b",
        ),
        tmp_path,
    )
    link = _link(run, "create_order", "confirm_order")

    assert link.relationship_type == RelationshipType.CONTEXT_SOFT
    assert link.causal_basis == CausalBasis.RESOURCE_CREATED
    assert not link.causal_evidence.session_compatible
    assert not link.causal_evidence.capture_compatible
    assert link.rejection_reasons == ["session_incompatible", "capture_incompatible"]
    assert len(run.workflow_instances) == 2


def test_unrelated_first_party_services_do_not_merge_on_equal_literals(tmp_path: Path) -> None:
    identifier = "REF_BOUNDARY_7C9M2Q5R8T1V4X6Z"
    journey = CorpusJourney(
        id="unrelated-first-party",
        name="unrelated-first-party",
        first_party_hosts=["orders.example.test", "reports.example.test"],
        captures=[
            CorpusCapture(
                name="orders",
                actor="ACCOUNT_A",
                session="shared-session",
                entries=[
                    CorpusTrafficEntry(
                        label="create_order",
                        offset_seconds=0,
                        method="POST",
                        path="/api/orders",
                        host="orders.example.test",
                        request={"quantity": 1},
                        response={"orderId": identifier, "status": "CREATED"},
                        status=201,
                    )
                ],
            ),
            CorpusCapture(
                name="reports",
                actor="ACCOUNT_A",
                session="shared-session",
                entries=[
                    CorpusTrafficEntry(
                        label="publish_report",
                        offset_seconds=2,
                        method="POST",
                        path=f"/api/reports/{identifier}/publish",
                        host="reports.example.test",
                        request={},
                        response={"reportId": identifier, "status": "PUBLISHED"},
                    )
                ],
            ),
        ],
    )
    run = run_realistic_corpus_journey(journey, tmp_path)

    assert not any(
        link.relationship_type == RelationshipType.CAUSAL_HARD for link in run.propagation_links
    )
    assert len(run.workflow_instances) == 2


def test_collection_ids_and_repeated_noise_values_remain_non_causal(tmp_path: Path) -> None:
    collection_id = "ORD_COLLECTION_7C9M2Q5R8T1V4X6Z"
    cursor = "CURSOR_7C9M2Q5R8T1V4X6Z"
    timestamp = "2026-08-05T10:00:00Z"
    journey = CorpusJourney(
        id="noise-values",
        name="noise-values",
        first_party_hosts=["api.noise.test"],
        captures=[
            CorpusCapture(
                name="noise",
                actor="ACCOUNT_A",
                session="noise-session",
                entries=[
                    CorpusTrafficEntry(
                        label="list_orders",
                        offset_seconds=0,
                        method="GET",
                        path="/api/orders",
                        host="api.noise.test",
                        response={
                            "orders": [{"orderId": collection_id}],
                            "active": True,
                            "amount": 100,
                            "timestamp": timestamp,
                            "cursor": cursor,
                        },
                    ),
                    CorpusTrafficEntry(
                        label="create_report",
                        offset_seconds=2,
                        method="POST",
                        path="/api/reports",
                        host="api.noise.test",
                        request={
                            "orderId": collection_id,
                            "active": True,
                            "amount": 100,
                            "timestamp": timestamp,
                            "cursor": cursor,
                        },
                        response={
                            "reportId": "RPT_NOISE_7C9M2Q5R8T1V4X6Z",
                            "status": "ACTIVE",
                        },
                        status=201,
                    ),
                ],
            )
        ],
    )
    run = run_realistic_corpus_journey(journey, tmp_path)
    link = _link(run, "list_orders", "create_report")

    assert link.relationship_type == RelationshipType.CONTEXT_SOFT
    assert link.causal_basis == CausalBasis.EXISTING_VALUE_OBSERVED
    assert link.causal_evidence.collection_member
    assert link.rejection_reasons == ["response_collection_member_observed"]
    assert not any(
        item.relationship_type == RelationshipType.CAUSAL_HARD for item in run.propagation_links
    )
    assert len(run.workflow_instances) == 2


def test_missed_edges_report_exact_structural_rejection_reasons(
    loader: RealisticCorpusLoader,
    runs: dict[str, CorpusRunResult],
) -> None:
    journey = next(item for item in loader.load_journey_labels() if item.id == "resource-lifecycle")
    expected = CausalEdgeLabel(
        id="diagnostic-read-edge",
        journey=journey.id,
        producer="read_order_1",
        consumer="confirm_order",
        field_name="orderId",
        relationship=RelationshipType.CAUSAL_HARD,
        expected_basis=CausalBasis.RESOURCE_CREATED,
        status="expected",
    )
    details = _evaluate_run(runs[journey.id], journey, [expected], [], [])
    diagnostic = details.evaluation.missed_edges[0]

    assert diagnostic.actual_basis == CausalBasis.REQUEST_VALUE_ECHOED
    assert diagnostic.actual_relationship == RelationshipType.CONTEXT_SOFT
    assert diagnostic.evidence.source_is_read
    assert diagnostic.rejection_reasons == [
        "request_value_echoed",
        "source_is_read_only",
        "value_previously_observed",
        "output_only_production_not_proven",
        "admissible_producer_semantics_not_proven",
    ]


def test_fragmented_journeys_explain_each_missing_bridge(
    loader: RealisticCorpusLoader,
    runs: dict[str, CorpusRunResult],
) -> None:
    original = next(item for item in loader.load_journey_labels() if item.id == "adversarial")
    journey = replace(
        original,
        expected_observations=["get_account", "post_transfer"],
        expected_components=1,
        expected_order=True,
        expected_steps=["get_account", "post_transfer"],
        expected_component_groups=[["get_account", "post_transfer"]],
    )
    expected = CausalEdgeLabel(
        id="diagnostic-fragmentation-edge",
        journey=journey.id,
        producer="get_account",
        consumer="post_transfer",
        field_name="accountId",
        relationship=RelationshipType.CAUSAL_HARD,
        expected_basis=CausalBasis.RESOURCE_CREATED,
        status="expected",
    )
    details = _evaluate_run(runs[journey.id], journey, [expected], [], [])
    diagnostic = details.evaluation.fragmentation

    assert details.evaluation.fragmented
    assert diagnostic is not None
    assert diagnostic.expected_components == 1
    assert diagnostic.actual_components == 2
    assert diagnostic.breaks[0].producer == "get_account"
    assert diagnostic.breaks[0].consumer == "post_transfer"
    assert diagnostic.breaks[0].rejection_reasons == ["no_admissible_causal_bridge"]
    assert details.evaluation.missed_edges[0].rejection_reasons == [
        "matching_value_not_extracted_or_consumed"
    ]


def test_adversarial_and_hypothesis_safety_counters_remain_zero(
    quality_reports: tuple[CorpusEvaluation, CorpusEvaluation],
    runs: dict[str, CorpusRunResult],
) -> None:
    report, _repeated = quality_reports
    aggregate = report.aggregate

    assert aggregate.forbidden_hard_edges == 0
    assert aggregate.forbidden_merges == 0
    assert aggregate.forbidden_prerequisites == 0
    assert aggregate.cross_actor_violations == 0
    assert aggregate.cross_session_violations == 0
    assert aggregate.request_echo_violations == 0
    assert aggregate.read_existing_id_violations == 0
    assert aggregate.test_ready_with_blockers == 0
    assert not any(
        hypothesis.readiness == HypothesisReadiness.TEST_READY and hypothesis.readiness_blockers
        for run in runs.values()
        for hypothesis in run.hypotheses
    )


def test_corpus_json_markdown_and_metrics_are_byte_deterministic(
    quality_reports: tuple[CorpusEvaluation, CorpusEvaluation],
    tmp_path: Path,
) -> None:
    first, second = quality_reports

    assert first.aggregate.deterministic_output
    assert second.aggregate.deterministic_output
    assert first.model_dump(mode="json") == second.model_dump(mode="json")
    assert render_realistic_markdown(first) == render_realistic_markdown(second)

    write_realistic_report(first, tmp_path / "first.json", tmp_path / "first.md")
    write_realistic_report(second, tmp_path / "second.json", tmp_path / "second.md")
    assert (tmp_path / "first.json").read_bytes() == (tmp_path / "second.json").read_bytes()
    assert (tmp_path / "first.md").read_bytes() == (tmp_path / "second.md").read_bytes()


@pytest.mark.parametrize(
    ("updates", "failure_code"),
    [
        ({"forbidden_hard_edges": 1}, "FORBIDDEN_HARD_EDGES"),
        ({"forbidden_merges": 1}, "FORBIDDEN_MERGES"),
        ({"forbidden_prerequisites": 1}, "FORBIDDEN_PREREQUISITES"),
        ({"fragmented_journeys": 1}, "FRAGMENTED_JOURNEYS"),
        ({"test_ready_with_blockers": 1}, "TEST_READY_WITH_BLOCKERS"),
        ({"cross_actor_violations": 1}, "CROSS_ACTOR_VIOLATIONS"),
        ({"cross_session_violations": 1}, "CROSS_SESSION_VIOLATIONS"),
        ({"request_echo_violations": 1}, "REQUEST_ECHO_VIOLATIONS"),
        ({"read_existing_id_violations": 1}, "READ_EXISTING_ID_VIOLATIONS"),
    ],
)
def test_quality_gates_fail_for_safety_regressions(
    quality_reports: tuple[CorpusEvaluation, CorpusEvaluation],
    updates: dict[str, object],
    failure_code: str,
) -> None:
    report, _repeated = quality_reports
    gate = load_realistic_quality_gate_configuration(GATE_CONFIGURATION)
    mutated = report.model_copy(update={"aggregate": report.aggregate.model_copy(update=updates)})

    assert failure_code in realistic_quality_gate_failures(
        mutated, gate.thresholds, repeated_report=mutated
    )


def test_quality_gate_detects_metric_and_determinism_regressions(
    quality_reports: tuple[CorpusEvaluation, CorpusEvaluation],
) -> None:
    report, repeated = quality_reports
    gate = load_realistic_quality_gate_configuration(GATE_CONFIGURATION)
    reduced_recall = report.model_copy(
        update={
            "aggregate": report.aggregate.model_copy(
                update={
                    "causal_edges": report.aggregate.causal_edges.model_copy(update={"recall": 0.9})
                }
            )
        }
    )
    changed_repeat = repeated.model_copy(
        update={
            "aggregate": repeated.aggregate.model_copy(
                update={"singleton_count": repeated.aggregate.singleton_count + 1}
            )
        }
    )

    assert "CAUSAL_EDGE_RECALL" in realistic_quality_gate_failures(
        reduced_recall, gate.thresholds, repeated_report=reduced_recall
    )
    assert "NON_DETERMINISTIC_OUTPUT" in realistic_quality_gate_failures(
        report, gate.thresholds, repeated_report=changed_repeat
    )
