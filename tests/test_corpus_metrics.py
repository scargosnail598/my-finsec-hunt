"""Tests for realistic-corpus metric contracts and diagnostics."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from finsec.behavior.corpus_metrics import (
    ClassificationMetrics,
    FragmentationBreak,
    FragmentationDiagnostic,
    MissedEdgeDiagnostic,
    RealisticQualityGateThresholds,
)
from finsec.behavior.domain import CausalBasis, CausalEvidence, RelationshipType


def test_classification_metrics_preserve_explicit_denominators() -> None:
    metrics = ClassificationMetrics(
        expected=3,
        actual=2,
        true_positive=2,
        false_positive=0,
        false_negative=1,
        precision=1.0,
        recall=2 / 3,
        f1=0.8,
    )

    assert metrics.model_dump(mode="json") == {
        "expected": 3,
        "actual": 2,
        "true_positive": 2,
        "false_positive": 0,
        "false_negative": 1,
        "precision": 1.0,
        "recall": 2 / 3,
        "f1": 0.8,
    }


def test_metric_contracts_reject_out_of_range_and_unknown_fields() -> None:
    with pytest.raises(ValidationError):
        ClassificationMetrics(
            expected=1,
            actual=1,
            true_positive=1,
            false_positive=0,
            false_negative=0,
            precision=1.1,
            recall=1.0,
            f1=1.0,
        )

    with pytest.raises(ValidationError):
        RealisticQualityGateThresholds(unreviewed_threshold=0)  # type: ignore[call-arg]


def test_missed_edge_diagnostic_persists_canonical_evidence_and_reasons() -> None:
    evidence = CausalEvidence(
        output_only=True,
        later_consumed=True,
        temporal_order=True,
        same_controlled_actor=True,
        session_compatible=True,
        capture_compatible=True,
        host_compatible=True,
        distinctive_value=True,
        consumer_state_changing=False,
    )
    diagnostic = MissedEdgeDiagnostic(
        edge_id="edge-1",
        journey="checkout",
        producer="issue",
        consumer="consume",
        producer_field="challenge",
        consumer_field="authorization_reference",
        expected_basis=CausalBasis.CAPABILITY_ISSUED,
        expected_relationship=RelationshipType.CAUSAL_HARD,
        actual_basis=CausalBasis.AMBIGUOUS_ORIGIN,
        actual_relationship=RelationshipType.CONTEXT_SOFT,
        evidence=evidence,
        rejection_reasons=["consumer_does_not_advance_workflow"],
    )

    payload = diagnostic.model_dump(mode="json")
    assert payload["evidence"]["output_only"] is True
    assert payload["evidence"]["consumer_state_changing"] is False
    assert payload["rejection_reasons"] == ["consumer_does_not_advance_workflow"]


def test_fragmentation_diagnostic_records_each_structural_break() -> None:
    diagnostic = FragmentationDiagnostic(
        journey="payment-confirmation",
        expected_components=1,
        actual_components=2,
        breaks=[
            FragmentationBreak(
                producer="issue",
                consumer="confirm",
                expected_basis=CausalBasis.CAPABILITY_ISSUED,
                actual_basis=CausalBasis.AMBIGUOUS_ORIGIN,
                actual_relationship=RelationshipType.CONTEXT_SOFT,
                rejection_reasons=["capability_semantics_not_proven"],
            )
        ],
    )

    assert diagnostic.breaks[0].rejection_reasons == ["capability_semantics_not_proven"]


def test_quality_gate_defaults_keep_precision_and_safety_strict() -> None:
    thresholds = RealisticQualityGateThresholds()

    assert thresholds.min_causal_edge_precision == 1.0
    assert thresholds.min_causal_edge_recall == 1.0
    assert thresholds.max_forbidden_hard_edges == 0
    assert thresholds.max_forbidden_merges == 0
    assert thresholds.max_forbidden_prerequisites == 0
    assert thresholds.max_test_ready_with_blockers == 0
    assert thresholds.require_deterministic_output is True
