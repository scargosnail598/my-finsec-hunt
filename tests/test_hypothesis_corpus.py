"""Regression coverage for the fully labeled BLH precision corpus."""

from __future__ import annotations

from pathlib import Path

from finsec.behavior.hypothesis_corpus import (
    HypothesisCorpusGateThresholds,
    evaluate_hypothesis_corpus,
    evaluate_hypothesis_corpus_gate_configuration,
    hypothesis_corpus_gate_failures,
    load_hypothesis_corpus,
    render_hypothesis_corpus_markdown,
    write_hypothesis_corpus_report,
)

FIXTURE = Path(__file__).parent / "fixtures" / "hypothesis_precision" / "corpus.yaml"
GATES = Path(__file__).parent / "fixtures" / "hypothesis_precision" / "quality-gates.yaml"


def test_fully_labeled_corpus_reports_exact_precision_and_compression() -> None:
    report = evaluate_hypothesis_corpus(load_hypothesis_corpus(FIXTURE))
    metrics = report.aggregate

    assert metrics.raw_candidates == 12
    assert metrics.unique_semantic_hypotheses == 10
    assert metrics.visible_research_items == 5
    assert metrics.suppressed_low_value_candidates == 5
    assert metrics.semantic_precision == 1.0
    assert metrics.semantic_recall == 1.0
    assert metrics.suppression_precision == 1.0
    assert metrics.research_queue_compression_ratio == 5 / 12
    assert metrics.evidence_provenance_loss == 0


def test_corpus_quality_gates_and_repeated_output_are_deterministic() -> None:
    first, second = evaluate_hypothesis_corpus_gate_configuration(GATES)

    assert first.model_dump(mode="json") == second.model_dump(mode="json")
    assert not hypothesis_corpus_gate_failures(
        first,
        HypothesisCorpusGateThresholds(),
        repeated_report=second,
    )


def test_corpus_structural_quality_gates_are_zero() -> None:
    metrics = evaluate_hypothesis_corpus(load_hypothesis_corpus(FIXTURE)).aggregate

    assert metrics.duplicate_semantic_hypotheses == 0
    assert metrics.self_referential_visible == 0
    assert metrics.malformed_label_visible == 0
    assert metrics.test_ready_with_blockers == 0
    assert metrics.top_10_family_distribution == {
        "ACTOR_SWITCH": 1,
        "CONCURRENT_EXECUTION": 1,
        "QUANTITY_VALUE_INVARIANT": 1,
        "REPLAY": 1,
        "RESOURCE_SWITCH": 1,
    }


def test_corpus_gate_reports_deliberate_precision_and_determinism_regressions() -> None:
    report = evaluate_hypothesis_corpus(load_hypothesis_corpus(FIXTURE))
    regressed = report.model_copy(deep=True)
    regressed.aggregate.semantic_precision = 0.5

    failures = hypothesis_corpus_gate_failures(
        regressed,
        HypothesisCorpusGateThresholds(),
        repeated_report=report,
    )

    assert "SEMANTIC_PRECISION" in failures
    assert "NON_DETERMINISTIC_OUTPUT" in failures


def test_corpus_json_and_markdown_reports_are_byte_stable(tmp_path: Path) -> None:
    report = evaluate_hypothesis_corpus(load_hypothesis_corpus(FIXTURE))
    first_json = tmp_path / "first.json"
    first_markdown = tmp_path / "first.md"
    second_json = tmp_path / "second.json"
    second_markdown = tmp_path / "second.md"

    write_hypothesis_corpus_report(report, first_json, first_markdown)
    write_hypothesis_corpus_report(report, second_json, second_markdown)

    assert first_json.read_bytes() == second_json.read_bytes()
    assert first_markdown.read_bytes() == second_markdown.read_bytes()
    assert first_markdown.read_text(encoding="utf-8") == render_hypothesis_corpus_markdown(report)
