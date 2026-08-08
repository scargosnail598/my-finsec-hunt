"""Tests for realistic workflow corpus loading and validation."""

from __future__ import annotations

from pathlib import Path

import pytest

from finsec.behavior.realistic_corpus import RealisticCorpusLoader, load_realistic_corpus

CORPUS_ROOT = Path(__file__).parent / "fixtures" / "workflow_realistic"


@pytest.fixture(scope="module")
def corpus() -> RealisticCorpusLoader:
    """Load the realistic corpus once per module."""
    return load_realistic_corpus(CORPUS_ROOT)


def test_corpus_structure_is_valid(corpus: RealisticCorpusLoader) -> None:
    """Verify corpus directories and files exist."""
    assert (CORPUS_ROOT / "journeys").is_dir()
    assert (CORPUS_ROOT / "labels").is_dir()
    assert (CORPUS_ROOT / "labels" / "causal-edges.yaml").exists()
    assert (CORPUS_ROOT / "labels" / "journeys.yaml").exists()
    assert (CORPUS_ROOT / "labels" / "prerequisites.yaml").exists()
    assert (CORPUS_ROOT / "labels" / "state-transitions.yaml").exists()


def test_all_journey_directories_exist(corpus: RealisticCorpusLoader) -> None:
    """Verify each expected journey has a directory with fixtures."""
    journey_labels = corpus.load_journey_labels()
    assert len(journey_labels) > 0, "Corpus has no journeys"

    for journey in journey_labels:
        journey_dir = CORPUS_ROOT / "journeys" / journey.id
        assert journey_dir.is_dir(), f"Missing journey directory: {journey.id}"
        assert (journey_dir / "journeys.json").exists(), (
            f"Missing fixture for journey: {journey.id}"
        )


def test_all_journeys_have_readmes(corpus: RealisticCorpusLoader) -> None:
    """Verify each journey directory has a README."""
    journey_labels = corpus.load_journey_labels()
    for journey in journey_labels:
        readme = CORPUS_ROOT / "journeys" / journey.id / "README.md"
        assert readme.exists(), f"Missing README for journey: {journey.id}"


def test_causal_edges_load_successfully(corpus: RealisticCorpusLoader) -> None:
    """Verify all causal edges can be parsed."""
    edges = corpus.load_causal_edges()
    assert len(edges) > 0, "Corpus has no causal edges"
    assert all(e.id for e in edges), "Some edges have no ID"
    assert all(e.producer for e in edges), "Some edges have no producer"
    assert all(e.consumer for e in edges), "Some edges have no consumer"


def test_journey_labels_load_successfully(corpus: RealisticCorpusLoader) -> None:
    """Verify all journey labels can be parsed."""
    journeys = corpus.load_journey_labels()
    assert len(journeys) > 0, "Corpus has no journeys"
    assert all(j.id for j in journeys), "Some journeys have no ID"
    assert all(j.expected_observations for j in journeys), "Some journeys have no observations"


def test_prerequisites_load_successfully(corpus: RealisticCorpusLoader) -> None:
    """Verify all prerequisites can be parsed."""
    prereqs = corpus.load_prerequisites()
    assert len(prereqs) > 0, "Corpus has no prerequisites"
    assert all(p.id for p in prereqs), "Some prerequisites have no ID"


def test_state_transitions_load_successfully(corpus: RealisticCorpusLoader) -> None:
    transitions = corpus.load_state_transitions()

    assert len(transitions) == 3
    assert all(item.id for item in transitions)
    assert all(item.from_state != item.to_state for item in transitions)


def test_expected_edges_count() -> None:
    """Verify expected edges count matches corpus statistics."""
    corpus = load_realistic_corpus(CORPUS_ROOT)
    edges = corpus.load_causal_edges()

    expected = [e for e in edges if e.status == "expected"]
    forbidden = [e for e in edges if e.status == "forbidden"]

    assert len(expected) == 28
    assert len(forbidden) == 9


def test_journey_categories() -> None:
    """Verify journeys are properly categorized."""
    corpus = load_realistic_corpus(CORPUS_ROOT)
    categories = corpus.get_journey_categories()

    # Should have multiple categories
    assert len(categories) > 1, "Corpus should have multiple categories"

    # Each category should have at least one journey
    for category, journeys in categories.items():
        assert len(journeys) > 0, f"Category {category} has no journeys"


def test_load_journey_fixtures() -> None:
    """Verify journey fixtures can be loaded as JSON."""
    corpus = load_realistic_corpus(CORPUS_ROOT)
    journeys = corpus.load_journey_labels()

    for journey in journeys[:3]:  # Test first 3 journeys
        fixture = corpus.load_journey_fixtures(journey.id)
        assert fixture is not None, f"Failed to load fixture for {journey.id}"
        assert "name" in fixture or "entries" in fixture or "captures" in fixture


def test_journey_inputs_include_actor_session_host_and_order_metadata() -> None:
    corpus = load_realistic_corpus(CORPUS_ROOT)

    for label in corpus.load_journey_labels():
        journey = corpus.load_journey(label.id)
        assert journey.first_party_hosts
        assert journey.captures
        for capture in journey.captures:
            assert capture.actor
            assert capture.session
            assert capture.entries
            assert all(entry.host for entry in capture.entries)
            assert all(entry.method for entry in capture.entries)
            assert all(entry.path.startswith("/") for entry in capture.entries)
            assert [entry.offset_seconds for entry in capture.entries] == sorted(
                entry.offset_seconds for entry in capture.entries
            )


def test_corpus_statistics() -> None:
    """Verify corpus has expected statistics from labels."""
    corpus = load_realistic_corpus(CORPUS_ROOT)

    journeys = corpus.load_journey_labels()
    edges = corpus.load_causal_edges()
    prereqs = corpus.load_prerequisites()
    transitions = corpus.load_state_transitions()

    assert len(journeys) == 9
    assert sum(len(item.expected_observations) for item in journeys) == 36
    assert len(edges) == 37
    assert len(prereqs) == 26
    assert len(transitions) == 3


def test_adversarial_corpus_included() -> None:
    """Verify adversarial journey is included."""
    corpus = load_realistic_corpus(CORPUS_ROOT)
    journeys = corpus.load_journey_labels()

    categories = {}
    for j in journeys:
        if j.category not in categories:
            categories[j.category] = []
        categories[j.category].append(j.id)

    # Adversarial category should exist
    assert "adversarial" in categories, "Missing adversarial category"
    # Should contain a single comprehensive adversarial journey with multiple independent workflows
    adversarial_journeys = categories["adversarial"]
    assert len(adversarial_journeys) >= 1, "Should have at least one adversarial journey"


def test_no_duplicate_edge_ids() -> None:
    """Verify all edge IDs are unique."""
    corpus = load_realistic_corpus(CORPUS_ROOT)
    edges = corpus.load_causal_edges()

    edge_ids = [e.id for e in edges]
    assert len(edge_ids) == len(set(edge_ids)), "Duplicate edge IDs found"


def test_all_edges_reference_valid_journeys() -> None:
    """Verify all edges reference journeys that exist."""
    corpus = load_realistic_corpus(CORPUS_ROOT)
    edges = corpus.load_causal_edges()
    journeys = {j.id for j in corpus.load_journey_labels()}

    for edge in edges:
        assert edge.journey in journeys, f"Edge {edge.id} references unknown journey {edge.journey}"


def test_all_prerequisites_reference_valid_journeys() -> None:
    """Verify all prerequisites reference journeys that exist."""
    corpus = load_realistic_corpus(CORPUS_ROOT)
    prereqs = corpus.load_prerequisites()
    journeys = {j.id for j in corpus.load_journey_labels()}

    for prereq in prereqs:
        assert prereq.journey in journeys, (
            f"Prerequisite {prereq.id} references unknown journey {prereq.journey}"
        )
