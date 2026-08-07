"""Realistic workflow corpus loading and validation infrastructure.

This module provides utilities to load the structured realistic workflow corpus,
parse ground truth labels, and compute recall/precision metrics against
reconstruction engine output.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from finsec.behavior.domain import CausalBasis, RelationshipType


@dataclass
class CausalEdgeLabel:
    """Ground truth label for a single expected or forbidden causal edge."""

    id: str
    journey: str
    producer: str
    consumer: str
    field_name: str
    resource_type: str | None = None
    value: str | None = None
    relationship: RelationshipType = RelationshipType.CAUSAL_HARD
    expected_basis: CausalBasis | None = None
    status: str = "expected"  # expected, forbidden, unknown
    reason: str = ""
    distinctive: bool = False
    cross_host: bool = False
    cross_capture: bool = False
    cross_actor: bool = False
    same_actor: bool = True
    state_transition: bool = False
    output_only: bool = False
    request_echo: bool = False
    coincidental: bool = False
    generic_value: bool = False
    read_before_write: bool = False
    reuse_legitimate: bool = False
    alias_handling: bool = False


@dataclass
class JourneyLabel:
    """Ground truth label for a journey's expected structure."""

    id: str
    name: str
    description: str
    expected_observations: list[str]
    expected_components: int = 1
    expected_order: bool = True
    expected_steps: list[str] | None = None
    status: str = "fully_labeled"
    difficulty: str = "obvious"
    category: str = ""


@dataclass
class PrerequisiteLabel:
    """Ground truth label for prerequisites and false adjacencies."""

    id: str
    journey: str
    dependent_action: str
    prerequisite_action: str
    field: str = ""
    status: str = "expected"  # expected, forbidden
    confidence: str = "HIGH_EVIDENCE"
    reason: str = ""


class RealisticCorpusLoader:
    """Load and validate the realistic workflow corpus."""

    def __init__(self, corpus_root: Path) -> None:
        """Initialize loader with corpus root directory.

        Args:
            corpus_root: Path to the workflow_realistic/ directory
        """
        self.corpus_root = corpus_root
        self.journeys_root = corpus_root / "journeys"
        self.labels_root = corpus_root / "labels"
        self._validate_structure()

    def _validate_structure(self) -> None:
        """Ensure required directories and files exist."""
        if not self.journeys_root.is_dir():
            raise FileNotFoundError(f"Missing journeys directory: {self.journeys_root}")
        if not self.labels_root.is_dir():
            raise FileNotFoundError(f"Missing labels directory: {self.labels_root}")
        if not (self.labels_root / "causal-edges.yaml").exists():
            raise FileNotFoundError("Missing causal-edges.yaml")
        if not (self.labels_root / "journeys.yaml").exists():
            raise FileNotFoundError("Missing journeys.yaml")
        if not (self.labels_root / "prerequisites.yaml").exists():
            raise FileNotFoundError("Missing prerequisites.yaml")

    def load_causal_edges(self) -> list[CausalEdgeLabel]:
        """Load all causal edge labels from causal-edges.yaml."""
        edges_file = self.labels_root / "causal-edges.yaml"
        with open(edges_file) as f:
            data = yaml.safe_load(f)

        edges: list[CausalEdgeLabel] = []
        for edge_dict in data.get("edges", []):
            edges.append(self._parse_edge_label(edge_dict))
        return edges

    def load_journey_labels(self) -> list[JourneyLabel]:
        """Load all journey labels from journeys.yaml."""
        journeys_file = self.labels_root / "journeys.yaml"
        with open(journeys_file) as f:
            data = yaml.safe_load(f)

        journeys: list[JourneyLabel] = []
        for journey_dict in data.get("journeys", []):
            journeys.append(self._parse_journey_label(journey_dict))
        return journeys

    def load_prerequisites(self) -> list[PrerequisiteLabel]:
        """Load all prerequisite labels from prerequisites.yaml."""
        prereqs_file = self.labels_root / "prerequisites.yaml"
        with open(prereqs_file) as f:
            data = yaml.safe_load(f)

        prerequisites: list[PrerequisiteLabel] = []
        for prereq_dict in data.get("prerequisites", []):
            prerequisites.append(self._parse_prerequisite_label(prereq_dict))
        return prerequisites

    def load_journey_fixtures(self, journey_id: str) -> dict[str, Any]:
        """Load raw fixture data for a journey.

        Args:
            journey_id: Journey identifier (directory name)

        Returns:
            Parsed journey fixture data (JSON/YAML)
        """
        journey_dir = self.journeys_root / journey_id
        journey_file = journey_dir / "journeys.json"

        if not journey_file.exists():
            raise FileNotFoundError(f"Missing fixture for journey: {journey_id}")

        import json

        with open(journey_file) as f:
            data: dict[str, Any] = json.load(f)
            return data

    def _parse_edge_label(self, edge_dict: dict[str, Any]) -> CausalEdgeLabel:
        """Parse a single edge label from dictionary."""
        expected_basis = None
        if edge_dict.get("expected_basis"):
            expected_basis = CausalBasis(edge_dict["expected_basis"])

        return CausalEdgeLabel(
            id=edge_dict.get("id", ""),
            journey=edge_dict.get("journey", ""),
            producer=edge_dict.get("producer", ""),
            consumer=edge_dict.get("consumer", ""),
            field_name=edge_dict.get("field_name", ""),
            resource_type=edge_dict.get("resource_type"),
            value=edge_dict.get("value"),
            relationship=RelationshipType(edge_dict.get("relationship", "CAUSAL_HARD")),
            expected_basis=expected_basis,
            status=edge_dict.get("status", "expected"),
            reason=edge_dict.get("reason", ""),
            distinctive=edge_dict.get("distinctive", False),
            cross_host=edge_dict.get("cross_host", False),
            cross_capture=edge_dict.get("cross_capture", False),
            cross_actor=edge_dict.get("cross_actor", False),
            same_actor=edge_dict.get("same_actor", True),
            state_transition=edge_dict.get("state_transition", False),
            output_only=edge_dict.get("output_only", False),
            request_echo=edge_dict.get("request_echo", False),
            coincidental=edge_dict.get("coincidental", False),
            generic_value=edge_dict.get("generic_value", False),
            read_before_write=edge_dict.get("read_before_write", False),
            reuse_legitimate=edge_dict.get("reuse_legitimate", False),
            alias_handling=edge_dict.get("alias_handling", False),
        )

    def _parse_journey_label(self, journey_dict: dict[str, Any]) -> JourneyLabel:
        """Parse a single journey label from dictionary."""
        return JourneyLabel(
            id=journey_dict.get("id", ""),
            name=journey_dict.get("name", ""),
            description=journey_dict.get("description", ""),
            expected_observations=journey_dict.get("expected_observations", []),
            expected_components=journey_dict.get("expected_components", 1),
            expected_order=journey_dict.get("expected_order", True),
            expected_steps=journey_dict.get("expected_steps"),
            status=journey_dict.get("status", "fully_labeled"),
            difficulty=journey_dict.get("difficulty", "obvious"),
            category=journey_dict.get("category", ""),
        )

    def _parse_prerequisite_label(self, prereq_dict: dict[str, Any]) -> PrerequisiteLabel:
        """Parse a single prerequisite label from dictionary."""
        return PrerequisiteLabel(
            id=prereq_dict.get("id", ""),
            journey=prereq_dict.get("journey", ""),
            dependent_action=prereq_dict.get("dependent_action", ""),
            prerequisite_action=prereq_dict.get("prerequisite_action", ""),
            field=prereq_dict.get("field", ""),
            status=prereq_dict.get("status", "expected"),
            confidence=prereq_dict.get("confidence", "HIGH_EVIDENCE"),
            reason=prereq_dict.get("reason", ""),
        )

    def get_expected_edges(self) -> list[tuple[str, str]]:
        """Get all edges labeled as 'expected'.

        Returns:
            List of (producer, consumer) tuples
        """
        edges = self.load_causal_edges()
        return [
            (e.producer, e.consumer)
            for e in edges
            if e.status == "expected" and e.relationship == RelationshipType.CAUSAL_HARD
        ]

    def get_forbidden_edges(self) -> list[tuple[str, str]]:
        """Get all edges labeled as 'forbidden'.

        Returns:
            List of (producer, consumer) tuples
        """
        edges = self.load_causal_edges()
        return [
            (e.producer, e.consumer)
            for e in edges
            if e.status == "forbidden" and e.relationship == RelationshipType.CAUSAL_HARD
        ]

    def get_journey_observations(self, journey_id: str) -> set[str]:
        """Get all expected observations for a journey.

        Args:
            journey_id: Journey identifier

        Returns:
            Set of observation labels
        """
        journeys = self.load_journey_labels()
        for j in journeys:
            if j.id == journey_id:
                return set(j.expected_observations)
        return set()

    def get_expected_journey_components(self, journey_id: str) -> int:
        """Get expected component count for a journey.

        Args:
            journey_id: Journey identifier

        Returns:
            Expected number of workflow components
        """
        journeys = self.load_journey_labels()
        for j in journeys:
            if j.id == journey_id:
                return j.expected_components
        return 1

    def get_journey_categories(self) -> dict[str, list[str]]:
        """Get journeys grouped by category.

        Returns:
            Mapping from category name to list of journey IDs
        """
        journeys = self.load_journey_labels()
        categories: dict[str, list[str]] = {}
        for j in journeys:
            if j.category not in categories:
                categories[j.category] = []
            categories[j.category].append(j.id)
        return categories


def load_realistic_corpus(corpus_root: Path | None = None) -> RealisticCorpusLoader:
    """Load the realistic workflow corpus.

    Args:
        corpus_root: Path to workflow_realistic/ directory.
                     Defaults to tests/fixtures/workflow_realistic

    Returns:
        Loader instance
    """
    if corpus_root is None:
        test_fixtures = Path(__file__).parent.parent.parent / "tests" / "fixtures"
        corpus_root = test_fixtures / "workflow_realistic"

    return RealisticCorpusLoader(corpus_root)
