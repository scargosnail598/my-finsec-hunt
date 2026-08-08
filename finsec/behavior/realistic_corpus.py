"""Realistic workflow corpus loading and validation infrastructure.

This module provides utilities to load the structured realistic workflow corpus,
parse ground truth labels, and compute recall/precision metrics against
reconstruction engine output.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field

from finsec.behavior.domain import CausalBasis, RelationshipType


class CorpusTrafficModel(BaseModel):
    """Reject accidental drift in traffic inputs consumed before labels are loaded."""

    model_config = ConfigDict(extra="forbid")


class CorpusTrafficEntry(CorpusTrafficModel):
    """One sanitized HTTP exchange supplied to the production ingestion path."""

    label: str
    offset_seconds: int = Field(ge=0)
    method: str
    path: str
    host: str
    query: dict[str, list[str]] = Field(default_factory=dict)
    request: dict[str, Any] | None = None
    response: dict[str, Any]
    request_headers: dict[str, str] = Field(default_factory=dict)
    response_headers: dict[str, str] = Field(default_factory=dict)
    status: int = Field(default=200, ge=100, le=599)


class CorpusCapture(CorpusTrafficModel):
    """One capture with explicit actor and logical-session context."""

    name: str
    actor: str
    session: str
    entries: list[CorpusTrafficEntry]


class CorpusJourney(CorpusTrafficModel):
    """Traffic-only realistic journey; ground-truth labels are deliberately absent."""

    id: str
    name: str
    captures: list[CorpusCapture]
    first_party_hosts: list[str]


@dataclass(frozen=True)
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
    same_value_different_semantics: bool = False
    value_from: str | None = None
    value_to: str | None = None


@dataclass(frozen=True)
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
    expected_component_groups: list[list[str]] = field(default_factory=list)


@dataclass(frozen=True)
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


@dataclass(frozen=True)
class StateTransitionLabel:
    """Ground truth for one resource-scoped lifecycle transition."""

    id: str
    journey: str
    producer: str
    consumer: str
    resource_type: str
    field: str
    from_state: str
    to_state: str
    status: str = "expected"
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
        if not (self.labels_root / "state-transitions.yaml").exists():
            raise FileNotFoundError("Missing state-transitions.yaml")

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

    def load_state_transitions(self) -> list[StateTransitionLabel]:
        """Load lifecycle labels independently from causal-edge reconstruction."""

        transitions_file = self.labels_root / "state-transitions.yaml"
        with transitions_file.open(encoding="utf-8") as handle:
            data = yaml.safe_load(handle) or {}
        return [
            StateTransitionLabel(
                id=item.get("id", ""),
                journey=item.get("journey", ""),
                producer=item.get("producer", ""),
                consumer=item.get("consumer", ""),
                resource_type=item.get("resource_type", ""),
                field=item.get("field", ""),
                from_state=item.get("from", ""),
                to_state=item.get("to", ""),
                status=item.get("status", "expected"),
                reason=item.get("reason", ""),
            )
            for item in data.get("state_transitions", [])
        ]

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

        with journey_file.open(encoding="utf-8") as f:
            data: dict[str, Any] = json.load(f)
            return data

    def load_journey(self, journey_id: str) -> CorpusJourney:
        """Load only traffic input; this method never opens the labels directory."""

        data = self.load_journey_fixtures(journey_id)
        raw_captures = data.get("captures")
        if raw_captures is None:
            raw_captures = [
                {
                    "name": data.get("capture", journey_id),
                    "actor": data.get("actor"),
                    "session": data.get("session", f"{journey_id}-session"),
                    "entries": data.get("entries", []),
                }
            ]
        captures = [
            CorpusCapture.model_validate(
                {
                    **capture,
                    "session": capture.get("session", f"{journey_id}-{capture['name']}-session"),
                }
            )
            for capture in raw_captures
        ]
        hosts = sorted(
            set(data.get("first_party_hosts", []))
            | {entry.host for capture in captures for entry in capture.entries}
        )
        return CorpusJourney(
            id=journey_id,
            name=str(data.get("name", journey_id)),
            captures=captures,
            first_party_hosts=hosts,
        )

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
            same_value_different_semantics=edge_dict.get("same_value_different_semantics", False),
            value_from=edge_dict.get("value_from"),
            value_to=edge_dict.get("value_to"),
        )

    def _parse_journey_label(self, journey_dict: dict[str, Any]) -> JourneyLabel:
        """Parse a single journey label from dictionary."""
        independent_workflows = journey_dict.get("independent_workflows", [])
        component_groups = [
            list(item.get("observations", []))
            for item in independent_workflows
            if isinstance(item, dict)
        ]
        expected_observations = journey_dict.get("expected_observations", [])
        return JourneyLabel(
            id=journey_dict.get("id", ""),
            name=journey_dict.get("name", ""),
            description=journey_dict.get("description", ""),
            expected_observations=expected_observations,
            expected_components=journey_dict.get("expected_components", 1),
            expected_order=journey_dict.get("expected_order", True),
            expected_steps=journey_dict.get("expected_steps"),
            status=journey_dict.get("status", "fully_labeled"),
            difficulty=journey_dict.get("difficulty", "obvious"),
            category=journey_dict.get("category", ""),
            expected_component_groups=component_groups or [expected_observations],
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
