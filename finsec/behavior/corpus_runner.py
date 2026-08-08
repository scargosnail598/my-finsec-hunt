"""Production-backed execution adapter for sanitized realistic corpus traffic."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import urlencode

from finsec.behavior.analysis import (
    analyze_business_logic,
    load_business_invariants,
    load_logic_hypotheses,
)
from finsec.behavior.domain import (
    ActionRecord,
    ActionStore,
    BehaviorModel,
    BusinessInvariant,
    LogicHypothesis,
    PropagationLink,
    ResourceInstance,
    ResourceInstanceStore,
    StateRecord,
    StateStore,
    TransitionRecord,
    WorkflowFamily,
    WorkflowInstance,
    WorkflowPrerequisite,
)
from finsec.behavior.realistic_corpus import CorpusJourney, CorpusTrafficEntry
from finsec.behavior.reconstruction import (
    load_propagation,
    load_transitions,
    load_workflow_families,
    load_workflow_instances,
)
from finsec.config.workspace import WorkspacePaths, create_workspace
from finsec.hypotheses.generator import generate_hypotheses
from finsec.ingest.har import ingest_har
from finsec.modeling.generator import generate_model
from finsec.modeling.invariants import generate_invariants
from finsec.modeling.models import Observation, ObservationStore
from finsec.normalization.inventory import build_inventory
from finsec.utils.yaml_store import load_yaml, write_yaml


class CorpusRunResult(BehaviorModel):
    """Structured production output for one traffic-only corpus journey."""

    journey_id: str
    label_observation_ids: dict[str, str]
    observations: list[Observation]
    actions: list[ActionRecord]
    resources: list[ResourceInstance]
    propagation_links: list[PropagationLink]
    workflow_instances: list[WorkflowInstance]
    workflow_families: list[WorkflowFamily]
    prerequisites: list[WorkflowPrerequisite]
    states: list[StateRecord]
    state_transitions: list[TransitionRecord]
    invariants: list[BusinessInvariant]
    hypotheses: list[LogicHypothesis]


def _har_entry(entry: CorpusTrafficEntry) -> dict[str, object]:
    timestamp = datetime(2026, 8, 5, 10, tzinfo=UTC) + timedelta(seconds=entry.offset_seconds)
    query_items = [(name, value) for name, values in entry.query.items() for value in values]
    url = f"https://{entry.host}{entry.path}"
    if query_items:
        url = f"{url}?{urlencode(query_items)}"
    request_headers = [
        {"name": name, "value": value} for name, value in sorted(entry.request_headers.items())
    ]
    request: dict[str, object] = {
        "method": entry.method,
        "url": url,
        "headers": request_headers,
        "queryString": [{"name": name, "value": value} for name, value in query_items],
    }
    if entry.request is not None:
        if not any(item["name"].lower() == "content-type" for item in request_headers):
            request_headers.append({"name": "Content-Type", "value": "application/json"})
        request["postData"] = {
            "mimeType": "application/json",
            "text": json.dumps(entry.request, sort_keys=True),
        }
    response_headers = [
        {"name": name, "value": value} for name, value in sorted(entry.response_headers.items())
    ]
    if not any(item["name"].lower() == "content-type" for item in response_headers):
        response_headers.append({"name": "Content-Type", "value": "application/json"})
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


def _configure_workspace(workspace: WorkspacePaths, journey: CorpusJourney) -> None:
    target = load_yaml(workspace.target)
    target["scope"]["hosts"] = journey.first_party_hosts
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
        for actor in sorted({capture.actor for capture in journey.captures})
    ]
    target["testing"]["synthetic"] = True
    target["testing"]["local_lab"] = True
    target["testing"]["maximum_requests_per_plan"] = 6
    write_yaml(workspace.target, target)


def _apply_logical_sessions(
    workspace: WorkspacePaths,
    capture_sessions: dict[str, tuple[str, str]],
) -> list[Observation]:
    store = ObservationStore.model_validate(load_yaml(workspace.observations))
    observations: list[Observation] = []
    for observation in store.observations:
        capture_name = Path(observation.source_reference.split("#", 1)[0]).name
        actor, session = capture_sessions[capture_name]
        observations.append(
            observation.model_copy(update={"session_identity": f"{actor}:{session}"})
        )
    write_yaml(
        workspace.observations,
        ObservationStore(observations=observations).model_dump(mode="json", exclude_none=True),
    )
    return observations


def run_realistic_corpus_journey(
    journey: CorpusJourney,
    output_root: Path,
) -> CorpusRunResult:
    """Run sanitized traffic through real ingestion, modeling, and reasoning functions."""

    workspace = create_workspace(journey.id, output_root / "workspaces")
    _configure_workspace(workspace, journey)
    captures_root = output_root / "captures" / journey.id
    captures_root.mkdir(parents=True, exist_ok=True)
    label_references: dict[str, tuple[str, int]] = {}
    capture_sessions: dict[str, tuple[str, str]] = {}
    for capture in journey.captures:
        document = {
            "log": {
                "version": "1.2",
                "creator": {"name": "finsec-realistic-corpus"},
                "entries": [_har_entry(entry) for entry in capture.entries],
            }
        }
        capture_path = captures_root / f"{capture.name}.har"
        capture_path.write_text(
            json.dumps(document, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        ingest = ingest_har(capture_path, workspace, actor=capture.actor, channel="WEB")
        capture_sessions[ingest.redacted_har.name] = (capture.actor, capture.session)
        for index, entry in enumerate(capture.entries):
            label_references[entry.label] = (ingest.redacted_har.name, index)

    observations = _apply_logical_sessions(workspace, capture_sessions)
    build_inventory(workspace)
    generate_model(workspace)
    generate_invariants(workspace)
    generate_hypotheses(workspace)
    analyze_business_logic(workspace)

    observation_ids: dict[str, str] = {}
    for label, (capture_name, index) in sorted(label_references.items()):
        suffix = f"{capture_name}#entry-{index}"
        observation_ids[label] = next(
            item.id for item in observations if item.source_reference.endswith(suffix)
        )

    actions = ActionStore.model_validate(load_yaml(workspace.behavior_actions)).actions
    resources = ResourceInstanceStore.model_validate(
        load_yaml(workspace.behavior_resources)
    ).resource_instances
    propagation = load_propagation(workspace).propagation_links
    instances = load_workflow_instances(workspace).workflow_instances
    families = load_workflow_families(workspace).workflow_families
    states = StateStore.model_validate(load_yaml(workspace.behavior_states)).states
    transitions = load_transitions(workspace).transitions
    invariants = load_business_invariants(workspace).business_invariants
    hypotheses = load_logic_hypotheses(workspace).hypotheses
    return CorpusRunResult(
        journey_id=journey.id,
        label_observation_ids=observation_ids,
        observations=observations,
        actions=actions,
        resources=resources,
        propagation_links=propagation,
        workflow_instances=instances,
        workflow_families=families,
        prerequisites=[
            prerequisite for family in families for prerequisite in family.causal_prerequisites
        ],
        states=states,
        state_transitions=transitions,
        invariants=invariants,
        hypotheses=hypotheses,
    )
