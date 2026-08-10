"""Session-capture context and intent-aware reconstruction regressions."""

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from typer.testing import CliRunner

from finsec.behavior.domain import RelationshipType
from finsec.behavior.reconstruction import (
    build_behavior_model,
    load_propagation,
    load_workflow_families,
    load_workflow_instances,
)
from finsec.captures.domain import (
    CaptureAssignment,
    CaptureConfidence,
    CaptureIntent,
    CaptureMode,
    CaptureQualityLabel,
    CaptureRelevance,
    MetadataSource,
)
from finsec.captures.service import find_capture, list_captures, load_capture_store
from finsec.cli import app
from finsec.config.workspace import WorkspacePaths, create_workspace
from finsec.ingest.har import ingest_har
from finsec.modeling.models import EndpointStore, ObservationStore
from finsec.normalization.inventory import build_inventory
from finsec.utils.yaml_store import load_yaml, write_yaml
from finsec.workflow import run_offline_workflow

RUNNER = CliRunner()
CORPUS_ROOT = Path(__file__).parent / "fixtures" / "session_capture"


def _workspace(tmp_path: Path, name: str = "capture-demo") -> WorkspacePaths:
    workspace = create_workspace(name, tmp_path / "workspaces")
    target = load_yaml(workspace.target)
    target["scope"]["hosts"] = ["api.example.test"]
    target["accounts"] = [
        {"id": "ACCOUNT_A", "ownership": "researcher"},
        {"id": "ACCOUNT_B", "ownership": "researcher"},
    ]
    target["testing"].update({"production": False, "synthetic": True, "local_lab": True})
    write_yaml(workspace.target, target)
    return workspace


def _entry(
    index: int,
    method: str,
    path: str,
    *,
    status: int = 200,
    request: dict[str, Any] | None = None,
    response: dict[str, Any] | list[Any] | None = None,
    host: str = "api.example.test",
) -> dict[str, Any]:
    started = datetime(2026, 1, 2, 10, 0, tzinfo=UTC) + timedelta(seconds=index)
    request_document: dict[str, Any] = {
        "method": method,
        "url": f"https://{host}{path}",
        "headers": [{"name": "Authorization", "value": "Bearer SYNTHETIC_TOKEN"}],
    }
    if request is not None:
        request_document["headers"].append({"name": "Content-Type", "value": "application/json"})
        request_document["postData"] = {
            "mimeType": "application/json",
            "text": json.dumps(request),
        }
    response_document = response if response is not None else {"ok": True}
    return {
        "startedDateTime": started.isoformat().replace("+00:00", "Z"),
        "request": request_document,
        "response": {
            "status": status,
            "headers": [{"name": "Content-Type", "value": "application/json"}],
            "content": {
                "mimeType": "application/json",
                "text": json.dumps(response_document),
            },
        },
    }


def _har(path: Path, entries: list[dict[str, Any]]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "log": {
                    "version": "1.2",
                    "creator": {"name": "session-capture-tests", "version": "1"},
                    "entries": entries,
                }
            }
        ),
        encoding="utf-8",
    )
    return path


def _assignment(
    mode: CaptureMode,
    intent: CaptureIntent | None = None,
) -> CaptureAssignment:
    return CaptureAssignment(
        actor_source=MetadataSource.USER_SUPPLIED,
        actor_confidence=CaptureConfidence.HIGH,
        capture_mode=mode,
        capture_mode_source=MetadataSource.USER_SUPPLIED,
        intent=intent,
    )


def _intent(action: str, resource: str, source: MetadataSource) -> CaptureIntent:
    return CaptureIntent(
        label=f"{action}_{resource}",
        action=action,
        resource_type=resource,
        confidence=CaptureConfidence.HIGH,
        source=source,
    )


def _corpus_captures(scenario: str) -> list[dict[str, Any]]:
    document = load_yaml(CORPUS_ROOT / "corpus.yaml")
    return [item for item in document["captures"] if item["scenario"] == scenario]


def _ingest_corpus(workspace: WorkspacePaths, scenario: str) -> dict[str, Any]:
    results: dict[str, Any] = {}
    for item in _corpus_captures(scenario):
        intent = item["intent"]
        result = ingest_har(
            CORPUS_ROOT / item["file"],
            workspace,
            actor=item["actor"],
            capture_assignment=_assignment(
                CaptureMode(item["mode"]),
                _intent(intent["action"], intent["resource"], MetadataSource.USER_SUPPLIED),
            ),
        )
        assert result.capture is not None
        results[item["file"]] = result
    return results


def test_har_creates_stable_capture_links_and_explainable_intent(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path)
    source = _har(
        tmp_path / "account-a-create-dns.har",
        [
            _entry(1, "GET", "/api/domains/101", response={"id": 101}),
            _entry(2, "GET", "/api/domains/101/dns-records", response=[]),
            _entry(
                3,
                "POST",
                "/api/domains/101/dns-records",
                status=201,
                request={"type": "A", "value": "192.0.2.10"},
                response={"id": 501, "type": "A"},
            ),
            _entry(
                4,
                "GET",
                "/api/domains/101/dns-records/501",
                response={"id": 501, "type": "A"},
            ),
        ],
    )

    first = ingest_har(
        source,
        workspace,
        actor="ACCOUNT_A",
        channel="WEB",
        capture_assignment=_assignment(CaptureMode.NORMAL_BEHAVIOR),
    )
    second = ingest_har(
        source,
        workspace,
        actor="ACCOUNT_A",
        channel="WEB",
        capture_assignment=_assignment(CaptureMode.NORMAL_BEHAVIOR),
    )

    assert first.capture is not None and second.capture is not None
    assert first.capture.capture_id == second.capture.capture_id
    assert first.capture.intent.action == "CREATE"
    assert first.capture.intent.resource_type == "dns_record"
    assert first.capture.intent.source == MetadataSource.ENGINE_INFERRED_RAW
    assert first.capture.intent_inference.evidence
    observations = ObservationStore.model_validate(load_yaml(workspace.observations)).observations
    assert {item.capture_id for item in observations} == {first.capture.capture_id}
    assert {item.capture_mode for item in observations} == {CaptureMode.NORMAL_BEHAVIOR}
    assert CaptureRelevance.PRIMARY in {item.capture_relevance for item in observations}
    assert load_capture_store(workspace).captures == [second.capture]

    listed = RUNNER.invoke(app, ["captures", "-w", str(workspace.root)])
    explained = RUNNER.invoke(
        app,
        ["captures", "-w", str(workspace.root), "--explain", first.capture.capture_id],
    )
    assert listed.exit_code == explained.exit_code == 0
    assert first.capture.capture_id in listed.output
    assert "Actor evidence" in explained.output
    assert "Observed intent evidence" in explained.output
    assert "CREATE dns_record" in explained.output


def test_user_confirmed_intent_persists_with_provenance(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path)
    source = _har(
        tmp_path / "confirmed.har",
        [_entry(1, "POST", "/api/orders", status=201, response={"id": 101})],
    )
    confirmed = _intent("CREATE", "order", MetadataSource.USER_CONFIRMED)

    result = ingest_har(
        source,
        workspace,
        actor="ACCOUNT_A",
        capture_assignment=CaptureAssignment(
            actor_source=MetadataSource.USER_CONFIRMED,
            actor_confidence=CaptureConfidence.HIGH,
            capture_mode=CaptureMode.NORMAL_BEHAVIOR,
            capture_mode_source=MetadataSource.USER_CONFIRMED,
            intent=confirmed,
        ),
    )

    assert result.capture is not None
    persisted = find_capture(workspace, result.capture.capture_id)
    assert persisted is not None
    assert persisted.intent == confirmed
    assert persisted.capture_mode_source == MetadataSource.USER_CONFIRMED
    assert persisted.actor_source == MetadataSource.USER_CONFIRMED
    assert persisted.actor_evidence

    refreshed = ingest_har(
        source,
        workspace,
        actor="ACCOUNT_A",
        capture_assignment=CaptureAssignment(
            actor_source=MetadataSource.USER_SUPPLIED,
            capture_mode=CaptureMode.NORMAL_BEHAVIOR,
            capture_mode_source=MetadataSource.USER_SUPPLIED,
            intent=confirmed,
        ),
    )
    assert refreshed.capture is not None
    assert refreshed.capture.actor_confidence == CaptureConfidence.HIGH


def test_unannotated_import_uses_workspace_capture_policy_default(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path)
    result = ingest_har(
        _har(
            tmp_path / "unannotated.har",
            [_entry(1, "GET", "/api/orders/101", response={"id": 101})],
        ),
        workspace,
        actor="ACCOUNT_A",
    )

    assert result.capture is not None
    assert result.capture.capture_mode == CaptureMode.NORMAL_BEHAVIOR
    assert result.capture.capture_mode_source == MetadataSource.ENGINE_INFERRED
    assert set(result.capture.observation_relevance.values()) == {CaptureRelevance.UNKNOWN}


def test_capture_policy_can_disable_automatic_intent_selection(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path)
    target = load_yaml(workspace.target)
    target["capture_policy"]["infer_intent"] = False
    write_yaml(workspace.target, target)

    result = ingest_har(
        _har(
            tmp_path / "policy-no-intent.har",
            [_entry(1, "POST", "/api/orders", status=201, response={"id": 101})],
        ),
        workspace,
        actor="ACCOUNT_A",
    )

    assert result.capture is not None
    assert result.capture.intent.action == "UNKNOWN"
    assert result.capture.intent_inference.proposed_action == "CREATE"


def test_broad_capture_warns_without_blocking_ingestion(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path)
    entries = [
        _entry(1, "POST", "/api/orders", status=201, response={"id": 101}),
        _entry(2, "PATCH", "/api/billing/202", request={"name": "x"}),
        _entry(3, "DELETE", "/api/firewalls/303"),
        _entry(4, "POST", "/api/iam/roles", status=201, response={"id": 404}),
        _entry(5, "GET", "/api/profiles/505"),
        _entry(6, "GET", "/api/notifications"),
    ]

    result = ingest_har(
        _har(tmp_path / "broad.har", entries),
        workspace,
        actor="ACCOUNT_A",
        capture_assignment=_assignment(CaptureMode.NORMAL_BEHAVIOR),
    )

    assert result.capture is not None
    assert CaptureQualityLabel.BROAD in result.capture.quality.labels
    assert CaptureQualityLabel.MULTI_INTENT in result.capture.quality.labels
    assert result.imported == len(entries)
    assert result.capture.quality.recommendation is not None


def test_probe_does_not_pollute_ownership_or_normal_workflows(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path)
    normal_a = ingest_har(
        _har(
            tmp_path / "account-a-order.har",
            [_entry(1, "GET", "/api/orders/101", response={"id": 101, "ownerId": "A"})],
        ),
        workspace,
        actor="ACCOUNT_A",
        capture_assignment=_assignment(
            CaptureMode.NORMAL_BEHAVIOR, _intent("READ", "order", MetadataSource.USER_SUPPLIED)
        ),
    )
    normal_b = ingest_har(
        _har(
            tmp_path / "account-b-order.har",
            [_entry(2, "GET", "/api/orders/202", response={"id": 202, "ownerId": "B"})],
        ),
        workspace,
        actor="ACCOUNT_B",
        capture_assignment=_assignment(
            CaptureMode.NORMAL_BEHAVIOR, _intent("READ", "order", MetadataSource.USER_SUPPLIED)
        ),
    )
    probe = ingest_har(
        _har(
            tmp_path / "account-b-probe-a-order.har",
            [_entry(3, "GET", "/api/orders/101", response={"id": 101, "ownerId": "A"})],
        ),
        workspace,
        actor="ACCOUNT_B",
        capture_assignment=_assignment(
            CaptureMode.RESEARCHER_PROBE, _intent("READ", "order", MetadataSource.USER_SUPPLIED)
        ),
    )
    assert normal_a.capture and normal_b.capture and probe.capture

    build_inventory(workspace)
    endpoints = EndpointStore.model_validate(load_yaml(workspace.endpoints)).endpoints
    endpoint = next(item for item in endpoints if item.path == "/api/orders/{orderId}")
    binding = next(item for item in endpoint.object_access if item.identifier == "orderId")
    baseline_ids = {
        observation_id for baseline in binding.baselines for observation_id in baseline.observations
    }
    assert binding.actor_object_binding_observed is True
    assert binding.distinct_actors == 2
    assert not baseline_ids.intersection(probe.capture.observation_ids)

    build_behavior_model(workspace)
    workflow_observations = {
        step.observation_id
        for instance in load_workflow_instances(workspace).workflow_instances
        for step in instance.steps
    }
    assert set(normal_a.capture.observation_ids + normal_b.capture.observation_ids).issubset(
        workflow_observations
    )
    assert not workflow_observations.intersection(probe.capture.observation_ids)


def test_explicit_unknown_capture_cannot_establish_normal_baselines(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path)
    result = ingest_har(
        _har(
            tmp_path / "unknown-order.har",
            [_entry(1, "GET", "/api/orders/101", response={"id": 101, "ownerId": "A"})],
        ),
        workspace,
        actor="ACCOUNT_A",
        capture_assignment=_assignment(
            CaptureMode.UNKNOWN,
            _intent("READ", "order", MetadataSource.USER_SUPPLIED),
        ),
    )
    assert result.capture is not None

    build_inventory(workspace)
    endpoints = EndpointStore.model_validate(load_yaml(workspace.endpoints)).endpoints
    endpoint = next(item for item in endpoints if item.path == "/api/orders/{orderId}")
    assert endpoint.object_access == []
    assert endpoint.baseline_observed_by == []

    build_behavior_model(workspace)
    workflow_observations = {
        step.observation_id
        for instance in load_workflow_instances(workspace).workflow_instances
        for step in instance.steps
    }
    assert not workflow_observations.intersection(result.capture.observation_ids)


def test_cross_capture_values_cannot_create_hard_causality(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path)
    first = ingest_har(
        _har(
            tmp_path / "challenge-create.har",
            [
                _entry(
                    1,
                    "POST",
                    "/api/challenges",
                    status=201,
                    response={"challengeId": "CHALLENGE-000001"},
                )
            ],
        ),
        workspace,
        actor="ACCOUNT_A",
        capture_assignment=_assignment(CaptureMode.NORMAL_BEHAVIOR),
    )
    second = ingest_har(
        _har(
            tmp_path / "challenge-consume.har",
            [
                _entry(
                    2,
                    "POST",
                    "/api/challenges/consume",
                    request={"challengeId": "CHALLENGE-000001"},
                    response={"accepted": True},
                )
            ],
        ),
        workspace,
        actor="ACCOUNT_A",
        capture_assignment=_assignment(CaptureMode.NORMAL_BEHAVIOR),
    )
    assert first.capture and second.capture

    build_inventory(workspace)
    build_behavior_model(workspace)
    cross_capture = [
        item
        for item in load_propagation(workspace).propagation_links
        if item.source_capture == first.capture.capture_id
        and item.destination_capture == second.capture.capture_id
    ]
    assert cross_capture
    assert all(item.relationship_type != RelationshipType.CAUSAL_HARD for item in cross_capture)
    assert all("capture_incompatible" in item.rejection_reasons for item in cross_capture)


def test_two_actor_parallel_normal_journeys_stay_separate_but_share_structure(
    tmp_path: Path,
) -> None:
    workspace = _workspace(tmp_path)
    for actor, order_id in (("ACCOUNT_A", 101), ("ACCOUNT_B", 202)):
        ingest_har(
            _har(
                tmp_path / f"{actor.lower()}-create-order.har",
                [
                    _entry(
                        order_id,
                        "POST",
                        "/api/orders",
                        status=201,
                        request={"quantity": 1},
                        response={"id": order_id, "status": "created"},
                    ),
                    _entry(
                        order_id + 1,
                        "GET",
                        f"/api/orders/{order_id}",
                        response={"id": order_id, "status": "created"},
                    ),
                ],
            ),
            workspace,
            actor=actor,
            capture_assignment=_assignment(CaptureMode.NORMAL_BEHAVIOR),
        )

    build_inventory(workspace)
    build_behavior_model(workspace)
    instances = load_workflow_instances(workspace).workflow_instances
    multi_step = [item for item in instances if len(item.steps) == 2]
    assert len(multi_step) == 2
    assert all(len(item.actors) == 1 for item in multi_step)
    assert {item.actors[0] for item in multi_step} == {"ACCOUNT_A", "ACCOUNT_B"}
    family = next(
        item
        for item in load_workflow_families(workspace).workflow_families
        if len(item.workflow_instance_ids) == 2
    )
    assert family.actors == ["ACCOUNT_A", "ACCOUNT_B"]


def test_arvan_style_dns_capture_marks_primary_context_and_noise(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path)
    entries = [
        _entry(1, "GET", "/api/domains/101", response={"id": 101}),
        _entry(2, "GET", "/api/domains/101/dns-records", response=[]),
        _entry(
            3,
            "POST",
            "/api/domains/101/dns-records",
            status=201,
            request={"type": "A", "value": "192.0.2.10"},
            response={"id": 501},
        ),
        _entry(4, "GET", "/api/domains/101/dns-records/501", response={"id": 501}),
        _entry(5, "GET", "/api/profile"),
        _entry(6, "GET", "/api/notifications"),
        _entry(7, "GET", "/api/billing/summary"),
        _entry(8, "POST", "/events", host="telemetry.example.test"),
    ]
    result = ingest_har(
        _har(tmp_path / "account-a-create-dns-with-context.har", entries),
        workspace,
        actor="ACCOUNT_A",
        capture_assignment=_assignment(CaptureMode.NORMAL_BEHAVIOR),
    )
    assert result.capture is not None

    build_inventory(workspace)
    refreshed = find_capture(workspace, result.capture.capture_id)
    assert refreshed is not None
    assert refreshed.intent.action == "CREATE"
    assert refreshed.intent.resource_type == "dns_record"
    assert refreshed.counts.primary == 1
    assert refreshed.counts.supporting >= 3
    assert refreshed.counts.context >= 3
    assert refreshed.counts.noise >= 1

    observations = ObservationStore.model_validate(load_yaml(workspace.observations)).observations
    by_path = {item.path: item for item in observations}
    assert by_path["/api/profile"].capture_relevance == CaptureRelevance.CONTEXT
    assert by_path["/events"].capture_relevance == CaptureRelevance.NOISE

    build_behavior_model(workspace)
    workflow_ids = {
        step.observation_id
        for instance in load_workflow_instances(workspace).workflow_instances
        for step in instance.steps
    }
    assert by_path["/api/domains/101"].id in workflow_ids
    assert by_path["/api/profile"].id not in workflow_ids
    assert by_path["/api/notifications"].id not in workflow_ids
    assert by_path["/events"].id not in workflow_ids


def test_legacy_workspace_without_capture_store_remains_loadable(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path)
    source = _har(
        tmp_path / "legacy.har",
        [
            _entry(
                1,
                "GET",
                "/api/payments/101",
                response={"id": 101, "status": "paid"},
            )
        ],
    )
    ingest_har(source, workspace, actor="ACCOUNT_A")
    document = load_yaml(workspace.observations)
    for observation in document["observations"]:
        observation.pop("capture_id", None)
        observation.pop("capture_mode", None)
        observation.pop("capture_relevance", None)
        observation["session_identity"] = None
    write_yaml(workspace.observations, document)
    workspace.captures.unlink()

    result = run_offline_workflow(workspace)
    legacy = list_captures(workspace)

    assert result.observations == 1
    assert legacy and legacy[0].legacy is True
    assert legacy[0].capture_mode == CaptureMode.UNKNOWN
    assert load_workflow_instances(workspace).workflow_instances


def test_order_acceptance_corpus_keeps_probe_out_of_normal_models(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path)
    results = _ingest_corpus(workspace, "order")
    probe = results["order-b-probe-a.har"].capture
    assert probe is not None

    build_inventory(workspace)
    endpoints = EndpointStore.model_validate(load_yaml(workspace.endpoints)).endpoints
    endpoint = next(item for item in endpoints if item.path == "/api/orders/{orderId}")
    binding = next(item for item in endpoint.object_access if item.identifier == "orderId")
    baseline_ids = {
        observation_id for baseline in binding.baselines for observation_id in baseline.observations
    }
    assert binding.actor_object_binding_observed is True
    assert binding.distinct_actors == 2
    assert binding.distinct_objects == 2
    assert not baseline_ids.intersection(probe.observation_ids)

    build_behavior_model(workspace)
    instances = load_workflow_instances(workspace).workflow_instances
    workflow_ids = {step.observation_id for item in instances for step in item.steps}
    assert not workflow_ids.intersection(probe.observation_ids)
    normal_ids = {
        observation_id
        for name, result in results.items()
        if name != "order-b-probe-a.har"
        for observation_id in result.capture.observation_ids
    }
    assert normal_ids.issubset(workflow_ids)
    parallel = [
        item
        for item in load_workflow_families(workspace).workflow_families
        if item.actors == ["ACCOUNT_A", "ACCOUNT_B"]
    ]
    assert len(parallel) >= 2


def test_arvan_acceptance_corpus_prioritizes_independent_dns_journeys(
    tmp_path: Path,
) -> None:
    workspace = _workspace(tmp_path)
    results = _ingest_corpus(workspace, "arvan_dns")

    for result in results.values():
        capture = result.capture
        assert capture.intent.action == "CREATE"
        assert capture.intent.resource_type == "dns_record"
        assert capture.counts.primary == 1
        assert capture.counts.supporting >= 3
        assert capture.counts.context >= 3
        assert capture.counts.noise >= 1
        assert CaptureQualityLabel.MULTI_INTENT not in capture.quality.labels

    build_inventory(workspace)
    build_behavior_model(workspace)
    observations = ObservationStore.model_validate(load_yaml(workspace.observations)).observations
    peripheral_ids = {
        item.id
        for item in observations
        if item.path in {"/api/profile", "/api/notifications", "/api/billing/summary", "/events"}
    }
    instances = load_workflow_instances(workspace).workflow_instances
    workflow_ids = {step.observation_id for item in instances for step in item.steps}
    assert not workflow_ids.intersection(peripheral_ids)
    dns_instances = [
        item for item in instances if any("dns-records" in step.route for step in item.steps)
    ]
    assert {item.actors[0] for item in dns_instances if len(item.actors) == 1} == {
        "ACCOUNT_A",
        "ACCOUNT_B",
    }
    assert all(len(item.actors) == 1 for item in dns_instances)
    assert any(
        item.actors == ["ACCOUNT_A", "ACCOUNT_B"]
        and any("dns" in resource_type.lower() for resource_type in item.resource_types)
        for item in load_workflow_families(workspace).workflow_families
    )
