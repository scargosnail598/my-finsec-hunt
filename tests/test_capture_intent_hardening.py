"""Journey-anchor hardening regressions for large browser session captures."""

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from typer.testing import CliRunner

from finsec.behavior.domain import RelationshipType
from finsec.behavior.reconstruction import build_behavior_model, load_propagation
from finsec.captures.analysis import (
    CaptureSignal,
    align_intents,
    assess_quality,
    classify_relevance,
    infer_intent,
    inferred_intent,
    resource_family,
)
from finsec.captures.domain import (
    CaptureAssignment,
    CaptureConfidence,
    CaptureIntent,
    CaptureMode,
    CaptureQualityLabel,
    CaptureRelevance,
    IntentAlignment,
    MetadataSource,
)
from finsec.captures.service import find_capture
from finsec.cli import app
from finsec.config.workspace import WorkspacePaths, create_workspace
from finsec.hypotheses.domain import HypothesisStore
from finsec.ingest.har import ingest_har
from finsec.modeling.models import EndpointStore, ObservationStore
from finsec.normalization.inventory import build_inventory
from finsec.normalization.path_semantics import path_resource_semantics
from finsec.utils.yaml_store import load_yaml, write_yaml
from finsec.workflow import run_offline_workflow

RUNNER = CliRunner()


def _workspace(tmp_path: Path) -> WorkspacePaths:
    workspace = create_workspace("intent-hardening", tmp_path / "workspaces")
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
) -> dict[str, Any]:
    started = datetime(2026, 8, 10, 10, 0, tzinfo=UTC) + timedelta(seconds=index)
    request_document: dict[str, Any] = {
        "method": method,
        "url": f"https://api.example.test{path}",
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
    path.write_text(
        json.dumps(
            {
                "log": {
                    "version": "1.2",
                    "creator": {"name": "intent-hardening-tests", "version": "1"},
                    "entries": entries,
                }
            }
        ),
        encoding="utf-8",
    )
    return path


def _declared_intent() -> CaptureIntent:
    return CaptureIntent(
        label="change_credential",
        action="CHANGE",
        resource_type="credential",
        confidence=CaptureConfidence.HIGH,
        source=MetadataSource.USER_CONFIRMED,
    )


def _assignment(mode: CaptureMode = CaptureMode.NORMAL_BEHAVIOR) -> CaptureAssignment:
    return CaptureAssignment(
        actor_source=MetadataSource.USER_CONFIRMED,
        actor_confidence=CaptureConfidence.HIGH,
        capture_mode=mode,
        capture_mode_source=MetadataSource.USER_CONFIRMED,
        intent=_declared_intent(),
    )


def _password_journey(offset: int, actor: str) -> list[dict[str, Any]]:
    entries = [
        _entry(offset + index, "GET", "/v1/users/me", response={"actor": actor})
        for index in range(20)
    ]
    entries.extend(
        [
            _entry(offset + 20, "OPTIONS", "/v1/users/me", status=204),
            _entry(offset + 21, "HEAD", "/v1/users/me", status=200),
            _entry(offset + 22, "GET", "/v1/wallets/me", response={"balance": "0"}),
            _entry(offset + 23, "POST", "/telemetry/heartbeat", status=202),
            _entry(
                offset + 24,
                "POST",
                "/v1/users/me/password",
                status=202,
                request={"currentPassword": "REDACTED", "password": "REDACTED"},
                response={"message": "accepted"},
            ),
            _entry(offset + 25, "OPTIONS", "/v1/users/me/password", status=204),
            _entry(offset + 26, "GET", "/v1/users/me", response={"actor": actor}),
        ]
    )
    return entries


def test_identity_selectors_resolve_to_actor_scoped_resources() -> None:
    user = path_resource_semantics("/v1/users/me")
    wallet = path_resource_semantics("/resid/v1/wallets/self")

    assert resource_family("/v1/users/me") == "user"
    assert resource_family("/resid/v1/wallets/self") == "wallet"
    assert user.subject_selector == wallet.subject_selector == "current_actor"
    assert "me" not in {user.resource, wallet.resource}


def test_nested_selector_retains_parent_and_child_resource_semantics() -> None:
    nested = path_resource_semantics("/v1/users/me/invitations")
    credential = path_resource_semantics("/v1/users/me/password")

    assert nested.resource == "invitation"
    assert nested.parent_resource == "user"
    assert nested.subject_selector == "current_actor"
    assert credential.resource == "user_credential"
    assert credential.parent_resource == "user"
    assert credential.semantic_component == "credential"


def test_protocol_isolation_and_passive_frequency_saturation() -> None:
    signals = [
        CaptureSignal(f"GET-{index}", index, "api.example.test", "GET", "/users/me", 200)
        for index in range(20)
    ]
    signals.extend(
        [
            CaptureSignal("OPTIONS", 20, "api.example.test", "OPTIONS", "/users/me", 204),
            CaptureSignal("HEAD", 21, "api.example.test", "HEAD", "/users/me", 200),
            CaptureSignal("PASSWORD", 22, "api.example.test", "POST", "/users/me/password", 202),
        ]
    )

    analysis = infer_intent(signals)
    intent = inferred_intent(analysis)
    relevance = classify_relevance(signals, intent, analysis)

    assert intent.action == "UPDATE"
    assert intent.resource_type == "user_credential"
    assert analysis.primary_anchor is not None
    assert analysis.primary_anchor.observation_ids == ["PASSWORD"]
    assert relevance["PASSWORD"] == CaptureRelevance.PRIMARY
    assert relevance["OPTIONS"] == CaptureRelevance.PROTOCOL_SUPPORT
    assert relevance["HEAD"] == CaptureRelevance.PROTOCOL_SUPPORT
    assert all(relevance[f"GET-{index}"] != CaptureRelevance.PRIMARY for index in range(20))
    assert analysis.metrics.protocol_requests_excluded == 2
    assert analysis.metrics.passive_operation_groups == 1
    assert analysis.metrics.repeated_passive_observations_saturated == 19


def test_background_post_is_not_a_journey_anchor() -> None:
    signals = [
        CaptureSignal("PROFILE", 1, "api.example.test", "GET", "/users/me", 200),
        CaptureSignal("HEARTBEAT", 2, "api.example.test", "POST", "/telemetry/heartbeat", 202),
    ]

    analysis = infer_intent(signals)
    relevance = classify_relevance(signals, inferred_intent(analysis), analysis)

    assert analysis.primary_anchor is not None
    assert analysis.primary_anchor.observation_ids == ["PROFILE"]
    assert all("HEARTBEAT" not in item.observation_ids for item in analysis.anchors)
    assert relevance["HEARTBEAT"] == CaptureRelevance.NOISE
    assert analysis.metrics.background_requests_excluded == 1


def test_multiple_mutations_preserve_quality_and_competing_anchors() -> None:
    signals = [
        CaptureSignal("SERVER", 1, "api.example.test", "POST", "/servers", 201),
        CaptureSignal("FIREWALL", 2, "api.example.test", "PATCH", "/firewalls/101", 200),
        CaptureSignal("DNS", 3, "api.example.test", "DELETE", "/dns-records/202", 204),
    ]
    analysis = infer_intent(signals)
    relevance = classify_relevance(signals, inferred_intent(analysis), analysis)
    quality = assess_quality(signals, analysis, relevance)

    assert len(analysis.anchors) == 3
    assert CaptureQualityLabel.MULTI_INTENT in quality.labels
    assert {item.observation_ids[0] for item in analysis.anchors} == {
        "SERVER",
        "FIREWALL",
        "DNS",
    }
    assert analysis.primary_anchor_id is not None


def test_declared_and_observed_intents_are_compared_without_overwrite() -> None:
    observed = CaptureIntent(
        label="update_user_credential",
        action="UPDATE",
        resource_type="user_credential",
        confidence=CaptureConfidence.HIGH,
        source=MetadataSource.ENGINE_REFINED,
    )
    inconsistent = CaptureIntent(
        label="read_me",
        action="READ",
        resource_type="me",
        confidence=CaptureConfidence.HIGH,
        source=MetadataSource.USER_CONFIRMED,
    )

    assert align_intents(_declared_intent(), observed) == IntentAlignment.CONSISTENT
    assert align_intents(inconsistent, observed) == IntentAlignment.CONFLICTING
    assert inconsistent.action == "READ"


def test_arvan_style_capture_refines_post_as_credential_update(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path)
    result = ingest_har(
        _har(tmp_path / "account-a-change-credential.har", _password_journey(0, "A")),
        workspace,
        actor="ACCOUNT_A",
        channel="WEB",
        capture_assignment=_assignment(),
    )
    assert result.capture is not None
    assert result.capture.provisional_intent.action == "UPDATE"
    assert result.capture.provisional_intent.source == MetadataSource.ENGINE_INFERRED_RAW

    build_inventory(workspace)
    capture = find_capture(workspace, result.capture.capture_id)
    assert capture is not None
    assert capture.declared_intent == _declared_intent()
    assert capture.observed_intent.action == "UPDATE"
    assert capture.observed_intent.resource_type == "user_credential"
    assert capture.observed_intent.source == MetadataSource.ENGINE_REFINED
    assert capture.intent_alignment == IntentAlignment.CONSISTENT
    assert capture.counts.primary == 1
    assert capture.counts.protocol_support == 3
    assert capture.analysis_metrics.repeated_passive_observations_saturated >= 19

    endpoints = EndpointStore.model_validate(load_yaml(workspace.endpoints)).endpoints
    endpoint = next(
        item for item in endpoints if item.method == "POST" and item.path == "/v1/users/me/password"
    )
    assert endpoint.action.name == "update"
    assert endpoint.state_change is True
    assert endpoint.resource.type == "UserCredential"

    observations = ObservationStore.model_validate(load_yaml(workspace.observations)).observations
    password = next(item for item in observations if item.path == "/v1/users/me/password")
    options = [item for item in observations if item.method == "OPTIONS"]
    assert password.capture_relevance == CaptureRelevance.PRIMARY
    assert all(item.capture_relevance == CaptureRelevance.PROTOCOL_SUPPORT for item in options)

    explained = RUNNER.invoke(
        app,
        ["captures", "-w", str(workspace.root), "--explain", capture.capture_id],
    )
    assert explained.exit_code == 0
    assert "Observed intent" in explained.output
    assert "UPDATE user_credential" in explained.output
    assert "Primary journey anchor" in explained.output
    assert "Protocol/background exclusions" in explained.output


def test_two_actor_parallel_credential_journeys_remain_isolated(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path)
    captures = []
    for actor, offset in (("ACCOUNT_A", 0), ("ACCOUNT_B", 100)):
        result = ingest_har(
            _har(
                tmp_path / f"{actor.lower()}-change-credential.har",
                _password_journey(offset, actor),
            ),
            workspace,
            actor=actor,
            channel="WEB",
            capture_assignment=_assignment(),
        )
        assert result.capture is not None
        captures.append(result.capture)

    result = run_offline_workflow(workspace)
    refreshed = [find_capture(workspace, item.capture_id) for item in captures]
    assert all(item is not None for item in refreshed)
    assert len({item.capture_id for item in refreshed if item is not None}) == 2
    assert {
        (item.actor_id, item.observed_intent.action, item.observed_intent.resource_type)
        for item in refreshed
        if item is not None
    } == {
        ("ACCOUNT_A", "UPDATE", "user_credential"),
        ("ACCOUNT_B", "UPDATE", "user_credential"),
    }

    observations = ObservationStore.model_validate(load_yaml(workspace.observations)).observations
    sessions = {
        item.actor_id: {
            observation.session_identity
            for observation in observations
            if observation.actor == item.actor_id
        }
        for item in refreshed
        if item is not None
    }
    assert all(len(values) == 1 for values in sessions.values())
    assert sessions["ACCOUNT_A"].isdisjoint(sessions["ACCOUNT_B"])

    build_behavior_model(workspace)
    capture_ids = {item.capture_id for item in refreshed if item is not None}
    cross_capture = [
        item
        for item in load_propagation(workspace).propagation_links
        if item.source_capture in capture_ids
        and item.destination_capture in capture_ids
        and item.source_capture != item.destination_capture
    ]
    assert all(item.relationship_type != RelationshipType.CAUSAL_HARD for item in cross_capture)

    hypotheses = HypothesisStore.model_validate(load_yaml(workspace.hypotheses)).hypotheses
    assert not [
        item
        for item in hypotheses
        if item.category == "authorization" and item.disposition == "ACTIVE"
    ]
    assert result.observations == len(observations)
