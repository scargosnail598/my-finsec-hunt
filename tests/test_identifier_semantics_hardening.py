"""Historical regressions for identifier semantics, ownership, and readiness."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from typer.testing import CliRunner

import finsec.cli as cli_module
from finsec.cli import app
from finsec.config.models import TargetDocument
from finsec.config.workspace import WorkspacePaths, create_workspace
from finsec.hypotheses.clustering import finalize_hypothesis_store
from finsec.hypotheses.domain import HypothesisRecord, HypothesisStore
from finsec.ingest.har import ingest_har
from finsec.mcp.service import FinsecMcpService
from finsec.modeling.domain import ActorStore, InvariantStore, ResourceStore
from finsec.modeling.generator import generate_model
from finsec.modeling.invariants import generate_invariants
from finsec.modeling.models import (
    ActorObjectBaseline,
    AuthenticationObservation,
    Confidence,
    Endpoint,
    EndpointAction,
    EndpointAuthentication,
    EndpointClassification,
    EndpointParameter,
    EndpointPrimaryClassification,
    EndpointResource,
    EndpointStore,
    KnowledgeStatus,
    NormalizationEvidence,
    ObjectAccessEvidence,
    Observation,
    ObservationStore,
)
from finsec.modeling.semantics import (
    IdentifierResourceRole,
    IdentifierSemanticAssessment,
    IdentifierSemanticClass,
    OwnershipState,
)
from finsec.normalization.identifier_semantics import classify_identifier_semantics
from finsec.normalization.inventory import build_inventory
from finsec.readiness.domain import (
    LifecycleStatus,
    OverallReadiness,
    ReadinessMetrics,
    ReadinessReport,
)
from finsec.testing.domain import TestPlanStore as PlanStore
from finsec.testing.planner import generate_plan
from finsec.utils.yaml_store import load_yaml, write_yaml
from finsec.validation.domain import ValidationStore
from finsec.web.service import (
    WorkspaceSnapshot,
    hypotheses_payload,
    hypothesis_detail,
    load_snapshot,
)

RUNNER = CliRunner()
HOST = "api.semantic-hardening.test"
FIREWALL_A = "11111111-1111-4111-8111-111111111111"
FIREWALL_B = "22222222-2222-4222-8222-222222222222"


def _target() -> TargetDocument:
    return TargetDocument.model_validate(
        {
            "target": {"name": "semantic-hardening", "slug": "semantic-hardening"},
            "scope": {"hosts": [HOST]},
            "accounts": [
                {"id": "ACCOUNT_A", "ownership": "researcher"},
                {"id": "ACCOUNT_B", "ownership": "researcher"},
            ],
            "testing": {
                "synthetic": True,
                "local_lab": True,
                "maximum_requests_per_plan": 6,
            },
        }
    )


def _observation(
    identifier: str,
    actor: str,
    path: str,
    *,
    status_code: int = 200,
) -> Observation:
    return Observation(
        id=identifier,
        source_reference=f"synthetic:{identifier}",
        source_fingerprint=f"fingerprint:{identifier}",
        actor=actor,
        channel="WEB",
        host=HOST,
        scheme="https",
        method="GET",
        path=path,
        status_code=status_code,
        content_type="application/json",
        authentication=AuthenticationObservation(present=True, observed_type="bearer"),
    )


def _parameter(
    name: str,
    *,
    semantics: IdentifierSemanticAssessment | None = None,
) -> EndpointParameter:
    return EndpointParameter(
        name=name,
        location="path",
        source="request",
        inferred_type="string",
        confidence=Confidence.HIGH,
        evidence=["OBS-A", "OBS-B"],
        knowledge_status=KnowledgeStatus.INFERRED,
        semantic_type="object_identifier",
        client_controlled=True,
        identifier_semantics=semantics or IdentifierSemanticAssessment(),
    )


def _endpoint(
    parameters: list[EndpointParameter],
    *,
    path: str = "/v1/regions/{region}/instances/{instanceId}",
    resource: str = "Instance",
    object_access: list[ObjectAccessEvidence] | None = None,
    sources: list[str] | None = None,
) -> Endpoint:
    return Endpoint(
        id="EP-SEMANTIC",
        method="GET",
        path=path,
        hosts=[HOST],
        channels=["WEB"],
        authentication=EndpointAuthentication(required=True, observed_type="bearer"),
        classification=EndpointClassification(
            primary=EndpointPrimaryClassification.FIRST_PARTY_API,
            confidence=Confidence.HIGH,
        ),
        resource=EndpointResource(type=resource, confidence=Confidence.HIGH),
        action=EndpointAction(name="read", type="read", confidence=Confidence.HIGH),
        parameters=parameters,
        object_access=object_access or [],
        state_change=False,
        security_relevance=8,
        observed_by=["ACCOUNT_A", "ACCOUNT_B"],
        baseline_observed_by=["ACCOUNT_A", "ACCOUNT_B"],
        sources=sources or ["OBS-A", "OBS-B"],
        confidence=Confidence.HIGH,
        normalization=NormalizationEvidence(observed_paths=[path]),
    )


def _record(identifier: str, endpoint: Endpoint, parameter: str) -> HypothesisRecord:
    return HypothesisRecord.model_validate(
        {
            "id": identifier,
            "key": f"auth-object-access:get:{endpoint.path}:{parameter}",
            "title": f"Raw authorization question for {parameter}",
            "kind": "SECURITY_HYPOTHESIS",
            "disposition": "ACTIVE",
            "category": "authorization",
            "component": endpoint.resource.type,
            "source": {"endpoints": [endpoint.id], "observations": endpoint.sources},
            "observations": endpoint.sources,
            "mutation_dimensions": ["ACTOR", "OBJECT"],
            "evidence_status": "INFERRED",
            "hypothesis": f"Substitute only {parameter} across controlled actors.",
            "reasoning": "The exact identifier semantics determine whether this is meaningful.",
            "preconditions": ["Use only researcher-controlled actors and objects."],
            "expected_secure_behavior": "The server preserves the authorization boundary.",
            "possible_vulnerable_behavior": "The server crosses the authorization boundary.",
            "potential_impact": {
                "confidentiality": "high",
                "integrity": "none",
                "availability": "none",
                "financial": "unknown",
            },
            "evidence_to_collect": ["Record both controlled baselines and the comparison."],
            "eligibility_evidence": ["Synthetic first-party authenticated endpoint."],
            "missing_evidence": [],
            "generation_rule": {"id": "AUTH_OBJECT_ACCESS", "version": "6"},
            "scores": {
                "impact": 4,
                "likelihood": 3,
                "confidence": 3,
                "testability": 3,
                "total": 13,
            },
            "priority": "P2",
        }
    )


def _finalize(
    endpoint: Endpoint,
    records: list[HypothesisRecord],
    observations: list[Observation],
) -> HypothesisStore:
    return finalize_hypothesis_store(
        _target(),
        ObservationStore(observations=observations),
        EndpointStore(endpoints=[endpoint]),
        ResourceStore(),
        HypothesisStore(hypotheses=records),
    )


def _owned_semantics(
    resource_type: str,
    *,
    role: IdentifierResourceRole = IdentifierResourceRole.SUBJECT,
    parent_resource_type: str | None = None,
) -> IdentifierSemanticAssessment:
    return IdentifierSemanticAssessment(
        semantic_class=IdentifierSemanticClass.OWNED_OBJECT,
        resource_role=role,
        resource_type=resource_type,
        parent_resource_type=parent_resource_type,
        ownership_state=OwnershipState.STRONG_INFERRED,
        confidence="high",
        evidence=["Synthetic controlled lifecycle evidence."],
        explanation="The exact synthetic object target is controlled by the researcher.",
    )


def test_case_a_shared_region_is_not_an_owned_object_boundary() -> None:
    observations = [
        _observation("OBS-A", "ACCOUNT_A", "/v1/regions/ir-thr-ba1/instances/a"),
        _observation("OBS-B", "ACCOUNT_B", "/v1/regions/ir-thr-ba1/instances/b"),
    ]
    parameter = _parameter("region")
    assessment = classify_identifier_semantics(
        path="/v1/regions/{region}/instances/{instanceId}",
        endpoint_resource="Instance",
        parameter=parameter,
        observations=observations,
        target=_target(),
    )
    endpoint = _endpoint([parameter.model_copy(update={"identifier_semantics": assessment})])
    record = _finalize(endpoint, [_record("HYP-001", endpoint, "region")], observations)
    hypothesis = record.hypotheses[0]

    assert assessment.semantic_class == IdentifierSemanticClass.REGION
    assert assessment.ownership_state == OwnershipState.SHARED
    assert hypothesis.kind == "RESEARCH_TASK"
    assert hypothesis.readiness == "RESEARCH_ONLY"
    assert hypothesis.mutation_target.semantics.semantic_class == IdentifierSemanticClass.REGION


def test_cases_b_and_g_distinct_firewalls_under_shared_region_are_secure_scoping_evidence() -> None:
    path = "/v1/regions/{region}/firewalls/{firewallId}"
    observations = [
        _observation("OBS-A", "ACCOUNT_A", f"/v1/regions/ir-thr-ba1/firewalls/{FIREWALL_A}"),
        _observation("OBS-B", "ACCOUNT_B", f"/v1/regions/ir-thr-ba1/firewalls/{FIREWALL_B}"),
    ]
    region = classify_identifier_semantics(
        path=path,
        endpoint_resource="Firewall",
        parameter=_parameter("region"),
        observations=observations,
        target=_target(),
    )
    firewall = classify_identifier_semantics(
        path=path,
        endpoint_resource="Firewall",
        parameter=_parameter("firewallId"),
        observations=observations,
        target=_target(),
    )

    assert region.semantic_class == IdentifierSemanticClass.REGION
    assert region.ownership_state == OwnershipState.SHARED
    assert firewall.semantic_class == IdentifierSemanticClass.OWNED_OBJECT
    assert firewall.ownership_state == OwnershipState.WEAK_INFERRED
    assert any("secure account scoping" in item for item in firewall.counterevidence)
    assert region.semantic_class != IdentifierSemanticClass.OWNED_OBJECT


@pytest.mark.parametrize(
    (
        "name",
        "path",
        "endpoint_resource",
        "location",
        "semantic_type",
        "expected_class",
        "expected_role",
    ),
    [
        (
            "accountId",
            "/v1/accounts/{accountId}",
            "Account",
            "path",
            "object_identifier",
            IdentifierSemanticClass.TENANT_CONTAINER,
            IdentifierResourceRole.TENANT,
        ),
        (
            "projectId",
            "/v1/projects/{projectId}/instances/{instanceId}",
            "Instance",
            "path",
            "object_identifier",
            IdentifierSemanticClass.PARENT_CONTAINER,
            IdentifierResourceRole.PARENT,
        ),
        (
            "zoneId",
            "/v1/availability-zones/{zoneId}/instances/{instanceId}",
            "Instance",
            "path",
            "object_identifier",
            IdentifierSemanticClass.REGION,
            IdentifierResourceRole.SHARED_SCOPE,
        ),
        (
            "collectionId",
            "/v1/collections/{collectionId}",
            "Collection",
            "path",
            "object_identifier",
            IdentifierSemanticClass.OBJECT_IDENTIFIER,
            IdentifierResourceRole.CHILD_OBJECT,
        ),
        (
            "userId",
            "/v1/users/{userId}",
            "User",
            "path",
            "object_identifier",
            IdentifierSemanticClass.ACTOR_IDENTIFIER,
            IdentifierResourceRole.ACTOR,
        ),
        (
            "sessionId",
            "/v1/sessions",
            "Session",
            "query",
            "authentication",
            IdentifierSemanticClass.AUTH_IDENTIFIER,
            IdentifierResourceRole.AUTH,
        ),
        (
            "planId",
            "/v1/plans/{planId}",
            "Plan",
            "path",
            "object_identifier",
            IdentifierSemanticClass.OBJECT_IDENTIFIER,
            IdentifierResourceRole.CHILD_OBJECT,
        ),
        (
            "code",
            "/v1/coupons/{code}",
            "Coupon",
            "path",
            "object_identifier",
            IdentifierSemanticClass.OBJECT_IDENTIFIER,
            IdentifierResourceRole.CHILD_OBJECT,
        ),
        (
            "profileId",
            "/v1/profiles/{profileId}",
            "Profile",
            "path",
            "object_identifier",
            IdentifierSemanticClass.OBJECT_IDENTIFIER,
            IdentifierResourceRole.CHILD_OBJECT,
        ),
        (
            "opaqueKey",
            "/v1/items",
            "Item",
            "query",
            "object_identifier",
            IdentifierSemanticClass.OBJECT_IDENTIFIER,
            IdentifierResourceRole.SUBJECT,
        ),
        (
            "filename",
            "/assets/{filename}",
            "Asset",
            "path",
            "unknown",
            IdentifierSemanticClass.NON_SECURITY_RELEVANT,
            IdentifierResourceRole.CHILD_OBJECT,
        ),
    ],
)
def test_classifier_distinguishes_identifier_families(
    name: str,
    path: str,
    endpoint_resource: str,
    location: str,
    semantic_type: str,
    expected_class: IdentifierSemanticClass,
    expected_role: IdentifierResourceRole,
) -> None:
    parameter = _parameter(name).model_copy(
        update={"location": location, "semantic_type": semantic_type}
    )

    assessment = classify_identifier_semantics(
        path=path,
        endpoint_resource=endpoint_resource,
        parameter=parameter,
        observations=[],
        target=_target(),
    )

    assert assessment.semantic_class == expected_class
    assert assessment.resource_role == expected_role


def test_case_c_region_and_instance_mutations_are_not_semantic_duplicates() -> None:
    region_semantics = IdentifierSemanticAssessment(
        semantic_class=IdentifierSemanticClass.REGION,
        resource_role=IdentifierResourceRole.SHARED_SCOPE,
        resource_type="Region",
        ownership_state=OwnershipState.SHARED,
        confidence="high",
        evidence=["Parameter denotes shared infrastructure scope."],
        explanation="Region is shared infrastructure scope.",
    )
    instance_semantics = IdentifierSemanticAssessment(
        semantic_class=IdentifierSemanticClass.OWNED_OBJECT,
        resource_role=IdentifierResourceRole.CHILD_OBJECT,
        resource_type="Instance",
        parent_resource_type="Region",
        ownership_state=OwnershipState.STRONG_INFERRED,
        confidence="high",
        evidence=["Two controlled actor/object lifecycles are available."],
        explanation="Instance is an evidence-backed controlled object.",
    )
    endpoint = _endpoint(
        [
            _parameter("region", semantics=region_semantics),
            _parameter("instanceId", semantics=instance_semantics),
        ]
    )
    observations = [
        _observation("OBS-A", "ACCOUNT_A", "/v1/regions/ir-thr-ba1/instances/a"),
        _observation("OBS-B", "ACCOUNT_B", "/v1/regions/ir-thr-ba1/instances/b"),
    ]
    store = _finalize(
        endpoint,
        [
            _record("HYP-001", endpoint, "region"),
            _record("HYP-002", endpoint, "instanceId"),
        ],
        observations,
    )
    by_id = {item.id: item for item in store.hypotheses}

    assert by_id["HYP-001"].grouping.cluster_id != by_id["HYP-002"].grouping.cluster_id
    assert by_id["HYP-001"].semantic_descriptor is not None
    assert by_id["HYP-002"].semantic_descriptor is not None
    assert (
        by_id["HYP-001"].semantic_descriptor.exact_key
        != by_id["HYP-002"].semantic_descriptor.exact_key
    )
    assert any(
        "mutation target" in item and "HYP-002" in item
        for item in by_id["HYP-001"].presentation.difference_reasons
    )


def test_negative_semantic_evidence_reduces_authorization_likelihood() -> None:
    semantics = IdentifierSemanticAssessment(
        semantic_class=IdentifierSemanticClass.OWNED_OBJECT,
        resource_role=IdentifierResourceRole.CHILD_OBJECT,
        resource_type="Firewall",
        ownership_state=OwnershipState.STRONG_INFERRED,
        confidence="high",
        evidence=["Controlled lifecycle evidence establishes an actor/object binding."],
        counterevidence=["Observed actor-specific IDs are consistent with secure scoping."],
        explanation="The object is controlled, while secure-scoping evidence lowers suspicion.",
    )
    endpoint = _endpoint(
        [_parameter("firewallId", semantics=semantics)],
        path="/v1/firewalls/{firewallId}",
        resource="Firewall",
    )
    observations = [
        _observation("OBS-A", "ACCOUNT_A", f"/v1/firewalls/{FIREWALL_A}"),
        _observation("OBS-B", "ACCOUNT_B", f"/v1/firewalls/{FIREWALL_B}"),
    ]

    hypothesis = _finalize(
        endpoint,
        [_record("HYP-001", endpoint, "firewallId")],
        observations,
    ).hypotheses[0]

    assert hypothesis.scores.likelihood == 2
    assert hypothesis.scores.confidence == 4
    assert hypothesis.scores.testability == 3


def test_case_d_nested_dns_record_targets_child_not_parent() -> None:
    path = "/cdn/4.0/domains/{domain}/dns-records/{dnsRecordId}"
    observations = [
        _observation(
            "OBS-A",
            "ACCOUNT_A",
            "/cdn/4.0/domains/domain-a/dns-records/record-a",
        ),
        _observation(
            "OBS-B",
            "ACCOUNT_B",
            "/cdn/4.0/domains/domain-b/dns-records/record-b",
        ),
    ]
    domain = classify_identifier_semantics(
        path=path,
        endpoint_resource="DnsRecord",
        parameter=_parameter("domain"),
        observations=observations,
        target=_target(),
    )
    record_id = classify_identifier_semantics(
        path=path,
        endpoint_resource="DnsRecord",
        parameter=_parameter("dnsRecordId"),
        observations=observations,
        target=_target(),
    )
    endpoint = _endpoint(
        [
            _parameter("domain", semantics=domain),
            _parameter("dnsRecordId", semantics=record_id),
        ],
        path=path,
        resource="DnsRecord",
    )
    store = _finalize(endpoint, [_record("HYP-001", endpoint, "dnsRecordId")], observations)

    assert domain.semantic_class == IdentifierSemanticClass.PARENT_CONTAINER
    assert domain.resource_role == IdentifierResourceRole.PARENT
    assert record_id.semantic_class == IdentifierSemanticClass.OWNED_OBJECT
    assert record_id.resource_role == IdentifierResourceRole.CHILD_OBJECT
    assert store.hypotheses[0].mutation_target.parameter == "dnsRecordId"
    assert store.hypotheses[0].readiness != "TEST_READY"


def test_nested_json_mutation_identity_is_exact_and_reaches_blocked_plan(
    tmp_path: Path,
) -> None:
    semantics = _owned_semantics("Transfer")
    json_paths = [
        "$.sender.id",
        "$.recipient.id",
        "$.billing.account.id",
        "$.shipping.account.id",
        "$.id",
    ]
    parameters = [
        _parameter("id", semantics=semantics),
        *[
            _parameter("id", semantics=semantics).model_copy(
                update={"location": "body", "json_path": json_path}
            )
            for json_path in json_paths
        ],
    ]
    endpoint = _endpoint(
        parameters,
        path="/v1/transfers/{id}",
        resource="Transfer",
    )
    observations = [
        _observation("OBS-A", "ACCOUNT_A", "/v1/transfers/transfer-a"),
        _observation("OBS-B", "ACCOUNT_B", "/v1/transfers/transfer-b"),
    ]
    requested_targets = [
        ("HYP-001", "path", "id", None),
        ("HYP-002", "body", "sender.id", "$.sender.id"),
        ("HYP-003", "body", "recipient.id", "$.recipient.id"),
        ("HYP-004", "body", "billing.account.id", "$.billing.account.id"),
        ("HYP-005", "body", "shipping.account.id", "$.shipping.account.id"),
        ("HYP-006", "body", "id", "$.id"),
    ]
    records: list[HypothesisRecord] = []
    for identifier, location, requested, _ in requested_targets:
        record = _record(identifier, endpoint, requested)
        records.append(
            record.model_copy(
                update={"key": (f"auth-object-access:get:{endpoint.path}:{location}:{requested}")}
            )
        )

    store = _finalize(endpoint, records, observations)
    by_id = {item.id: item for item in store.hypotheses}

    for identifier, location, _, json_path in requested_targets:
        target = by_id[identifier].mutation_target
        assert target.location == location
        assert target.json_path == json_path
    assert by_id["HYP-002"].semantic_descriptor is not None
    assert by_id["HYP-003"].semantic_descriptor is not None
    assert by_id["HYP-004"].semantic_descriptor is not None
    assert by_id["HYP-005"].semantic_descriptor is not None
    assert by_id["HYP-001"].semantic_descriptor is not None
    assert by_id["HYP-006"].semantic_descriptor is not None
    assert (
        by_id["HYP-002"].semantic_descriptor.exact_key
        != by_id["HYP-003"].semantic_descriptor.exact_key
    )
    assert (
        by_id["HYP-004"].semantic_descriptor.exact_key
        != by_id["HYP-005"].semantic_descriptor.exact_key
    )
    assert (
        by_id["HYP-001"].semantic_descriptor.exact_key
        != by_id["HYP-006"].semantic_descriptor.exact_key
    )

    workspace = create_workspace("nested-targets", tmp_path / "workspaces")
    write_yaml(workspace.target, _target().model_dump(mode="json", exclude_none=True))
    write_yaml(
        workspace.observations,
        ObservationStore(observations=observations).model_dump(mode="json", exclude_none=True),
    )
    write_yaml(
        workspace.endpoints,
        EndpointStore(endpoints=[endpoint]).model_dump(mode="json", exclude_none=True),
    )
    write_yaml(workspace.resources, ResourceStore().model_dump(mode="json", exclude_none=True))
    write_yaml(workspace.hypotheses, store.model_dump(mode="json", exclude_none=True))

    plan = generate_plan(workspace, "HYP-002").plan

    assert plan.mutation_target.location == "body"
    assert plan.mutation_target.json_path == "$.sender.id"
    assert plan.requests == []
    assert plan.execution.supported is False
    assert any("exact path targets only" in item for item in plan.execution.blockers)
    web_target = hypothesis_detail(load_snapshot(workspace), "HYP-002")["explanation"][
        "mutation_target"
    ]
    mcp_target = (
        FinsecMcpService.from_workspace_path(workspace.root)
        .hypothesis_context("HYP-002")
        .hypothesis.explanation.mutation_target
    )
    assert web_target["location"] == "body"
    assert web_target["json_path"] == "$.sender.id"
    assert mcp_target.location == "body"
    assert mcp_target.json_path == "$.sender.id"


def test_literal_dns_parents_share_campaign_without_replacing_member_titles(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    semantics = _owned_semantics(
        "DnsRecord",
        role=IdentifierResourceRole.CHILD_OBJECT,
        parent_resource_type="Domain",
    )
    endpoints: list[Endpoint] = []
    observations: list[Observation] = []
    records: list[HypothesisRecord] = []
    for index, domain in enumerate(("a.test", "b.test"), start=3):
        observation_id = f"OBS-{index}"
        endpoint = _endpoint(
            [_parameter("dnsRecordId", semantics=semantics)],
            path=f"/cdn/4.0/domains/{domain}/dns-records/{{dnsRecordId}}",
            resource="DnsRecord",
            sources=[observation_id],
        ).model_copy(
            update={
                "id": f"EP-{index}",
                "method": "DELETE",
                "action": EndpointAction(
                    name="delete", type="mutation", confidence=Confidence.HIGH
                ),
                "state_change": True,
                "state_change_reasons": ["Synthetic DELETE regression."],
            }
        )
        observation = _observation(
            observation_id,
            "ACCOUNT_A" if index == 3 else "ACCOUNT_B",
            f"/cdn/4.0/domains/{domain}/dns-records/record-{index}",
        ).model_copy(update={"method": "DELETE", "status_code": 204})
        record = _record(f"HYP-00{index}", endpoint, "dnsRecordId").model_copy(
            update={"key": (f"auth-object-access:delete:{endpoint.path}:path:dnsRecordId")}
        )
        endpoints.append(endpoint)
        observations.append(observation)
        records.append(record)

    first = finalize_hypothesis_store(
        _target(),
        ObservationStore(observations=observations),
        EndpointStore(endpoints=endpoints),
        ResourceStore(),
        HypothesisStore(hypotheses=records),
    )
    second = finalize_hypothesis_store(
        _target(),
        ObservationStore(observations=list(reversed(observations))),
        EndpointStore(endpoints=list(reversed(endpoints))),
        ResourceStore(),
        HypothesisStore(hypotheses=list(reversed(records))),
    )
    assert first.model_dump(mode="json") == second.model_dump(mode="json")

    by_id = {item.id: item for item in first.hypotheses}
    campaign = first.campaigns[0]
    assert campaign.relationship == "OVERLAPPING_TEST_CAMPAIGN"
    assert campaign.member_ids == ["HYP-003", "HYP-004"]
    assert campaign.shared_setup
    assert campaign.distinctions
    assert by_id["HYP-003"].grouping.campaign_id == campaign.id
    assert by_id["HYP-004"].grouping.campaign_id == campaign.id
    assert by_id["HYP-003"].grouping.cluster_id != by_id["HYP-004"].grouping.cluster_id
    assert by_id["HYP-003"].title != campaign.title
    assert by_id["HYP-004"].title != campaign.title
    assert by_id["HYP-003"].domain_intent.parent_resource == "Domain"
    assert by_id["HYP-004"].domain_intent.parent_resource == "Domain"
    assert by_id["HYP-003"].mutation_target.semantics.parent_resource_type == "Domain"
    assert by_id["HYP-004"].mutation_target.semantics.parent_resource_type == "Domain"
    assert by_id["HYP-003"].semantic_descriptor is not None
    assert by_id["HYP-004"].semantic_descriptor is not None
    assert by_id["HYP-003"].semantic_descriptor.parent_contexts == ["a.test"]
    assert by_id["HYP-004"].semantic_descriptor.parent_contexts == ["b.test"]

    workspace = create_workspace("dns-campaign", tmp_path / "workspaces")
    write_yaml(workspace.target, _target().model_dump(mode="json", exclude_none=True))
    write_yaml(workspace.hypotheses, first.model_dump(mode="json", exclude_none=True))
    snapshot = WorkspaceSnapshot(
        paths=workspace,
        target=_target(),
        observations=ObservationStore(observations=observations),
        endpoints=EndpointStore(endpoints=endpoints),
        actors=ActorStore(),
        resources=ResourceStore(),
        invariants=InvariantStore(),
        hypotheses=first,
        plans=PlanStore(),
        validations=ValidationStore(),
    )
    web_rows = {item["id"]: item for item in hypotheses_payload(snapshot)["hypotheses"]}
    mcp_rows = {
        item.id: item
        for item in FinsecMcpService.from_workspace_path(workspace.root)
        .list_hypotheses(active_only=False, include_research_tasks=True)
        .hypotheses
    }
    for identifier in ("HYP-003", "HYP-004"):
        assert web_rows[identifier]["title"] == by_id[identifier].title
        assert web_rows[identifier]["member_title"] == by_id[identifier].title
        assert web_rows[identifier]["campaign_title"] == campaign.title
        assert mcp_rows[identifier].title == by_id[identifier].title
        assert mcp_rows[identifier].member_title == by_id[identifier].title
        assert mcp_rows[identifier].campaign_title == campaign.title

    monkeypatch.setattr(cli_module, "resolve_workspace", lambda _: workspace)
    monkeypatch.setattr(
        cli_module,
        "generate_hypotheses",
        lambda _: SimpleNamespace(conflicts=[]),
    )
    monkeypatch.setattr(cli_module, "load_hypotheses", lambda _: first)
    monkeypatch.setattr(
        cli_module,
        "inspect_plan_alignment",
        lambda *_: SimpleNamespace(plan_status="BLOCKED", agrees=True, violation=None),
    )
    environment = {"COLUMNS": "240"}
    listed = RUNNER.invoke(
        app,
        ["hypotheses", "--workspace", str(workspace.root)],
        env=environment,
    )
    campaigns = RUNNER.invoke(
        app,
        ["hypotheses", "--workspace", str(workspace.root), "--campaigns"],
        env=environment,
    )
    member = RUNNER.invoke(
        app,
        ["hypotheses", "--workspace", str(workspace.root), "--explain", "HYP-004"],
        env=environment,
    )
    campaign_explain = RUNNER.invoke(
        app,
        ["hypotheses", "--workspace", str(workspace.root), "--explain", campaign.id],
        env=environment,
    )
    for result in (listed, campaigns, member, campaign_explain):
        assert result.exit_code == 0, result.output
    assert by_id["HYP-003"].title in listed.output
    assert by_id["HYP-004"].title in listed.output
    assert campaign.title not in listed.output
    assert campaign.title in campaigns.output
    assert by_id["HYP-004"].title in member.output
    assert campaign.title not in member.output
    assert campaign.title in campaign_explain.output
    assert "HYP-003, HYP-004" in campaign_explain.output
    assert "Shared setup:" in campaign_explain.output
    assert "Distinction:" in campaign_explain.output
    assert "Next action:" in campaign_explain.output

    report = ReadinessReport(
        workspace="dns-campaign",
        overall=OverallReadiness(status=LifecycleStatus.BLOCKED),
        stages=[],
        metrics=ReadinessMetrics(
            active_hypotheses=2,
            hypotheses_not_tested=2,
        ),
    )
    monkeypatch.setattr(cli_module, "resolve_workspace_readiness", lambda _: report)
    status = RUNNER.invoke(
        app,
        ["status", "--workspace", str(workspace.root)],
        env=environment,
    )
    assert status.exit_code == 0, status.output
    assert by_id["HYP-003"].title in status.output
    assert by_id["HYP-004"].title in status.output
    assert campaign.title not in status.output


def test_case_e_one_controlled_baseline_is_not_test_ready() -> None:
    semantics = IdentifierSemanticAssessment(
        semantic_class=IdentifierSemanticClass.OWNED_OBJECT,
        resource_role=IdentifierResourceRole.SUBJECT,
        resource_type="Firewall",
        ownership_state=OwnershipState.STRONG_INFERRED,
        confidence="high",
        evidence=["One controlled lifecycle is available."],
        explanation="The exact object is known, but the comparison baseline is incomplete.",
    )
    access = ObjectAccessEvidence(
        identifier="firewallId",
        source="CONTROLLED_LIFECYCLE",
        baselines=[
            ActorObjectBaseline(
                actor="ACCOUNT_A",
                requested_value=FIREWALL_A,
                subject_resource_id="RSC-A",
                endpoint_id="EP-SEMANTIC",
                baseline_id="BASE-A",
                operation="READ",
                observations=["OBS-A"],
            )
        ],
        distinct_actors=1,
        distinct_objects=1,
        actor_object_binding_observed=True,
        baseline_ids=["BASE-A"],
    )
    endpoint = _endpoint(
        [_parameter("firewallId", semantics=semantics)],
        path="/v1/firewalls/{firewallId}",
        resource="Firewall",
        object_access=[access],
        sources=["OBS-A"],
    )
    observations = [_observation("OBS-A", "ACCOUNT_A", f"/v1/firewalls/{FIREWALL_A}")]
    hypothesis = _finalize(
        endpoint,
        [_record("HYP-001", endpoint, "firewallId")],
        observations,
    ).hypotheses[0]

    assert hypothesis.readiness == "REVIEW_REQUIRED"
    assert hypothesis.readiness_assessment.comparison_coverage.observed_distinct_actors == 1
    assert hypothesis.readiness_assessment.comparison_coverage.distinct_controlled_objects == 1
    assert hypothesis.readiness_assessment.comparison_coverage.missing_actor_ids == ["ACCOUNT_B"]
    assert any(
        "Missing controlled object baseline for ACCOUNT_B" in item
        for item in hypothesis.readiness_assessment.missing_prerequisites
    )


def _har_entry(minute: int, method: str, path: str, response: dict[str, Any]) -> dict[str, Any]:
    return {
        "startedDateTime": f"2026-08-01T10:{minute:02d}:00Z",
        "request": {
            "method": method,
            "url": f"https://{HOST}{path}",
            "headers": [{"name": "Authorization", "value": "Bearer SYNTHETIC_SECRET"}],
        },
        "response": {
            "status": 200,
            "headers": [{"name": "Content-Type", "value": "application/json"}],
            "content": {"mimeType": "application/json", "text": json.dumps(response)},
        },
    }


def _owned_workspace(tmp_path: Path) -> WorkspacePaths:
    workspace = create_workspace("owned-firewalls", tmp_path / "workspaces")
    target = load_yaml(workspace.target)
    target.update(_target().model_dump(mode="json", exclude_none=True))
    write_yaml(workspace.target, target)
    captures = [
        (
            "ACCOUNT_A",
            FIREWALL_A,
            [
                _har_entry(1, "POST", "/v1/firewalls", {"id": FIREWALL_A}),
                _har_entry(2, "GET", f"/v1/firewalls/{FIREWALL_A}", {"id": FIREWALL_A}),
            ],
        ),
        (
            "ACCOUNT_B",
            FIREWALL_B,
            [
                _har_entry(3, "POST", "/v1/firewalls", {"id": FIREWALL_B}),
                _har_entry(4, "GET", f"/v1/firewalls/{FIREWALL_B}", {"id": FIREWALL_B}),
            ],
        ),
    ]
    for actor, value, entries in captures:
        capture = tmp_path / f"{actor.lower()}-{value[:8]}.har"
        capture.write_text(
            json.dumps(
                {
                    "log": {
                        "version": "1.2",
                        "creator": {"name": "semantic-hardening"},
                        "entries": entries,
                    }
                },
                sort_keys=True,
            ),
            encoding="utf-8",
        )
        ingest_har(capture, workspace, actor=actor, channel="WEB")
    build_inventory(workspace)
    generate_model(workspace)
    generate_invariants(workspace)
    from finsec.hypotheses.generator import generate_hypotheses

    generate_hypotheses(workspace)
    return workspace


def _generation_signature(store: HypothesisStore) -> dict[str, object]:
    return {
        "hypotheses": [
            {
                "id": item.id,
                "disposition": item.disposition,
                "semantic_class": item.mutation_target.semantics.semantic_class,
                "ownership_state": item.mutation_target.semantics.ownership_state,
                "visible": item.presentation.visible,
                "suppression_reason": item.presentation.suppression_reason,
                "cluster_id": item.grouping.cluster_id,
                "campaign_id": item.grouping.campaign_id,
                "readiness": item.readiness,
                "scores": item.scores.model_dump(mode="json"),
            }
            for item in store.hypotheses
        ],
        "campaigns": [item.model_dump(mode="json") for item in store.campaigns],
    }


def test_case_f_two_controlled_lifecycles_build_exact_object_substitution(
    tmp_path: Path,
) -> None:
    workspace = _owned_workspace(tmp_path)
    endpoints = EndpointStore.model_validate(load_yaml(workspace.endpoints))
    assert endpoints.version == 2
    endpoint = next(
        item for item in endpoints.endpoints if item.method == "GET" and "{firewallId}" in item.path
    )
    binding = next(item for item in endpoint.object_access if item.identifier == "firewallId")
    store = HypothesisStore.model_validate(load_yaml(workspace.hypotheses))
    authentication_task = next(
        item
        for item in store.hypotheses
        if item.generation_rule.get("id") == "AUTH_ENFORCEMENT_RESEARCH"
    )
    hypothesis = next(
        item
        for item in store.hypotheses
        if endpoint.id in item.source.endpoints
        and item.category == "authorization"
        and item.mutation_target.parameter == "firewallId"
    )
    assert authentication_task.mutation_target.parameter is None
    first_signature = _generation_signature(store)

    build_inventory(workspace)
    generate_model(workspace)
    generate_invariants(workspace)
    from finsec.hypotheses.generator import generate_hypotheses

    generate_hypotheses(workspace)
    regenerated_store = HypothesisStore.model_validate(load_yaml(workspace.hypotheses))
    assert _generation_signature(regenerated_store) == first_signature

    plan = generate_plan(workspace, hypothesis.id).plan

    assert binding.source == "CONTROLLED_LIFECYCLE"
    assert binding.distinct_actors == 2
    assert binding.distinct_objects == 2
    assert (
        hypothesis.mutation_target.semantics.semantic_class == IdentifierSemanticClass.OWNED_OBJECT
    )
    assert hypothesis.mutation_target.semantics.ownership_state == OwnershipState.STRONG_INFERRED
    assert hypothesis.readiness == "TEST_READY"
    assert plan.execution.supported is True
    assert plan.execution.pattern == "OBJECT_SUBSTITUTION"
    assert plan.requests[1].mutations[0].parameter == "firewallId"

    explained = RUNNER.invoke(
        app,
        ["hypotheses", "--workspace", str(workspace.root), "--explain", hypothesis.id],
    )
    assert explained.exit_code == 0, explained.output
    assert "Object semantics and ownership" in explained.output
    assert "Mutation target: firewallId" in explained.output
    assert "Semantic class: OWNED_OBJECT" in explained.output
    assert "Ranking rationale" in explained.output
    assert "Suppression and distinction" in explained.output

    web = hypothesis_detail(load_snapshot(workspace), hypothesis.id)["explanation"]
    assert web["mutation_target"]["parameter"] == "firewallId"
    assert web["identifier_semantics"]["ownership_state"] == "STRONG_INFERRED"
    assert web["presentation"]["retention_reasons"]
    assert web["presentation"]["cluster_id"] == hypothesis.grouping.cluster_id

    mcp = FinsecMcpService.from_workspace_path(workspace.root).hypothesis_context(hypothesis.id)
    assert mcp.hypothesis.explanation.mutation_target.parameter == "firewallId"
    assert mcp.hypothesis.explanation.identifier_semantics.semantic_class == "OWNED_OBJECT"
    assert mcp.hypothesis.explanation.retention_reasons


def test_legacy_records_default_to_unknown_semantics() -> None:
    legacy_parameter = EndpointParameter.model_validate(
        {
            "name": "legacyId",
            "location": "path",
            "source": "request",
            "inferred_type": "string",
            "confidence": "medium",
            "knowledge_status": "INFERRED",
            "semantic_type": "object_identifier",
            "client_controlled": True,
        }
    )
    endpoint = _endpoint([legacy_parameter], path="/v1/legacy/{legacyId}", resource="Legacy")
    legacy_record = _record("HYP-001", endpoint, "legacyId").model_dump(
        mode="json", exclude_none=True
    )
    legacy_record.pop("mutation_target", None)
    legacy_record.pop("presentation", None)
    legacy_record.pop("readiness_assessment", None)
    loaded = HypothesisRecord.model_validate(legacy_record)

    assert (
        legacy_parameter.identifier_semantics.semantic_class
        == IdentifierSemanticClass.OPAQUE_UNKNOWN
    )
    assert legacy_parameter.identifier_semantics.ownership_state == OwnershipState.UNKNOWN
    assert loaded.mutation_target.semantics.semantic_class == IdentifierSemanticClass.OPAQUE_UNKNOWN
    assert loaded.presentation.retention_reasons == []
    assert loaded.readiness != "TEST_READY"
