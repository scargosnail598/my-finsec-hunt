"""Read-only MCP service and HYP-002 interpretation tests."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from finsec.config.models import TargetDocument
from finsec.config.workspace import WorkspacePaths, create_workspace
from finsec.evidence.domain import EvidenceArtifact, EvidenceMetadata
from finsec.execution.domain import (
    EvidenceHash,
    ExecutionAuditRecord,
    ExecutionComparison,
    ExecutionResponseSummary,
)
from finsec.execution.policy import plan_checksum
from finsec.hypotheses.domain import (
    HypothesisRecord,
    HypothesisStore,
)
from finsec.mcp.service import FinsecMcpError, FinsecMcpService
from finsec.modeling.domain import InvariantRecord, InvariantStore
from finsec.modeling.models import (
    ActorObjectBaseline,
    AuthenticationObservation,
    Confidence,
    Endpoint,
    EndpointAuthentication,
    EndpointParameter,
    EndpointResource,
    EndpointStore,
    KnowledgeStatus,
    NormalizationEvidence,
    ObjectAccessEvidence,
    Observation,
    ObservationStore,
)
from finsec.testing.domain import (
    PlanAccounts,
    PlanApproval,
    PlanExecutionConfig,
    RequestExpectation,
    RequestMutation,
    RiskClassification,
    StructuredRequest,
)
from finsec.testing.domain import (
    TestPlanRecord as PlanRecord,
)
from finsec.testing.domain import (
    TestPlanStore as PlanStore,
)
from finsec.utils.yaml_store import load_yaml, write_yaml
from finsec.validation.domain import ValidationCheck, ValidationRecord, ValidationStore

CANARIES = {
    "SUPER_SECRET_BEARER_TOKEN",
    "SESSION_COOKIE_CANARY",
    "CSRF_CANARY",
}


def _hypothesis(
    hypothesis_id: str,
    *,
    kind: str = "SECURITY_HYPOTHESIS",
    disposition: str = "ACTIVE",
    priority: str = "P1",
    scores: tuple[int, int, int, int] = (4, 3, 3, 5),
) -> HypothesisRecord:
    impact, likelihood, confidence, testability = scores
    return HypothesisRecord.model_validate(
        {
            "id": hypothesis_id,
            "key": f"test:{hypothesis_id}",
            "title": (
                "Potential mixed anonymous and authenticated cross-account Basket access "
                "through basketId"
            ),
            "kind": kind,
            "disposition": disposition,
            "category": "research" if kind == "RESEARCH_TASK" else "authorization",
            "component": "Basket / EP-001",
            "source": {
                "endpoints": ["EP-001"],
                "invariants": ["INV-001"],
                "observations": ["OBS-000001", "OBS-000002"],
            },
            "invariant": ["INV-001"],
            "observations": ["OBS-000001", "OBS-000002"],
            "mutation_dimensions": [] if kind == "RESEARCH_TASK" else ["ACTOR", "OBJECT"],
            "required_state": ["Both basket objects belong to researcher-controlled accounts."],
            "attacker_capability": ["Can substitute one controlled basket identifier."],
            "evidence_status": "INFERRED",
            "hypothesis": (
                "An anonymous caller or authenticated non-owner may cross the Basket boundary."
            ),
            "reasoning": (
                "Observed two account-labelled baselines. Authorization: Bearer "
                "SUPER_SECRET_BEARER_TOKEN must never leave the server."
            ),
            "preconditions": ["Use only the two researcher-controlled accounts."],
            "expected_secure_behavior": "Reject the non-owner without exposing Basket data.",
            "possible_vulnerable_behavior": "Return another controlled account's Basket data.",
            "potential_impact": {
                "confidentiality": "high",
                "integrity": "none",
                "availability": "none",
                "financial": "unknown",
            },
            "evidence_to_collect": ["One baseline and one single-dimension comparison."],
            "eligibility_evidence": ["OBS-000001", "OBS-000002"],
            "missing_evidence": [
                "Authenticated Account B to Account A comparison has not been tested."
            ],
            "priority_rationale": ["Controlled object-boundary comparison is testable."],
            "scores": {
                "impact": impact,
                "likelihood": likelihood,
                "confidence": confidence,
                "testability": testability,
                "total": sum(scores),
            },
            "priority": priority,
            "status": "NOT_TESTED",
            "safety_notes": ["Change exactly one object identifier and stop after minimum proof."],
        }
    )


def _workspace(tmp_path: Path) -> WorkspacePaths:
    workspace = create_workspace("mcp-demo", tmp_path / "workspaces")
    target = load_yaml(workspace.target)
    target["scope"]["hosts"] = ["api.example.test"]
    target["accounts"] = [
        {"id": "ACCOUNT_A", "ownership": "researcher"},
        {"id": "ACCOUNT_B", "ownership": "researcher"},
        {"id": "EXTERNAL", "ownership": "external"},
    ]
    write_yaml(workspace.target, target)

    observations = ObservationStore(
        observations=[
            Observation(
                id="OBS-000001",
                source="HAR",
                source_reference="observations/har/account-a-redacted.har#entry-1",
                source_fingerprint="a" * 64,
                actor="ACCOUNT_A",
                channel="WEB",
                host="api.example.test",
                scheme="https",
                method="GET",
                path="/rest/basket/101",
                query_parameters={"token": ["SUPER_SECRET_BEARER_TOKEN"]},
                response_fields=["data.id", "data.UserId"],
                status_code=200,
                content_type="application/json",
                authentication=AuthenticationObservation(
                    present=False,
                    observed_type="none",
                ),
            ),
            Observation(
                id="OBS-000002",
                source="HAR",
                source_reference="observations/har/account-b-redacted.har#entry-1",
                source_fingerprint="b" * 64,
                actor="ACCOUNT_B",
                channel="WEB",
                host="api.example.test",
                scheme="https",
                method="GET",
                path="/rest/basket/202",
                response_fields=["data.id", "data.UserId"],
                status_code=200,
                content_type="application/json",
                authentication=AuthenticationObservation(
                    present=True,
                    observed_type="bearer",
                ),
            ),
            Observation(
                id="OBS-000003",
                source="OPENAPI",
                source_reference="documentation:openapi.yaml#/rest/basket/{basketId}",
                source_fingerprint="c" * 64,
                actor="UNKNOWN",
                channel="UNKNOWN",
                host="api.example.test",
                scheme="https",
                method="GET",
                path="/rest/basket/{basketId}",
                authentication=AuthenticationObservation(
                    present=False,
                    observed_type="none",
                ),
            ),
        ]
    )
    write_yaml(workspace.observations, observations.model_dump(mode="json", exclude_none=True))

    endpoint = Endpoint(
        id="EP-001",
        method="GET",
        path="/rest/basket/{basketId}",
        hosts=["api.example.test"],
        channels=["WEB"],
        authentication=EndpointAuthentication(
            required=False,
            observed_type="mixed",
            anonymous_success_observed=True,
        ),
        resource=EndpointResource(type="Basket", confidence=Confidence.HIGH),
        parameters=[
            EndpointParameter(
                name="basketId",
                location="path",
                inferred_type="integer",
                confidence=Confidence.HIGH,
                evidence=["OBS-000001", "OBS-000002"],
                knowledge_status=KnowledgeStatus.INFERRED,
                semantic_type="object_identifier",
                original_examples=["101", "202", "SESSION_COOKIE_CANARY"],
            )
        ],
        object_access=[
            ObjectAccessEvidence(
                identifier="basketId",
                owner_field_path="$.data.UserId",
                baselines=[
                    ActorObjectBaseline(
                        actor="ACCOUNT_A",
                        requested_value="101",
                        response_object_path="$.data.id",
                        owner_value_fingerprint="owner-a",
                        observations=["OBS-000001"],
                    ),
                    ActorObjectBaseline(
                        actor="ACCOUNT_B",
                        requested_value="202",
                        response_object_path="$.data.id",
                        owner_value_fingerprint="owner-b",
                        observations=["OBS-000002"],
                    ),
                ],
                distinct_actors=2,
                distinct_objects=2,
                distinct_owner_values=2,
                actor_object_binding_observed=True,
            )
        ],
        state_change=False,
        sources=["OBS-000001", "OBS-000002"],
        confidence=Confidence.HIGH,
        normalization=NormalizationEvidence(
            observed_paths=["/rest/basket/101", "/rest/basket/202"],
            rules=["numeric object identifier"],
        ),
    )
    write_yaml(workspace.endpoints, EndpointStore(endpoints=[endpoint]).model_dump(mode="json"))

    invariant = InvariantRecord(
        id="INV-001",
        key="authz:basket",
        category="authorization",
        statement="Basket lookup must authorize the caller for the selected object.",
        resources=["Basket"],
        endpoints=["EP-001"],
        evidence=["EP-001", "OBS-000001", "OBS-000002"],
        confidence=Confidence.MEDIUM,
        knowledge_status=KnowledgeStatus.ASSUMED,
        rationale="Object ownership is inferred from two controlled baselines.",
    )
    write_yaml(workspace.invariants, InvariantStore(invariants=[invariant]).model_dump(mode="json"))

    hypotheses = HypothesisStore(
        hypotheses=[
            _hypothesis("HYP-003", priority="P2", scores=(3, 3, 3, 3)),
            _hypothesis("HYP-002"),
            _hypothesis(
                "HYP-010",
                kind="RESEARCH_TASK",
                disposition="NEEDS_RESEARCH",
                priority="P3",
                scores=(2, 2, 2, 2),
            ),
        ]
    )
    write_yaml(workspace.hypotheses, hypotheses.model_dump(mode="json", exclude_none=True))

    baseline = StructuredRequest(
        id="baseline",
        role="BASELINE",
        method="GET",
        scheme="https",
        host="api.example.test",
        path="/rest/basket/101",
        actor="ACCOUNT_B",
        channel="WEB",
        expected=RequestExpectation(object_path="$.data.id", object_value="101"),
    )
    comparison_request = StructuredRequest(
        id="object-substitution",
        role="MUTATED",
        clone_of="baseline",
        method="GET",
        scheme="https",
        host="api.example.test",
        path="/rest/basket/202",
        actor="ACCOUNT_B",
        channel="WEB",
        mutations=[
            RequestMutation(
                dimension="OBJECT",
                location="path",
                parameter="basketId",
                from_value="101",
                to_value="202",
                source_actor="ACCOUNT_B",
                target_actor="ACCOUNT_A",
            )
        ],
    )
    plan = PlanRecord(
        id="TEST-001",
        key="plan:HYP-002",
        hypothesis_id="HYP-002",
        purpose="Test one controlled object boundary.",
        risk=RiskClassification(
            destructive=False,
            financial=False,
            affects_external_user=False,
            concurrency=False,
            request_budget=2,
            decision="REQUIRES_HUMAN_APPROVAL",
        ),
        accounts=PlanAccounts(object_owner="ACCOUNT_A", actor="ACCOUNT_B"),
        preconditions=["Use controlled accounts."],
        setup=[],
        actions=[],
        secure_assertions=[],
        interesting_behavior=[],
        evidence_to_capture=[],
        stop_conditions=["Stop after one failed baseline."],
        cleanup=[],
        requests=[baseline, comparison_request],
        execution=PlanExecutionConfig(
            supported=True,
            pattern="OBJECT_SUBSTITUTION",
            request_budget=2,
            mutation_dimensions=["OBJECT"],
            stop_conditions=["baseline request fails"],
        ),
        status="READY_FOR_REVIEW",
    )
    current_plan_checksum = plan_checksum(plan)
    plan.approval_status = "APPROVED"
    plan.approval = PlanApproval(
        approved_by="pytest",
        approved_at=datetime(2026, 7, 27, tzinfo=UTC),
        plan_checksum=current_plan_checksum,
        target_policy_checksum="policy-checksum",
    )
    write_yaml(workspace.test_plans, PlanStore(plans=[plan]).model_dump(mode="json"))

    comparison = ExecutionComparison(
        outcome="BASELINE_FAILED",
        baseline=ExecutionResponseSummary(
            request_id="baseline",
            status_code=401,
            content_type="application/json",
            response_length=80,
            json_paths=["$.error.code"],
            requested_object_id="101",
        ),
        reasons=["The credential-absent baseline returned 401."],
    )
    comparison_path = workspace.evidence_for("HYP-002") / "executions/execution-v1/comparison.yaml"
    write_yaml(comparison_path, comparison.model_dump(mode="json", exclude_none=True))
    comparison_sha = hashlib.sha256(comparison_path.read_bytes()).hexdigest()

    audit = ExecutionAuditRecord(
        hypothesis_id="HYP-002",
        plan_id="TEST-001",
        plan_checksum=current_plan_checksum,
        target_policy_checksum="policy-checksum",
        started_at=datetime(2026, 7, 27, tzinfo=UTC),
        completed_at=datetime(2026, 7, 27, 0, 0, 1, tzinfo=UTC),
        status="STOPPED",
        outcome="BASELINE_FAILED",
        actor_labels=["ACCOUNT_B"],
        request_count=1,
        methods=["GET"],
        hosts=["api.example.test"],
        paths=["/rest/basket/101"],
        mutation_dimensions=["OBJECT"],
        stop_conditions=["baseline request fails"],
        evidence=[
            EvidenceHash(
                path="executions/execution-v1/comparison.yaml",
                sha256=comparison_sha,
            )
        ],
        tool_version="0.5.0",
    )
    write_yaml(
        workspace.executions_for("HYP-002") / "execution-v1.yaml",
        audit.model_dump(mode="json"),
    )

    evidence = EvidenceMetadata(
        hypothesis_id="HYP-002",
        test_id="TEST-001",
        artifacts=[
            EvidenceArtifact(
                id="EVD-001",
                kind="other",
                path="executions/execution-v1/comparison.yaml",
                source_name="SUPER_SECRET_BEARER_TOKEN-comparison.yaml",
                sha256=comparison_sha,
                redaction="AUTOMATIC",
                description="Contact researcher@example.test; Cookie: SESSION_COOKIE_CANARY",
            )
        ],
        notes="Authorization: Bearer SUPER_SECRET_BEARER_TOKEN",
    )
    write_yaml(
        workspace.evidence_for("HYP-002") / "metadata.yaml",
        evidence.model_dump(mode="json", exclude_none=True),
    )

    validation = ValidationRecord(
        id="VAL-001",
        key="validation:HYP-002",
        hypothesis_id="HYP-002",
        title="Incomplete Basket authorization evidence",
        disposition="NEEDS_MORE_EVIDENCE",
        summary="The anonymous branch was tested, but authenticated BOLA was not reproduced.",
        checks=[
            ValidationCheck(
                id="AUTHZ-COMPARISON",
                question="Was authenticated cross-account access tested?",
                result="MISSING",
                detail="No comparison response exists.",
            )
        ],
        evidence_artifacts=["EVD-001"],
        missing_requirements=["Authenticated Account B to Account A comparison."],
        report_ready=False,
    )
    write_yaml(
        workspace.validations,
        ValidationStore(validations=[validation]).model_dump(mode="json"),
    )
    return workspace


def _file_hashes(root: Path) -> dict[str, str]:
    return {
        str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def _serialized_public_results(service: FinsecMcpService) -> str:
    results = [
        service.workspace_summary(),
        service.list_hypotheses(active_only=False, include_research_tasks=True),
        service.hypothesis_context("HYP-002"),
        service.evidence_summary("HYP-002"),
    ]
    return json.dumps([item.model_dump(mode="json") for item in results], sort_keys=True)


def test_workspace_summary_and_public_results_are_correct_and_serializable(
    tmp_path: Path,
) -> None:
    service = FinsecMcpService.from_workspace_path(_workspace(tmp_path).root)

    summary = service.workspace_summary()
    serialized = _serialized_public_results(service)

    assert summary.target_name == "mcp-demo"
    assert summary.in_scope_hosts == ["api.example.test"]
    assert summary.researcher_controlled_account_count == 2
    assert summary.counts.observations == 3
    assert summary.counts.active_hypotheses == 2
    assert summary.counts.research_tasks == 1
    assert summary.counts.executions == 1
    assert summary.counts.evidence_sets == 1
    assert summary.counts.evidence_records == 1
    assert summary.observation_authentication_states.present == 1
    assert summary.observation_authentication_states.absent_confirmed == 1
    assert summary.observation_authentication_states.unknown_or_redacted == 1
    assert not any(canary in serialized for canary in CANARIES)


def test_hypothesis_ordering_filters_and_priority_semantics(tmp_path: Path) -> None:
    service = FinsecMcpService.from_workspace_path(_workspace(tmp_path).root)

    active = service.list_hypotheses()
    all_records = service.list_hypotheses(active_only=False, include_research_tasks=True)

    assert [item.id for item in active.hypotheses] == ["HYP-002", "HYP-003"]
    assert [item.id for item in all_records.hypotheses] == [
        "HYP-002",
        "HYP-003",
        "HYP-010",
    ]
    assert "not vulnerability severity" in active.priority_interpretation


def test_unknown_and_path_traversal_hypothesis_ids_are_rejected(tmp_path: Path) -> None:
    service = FinsecMcpService.from_workspace_path(_workspace(tmp_path).root)

    with pytest.raises(FinsecMcpError, match="Unknown hypothesis"):
        service.hypothesis_context("HYP-999")
    with pytest.raises(FinsecMcpError, match="HYP-001"):
        service.evidence_summary("../../target.yaml")


def test_malformed_and_unsupported_workspace_data_returns_safe_errors(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path)
    service = FinsecMcpService.from_workspace_path(workspace.root)
    workspace.endpoints.write_text("version: [malformed", encoding="utf-8")

    with pytest.raises(FinsecMcpError) as malformed:
        service.workspace_summary()

    assert "Endpoint store" in str(malformed.value)
    assert str(workspace.root) not in str(malformed.value)

    write_yaml(workspace.endpoints, {"version": 2, "endpoints": []})
    assert service.workspace_summary().counts.endpoints == 0

    write_yaml(workspace.endpoints, {"version": 3, "endpoints": []})
    with pytest.raises(FinsecMcpError, match="unsupported"):
        service.workspace_summary()


def test_hyp_002_context_distinguishes_anonymous_401_from_authenticated_bola(
    tmp_path: Path,
) -> None:
    service = FinsecMcpService.from_workspace_path(_workspace(tmp_path).root)

    context = service.hypothesis_context("HYP-002")
    execution = context.executions[0]

    assert execution.authentication.state == "ABSENT_CONFIRMED"
    assert execution.tested_branch == "ANONYMOUS_OR_CREDENTIAL_ABSENT"
    assert execution.baseline is not None
    assert execution.baseline.status_code == 401
    assert execution.comparison is None
    assert execution.authorization_boundary_tested is False
    assert any("contradicts anonymous access only" in item for item in execution.interpretation)
    assert any(
        "cross-account authorization behavior remains untested" in item
        for item in execution.interpretation
    )
    assert context.hypothesis.lifecycle_status == "NOT_TESTED"
    assert context.evidence.validation is not None
    assert context.evidence.validation.disposition == "NEEDS_MORE_EVIDENCE"


def test_changed_plan_cannot_supply_execution_authentication_fidelity(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path)
    store = PlanStore.model_validate(load_yaml(workspace.test_plans))
    store.plans[0].requests[0].path = "/rest/basket/999"
    write_yaml(workspace.test_plans, store.model_dump(mode="json"))
    service = FinsecMcpService.from_workspace_path(workspace.root)

    execution = service.hypothesis_context("HYP-002").executions[0]

    assert execution.authentication.state == "UNKNOWN_OR_REDACTED"
    assert execution.tested_branch == "AUTHENTICATION_UNKNOWN"


def test_mcp_reads_do_not_mutate_workspace_files_or_expose_artifact_paths(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path)
    before = _file_hashes(workspace.root)
    service = FinsecMcpService.from_workspace_path(workspace.root)

    evidence = service.evidence_summary("HYP-002")
    _serialized_public_results(service)
    after = _file_hashes(workspace.root)

    assert before == after
    serialized = evidence.model_dump_json()
    assert "source_name" not in serialized
    assert "executions/execution-v1/comparison.yaml" not in serialized


def test_workspace_confinement_rejects_symlinked_evidence_metadata(tmp_path: Path) -> None:
    workspace = _workspace(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "metadata.yaml").write_text("version: 1\n", encoding="utf-8")
    evidence_root = workspace.evidence_for("HYP-003")
    evidence_root.symlink_to(outside, target_is_directory=True)
    service = FinsecMcpService.from_workspace_path(workspace.root)

    with pytest.raises(FinsecMcpError, match="outside"):
        service.evidence_summary("HYP-003")


def test_mcp_can_setup_import_and_generate_only_passive_artifacts(
    tmp_path: Path, sample_har: tuple[Path, dict[str, object]]
) -> None:
    source, _ = sample_har
    import_root = tmp_path / "imports"
    import_root.mkdir()
    imported_source = import_root / "account-a.har"
    imported_source.write_bytes(source.read_bytes())
    workspace_path = tmp_path / "workspaces" / "mcp-passive"
    service = FinsecMcpService.from_configured_path(
        workspace_path,
        import_root=import_root,
    )

    setup = service.setup_workspace(
        target_name="MCP Passive",
        slug="mcp-passive",
        in_scope_hosts=["api.example.test"],
        account_labels=["ACCOUNT_A", "ACCOUNT_B"],
        production=True,
        authorization_confirmed=True,
    )
    ingest = service.ingest_har_capture(
        source_name="account-a.har",
        actor="ACCOUNT_A",
        channel="WEB",
    )
    workflow = service.generate_hypotheses()
    target = TargetDocument.model_validate(load_yaml(workspace_path / "target.yaml"))

    assert setup.status == "CREATED"
    assert setup.slug == "mcp-passive"
    assert target.testing.active_execution_enabled is False
    assert target.testing.human_approval_required is True
    assert target.testing.destructive_testing is False
    assert ingest.imported == 5
    assert ingest.knowledge_state == "OBSERVED"
    assert workflow.observations == 5
    assert workflow.endpoints > 0
    assert workflow.hypotheses_generated is True
    assert not (workspace_path / "tests" / "plans" / "plans.yaml").exists()
    assert list((workspace_path / "tests" / "executions").iterdir()) == []
    assert imported_source.is_file()


def test_mcp_setup_requires_authorization_and_never_overwrites(tmp_path: Path) -> None:
    workspace_path = tmp_path / "workspaces" / "mcp-passive"
    service = FinsecMcpService.from_configured_path(workspace_path)

    with pytest.raises(FinsecMcpError, match="explicit confirmation"):
        service.setup_workspace(
            target_name="MCP Passive",
            slug="mcp-passive",
            in_scope_hosts=["api.example.test"],
            account_labels=["ACCOUNT_A"],
            production=True,
            authorization_confirmed=False,
        )
    assert not workspace_path.exists()

    workspace_path.mkdir(parents=True)
    sentinel = workspace_path / "researcher-notes.txt"
    sentinel.write_text("preserve me", encoding="utf-8")
    with pytest.raises(FinsecMcpError, match="never overwrites"):
        service.setup_workspace(
            target_name="MCP Passive",
            slug="mcp-passive",
            in_scope_hosts=["api.example.test"],
            account_labels=["ACCOUNT_A"],
            production=True,
            authorization_confirmed=True,
        )
    assert sentinel.read_text(encoding="utf-8") == "preserve me"


def test_mcp_har_import_requires_allowlisted_basename_actor_and_channel(
    tmp_path: Path,
) -> None:
    workspace = _workspace(tmp_path)
    import_root = tmp_path / "imports"
    import_root.mkdir()
    service = FinsecMcpService.from_configured_path(workspace.root, import_root=import_root)

    with pytest.raises(FinsecMcpError, match="without directories"):
        service.ingest_har_capture(
            source_name="../outside.har",
            actor="ACCOUNT_A",
            channel="WEB",
        )
    with pytest.raises(FinsecMcpError, match="configured account"):
        service.ingest_har_capture(
            source_name="missing.har",
            actor="UNCONFIGURED",
            channel="WEB",
        )
    with pytest.raises(FinsecMcpError, match="Channel must be"):
        service.ingest_har_capture(
            source_name="missing.har",
            actor="ACCOUNT_A",
            channel="BLUETOOTH",
        )
