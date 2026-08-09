"""Synthetic end-to-end coverage for deterministic business-logic analysis."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from finsec.behavior.analysis import (
    analyze_business_logic,
    load_business_invariants,
    load_logic_hypotheses,
)
from finsec.behavior.domain import (
    CausalBasis,
    InferenceConfidence,
    PropagationStore,
    RelationshipType,
    SafetyClassification,
)
from finsec.behavior.reconstruction import (
    load_propagation,
    load_workflow_families,
    load_workflow_graph,
    load_workflow_instances,
)
from finsec.config.workspace import WorkspacePaths, create_workspace
from finsec.evidence.manager import add_evidence, ensure_evidence
from finsec.hypotheses.domain import HypothesisStore
from finsec.hypotheses.generator import generate_hypotheses
from finsec.ingest.har import ingest_har
from finsec.modeling.generator import generate_model
from finsec.modeling.invariants import generate_invariants
from finsec.normalization.inventory import build_inventory
from finsec.readiness.domain import LifecycleStatus, PipelineStage
from finsec.readiness.resolver import resolve_workspace_readiness
from finsec.testing.planner import generate_plan
from finsec.utils.yaml_store import load_yaml, write_yaml
from finsec.validation.validator import validate_hypothesis

HOST = "api.logic.test"


def _entry(
    minute: int,
    method: str,
    path: str,
    response: dict[str, Any],
    *,
    request: dict[str, Any] | None = None,
    token: str = "SYNTHETIC_AUTH_SECRET",
) -> dict[str, Any]:
    headers = [{"name": "Authorization", "value": f"Bearer {token}"}]
    request_document: dict[str, Any] = {
        "method": method,
        "url": f"https://{HOST}{path}",
        "headers": headers,
        "queryString": [],
    }
    if request is not None:
        headers.append({"name": "Content-Type", "value": "application/json"})
        request_document["postData"] = {
            "mimeType": "application/json",
            "text": json.dumps(request, sort_keys=True),
        }
    return {
        "startedDateTime": f"2026-07-01T10:{minute:02d}:00Z",
        "request": request_document,
        "response": {
            "status": 200,
            "headers": [{"name": "Content-Type", "value": "application/json"}],
            "redirectURL": "",
            "content": {
                "mimeType": "application/json",
                "text": json.dumps(response, sort_keys=True),
            },
        },
    }


def _har(entries: list[dict[str, Any]]) -> dict[str, Any]:
    return {"log": {"version": "1.2", "creator": {"name": "pytest"}, "entries": entries}}


def _captures() -> dict[str, tuple[str, dict[str, Any]]]:
    account_a = [
        _entry(1, "POST", "/api/orders/1001/create", {"orderId": 1001, "status": "created"}),
        _entry(2, "POST", "/api/orders/1002/create", {"orderId": 1002, "status": "created"}),
        _entry(3, "POST", "/api/orders/1001/add", {"orderId": 1001, "status": "item_added"}),
        _entry(4, "POST", "/api/orders/1002/add", {"orderId": 1002, "status": "item_added"}),
        _entry(
            5,
            "POST",
            "/api/orders/1001/pay",
            {"orderId": 1001, "paymentId": 5001, "status": "paid"},
            request={"amount": 1200, "orderId": 1001},
        ),
        _entry(
            6,
            "POST",
            "/api/orders/1002/pay",
            {"orderId": 1002, "paymentId": 5002, "status": "paid"},
            request={"amount": 900, "orderId": 1002},
        ),
        _entry(7, "POST", "/api/orders/1001/ship", {"orderId": 1001, "status": "shipped"}),
        _entry(8, "POST", "/api/orders/1002/ship", {"orderId": 1002, "status": "shipped"}),
        _entry(9, "POST", "/api/orders/1003/create", {"orderId": 1003, "status": "created"}),
        _entry(
            10,
            "POST",
            "/api/orders/1003/apply",
            {"orderId": 1003, "couponId": 6001, "status": "discounted"},
            request={"couponId": 6001},
        ),
        _entry(11, "POST", "/api/orders/1003/add", {"orderId": 1003, "status": "item_added"}),
        _entry(
            12,
            "POST",
            "/api/orders/1003/pay",
            {"orderId": 1003, "paymentId": 5003, "status": "paid"},
            request={"amount": 700, "orderId": 1003},
        ),
        _entry(13, "POST", "/api/orders/1003/ship", {"orderId": 1003, "status": "shipped"}),
        _entry(14, "POST", "/api/orders/1004/create", {"orderId": 1004, "status": "created"}),
        _entry(15, "POST", "/api/orders/1004/ship", {"orderId": 1004, "status": "shipped"}),
        _entry(16, "POST", "/api/orders/1005/create", {"orderId": 1005, "status": "created"}),
        _entry(
            17,
            "POST",
            "/api/orders/1005/apply",
            {"orderId": 1005, "couponId": 6002, "status": "discounted"},
            request={"couponId": 6002},
        ),
        _entry(
            18,
            "POST",
            "/api/orders/1005/cancel",
            {"orderId": 1005, "couponId": 6002, "status": "cancelled"},
        ),
        _entry(19, "POST", "/api/rewards/6101/claim", {"rewardId": 6101, "status": "claimed"}),
        _entry(
            20,
            "POST",
            "/api/payments/7001/refund",
            {"paymentId": 7001, "status": "refunded", "amount": 300},
            request={"amount": 300},
        ),
        _entry(
            21,
            "POST",
            "/api/payments/7001/refund",
            {"paymentId": 7001, "status": "refunded", "amount": 300},
            request={"amount": 300},
        ),
        _entry(
            22,
            "POST",
            "/api/payments/7101/initiate",
            {"paymentId": 7101, "paymentReference": "PAYREF-1", "status": "pending"},
            request={"orderId": 2001, "amount": 1200},
        ),
        _entry(
            23,
            "POST",
            "/api/payments/7102/confirm",
            {"paymentId": 7102, "orderId": 2002, "status": "confirmed"},
            request={"paymentReference": "PAYREF-1", "orderId": 2002},
        ),
        _entry(
            24,
            "POST",
            "/api/invitations/8001/invite",
            {
                "invitationId": 8001,
                "organizationId": 8101,
                "invitationReference": "INVREF-1",
                "status": "pending",
            },
        ),
        _entry(
            26,
            "POST",
            "/api/wallets/9001/withdraw",
            {"walletId": 9001, "withdrawalId": 9002, "status": "completed"},
            request={"amount": 100},
        ),
        _entry(
            27,
            "POST",
            "/api/subscriptions/9101/refund",
            {
                "subscriptionId": 9101,
                "paymentId": 9102,
                "paymentStatus": "refunded",
                "entitlementStatus": "active",
            },
        ),
        _entry(
            28,
            "POST",
            "/api/transfers/9201/initiate",
            {"transferId": 9201, "status": "pending"},
            request={"amount": 50},
        ),
        _entry(
            29, "POST", "/api/transfers/9201/approve", {"transferId": 9201, "status": "approved"}
        ),
        _entry(30, "GET", "/api/jobs/9301/status", {"jobId": 9301, "status": "pending"}),
        _entry(31, "GET", "/api/jobs/9301/status", {"jobId": 9301, "status": "pending"}),
        _entry(32, "GET", "/api/jobs/9301/status", {"jobId": 9301, "status": "pending"}),
        _entry(33, "POST", "/api/tickets/9401/create", {"ticketId": 9401}),
    ]
    account_b = [
        _entry(
            25,
            "POST",
            "/api/invitations/8001/accept",
            {"invitationId": 8001, "organizationId": 8101, "status": "accepted"},
            request={"invitationReference": "INVREF-1"},
            token="SYNTHETIC_ACCOUNT_B_SECRET",
        )
    ]
    return {
        "account-a.har": ("ACCOUNT_A", _har(account_a)),
        "account-b.har": ("ACCOUNT_B", _har(account_b)),
    }


def _configure(workspace: WorkspacePaths) -> None:
    target = load_yaml(workspace.target)
    target["scope"]["hosts"] = [HOST]
    target["accounts"] = [
        {
            "id": "ACCOUNT_A",
            "ownership": "researcher",
            "role": "requester",
            "authentication": {"auth_type": "none", "source": {"type": "none"}, "status": "NONE"},
        },
        {
            "id": "ACCOUNT_B",
            "ownership": "researcher",
            "role": "approver",
            "authentication": {"auth_type": "none", "source": {"type": "none"}, "status": "NONE"},
        },
    ]
    target["testing"]["synthetic"] = True
    target["testing"]["local_lab"] = True
    target["testing"]["maximum_requests_per_plan"] = 6
    write_yaml(workspace.target, target)


def _build_workspace(tmp_path: Path, name: str = "logic-demo") -> WorkspacePaths:
    workspace = create_workspace(name, tmp_path / "workspaces")
    _configure(workspace)
    capture_root = tmp_path / "captures"
    capture_root.mkdir()
    for filename, (actor, document) in _captures().items():
        path = capture_root / filename
        path.write_text(json.dumps(document, sort_keys=True), encoding="utf-8")
        ingest_har(path, workspace, actor=actor, channel="WEB")
    build_inventory(workspace)
    generate_model(workspace)
    generate_invariants(workspace)
    generate_hypotheses(workspace)
    analyze_business_logic(workspace)
    return workspace


def _build_entries_workspace(
    tmp_path: Path, entries: list[dict[str, Any]], *, name: str
) -> WorkspacePaths:
    workspace = create_workspace(name, tmp_path / "workspaces")
    _configure(workspace)
    capture = tmp_path / f"{name}.har"
    capture.write_text(json.dumps(_har(entries), sort_keys=True), encoding="utf-8")
    ingest_har(capture, workspace, actor="ACCOUNT_A", channel="WEB")
    build_inventory(workspace)
    generate_model(workspace)
    generate_invariants(workspace)
    generate_hypotheses(workspace)
    analyze_business_logic(workspace)
    return workspace


@pytest.fixture(scope="module")
def logic_workspace(tmp_path_factory: pytest.TempPathFactory) -> WorkspacePaths:
    return _build_workspace(tmp_path_factory.mktemp("business-logic"))


def _logic(workspace: WorkspacePaths) -> list[Any]:
    return load_logic_hypotheses(workspace).hypotheses


def _link_for_actions(workspace: WorkspacePaths, source: str, destination: str) -> Any:
    action_by_observation = {
        step.observation_id: step.action_name
        for instance in load_workflow_instances(workspace).workflow_instances
        for step in instance.steps
    }
    return next(
        link
        for link in load_propagation(workspace).propagation_links
        if action_by_observation.get(link.source_observation_id) == source
        and action_by_observation.get(link.destination_observation_id) == destination
    )


def test_valid_checkout_reconstructs_ordered_behavior(logic_workspace: WorkspacePaths) -> None:
    families = load_workflow_families(logic_workspace).workflow_families
    order = next(
        item
        for item in families
        if item.common_path == ["CREATE_ORDER", "ADD_ORDER", "PAY_ORDER", "SHIP_ORDER"]
    )
    assert len(order.workflow_instance_ids) == 2
    assert order.causal_prerequisites


def test_payment_mutations_are_financial_research_tasks(
    logic_workspace: WorkspacePaths,
) -> None:
    item = next(value for value in _logic(logic_workspace) if value.affected_action == "PAY_ORDER")
    assert item.safety_classification == SafetyClassification.FINANCIAL_STATE_CHANGE
    assert item.kind == "RESEARCH_TASK"


def test_request_budget_blocker_is_explicit(tmp_path: Path) -> None:
    workspace = _build_workspace(tmp_path)
    target = load_yaml(workspace.target)
    target["testing"]["maximum_requests_per_plan"] = 1
    write_yaml(workspace.target, target)
    analyze_business_logic(workspace)
    assert any(
        "request budget is too low" in blocker.lower()
        for item in _logic(workspace)
        for blocker in item.readiness_blockers
    )


def test_step_skip_candidate_is_specific(logic_workspace: WorkspacePaths) -> None:
    item = next(
        value
        for value in _logic(logic_workspace)
        if value.family == "STEP_SKIPPING" and value.affected_action == "SHIP_ORDER"
    )
    assert "pay order" in item.title.lower()
    assert item.mutated_behavior == "omit PAY_ORDER and invoke SHIP_ORDER"
    assert item.invariant_statement
    invariant = next(
        value
        for value in load_business_invariants(logic_workspace).business_invariants
        if value.id == item.invariant_id
    )
    assert invariant.causal_evidence
    assert invariant.support_count == 2
    assert invariant.support_ratio == 1.0
    assert invariant.confidence == InferenceConfidence.MODERATE_EVIDENCE


def test_reward_claim_generates_replay_candidate(logic_workspace: WorkspacePaths) -> None:
    assert any(
        item.family == "REPLAY" and item.affected_action == "CLAIM_REWARD"
        for item in _logic(logic_workspace)
    )


def test_coupon_cancellation_rejects_unsupported_partial_rollback(
    logic_workspace: WorkspacePaths,
) -> None:
    rejection = next(
        item
        for item in load_logic_hypotheses(logic_workspace).rejections
        if item.mutation_family == "PARTIAL_ROLLBACK" and item.affected_action == "CANCEL_ORDER"
    )
    assert rejection.reasons == [
        "Partial rollback requires at least two linked resource or state effects that can be "
        "compared."
    ]


def test_duplicate_refund_generates_duplicate_action(logic_workspace: WorkspacePaths) -> None:
    assert any(
        item.family == "DUPLICATE_ACTION" and item.affected_action == "REFUND_PAYMENT"
        for item in _logic(logic_workspace)
    )


def test_payment_reference_reuse_is_linked_across_resources(
    logic_workspace: WorkspacePaths,
) -> None:
    assert any(item.family == "CROSS_WORKFLOW_TOKEN_REUSE" for item in _logic(logic_workspace))


def test_invitation_actor_switch_requires_two_controlled_actors(
    logic_workspace: WorkspacePaths,
) -> None:
    candidates = [
        item
        for item in _logic(logic_workspace)
        if item.family == "ACTOR_SWITCH" and "INVITATION" in item.affected_action
    ]
    assert candidates and candidates[0].controlled_actors_required == 2


def test_withdrawal_concurrency_remains_research_only(logic_workspace: WorkspacePaths) -> None:
    item = next(
        value
        for value in _logic(logic_workspace)
        if value.family == "CONCURRENT_EXECUTION" and "WITHDRAW" in value.affected_action
    )
    assert item.kind == "RESEARCH_TASK"
    assert item.safety_classification == "CONCURRENT"
    assert not any("Concurrency testing" in blocker for blocker in item.readiness_blockers)
    assert any(
        warning.code == "CONCURRENCY_EXECUTION_UNSUPPORTED" and warning.stage == "EXECUTION_POLICY"
        for warning in item.readiness_assessment.warnings
    )


def test_business_logic_producer_uses_unified_readiness_evaluator(
    logic_workspace: WorkspacePaths,
) -> None:
    logic_records = _logic(logic_workspace)
    assert logic_records
    assert all(
        item.readiness_assessment.evaluator == "unified-hypothesis-readiness-v1"
        for item in logic_records
    )

    backlog = HypothesisStore.model_validate(load_yaml(logic_workspace.hypotheses))
    synchronized = [item for item in backlog.hypotheses if item.id.startswith("BLH-")]
    assert synchronized
    assert all(
        item.readiness_assessment.evaluator == "unified-hypothesis-readiness-v1"
        for item in synchronized
    )


def test_partial_refund_tracks_entitlement_state(logic_workspace: WorkspacePaths) -> None:
    states = load_yaml(logic_workspace.behavior_states)["states"]
    assert any(item["name"] == "ACTIVE" for item in states)
    assert any(
        item.family == "PARTIAL_ROLLBACK" and "SUBSCRIPTION" in item.affected_action
        for item in _logic(logic_workspace)
    )


def test_coupon_journey_remains_separate_from_core_family(
    logic_workspace: WorkspacePaths,
) -> None:
    families = load_workflow_families(logic_workspace).workflow_families
    core = next(
        item
        for item in families
        if item.common_path == ["CREATE_ORDER", "ADD_ORDER", "PAY_ORDER", "SHIP_ORDER"]
    )
    coupon = next(
        item
        for item in families
        if item.common_path
        == ["CREATE_ORDER", "APPLY_ORDER", "ADD_ORDER", "PAY_ORDER", "SHIP_ORDER"]
    )
    assert core.id != coupon.id
    assert "APPLY_ORDER" not in core.required_looking_steps
    assert "APPLY_ORDER" in coupon.required_looking_steps


def test_interleaved_orders_remain_distinct_workflow_instances(
    logic_workspace: WorkspacePaths,
) -> None:
    order = next(
        item
        for item in load_workflow_families(logic_workspace).workflow_families
        if item.common_path == ["CREATE_ORDER", "ADD_ORDER", "PAY_ORDER", "SHIP_ORDER"]
    )
    instances = [
        item
        for item in load_workflow_instances(logic_workspace).workflow_instances
        if item.family_id == order.id
    ]
    action_paths = [tuple(step.action_name for step in item.steps) for item in instances]
    assert action_paths.count(("CREATE_ORDER", "ADD_ORDER", "PAY_ORDER", "SHIP_ORDER")) >= 2


def test_equal_scalar_values_do_not_bridge_unrelated_resource_workflows(
    tmp_path: Path,
) -> None:
    workspace = _build_entries_workspace(
        tmp_path,
        [
            _entry(
                1,
                "GET",
                "/api/orders/7",
                {
                    "order": {
                        "id": 7,
                        "status": "delivered",
                        "product": {"id": 1, "price": 100},
                    }
                },
            ),
            _entry(
                2,
                "POST",
                "/api/orders/7/return",
                {"order": {"id": 7, "status": "return_pending"}},
            ),
            _entry(
                3,
                "GET",
                "/api/posts/recent",
                {"posts": [{"id": 7, "authorId": 1}]},
            ),
            _entry(
                4,
                "POST",
                "/api/posts/7/comment",
                {"id": 1, "postId": 7},
                request={"authorId": 1},
            ),
        ],
        name="typed-correlation",
    )
    for instance in load_workflow_instances(workspace).workflow_instances:
        action_resources = {
            step.action_name.rsplit("_", 1)[-1]
            for step in instance.steps
            if "_" in step.action_name
        }
        assert not {"ORDER", "POST"}.issubset(action_resources)


def test_read_existing_identifier_is_context_only_and_creates_no_prerequisite(
    tmp_path: Path,
) -> None:
    workspace = _build_entries_workspace(
        tmp_path,
        [
            _entry(
                1,
                "GET",
                "/api/orders/42",
                {"orderId": "ORD-42", "status": "delivered"},
            ),
            _entry(
                2,
                "POST",
                "/api/orders/42/return",
                {"orderId": "ORD-42", "status": "return_pending"},
                request={"orderId": "ORD-42"},
            ),
        ],
        name="read-existing-negative",
    )
    link = _link_for_actions(workspace, "READ_ORDER", "RETURN_ORDER")
    instances = load_workflow_instances(workspace).workflow_instances
    observation_instance = {
        step.observation_id: instance.id for instance in instances for step in instance.steps
    }

    assert link.relationship_type == RelationshipType.CONTEXT_SOFT
    assert link.causal_basis == CausalBasis.EXISTING_VALUE_OBSERVED
    assert "OBSERVED_EXISTING_VALUE" in link.evidence_reason
    assert (
        observation_instance[link.source_observation_id]
        != observation_instance[link.destination_observation_id]
    )
    assert not any(
        item.prerequisite_action == "READ_ORDER" and item.dependent_action == "RETURN_ORDER"
        for family in load_workflow_families(workspace).workflow_families
        for item in family.causal_prerequisites
    )
    assert not any(
        item.affected_action == "RETURN_ORDER"
        and item.family in {"STEP_SKIPPING", "OUT_OF_ORDER_EXECUTION"}
        for item in _logic(workspace)
    )


def test_echoed_and_ambiguous_identifiers_are_soft_with_explicit_reasons(
    tmp_path: Path,
) -> None:
    echoed = _build_entries_workspace(
        tmp_path,
        [
            _entry(
                1,
                "POST",
                "/api/orders/42/update",
                {"orderId": "ORD-ECHO", "updated": "ok"},
                request={"orderId": "ORD-ECHO"},
            ),
            _entry(
                2,
                "POST",
                "/api/orders/42/approve",
                {"approvalId": "APPROVAL-ECHO"},
                request={"orderId": "ORD-ECHO"},
            ),
        ],
        name="echoed-producer-negative",
    )
    echoed_link = _link_for_actions(echoed, "UPDATE_ORDER", "APPROVE_ORDER")
    assert echoed_link.relationship_type == RelationshipType.CONTEXT_SOFT
    assert echoed_link.causal_basis == CausalBasis.REQUEST_VALUE_ECHOED
    assert "ECHOED_REQUEST_VALUE" in echoed_link.evidence_reason

    ambiguous = _build_entries_workspace(
        tmp_path,
        [
            _entry(1, "POST", "/api/orders/42/adjust", {"ticketId": "TICKET-AMBIGUOUS"}),
            _entry(
                2,
                "GET",
                "/api/orders/42/confirmation-preview",
                {"preview": "available"},
                request={"ticketId": "TICKET-AMBIGUOUS"},
            ),
        ],
        name="ambiguous-producer-negative",
    )
    ambiguous_link = next(
        item
        for item in load_propagation(ambiguous).propagation_links
        if item.value_fingerprint and item.causal_basis == CausalBasis.AMBIGUOUS_ORIGIN
    )
    assert ambiguous_link.relationship_type == RelationshipType.CONTEXT_SOFT
    assert "AMBIGUOUS_PRODUCER" in ambiguous_link.evidence_reason


def test_created_identifier_issued_nonce_and_state_transition_remain_hard(
    tmp_path: Path,
) -> None:
    workspace = _build_entries_workspace(
        tmp_path,
        [
            _entry(
                1,
                "POST",
                "/api/orders/create",
                {"orderId": "ORD-NEW"},
                request={"quantity": 1},
            ),
            _entry(
                2,
                "POST",
                "/api/orders/42/confirm",
                {"accepted": "yes"},
                request={"orderId": "ORD-NEW"},
            ),
            _entry(
                3,
                "GET",
                "/api/checkouts/nonce",
                {"checkoutNonce": "NONCE-CAPABILITY-0001"},
            ),
            _entry(
                4,
                "POST",
                "/api/checkouts/execute",
                {"status": "completed"},
                request={"checkoutNonce": "NONCE-CAPABILITY-0001"},
            ),
            _entry(
                5,
                "POST",
                "/api/transfers/42/initiate",
                {"transferId": "TRANSFER-STATE-42", "transferStatus": "pending"},
                request={"transferId": "TRANSFER-STATE-42"},
            ),
            _entry(
                6,
                "POST",
                "/api/transfers/42/approve",
                {"transferId": "TRANSFER-STATE-42", "transferStatus": "approved"},
                request={"transferId": "TRANSFER-STATE-42"},
            ),
        ],
        name="positive-producer-controls",
    )
    links = load_propagation(workspace).propagation_links
    by_basis = {
        basis: next(item for item in links if item.causal_basis == basis)
        for basis in (
            CausalBasis.RESOURCE_CREATED,
            CausalBasis.CAPABILITY_ISSUED,
            CausalBasis.STATE_TRANSITION_PRODUCED,
        )
    }

    assert all(item.relationship_type == RelationshipType.CAUSAL_HARD for item in by_basis.values())
    assert by_basis[CausalBasis.CAPABILITY_ISSUED].source_observation_id
    state_family = next(
        family
        for family in load_workflow_families(workspace).workflow_families
        if any(item.dependent_action == "APPROVE_TRANSFER" for item in family.causal_prerequisites)
    )
    state_prerequisite = next(
        item
        for item in state_family.causal_prerequisites
        if item.dependent_action == "APPROVE_TRANSFER"
    )
    assert state_prerequisite.causal_bases == [CausalBasis.STATE_TRANSITION_PRODUCED]


def test_collection_identifiers_do_not_chain_separate_order_instances(tmp_path: Path) -> None:
    workspace = _build_entries_workspace(
        tmp_path,
        [
            _entry(1, "GET", "/api/products", {"products": [{"id": 3, "price": 100}]}),
            _entry(
                2,
                "POST",
                "/api/orders",
                {"id": 7, "status": "created"},
                request={"productId": 3, "quantity": 1},
            ),
            _entry(
                3,
                "POST",
                "/api/orders",
                {"id": 8, "status": "created"},
                request={"productId": 3, "quantity": 1},
            ),
        ],
        name="collection-fanout",
    )
    order_instances = [
        instance
        for instance in load_workflow_instances(workspace).workflow_instances
        if any(step.action_name == "CREATE_ORDER" for step in instance.steps)
    ]
    assert len(order_instances) == 2
    assert all(
        sum(step.action_name == "CREATE_ORDER" for step in instance.steps) == 1
        for instance in order_instances
    )


def test_refund_response_preserves_each_resource_state(
    logic_workspace: WorkspacePaths,
) -> None:
    refund_step = next(
        step
        for instance in load_workflow_instances(logic_workspace).workflow_instances
        for step in instance.steps
        if step.action_name == "REFUND_SUBSCRIPTION"
    )
    observed = {
        (state.resource_type, state.state_after) for state in refund_step.state_observations
    }
    assert ("payment", "REFUNDED") in observed
    assert ("entitlement", "ACTIVE") in observed


def test_return_order_generates_financial_replay_and_value_research_tasks(
    tmp_path: Path,
) -> None:
    workspace = _build_entries_workspace(
        tmp_path,
        [
            _entry(1, "GET", "/api/account/dashboard", {"availableCredit": 100}),
            _entry(
                2,
                "GET",
                "/api/orders/7",
                {
                    "order": {
                        "id": 7,
                        "quantity": 1,
                        "status": "delivered",
                        "product": {"id": 3, "price": 100},
                    }
                },
            ),
            _entry(
                3,
                "POST",
                "/api/orders/7/return",
                {
                    "order": {
                        "id": 7,
                        "quantity": 1,
                        "status": "return_pending",
                        "product": {"id": 3, "price": 100},
                    }
                },
            ),
            _entry(4, "GET", "/api/account/dashboard", {"availableCredit": 200}),
        ],
        name="order-return",
    )
    candidates = [item for item in _logic(workspace) if item.affected_action == "RETURN_ORDER"]
    assert {item.family for item in candidates} >= {"REPLAY", "DUPLICATE_ACTION"}
    assert all(
        item.safety_classification == SafetyClassification.FINANCIAL_STATE_CHANGE
        for item in candidates
        if item.family != "CONCURRENT_EXECUTION"
    )
    assert (
        next(
            item for item in candidates if item.family == "CONCURRENT_EXECUTION"
        ).safety_classification
        == SafetyClassification.CONCURRENT
    )
    assert not any(item.family == "QUANTITY_VALUE_INVARIANT" for item in candidates)
    value_rejection = next(
        item
        for item in load_logic_hypotheses(workspace).rejections
        if item.mutation_family == "QUANTITY_VALUE_INVARIANT"
        and item.affected_action == "RETURN_ORDER"
    )
    assert "No client-controlled request field" in value_rejection.reasons[0]
    assert not any(item.affected_action == "ALL_ORDER" for item in _logic(workspace))


def test_legacy_propagation_link_without_destination_kind_remains_loadable() -> None:
    store = PropagationStore.model_validate(
        {
            "version": 1,
            "propagation_links": [
                {
                    "id": "PROP-LEGACY",
                    "value_fingerprint": "a" * 64,
                    "value_kind": "RESOURCE_IDENTIFIER",
                    "source_observation_id": "OBS-000001",
                    "source_field": "$.id",
                    "destination_observation_id": "OBS-000002",
                    "destination_field": "$.orderId",
                    "confidence": "MODERATE_EVIDENCE",
                }
            ],
        }
    )

    link = store.propagation_links[0]
    assert link.destination_value_kind is None
    assert link.relationship_type == RelationshipType.CONTEXT_SOFT
    assert link.causal_basis == CausalBasis.LEGACY_UNTYPED
    assert "Rebuild from factual observations" in link.evidence_reason


def test_read_only_all_action_is_never_selected_as_a_mutation(tmp_path: Path) -> None:
    workspace = _build_entries_workspace(
        tmp_path,
        [
            _entry(
                1,
                "GET",
                "/api/orders/all",
                {"orders": [{"id": 7, "quantity": 1, "status": "delivered"}]},
            ),
            _entry(
                2,
                "GET",
                "/api/orders/all",
                {"orders": [{"id": 8, "quantity": 1, "status": "delivered"}]},
            ),
        ],
        name="read-only-orders",
    )
    assert not any(item.affected_action == "ALL_ORDER" for item in _logic(workspace))


def test_order_detail_without_update_method_creates_shadow_endpoint_research_task(
    tmp_path: Path,
) -> None:
    workspace = _build_entries_workspace(
        tmp_path,
        [
            _entry(
                1,
                "GET",
                "/api/orders/7",
                {
                    "order": {
                        "id": 7,
                        "quantity": 1,
                        "status": "delivered",
                        "product": {"id": 3, "price": 100},
                    }
                },
            ),
            _entry(
                2,
                "GET",
                "/api/orders/8",
                {
                    "order": {
                        "id": 8,
                        "quantity": 1,
                        "status": "delivered",
                        "product": {"id": 4, "price": 200},
                    }
                },
            ),
            _entry(
                3,
                "POST",
                "/api/orders",
                {"credit": 900, "id": 9},
                request={"productId": 3, "quantity": 1},
            ),
        ],
        name="shadow-order-update",
    )
    candidate = next(item for item in _logic(workspace) if item.family == "SHADOW_ENDPOINT")
    assert candidate.kind == "RESEARCH_TASK"
    assert candidate.candidate_methods == ["PATCH", "PUT"]
    assert candidate.candidate_paths
    assert {"quantity", "status"}.issubset(set(candidate.candidate_fields))
    assert candidate.safety_classification == SafetyClassification.FINANCIAL_STATE_CHANGE


def test_polling_is_suppressed_from_business_workflows(logic_workspace: WorkspacePaths) -> None:
    steps = [
        step.action_name
        for item in load_workflow_instances(logic_workspace).workflow_instances
        for step in item.steps
    ]
    assert "STATUS_JOB" not in steps


def test_incomplete_capture_preserves_uncertainty(logic_workspace: WorkspacePaths) -> None:
    incomplete = next(
        item
        for item in load_workflow_instances(logic_workspace).workflow_instances
        if [step.action_name for step in item.steps] == ["CREATE_TICKET"]
    )
    assert incomplete.ambiguities
    assert incomplete.segmentation_confidence == "WEAK_EVIDENCE"


def test_repeated_analysis_is_byte_stable(logic_workspace: WorkspacePaths) -> None:
    paths = [
        logic_workspace.workflow_instances,
        logic_workspace.workflow_families,
        logic_workspace.behavior_states,
        logic_workspace.behavior_transitions,
        logic_workspace.business_invariants,
        logic_workspace.business_logic_hypotheses,
    ]
    before = {path: path.read_bytes() for path in paths}
    analyze_business_logic(logic_workspace)
    assert before == {path: path.read_bytes() for path in paths}


def test_irrelevant_observation_does_not_change_hypothesis_ids(tmp_path: Path) -> None:
    workspace = _build_workspace(tmp_path)
    before = {item.fingerprint: item.id for item in _logic(workspace)}
    irrelevant = tmp_path / "irrelevant.har"
    irrelevant.write_text(
        json.dumps(
            _har(
                [
                    _entry(40, "GET", "/static/app.js", {"ignored": True}),
                    _entry(41, "POST", "/telemetry/collect", {"ignored": True}),
                ]
            )
        ),
        encoding="utf-8",
    )
    ingest_har(irrelevant, workspace, actor="ACCOUNT_A", channel="WEB")
    build_inventory(workspace)
    generate_model(workspace)
    generate_invariants(workspace)
    generate_hypotheses(workspace)
    analyze_business_logic(workspace)
    after = {item.fingerprint: item.id for item in _logic(workspace)}
    assert all(after[fingerprint] == identifier for fingerprint, identifier in before.items())


def test_existing_workspace_is_extended_lazily(tmp_path: Path) -> None:
    workspace = create_workspace("legacy", tmp_path / "workspaces")
    _configure(workspace)
    for path in (
        workspace.behavior_actions,
        workspace.workflow_instances,
        workspace.workflow_families,
        workspace.business_invariants,
        workspace.business_logic_hypotheses,
    ):
        path.unlink()
    capture = tmp_path / "legacy.har"
    capture.write_text(
        json.dumps(
            _har([_entry(1, "POST", "/api/rewards/1/claim", {"rewardId": 1, "status": "claimed"})])
        ),
        encoding="utf-8",
    )
    ingest_har(capture, workspace, actor="ACCOUNT_A", channel="WEB")
    build_inventory(workspace)
    generate_model(workspace)
    generate_invariants(workspace)
    generate_hypotheses(workspace)
    analyze_business_logic(workspace)
    assert workspace.workflow_instances.is_file()
    assert workspace.business_logic_hypotheses.is_file()


def test_planner_refuses_unsafe_or_under_evidenced_execution(
    logic_workspace: WorkspacePaths,
) -> None:
    item = next(value for value in _logic(logic_workspace) if value.kind == "SECURITY_HYPOTHESIS")
    result = generate_plan(logic_workspace, item.id)
    assert result.plan.status == "BLOCKED"
    assert not result.plan.execution.supported
    assert result.plan.execution_default == "DO_NOT_EXECUTE"
    readiness = resolve_workspace_readiness(logic_workspace)
    plan_stage = next(item for item in readiness.stages if item.id == PipelineStage.PLAN)
    assert plan_stage.status == LifecycleStatus.COMPLETE
    analyze_business_logic(logic_workspace)
    refreshed = resolve_workspace_readiness(logic_workspace)
    refreshed_plan = next(item for item in refreshed.stages if item.id == PipelineStage.PLAN)
    assert refreshed_plan.status == LifecycleStatus.COMPLETE


def _assessment(*, secure_observed: bool) -> dict[str, bool]:
    return {
        "scope_compliant": True,
        "rules_compliant": True,
        "researcher_controlled_accounts": True,
        "ownership_or_boundary_verified": True,
        "expected_secure_behavior_observed": secure_observed,
        "unauthorized_capability_demonstrated": not secure_observed,
        "actual_behavior_verified": True,
        "authoritative_result_verified": True,
        "negative_control_performed": True,
        "reproduced_clean_session": True,
        "alternative_explanations_ruled_out": True,
        "meaningful_impact_demonstrated": not secure_observed,
        "realistic_prerequisites": True,
        "documented_or_intended_behavior": False,
        "client_side_only": False,
        "known_duplicate": False,
        "redaction_reviewed": True,
    }


def _evidence_file(tmp_path: Path, name: str, value: dict[str, Any]) -> Path:
    path = tmp_path / name
    path.write_text(json.dumps(value, sort_keys=True), encoding="utf-8")
    return path


def test_backend_enforcement_rejects_hypothesis_cleanly(tmp_path: Path) -> None:
    workspace = _build_workspace(tmp_path)
    item = next(value for value in _logic(workspace) if value.kind == "SECURITY_HYPOTHESIS")
    generate_plan(workspace, item.id)
    evidence = ensure_evidence(workspace, item.id)
    metadata = load_yaml(evidence.root / "metadata.yaml")
    metadata["assessment"] = _assessment(secure_observed=True)
    write_yaml(evidence.root / "metadata.yaml", metadata)
    result = validate_hypothesis(workspace, item.id)
    assert result.validation.disposition == "REFUTED"
    backlog = load_yaml(workspace.hypotheses)
    record = next(value for value in backlog["hypotheses"] if value["id"] == item.id)
    assert record["epistemic_status"] == "REJECTED_BY_BACKEND"


def test_confirmation_requires_mutation_and_state_evidence(tmp_path: Path) -> None:
    workspace = _build_workspace(tmp_path)
    item = next(value for value in _logic(workspace) if value.kind == "SECURITY_HYPOTHESIS")
    plan = generate_plan(workspace, item.id).plan
    plans = load_yaml(workspace.test_plans)
    stored = next(value for value in plans["plans"] if value["id"] == plan.id)
    stored["status"] = "READY_FOR_REVIEW"
    stored["risk"]["decision"] = "REQUIRES_HUMAN_APPROVAL"
    stored["approval_status"] = "APPROVED"
    write_yaml(workspace.test_plans, plans)
    evidence = ensure_evidence(workspace, item.id)
    artifacts = [
        ("request", "request.json", {"mutation": item.mutated_behavior}),
        ("response", "response.json", {"accepted": True}),
        ("before", "before.json", {"order": {"status": "created"}}),
        ("after", "after.json", {"order": {"status": "shipped"}}),
        ("delayed_after", "delayed.json", {"order": {"status": "shipped"}}),
    ]
    if len(item.controlled_resources_required) > 1:
        artifacts.append(
            (
                "related_state",
                "related.json",
                {"resources": {name: "verified" for name in item.controlled_resources_required}},
            )
        )
    for kind, name, document in artifacts:
        add_evidence(workspace, item.id, _evidence_file(tmp_path, name, document), kind)
    metadata = load_yaml(evidence.root / "metadata.yaml")
    metadata["assessment"] = _assessment(secure_observed=False)
    write_yaml(evidence.root / "metadata.yaml", metadata)
    result = validate_hypothesis(workspace, item.id)
    assert result.validation.disposition == "CONFIRMED"
    assert all(check.result == "PASS" for check in result.validation.checks)


def test_all_required_mutation_families_are_implemented(logic_workspace: WorkspacePaths) -> None:
    generated = {item.family for item in _logic(logic_workspace)}
    assert generated == {
        "STEP_SKIPPING",
        "OUT_OF_ORDER_EXECUTION",
        "REPLAY",
        "DUPLICATE_ACTION",
        "CONCURRENT_EXECUTION",
        "TERMINAL_STATE_BYPASS",
        "ACTOR_SWITCH",
        "RESOURCE_SWITCH",
        "CROSS_WORKFLOW_TOKEN_REUSE",
        "PARTIAL_ROLLBACK",
        "QUANTITY_VALUE_INVARIANT",
        "ROLE_APPROVAL_BYPASS",
    }


def test_graph_and_artifacts_do_not_store_capture_secrets(logic_workspace: WorkspacePaths) -> None:
    family = next(
        item
        for item in load_workflow_families(logic_workspace).workflow_families
        if item.common_path == ["CREATE_ORDER", "ADD_ORDER", "PAY_ORDER", "SHIP_ORDER"]
    )
    graph = load_workflow_graph(logic_workspace, family.id)
    assert graph.workflow_family_id == family.id
    assert any(edge.median_timing_seconds is not None for edge in graph.edges)
    stored = "\n".join(
        path.read_text(encoding="utf-8")
        for path in logic_workspace.root.rglob("*")
        if path.is_file()
    )
    assert "SYNTHETIC_AUTH_SECRET" not in stored
    assert "SYNTHETIC_ACCOUNT_B_SECRET" not in stored
